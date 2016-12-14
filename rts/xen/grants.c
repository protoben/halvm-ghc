#define __XEN__
#include <stdint.h>
#include <stdlib.h>
#include <alloca.h>
#include <xen/xen.h>
#include <xen/grant_table.h>
#include <xen/memory.h>
#include "grants.h"
#include "hypercalls.h"
#include <assert.h>
#include "memory.h"
#include <string.h>
#include <errno.h>
#include "vmm.h"

#define min(a,b) (((a)<(b)) ? (a) : (b))

static int grant_table_interface_verson = 0;

/*******************************************************************************
 *
 * VERSION 2 INTERFACE (PREFERRED)
 *
 ******************************************************************************/

static grant_entry_v2_t *grant_table  = NULL;
static grant_status_t   *status_table = NULL;
static grant_ref_t       max_ref      = 0;

static void init_grants_v2(void)
{
  gnttab_query_size_t  qsize     = { .dom = DOMID_SELF };
  gnttab_setup_table_t stable    = { .dom = DOMID_SELF };
  gnttab_get_status_frames_t gsf = { .dom = DOMID_SELF };
  uint32_t i, num_stat_frames;
  xen_pfn_t *table_pfns;
  uint64_t *stat_pfns;
  mfn_t *mframes;

  /* figure out how big we can make our grant table */
  assert(HYPERCALL_grant_table_op(GNTTABOP_query_size, &qsize, 1) >= 0);
  assert(qsize.status == GNTST_okay);

  /* allocate the grant table */
  table_pfns = alloca(qsize.max_nr_frames * sizeof(xen_pfn_t));
  memset(table_pfns, 0, qsize.max_nr_frames * sizeof(xen_pfn_t));
  stable.nr_frames = qsize.max_nr_frames;
  stable.frame_list.p = table_pfns;
  assert( HYPERCALL_grant_table_op(GNTTABOP_setup_table, &stable, 1) >= 0);
  assert( stable.status == GNTST_okay );

  /* map it into our address space */
  mframes = alloca(qsize.max_nr_frames * sizeof(mfn_t));
  memset(mframes, 0, qsize.max_nr_frames * sizeof(mfn_t));
  for(i = 0; i < qsize.max_nr_frames; i++)
    mframes[i] = table_pfns[i];
  grant_table = map_frames(mframes, qsize.max_nr_frames);

  /* note down the maximum grant reference */
  max_ref = (qsize.max_nr_frames * PAGE_SIZE) / sizeof(grant_entry_v2_t);
  num_stat_frames = qsize.nr_frames;
  max_ref = min(max_ref, (qsize.nr_frames * PAGE_SIZE) / sizeof(uint16_t));

  /* allocate the status table */
  stat_pfns = alloca(qsize.max_nr_frames * sizeof(uint64_t));
  memset(stat_pfns, 0, qsize.max_nr_frames * sizeof(uint64_t));
  gsf.nr_frames = num_stat_frames;
  gsf.frame_list.p = stat_pfns;
  assert(HYPERCALL_grant_table_op(GNTTABOP_get_status_frames, &gsf, 1) >= 0);
  assert(gsf.status == GNTST_okay);

  /* map it into our address space */
  memset(mframes, 0, qsize.max_nr_frames * sizeof(mfn_t));
  for(i = 0; i < qsize.max_nr_frames; i++)
    mframes[i] = stat_pfns[i];
  status_table = map_frames(mframes, num_stat_frames);
}

static long alloc_grant_v2(domid_t dom, void *p, uint16_t len, int ro,
                           grant_ref_t *pref)
{
  uint16_t offset;
  grant_ref_t i;
  pte_t pte;
  mfn_t mfn;

  offset = (uint16_t)((uintptr_t)p & (PAGE_SIZE-1));
  if( (offset + len) > 4096 ) return -EINVAL;
  pte = get_pt_entry(p);
  if( !ENTRY_PRESENT(pte) ) return -EINVAL;
  mfn = pte >> PAGE_SHIFT;

  for(i = 0; i < max_ref; i++) {
    if( (grant_table[i].hdr.flags & GTF_type_mask) == GTF_invalid ) {
      uint16_t flags = GTF_permit_access;

      grant_table[i].hdr.domid = dom;
      if(len == 4096) {
        grant_table[i].full_page.frame = mfn;
      } else {
        grant_table[i].sub_page.page_off = offset;
        grant_table[i].sub_page.length   = len;
        grant_table[i].sub_page.frame    = mfn;
        flags |= GTF_sub_page;
      }

      if(ro) flags |= GTF_readonly;
      system_wmb();
      grant_table[i].hdr.flags = flags;

      *pref = i;
      return 0;
    }
  }

  return -EXFULL;
}

static long end_grant_v2(grant_ref_t gref)
{
  if(gref >= max_ref)
    return -EINVAL;

  grant_table[gref].hdr.flags = 0;
  system_mb();

  if( status_table[gref] & (GTF_reading | GTF_writing) )
    return -EAGAIN;

  system_mb();
  return 1;
}

static long prepare_transfer_v2(domid_t dom)
{
  grant_ref_t i;

  for(i = 0; i < max_ref; i++)
    if( (grant_table[i].hdr.flags & GTF_type_mask) == GTF_invalid ) {
      grant_table[i].hdr.domid = dom;
      grant_table[i].hdr.flags = GTF_accept_transfer;
      return i;
    }

  return -EXFULL;
}

static long complete_transfer_v2(grant_ref_t ref, int reset)
{
  xen_pfn_t mfn;
  uint16_t flags;

  if(ref >= max_ref)
    return -EINVAL;

  flags = grant_table[ref].hdr.flags;
  if( !(flags & GTF_transfer_committed) )
    return -EAGAIN;

  while( !(flags & GTF_transfer_completed) ) {
    flags = grant_table[ref].hdr.flags;
  }

  mfn = grant_table[ref].full_page.frame;
  assert(mfn);

  if(reset) {
    grant_table[ref].hdr.flags = GTF_accept_transfer;
  } else {
    grant_table[ref].hdr.flags = 0;
  }

  return mfn;
}

/*******************************************************************************
 *
 * VERSION 1 INTERFACE (DEPRECATED, BUT REQUIRED BY AMAZON)
 *
 ******************************************************************************/

#define V1_NR_GRANT_FRAMES 4
#define V1_NUM_ENTRIES (V1_NR_GRANT_FRAMES*PAGE_SIZE / sizeof(grant_entry_v1_t))

static grant_entry_v1_t *v1_grant_table;

static void init_grants_v1(void)
{
  struct gnttab_setup_table setup;
  mfn_t frames[V1_NR_GRANT_FRAMES];

  setup.dom = DOMID_SELF;
  setup.nr_frames = V1_NR_GRANT_FRAMES;
  setup.frame_list.p = (unsigned long*)frames;

  assert(HYPERCALL_grant_table_op(GNTTABOP_setup_table, &setup, 1) >= 0);
  v1_grant_table = map_frames(frames, V1_NR_GRANT_FRAMES);
}

static long alloc_grant_v1(domid_t dom, void *p,
                           uint16_t len __attribute__((unused)),
                           int ro,
                           grant_ref_t *pref)
{
  grant_ref_t i;
  pte_t pte;
  mfn_t mfn;

  pte = get_pt_entry(p);
  if( !ENTRY_PRESENT(pte) ) return -EINVAL;
  mfn = pte >> PAGE_SHIFT;

  for(i = 0; i < V1_NUM_ENTRIES; i++)
  {
    if( (v1_grant_table[i].flags & GTF_type_mask) == GTF_invalid )
    {
      v1_grant_table[i].frame = mfn;
      v1_grant_table[i].domid = dom;
      system_wmb();
      v1_grant_table[i].flags = GTF_permit_access | (ro ? GTF_readonly : 0);
      system_wmb();

      *pref = i;
      return 0;
    }
  }

  return -EXFULL;
}

static long end_grant_v1(grant_ref_t gref)
{
  uint16_t flags;
  int done = 0;

  if(gref >= V1_NUM_ENTRIES)
    return -EINVAL;

  flags = v1_grant_table[gref].flags;
  do {
    if(flags & (GTF_reading | GTF_writing))
      return -EAGAIN;
    done =
      __atomic_compare_exchange_n(&v1_grant_table[gref].flags, &flags, 0,
                                  0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
  } while(!done);

  return 1;
}

static long prepare_transfer_v1(domid_t dom)
{
  grant_ref_t i;

  for(i = 0; i < V1_NUM_ENTRIES; i++)
  {
    if( (v1_grant_table[i].flags & GTF_type_mask) == GTF_invalid )
    {
      v1_grant_table[i].domid = dom;
      v1_grant_table[i].flags = GTF_accept_transfer;
      return i;
    }
  }

  return -EXFULL;
}

static long complete_transfer_v1(grant_ref_t ref, int reset)
{
  xen_pfn_t mfn;
  uint16_t flags;

  if(ref >= V1_NUM_ENTRIES)
    return -EINVAL;

  flags = v1_grant_table[ref].flags;
  if( !(flags & GTF_transfer_committed) )
    return -EAGAIN;

  mfn = v1_grant_table[ref].frame;
  assert(mfn);

  v1_grant_table[ref].flags = reset ? GTF_accept_transfer : GTF_invalid;
  return mfn;
}

/*******************************************************************************
 *
 * High-Level Interface
 *
 ******************************************************************************/

void init_grants(void)
{
  gnttab_set_version_t svers = { .version = 2 };

  /* we really want to use version 2 of the grant table API */
  if(HYPERCALL_grant_table_op(GNTTABOP_set_version, &svers, 1) >= 0) {
    /* that should have worked, but let's double check, for sanity */
    gnttab_get_version_t gvers = { .dom = DOMID_SELF };
    assert(HYPERCALL_grant_table_op(GNTTABOP_get_version, &gvers, 1) >= 0);
    assert(gvers.version == 2);
    grant_table_interface_verson = 2;
    init_grants_v2();
  } else {
    grant_table_interface_verson = 1;
    init_grants_v1();
  }
}

long alloc_grant(domid_t dom, void *p, uint16_t len, int ro, grant_ref_t *pref)
{
  if(grant_table_interface_verson == 2)
    return alloc_grant_v2(dom, p, len, ro, pref);
  else
    return alloc_grant_v1(dom, p, len, ro, pref);
}

long end_grant(grant_ref_t gref)
{
  if(grant_table_interface_verson == 2)
    return end_grant_v2(gref);
  else
    return end_grant_v1(gref);
}

long map_grants(domid_t dom, int readonly,
                grant_ref_t *refs, size_t count,
                void **outptr, uint32_t *outhndls,
                uint64_t *outpaddrs)
{
  gnttab_map_grant_ref_t *args;
  uintptr_t addr;
  uint16_t flags;
  size_t i;
  long res;

  if(!outptr)
    return -EINVAL;
  *outptr = NULL;

  if(!outhndls)
    return -EINVAL;
  memset(outhndls, 0, sizeof(uint32_t) * count);

  args = calloc(count, sizeof(gnttab_map_grant_ref_t));
  if(!args)
    return -ENOMEM;

  addr = (uintptr_t)claim_shared_space(count * 4096);

  flags = GNTMAP_host_map | GNTMAP_application_map;
  if(readonly)
    flags |= GNTMAP_readonly;
  if(outpaddrs)
    flags |= GNTMAP_device_map;

  for(i = 0; i < count; i++) {
    args[i].host_addr = addr + (i * PAGE_SIZE);
    args[i].flags     = flags;
    args[i].ref       = refs[i];
    args[i].dom       = dom;
  }

  res = HYPERCALL_grant_table_op(GNTTABOP_map_grant_ref, args, count);
  if(res < 0) {
    free(args);
    return res;
  }

  for(i = 0; i < count; i++)
    if(args[i].status != GNTST_okay) {
      free(args);
      return -args[i].status;
    }

  *outptr = (void*)addr;
  for(i = 0; i < count; i++) {
    outhndls[i] = args[i].handle;
    if(outpaddrs) outpaddrs[i] = args[i].dev_bus_addr;
  }

  free(args);
  return 0;
}

long unmap_grants(grant_handle_t *handles, size_t count)
{
  gnttab_unmap_grant_ref_t *args;
  size_t i;
  long res;

  args = calloc(count, sizeof(gnttab_unmap_grant_ref_t));
  if(!args) {
    return -ENOMEM;
  }

  for(i = 0; i < count; i++)
    args[i].handle = handles[i];

  res = HYPERCALL_grant_table_op(GNTTABOP_unmap_grant_ref, args, count);
  if(res < 0) {
    free(args);
    return res;
  }

  for(i = 0; i < count; i++)
    if(args[i].status != GNTST_okay) {
      free(args);
      return -args[i].status;
    }

  free(args);
  return 0;
}

long prepare_transfer(domid_t dom)
{
  if(grant_table_interface_verson == 2)
    return prepare_transfer_v2(dom);
  else
    return prepare_transfer_v1(dom);
}

long transfer_frame(domid_t dom, grant_ref_t ref, void *ptr)
{
  xen_memory_reservation_t rsv;
  gnttab_transfer_t trans;
  xen_pfn_t pfn, mfn, new_mfn;
  pte_t pte;
  long res;

  if( (uintptr_t)ptr & (PAGE_SIZE-1) ) {
    return -EINVAL; /* this needs to be page aligned */
  }

  pte = get_pt_entry(ptr);
  if( !ENTRY_PRESENT(pte) ) {
    return -EINVAL; /* and it must be mapped */
  }

  mfn = pte >> PAGE_SHIFT;
  set_pt_entry(ptr, NULL); /* unmap it */

  /* replace the PFN we're using */
  pfn = machine_to_phys_mapping[mfn];
  assert(pfn);
  rsv.extent_start.p = &new_mfn;
  rsv.nr_extents     = 1;
  rsv.extent_order   = 0;
  rsv.mem_flags      = 0;
  rsv.domid          = DOMID_SELF;
  res = HYPERCALL_memory_op(XENMEM_increase_reservation, &rsv);
  if( res < 0 ) {
    return res;
  }
  p2m_map[pfn] = new_mfn;

  /* do the transfer */
  trans.mfn = mfn;
  trans.domid = dom;
  trans.ref = ref;
  res = HYPERCALL_grant_table_op(GNTTABOP_transfer, &trans, 1);
  return (res < 0) ? res : trans.status;
}

long complete_transfer(grant_ref_t ref, int reset)
{
  if(grant_table_interface_verson == 2)
    return complete_transfer_v2(ref, reset);
  else
    return complete_transfer_v1(ref, reset);
}

long copy_frame(unsigned long src, int src_is_ref, domid_t sdom, uint16_t soff,
                unsigned long dst, int dst_is_ref, domid_t ddom, uint16_t doff,
                uint16_t length)
{
  gnttab_copy_t copy;
  long res;

  memset(&copy, 0, sizeof(gnttab_copy_t));

  if(src_is_ref) {
    copy.source.u.ref = src;
    copy.flags = GNTCOPY_source_gref;
  } else copy.source.u.gmfn = src;

  if(dst_is_ref) {
    copy.dest.u.ref = dst;
    copy.flags |= GNTCOPY_dest_gref;
  } else copy.dest.u.gmfn = dst;

  copy.source.domid  = sdom;
  copy.source.offset = soff;
  copy.dest.domid    = ddom;
  copy.dest.offset   = doff;
  copy.len           = length;

  res = HYPERCALL_grant_table_op(GNTTABOP_copy, &copy, 1);
  return (res < 0) ? res : copy.status;
}
