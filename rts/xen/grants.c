#define __XEN__
#include <stdint.h>
#include <stdlib.h>
#include <alloca.h>
#include <xen/xen.h>
#include <xen/grant_table.h>
#include "grants.h"
#include "hypercalls.h"
#include <assert.h>
#include "memory.h"
#include <string.h>
#include <errno.h>
#include "vmm.h"

#define min(a,b) (((a)<(b)) ? (a) : (b))

static grant_entry_v2_t *grant_table  = NULL;
static grant_status_t   *status_table = NULL;
static grant_ref_t       max_ref      = 0;

void init_grants(void)
{
  gnttab_set_version_t svers     = { .version = 2 };
  gnttab_get_version_t gvers     = { .dom = DOMID_SELF };
  gnttab_query_size_t  qsize     = { .dom = DOMID_SELF };
  gnttab_setup_table_t stable    = { .dom = DOMID_SELF };
  gnttab_get_status_frames_t gsf = { .dom = DOMID_SELF };
  int num_stat_frames;
  mfn_t *frames;

  /* we really want to use version 2 of the grant table API */
  assert(HYPERCALL_grant_table_op(GNTTABOP_set_version, &svers, 1) >= 0);
  assert(HYPERCALL_grant_table_op(GNTTABOP_get_version, &gvers, 1) >= 0);
  assert(gvers.version == 2);

  /* figure out how big we can make our grant table */
  assert(HYPERCALL_grant_table_op(GNTTABOP_query_size, &qsize, 1) >= 0);
  assert(qsize.status == GNTST_okay);

  /* allocate the grant table */
  frames = alloca(qsize.max_nr_frames * sizeof(mfn_t));
  stable.nr_frames = qsize.max_nr_frames;
  stable.frame_list.p = frames;
  assert(HYPERCALL_grant_table_op(GNTTABOP_setup_table, &stable, 1) >= 0);
  assert(stable.status == GNTST_okay);
  grant_table = map_frames(frames, qsize.max_nr_frames);

  /* note down the maximum grant reference */
  max_ref = (qsize.max_nr_frames * PAGE_SIZE) / sizeof(grant_entry_v2_t);
  num_stat_frames = qsize.nr_frames;
  max_ref = min(max_ref, (qsize.nr_frames * PAGE_SIZE) / sizeof(uint16_t));

  /* allocate the status table */
  memset(frames, 0, qsize.max_nr_frames * sizeof(mfn_t));
  gsf.nr_frames = num_stat_frames;
  gsf.frame_list.p = frames;
  assert(HYPERCALL_grant_table_op(GNTTABOP_get_status_frames, &gsf, 1) >= 0);
  assert(gsf.status == GNTST_okay);
  status_table = map_frames(frames, num_stat_frames);
}

long alloc_grant(domid_t dom, void *p, uint16_t len, int ro, grant_ref_t *pref)
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

long end_grant(grant_ref_t gref)
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

long map_grants(domid_t dom, int readonly, grant_ref_t *refs, size_t count,
                void **outptr, uint32_t *outhndls, uint64_t *outpaddrs)
{
  gnttab_map_grant_ref_t *args;
  uint16_t flags;
  uint64_t addr;
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

  addr = claim_shared_space(count * 4096);

  flags = GNTMAP_host_map | GNTMAP_application_map;
  if(readonly)
    flags |= GNTMAP_readonly;
  if(outpaddrs)
    flags |= GNTMAP_device_map;

  for(i = 0; i < count; i++) {
    args[i].host_addr = (uintptr_t)addr + (i * PAGE_SIZE);
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
  grant_ref_t i;

  for(i = 0; i < max_ref; i++)
    if( (grant_table[i].hdr.flags & GTF_type_mask) == GTF_invalid ) {
      grant_table[i].hdr.domid = dom;
      grant_table[i].hdr.flags = GTF_accept_transfer;
      return i;
    }

  return -EXFULL;
}

long transfer_frame(domid_t dom, grant_ref_t ref, xen_pfn_t mfn)
{
  gnttab_transfer_t trans = { .mfn = mfn, .domid = dom, .ref = ref };
  long res = HYPERCALL_grant_table_op(GNTTABOP_transfer, &trans, 1);
  return (res < 0) ? res : trans.status;
}

long complete_transfer(grant_ref_t ref, int reset)
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

