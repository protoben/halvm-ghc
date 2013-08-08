#ifdef CONFIG_X86_64
#include "vmm.h"
#include "memory.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "hypercalls.h"
#include "locks.h"
#include "vcpu.h"

struct local_pts {
  pte_t local_l4_physaddr;
  pte_t local_l3_physaddr;
  pte_t local_l2_physaddr;
  pte_t local_l1_physaddr;
};

static halvm_mutex_t     vmm_lock;
// Information regarding the handy temporary space we use
static pte_t            *temp_table;
static maddr_t           temp_table_pt_entry;
// Information about the local page tables we use per VCPU
static struct local_pts *local_pts;
static uint32_t          num_local_pts;
// The start of where we've been mapped
extern int               _text;

extern void initMutex(halvm_mutex_t *mutex);

static inline int mmu_update(uint64_t ptr, uint64_t val)
{
  mmu_update_t update;
  update.ptr = ptr;
  update.val = val;
  return HYPERCALL_mmu_update(&update, 1, NULL, DOMID_SELF) >= 0;
}

static void temporarily_map(maddr_t maddr, maddr_t flags)
{
  mmuext_op_t flush;

  flush.cmd = MMUEXT_INVLPG_LOCAL;
  flush.arg1.linear_addr = (unsigned long)temp_table;
  assert(HYPERCALL_mmuext_op(&flush, 1, NULL, DOMID_SELF) >= 0);

  assert(mmu_update(temp_table_pt_entry,
                    ENTRY_MADDR(maddr)|PG_PRESENT|PG_USER|flags));

}

static void unmap_temporary(void)
{
  assert(mmu_update(temp_table_pt_entry, 0));
}

static void set_mfn_as_page_table(xen_pfn_t mfn, unsigned int cmd)
{
  mmuext_op_t pin;

  pin.cmd = cmd;
  pin.arg1.mfn = mfn;
  assert(HYPERCALL_mmuext_op(&pin, 1, NULL, DOMID_SELF) >= 0);
}

static void copy_mfn(xen_pfn_t mfn1, xen_pfn_t mfn2)
{
  gnttab_copy_t copy;

  copy.source.u.gmfn = mfn1;
  copy.source.domid  = DOMID_SELF;
  copy.source.offset = 0;
  copy.dest.u.gmfn   = mfn2;
  copy.dest.domid    = DOMID_SELF;
  copy.dest.offset   = 0;
  copy.len           = 4096;
  copy.flags         = 0;
  copy.status        = 0;
  assert(HYPERCALL_grant_table_op(GNTTABOP_copy, &copy, 1) >= 0);
  assert(copy.status == GNTST_okay);
}

static xen_pfn_t create_new_pagetable(pte_t first,
                                      xen_pfn_t base,
                                      unsigned int level)
{
  xen_pfn_t mfn = get_free_frame();

  if(base) {
    copy_mfn(base, mfn);
    temporarily_map(mfn << PAGE_SHIFT, PG_READWRITE);
  } else {
    temporarily_map(mfn << PAGE_SHIFT, PG_READWRITE);
    memset(temp_table, 0, PAGE_SIZE);
  }

  temp_table[0] = first;
  unmap_temporary();

  set_mfn_as_page_table(mfn, level);
  return mfn;
}

void *initialize_vmm(start_info_t *sinfo, uint32_t num_vcpus, void *init_sp)
{
  uintptr_t     l4vb_off  = (uintptr_t)sinfo->pt_base - (uintptr_t)&_text;
  uintptr_t     l4vb_poff = l4vb_off >> PAGE_SHIFT;
  pte_t        *l4_virt_base = (pte_t*)sinfo->pt_base;
  maddr_t       l4_phys_base = p2m_map[l4vb_poff] << PAGE_SHIFT;
  pte_t        *table, entry;
  mfn_t         mfn;
  pfn_t         pfn;
  uint64_t      i;

  // Figure out where the temporary table's page table entry is.
  temp_table = init_sp;
  entry      = l4_virt_base[VADDR_L4_IDX(temp_table)];
  mfn        = entry >> PAGE_SHIFT;
  pfn        = machine_to_phys_mapping[mfn];
  table      = (pte_t*)((uintptr_t)&_text + (pfn << PAGE_SHIFT)); // L3
  entry      = table[VADDR_L3_IDX(temp_table)];
  mfn        = entry >> PAGE_SHIFT;
  pfn        = machine_to_phys_mapping[mfn];
  table      = (pte_t*)((uintptr_t)&_text + (pfn << PAGE_SHIFT)); // L2
  entry      = table[VADDR_L2_IDX(temp_table)];
  temp_table_pt_entry = ENTRY_MADDR(entry) + (8 * VADDR_L1_IDX(temp_table));
  initMutex(&vmm_lock);

  // Figure out the memory for our page table maps
  num_local_pts = num_vcpus;
  local_pts     = (struct local_pts *)((uintptr_t)init_sp + PAGE_SIZE);

  // Initialize the VCPU information for VCPU0.
  local_pts[0].local_l4_physaddr = l4_phys_base;
  if(ENTRY_PRESENT(l4_virt_base[0])) {
    /* in this case, there is an L3 table around that we should use. */
    local_pts[0].local_l3_physaddr = ENTRY_MADDR(l4_virt_base[0]);
    /* We also need to map it to get the L2 address, if possible.    */
    temporarily_map(local_pts[0].local_l3_physaddr, 0);
    if(ENTRY_PRESENT(temp_table[0])) {
      /* OK, so there is an L2 table in evidence that we should use. */
      local_pts[0].local_l2_physaddr = ENTRY_MADDR(temp_table[0]);
    } else {
      /* there was not an L2 table, so we need to build one */
      mfn = create_new_pagetable(0, 0, MMUEXT_PIN_L2_TABLE);
      local_pts[0].local_l2_physaddr = ENTRY_MADDR(temp_table[0]);
      /* and we need to update the L3 table */
      assert(mmu_update(local_pts[0].local_l3_physaddr,
                        (mfn << PAGE_SHIFT) | STANDARD_RW_PERMS));
    }
  } else {
    /* there was not an L3 table or, necessarily, an L2 table */
    mfn = create_new_pagetable(0, 0, MMUEXT_PIN_L2_TABLE);
    local_pts[0].local_l2_physaddr = mfn << PAGE_SHIFT;
    mfn = create_new_pagetable((mfn << PAGE_SHIFT) | STANDARD_RW_PERMS, 0,
                               MMUEXT_PIN_L3_TABLE);
    local_pts[0].local_l3_physaddr = mfn << PAGE_SHIFT;
    /* and we need to update the L4 table */
    assert(mmu_update(local_pts[0].local_l3_physaddr,
                      (mfn << PAGE_SHIFT) | STANDARD_RW_PERMS));
  }
  temporarily_map(local_pts[0].local_l2_physaddr, 0);
  assert(!ENTRY_PRESENT(temp_table[0]));
  mfn = create_new_pagetable(0, 0, MMUEXT_PIN_L1_TABLE);
  local_pts[0].local_l1_physaddr = mfn << PAGE_SHIFT;
  assert(mmu_update(local_pts[0].local_l2_physaddr,
                    (mfn << PAGE_SHIFT) | STANDARD_RW_PERMS));

  // Initialize the VCPU information for all the subordinate VCPUs.
  for(i = 1; i < num_vcpus; i++) {
    mfn = create_new_pagetable(0, 0, MMUEXT_PIN_L1_TABLE);
    local_pts[i].local_l1_physaddr = mfn << PAGE_SHIFT;
    mfn = create_new_pagetable((mfn << PAGE_SHIFT) | STANDARD_RW_PERMS,
                               local_pts[0].local_l2_physaddr >> PAGE_SHIFT,
                               MMUEXT_PIN_L2_TABLE);
    local_pts[i].local_l2_physaddr = mfn << PAGE_SHIFT;
    mfn = create_new_pagetable((mfn << PAGE_SHIFT) | STANDARD_RW_PERMS,
                               local_pts[0].local_l3_physaddr >> PAGE_SHIFT,
                               MMUEXT_PIN_L3_TABLE);
    local_pts[i].local_l3_physaddr = mfn << PAGE_SHIFT;
    mfn = create_new_pagetable((mfn << PAGE_SHIFT) | STANDARD_RW_PERMS,
                               local_pts[0].local_l4_physaddr >> PAGE_SHIFT,
                               MMUEXT_PIN_L4_TABLE);
    local_pts[i].local_l4_physaddr = mfn << PAGE_SHIFT;
  }

  return (void*)((uintptr_t)init_sp + PAGE_SIZE +
                            (num_vcpus * sizeof(struct local_pts)));
}

static pte_t create_table_entry(maddr_t table_base, int idx, int level)
{
  mfn_t mfn = get_free_frame();
  mmuext_op_t extreq;
  pte_t retval;

  assert(mfn);

  /* clear the new page table */
  temporarily_map(mfn << PAGE_SHIFT, PG_READWRITE);
  memset(temp_table, 0, PAGE_SIZE);

  /* unmap it; we can't have any writable links mapped */
  assert(mmu_update(temp_table_pt_entry, 0));

  /* pin it */
  extreq.cmd = level;
  extreq.arg1.mfn = mfn;
  assert(HYPERCALL_mmuext_op(&extreq, 1, NULL, DOMID_SELF) >= 0);

  /* write in the value */
  retval = (mfn << PAGE_SHIFT) | PG_USER | PG_PRESENT | PG_READWRITE;
  assert(mmu_update(table_base + (64 * idx), retval));

  return retval;
}

pte_t get_pt_entry(void *addr)
{
   pte_t entry;

   halvm_acquire_lock(&vmm_lock);
   temporarily_map(local_pts[vcpu_num()].local_l4_physaddr, 0);
   entry = temp_table[VADDR_L4_IDX(addr)];
   if(ENTRY_PRESENT(entry)) {
     temporarily_map(ENTRY_MADDR(entry), 0);
     entry = temp_table[VADDR_L3_IDX(addr)];
     if(ENTRY_PRESENT(entry)) {
       temporarily_map(ENTRY_MADDR(entry), 0);
       entry = temp_table[VADDR_L2_IDX(addr)];
       if(ENTRY_PRESENT(entry)) {
         pte_t retval;

         temporarily_map(ENTRY_MADDR(entry), 0);
         retval = temp_table[VADDR_L1_IDX(addr)];
         halvm_release_lock(&vmm_lock);
         return retval;
       }
     }
   }

   halvm_release_lock(&vmm_lock);
   return 0;
}

static inline void set_local_pt_entry(void *addr, pte_t new_val)
{
  assert(mmu_update(local_pts[vcpu_num()].local_l1_physaddr +
                     (VADDR_L1_IDX(addr) * sizeof(pte_t)),
                    new_val));
}

static inline void set_dupped_pt_entry(void *addr, pte_t val)
{
  pte_t l3_base = local_pts[vcpu_num()].local_l3_physaddr, l2_base, l1_base;

  /* grab the lock, and make sure the world is sane */
  halvm_acquire_lock(&vmm_lock);
  assert(VADDR_L4_IDX(addr) == 0);

  temporarily_map(l3_base, 0);
  if(!ENTRY_PRESENT(temp_table[VADDR_L3_IDX(addr)])) {
    /* this address has neither an L2 or an L1 table. */
    xen_pfn_t l2_mfn, l1_mfn;
    uint32_t i;

    l2_mfn = create_new_pagetable(0, 0, MMUEXT_PIN_L2_TABLE);
    l1_mfn = create_new_pagetable(0, 0, MMUEXT_PIN_L1_TABLE);
    l2_base = l2_mfn << PAGE_SHIFT; l1_base = l1_mfn << PAGE_SHIFT;
    assert(mmu_update( l1_base + (sizeof(pte_t) * VADDR_L1_IDX(addr)), val));
    assert(mmu_update( l2_base + (sizeof(pte_t) * VADDR_L2_IDX(addr)),
                       l1_base | PG_PRESENT | PG_USER | PG_READWRITE));

    for(i = 0; i < num_local_pts; i++) {
      l3_base = local_pts[i].local_l3_physaddr;
      assert(mmu_update( l3_base + (sizeof(pte_t) * VADDR_L3_IDX(addr)),
                         l2_base | PG_PRESENT | PG_USER | PG_READWRITE));
    }
    halvm_release_lock(&vmm_lock);
    return;
  }

  l2_base = ENTRY_MADDR(temp_table[VADDR_L3_IDX(addr)]);
  temporarily_map(l2_base, 0);
  if(!ENTRY_PRESENT(temp_table[VADDR_L2_IDX(addr)])) {
    /* this address needs an L1 table created. because we share L2 tables */
    /* we shouldn't need to loop around like the previous !present case */
    xen_pfn_t l1_mfn;

    l1_mfn = create_new_pagetable(0, 0, MMUEXT_PIN_L1_TABLE);
    l1_base = l1_mfn << PAGE_SHIFT;
    assert(mmu_update(l1_base + (sizeof(pte_t) * VADDR_L1_IDX(addr)), val));
    assert(mmu_update(l2_base + (sizeof(pte_t) * VADDR_L2_IDX(addr)),
                      l1_base | PG_PRESENT | PG_USER | PG_READWRITE));
    halvm_release_lock(&vmm_lock);
    return;
  }

  l1_base = ENTRY_MADDR(temp_table[VADDR_L2_IDX(addr)]);
  assert(mmu_update(l1_base + (sizeof(pte_t) * VADDR_L1_IDX(addr)), val));
}

static inline void set_global_pt_entry(void *addr, pte_t new_val)
{
  pte_t l4_entry, l3_entry, l2_entry;
  halvm_acquire_lock(&vmm_lock);

  printf("set_global_pt_entry(%p, %lx)\n", addr, new_val);
  temporarily_map(local_pts[vcpu_num()].local_l4_physaddr, 0);
  l4_entry = temp_table[VADDR_L4_IDX(addr)];
  if(!ENTRY_PRESENT(l4_entry))
    l4_entry = create_table_entry(local_pts[vcpu_num()].local_l4_physaddr,
                                  VADDR_L4_IDX(addr), MMUEXT_PIN_L3_TABLE);

  temporarily_map(ENTRY_MADDR(l4_entry), 0);
  l3_entry = temp_table[VADDR_L3_IDX(addr)];
  if(!ENTRY_PRESENT(l3_entry))
    l3_entry = create_table_entry(ENTRY_MADDR(l4_entry), VADDR_L3_IDX(addr),
                                  MMUEXT_PIN_L2_TABLE);

  temporarily_map(ENTRY_MADDR(l3_entry), 0);
  l2_entry = temp_table[VADDR_L2_IDX(addr)];
  if(!ENTRY_PRESENT(l2_entry))
    l2_entry = create_table_entry(ENTRY_MADDR(l3_entry), VADDR_L2_IDX(addr),
                                  MMUEXT_PIN_L1_TABLE);

  assert(mmu_update(ENTRY_MADDR(l2_entry) +
                       (VADDR_L1_IDX(addr) * sizeof(pte_t)),
                    new_val));

  halvm_release_lock(&vmm_lock);
}

void set_pt_entry(void *addr_unaligned, pte_t new_val)
{
  void *addr = (void*)((uintptr_t)addr_unaligned & (~(PAGE_SIZE-1)));

  assert(addr);
  if( ((uintptr_t)addr >= (uintptr_t)VCPU_LOCAL_START) &&
      ((uintptr_t)addr <  (uintptr_t)VCPU_LOCAL_END) )
    set_local_pt_entry(addr, new_val);
  else if( ((uintptr_t)addr >= (uintptr_t)VCPU_LOCAL_END) &&
           ((uintptr_t)addr <  (uintptr_t)GLOBAL_TABLE_START) )
    set_dupped_pt_entry(addr, new_val);
  else
    set_global_pt_entry(addr, new_val);

  if(ENTRY_PRESENT(new_val)) {
    mmuext_op_t flush;
    flush.cmd = MMUEXT_INVLPG_ALL;
    flush.arg1.linear_addr = (unsigned long)addr;
    assert(HYPERCALL_mmuext_op(&flush, 1, NULL, DOMID_SELF) >= 0);
  }

  halvm_release_lock(&vmm_lock);
}

#endif
