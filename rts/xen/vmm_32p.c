#ifdef CONFIG_X86_PAE
#include "vmm.h"
#include "memory.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "hypercalls.h"
#include "locks.h"
#include "smp.h"

static halvm_mutex_t     vmm_lock;
// Information regarding the handy temporary space we use
static pte_t            *temp_table;
static maddr_t           temp_table_pt_entry;
static maddr_t           l3_phys_base;
// The start of where we've been mapped
extern int               _text;

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
  int res;

  flush.cmd = MMUEXT_INVLPG_LOCAL;
  flush.arg1.linear_addr = (unsigned long)temp_table;
  assert(HYPERCALL_mmuext_op(&flush, 1, NULL, DOMID_SELF) >= 0);

  res = mmu_update(temp_table_pt_entry,
                   ENTRY_MADDR(maddr)|PG_PRESENT|PG_USER|flags);
  if(res <= 0) {
    assert(*(void**)(0));
  }
}

void *initialize_vmm(start_info_t *sinfo, void *init_sp)
{
  uintptr_t     l3vb_off  = (uintptr_t)sinfo->pt_base - (uintptr_t)&_text;
  uintptr_t     l3vb_poff = l3vb_off >> PAGE_SHIFT;
  pte_t        *l3_virt_base = (pte_t*)sinfo->pt_base;
  pte_t        *table, entry;
  mfn_t         mfn;
  pfn_t         pfn;

  l3_phys_base = ((pte_t)(p2m_map[l3vb_poff] & 0x7FFFFFFF)) << PAGE_SHIFT;
  // Figure out where the temporary table's page table entry is.
  temp_table   = init_sp;
  entry        = l3_virt_base[VADDR_L3_IDX(temp_table)];
  mfn          = entry >> PAGE_SHIFT;
  pfn          = machine_to_phys_mapping[mfn];
  table        = (pte_t*)((uintptr_t)&_text + (pfn << PAGE_SHIFT)); // L2 table
  entry        = table[VADDR_L2_IDX(temp_table)];
  temp_table_pt_entry = ENTRY_MADDR(entry) + (8 * VADDR_L1_IDX(temp_table));
  initMutex(&vmm_lock);
  return (void*)((uintptr_t)init_sp + PAGE_SIZE);
}

static pte_t create_table_entry(maddr_t table_base, int idx, int level)
{
  mfn_t mfn = get_free_frame();
  mmuext_op_t extreq;
  pte_t retval;

  assert(mfn);

  /* clear the new page table */
  temporarily_map((maddr_t)mfn << PAGE_SHIFT, PG_READWRITE);
  memset(temp_table, 0, PAGE_SIZE);

  /* unmap it; we can't have any writable links mapped */
  assert(mmu_update(temp_table_pt_entry, 0));

  /* pin it */
  extreq.cmd = level;
  extreq.arg1.mfn = mfn;
  assert(HYPERCALL_mmuext_op(&extreq, 1, NULL, DOMID_SELF) >= 0);

  /* write in the value */
  retval = (((pte_t)mfn) << PAGE_SHIFT) | PG_USER | PG_PRESENT | PG_READWRITE;
  assert(mmu_update(table_base + (sizeof(pte_t) * idx), retval));

  return retval;
}

pte_t get_pt_entry(void *addr)
{
   pte_t entry;

   halvm_acquire_lock(&vmm_lock);
   temporarily_map(l3_phys_base, 0);
   entry = temp_table[VADDR_L3_IDX(addr)];
   if(ENTRY_PRESENT(entry)) {
     temporarily_map(ENTRY_MADDR(entry), 0);
     entry = temp_table[VADDR_L2_IDX(addr)];
     if(ENTRY_PRESENT(entry)) {
       temporarily_map(ENTRY_MADDR(entry), 0);
       entry = temp_table[VADDR_L1_IDX(addr)];
       halvm_release_lock(&vmm_lock);
       return entry;
     }
   }

   halvm_release_lock(&vmm_lock);
   return 0;
}

void set_pt_entry(void *addr, pte_t val)
{
  pte_t l3ent, l2ent;

  halvm_acquire_lock(&vmm_lock);
  temporarily_map(l3_phys_base, 0);
  l3ent = temp_table[VADDR_L3_IDX(addr)];
  if(!ENTRY_PRESENT(l3ent)) {
    l3ent = create_table_entry(l3_phys_base, VADDR_L3_IDX(addr),
                               MMUEXT_PIN_L2_TABLE);
  }

  temporarily_map(ENTRY_MADDR(l3ent), 0);
  l2ent = temp_table[VADDR_L2_IDX(addr)];
  if(!ENTRY_PRESENT(l2ent)) {
    l2ent = create_table_entry(ENTRY_MADDR(l3ent), VADDR_L2_IDX(addr),
                               MMUEXT_PIN_L1_TABLE);
  }
  assert(mmu_update(ENTRY_MADDR(l2ent)+(VADDR_L1_IDX(addr)*sizeof(pte_t)),val));
  halvm_release_lock(&vmm_lock);

  /* if(ENTRY_PRESENT(val)) { */
    mmuext_op_t flush;
    flush.cmd = MMUEXT_INVLPG_ALL;
    flush.arg1.linear_addr = (unsigned long)addr;
    assert(HYPERCALL_mmuext_op(&flush, 1, NULL, DOMID_SELF) >= 0);
  /* } */
}

void *machine_to_virtual(uint64_t maddr)
{
  pte_t l3_entry, l2_entry;
  int i, j, k;

  for(i = 0; i < 512; i++) {
    if(i == VADDR_L3_IDX(HYPERVISOR_VIRT_START))
      break;

    temporarily_map(l3_phys_base, 0);
    l3_entry = temp_table[i];
    if(ENTRY_PRESENT(l3_entry)) {
      pte_t l2_table_base = ENTRY_MADDR(l3_entry);

      for(j = 0; j < 512; j++) {
        temporarily_map(l2_table_base, 0);
        l2_entry = temp_table[j];

        if(ENTRY_PRESENT(l2_entry)) {
          pte_t l1_table_base = ENTRY_MADDR(l2_entry);

          temporarily_map(l1_table_base, 0);
          for(k = 0; k < 512; k++) {
            if(ENTRY_PRESENT(temp_table[k])) {
              if(ENTRY_MADDR(maddr) == ENTRY_MADDR(temp_table[k])) {
                void *base = BUILD_ADDR(i, j, k);
                uintptr_t offset = maddr & (PAGE_SIZE-1);
                return (void*)((uintptr_t)base + offset);
              }
            }
          }
        }
      }
    }
  }

  return NULL;
}
#endif
