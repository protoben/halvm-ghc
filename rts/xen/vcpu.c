#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <memory.h>
#include <runtime_reqs.h>
#include <sys/mman.h>
#include "hypercalls.h"
#include "locks.h"
#include "vcpu.h"
#include "vmm.h"

#ifdef THREADED_RTS
#include "ghcplatform.h"
#include "Rts.h"
#include "rts/OSThreads.h"
#else
extern void initMutex(halvm_mutex_t *mutex);
#endif

#define INIT_KEYTAB_SIZE        4096
#define IRQ_STACK_SIZE          (8 * PAGE_SIZE)

static halvm_mutex_t      global_key_table_lock;
static uint32_t          *used_keys_start = NULL;
static uint32_t          *used_keys_end   = NULL;
       vcpu_local_info_t *vcpu_local_info = NULL;

void init_smp_system(void)
{
  initMutex(&global_key_table_lock);
  used_keys_start = runtime_alloc(NULL, INIT_KEYTAB_SIZE, PROT_READWRITE,
                                        ALLOC_ALL_CPUS);
  assert(used_keys_start);
  used_keys_end = (uint32_t*)((uintptr_t)used_keys_start + INIT_KEYTAB_SIZE);
  memset(used_keys_start, 0xFF, INIT_KEYTAB_SIZE);
}

void init_vcpu(int num)
{
  vcpu_register_vcpu_info_t vcpu_info;
  vcpu_register_runstate_memory_area_t rstat_info;
  mfn_t local_info_mfn;
  void *p, *stk_top;

  assert(sizeof(vcpu_local_info) < PAGE_SIZE);
  stk_top = (void*)((uintptr_t)VCPU_LOCAL_START + IRQ_STACK_SIZE);

  /* allocate the IRQ stack */
  for(p = VCPU_LOCAL_START; p < stk_top; p = (void*)((uintptr_t)p + 4096)) {
    mfn_t mfn = get_free_frame();
    assert(mfn);
    set_pt_entry(p, (mfn << PAGE_SHIFT) | STANDARD_RW_PERMS);
  }
  memset(VCPU_LOCAL_START, 0, IRQ_STACK_SIZE);

  /* allocate the local info structure */
  local_info_mfn = get_free_frame();
  assert(local_info_mfn);
  set_pt_entry(stk_top, (local_info_mfn<<PAGE_SHIFT)|STANDARD_RW_PERMS);
  vcpu_local_info = stk_top;

  /* base vcpu structure allocation / initialization */
  memset(vcpu_local_info, 0, sizeof(vcpu_local_info_t));
  vcpu_local_info->vcpu_num = num;
  vcpu_local_info->irq_stack_top = (void*)vcpu_local_info;
  vcpu_local_info->local_keys_allocated =
     (PAGE_SIZE - sizeof(vcpu_local_info_t)) / sizeof(void*);
  memset(vcpu_local_info->local_vals, 0,
         sizeof(void*) * vcpu_local_info->local_keys_allocated);

  /* link over the vcpu_info information for us */
  vcpu_info.mfn    = local_info_mfn;
  vcpu_info.offset = __builtin_offsetof(vcpu_local_info_t, other_info);
  vcpu_info.rsvd   = 0;
  assert(HYPERCALL_vcpu_op(VCPUOP_register_vcpu_info, num, &vcpu_info) >= 0);

  /* link over the runstate information for us */
  rstat_info.addr.v = &(vcpu_local_info->runstate_info);
  assert(HYPERCALL_vcpu_op(VCPUOP_register_runstate_memory_area, num,
                           &rstat_info) >= 0);

}

#ifdef THREADED_RTS
void newThreadLocalKey(halvm_vcpukey_t *key)
{
  uint32_t *curptr;
  uintptr_t baseptr, cursize, newsize;
  int       i;

  assert(!halvm_acquire_lock(&global_key_table_lock));

 try_again:
  curptr  = used_keys_start;
  baseptr = (uintptr_t)&(vcpu_local_info->local_vals);
  while((uintptr_t)curptr < (uintptr_t)used_keys_end) {
    uint32_t curval = *curptr;

    if(curval != 0xFFFFFFFF)
      for(i = 0; i < 32; i++)
        if((curval & (1 << i)) == 0) {
          *curptr = curval | (1 << i);
          *key = baseptr + (i * sizeof(void*));
          assert(!halvm_release_lock(&global_key_table_lock));
          return;
        }

    curptr  = (uint32_t*)((uintptr_t)curptr + sizeof(uint32_t));
    baseptr = baseptr + (32 * sizeof(void*));
  }

  /* we need more room! */
  cursize = (uintptr_t)used_keys_end - (uintptr_t)used_keys_start;
  newsize = cursize + INIT_KEYTAB_SIZE;
  used_keys_start = runtime_realloc(used_keys_start, cursize, newsize);
  memset(used_keys_end, 0, INIT_KEYTAB_SIZE);
  used_keys_end = (uint32_t*)((uintptr_t)used_keys_start + newsize);
  goto try_again;
}

void *getThreadLocalVar(halvm_vcpukey_t *key)
{
  uintptr_t  numval = *key;
  void      *ptrval = (void*)numval;
  pte_t      entry  = get_pt_entry(ptrval);

  if(entry & PG_PRESENT)
    return *(void**)ptrval;
  else
    return NULL;
}

void setThreadLocalVar(halvm_vcpukey_t *key, void *value)
{
  uintptr_t  numval = *key;
  void      *ptrval = (void*)numval;
  pte_t      entry  = get_pt_entry(ptrval);

  if( !(entry & PG_PRESENT) ) {
    mfn_t mfn = get_free_frame();
    set_pt_entry(ptrval, (mfn << PAGE_SHIFT) | STANDARD_RW_PERMS);
    memset((void*)(numval & ~(PAGE_SIZE - 1)), 0, PAGE_SIZE);
  }

  *(void**)ptrval = value;
}

void freeThreadLocalKey(halvm_vcpukey_t *key)
{
  uintptr_t offset = *key - (uintptr_t)vcpu_local_info->local_vals;
  uintptr_t index  = offset / sizeof(void*);
  uintptr_t w_ind  = index / 32;
  uintptr_t b_ind  = index & 31;
  uint32_t  bit    = 1 << b_ind;

  assert(!halvm_acquire_lock(&global_key_table_lock));
  used_keys_start[w_ind] = used_keys_start[w_ind] & ~bit;
  assert(!halvm_release_lock(&global_key_table_lock));
}
#endif // THREADED_RTS

