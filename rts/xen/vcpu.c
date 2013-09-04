#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <memory.h>
#include <runtime_reqs.h>
#include <sys/mman.h>
#include <limits.h>
#include "hypercalls.h"
#include "locks.h"
#include "signals.h"
#include "vcpu.h"
#include "vmm.h"
#include "Rts.h"
#include "RtsUtils.h"
#include "Task.h"
#include <xen/xen.h>
#include <xen/vcpu.h>

#define INIT_KEYTAB_SIZE        4096
#define IRQ_STACK_SIZE          (8 * PAGE_SIZE)

static halvm_mutex_t      global_key_table_lock;
static evtchn_port_t     *ipi_ports       = NULL;
static int               *ipi_fired       = NULL;
static uint32_t          *used_keys_start = NULL;
static uint32_t          *used_keys_end   = NULL;
       vcpu_local_info_t *vcpu_local_info = NULL;
static uint32_t           num_vcpus       = 0;
static uint32_t           next_new_vcpu   = 0;

extern void hypervisor_callback(void);
extern void failsafe_callback(void);
static void ipi_handler(int);

void init_smp_system(uint32_t vcpus)
{
  initMutex(&global_key_table_lock);
  used_keys_start = runtime_alloc(NULL, INIT_KEYTAB_SIZE, PROT_READWRITE,
                                        ALLOC_ALL_CPUS);
  assert(used_keys_start);
  used_keys_end = (uint32_t*)((uintptr_t)used_keys_start + INIT_KEYTAB_SIZE);
  memset(used_keys_start, 0xFF, INIT_KEYTAB_SIZE);
  ipi_ports = calloc(vcpus, sizeof(evtchn_port_t));
  ipi_fired = calloc(vcpus, sizeof(int));
  num_vcpus = vcpus;
  next_new_vcpu = 1;
}

void init_vcpu(int num)
{
  vcpu_register_vcpu_info_t vcpu_info;
  vcpu_register_runstate_memory_area_t rstat_info;
  mfn_t linfo_mfn;
  void *p, *stk_top;

  assert(sizeof(vcpu_local_info) < PAGE_SIZE);
  stk_top = (void*)((uintptr_t)VCPU_LOCAL_START + IRQ_STACK_SIZE);

  /* allocate the IRQ stack */
  for(p = VCPU_LOCAL_START; p < stk_top; p = (void*)((uintptr_t)p + 4096)) {
    mfn_t mfn = get_free_frame();
    assert(mfn);
    set_local_pt_entry(num, p, (mfn << PAGE_SHIFT) | STANDARD_RW_PERMS);
  }
  memset(VCPU_LOCAL_START, 0, IRQ_STACK_SIZE);

  /* allocate the local info structure */
  linfo_mfn = get_free_frame();
  assert(linfo_mfn);
  set_local_pt_entry(num, stk_top, (linfo_mfn<<PAGE_SHIFT)|STANDARD_RW_PERMS);
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
  vcpu_info.mfn    = linfo_mfn;
  vcpu_info.offset = __builtin_offsetof(vcpu_local_info_t, other_info);
  vcpu_info.rsvd   = 0;
  assert(HYPERCALL_vcpu_op(VCPUOP_register_vcpu_info, num, &vcpu_info) >= 0);

  /* link over the runstate information for us */
  rstat_info.addr.v = &(vcpu_local_info->runstate_info);
  assert(HYPERCALL_vcpu_op(VCPUOP_register_runstate_memory_area, num,
                           &rstat_info) >= 0);

  /* bind an IPI (inter-processor interrupt) port for us to signal on */
  ipi_ports[num] = bind_ipi(num);
  assert(ipi_ports[num] > 0);
  set_c_handler(ipi_ports[num], ipi_handler);
}

void signal_vcpu(int vcpu)
{
  channel_send(ipi_ports[vcpu]);
}

static void ipi_handler(int port)
{
  printf("Received IPI for VCPU %d on %d\n", vcpu_local_info->vcpu_num, port);
  ipi_fired[vcpu_local_info->vcpu_num] = 1;
}

void wait_for_vcpu_signal(int vcpu)
{
  while(!ipi_fired[vcpu])
    runtime_block(ULONG_MAX);
  assert(ipi_fired[vcpu]);
  ipi_fired[vcpu] = 0;
}

#ifdef THREADED_RTS
void newThreadLocalKey(halvm_vcpukey_t *key)
{
  uint32_t *curptr;
  uintptr_t baseptr, cursize, newsize;

  halvm_acquire_lock(&global_key_table_lock);
 try_again:
  curptr  = used_keys_start;
  baseptr = (uintptr_t)vcpu_local_info->local_vals;
  while((uintptr_t)curptr < (uintptr_t)used_keys_end) {
    uint32_t curval = *curptr;
    int free = __builtin_ffsl(curval);

    if(free) {
      free -= 1; /* ffsl returns lowest set bit + 1 */
      *curptr = curval & ~(1 << free);
      *key = baseptr + (free * sizeof(void*));
      halvm_release_lock(&global_key_table_lock);
      return;
    }

    curptr  = (uint32_t*)((uintptr_t)curptr + sizeof(uint32_t));
    baseptr = baseptr + (32 * sizeof(void*));
  }

  /* we need more room! */
  cursize = (uintptr_t)used_keys_end - (uintptr_t)used_keys_start;
  newsize = cursize + INIT_KEYTAB_SIZE;
  used_keys_start = runtime_realloc(used_keys_start, 1, cursize, newsize);
  memset(used_keys_end, 0xFF, INIT_KEYTAB_SIZE);
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
  used_keys_start[w_ind] = used_keys_start[w_ind] | bit;
  assert(!halvm_release_lock(&global_key_table_lock));
}
#endif // THREADED_RTS

nat getNumberOfProcessors(void)
{
  return num_vcpus;
}

int forkOS_createThread(HsStablePtr entry)
{
  printf("forkOS_createThread(%p)\n", entry);
  return 0; // FIXME
}

#ifdef THREADED_RTS
static void startSubordinateVCPU(uint32_t vcpu_num,
                                 OSThreadProc *startProc,
                                 void *param)
{
  printf("Starting subordinate VCPU #%d\n", vcpu_num);
  init_vcpu(vcpu_num);
  startProc(param);
}

static void subordinateQuit(void)
{
  printf("Reached subordinate quit. Weird.\n");
  while(1) runtime_block(ULONG_MAX);
}

int createOSThread(OSThreadId *pId, OSThreadProc *startProc, void *param)
{
  vcpu_guest_context_t *context = malloc(sizeof(vcpu_guest_context_t));
  unsigned long creg;
  uint32_t vcpu_num;
  void **vcpu_stack;

  vcpu_num = __sync_fetch_and_add(&next_new_vcpu, 1);
  memset(context, 0, sizeof(vcpu_guest_context_t));
  vcpu_stack = runtime_alloc(NULL, STACK_SIZE, PROT_READWRITE, ALLOC_ALL_CPUS);
  vcpu_stack = (void**)((uintptr_t)vcpu_stack + STACK_SIZE);

  /* set some basic domain flags */
  context->flags  = VGCF_i387_valid;
  context->flags |= VGCF_in_kernel;
  context->flags |= VGCF_failsafe_disables_events;
#ifdef __x86_64__
  context->flags |= VGCF_syscall_disables_events;
#endif
  /* set up the user registers */
  context->user_regs.eip = (unsigned long)&startSubordinateVCPU;
  context->user_regs.cs = FLAT_KERNEL_CS;
  context->user_regs.ss = FLAT_KERNEL_SS;
  context->user_regs.ds = FLAT_KERNEL_DS;
  context->user_regs.es = FLAT_KERNEL_DS;
  context->user_regs.fs = FLAT_KERNEL_DS;
  context->user_regs.gs = FLAT_KERNEL_DS;
#ifdef __i386__
  vcpu_stack[-1] = param; /* arg #3 */
  vcpu_stack[-2] = startProc; /* arg #2 */
  vcpu_stack[-3] = (void)vcpu_num; /* arg #1 */
  vcpu_stack[-4] = subordinateQuit; /* works as a return point */
  context->user_regs.esp = (unsigned long)&(vcpu_stack[-5]);
#else
  context->user_regs.rdi = vcpu_num; /* arg #1 */
  context->user_regs.rsi = (unsigned long)startProc;
  context->user_regs.rdx = (unsigned long)param;
  vcpu_stack[-1] = subordinateQuit; /* works as a return point */
  context->user_regs.esp = (unsigned long)&(vcpu_stack[-1]);
#endif
  /* set the control registers */
  asm("mov %%cr0, %0" : "=r"(creg)); context->ctrlreg[0] = creg;
  asm("mov %%cr2, %0" : "=r"(creg)); context->ctrlreg[2] = creg;
  asm("mov %%cr4, %0" : "=r"(creg)); context->ctrlreg[4] = creg;
  /* set up the page table base */
  asm("mov %%cr3, %0" : "=r"(creg));
  context->ctrlreg[3] = vcpu_pt_base(vcpu_num) | (creg & (PAGE_SIZE - 1));
  /* set the callback pointers */
#ifdef __i386__
  context->event_callback_cs = KERNEL_CS;
  context->event_callback_eip = (unsigned long)&hypervisor_callback;
  context->failsafe_callback_cs = KERNEL_CS;
  context->failsafe_callback_eip = (unsigned long)&failsafe_callback;
#else
  context->event_callback_eip = (unsigned long)&hypervisor_callback;
  context->failsafe_callback_eip = (unsigned long)&failsafe_callback;
#endif
  assert( HYPERCALL_vcpu_op(VCPUOP_initialise, vcpu_num, context) >= 0);
  free(context);
  assert( HYPERCALL_vcpu_op(VCPUOP_up, vcpu_num, context) >= 0);

  *pId = vcpu_num;

  return 0;
}

OSThreadId osThreadId(void)
{
  return vcpu_local_info->vcpu_num;
}

void interruptOSThread(OSThreadId id)
{
  printf("interruptOSThread(%d)\n", id);
  // FIXME
}

void shutdownThread(void)
{
  printf("shutdownThread()\n");
  while(1) {}
}

void yieldThread(void)
{
  printf("yieldThread()\n");
  // FIXME
}

rtsBool osThreadIsAlive(OSThreadId id)
{
  vcpu_runstate_info_t rinf;
  long res = HYPERCALL_vcpu_op(VCPUOP_get_runstate_info, id, &rinf);
  if(res < 0)
    return rtsFalse;

  return (rinf.state == RUNSTATE_offline) ? rtsFalse : rtsTrue;
}

void setThreadAffinity(nat n, nat m)
{
  printf("setThreadAffinity(%d, %d)\n", n, m);
  // FIXME
}
#endif
