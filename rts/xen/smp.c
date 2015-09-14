#define __XEN__
#include <assert.h>
#include <errno.h>
#include <runtime_reqs.h>
#include <sys/mman.h>
#include <stdint.h>
#include <string.h>
#include <xen/xen.h>
#include <xen/vcpu.h>

#include "Rts.h"
#include "RtsUtils.h"
#include "rts/OSThreads.h"

#include "hypercalls.h"
#include "locks.h"
#include "memory.h"
#include "signals.h"
#include "smp.h"
#include "time_rts.h"
#include "vmm.h"

#define INIT_KEYTAB_SIZE       1024

#ifdef THREADED_RTS
enum thread_state {
  threadRunning,
  threadReadyToRun,
  threadBlocked,
  threadSleeping,
  threadCreated,
  threadDead
};

struct _vcpu_thread {
  struct _vcpu_thread         *prev;
  struct _vcpu_thread         *next;
  enum thread_state            state;
  void                       **localKeys;
  uintptr_t                    numKeys;
  /* savedStack: valid iff state in [threadBlocked,threadSleeping] */
  void                        *savedStack;
  /* wakeTarget: valid iff state in [threadSleeping] */
  unsigned long                wakeTarget;
  /* startProc/param: validd iff state in [threadCreated] */
  OSThreadProc                *startProc;
  void                        *param;
};

struct _desc {
  uint16_t limit_low;
  uint16_t base_low;
  uint8_t  base_mid;
  uint8_t  type : 4;
  uint8_t  s : 1;
  uint8_t  dpl : 2;
  uint8_t  p : 1;
  uint8_t  limit_high : 4;
  uint8_t  avl : 1;
  uint8_t  l : 1;
  uint8_t  db : 1;
  uint8_t  g : 1;
  uint8_t  base_high;
} __attribute__((packed));
typedef struct _desc desc_t;

#define vcpu_selector(x) (((x) << 3) | (1 << 2))

static halvm_mutex_t  thread_lists_lock;
static vcpu_thread_t *run_queue_start; /* threads waiting to run */
static vcpu_thread_t *run_queue_end;   /* threads waiting to run */
static vcpu_thread_t *sleeping_queue;
static evtchn_port_t *waiting_vcpus;
static uint32_t       num_vcpus;

static halvm_mutex_t  key_table_lock;
static uint32_t       key_table_size;
static uint8_t       *used_keys;

static void startSubordinateVCPU(void);
static void subordinateQuit(void);
static void runNextTask(void);
extern void hypervisor_callback(void);
extern void failsafe_callback(void);

void saveContextAndGo(vcpu_thread_t *);
void restoreContext(vcpu_thread_t *);

void init_smp_system(uint32_t ncpus)
{
  per_vcpu_data_t *percpudata;
  vcpu_thread_t *initialThread;
  vcpu_local_info_t *infos;
  mmuext_op_t setldt;
  desc_t *ldt;
  uint32_t i;

  assert(ncpus < 8192); /* max LDT entries */
  num_vcpus = ncpus;

  initMutex(&thread_lists_lock);
  run_queue_start = NULL;
  run_queue_end   = NULL;
  sleeping_queue  = NULL;
  waiting_vcpus   = calloc(ncpus, sizeof(evtchn_port_t));
  /* we use runtime_alloc here because it gives us back page-aligned addrs */
  percpudata = runtime_alloc(NULL,ncpus*sizeof(per_vcpu_data_t),PROT_READWRITE);
  infos = runtime_alloc(NULL, ncpus*sizeof(vcpu_local_info_t), PROT_READWRITE);
  ldt = runtime_alloc(NULL, ncpus * sizeof(desc_t), PROT_READWRITE);
  memset(percpudata, 0, ncpus * sizeof(per_vcpu_data_t));
  memset(infos, 0, ncpus * sizeof(vcpu_local_info_t));
  memset(ldt, 0, ncpus * sizeof(desc_t));

  initMutex(&key_table_lock);
  key_table_size = INIT_KEYTAB_SIZE;
  used_keys = calloc(key_table_size, sizeof(uint8_t));

  initialThread = malloc(sizeof(vcpu_thread_t));
  initialThread->next = initialThread->prev = NULL;
  initialThread->state = threadRunning;

  for(i = 0; i < ncpus; i++) {
    uintptr_t cpuptr = (uintptr_t)(&percpudata[i]);
    vcpu_register_vcpu_info_t inforeg;
    unsigned long offset, modulus;
    evtchn_port_t ipi_port;

    percpudata[i].cpuinfo = &infos[i];
    percpudata[i].irqstack = runtime_alloc(NULL,IRQ_STACK_SIZE,PROT_READWRITE);

    ipi_port = bind_ipi(i);
    offset  = ipi_port / (sizeof(unsigned long) * 8);
    modulus = ipi_port % (sizeof(unsigned long) * 8);

    infos[i].num = i;
    infos[i].cur_thread = initialThread;
    infos[i].ipi_port = ipi_port;
    infos[i].local_evt_bits[offset] = 1 << modulus;

    inforeg.mfn = (uint64_t)get_pt_entry(&(infos[i].info)) >> PAGE_SHIFT;
    inforeg.offset = (uintptr_t)&(infos[i].info) & (PAGE_SIZE-1);
    assert(HYPERCALL_vcpu_op(VCPUOP_register_vcpu_info, i, &inforeg) >= 0);

    ldt[i].limit_low = sizeof(per_vcpu_data_t);
    ldt[i].type      = 2; /* Data, Read/Write */
    ldt[i].s         = 1; /* code or, in this case, data segment */
    ldt[i].p         = 1; /* present */
    ldt[i].base_low  = cpuptr & 0xFFFF; /* low 16 */
    ldt[i].base_mid  = (cpuptr >> 16) & 0xFF;
    ldt[i].base_high = (cpuptr >> 24) & 0xFF;
  }

  /* the LDT cannot be read/write, so adjust its entries in the page tables */
  for(i = 0; i < ((ncpus * sizeof(desc_t)) + (PAGE_SIZE-1)) / PAGE_SIZE; i++) {
    void *addr = (void*)((uintptr_t)ldt + (i * PAGE_SIZE));
    set_pt_entry(addr, get_pt_entry(addr) & ~PG_READWRITE);
  }

  /* set the LDT in place and load VCPU#0's FS entry */
  setldt.cmd = MMUEXT_SET_LDT;
  setldt.arg1.linear_addr = (unsigned long)ldt;
  setldt.arg2.nr_ents = ncpus;
  assert(HYPERCALL_mmuext_op(&setldt, 1, NULL, DOMID_SELF) >= 0);
  asm("movl %0, %%fs" : : "r"(vcpu_selector(0)));
  assert(cpu_info() == &infos[0]);

  for(i = 1; i < ncpus; i++) {
    vcpu_guest_context_t *context = malloc(sizeof(vcpu_guest_context_t));
    unsigned long creg;
    void **stack;

    stack = runtime_alloc(NULL, VCPU_STACK_SIZE, PROT_READWRITE);
    memset(context, 0, sizeof(vcpu_guest_context_t));
    memset(stack, 0, VCPU_STACK_SIZE);
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
    context->user_regs.fs = vcpu_selector(i);
    context->user_regs.gs = FLAT_KERNEL_DS;
    stack = (void**)((uintptr_t)stack + VCPU_STACK_SIZE);
    stack[-1] = subordinateQuit; /* works as a return point */
    context->user_regs.esp = (unsigned long)&(stack[-1]);
    /* set the control registers */
    asm("mov %%cr0, %0" : "=r"(creg)); context->ctrlreg[0] = creg;
    asm("mov %%cr2, %0" : "=r"(creg)); context->ctrlreg[2] = creg;
    asm("mov %%cr3, %0" : "=r"(creg)); context->ctrlreg[3] = creg;
    asm("mov %%cr4, %0" : "=r"(creg)); context->ctrlreg[4] = creg;
    /* set the LDT */
    context->ldt_base = (unsigned long)ldt;
    context->ldt_ents = ncpus;
    /* set the callback pointers */
#ifdef __i386__
    context->event_callback_cs = FLAT_KERNEL_CS;
    context->event_callback_eip = (unsigned long)&hypervisor_callback;
    context->failsafe_callback_cs = FLAT_KERNEL_CS;
    context->failsafe_callback_eip = (unsigned long)&failsafe_callback;
#else
    context->event_callback_eip = (unsigned long)&hypervisor_callback;
    context->failsafe_callback_eip = (unsigned long)&failsafe_callback;
#endif
    assert( HYPERCALL_vcpu_op(VCPUOP_initialise, i, context) >= 0);
    free(context);
    assert( HYPERCALL_vcpu_op(VCPUOP_up, i, context) >= 0);
  }
}

#define VCPU_LOCAL_STARTU ((uintptr_t)VCPU_LOCAL_START)

static void startSubordinateVCPU()
{
  runNextTask();
}

static void subordinateQuit()
{
  while(1) (void)HYPERCALL_vcpu_op(VCPUOP_down, vcpu_num(), 0);
}

static unsigned long get_sleep_time(void)
{
  unsigned long target = 24 * 60 * 60 * 1000;
  unsigned long now = getDelayTarget(0);
  vcpu_thread_t *thr;

  halvm_acquire_lock(&thread_lists_lock);
  for(thr = sleeping_queue; thr; thr = thr->next) {
    unsigned long candidate = (thr->wakeTarget - now) / 1000;
    if(thr->wakeTarget < now) target = 0;
    if(candidate < target) target = candidate;
  }
  halvm_release_lock(&thread_lists_lock);

  return target;
}

static void runNextTask()
{
  void *p;

  while(1) {
    halvm_acquire_lock(&thread_lists_lock);
    if(run_queue_start) {
      vcpu_thread_t *next_task = run_queue_start;

      /* adjust the head and tail pointers */
      run_queue_start = next_task->next;
      next_task->prev = next_task->next = NULL;
      if(run_queue_start)
        run_queue_start->prev = NULL;
      else
        run_queue_end = NULL;
      /* we're either going to jump somewhere else or die at this point,
         so be nice and release the lock */
      halvm_release_lock(&thread_lists_lock);

      switch(next_task->state) {
        case threadRunning:
          printf("ERROR: Running thread on run queue.\n");
          assert(0);
        case threadReadyToRun:
          next_task->state = threadRunning;
          vcpu_cur_thread() = next_task;
          restoreContext(next_task);
          assert(0); /* should not get here */
        case threadBlocked:
          printf("ERROR: Blocked thread on run queue.\n");
          assert(0);
        case threadSleeping:
          printf("ERROR: Sleeping thread on run queue.\n");
          assert(0);
        case threadCreated:
          vcpu_cur_thread() = next_task;
          p = runtime_alloc(NULL, VCPU_STACK_SIZE, PROT_READWRITE);
#ifdef __x86_64__
          asm("mov %0, %%rsp" : : "r"((uintptr_t)p + VCPU_STACK_SIZE));
#else
          asm("mov %0, %%esp" : : "r"((uintptr_t)p + VCPU_STACK_SIZE));
#endif
          /* I'm not sure enough of the disposition of local variables to */
          /* really trust using them after the stack swap */
          vcpu_cur_thread()->state = threadRunning;
          vcpu_cur_thread()->startProc(
              vcpu_cur_thread()->param);
          shutdownThread(); /* if we get back here, we should just die */
        case threadDead:
          printf("ERROR: Dead thread on run queue.\n");
          assert(0);
        default:
          printf("ERROR: Unacceptable task state on sleeping queue: %d\n",
                 next_task->state);
          assert(0);
      }
    }

    /* block signals before we release the lock, to avoid a signalling race */
    allow_signals(0);
    waiting_vcpus[vcpu_num()] = vcpu_ipi_port();
    __sync_synchronize();
    halvm_release_lock(&thread_lists_lock);
    runtime_block(get_sleep_time()); /* will turn signals back on */
    pokeSleepThread();
  }
}

void newThreadLocalKey(halvm_vcpukey_t *key)
{
  uint32_t i;

  halvm_acquire_lock(&key_table_lock);
  for(i = 0; i < key_table_size; i++)
    if(!used_keys[i]) {
      used_keys[i] = 1;
      *key = i;
      halvm_release_lock(&key_table_lock);
      return;
    }

  /* need to resize */
  used_keys = realloc(used_keys, (key_table_size * 2) * sizeof(uint8_t));
  for(i = key_table_size; i < (key_table_size * 2); i++)
    used_keys[i] = 0;
  *key = key_table_size;
  used_keys[key_table_size] = 1;
  key_table_size = key_table_size * 2;
  halvm_release_lock(&key_table_lock);
}

void *getThreadLocalVar(halvm_vcpukey_t *key)
{
  vcpu_thread_t *me = vcpu_cur_thread();
  uintptr_t index = *key, i;

  assert(me);
  assert(me->state == threadRunning);

  if(me->numKeys > index) {
    return me->localKeys[index];
  }

  me->localKeys = realloc(me->localKeys, (index+1) * sizeof(void*));
  for(i = me->numKeys; i <= index; i++)
    me->localKeys[i] = NULL;
  me->numKeys = index + 1;

  return NULL;
}

void setThreadLocalVar(halvm_vcpukey_t *key, void *value)
{
  vcpu_thread_t *me = vcpu_cur_thread();
  uintptr_t index = *key, i;

  assert(me);
  assert(me->state == threadRunning);

  if(me->numKeys > index) {
    me->localKeys[index] = value;
    return;
  }

  me->localKeys =
    realloc(me->localKeys, (index+1) * sizeof(void*));
  for(i = me->numKeys; i < index; i++)
    me->localKeys[i] = NULL;
  me->numKeys = index + 1;
  me->localKeys[index] = value;
}

void freeThreadLocalKey(halvm_vcpukey_t *key)
{
  /* this is a bit incorrect, as free/get will still get the old value,
     but I don't think it matters in the current GHC usage */
  halvm_acquire_lock(&key_table_lock);
  used_keys[*key] = 0;
  halvm_release_lock(&key_table_lock);
}

nat getNumberOfProcessors(void)
{
  return num_vcpus;
}

int forkOS_createThread(HsStablePtr entry __attribute__((unused)))
{
  printf("ERROR: forkOS_createThread called.\n");
  return 0;
}

int createOSThread(OSThreadId *pid, OSThreadProc *startProc, void *param)
{
  vcpu_thread_t *newt = malloc(sizeof(vcpu_thread_t));
  uint32_t i;

  if(!newt)
    return EAGAIN;

  memset(newt, 0, sizeof(vcpu_thread_t));
  newt->state = threadCreated;
  newt->numKeys = key_table_size;
  newt->localKeys = calloc(newt->numKeys, sizeof(void*));
  newt->startProc = startProc;
  newt->param = param;
  newt->next = newt->prev = NULL;

  halvm_acquire_lock(&thread_lists_lock);
  if(run_queue_start) {
    assert(run_queue_end);
    run_queue_end->next = newt;
    newt->prev = run_queue_end;
    run_queue_end = newt;
  } else {
    assert(!run_queue_end);
    run_queue_start = run_queue_end = newt;
  }
  halvm_release_lock(&thread_lists_lock);

  for(i = 0; i < num_vcpus; i++) {
    evtchn_port_t sleeping = __sync_lock_test_and_set(&(waiting_vcpus[i]), 0);
    if(sleeping) {
      channel_send(sleeping);
      break;
    }
  }

  *pid = newt;
  return 0;
}

OSThreadId osThreadId(void)
{
  return vcpu_cur_thread();
}

void interruptOSThread(OSThreadId id __attribute__((unused)))
{
  printf("ERROR: interruptOSThread called.\n");
}

void shutdownThread(void)
{
  assert(vcpu_cur_thread());
  assert(vcpu_cur_thread()->state == threadRunning);
  assert(!vcpu_cur_thread()->next);
  assert(!vcpu_cur_thread()->prev);
  vcpu_cur_thread()->state = threadDead;
  /* this leaks memory in order to make osThreadIsAlive work ... bad plan? */
  runNextTask();
  __builtin_unreachable();
}

void __attribute__((noinline,noclone)) saveContextAndGo(vcpu_thread_t *thr)
{
#ifdef __x86_64__
  asm volatile ("push %%rbx ;"
                "push %%rbp ;"
                "push %%r12 ;"
                "push %%r13 ;"
                "push %%r14 ;"
                "push %%r15 ;"
                "movq %%rsp, %0 ;"
                "jmp runNextTask"
                : "=m"(thr->savedStack) : : "memory");
#else
  asm volatile ("push %%ebx ;"
                "push %%ebp ;"
                "mov  %%esp, %0 ;"
                "jmp runNextTask"
                : "=m"(thr->savedStack) : : "memory");
#endif
}

void __attribute__((noinline)) restoreContext(vcpu_thread_t *thr)
{
#ifdef __x86_64__
  asm volatile ("mov %0, %%rsp ; "
                "pop %%r15 ; "
                "pop %%r14 ; "
                "pop %%r13 ; "
                "pop %%r12 ; "
                "pop %%rbp ;"
                "pop %%rbx ;"
                : : "m"(thr->savedStack) : "memory");
#else
  asm volatile ("mov %0, %%esp ; "
                "pop %%ebp ;"
                "pop %%ebx ;"
                : : "m"(thr->savedStack) : "memory");
#endif
}

void yieldThread(void)
{
  vcpu_thread_t *me = vcpu_cur_thread();

  halvm_acquire_lock(&thread_lists_lock);
  if(run_queue_end) {
    me->prev = run_queue_end;
    me->next = NULL;
    run_queue_end->next = me;
    run_queue_end = me;
  } else {
    run_queue_start = run_queue_end = me;
  }
  halvm_release_lock(&thread_lists_lock);
  me->state = threadReadyToRun;
  vcpu_cur_thread() = NULL;
  saveContextAndGo(me);
}

void unlockThread(vcpu_thread_t *thr)
{
  halvm_acquire_lock(&thread_lists_lock);
  if(run_queue_end) {
    run_queue_end->next = thr;
    thr->prev = run_queue_end;
    thr->next = NULL;
    run_queue_end = thr;
  } else {
    run_queue_start = run_queue_end = thr;
    thr->next = thr->prev = NULL;
  }
  thr->state = threadReadyToRun;
  halvm_release_lock(&thread_lists_lock);
}

void lockCurrentThread(halvm_mutex_t *lock)
{
  vcpu_thread_t *me = vcpu_cur_thread();

  vcpu_cur_thread() = NULL;
  me->prev = me->next = NULL;
  me->state = threadBlocked;
  halvm_release_lock(lock);
  saveContextAndGo(me);
  halvm_acquire_lock(lock);
}

void sleepUntilWaiter(unsigned long target_us)
{
  vcpu_thread_t *me = vcpu_cur_thread();

  vcpu_cur_thread() = NULL;
  me->prev = NULL;
  me->state = threadSleeping;
  me->wakeTarget = target_us;

  halvm_acquire_lock(&thread_lists_lock);
  me->next = sleeping_queue;
  if(sleeping_queue)
    sleeping_queue->prev = me;
  sleeping_queue = me;
  halvm_release_lock(&thread_lists_lock);

  saveContextAndGo(me);
}

void pokeSleepThread(void)
{
  halvm_acquire_lock(&thread_lists_lock);
  while(sleeping_queue) {
    vcpu_thread_t *cur = sleeping_queue;

    assert(cur->state == threadSleeping);
    cur->state = threadReadyToRun;
    sleeping_queue = sleeping_queue->next;
    if(run_queue_end) {
      cur->prev = run_queue_end;
      cur->next = NULL;
      run_queue_end->next = cur;
      run_queue_end = cur;
    } else {
      run_queue_start = run_queue_end = cur;
      cur->next = cur->prev = NULL;
    }
  }
  halvm_release_lock(&thread_lists_lock);
}

rtsBool osThreadIsAlive(OSThreadId id)
{
  return (id->state != threadDead);
}

void setThreadAffinity(nat n, nat m)
{
  printf("setThreadAffinity(%d, %d)\n", n, m); // FIXME
}
#else
int forkOS_createThread(HsStablePtr entry __attribute__((unused)))
{
  printf("ERROR: forkOS_createThread called.\n");
  return 0;
}

nat getNumberOfProcessors(void)
{
  return 1;
}

void sleepUntilWaiter(unsigned long target_us __attribute__((unused)))
{
}

#endif
