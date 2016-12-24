#define __XEN__
#include <hypercalls.h>
#include <xen/xen.h>

#ifdef __i386__
#define HC_RET          "eax"
#define HC_ARG1         "ebx"
#define HC_ARG2         "ecx"
#define HC_ARG3         "edx"
#define HC_ARG4         "esi"
#define HC_ARG5         "edi"
#endif

#ifdef __x86_64__
#define HC_RET          "rax"
#define HC_ARG1         "rdi"
#define HC_ARG2         "rsi"
#define HC_ARG3         "rdx"
#define HC_ARG4         "r10"
#define HC_ARG5         "r8"
#endif

extern struct { char _entry[32]; } hypercall_page[];

#define hypercall(x, a1, a2, a3, a4, a5)                                  \
  ({                                                                         \
     register unsigned long __res  asm(HC_RET);                              \
     register unsigned long __arg1 asm(HC_ARG1) = __arg1;                    \
     register unsigned long __arg2 asm(HC_ARG2) = __arg2;                    \
     register unsigned long __arg3 asm(HC_ARG3) = __arg3;                    \
     register unsigned long __arg4 asm(HC_ARG4) = __arg4;                    \
     register unsigned long __arg5 asm(HC_ARG5) = __arg5;                    \
     __arg1 = (unsigned long)(a1);                                           \
     __arg2 = (unsigned long)(a2);                                           \
     __arg3 = (unsigned long)(a3);                                           \
     __arg4 = (unsigned long)(a4);                                           \
     __arg5 = (unsigned long)(a5);                                           \
     asm volatile ("call hypercall_page+%c[offset]"                          \
                  : "=r"(__res), "+r"(__arg1), "+r"(__arg2), "+r"(__arg3),   \
                    "+r"(__arg4), "+r"(__arg5)                               \
                  : [offset] "i" (__HYPERVISOR_##x * sizeof(hypercall_page[0]))\
                  : "memory");                                                 \
     __res;                                                                    \
   })

long HYPERCALL_mmu_update(const struct mmu_update reqs[],
                          unsigned count, unsigned *done_out,
                          unsigned dom)
{
  return hypercall(mmu_update, (uintptr_t)reqs, count,
                   (uintptr_t)done_out, dom, 0);
}

long HYPERCALL_memory_op(unsigned int cmd, void *arg)
{
  return hypercall(memory_op, cmd, (uintptr_t)arg, 0, 0, 0);
}

long HYPERCALL_console_io(int cmd, int count, char *buffer)
{
  return hypercall(console_io, cmd, count,(uintptr_t)buffer,0,0);
}

long HYPERCALL_vcpu_op(int cmd, int vcpuid, void *extra)
{
  return hypercall(vcpu_op, cmd, vcpuid, (uintptr_t)extra, 0, 0);
}

long HYPERCALL_mmuext_op(struct mmuext_op *op, unsigned int count,
                         unsigned int *pdone, unsigned int foreigndom)
{
  return hypercall(mmuext_op, (uintptr_t)op, count,
                   (uintptr_t)pdone, foreigndom, 0);
}

long HYPERCALL_sched_op(int cmd, void *arg)
{
  return hypercall(sched_op, cmd, (uintptr_t)arg, 0, 0, 0);
}

long HYPERCALL_domctl(xen_domctl_t *op)
{
  return hypercall(domctl, (uintptr_t)op, 0, 0, 0, 0);
}

long HYPERCALL_grant_table_op(int cmd, void *args, unsigned int count)
{
  return hypercall(grant_table_op, cmd, args, count, 0, 0);
}

long HYPERCALL_set_trap_table(const struct trap_info traps[])
{
  return hypercall(set_trap_table, traps, 0, 0, 0, 0);
}

long HYPERCALL_set_callbacks(void *event, void *fail)
{
#ifdef __x86_64__
  return hypercall(set_callbacks, event, fail, 0, 0, 0);
#else
  return hypercall(set_callbacks,FLAT_KERNEL_CS,event,FLAT_KERNEL_CS,fail,0);
#endif
}

long HYPERCALL_event_channel_op(int cmd, void *arg)
{
  return hypercall(event_channel_op, cmd, arg, 0, 0, 0);
}

long HYPERCALL_set_timer_op(uint64_t until)
{
  return hypercall(set_timer_op, until, 0, 0, 0, 0);
}
