#ifndef RTS_XEN_HYPERCALLS_H
#define RTS_XEN_HYPERCALLS_H

#include <assert.h>
#include <stdint.h>
#include <sys/types.h>
#include <xen/xen.h>
#include <xen/platform.h>
#include <xen/tmem.h>
#include <xen/event_channel.h>
#include <xen/xsm/flask_op.h>

typedef struct xen_domctl xen_domctl_t;
typedef struct xen_sysctl xen_sysctl_t;

long HYPERCALL_set_trap_table(const struct trap_info traps[]);
long HYPERCALL_mmu_update(const struct mmu_update reqs[],
                          unsigned count, unsigned *done_out,
                          unsigned foreigndom);
long HYPERCALL_set_gdt(const xen_pfn_t frames[], unsigned int entries);
long HYPERCALL_stack_switch(unsigned long ss, unsigned long esp);
long HYPERCALL_set_callbacks(void *event_addr, void *fail_addr);
long HYPERCALL_fpu_taskswitch(int set);
long HYPERCALL_platform_op(const struct xen_platform_op*);
long HYPERCALL_set_debugreg(int regno, unsigned long val);
unsigned long HYPERCALL_get_debugreg(int regno);
long HYPERCALL_update_descriptor(uint64_t ma, uint64_t desc);
long HYPERCALL_memory_op(unsigned int cmd, void *arg);
long HYPERCALL_multicall(multicall_entry_t *entries, int nr_calls);
long HYPERCALL_update_va_mapping(unsigned long va, uint64_t val,
                                 unsigned long fl);
long HYPERCALL_set_timer_op(uint64_t timeout);
long HYPERCALL_xen_version(int cmd, void *buffer);
long HYPERCALL_console_io(int cmd, int count, char *buffer);
long HYPERCALL_grant_table_op(int cmd, void *args, unsigned int count);
long HYPERCALL_vm_assist(unsigned int cmd, unsigned int type);
long HYPERCALL_update_va_mapping_otherdomain(unsigned long va, uint64_t val,
                                             unsigned long fl, domid_t domid);
long HYPERCALL_iret(void);
long HYPERCALL_vcpu_op(int cmd, int vcpuid, void *extra);
#ifdef __x86_64__
long HYPERCALL_set_segment_base(unsigned int which, unsigned long base);
#endif
long HYPERCALL_mmuext_op(struct mmuext_op *op, unsigned int count,
                         unsigned int *pdone, unsigned int foreigndom);
#ifdef XEN_FLASK_INTERFACE_VERSION
long HYPERCALL_xsm_op(xen_flask_op_t *op);
#else
long HYPERCALL_xsm_op(flask_op_t *op);
#endif
long HYPERCALL_nmi_op(int cmd, void *arg);
long HYPERCALL_sched_op(int cmd, void *arg);
long HYPERCALL_callback_op(int cmd, void *arg);
long HYPERCALL_xenoprof_op(int op, void *arg);
long HYPERCALL_event_channel_op(int cmd, void *arg);
long HYPERCALL_physdev_op(int cmd, void *arg);
long HYPERCALL_hvm_op(int op, void *arg);
long HYPERCALL_sysctl(xen_sysctl_t *op);
long HYPERCALL_domctl(xen_domctl_t *op);
long HYPERCALL_kexec_op(unsigned long op, int arg1, void *arg);
long HYPERCALL_tmem_op(tmem_op_t *ops);

#endif
