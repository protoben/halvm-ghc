#ifndef RTS_XEN_VCPU_H
#define RTS_XEN_VCPU_H

#ifndef __XEN__
#define __XEN__
#endif

#include <sys/types.h>
#include <stdint.h>
#include <xen/xen.h>
#include <xen/vcpu.h>

struct vcpu_local_info {
  uint32_t              vcpu_num; /* what VCPU this is */
  unsigned long         local_evt_bits[sizeof(unsigned long)];
  void*                 irq_stack_top;
  uint64_t              timer_target;
  vcpu_runstate_info_t  runstate_info;
  struct vcpu_info      other_info;
  uintptr_t             local_keys_allocated;
  void                 *local_vals[0];
};

#define VCPU_KEY_FREE_LIST_END        ((uintptr_t)(-1))

typedef struct vcpu_local_info vcpu_local_info_t;

extern vcpu_local_info_t *vcpu_local_info;

#define vcpu_num() (vcpu_local_info ? vcpu_local_info->vcpu_num : 0)

void init_smp_system(uint32_t);
void init_vcpu(int);
void signal_vcpu(int);
void wait_for_vcpu_signal(int);
void set_vcpu_timer(uint64_t);

#endif