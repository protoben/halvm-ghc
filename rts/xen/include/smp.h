#ifndef RTS_XEN_SMP_H
#define RTS_XEN_SMP_H

#ifndef __XEN__
#define __XEN__
#endif

#include <stdint.h>
#include <xen/xen.h>
#include <xen/event_channel.h>
#include "locks.h"

#ifdef THREADED_RTS
#define MUNUSED
#else
#define MUNUSED __attribute__((unused))
#endif

#ifdef THREADED_RTS
typedef struct _vcpu_thread vcpu_thread_t;

struct _vcpu_local_info {
  uint32_t          num;
  evtchn_port_t     ipi_port;
  vcpu_thread_t    *cur_thread;
  unsigned long     local_evt_bits[sizeof(unsigned long) * 8];
  struct vcpu_info  info;
} __attribute__((aligned(512)));

typedef struct _vcpu_local_info vcpu_local_info_t;

struct _per_vcpu_data {
  vcpu_local_info_t  *cpuinfo;
  void               *irqstack;
} __attribute__((aligned(16)));

typedef struct _per_vcpu_data per_vcpu_data_t;

static inline vcpu_local_info_t *cpu_info(void)
{
  vcpu_local_info_t *out;
  asm("mov %%fs:0, %0" : "=r"(out));
  return out;
}

#define vcpu_num()        (cpu_info()->num)
#define vcpu_ipi_port()   (cpu_info()->ipi_port)
#define vcpu_cur_thread() (cpu_info()->cur_thread)
#define vcpu_evt_bits(x)  (cpu_info()->local_evt_bits[x])
#define vcpu_info()       (cpu_info()->info)

void init_smp_system(uint32_t);
void unlockThread(vcpu_thread_t *);
void lockCurrentThread(halvm_mutex_t*);
void pokeSleepThread(void);
#else
extern struct shared_info *HYPERVISOR_shared_info;

#define vcpu_num()       (0)
#define vcpu_info()      (HYPERVISOR_shared_info->vcpu_info[0])
#define vcpu_evt_bits(x) (0)
#endif

void sleepUntilWaiter(unsigned long);

#endif
