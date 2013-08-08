#ifndef RTS_XEN_LOCKS_H
#define RTS_XEN_LOCKS_H

#include <stdint.h>

typedef uint32_t  halvm_condlock_t;
typedef uint32_t  halvm_mutex_t;
typedef uint32_t  halvm_vcpu_t;
typedef uintptr_t halvm_vcpukey_t;

int  halvm_acquire_lock(halvm_mutex_t *mutex);
int  halvm_try_acquire_lock(halvm_mutex_t *mutex);
int  halvm_release_lock(halvm_mutex_t *mutex);

#endif
