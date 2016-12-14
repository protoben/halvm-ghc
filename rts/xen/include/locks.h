#ifndef RTS_XEN_LOCKS_H
#define RTS_XEN_LOCKS_H

#include <stdint.h>

typedef uint32_t             halvm_mutex_t;
typedef struct _vcpu_thread *halvm_vcpu_t;

struct condlock {
  halvm_mutex_t        lock;
  struct _vcpu_thread *waiter;
  uint32_t             state;
};

#define CONDLOCK_EMPTY        1
#define CONDLOCK_WAITING      2
#define CONDLOCK_SIGNALED     3

typedef struct condlock halvm_condlock_t;
typedef uintptr_t       halvm_vcpukey_t;

int  halvm_acquire_lock(halvm_mutex_t *mutex);
int  halvm_try_acquire_lock(halvm_mutex_t *mutex);
int  halvm_release_lock(halvm_mutex_t *mutex);

#ifndef THREADED_RTS
void initMutex(halvm_mutex_t *);
void closeMutex(halvm_mutex_t *);
#endif

#endif
