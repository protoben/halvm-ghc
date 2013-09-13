#include <errno.h>
#include "locks.h"
#include "vcpu.h"
#include "signals.h"
#include "Rts.h"
#include <runtime_reqs.h>

#define LOCK_FREE             0
#define LOCK_TAKEN            1
#define LOCK_CLOSED           0xbadbadFF

static uint32_t  num_vcpus = 0;

void init_locks(uint32_t vcpus)
{
  num_vcpus = vcpus;
}

int halvm_acquire_lock(halvm_mutex_t *mutex)
{
  unsigned long count = 1;

  while(1) {
    switch(__sync_val_compare_and_swap(mutex, LOCK_FREE, LOCK_TAKEN)) {
      case LOCK_FREE:
        return 0;
      case LOCK_TAKEN:
        break;
      case LOCK_CLOSED:
        return EINVAL;
      default:
        printf("ERROR: Lock in weird state!\n");
        return EINVAL;
    }

    if(!(count && 0xFFF)) {
      runtime_block(0);
    }
  }
}

int halvm_try_acquire_lock(halvm_mutex_t *mutex)
{
  switch(__sync_val_compare_and_swap(mutex, LOCK_FREE, LOCK_TAKEN)) {
    case LOCK_FREE:
      return 0;
    case LOCK_TAKEN:
      return EBUSY;
    case LOCK_CLOSED:
      return EINVAL;
    default:
      printf("ERROR: Lock in weird state (2)\n");
      return EINVAL;
  }
}

int halvm_release_lock(halvm_mutex_t *mutex)
{
  switch(__sync_val_compare_and_swap(mutex, LOCK_TAKEN, LOCK_FREE)) {
    case LOCK_FREE:
      return EINVAL;
    case LOCK_TAKEN:
      return 0;
    case LOCK_CLOSED:
      return EINVAL;
    default:
      printf("ERROR: Lock in weird state (3)\n");
      return EINVAL;
  }
}

/* ************************************************************************* */

void initMutex(halvm_mutex_t *mut)
{
  *mut = LOCK_FREE;
}

void closeMutex(halvm_mutex_t *mut)
{
  *mut = LOCK_CLOSED;
}

/* ************************************************************************* */

/* ************************************************************************* */

#ifdef THREADED_RTS

void initCondition(halvm_condlock_t *cond)
{
  initMutex( &(cond->lock) );
  cond->numWaiters = 0;
  cond->waiters = calloc(num_vcpus, sizeof(halvm_vcpu_t));
}

void closeCondition(halvm_condlock_t *cond)
{
  broadcastCondition(cond); /* flush anyone waiting */
  halvm_acquire_lock( &(cond->lock) );
  free(cond->waiters); cond->waiters = NULL;
  closeMutex( &(cond->lock) );
}

rtsBool broadcastCondition(halvm_condlock_t *cond)
{
  uint32_t i;

  halvm_acquire_lock( &(cond->lock) );
  for(i = 0; i < cond->numWaiters; i++)
    signal_vcpu(cond->waiters[i]);
  cond->numWaiters = 0;
  halvm_release_lock( &(cond->lock) );
  return rtsTrue;
}

rtsBool signalCondition(halvm_condlock_t *cond)
{
  uint32_t i;

  halvm_acquire_lock( &(cond->lock) );
  if(cond->numWaiters > 0) {
    signal_vcpu(cond->waiters[0]);
    for(i = 1; i < cond->numWaiters; i++)
      cond->waiters[i-1] = cond->waiters[i];
    cond->numWaiters -= 1;
  }
  halvm_release_lock( &(cond->lock) );
  return rtsTrue;
}

rtsBool waitCondition(halvm_condlock_t *cond, Mutex *mut)
{
  halvm_acquire_lock( &(cond->lock) );
  allow_signals(0); /* avoid a race with a broadcast on this condlock */
  cond->waiters[cond->numWaiters++] = vcpu_local_info->vcpu_num;
  halvm_release_lock( &(cond->lock) );
  halvm_release_lock(mut);
  wait_for_vcpu_signal(vcpu_local_info->vcpu_num);
  /* we will come out of the block with signals enabled, so no need to */
  /* re-enable. */
  halvm_acquire_lock(mut);
  return rtsTrue;
}

#endif

