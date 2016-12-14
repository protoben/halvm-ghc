#include <errno.h>
#include "locks.h"
#include "smp.h"
#include "signals.h"
#include "Rts.h"
#include "sm/GC.h"
#include "RtsSignals.h"
#include "Task.h"
#include <runtime_reqs.h>
#include <assert.h>

#define LOCK_FREE             0
#define LOCK_TAKEN            1
#define LOCK_CLOSED           0xbadbadFF

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
/* the GHC RTS doesn't use the full power of conditional locks. instead,    */
/* it uses them as a handy way to go to sleep or get woken up when a task   */
/* runs out of things to do, while ensuring that a particular lock is held  */
/* when it wakes up. This means, for example, that there's always a maximum */
/* of one person waiting on the lock, which in turn means we can greatly    */
/* simplify our implementation.                                             */
void initCondition(halvm_condlock_t *cond)
{
  initMutex( &(cond->lock) );
  cond->waiter = 0;
  cond->state = CONDLOCK_EMPTY;
}

void closeCondition(halvm_condlock_t *cond)
{
  closeMutex( &(cond->lock) );
}


rtsBool broadcastCondition(halvm_condlock_t *cond __attribute__((unused)))
{
  return rtsTrue;
}

rtsBool signalCondition(halvm_condlock_t *cond)
{
  halvm_acquire_lock( &(cond->lock) );
  if(cond->state == CONDLOCK_WAITING) {
    cond->state = CONDLOCK_SIGNALED;
    unlockThread(cond->waiter);
    cond->waiter = NULL;
  }
  halvm_release_lock( &(cond->lock) );
  return rtsTrue;
}

rtsBool waitCondition(halvm_condlock_t *cond, Mutex *mut)
{
  halvm_acquire_lock( &(cond->lock) );
  halvm_release_lock( mut );
  assert(cond->state != CONDLOCK_WAITING);
  assert(cond->state != CONDLOCK_SIGNALED);
  cond->waiter = vcpu_cur_thread();
  cond->state  = CONDLOCK_WAITING;
  lockCurrentThread( &(cond->lock) );
  assert(cond->state == CONDLOCK_SIGNALED);
  cond->state = CONDLOCK_EMPTY;
  halvm_release_lock( &(cond->lock) );
  halvm_acquire_lock(mut);
  return rtsTrue;
}

#endif

