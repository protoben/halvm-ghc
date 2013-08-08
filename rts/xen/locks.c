#include <errno.h>
#include "locks.h"
#include "vcpu.h"
#include "Rts.h"

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
      threadYield();
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
  printf("initCondition()\n");
  // FIXME
}

void closeCondition(halvm_condlock_t *cond)
{
  printf("closeCondition()\n");
  // FIXME
}

rtsBool broadcastCondition(halvm_condlock_t *cond)
{
  printf("broadcastCondition()\n");
  // FIXME
}

rtsBool signalCondition(halvm_condlock_t *cond)
{
  printf("signalCondition()\n");
  // FIXME
}

rtsBool waitCondition(halvm_condlock_t *cond, Mutex *mut)
{
  printf("waitCondition()\n");
  // FIXME
}

#endif

