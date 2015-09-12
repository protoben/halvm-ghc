#include "Rts.h"
#include "Prelude.h"
#include <assert.h>
#include "iomanager.h"
#include "time_rts.h"
#include "signals.h"
#include "Task.h"
#include "Schedule.h"
#include "smp.h"

void setIOManagerControlFd(int fd)
{
  printf("ERROR: Someone called setIOManagerControlFd(%d)\n", fd);
}

void setIOManagerWakeupFd(int fd)
{
  printf("ERROR: Someone called setIOManagerWakeupFd(%d)\n", fd);
}

void ioManagerWakeup(void)
{
  /* nothin'! */
}

#ifdef THREADED_RTS
typedef struct waiter {
  struct waiter *next;
  StgWord target;
  StgStablePtr action;
} waiter_t;

static halvm_mutex_t  waiters_lock;
static waiter_t      *waiters = NULL;
#endif

void registerWaiter(HsInt usecs MUNUSED, StgStablePtr action MUNUSED)
{
#ifdef THREADED_RTS
  waiter_t *newWaiter = malloc(sizeof(waiter_t));
  waiter_t *cur, *prev;

  newWaiter->target = getDelayTarget(usecs);
  newWaiter->action = action;

  halvm_acquire_lock(&waiters_lock);
  for(cur = waiters, prev = NULL; cur; prev = cur, cur = cur->next)
    if(cur->target > newWaiter->target) {
      newWaiter->next = cur;
      if(prev) prev->next = newWaiter; else waiters = newWaiter;
      halvm_release_lock(&waiters_lock);
      return;
    }

  newWaiter->next = NULL;
  if(prev) prev->next = newWaiter; else waiters = newWaiter;
  halvm_release_lock(&waiters_lock);
  pokeSleepThread();
#endif
}

StgWord waitForWaiter(StgStablePtr *out MUNUSED)
{
#ifdef THREADED_RTS
  StgStablePtr signal = dequeueSignalHandler();
  unsigned long target;

  if(signal) {
    *out = signal;
    return 0;
  }

  halvm_acquire_lock(&waiters_lock);
  if(waiters && waiters->target <= getDelayTarget(0)) {
    waiter_t *dead = waiters;

    *out = waiters->action;
    waiters = waiters->next;
    halvm_release_lock(&waiters_lock);
    free(dead);

    return 0;
  }
  target = waiters ? waiters->target : getDelayTarget(6000000);
  halvm_release_lock(&waiters_lock);

  return target;
#else
  return NULL;
#endif
}

#ifdef THREADED_RTS
void ioManagerDie(void)
{
  if(waiters) {
    printf("WARNING: IO Manager is dying with people waiting to run.\n");
  }
}

void ioManagerStart(void)
{
  Capability *cap;

  initMutex(&waiters_lock);
  cap = rts_lock();
  rts_evalIO(&cap, &base_GHCziConcziIO_ensureIOManagerIsRunning_closure, NULL);
  rts_unlock(cap);
}
#endif
