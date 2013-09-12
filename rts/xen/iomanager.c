#include "Rts.h"
#include "Prelude.h"
#include <assert.h>
#include "iomanager.h"
#include "time_rts.h"
#include "Task.h"
#include "Schedule.h"
#include "vcpu.h"

void setIOManagerControlFd(int fd)
{
  printf("ERROR: Someone called setIOManagerControlFd(%d)\n", fd);
  assert(0);
}

void setIOManagerWakeupFd(int fd)
{
  printf("ERROR: Someone called setIOManagerWakeupFd(%d)\n", fd);
  assert(0);
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

static waiter_t *waiters = NULL;

static void forceSingleShotTimer(void)
{
  if(!waiters)
    return;

  set_vcpu_timer((uint64_t)waiters->target * 1000);
}

void registerWaiter(int usecs, StgStablePtr action)
{
  waiter_t *newWaiter = malloc(sizeof(waiter_t));
  waiter_t *cur, *prev;

  newWaiter->target = getDelayTarget(usecs);
  newWaiter->action = action;

  for(cur = waiters, prev = NULL; cur; prev = cur, cur = cur->next)
    if(cur->target > newWaiter->target) {
      newWaiter->next = cur;
      if(prev) prev->next = newWaiter; else waiters = newWaiter;
      return;
    }

  newWaiter->next = NULL;
  if(prev) prev->next = newWaiter; else waiters = newWaiter;
  forceSingleShotTimer();
}

void checkWaiters()
{
  StgWord now = getDelayTarget(0);
  Task *me = NULL;

  while(waiters && (waiters->target <= now)) {
    waiter_t *next = waiters->next;
    StgClosure *h;
    StgTSO *t;

    if(!me) assert(me = myTask());
    h = (StgClosure*)deRefStablePtr(waiters->action);
    t = createIOThread(me->cap, RtsFlags.GcFlags.initialStkSize, h);
    scheduleThread(me->cap, t);
    /* add the thread */
    free(waiters);
    waiters = next;
  }

  if(me) {
    Task *me = myTask();
    me->wakeup = rtsTrue;
    signalCondition(&me->cond);
  }

  if(waiters) forceSingleShotTimer();
}

void ioManagerDie(void)
{
  if(waiters) {
    printf("WARNING: IO Manager is dying with people waiting to run.\n");
  }
}

void ioManagerStart(void)
{
  /* nothing */
}
#endif
