// BANNERSTART
// - Copyright 2006-2008, Galois, Inc.
// - This software is distributed under a standard, three-clause BSD license.
// - Please see the file LICENSE, distributed with this software, for specific
// - terms and conditions.
// Author: Adam Wick <awick@galois.com>
// BANNEREND

#include <Rts.h>
#include "AwaitEvent.h"
#include "Schedule.h"
#include "errno.h"
#include "time.h"
#include "limits.h"

lnat getDelayTarget(HsInt);

static void *saved_termios[3] = { NULL, NULL, NULL };

void *__hscore_get_saved_termios(int fd)
{
  if(0 <= fd && fd < 3)
    return saved_termios;
  else
    return NULL;
}

void __hscore_set_saved_termios(int fd, void *ts)
{
  if(0 <= fd && fd < 3)
    saved_termios[fd] = ts;
}

extern lnat getourtimeofday(void);
extern void startSignalHandlers(Capability *cap);

nat getNumberOfProcessors(void) {
    return 1;
}

int forkOS_createThread( HsStablePtr entry __attribute__((unused)) )
{
  return ENOSYS;
}

/* The POSIX implementation of the following two routines switch between     */
/* different time units based on whether we're on a 32-bit or 64-bit         */
/* architecture. They use milliseconds for 32-bit machines and nanoseconds   */
/* for 64-bit machines, I believe. This gives us counter sizes of:           */
/*     2^32 - 1 milliseconds = ~50 days                                      */
/*     2^64 - 1 nanoseconds  = ~223,504 days                                 */
/* This is probably reasonable, so we'll copy this concept.                  */
#if SIZEOF_VOID_P == 4
# define MS_TO_TARGET(x)                ((x) / 1000)
# define TARGET_TO_MILLS(x)             (x)
# define TARGET_HZ                      1000
#else
# define MS_TO_TARGET(x)                ((x) * 1000)
# define TARGET_TO_MILLS(x)             ((x) / 1000000)
# define TARGET_HZ                      1000000000
#endif
static lnat microseconds_to_target(HsInt us)
{
  return MS_TO_TARGET(us);
}

static lnat ticks_to_target(lnat ticks)
{
  lnat ticksPerSec = TIME_RESOLUTION / RtsFlags.MiscFlags.tickInterval;

  if(ticksPerSec > TARGET_HZ) {
    /* In this case, the tick time resolution is finer than we want. */
    lnat ticksPerTime = ticksPerSec / TARGET_HZ;
    return ticks / ticksPerTime;
  } else {
    /* In this case, the tick time resolution is coarser than we want */
    lnat timePerTick = TARGET_HZ / ticksPerSec;
    return ticks * timePerTick;
  }
}

/* given a delay provided in microseconds, compute the target wake-up time.   */
lnat getDelayTarget(HsInt us)
{
  lnat now = getourtimeofday(); /* given in ticks */

  return microseconds_to_target(us) + ticks_to_target(now);
}

#ifndef THREADED_RTS
static rtsBool wakeUpSleepingThreads(lnat ticks)
{
  StgTSO *tso;
  rtsBool flag = rtsFalse;
  lnat now = ticks_to_target(ticks);

  while(sleeping_queue != END_TSO_QUEUE &&
        ((long)now - (long)sleeping_queue->block_info.target) > 0)
  {
    tso = sleeping_queue;
    sleeping_queue = tso->_link;
    tso->why_blocked = NotBlocked;
    tso->_link = END_TSO_QUEUE;
    pushOnRunQueue(&MainCapability, tso);
    flag = rtsTrue;
  }

  return flag;
}

void awaitEvent(rtsBool wait)
{
  do {
    lnat ticks = getourtimeofday();

    /* anyone sleeping that should wake up now? */
    if(wakeUpSleepingThreads(ticks))
      return;

    /* block for a bit, if people are OK waiting */
    if(wait) {
      lnat wait_amt = 0;

      if(sleeping_queue != END_TSO_QUEUE) {
        lnat amt = sleeping_queue->block_info.target - ticks_to_target(ticks);
        /* turn this back into milliseconds, the unit for block_domain */
        wait_amt = TARGET_TO_MILLS(amt);
      } else {
        wait_amt = LONG_MAX;
      }
      block_domain(wait_amt);
    }

    /* if there are any signals pending, schedule them */
    if(signals_pending()) {
      startSignalHandlers(&MainCapability);
      return; /* still hold the lock */
    }

    /* we were interrupted, return to the scheduler immediately. */
    if(sched_state >= SCHED_INTERRUPTING) {
      return; /* still hold the lock */
    }

    /* check for threads that need waking up */
    wakeUpSleepingThreads(getourtimeofday());
  } while( wait && (sched_state == SCHED_RUNNING) 
                && emptyRunQueue(&MainCapability) );
}
#endif

#ifdef THREADED_RTS
static inline uint32_t atomic_cas_u32(uint32_t *ptr, uint32_t old, uint32_t new)
{
    unsigned long res;

    __asm__(
       "lock cmpxchgl %%ecx, (%%edx)"
     : "=a" (res) /* OUT: eax -> res */
     : "a" (old) /* IN: eax = old */, 
       "c" (new) /* IN: ecx = new */,
       "d" (ptr) /* IN: edx = ptr */
     : "memory"
    );

    return res;
}

void halvm_acquire_lock(Mutex *m)
{
  while(atomic_cas_u32(m, 0, 1)) { }
}

void halvm_release_lock(Mutex *m)
{
  *m = 0;
}

void initMutex(Mutex *m)
{
  *m = 0;
}

void closeMutex(Mutex *m)
{
  *m = 0;
}

#endif
