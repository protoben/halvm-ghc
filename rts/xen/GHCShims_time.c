// BANNERSTART
// - Copyright 2006-2008, Galois, Inc.
// - This software is distributed under a standard, three-clause BSD license.
// - Please see the file LICENSE, distributed with this software, for specific
// - terms and conditions.
// Author: Adam Wick <awick@galois.com>
// BANNEREND

#include "Rts.h"
#include "GetTime.h"
#include "Ticker.h"
#include "time.h"
#include "limits.h"
#include "arch.h"

// Below to remove warnings.
lnat getourtimeofday(void);
lnat getDelayTarget(HsInt);
// Above to remove warnings.

/* Results to be provided in nanoseconds */
Time getThreadCPUTime(void)
{
  /* monotonic clock is given in nanoseconds */
  return monotonic_clock();
}

/* Results to be provided in nanoseconds */
Time getProcessCPUTime(void)
{
  return monotonic_clock();
}

/* Results to be provided in nanoseconds */
Time getProcessElapsedTime(void)
{
  return monotonic_clock();
}

/* Results to be provided in nanoseconds */
void getProcessTimes(Time *user, Time *elapsed)
{
  *user    = monotonic_clock();
  *elapsed = monotonic_clock();
}

void initializeTimer(void)
{
  /* already handled */
}

/******************************************************************************/

extern volatile TickProc timer0_proc;
       volatile TickProc saved_ticker;

void initTicker  (Time interval __attribute__((unused)), TickProc handle_tick)
{
  saved_ticker = handle_tick;
}

void startTicker (void)
{
  timer0_proc = saved_ticker;
}

void stopTicker  (void)
{
  saved_ticker = timer0_proc;
  timer0_proc = NULL;
}

void exitTicker  ( rtsBool wait __attribute__((unused)) )
{
  saved_ticker = NULL;
}

StgWord64 getMonotonicNSec(void)
{
  return monotonic_clock();
}

/******************************************************************************/

lnat getourtimeofday(void)
{
  //static u64 last_time = 0;
  struct timeval tv;
  u64  work, ticks_per_sec;

  gettimeofday(&tv, (struct timezone *)NULL);
  /* The tickInterval is given in units of TIME_RESOLUTION, which is */
  /* given in Hertz. So we need to translate between the underlying  */
  /* clock information -- given in seconds and microseconds -- into  */
  /* that format and then divide by the tickInterval, hoping not to  */
  /* lose too much precision along the way.                          */
  assert(TIME_RESOLUTION > RtsFlags.MiscFlags.tickInterval);
  /* To get to ticks, we want to multiply the number of seconds by   */
  /* the number of ticks per second.                                 */
  ticks_per_sec = TIME_RESOLUTION / RtsFlags.MiscFlags.tickInterval;
  work          = ticks_per_sec  * tv.tv_sec;
  /* Similarly, we'll want to figure out how many microseconds there */
  /* are per tick.                                                   */
  if(TIME_RESOLUTION > 1000000) {
    /* in this case, our time resolution is finer than a microsecond */
    u64 points_per_usec = TIME_RESOLUTION / 1000000;
    u64 converted_usec  = points_per_usec * tv.tv_usec;
    work               += converted_usec / RtsFlags.MiscFlags.tickInterval;
  } else {
    /* in this case, our time resolution is worse than a microsecond */
    u64 usecs_per_point = 1000000 / TIME_RESOLUTION;
    u64 converted_usec  = tv.tv_usec / usecs_per_point;
    work               += converted_usec / RtsFlags.MiscFlags.tickInterval;
  }

  return (lnat)work;
}
