#define __XEN__
#include <stdint.h>
#include "Rts.h"
#include "Ticker.h"
#include "GetTime.h"
#include <stdlib.h>
#include <time.h>
#include <runtime_reqs.h>
#include "time_rts.h"
#include <signals.h>
#include <xen/xen.h>
#include <xen/vcpu.h>
#include <assert.h>
#include "hypercalls.h"
#include "vcpu.h"

#ifdef __x86_64
# define rmb() asm volatile("lfence" : : : "memory")
#else
# define rmb() asm volatile("lock; addl $0, 0(%%esp)" : : : "memory")
#endif

/* ************************************************************************* */

static uint32_t            timer_echan = 0;
static struct shared_info *shared_info = NULL;

void init_time(struct shared_info *sinfo)
{
  long res = bind_virq(VIRQ_TIMER, 0);
  assert(res >= 0);
  timer_echan = res;
  shared_info = sinfo;
}

static inline uint64_t rdtscll(void)
{
  unsigned long highbits, lowbits;

  asm volatile("rdtsc" : "=a"(lowbits), "=d"(highbits));
  return ((uint64_t)highbits << 32) | (uint64_t)lowbits;
}

static uint64_t monotonic_clock(void)
{
  uint32_t start_version, end_version;
  uint64_t retval = 0;

  do {
    uint64_t now, delta, shift, offset;

    /* if the low bit in the version is set, an update is in progress */
    do { start_version = vcpu_local_info->other_info.time.version; }
         while (start_version & 0x1);
    /* fetch the version when we start */
    start_version = vcpu_local_info->other_info.time.version;
    rmb();
    /* pull in the base system time */
    retval = vcpu_local_info->other_info.time.system_time;
    /* now we figure out the difference between now and when that was written */
    now    = rdtscll();
    delta  = now - vcpu_local_info->other_info.time.tsc_timestamp;
    if(vcpu_local_info->other_info.time.tsc_shift < 0)
      shift = delta >> -vcpu_local_info->other_info.time.tsc_shift;
    else
      shift = delta << vcpu_local_info->other_info.time.tsc_shift;
    offset = (shift * vcpu_local_info->other_info.time.tsc_to_system_mul) >> 32;
    /* now we can add that difference back to our system time */
    retval += offset;
    rmb();
    /* get our end version */
    end_version = vcpu_local_info->other_info.time.version;
    rmb();
    /* if the two values are different, we my have an inconsistent time */
  } while(start_version != end_version);

  return retval;
}

/* ************************************************************************* */

time_t runtime_time()
{
  uint32_t start_version, end_version;
  time_t retval;

  do {
    /* if the low bit in the version is set, an update is in progress */
    do { start_version = vcpu_local_info->other_info.time.version; }
         while (start_version & 0x1);
    rmb();
    retval  = shared_info->wc_sec;
    retval += monotonic_clock() / (10 ^ 9); /* ns -> s */
    rmb();
    end_version = vcpu_local_info->other_info.time.version;
    rmb();
  } while(start_version != end_version);

  return retval;
}

void getProcessTimes(Time *user, Time *elapsed)
{
  uint64_t now = monotonic_clock();
  if(user)    *user    = NSToTime(now);
  if(elapsed) *elapsed = NSToTime(now);
}

/* ************************************************************************* */

void initializeTimer()
{
  /* nothing for the HaLVM */
}

Time getProcessElapsedTime()
{
  return NSToTime(monotonic_clock());
}

Time getProcessCPUTime()
{
  return NSToTime(monotonic_clock());
}

Time getThreadCPUTime()
{
  return NSToTime(monotonic_clock());
}

StgWord64 getMonotonicNSec()
{
  return NSToTime(monotonic_clock());
}

/* ************************************************************************* */

StgWord getDelayTarget(HsInt us /* microseconds */)
{
  Time now = monotonic_clock() / 1000; /* ns -> us */

  /* this checks for an overflow case */
  if(us > ((~0) - now))
    return ~0;

  return now + us;
}

/* ************************************************************************* */

static uint64_t timer_interval = 0;

void initTicker(Time interval, TickProc handle_tick)
{
  /* the interval is given in units of TIME_RESOLUTION, which is essentially */
  /* provided as a hertz value. I could probably assume that it'll remain at */
  /* nanoseconds, but this is a bit more reasonable ... */
  timer_interval = (interval * TIME_RESOLUTION) / 1000000000;
  set_c_handler(timer_echan, handle_tick);
}

void startTicker(void)
{
  HYPERCALL_vcpu_op(VCPUOP_set_periodic_timer, vcpu_num(), &timer_interval);
}

void stopTicker(void)
{
  HYPERCALL_vcpu_op(VCPUOP_stop_periodic_timer, vcpu_num(), &timer_interval);
}

void exitTicker(rtsBool wait __attribute__((unused)))
{
  timer_interval = 0;
  clear_c_handler(timer_echan);
}
