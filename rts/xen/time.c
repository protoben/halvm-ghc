#define __XEN__
#include <stdint.h>
#include "Rts.h"
#include "Ticker.h"
#include "GetTime.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <runtime_reqs.h>
#include "time_rts.h"
#include <signals.h>
#include <xen/xen.h>
#include <xen/vcpu.h>
#include <assert.h>
#include "hypercalls.h"
#include "memory.h"
#include "smp.h"
#include <errno.h>

#ifdef __x86_64
# define rmb() asm volatile("lfence" : : : "memory")
#else
# define rmb() asm volatile("lock; addl $0, 0(%%esp)" : : : "memory")
#endif

/* ************************************************************************* */

static uint64_t            start_time  = 0;
static uint32_t            timer_echan = 0;
static struct shared_info *shared_info = NULL;

void init_time(struct shared_info *sinfo)
{
  long res = bind_virq(VIRQ_TIMER, 0);
  assert(res >= 0);
  timer_echan = res;
  shared_info = sinfo;
  start_time = monotonic_clock();
}

static inline uint64_t rdtscll(void)
{
  uint32_t highbits, lowbits;
  uint64_t retval;

  asm volatile("rdtsc" : "=a"(lowbits), "=d"(highbits));
  retval = (((uint64_t)highbits) << 32) | ((uint64_t)lowbits);
  return retval;
}

uint64_t monotonic_clock(void)
{
  struct vcpu_time_info *time = &vcpu_info().time;
  uint32_t start_version, end_version;
  uint64_t now, delta, retval = 0;

  do {
    /* if the low bit in the version is set, an update is in progress */
    do { start_version = time->version; } while (start_version & 0x1);
    __sync_synchronize();
    /* pull in the base system time */
    retval = time->system_time;
    /* now we figure out the difference between now and when that was written */
    now    = rdtscll();
    delta  = now - time->tsc_timestamp;
    if(time->tsc_shift < 0)
      delta >>= -time->tsc_shift;
    else
      delta <<= time->tsc_shift;
    retval += (delta * time->tsc_to_system_mul) >> 32;
    __sync_synchronize();
    /* get our end version */
    end_version = time->version;
    __sync_synchronize();
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
    do { start_version = vcpu_info().time.version; }
         while (start_version & 0x1);
    rmb();
    retval  = shared_info->wc_sec;
    retval += shared_info->wc_nsec / 1000000000ULL; /* ns -> s */
    rmb();
    end_version = vcpu_info().time.version;
    rmb();
  } while(start_version != end_version);

  return retval;
}

int runtime_gettimeofday(struct timeval *tv)
{
  uint32_t start_version, end_version;
  uint64_t offset = monotonic_clock();

  if(!tv) return EFAULT;

  do {
    /* if the low bit in the version is set, an update is in progress */
    do { start_version = vcpu_info().time.version; }
         while (start_version & 0x1);
    rmb();
    tv->tv_sec  = shared_info->wc_sec + (offset / 1000000000ULL);
    tv->tv_usec = (shared_info->wc_nsec + (offset % 1000000000ULL)) / 1000ULL;
    rmb();
    end_version = vcpu_info().time.version;
    rmb();
  } while(start_version != end_version);

  return 0;
}

int runtime_rusage(int who __attribute__((unused)), struct rusage *usage)
{
  uint64_t now  = monotonic_clock();
  uint64_t diff = now - start_time;

  assert(now >= start_time);
  memset(usage, 0, sizeof(struct rusage));
  usage->ru_utime.tv_sec  = diff / 1000000000;
  usage->ru_utime.tv_usec = (diff % 1000000000) / 1000;
  usage->ru_maxrss        = max_pages * 4096;
  usage->ru_ixrss         = cur_pages * 4096;
  usage->ru_idrss         = cur_pages * 4096;
  usage->ru_isrss         = VCPU_STACK_SIZE;

  return 0;
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
  Time now = (Time)((uint64_t)monotonic_clock() / (uint64_t)1000); /* ns->us */

  if( (now + us) < now ) {
    printf("Exceptional case in getDelayTarget.\n");
    return 0;
  }

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
