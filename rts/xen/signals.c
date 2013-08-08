#define __XEN__
#include "Rts.h"
#include "Schedule.h"
#include "RtsSignals.h"
#include "RtsUtils.h"
#include "signals.h"
#include <runtime_reqs.h>
#include <string.h>
#include <sys/mman.h>
#include <xen/xen.h>
#include <xen/event_channel.h>
#include "hypercalls.h"
#include <assert.h>
#include "locks.h"
#include "vcpu.h"
#include "time_rts.h"

/* ************************************************************************ */

#define MAX_EVTCHANS            ((sizeof(long) * 8) * (sizeof(long) * 8))
#define MAX_PENDING_HANDLERS    MAX_EVTCHANS

typedef struct signal_handler {
  void         (*c_handler)(int);
  StgStablePtr  haskell_handler;
} signal_handler_t;

static signal_handler_t   *signal_handlers;
static struct shared_info *shared_info;

void init_signals(struct shared_info *sinfo)
{
  shared_info = sinfo;
  signal_handlers = runtime_alloc(NULL, MAX_EVTCHANS * sizeof(signal_handler_t),
                                  PROT_READWRITE, ALLOC_ALL_CPUS);
  memset(signal_handlers, 0, MAX_EVTCHANS * sizeof(signal_handler_t));
  memset(shared_info->evtchn_mask, 0xFF, sizeof(shared_info->evtchn_mask));
}

long bind_virq(uint32_t virq, uint32_t vcpu)
{
  evtchn_bind_virq_t arg = { .virq = virq, .vcpu = vcpu, .port = 0 };
  long res = HYPERCALL_event_channel_op(EVTCHNOP_bind_virq, &arg);
  return (res >= 0) ? arg.port : res;
}

long bind_pirq(uint32_t pirq, int will_share)
{
  evtchn_bind_pirq_t arg = { .pirq  = pirq,
                             .flags = will_share ? BIND_PIRQ__WILL_SHARE : 0,
                             .port  = 0 };
  long res = HYPERCALL_event_channel_op(EVTCHNOP_bind_pirq, &arg);
  return (res >= 0) ? arg.port : res;
}

void set_c_handler(uint32_t chan, void (handler)(int))
{
  assert(chan < MAX_EVTCHANS);
  signal_handlers[chan].c_handler = handler;
  unmask_channel(chan);
}

void set_haskell_handler(uint32_t chan, StgStablePtr handler)
{
  assert(chan < MAX_EVTCHANS);
  signal_handlers[chan].haskell_handler = handler;
  unmask_channel(chan);
}

void mask_channel(uint32_t chan)
{
  void *p = shared_info->evtchn_mask;
  asm volatile("lock btsl %0, %1" : : "r"(chan), "m"(p) : "memory");
}

void unmask_channel(uint32_t chan)
{
  void *p = shared_info->evtchn_mask;
  asm volatile("lock btrl %0, %1" : : "r"(chan), "m"(p) : "memory");
}

/* ************************************************************************ */

void do_hypervisor_callback(void *u __attribute__((unused)))
{
  printf("hypervisor_callback!\n");
}

/* ************************************************************************ */

void initDefaultHandlers(void)
{
  /* nothing! */
}

void resetDefaultHandlers(void)
{
  /* nothing! */
}

/* ************************************************************************ */

static halvm_mutex_t  handler_buf_lock;
static StgStablePtr  *pending_handler_buf  = NULL;
static int            next_pending_handler = 0;

int signals_pending(void)
{
  return next_pending_handler;
}

void initUserSignals(void)
{
  pending_handler_buf  = calloc(MAX_PENDING_HANDLERS, sizeof(StgStablePtr));
  next_pending_handler = 0;
  initMutex(&handler_buf_lock);
}

void awaitUserSignals(void)
{
  while(!signals_pending() && sched_state == SCHED_RUNNING)
    runtime_block(0);
}

rtsBool anyUserHandlers(void)
{
  int i;

  for(i = 0; i < (int)MAX_EVTCHANS; i++)
    if(signal_handlers[i].haskell_handler)
      return rtsTrue;

  return rtsFalse;
}

void blockUserSignals(void)
{
  /* nothing to do */
}

void unblockUserSignals(void)
{
  /* nothing to do */
}

/* ************************************************************************ */

void markSignalHandlers(evac_fn evac __attribute__((unused)),
                        void *user __attribute__((unused)))
{
  assert(!signals_pending());
}

void freeSignalHandlers(void)
{
  assert(!signals_pending());
}

void startSignalHandlers(Capability *cap)
{
  int i;

  halvm_acquire_lock(&handler_buf_lock);
  vcpu_local_info->other_info.evtchn_upcall_mask = 1;
  for(i = 0; i < next_pending_handler; i++) {
    StgClosure *h = (StgClosure*)deRefStablePtr(pending_handler_buf[i]);
    scheduleThread(cap, createIOThread(cap,RtsFlags.GcFlags.initialStkSize,h));
  }
  next_pending_handler = 0;
  vcpu_local_info->other_info.evtchn_upcall_mask = 0;
  halvm_release_lock(&handler_buf_lock);
}

/* ************************************************************************ */

#ifndef THREADED_RTS
static rtsBool wakeUpSleepingThreads(StgWord now)
{
  rtsBool retval = rtsFalse;

   /* wake up anyone that's sleeping */
   while((sleeping_queue != END_TSO_QUEUE) &&
         (now - sleeping_queue->block_info.target > 0))
   {
     StgTSO *tso      = sleeping_queue;
     retval           = rtsTrue;
     sleeping_queue   = tso->_link;
     tso->why_blocked = NotBlocked;
     tso->_link       = END_TSO_QUEUE;
     pushOnRunQueue(&MainCapability, tso);
   }

   return retval;
}

void awaitEvent(rtsBool wait)
{
  do {
    StgWord now = getDelayTarget(0);

    if(wakeUpSleepingThreads(now))
      return;

    /* if we're supposed to wait, try blocking for awhile */
    if(wait) {
      lnat block_time = ~0;

      if(sleeping_queue != END_TSO_QUEUE) {
        block_time  = sleeping_queue->block_info.target - now; /* in us */
        block_time /= 1000; /* us -> ms */
      }
      runtime_block(block_time);
    }

    if(signals_pending()) {
      startSignalHandlers(&MainCapability);
      return;
    }

    if(sched_state >= SCHED_INTERRUPTING)
      return;

    wakeUpSleepingThreads(getDelayTarget(0));
  } while(wait && (sched_state == SCHED_RUNNING)
               && emptyRunQueue(&MainCapability));
}
#endif

void runtime_block(unsigned long milliseconds)
{
  printf("runtime_block(%d)\n", milliseconds);
  // FIXME
}

int stg_sig_install(int sig, int spi, void *mask __attribute__((unused)))
{
  assert(sig == 2);
  return spi;
}
