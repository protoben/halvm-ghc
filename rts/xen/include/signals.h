#ifndef RTS_XEN_SIGNALS_H
#define RTS_XEN_SIGNALS_H

#ifndef __XEN__
#define __XEN__
#endif

#include <stdint.h>
#include <xen/xen.h>
#include <Rts.h>

void init_signals(struct shared_info *);

long bind_virq(uint32_t, uint32_t);
long bind_pirq(uint32_t, int);
long bind_ipi(uint32_t);
void set_c_handler(uint32_t, void (*)(int));
void clear_c_handler(uint32_t);
void set_haskell_handler(uint32_t, StgStablePtr);
StgStablePtr clear_haskell_handler(uint32_t);
long channel_send(uint32_t);
long channel_alloc(uint32_t, uint32_t);
long channel_bind(uint32_t, uint32_t);
long channel_close(uint32_t);

void mask_channel(uint32_t);
void unmask_channel(uint32_t);

void do_hypervisor_callback(void *);

rtsBool anyUserHandlers(void);
int     signals_pending(void);
int     allow_signals(int);
StgStablePtr dequeueSignalHandler(void);

#ifndef THREADED_RTS
void    awaitEvent(rtsBool);
#endif

#endif
