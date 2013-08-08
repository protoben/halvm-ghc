#ifndef RTS_XEN_SIGNALS_H
#define RTS_XEN_SIGNALS_H

#ifndef __XEN__
#define __XEN__
#endif

#include <stdint.h>
#include <xen/xen.h>
#include <Rts.h>

#define IRQ_STACK_SIZE        16384

void init_signals(struct shared_info *);

long bind_virq(uint32_t, uint32_t);
long bind_pirq(uint32_t, int);
void set_c_handler(uint32_t, void (*)(int));
void set_haskell_handler(uint32_t, StgStablePtr);

void mask_channel(uint32_t);
void unmask_channel(uint32_t);

void do_hypervisor_callback(void *);

rtsBool anyUserHandlers(void);
int     signals_pending(void);

#ifndef THREADED_RTS
void    awaitEvent(rtsBool);
#endif

#endif
