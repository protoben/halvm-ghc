#ifndef RTS_XEN_TIME_H
#define RTS_XEN_TIME_H

#ifndef __XEN__
#define __XEN__
#endif

#include <xen/xen.h>
#include "Rts.h"

void     init_time(struct shared_info *);
StgWord  getDelayTarget(HsInt /* microseconds */);
uint64_t monotonic_clock(void);

#endif
