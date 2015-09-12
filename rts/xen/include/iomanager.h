#ifndef RTS_XEN_IOMANAGER_H
#define RTS_XEN_IOMANAGER_H

#include "Rts.h"

StgWord waitForWaiter(StgStablePtr *out);
void registerWaiter(HsInt, StgStablePtr);

#endif
