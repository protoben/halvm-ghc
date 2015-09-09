#ifndef RTS_XEN_IOMANAGER_H
#define RTS_XEN_IOMANAGER_H

StgWord waitForWaiter(StgStablePtr *out);
void registerWaiter(int, StgStablePtr);

#endif
