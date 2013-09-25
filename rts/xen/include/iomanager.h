#ifndef RTS_XEN_IOMANAGER_H
#define RTS_XEN_IOMANAGER_H

StgStablePtr waitForWaiter(void);
void registerWaiter(int, StgStablePtr);

#endif
