#ifndef RTS_XEN_IOMANAGER_H
#define RTS_XEN_IOMANAGER_H

void registerWaiter(int, StgStablePtr);
void checkWaiters(void);

#endif
