#include "Rts.h"
#include "GetTime.h"

#include <sys/time.h>


void getUnixEpochTime(StgWord64 *sec, StgWord32 *nsec) {
    struct timeval tv;
    gettimeofday(&tv, (struct timezone *) NULL);
    *sec  = tv.tv_sec;
    *nsec = tv.tv_usec * 1000;
}
