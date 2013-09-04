#include "Rts.h"
#include "Prelude.h"

static int controlFd = 0;
static int wakeupFd = 0;

void setIOManagerControlFd(int fd)
{
  printf("setIOManagerControlFd()\n");
  controlFd = fd;
}

void setIOManagerWakeupFd(int fd)
{
  printf("setIOManagerWakeupFd()\n");
  wakeupFd = fd;
}

void ioManagerWakeup(void)
{
  printf("ioManagerWakeup()\n");
  // FIXME
}

#ifdef THREADED_RTS
void ioManagerDie(void)
{
  printf("ioManagerDie()\n");
  // FIXME
}

void ioManagerStart(void)
{
  Capability *cap;

  if(controlFd < 0 || wakeupFd < 0) {
    printf("starting ioManager capability?\n");
    cap = rts_lock();
    rts_evalIO(&cap, &base_GHCziConcziIO_ensureIOManagerIsRunning_closure,NULL);
    rts_unlock(cap);
  }
}
#endif
