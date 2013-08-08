#include "Rts.h"

#ifndef THREADED_RTS
void setIOManagerControlFd(int fd)
{
  printf("setIOManagerControlFd()\n");
  // FIXME
}

void setIOManagerWakeupFd(int fd)
{
  printf("setIOManagerWakeupFd()\n");
  // FIXME
}

void ioManagerWakeup(void)
{
  printf("ioManagerWakeup()\n");
  // FIXME
}
#endif

#ifdef THREADED_RTS
void ioManagerDie(void)
{
  printf("ioManagerDie()\n");
  // FIXME
}

void ioManagerStart(void)
{
  printf("ioManagerStart()\n");
  // FIXME
}
#endif
