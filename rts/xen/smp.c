#include "Rts.h"
#include "RtsUtils.h"
#include "Task.h"

#ifndef THREADED_RTS
nat getNumberOfProcessors(void)
{
  printf("getNumberOfProcessors()\n");
  return 1; // FIXME
}

int forkOS_createThread(HsStablePtr entry)
{
  printf("forkOS_createThread(%p)\n", entry);
  return 0; // FIXME
}
#endif

#ifdef THREADED_RTS
int createOSThread(OSThreadId *pId, OSThreadProc *startProc, void *param)
{
  printf("createOSThread(%p, %p, %p)\n", pId, startProc, param);
  // FIXME
}

OSThreadId osThreadId(void)
{
  printf("osThreadId\n");
  return NULL;
}

void interruptOSThread(OSThreadId id)
{
  printf("interruptOSThread(%d)\n", id);
  // FIXME
}

void shutdownThread(void)
{
  printf("shutdownThread()\n");
  // FIXME
}

void yieldThread(void)
{
  printf("yieldThread()\n");
  // FIXME
}

rtsBool osThreadIsAlive(OSThreadId id)
{
  printf("osThreadIsAlive(%d)\n", id);
  return NULL; // FIXME
}

void setThreadAffinity(nat n, nat m)
{
  printf("setThreadAffinity(%d, %d)\n", n, m);
  // FIXME
}
#endif
