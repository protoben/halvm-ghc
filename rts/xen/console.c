#include <runtime_reqs.h>
#include <hypercalls.h>
#include <xen/xen.h>

void runtime_write(size_t count, char *msg)
{
  (void)HYPERCALL_console_io(CONSOLEIO_write, count, msg);
}
