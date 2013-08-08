#include <runtime_reqs.h>
#include <sys/mman.h>

void *mremap(void *old_address, size_t old_size, size_t new_size,
             int flags __attribute__((unused)))
{
  return runtime_realloc(old_address, old_size, new_size);
}
