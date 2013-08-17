#ifndef MINLIBC_RUNTIME_REQS
#define MINLIBC_RUNTIME_REQS

#include <sys/types.h>
#include <time.h>

#define ALLOC_CPU_LOCAL         0
#define ALLOC_ALL_CPUS          1
#define ALLOC_GLOBAL_ONLY       2

void    runtime_write(size_t len, char *buffer);
void    runtime_block(unsigned long milliseconds);
void    runtime_exit(void) __attribute__((noreturn));
void   *runtime_alloc(void *start, size_t length, int prot, int target);
void   *runtime_realloc(void *start, size_t oldlen, size_t newlen);
void    runtime_free(void *start, size_t length);
int     runtime_memprotect(void *addr, size_t length, int prot);
int     runtime_pagesize(void);
time_t  runtime_time(void);

#endif
