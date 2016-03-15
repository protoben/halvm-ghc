#define __XEN__
#include <sys/types.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <xen/xen.h>
#include <hypercalls.h>
#include <xen/sched.h>
#include <xen/vcpu.h>
#include <errno.h>
#include <assert.h>
#include <runtime_reqs.h>
#include "memory.h"
#include "smp.h"
#include "locks.h"
#include "time_rts.h"
#include "signals.h"
#include "grants.h"
#include <sys/mman.h>

void main(int, char**);
void runtime_entry(start_info_t *, void *) __attribute__((noreturn));
void shutdown(int) __attribute__((noreturn));

struct start_info  *system_start_info      = NULL;
struct shared_info *HYPERVISOR_shared_info = NULL;

extern void divide_error(void);
extern void debug(void);
extern void int3(void);
extern void overflow(void);
extern void bounds(void);
extern void invalid_op(void);
extern void device_not_available(void);
extern void coprocessor_segment_overrun(void);
extern void invalid_TSS(void);
extern void segment_not_present(void);
extern void stack_segment(void);
extern void general_protection(void);
extern void page_fault(void);
extern void spurious_interrupt_bug(void);
extern void coprocessor_error(void);
extern void alignment_check(void);
extern void machine_check(void);
extern void simd_coprocessor_error(void);
extern void hypervisor_callback(void);
extern void failsafe_callback(void);

#if 0
static trap_info_t trap_table[] = {
  {  0, 0, FLAT_KERNEL_CS, (unsigned long)divide_error                },
  {  1, 0, FLAT_KERNEL_CS, (unsigned long)debug                       },
  {  3, 3, FLAT_KERNEL_CS, (unsigned long)int3                        },
  {  4, 3, FLAT_KERNEL_CS, (unsigned long)overflow                    },
  {  5, 3, FLAT_KERNEL_CS, (unsigned long)bounds                      },
  {  6, 0, FLAT_KERNEL_CS, (unsigned long)invalid_op                  },
  {  7, 0, FLAT_KERNEL_CS, (unsigned long)device_not_available        },
  {  9, 0, FLAT_KERNEL_CS, (unsigned long)coprocessor_segment_overrun },
  { 10, 0, FLAT_KERNEL_CS, (unsigned long)invalid_TSS                 },
  { 11, 0, FLAT_KERNEL_CS, (unsigned long)segment_not_present         },
  { 12, 0, FLAT_KERNEL_CS, (unsigned long)stack_segment               },
  { 13, 0, FLAT_KERNEL_CS, (unsigned long)general_protection          },
  { 14, 0, FLAT_KERNEL_CS, (unsigned long)page_fault                  },
  { 15, 0, FLAT_KERNEL_CS, (unsigned long)spurious_interrupt_bug      },
  { 16, 0, FLAT_KERNEL_CS, (unsigned long)coprocessor_error           },
  { 17, 0, FLAT_KERNEL_CS, (unsigned long)alignment_check             },
  { 18, 0, FLAT_KERNEL_CS, (unsigned long)machine_check               },
  { 19, 0, FLAT_KERNEL_CS, (unsigned long)simd_coprocessor_error      },
  {  0, 0,           0, 0                           }
};
#endif

enum cmdline_parse_state {
  stateEmpty,
  stateSingle,
  stateDouble
};

static inline uint32_t get_num_vcpus(void)
{
  uint32_t i;

  for(i = 0; i < 16384; i++) {
    vcpu_runstate_info_t rstate_info;
    long res = HYPERCALL_vcpu_op(VCPUOP_get_runstate_info, i, &rstate_info);
    if(res < 0)
      break;
  }

  return i;
}

static char **argv          = NULL;
static int    argc          = 0;
static void  *runtime_stack = NULL;

void runtime_entry(start_info_t *start_info, void *init_sp)
{
  enum cmdline_parse_state state;
  uint32_t num_vcpus, i, pos;
  unsigned long maxpages;
  mfn_t shared_info_mfn;
  size_t cmdline_size;

  /* system startup stuff, that must occur before we go to GHC */
  system_start_info = start_info;
  num_vcpus = get_num_vcpus();
  assert(num_vcpus > 0);
  printf("Starting %d-CPU HaLVM\n", num_vcpus);
  maxpages = initialize_memory(start_info, init_sp);
  shared_info_mfn = (mfn_t)start_info->shared_info >> PAGE_SHIFT;
  // just for my own sanity, make sure that the machine address we're
  // given for the shared info struct is page aligned.
  assert(!((uintptr_t)start_info->shared_info & (PAGE_SIZE-1)));
  HYPERVISOR_shared_info = map_frames(&shared_info_mfn,1);
  runtime_stack = runtime_alloc(NULL, VCPU_STACK_SIZE, PROT_READWRITE);
#ifdef __x86_64__
  asm("mov %0, %%rsp" :
      : "r"((uintptr_t)runtime_stack + VCPU_STACK_SIZE - PAGE_SIZE));
#else
  asm("mov %0, %%esp" :
      : "r"((uintptr_t)runtime_stack + VCPU_STACK_SIZE - PAGE_SIZE));
#endif
  init_signals(HYPERVISOR_shared_info);
#ifdef THREADED_RTS
  init_smp_system(num_vcpus);
#else
  if(num_vcpus > 1)
    printf("WARNING: Allocated >1 CPUs in the non-threaded RTS.\n");
#endif
  /* Don't register our trap table, as Xen's default gives more useful
   * information */
  /* assert(HYPERCALL_set_trap_table(trap_table) >= 0); */
  assert(HYPERCALL_set_callbacks(hypervisor_callback, failsafe_callback) >= 0);
  allow_signals(1);
  init_time(HYPERVISOR_shared_info);
  init_grants();

  /* OK, now we need to figure out what command line to give GHC. */
  cmdline_size = strlen((const char *)start_info->cmd_line) + 1;
  argc = 0; argv = malloc((6 + cmdline_size) * sizeof(char *));
  memset(argv, 0, (6 + cmdline_size) * sizeof(char *));
  /* these are constant ... */
  argv[argc++] = "HaLVM";
  argv[argc++] = "+RTS";
  argv[argc++] = "-c";
  /* tell GHC how much memory to use */
  argv[argc] = malloc(16);
  snprintf(argv[argc],16,"-M%dm", (maxpages - used_frames()) / 256);
  argc++;
#ifdef THREADED_RTS
  argv[argc++] = "-N";
#endif
  /* close off the RTS section */
  argv[argc++] = "-RTS";
  /* copy over the command line arguments */
  for(i = 0, state = stateEmpty, pos = 0; start_info->cmd_line[i]; i++) {
    switch(start_info->cmd_line[i]) {
      case ' ':
        if(state == stateEmpty) {
          if(argv[argc])
            argv[argc++][pos] = '\0'; pos = 0;
        } else {
          if(!argv[argc]) argv[argc] = malloc(cmdline_size);
          argv[argc][pos++] = ' ';
        }
        break;

      case '\'':
        if(state == stateSingle) {
          argv[argc++][pos] = '\0'; pos = 0; state = stateEmpty;
        } else if(state == stateDouble) {
          if(!argv[argc]) argv[argc] = malloc(cmdline_size);
          argv[argc][pos++] = '\'';
        } else {
          state = stateSingle;
        }
        break;

      case '"':
        if(state == stateDouble) {
          argv[argc++][pos] = '\0'; pos = 0; state = stateEmpty;
        } else if(state == stateSingle) {
          if(!argv[argc]) argv[argc] = malloc(cmdline_size);
          argv[argc][pos++] = '\"';
        } else {
          state = stateDouble;
        }
        break;

      default:
        if(!argv[argc]) argv[argc] = malloc(cmdline_size);
        argv[argc][pos++] = start_info->cmd_line[i];
        break;
    }
  }
  if(argv[argc]) {
    argv[argc][pos++] = '\0';
    argc++;
  }

  /* Jump to GHC */
  main(argc, argv);

  /* Ideally we should never get here, but just in case GHC returns ... */
  runtime_exit();
}

void runtime_exit(void)
{
  shutdown(SHUTDOWN_poweroff);
}

/* SCHEDOP_shutdown tells Xen not to schedule us anymore. Toolstack cleans up */
void shutdown(int reason)
{
  sched_shutdown_t op ={ .reason = reason ? SHUTDOWN_crash : SHUTDOWN_poweroff};
  for( ;; ) HYPERCALL_sched_op(SCHEDOP_shutdown, &op);
}
