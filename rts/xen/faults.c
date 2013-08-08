#include <stdio.h>
#include <runtime_reqs.h>

#ifdef __i386__
struct pt_regs {
  long ebx;
  long ecx;
  long edx;
  long esi;
  long edi;
  long ebp;
  long eax;
  long xds;
  long xes;
  long orig_eax;
  long ip;
  long xcs;
  long eflags;
  long esp;
  long xss;
};
#endif

#ifdef __x86_64__
struct pt_regs {
  unsigned long r15;
  unsigned long r14;
  unsigned long r13;
  unsigned long r12;
  unsigned long rbp;
  unsigned long rbx;
  unsigned long r11;
  unsigned long r10;
  unsigned long r9;
  unsigned long r8;
  unsigned long rax;
  unsigned long rcx;
  unsigned long rdx;
  unsigned long rsi;
  unsigned long rdi;
  unsigned long orig_rax;
  unsigned long ip;
  unsigned long cs;
  unsigned long eflags;
  unsigned long rsp;
  unsigned long ss;
};
#endif

#define DEFINE_FAULT2(name, str)                                           \
void name(struct pt_regs *, unsigned long) __attribute__((noreturn));      \
void name(struct pt_regs *regs, unsigned long code)                        \
{                                                                          \
  printf("FAULT: %s at %p, error code %lx\n", str, (void*)regs->ip, code); \
  runtime_exit();                                                          \
}

#define DEFINE_FAULT1(name, str)                                           \
void name(struct pt_regs *) __attribute__((noreturn));                     \
void name(struct pt_regs *regs)                                            \
{                                                                          \
  printf("FAULT: %s at %p\n", str, (void*)regs->ip);                       \
  runtime_exit();                                                          \
}

DEFINE_FAULT2(do_divide_error, "divide error")
DEFINE_FAULT2(do_int3, "int3")
DEFINE_FAULT2(do_overflow, "overflow")
DEFINE_FAULT2(do_bounds, "bounds error")
DEFINE_FAULT2(do_invalid_op, "invalid operation")
DEFINE_FAULT2(do_device_not_available, "device not available")
DEFINE_FAULT2(do_coprocessor_segment_overrun, "coprocessor segment overrun")
DEFINE_FAULT2(do_invalid_TSS, "invalid TSS")
DEFINE_FAULT2(do_segment_not_present, "segment not present")
DEFINE_FAULT2(do_stack_segment, "stack segment")
DEFINE_FAULT2(do_alignment_check, "alignment check")
DEFINE_FAULT2(do_machine_check, "machine check")
DEFINE_FAULT2(do_page_fault, "page fault")
DEFINE_FAULT2(do_general_protection, "general protection")

DEFINE_FAULT1(do_debug, "debug")
DEFINE_FAULT1(do_coprocessor_error, "coprocessor error")
DEFINE_FAULT1(simd_math_error, "SIMD math error")
DEFINE_FAULT1(do_simd_coprocessor_error, "SIMD coprocessor error")
DEFINE_FAULT1(do_spurious_interrupt_bug, "spurious interrupt")
