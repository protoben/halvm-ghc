#ifndef RTS_XEN_MEMORY_H
#define RTS_XEN_MEMORY_H

#ifndef __XEN__
#define __XEN__
#endif

#include <stdint.h>
#include <sys/types.h>
#include <xen/xen.h>

// start the haskell heap at 64M
#define HASKELL_HEAP_START        ((char *)0x4000000)

#define PAGE_SHIFT                12
#define PAGE_SIZE                 (1 << PAGE_SHIFT)
#define VCPU_STACK_SIZE           (256 * PAGE_SIZE)
#define IRQ_STACK_SIZE            (8 * PAGE_SIZE)


#ifdef CONFIG_X86_32
#error "Pure 32-bit mode is no longer supported!"
#endif

#ifdef CONFIG_X86_PAE
typedef uint32_t mfn_t;
typedef uint32_t pfn_t;
typedef uint64_t maddr_t;
#define PFN_SET_BIT               (1 << 31)
#define CPU_LOCAL_MEM_START       0x4000
#define CPU_LOCAL_MEM_END         (512 * 4096)
#define IN_HYPERVISOR_SPACE(x)    ((uintptr_t)(x) >= HYPERVISOR_VIRT_START)
#define MEMORY_TYPES_DECLARED
#endif

#ifdef CONFIG_X86_64
typedef uint64_t mfn_t;
typedef uint64_t pfn_t;
typedef uint64_t maddr_t;
#define PFN_SET_BIT               (1UL << 63)
#define CPU_LOCAL_MEM_START       0x4000
#define CPU_LOCAL_MEM_END         (512 * 4096)
#define IN_HYPERVISOR_SPACE(x)    (((uintptr_t)(x) >= HYPERVISOR_VIRT_START) &&\
                                   ((uintptr_t)(x) <  HYPERVISOR_VIRT_END))
#define MEMORY_TYPES_DECLARED
#endif

#ifndef MEMORY_TYPES_DECLARED
#error "Need to be compiled with CONFIG_X86_32, 64, or PAE."
#endif

extern mfn_t         *p2m_map;
extern unsigned long  cur_pages;
extern unsigned long  max_pages;

void           set_pframe_used(pfn_t);
void           set_pframe_unused(pfn_t);
mfn_t          get_free_frame(void);
unsigned long  used_frames(void);

unsigned long  initialize_memory(start_info_t *, void *);
void          *claim_shared_space(size_t);
void          *map_frames(mfn_t *, size_t);
long           pin_frame(int, mfn_t, domid_t);

void           system_wmb(void);
void           system_rmb(void);
void           system_mb(void);

#endif
