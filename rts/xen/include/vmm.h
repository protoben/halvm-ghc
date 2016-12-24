#ifndef RTS_XEN_VMM_H
#define RTS_XEN_VMM_H

#ifndef __XEN__
#define __XEN__
#endif

#include <stdint.h>
#include <sys/types.h>
#include <xen/xen.h>

#define PG_PRESENT          (1 << 0)
#define PG_READWRITE        (1 << 1)
#define PG_USER             (1 << 2)
#define PG_WRITETHROUGH     (1 << 3)
#define PG_CACHEDISABLE     (1 << 4)
#define PG_ACCESSED         (1 << 5)
#define PG_DIRTY            (1 << 6)
#define PG_SIZE             (1 << 7)
#define PG_GLOBAL           (1 << 8)
#define PG_CLAIMED          (1 << 9)
#define PG_UNUSED1          (1 << 10)
#define PG_UNUSED2          (1 << 11)

#define STANDARD_PERMS      (PG_PRESENT | PG_USER | PG_CLAIMED)
#define STANDARD_RW_PERMS   (STANDARD_PERMS | PG_READWRITE)

#ifdef CONFIG_X86_PAE
typedef uint64_t            pte_t;

#define NUM_PT_ENTRIES      512
#define MADDR_MASK          0x0000000FFFFFF000ULL
#define PG_EXECUTABLE       0xFFFFFFFFFFFFFFFFULL
#define NUM_PT_LEVELS       3

#define BUILD_ADDR(b,c,d)   ((void*)((((uintptr_t)(b)) << 30)    |         \
                                     (((uintptr_t)(c)) << 21)    |         \
                                     (((uintptr_t)(d)) << 12)))
#define CANONICALIZE(x)     (x)
#define DECANONICALIZE(x)   (x)
#endif

#ifdef CONFIG_X86_64
typedef uint64_t            pte_t;

#define NUM_PT_ENTRIES      512
#define MADDR_MASK          0x000FFFFFFFFFF000ULL
#define PG_EXECUTABLE       0x7FFFFFFFFFFFFFFFULL
#define NUM_PT_LEVELS       4

#define BUILD_ADDR(a,b,c,d) ((void*)((((uintptr_t)(a)) << 39)    |         \
                                     (((uintptr_t)(b)) << 30)    |         \
                                     (((uintptr_t)(c)) << 21)    |         \
                                     (((uintptr_t)(d)) << 12)))
#define CANONICALIZE(x)     (void*)((((uintptr_t)(x)) & (1UL << 49))       \
                                    ? ((uintptr_t)x | 0xffff000000000000)  \
                                    : ((uintptr_t)x & 0xFFFFFFFFFFFF))
#define DECANONICALIZE(x)   ((void*)((uintptr_t)(x) & 0xFFFFFFFFFFFF))
#endif

#define INDEX_MASK          ((NUM_PT_ENTRIES) - 1)

#define VADDR_L1_IDX(x)     ((((uintptr_t)(x)) >> 12) & INDEX_MASK)
#define VADDR_L2_IDX(x)     ((((uintptr_t)(x)) >> 21) & INDEX_MASK)
#define VADDR_L3_IDX(x)     ((((uintptr_t)(x)) >> 30) & INDEX_MASK)
#define VADDR_L4_IDX(x)     ((((uintptr_t)(x)) >> 39) & INDEX_MASK)

#define ENTRY_PRESENT(x)    ((x) & PG_PRESENT)
#define ENTRY_CLAIMED(x)    ((x) & PG_CLAIMED)
#define ENTRY_MADDR(x)      ((pte_t)(x) & MADDR_MASK)

void  *initialize_vmm(start_info_t *, void *);
pte_t  get_pt_entry(void *addr);
void   set_pt_entry(void *addr, pte_t entry);
void  *machine_to_virtual(uint64_t maddr);

#endif
