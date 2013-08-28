#define __XEN__
#include "Rts.h"
#include "RtsUtils.h"
#include "sm/OSMem.h"
#include <runtime_reqs.h>
#include <xen/xen.h>
#include <xen/memory.h>
#include "vmm.h"
#include "memory.h"
#include <assert.h>
#include "hypercalls.h"
#include <sys/mman.h>
#include "locks.h"
#include <errno.h>

#define PAGE_ALIGN(t1,t2,x) (t1)(((t2)x + (PAGE_SIZE-1)) & (~(PAGE_SIZE-1)))

extern int            _text;
       unsigned long  cur_pages = 0;
       unsigned long  max_pages = 0;

extern void initMutex(halvm_mutex_t *mutex);

/******************************************************************************/

mfn_t *p2m_map = NULL;

void set_pframe_used(pfn_t pfn)
{
  assert(pfn < cur_pages);
  assert(p2m_map);
  assert(p2m_map[pfn]);
  p2m_map[pfn] = p2m_map[pfn] | PFN_SET_BIT;
}

void set_pframe_unused(pfn_t pfn)
{
  assert(pfn < cur_pages);
  assert(p2m_map);
  assert(p2m_map[pfn]);
  p2m_map[pfn] = p2m_map[pfn] & (~PFN_SET_BIT);
}

mfn_t get_free_frame()
{
  unsigned long i;

  assert(p2m_map);
  for(i = 0; i < cur_pages; i++)
    if(!(p2m_map[i] & PFN_SET_BIT)) {
      mfn_t retval = p2m_map[i];
      p2m_map[i] = p2m_map[i] | PFN_SET_BIT;
      return retval;
    }

  return 0;
}

unsigned long used_frames(void)
{
  unsigned long i, retval;

  for(i = 0, retval = 0; i < cur_pages; i++)
    if(p2m_map[i] & PFN_SET_BIT)
      retval += 1;

  return retval;
}

/******************************************************************************/

static halvm_mutex_t  memory_search_lock;

unsigned long initialize_memory(start_info_t *start_info,
                                uint32_t num_vcpus,
                                void *init_sp)
{
  domid_t self = DOMID_SELF;
  void *free_space_start, *init_alloc_end, *cur;
  uint32_t i, used_frames;

  /* gather some basic information about ourselves */
  p2m_map   = (mfn_t*)start_info->mfn_list;
  max_pages = HYPERCALL_memory_op(XENMEM_maximum_reservation, &self);
  cur_pages = HYPERCALL_memory_op(XENMEM_current_reservation, &self);

  /* sanity checks */
  assert(p2m_map);
  assert((long)cur_pages > 0);
  assert((long)max_pages > 0);
  assert((uintptr_t)VCPU_LOCAL_END <= (uintptr_t)&_text);

  /* basic setup */
  init_alloc_end = (void*)(((uintptr_t)init_sp + 0x3FFFFF) & (~0x3FFFFF));
  if( ((uintptr_t)init_alloc_end - (uintptr_t)init_sp) < (512 * 1024) ) {
    /* Xen guarantees at least 4MB alignment and 512kB padding after */
    /* the stack. So the above does the alignment, and this if does  */
    /* the edge case.                                                */
    init_alloc_end = (void*)((uintptr_t)init_alloc_end + (4 * 1024 * 1024));
  }
  used_frames = ((uintptr_t)init_alloc_end - (uintptr_t)&_text) >> PAGE_SHIFT;
  for(i = 0; i < used_frames; i++)
    set_pframe_used(i);

  free_space_start = initialize_vmm(start_info, num_vcpus, init_sp);
  free_space_start = PAGE_ALIGN(void*,uintptr_t,free_space_start);
  i = ((uintptr_t)free_space_start - (uintptr_t)&_text) >> PAGE_SHIFT;
  for(cur = free_space_start;
      i < used_frames;
      i++, cur = (void*)((uintptr_t)cur + 4096)) {
    set_pframe_unused(i);
    set_pt_entry(cur, 0);
  }

  /* Finally, initialize the lock */
  initMutex(&memory_search_lock);

  return max_pages;
}

/******************************************************************************/

static inline void *advance_page(void *p, int target)
{
  void *next = CANONICALIZE((void*)((uintptr_t)DECANONICALIZE(p) + 4096));

  if( (target == ALLOC_CPU_LOCAL) && (next == (void*)VCPU_LOCAL_END) )
    return VCPU_LOCAL_START;

  if( (target == ALLOC_ALL_CPUS) && ((uintptr_t)next == 0) )
    return VCPU_LOCAL_END;

  if( (target == ALLOC_GLOBAL_ONLY) && ((uintptr_t)next == 0) )
    return GLOBAL_TABLE_START;

  return next;
}

static inline void *run_search_loop(void *start, size_t length, int target)
{
  void *cur = start, *retval = NULL;
  size_t needed_space = length;

  assert(start);
  while(needed_space > 0) {
    pte_t ent = get_pt_entry(cur);

    if(ENTRY_PRESENT(ent) || ENTRY_CLAIMED(ent)) {
      /* nevermind, we can't use anything we've found up until now */
      needed_space = length;
      retval       = NULL;
    } else {
      /* we can start or extend the current run */
      if(!retval) retval = cur;
      needed_space     = needed_space - PAGE_SIZE;
    }

    if(needed_space > 0) {
      cur = advance_page(cur, target);

      /* check for wraparound, which is bad */
      if( cur < retval ) {
        needed_space = length;
        retval       = NULL;
      }

      /* if we're back where we started from, give up */
      if( cur == start )
        return NULL;
    }
  }

  return retval;
}

static inline void *find_new_addr(void *start_in, size_t length, int target)
{
  static void *glob_search_hint = VCPU_LOCAL_END;
  void *start = PAGE_ALIGN(void*,uintptr_t,start_in);

  /* now we do some processing to make start something reasonable */
  if(target == ALLOC_CPU_LOCAL) {
    /* so we're doing local allocation. if they gave us an address, then */
    /* make sure it's in the right ballpark.                             */
    if( ((uintptr_t)start < (uintptr_t)VCPU_LOCAL_START) ||
        ((uintptr_t)start >= (uintptr_t)VCPU_LOCAL_END) )
      start = NULL;

    if(!start)
      start = (void*)VCPU_LOCAL_START;
  } else {
    /* in this case we're doing global allocation. So if they've tried to */
    /* give us something in the global region, ignore them.               */
    if( ((uintptr_t)start >= (uintptr_t)VCPU_LOCAL_START) &&
        ((uintptr_t)start <  (uintptr_t)VCPU_LOCAL_END) )
      start = NULL;

    /* and if they didn't give us any info (or it's junk, see above), */
    /* let's use a reasonable hint about where to start our search.   */
    if(!start)
      start = glob_search_hint;
  }

  return run_search_loop(start, length, target);
}

void *runtime_alloc(void *start, size_t length_in, int prot, int target)
{
  size_t length = PAGE_ALIGN(size_t,size_t,length_in);
  void *dest, *cur, *end;

  halvm_acquire_lock(&memory_search_lock);
  assert(dest = find_new_addr(start, length, target));
  cur = dest;
  end = (void*)((uintptr_t)dest + length);
  while( (uintptr_t)cur < (uintptr_t)end ) {
    pte_t entry = get_free_frame() << PAGE_SHIFT;

    if(!entry) {
      /* ACK! We're out of memory */
      cur = dest;
      end = cur;

      /* Free anything we've allocated for this request */
      while( (uintptr_t)cur < (uintptr_t)end ) {
        pte_t entry = get_pt_entry(cur);
        set_pframe_unused(entry >> PAGE_SHIFT);
        set_pt_entry(cur, 0);
      }

      /* and return failure */
      halvm_release_lock(&memory_search_lock);
      return NULL;
    } else {
      entry = entry | PG_PRESENT | PG_USER;
      if(prot & PROT_WRITE)
        entry = entry | PG_READWRITE;
      set_pt_entry(cur, entry);
    }

    cur = advance_page(cur, target);
  }

  /* done! */
  halvm_release_lock(&memory_search_lock);
  return dest;
}

void *map_frames(mfn_t *frames, size_t num_frames)
{
  void *dest;
  size_t i;

  halvm_acquire_lock(&memory_search_lock);
  assert(dest = find_new_addr(NULL, num_frames * PAGE_SIZE, ALLOC_ALL_CPUS));
  for(i = 0; i < num_frames; i++)
    set_pt_entry((void*)((uintptr_t)dest + (i * PAGE_SIZE)),
                 (frames[i] << PAGE_SHIFT) | STANDARD_RW_PERMS);
  halvm_release_lock(&memory_search_lock);
  return dest;
}

long pin_frame(int level, mfn_t mfn, domid_t dom)
{
  mmuext_op_t op;

  switch(level) {
    case 1: op.cmd = MMUEXT_PIN_L1_TABLE; break;
    case 2: op.cmd = MMUEXT_PIN_L2_TABLE; break;
    case 3: op.cmd = MMUEXT_PIN_L3_TABLE; break;
    case 4: op.cmd = MMUEXT_PIN_L4_TABLE; break;
    default:
      return -EINVAL;
  }
  op.arg1.mfn = mfn;

  return HYPERCALL_mmuext_op(&op, 1, NULL, dom);
}

void *runtime_realloc(void *start, size_t oldlen, size_t newlen)
{
  printf("runtime_realloc(%p, %d, %d)\n", start, oldlen, newlen);
  return NULL; // FIXME
}

void *claim_shared_space(size_t amt)
{
  void *retval;
  int i;

  amt = (amt + (PAGE_SIZE-1)) & ~(PAGE_SIZE-1);
  halvm_acquire_lock(&memory_search_lock);
  retval = run_search_loop(GLOBAL_TABLE_START, amt, ALLOC_GLOBAL_ONLY);
  for(i = 0; i < (amt / PAGE_SIZE); i++)
    set_pt_entry((void*)((uintptr_t)retval + (i * PAGE_SIZE)), PG_CLAIMED);
  halvm_release_lock(&memory_search_lock);
  return retval;
}

void runtime_free(void *start, size_t length)
{
  void *end = (void*)((uintptr_t)start + length);

  halvm_acquire_lock(&memory_search_lock);
  while(start < end) {
    pte_t pte = get_pt_entry(start);

    if(ENTRY_PRESENT(pte)) {
      mfn_t mfn = pte >> PAGE_SHIFT;
      pfn_t pfn = machine_to_phys_mapping[mfn];
      if(pfn) set_pframe_unused(pfn);
    }
    set_pt_entry(start, 0);
    start = (void*)((uintptr_t)start + PAGE_SIZE);
  }
  halvm_release_lock(&memory_search_lock);
}

int runtime_memprotect(void *addr, size_t length, int prot)
{
  printf("runtime_memprotect(%p, %d, %d)\n", addr, length, prot);
  return 0; // FIXME
}

int runtime_pagesize()
{
  return PAGE_SIZE;
}

/******************************************************************************/

W_ getPageSize(void)
{
  return runtime_pagesize();
}

W_ getPageFaults(void)
{
  return 0;
}

void *osGetMBlocks(nat n)
{
  size_t padsize = (n + 1) * MBLOCK_SIZE;
  void *allocp, *retval, *extra;

  allocp = runtime_alloc(NULL, padsize, PROT_READWRITE, ALLOC_ALL_CPUS);
  retval = (void*)(((uintptr_t)allocp + (MBLOCK_SIZE-1)) & ~(MBLOCK_SIZE-1));
  /* free the stuff at the beginning and end that we don't need */
  if(allocp == retval) {
    /* we got back an aligned value, so all the extra is at the end */
    extra = (void*)((uintptr_t)allocp + (n * MBLOCK_SIZE));
    runtime_free(extra, MBLOCK_SIZE);
  } else {
    /* if this case fires, we used some of our extra memory to align the */
    /* return value, so this is going to be a little complicated.        */
    size_t extra_head, extra_tail;

    extra = (void*)((uintptr_t)retval + (n * MBLOCK_SIZE));
    extra_head = (uintptr_t)retval - (uintptr_t)allocp;
    extra_tail = ((uintptr_t)allocp + padsize) - (uintptr_t)extra;

    runtime_free(allocp, extra_head);
    runtime_free(extra, extra_tail);
  }

  return retval;
}

void osFreeAllMBlocks(void)
{
  /* ignore this */
}

void osMemInit(void)
{
  /* ignore this */
}

void osFreeMBlocks(char *addr, nat n)
{
  runtime_free(addr, n * MBLOCK_SIZE);
}

void osReleaseFreeMemory(void)
{
  /* ignore this */
}

void setExecutable(void *p, W_ len, rtsBool exec)
{
  void *end = (void*)((uintptr_t)p + len);

  printf("setExecutable(%p, %d, %d)\n", p, len, exec);
  while((uintptr_t)p < (uintptr_t)end) {
    pte_t entry = get_pt_entry(p);

    if(entry & PG_PRESENT)
      set_pt_entry(p, entry & PG_EXECUTABLE);
    p = (void*)((uintptr_t)p + 4096);
  }
}

void system_wmb()
{
#ifdef __x86_64__
  asm volatile ("sfence" : : : "memory");
#else
  asm volatile ("" : : : "memory");
#endif
}

void system_rmb()
{
#ifdef __x86_64__
  asm volatile ("lfence" : : : "memory");
#else
  asm volatile ("lock; addl $0, 0(%%esp)" : : : "memory");
#endif
}

void system_mb()
{
#ifdef __x86_64__
  asm volatile ("mfence" : : : "memory");
#else
  asm volatile ("lock; addl $0, 0(%%esp)" : : : "memory");
#endif
}

