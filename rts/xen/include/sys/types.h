// mainly from mini-os
/* -*-  mode:c; c-basic-offset:4; tab-width:4 -*-
 ****************************************************************************
 * (c) 2003 - rolf neugebauer - intel research cambridge
 ****************************************************************************
 *
 *        file: types.h
 *      author: rolf neugebauer (neugebar@dcs.gla.ac.uk)
 *     changes: 
 *              
 *        date: may 2003
 * 
 * environment: xen minimal os
 * description: a random collection of type definitions
 *
 ****************************************************************************
 * $id: h-insert.h,v 1.4 2002/11/08 16:03:55 rn exp $
 ****************************************************************************
 */

#ifndef _types_h_
#define _types_h_

// comapatability: some people imprt stdio.h for null.
#ifndef null
#define null 0
#endif

typedef signed char         s8;
typedef unsigned char       u8;
typedef signed short        s16;
typedef unsigned short      u16;
typedef signed int          s32;
typedef unsigned int        u32;
#ifdef __i386__
typedef signed long long    s64;
typedef unsigned long long  u64;
#elif defined(__x86_64__)
typedef signed long         s64;
typedef unsigned long       u64;
#endif

typedef long unsigned int   size_t;

/* freebsd compat types */
typedef unsigned char       u_char;
typedef unsigned int        u_int;
typedef unsigned long       u_long;
#ifdef __i386__
typedef long long           quad_t;
typedef unsigned long long  u_quad_t;
typedef unsigned long int   uintptr_t;
typedef long int            intptr_t;

# ifdef config_x86_pae
typedef struct { unsigned long pte_low, pte_high; } pte_t;
# else
typedef struct { unsigned long pte_low; } pte_t;
# endif
#elif defined(__x86_64__)
typedef long                quad_t;
typedef unsigned long       u_quad_t;
typedef unsigned long       uintptr_t;
typedef long int            intptr_t;

typedef struct { unsigned long pte; } pte_t;
#endif

typedef  u8 uint8_t;
typedef  s8 int8_t;
typedef u16 uint16_t;
typedef s16 int16_t;
typedef u32 uint32_t;
typedef u32 u_int32_t;
typedef s32 int32_t;
typedef u64 uint64_t;
typedef s64 int64_t;

typedef int                bool;

typedef int off_t;

typedef char *__caddr_t;
typedef __caddr_t caddr_t;
typedef unsigned long pid_t;

typedef uint32_t ino_t;
typedef uint64_t dev_t;

// xxx make sure that these are correct
typedef uint16_t mode_t;
typedef uint32_t uid_t;
typedef uint32_t nlink_t;
typedef uint32_t blksize_t;
typedef uint32_t blkcnt_t;
typedef uint32_t gid_t;


#define LITTLE_ENDIAN 1234

#endif /* _TYPES_H_ */
