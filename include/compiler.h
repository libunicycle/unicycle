// SPDX-License-Identifier: MIT

#pragma once

#include "config.h"

#ifndef __ASSEMBLER__
typedef signed long int ssize_t;
#endif /* ! __ASSEMBLER__ */

#define PRINTFLIKE(__fmt, __varargs) __attribute__((__format__(__printf__, __fmt, __varargs)))
#define PACKED __attribute__((packed))
#define ALIGNED(x) __attribute__((aligned(x)))
#define NORETURN __attribute__((noreturn))
#define NOINLINE __attribute__((noinline))
#define SECTION(s) __attribute__((section(s)))
#define UNUSED __attribute__((unused))
#define USED __attribute__((used))
#define INIT_CODE SECTION(".init.text")
#define INIT_DATA SECTION(".init.data")

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define SIZEOF_FIELD(type, field) sizeof(((type *)NULL)->field)

#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#define MIN(a, b) (((a) < (b)) ? (a) : (b))

// rounds n up to multiple of d. d have to be power of 2.
#define ROUND_UP(n, d) ((n + (__typeof__(n))d - 1) & ~((__typeof__(n))d - 1))
#define ROUND_DOWN(n, d) ((n) & ~((__typeof__(n))d - 1))
#define IS_ROUNDED(n, d) (((n) & ((__typeof__(n))d - 1)) == 0)

#define DIV_ROUND_UP(n, d) ((n + (__typeof__(n))d - 1) / (__typeof__(n))(d))

#define ISPOW2(x) ((x) != 0 && ((x & (x - 1)) == 0))

// Number of leading zero bits
#define CLZ(x)                                     \
    _Generic(x, int                                \
             : __builtin_clz, unsigned int         \
             : __builtin_clz, long                 \
             : __builtin_clzl, unsigned long       \
             : __builtin_clzl, long long           \
             : __builtin_clzll, unsigned long long \
             : __builtin_clzll)(x)
// One plus position of the least significant '1' bit
#define FFS(x)                                     \
    _Generic(x, int                                \
             : __builtin_ffs, unsigned int         \
             : __builtin_ffs, long                 \
             : __builtin_ffsl, unsigned long       \
             : __builtin_ffsl, long long           \
             : __builtin_ffsll, unsigned long long \
             : __builtin_ffsll)(x)
// One plus position of the most significant '1' bit
#define FLS(x) ((x) ? sizeof(x) * 8 - CLZ(x) : 0)
// Integer log with base 2
#define ILOG2(x) (FLS(x) - 1)
// Integer log with base 2 rounding result up
#define ILOG2_UP(x) FLS((x)-1)
#define PAGE_ORDER(order) ((uint64_t)1 << (order))

// XXX: if we use __builtin_clz can compiler optimize it out?
#define ROUND_UP_POW2(x) ((uint64_t)1 << ILOG2_UP(x))

#define BIT(x) ((uint64_t)1 << (x))

#define IFD if (CONFIG_DEBUG)
#define IFV if (CONFIG_DEBUG)
#define IFVV if (CONFIG_DEBUG)

#if IS_ENABLED(CONFIG_SMP)
#define PERCPU _Thread_local
#else
#define PERCPU
#endif

// A marker macro
#define __le __attribute__((scalar_storage_order("little-endian")))
#define __be __attribute__((scalar_storage_order("big-endian")))
#define __mmio volatile

#define bswap(x) _Generic(x, uint16_t : __builtin_bswap16, uint32_t : __builtin_bswap32, uint64_t : __builtin_bswap64)(x)

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define cpu_to_le(x) (x)
#define le_to_cpu(x) (x)
#define cpu_to_be(x) bswap(x)
#define be_to_cpu(x) bswap(x)
#else
#define cpu_to_le(x) bswap(x)
#define le_to_cpu(x) bswap(x)
#define cpu_to_be(x) (x)
#define be_to_cpu(x) (x)
#endif

#define COMPILER_BARRIER __asm__ volatile("" : : : "memory")

#define container_of(ptr, type, member)              \
    ({                                               \
        const void *__mptr = (void *)(ptr);          \
        ((type *)(__mptr - offsetof(type, member))); \
    })

#define GET_MACRO(_0, _1, _2, _3, _4, _5, _6, NAME, ...) NAME
