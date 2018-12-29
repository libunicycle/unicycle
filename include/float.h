/* This file is based on MUSL project code */

#pragma once

#include "arch.h"
#include <stdint.h>

#define INT_MAX 0x7fffffff
#define ULONG_MAX -1UL

static inline int isdigit(int c) { return (unsigned)c - '0' < 10; }

#define FP_NAN 0
#define FP_INFINITE 1
#define FP_ZERO 2
#define FP_SUBNORMAL 3
#define FP_NORMAL 4

static __inline unsigned __FLOAT_BITS(float __f) {
    union {
        float __f;
        unsigned __i;
    } __u;
    __u.__f = __f;
    return __u.__i;
}
static __inline unsigned long long __DOUBLE_BITS(double __f) {
    union {
        double __f;
        unsigned long long __i;
    } __u;
    __u.__f = __f;
    return __u.__i;
}

#if LDBL_MANT_DIG == 53 && LDBL_MAX_EXP == 1024
#elif LDBL_MANT_DIG == 64 && LDBL_MAX_EXP == 16384 && __BYTE_ORDER == __LITTLE_ENDIAN
union ldshape {
    long double f;
    struct {
        uint64_t m;
        uint16_t se;
    } i;
};
#elif LDBL_MANT_DIG == 113 && LDBL_MAX_EXP == 16384 && __BYTE_ORDER == __LITTLE_ENDIAN
union ldshape {
    long double f;
    struct {
        uint64_t lo;
        uint32_t mid;
        uint16_t top;
        uint16_t se;
    } i;
    struct {
        uint64_t lo;
        uint64_t hi;
    } i2;
};
#elif LDBL_MANT_DIG == 113 && LDBL_MAX_EXP == 16384 && __BYTE_ORDER == __BIG_ENDIAN
union ldshape {
    long double f;
    struct {
        uint16_t se;
        uint16_t top;
        uint32_t mid;
        uint64_t lo;
    } i;
    struct {
        uint64_t hi;
        uint64_t lo;
    } i2;
};
#else
#error Unsupported long double representation
#endif

int __fpclassifyl(long double x);

#define fpclassify(x) (sizeof(x) == sizeof(float) ? __fpclassifyf(x) : sizeof(x) == sizeof(double) ? __fpclassify(x) : __fpclassifyl(x))

#define isinf(x)                                        \
    (sizeof(x) == sizeof(float)                         \
         ? (__FLOAT_BITS(x) & 0x7fffffff) == 0x7f800000 \
         : sizeof(x) == sizeof(double) ? (__DOUBLE_BITS(x) & -1ULL >> 1) == 0x7ffULL << 52 : __fpclassifyl(x) == FP_INFINITE)

#define isnan(x)                                       \
    (sizeof(x) == sizeof(float)                        \
         ? (__FLOAT_BITS(x) & 0x7fffffff) > 0x7f800000 \
         : sizeof(x) == sizeof(double) ? (__DOUBLE_BITS(x) & -1ULL >> 1) > 0x7ffULL << 52 : __fpclassifyl(x) == FP_NAN)

#define isnormal(x)                                                    \
    (sizeof(x) == sizeof(float)                                        \
         ? ((__FLOAT_BITS(x) + 0x00800000) & 0x7fffffff) >= 0x01000000 \
         : sizeof(x) == sizeof(double) ? ((__DOUBLE_BITS(x) + (1ULL << 52)) & -1ULL >> 1) >= 1ULL << 53 : __fpclassifyl(x) == FP_NORMAL)

#define isfinite(x)                                    \
    (sizeof(x) == sizeof(float)                        \
         ? (__FLOAT_BITS(x) & 0x7fffffff) < 0x7f800000 \
         : sizeof(x) == sizeof(double) ? (__DOUBLE_BITS(x) & -1ULL >> 1) < 0x7ffULL << 52 : __fpclassifyl(x) > FP_INFINITE)

int __signbitl(long double x);

#define signbit(x)                                             \
    (sizeof(x) == sizeof(float) ? (int)(__FLOAT_BITS(x) >> 31) \
                                : sizeof(x) == sizeof(double) ? (int)(__DOUBLE_BITS(x) >> 63) : __signbitl(x))

double frexp(double x, int *e);
long double frexpl(long double x, int *e);