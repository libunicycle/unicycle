/* This file is based on MUSL project code */

#include "float.h"
#include "arch.h"
#include <stdint.h>

#if LDBL_MANT_DIG == 53 && LDBL_MAX_EXP == 1024
long double frexpl(long double x, int *e) { return frexp(x, e); }
#elif (LDBL_MANT_DIG == 64 || LDBL_MANT_DIG == 113) && LDBL_MAX_EXP == 16384
long double frexpl(long double x, int *e) {
    union ldshape u = {x};
    int ee = u.i.se & 0x7fff;

    if (!ee) {
        if (x) {
            x = frexpl(x * 0x1p120, e);
            *e -= 120;
        } else
            *e = 0;
        return x;
    } else if (ee == 0x7fff) {
        return x;
    }

    *e = ee - 0x3ffe;
    u.i.se &= 0x8000;
    u.i.se |= 0x3ffe;
    return u.f;
}
#endif

double frexp(double x, int *e) {
    union {
        double d;
        uint64_t i;
    } y = {x};
    int ee = y.i >> 52 & 0x7ff;

    if (!ee) {
        if (x) {
            x = frexp(x * 0x1p64, e);
            *e -= 64;
        } else
            *e = 0;
        return x;
    } else if (ee == 0x7ff) {
        return x;
    }

    *e = ee - 0x3fe;
    y.i &= 0x800fffffffffffffull;
    y.i |= 0x3fe0000000000000ull;
    return y.d;
}

#if LDBL_MANT_DIG == 53 && LDBL_MAX_EXP == 1024
int __fpclassifyl(long double x) { return __fpclassify(x); }
#elif LDBL_MANT_DIG == 64 && LDBL_MAX_EXP == 16384
int __fpclassifyl(long double x) {
    union ldshape u = {x};
    int e = u.i.se & 0x7fff;
    int msb = u.i.m >> 63;
    if (!e && !msb)
        return u.i.m ? FP_SUBNORMAL : FP_ZERO;
    if (!msb)
        return FP_NAN;
    if (e == 0x7fff)
        return u.i.m << 1 ? FP_NAN : FP_INFINITE;
    return FP_NORMAL;
}
#elif LDBL_MANT_DIG == 113 && LDBL_MAX_EXP == 16384
int __fpclassifyl(long double x) {
    union ldshape u = {x};
    int e = u.i.se & 0x7fff;
    u.i.se = 0;
    if (!e)
        return u.i2.lo | u.i2.hi ? FP_SUBNORMAL : FP_ZERO;
    if (e == 0x7fff)
        return u.i2.lo | u.i2.hi ? FP_NAN : FP_INFINITE;
    return FP_NORMAL;
}
#endif

#if (LDBL_MANT_DIG == 64 || LDBL_MANT_DIG == 113) && LDBL_MAX_EXP == 16384
int __signbitl(long double x) {
    union ldshape u = {x};
    return u.i.se >> 15;
}
#elif LDBL_MANT_DIG == 53 && LDBL_MAX_EXP == 1024
int __signbitl(long double x) { return __signbit(x); }
#endif