// SPDX-License-Identifier: MIT

#include "mem.h"

void memset(void *p, uint8_t c, size_t n) { memset8(p, c, n); }

void memset8(uint8_t *p, uint8_t c, size_t n) {
    for (size_t i = 0; i < n; i++) {
        *p++ = c;
    }
}

void memset16(uint16_t *p, uint16_t c, size_t n) {
    for (size_t i = 0; i < n; i++) {
        *p++ = c;
    }
}

void memset32(uint32_t *p, uint32_t c, size_t n) {
    for (size_t i = 0; i < n; i++) {
        *p++ = c;
    }
}

void memset64(uint64_t *p, uint64_t c, size_t n) {
    for (size_t i = 0; i < n; i++) {
        *p++ = c;
    }
}

void memcpy(void *dest, const void *src, size_t n) { memcpy8(dest, src, n); }

void memcpy8(uint8_t *dest, const uint8_t *src, size_t n) {
    for (size_t i = 0; i < n; i++) {
        *dest++ = *src++;
    }
}

void memcpy16(uint16_t *dest, const uint16_t *src, size_t n) {
    for (size_t i = 0; i < n; i++) {
        *dest++ = *src++;
    }
}

void memcpy32(uint32_t *dest, const uint32_t *src, size_t n) {
    for (size_t i = 0; i < n; i++) {
        *dest++ = *src++;
    }
}

void memcpy64(uint64_t *dest, const uint64_t *src, size_t n) {
    for (size_t i = 0; i < n; i++) {
        *dest++ = *src++;
    }
}

const void *memchr(const void *s, char c, size_t n) {
    for (size_t i = 0; i < n; i++, s++) {
        if (*(char *)s == c)
            return s;
    }
    return NULL;
}
const void *memrchr(const void *s, char c, size_t n) {
    const char *ptr = s + n - 1;
    for (size_t i = 0; i < n; i++, s--) {
        if (*ptr == c)
            return s;
    }
    return NULL;
}

int memcmp(const void *vl, const void *vr, size_t n) {
    const unsigned char *l = vl, *r = vr;
    for (; n && *l == *r; n--, l++, r++)
        ;
    return n ? *l - *r : 0;
}
