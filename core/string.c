// SPDX-License-Identifier: MIT

#include "string.h"
#include <stdbool.h>

size_t strlen(const char *s) {
    size_t res = 0;
    while (*s++) {
        res++;
    }
    return res;
}

size_t strnlen(const char *s, size_t maxlen) {
    size_t res = 0;
    while (*s++ && maxlen-- > 0) {
        res++;
    }
    return res;
}

int strcmp(const char *s1, const char *s2) {
    for (; *s1 && *s2 && *s1 == *s2; s1++, s2++)
        ;
    return *s1 - *s2;
}

int strncmp(const char *s1, const char *s2, size_t n) {
    for (; *s1 && *s2 && n && *s1 == *s2; s1++, s2++, n--)
        ;

    return n == 0 ? 0 : *s1 - *s2;
}

/* Lookup table for digit values. '0' <= X <= 'z */
static const int8_t table[] = {0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  -1, -1, -1, -1, -1, -1, -1, 10, 11, 12, 13, 14, 15, 16, 17,
                               18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, -1, -1, -1, -1, -1, -1, 10,
                               11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35};

int64_t strtonum(const char *nptr, const char **endptr, int base) {
    int64_t result = 0;
    bool negative = false;

    while (*nptr == ' ') {
        // skip leading spaces
        nptr++;
    }

    if (*nptr == '-') {
        negative = true;
        nptr++;
    }

    while (true) {
        char chr = *nptr++;
        if (chr < '0' || chr > 'z') {
            // out of range
            break;
        }
        int8_t digit = table[chr - '0'];
        if (digit >= base)
            break; // out of range

        result = base * result + digit;
    }

    if (negative)
        result = -result;

    if (endptr)
        *endptr = nptr;

    return result;
}

int isalpha(int c) { return ((unsigned)c | 32) - 'a' < 26; }

int isprint(int c) { return (unsigned)c - 0x20 < 0x5f; }

int isdigit(int c) { return (unsigned)c - '0' < 10; }

int isxdigit(int c) { return isdigit(c) || ((unsigned)c | 32) - 'a' < 6; }

int isspace(int c) { return c == ' ' || (unsigned)c - '\t' < 5; }

char *strcpy(char *restrict dest, const char *restrict src) {
    const char *s = src;
    char *d = dest;
    while ((*d++ = *s++))
        ;
    return dest;
}

char *strncpy(char *dest, const char *src, size_t n) {
    size_t i;

    for (i = 0; i < n && src[i] != '\0'; i++)
        dest[i] = src[i];
    for (; i < n; i++)
        dest[i] = '\0';

    return dest;
}

char *strcat(char *restrict dest, const char *restrict src) {
    strcpy(dest + strlen(dest), src);
    return dest;
}

char *strncat(char *restrict d, const char *restrict s, size_t n) {
    char *a = d;
    d += strlen(d);
    while (n && *s)
        n--, *d++ = *s++;
    *d++ = 0;
    return a;
}

char *strstr(const char *haystack, const char *needle) {
    if (!*needle) {
        return (char *)haystack;
    }

    for (; *haystack; haystack++) {
        // check that the first symbol of needle matches
        if (*haystack != *needle) {
            continue;
        }

        const char *a = haystack;
        const char *b = needle;

        while (true) {
            if (!*b) {
                return (char *)haystack;
            }
            if (*a++ != *b++) {
                break;
            }
        }
    }

    return NULL;
}

int toupper(int c) {
    if (islower(c))
        return c & 0x5f;
    return c;
}

int tolower(int c) {
    if (isupper(c))
        return c | 32;
    return c;
}

int isupper(int c) { return (unsigned)c - 'A' < 26; }

int islower(int c) { return (unsigned)c - 'a' < 26; }
