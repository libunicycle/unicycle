// SPDX-License-Identifier: MIT

#pragma once

#include <stddef.h>
#include <stdint.h>

size_t strlen(const char *s);
size_t strnlen(const char *s, size_t maxlen);
int strcmp(const char *s1, const char *s2);
int strncmp(const char *s1, const char *s2, size_t n);
char *strcat(char *restrict dest, const char *restrict src);
char *strncat(char *restrict d, const char *restrict s, size_t n);
char *strcpy(char *restrict dest, const char *restrict src);
char *strncpy(char *dest, const char *src, size_t n);
char *strstr(const char *haystack, const char *needle);

int64_t strtonum(const char *nptr, const char **endptr, int base);
#define strtoul strtonum

int isalpha(int c);
int isprint(int c);
int isspace(int c);
int isdigit(int c);
int isxdigit(int c);

int toupper(int c);
int tolower(int c);

int isupper(int c);
int islower(int c);