// SPDX-License-Identifier: MIT

#pragma once

#include <stddef.h>

typedef struct mbstate mbstate_t;

size_t wcrtomb(char *restrict s, wchar_t wc, mbstate_t *restrict st);
int wctomb(char *s, wchar_t wc);