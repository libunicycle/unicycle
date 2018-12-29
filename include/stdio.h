// SPDX-License-Identifier: MIT

#pragma once

#include "compiler.h"

#include <stdarg.h>
#include <stddef.h>

int printf(const char *fmt, ...) PRINTFLIKE(1, 2);
int vprintf(const char *fmt, va_list ap);

int sprintf(char *str, const char *fmt, ...) PRINTFLIKE(2, 3);
int vsprintf(char *str, const char *fmt, va_list ap);

int snprintf(char *str, size_t len, const char *fmt, ...) PRINTFLIKE(3, 4);
int vsnprintf(char *str, size_t len, const char *fmt, va_list ap);
