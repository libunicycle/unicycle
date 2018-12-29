#pragma once

#include <stddef.h>

void sort(void *array, size_t num, size_t elem_size, int (*cmp)(const void *, const void *));
