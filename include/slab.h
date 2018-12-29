// SPDX-License-Identifier: MIT

#pragma once

#include <stddef.h>
#include <stdint.h>

// slab allocator works with objects up to 32KiB
// anything else should be allocated with buddy allocator
#define ALLOC_SLAB_MAX_SIZE (32 * 1024)

void *alloc_slab_allocate(size_t size);
void alloc_slab_free(void *obj, size_t size);