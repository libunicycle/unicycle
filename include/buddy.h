// SPDX-License-Identifier: MIT

#pragma once

#include <stddef.h>
#include <stdint.h>

// Smallest size that can be served by buddy allocator
#define BUDDY_SIZE_GRANULARITY (4 * 1024)

// Add region of memory to allocator, its functionality similar to alloc_buddy_free()
// except its begin/end might cross 2^N area.
// Should be used only at the boot time
void alloc_buddy_append(uintptr_t begin, uintptr_t end);

// Allocates area of given size. Its functionality similar to alloc_buddy_allocate
// except it does not require size to be power of 2.
// Should be used only at the boot time
// void *alloc_buddy_substruct(size_t size);

void *alloc_buddy_allocate(uint32_t page_order);
void alloc_buddy_free(void *area, uint32_t page_order);

// Expands or shrinks buddy area
// Returns pointer to the new area or NULL in case of error (e.g. not possible to expand
// as buddy is already in use).
// void *alloc_buddy_area_resize(void *area, uint32_t new_order);
