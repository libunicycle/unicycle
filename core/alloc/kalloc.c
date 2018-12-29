// SPDX-License-Identifier: MIT

// Unicycle memory allocator

#include "kalloc.h"
#include "compiler.h"
#include "lock.h"
#include "shout.h"
#include "slab.h"
#include "stdio.h"
#include <stdbool.h>

inline void kfree_size(void *ptr, size_t size) { alloc_slab_free(ptr, size); }

inline void *kalloc_size(size_t size) { return alloc_slab_allocate(size); }

inline void *kalloc_align(size_t size, size_t align) {
    PANIC_IF(!ISPOW2(align), "Alignment requirement expected to be power of 2");
    return kalloc_size(ROUND_UP(size, align));
}
