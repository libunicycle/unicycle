// SPDX-License-Identifier: MIT

#pragma once

#include "asan.h"
#include "compiler.h"
#include "kalloc.h"
#include "lock.h"
#include "mem.h"
#include "shout.h"
#include "slab.h"
#include "stdio.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define KALLOC_NO_REDZONE BIT(0)     // Do not allocate redzone at the end of the object
#define KALLOC_ASAN_SKIP_INIT BIT(1) // Do not mark allocated area as 'available'
#define KALLOC_WIPE BIT(2)           // Do not mark allocated area as 'available'

static inline void *kalloc_size(size_t size) {
    void *obj = alloc_slab_allocate(size + ASAN_REDZONE_SIZE);
    // TOTHINK: maybe we should pass redzone size to asan function as well?
    // having redzone information there we can check that the area is properly poisoned...
    asan_mark_memory_region((uintptr_t)obj, size, ASAN_TAG_RW);
    return obj;
}

static inline void *kalloc_size_flags(size_t size, uint32_t flags) {
    size_t total_size = size;
    if (!(flags & KALLOC_NO_REDZONE))
        total_size += ASAN_REDZONE_SIZE;
    void *obj = alloc_slab_allocate(total_size);
    if (!(flags & KALLOC_ASAN_SKIP_INIT))
        asan_mark_memory_region((uintptr_t)obj, size, ASAN_TAG_RW);
    PANIC_IF(flags & KALLOC_ASAN_SKIP_INIT && flags & KALLOC_WIPE); // the area is marked as unavailable so we can't touch it here
    if (flags & KALLOC_WIPE)
        memset(obj, 0, size);
    return obj;
}

static inline void *kalloc_align(size_t size, size_t align) {
    PANIC_IF(!ISPOW2(align), "Alignment requirement expected to be power of 2");
    return kalloc_size(ROUND_UP(size, align));
}

// BUILD_PANIC_IF(_Generic((type), void : false, default : true), "Please specify type of allocated object or use kalloc_size()");
#define kalloc(type) ({ (type *)kalloc_align(sizeof(type), __alignof__(type)); })

// Allocate array of types
#define kalloca(type, num) (type *)kalloc_align(sizeof(type) * num, __alignof__(type))

static inline void kfree_size(void *ptr, size_t size) {
    alloc_slab_free(ptr, size + ASAN_REDZONE_SIZE);
    asan_mark_memory_region((uintptr_t)ptr, size, ASAN_TAG_SLAB_FREED);
}

static inline void kfree_size_flags(void *ptr, size_t size, uint32_t flags) {
    size_t total_size = size;
    if (!(flags & KALLOC_NO_REDZONE))
        total_size += ASAN_REDZONE_SIZE;
    alloc_slab_free(ptr, total_size);

    // Note that we mark the memory as 'FREED' even if KALLOC_ASAN_SKIP_INIT is not set.
    // KALLOC_ASAN_SKIP_INIT is more about skipping initialization during allocation.
    // But when we return the memory back we want to be sure nobody accidentally uses it.
    asan_mark_memory_region((uintptr_t)ptr, size, ASAN_TAG_SLAB_FREED);
}

// This macro needs a pointer to valid type (not to void). It uses type to figure out
// data size to be freed.
#define kfree(ptr)                                                                                                                     \
    ({                                                                                                                                 \
        BUILD_PANIC_IF(_Generic((ptr), void * : true, default : false), "Please specify type of freeing pointer or use kfree_size()"); \
        kfree_size(ptr, sizeof(*ptr));                                                                                                 \
    })
