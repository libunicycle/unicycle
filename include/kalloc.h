// SPDX-License-Identifier: MIT

#pragma once

#include "shout.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

void *kalloc_align(size_t size, size_t align);
void *kalloc_size(size_t size);

// BUILD_PANIC_IF(_Generic((type), void : false, default : true), "Please specify type of allocated object or use kalloc_size()");
#define kalloc(type) ({ (type *)kalloc_align(sizeof(type), __alignof__(type)); })

// Allocate array of types
#define kalloca(type, num) (type *)kalloc_align(sizeof(type) * num, __alignof__(type))

void kfree_size(void *ptr, size_t size);

// This macro needs a pointer to valid type (not to void). It uses type to figure out
// data size to be freed.
#define kfree(ptr)                                                                                                                     \
    ({                                                                                                                                 \
        BUILD_PANIC_IF(_Generic((ptr), void * : true, default : false), "Please specify type of freeing pointer or use kfree_size()"); \
        kfree_size(ptr, sizeof(*ptr));                                                                                                 \
    })
