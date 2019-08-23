// SPDX-License-Identifier: MIT

#pragma once

#include "compiler.h"
#include "config.h"
#include <stddef.h>
#include <stdint.h>

// TODO: revise the list of memory tags
#define ASAN_TAG_UNINITIALIZED 0xff
#define ASAN_TAG_SLAB_FREED 0xfe

// 0 means all bytes are valid
// 1-7 means only first N bytes are valid and the rest is poisoned
#define ASAN_TAG_RW 0x0

#ifdef CONFIG_ASAN

void asan_enable_reporting(void);
uintptr_t asan_init_shadow(uintptr_t max_addr);
// tag parameter on of the ASAN_TAG_* values
void asan_mark_memory_region(uintptr_t start, size_t size, uint8_t tag);

#else

static inline void asan_enable_reporting(void) {}
static inline void asan_mark_memory_region(UNUSED uintptr_t start, UNUSED size_t size, UNUSED uint8_t tag) {}

#endif