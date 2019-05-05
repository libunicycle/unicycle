// SPDX-License-Identifier: MIT

#include "asan.h"
#include "mem.h"
#include "shout.h"
#include "stack.h"
#include <stddef.h>
#include <stdio.h>

#define ASAN_GRANULARITY 8
#define ASAN_GRANULARITY_MASK ((uintptr_t)ASAN_GRANULARITY - 1)

uintptr_t asan_shadow_start;
uintptr_t asan_shadow_length;
bool asan_reporting_enabled;
PERCPU uint32_t asan_depth;

static void report_invalid_access(uintptr_t addr, size_t size, bool write) {
    if (!asan_reporting_enabled)
        return;

    // ASAN report codepath might call __asan_*().
    // Return here to avoid infinite recursion
    if (asan_depth > 0)
        return;

    asan_depth++;

    printf("!!!!!!!! invalid access to address 0x%lx size=0x%lx write=%d at IP=%p\n", addr, size, write, __builtin_return_address(0));
    dump_stack();

    asan_depth--;
}

static void *asan_addr_to_shadow(uintptr_t addr) { return (void *)(addr / ASAN_GRANULARITY + asan_shadow_start); }

static inline bool memory_is_poisoned_1(uintptr_t addr) {
    int8_t shadow_value = *(int8_t *)asan_addr_to_shadow(addr);
    if (shadow_value == ASAN_TAG_RW)
        return false;

    int8_t last_accessible_byte = addr & ASAN_GRANULARITY_MASK;
    return last_accessible_byte >= shadow_value;
}

static inline bool memory_is_poisoned_2_4_8(uintptr_t addr, size_t size) {
    uint8_t *shadow_addr = (uint8_t *)asan_addr_to_shadow(addr);

    if (((addr + size - 1) & ASAN_GRANULARITY_MASK) < size - 1)
        return *shadow_addr || memory_is_poisoned_1(addr + size - 1);

    return memory_is_poisoned_1(addr + size - 1);
}

static inline bool memory_is_poisoned_16(uintptr_t addr) {
    uint16_t *shadow_addr = (uint16_t *)asan_addr_to_shadow(addr);

    if (!IS_ROUNDED(addr, ASAN_GRANULARITY))
        return *shadow_addr || memory_is_poisoned_1(addr + 15);

    return *shadow_addr;
}

static inline uintptr_t bytes_is_nonzero(const uint8_t *start, size_t size) {
    while (size) {
        if (*start)
            return (uintptr_t)start;
        start++;
        size--;
    }

    return 0;
}

static inline uintptr_t memory_is_nonzero(const void *start, const void *end) {
    unsigned int prefix = (unsigned long)start % 8;

    if (end - start <= 16)
        return bytes_is_nonzero(start, end - start);

    if (prefix) {
        prefix = 8 - prefix;
        uintptr_t ret = bytes_is_nonzero(start, prefix);
        if (ret)
            return ret;
        start += prefix;
    }

    size_t words = (end - start) / 8;
    while (words) {
        if (*(uint64_t *)start)
            return bytes_is_nonzero(start, 8);
        start += 8;
        words--;
    }

    return bytes_is_nonzero(start, (end - start) % 8);
}

static inline bool memory_is_poisoned_n(uintptr_t addr, size_t size) {
    uintptr_t ret = memory_is_nonzero(asan_addr_to_shadow(addr), asan_addr_to_shadow(addr + size - 1) + 1);

    if (ret) {
        uintptr_t last_byte = addr + size - 1;
        int8_t *last_shadow = (int8_t *)asan_addr_to_shadow(last_byte);

        if ((ret != (uintptr_t)last_shadow || ((int8_t)(last_byte & ASAN_GRANULARITY_MASK) >= *last_shadow)))
            return true;
    }
    return false;
}

static inline bool memory_is_poisoned(uintptr_t addr, size_t size) {
    if (addr >= asan_shadow_start)
        return false;

    if (__builtin_constant_p(size)) {
        switch (size) {
        case 1:
            return memory_is_poisoned_1(addr);
        case 2:
        case 4:
        case 8:
            return memory_is_poisoned_2_4_8(addr, size);
        case 16:
            return memory_is_poisoned_16(addr);
        default:
            // TODO: it needs to be a build bug like BUILD_ASSERT(0)
            __builtin_trap();
            return true;
        }
    }

    return memory_is_poisoned_n(addr, size);
}

static inline void asan_load_store_callback(uintptr_t addr, size_t size, bool write) {
    if (memory_is_poisoned(addr, size))
        report_invalid_access(addr, size, write);
}

#define ASAN_LOAD_STORE_CALLBACK(size)                                                                                                    \
    __attribute__((externally_visible)) void __asan_load##size##_noabort(uintptr_t addr) { asan_load_store_callback(addr, size, false); } \
    __attribute__((externally_visible)) void __asan_store##size##_noabort(uintptr_t addr) { asan_load_store_callback(addr, size, true); }

ASAN_LOAD_STORE_CALLBACK(1);
ASAN_LOAD_STORE_CALLBACK(2);
ASAN_LOAD_STORE_CALLBACK(4);
ASAN_LOAD_STORE_CALLBACK(8);
ASAN_LOAD_STORE_CALLBACK(16);

__attribute__((externally_visible)) void __asan_loadN_noabort(uintptr_t addr, size_t size) { asan_load_store_callback(addr, size, false); }
__attribute__((externally_visible)) void __asan_storeN_noabort(uintptr_t addr, size_t size) { asan_load_store_callback(addr, size, true); }

__attribute__((externally_visible)) void __asan_handle_no_return(void) {}

void asan_mark_memory_region(uintptr_t start, size_t size, uint8_t tag) {
    // Some writes to MMIO are instructed by ASAN but have no corresponding shadow area
    // Check if the region that we want to mark is inside of the area managed by ASAN
    if (start >= asan_shadow_start)
        return;

    PANIC_IF(!IS_ROUNDED(start, ASAN_GRANULARITY));

    void *shadow_mem = asan_addr_to_shadow(start);

    // PANIC_IF(shadow_offset + DIV_ROUND_UP(size, ASAN_GRANULARITY) > asan_shadow_length);

    memset(shadow_mem, tag, size / ASAN_GRANULARITY);

    if (size & ASAN_GRANULARITY_MASK) {
        uint8_t *last_byte = shadow_mem + size / ASAN_GRANULARITY;
        if (tag == ASAN_TAG_RW)
            // if we unpoison the memory and the last byte is not fully unpoisened then we need to set it correctly
            *last_byte = size & ASAN_GRANULARITY_MASK;
        else
            *last_byte = tag;
    }
}

void asan_enable_reporting(void) { asan_reporting_enabled = true; }

#define PAGE_SIZE 4096 // TODO: move this const to arch-independent header

uintptr_t asan_init_shadow(uintptr_t max_addr) {
    uintptr_t shadow_start = ROUND_DOWN(max_addr / (ASAN_GRANULARITY + 1) * ASAN_GRANULARITY, PAGE_SIZE);

    asan_shadow_start = shadow_start;
    asan_shadow_length = max_addr - shadow_start;

    // mark all memory as uninitialized
    memset((void *)asan_shadow_start, ASAN_TAG_UNINITIALIZED, asan_shadow_length);
    printf("ASAN shadow initialized at 0x%lx and has size 0x%lx\n", asan_shadow_start, asan_shadow_length);

    return shadow_start;
}
