// SPDX-License-Identifier: MIT

#pragma once

#include "compiler.h"
#include "shout.h"
#include "x86.h"
#include <stdint.h>

#define NULL_SELECTOR 0x0
#define CODE_SELECTOR 0x8
#define DATA_SELECTOR 0x10

// Top 16 bits is 4K page aligned address, low 16 bits are page flags
typedef uint64_t page_entry;
BUILD_PANIC_IF(sizeof(page_entry) != 8, "page structure must be 64-bit long");

#define PAGE_PRESENT BIT(0)
#define PAGE_WRITABLE BIT(1)
#define PAGE_USERMODE BIT(2) // if the page flag is set then user-mode allows access this memory
#define PAGE_WRITE_THROUGH BIT(3)
#define PAGE_CACHE_DISABLE BIT(4)
#define PAGE_ACCESSED BIT(5) // system accessed this page
#define PAGE_DIRTY BIT(6)
#define PAGE_LARGE BIT(7) // 1G, 2M or 4K page
#define PAGE_NO_EXECUTABLE BIT(63)

#define PAGE_ENTRIES_PER_TABLE (PAGE_SIZE / sizeof(page_entry))
BUILD_PANIC_IF(PAGE_ENTRIES_PER_TABLE != 512);
extern page_entry p4_table[PAGE_ENTRIES_PER_TABLE];

struct PACKED gdt64_pointer {
    uint16_t size;
    uint64_t pointer;
};
extern const struct gdt64_pointer gdt64_pointer;

void page_table_set_bit(size_t start, size_t length, uint64_t mask, uint64_t bits);
void page_table_set_readable(size_t start, size_t length, bool readable);
void page_table_set_writable(size_t start, size_t length, bool writable);
void page_table_set_cacheable(size_t start, size_t length, bool cacheable);
void page_table_set_executable(size_t start, size_t length, bool executable);

void page_table_dump(void);