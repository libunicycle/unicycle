// SPDX-License-Identifier: MIT

#include "mmu.h"
#include "compiler.h"
#include "kalloc.h"
#include "mem.h"
#include <stdint.h>

struct descriptor_table {
    uint16_t limit;
    uint16_t address;
    uint8_t address_16_23;
    uint8_t access; // access and type
    uint8_t flags;  // limit 16-19 and flags;
    uint8_t address_24_31;
};

BUILD_PANIC_IF(sizeof(struct descriptor_table) != 8, "descriptor_table structure must be 64-bit long");

#define SEG_NULL \
    { 0, 0, 0, 0, 0, 0 }
#define SEG_CODE_64(dpl) \
    { 0, 0, 0, (((1 /*p*/) << 7) | ((dpl) << 5) | 0x18 | ((0 /*c*/) << 2)), (((0 /*d*/) << 6) | ((1 /*l*/) << 5)), 0 }
#define SEG_DATA_64(dpl) \
    { 0xffff, 0, 0, (0x92 | ((dpl) << 5)), 0x8f, 0 }

const struct descriptor_table gdt64[] ALIGNED(8) = {
    SEG_NULL, SEG_CODE_64(0), SEG_DATA_64(0), // we use the data segment for %fs/%gs
};

const struct gdt64_pointer gdt64_pointer ALIGNED(8) = {
    .size = sizeof(gdt64) - 1,
    .pointer = (uint64_t)gdt64,
};

page_entry p4_table[PAGE_ENTRIES_PER_TABLE] ALIGNED(PAGE_SIZE);

// We track only following page table bits
#define PAGE_TABLE_BITS_MASK (PAGE_PRESENT | PAGE_WRITABLE | PAGE_CACHE_DISABLE | PAGE_WRITE_THROUGH | PAGE_NO_EXECUTABLE)

#define L4_ADDR_OFFSET 39
#define L4_PAGE_ENTRY_SIZE ((uintptr_t)1 << L4_ADDR_OFFSET) // 512G
#define L3_ADDR_OFFSET 30
#define L3_PAGE_ENTRY_SIZE ((uintptr_t)1 << L3_ADDR_OFFSET) // 1G
#define L2_ADDR_OFFSET 21
#define L2_PAGE_ENTRY_SIZE ((uintptr_t)1 << L2_ADDR_OFFSET) // 2M
#define L1_ADDR_OFFSET 12
#define L1_PAGE_ENTRY_SIZE ((uintptr_t)1 << L1_ADDR_OFFSET) // 4K

static const size_t PAGE_ENTRY_SIZES[] = {L1_PAGE_ENTRY_SIZE, L2_PAGE_ENTRY_SIZE, L3_PAGE_ENTRY_SIZE, L4_PAGE_ENTRY_SIZE};

#define PAGE_ENTRY_ADDR_MASK (((1UL << 36) - 1) << 12)

static page_entry *page_entry_split(page_entry *future_parent, size_t level /* children's level */, uint64_t address) {
    // printf("page_entry_split dir 0x%lx start 0x%lx level %ld\n", (uintptr_t)future_parent, *future_parent & PAGE_ENTRY_ADDR_MASK, level);
    PANIC_IF(level < 1, "There is no such thing as 0-level page");
    page_entry *dir = kalloc_size_noredzone(PAGE_SIZE);
    memset(dir, 0, PAGE_SIZE);
    size_t page_size = PAGE_ENTRY_SIZES[level - 1];

    if (level > 1)
        address |= PAGE_LARGE;

    for (size_t i = 0; i < PAGE_ENTRIES_PER_TABLE; i++) {
        dir[i] = address;
        address += page_size;
    }

    *future_parent &= ~PAGE_LARGE; // clear the flag as parent points to directory now
    // now future_parent points to the page directory; update the parent pointer
    *future_parent = (*future_parent & ~PAGE_ENTRY_ADDR_MASK) | (uintptr_t)dir;

    // printf("page_entry_split dir 0x%lx points now to 0x%lx\n", (uintptr_t)future_parent, (uintptr_t)dir);
    return dir;
}

static void page_dir_normalize(page_entry *page_dir, page_entry *parent_entry, size_t level) {
    // Check if current level page mapping can be folded back to parent
    if (level < 3) {
        // only level 1 and 2 can be folded back to parent
        uint64_t expected_flags = page_dir[0] & ~PAGE_ENTRY_ADDR_MASK;
        expected_flags |= PAGE_LARGE; // to fold the directory the entries must not have children
        bool canfold = true;
        for (size_t i = 0; i < PAGE_ENTRIES_PER_TABLE; i++) {
            if ((page_dir[i] & ~PAGE_ENTRY_ADDR_MASK) != expected_flags) {
                canfold = false;
                break;
            }
        }

        if (canfold) {
            // printf("merge page dir at address %lx level %ld into parent\n", page_dir[0] & PAGE_ENTRY_ADDR_MASK, level);
            *parent_entry = expected_flags | PAGE_LARGE | (page_dir[0] & PAGE_ENTRY_ADDR_MASK);
            kfree_size_noredzone(page_dir, PAGE_SIZE);

            return;
        }
    }

    // check flags in page_dir and propagate it to parent_entry
    if (level < 4) {
        uint64_t flags_at_least_once = 0;  // tracks what flags were set at least once
        uint64_t flags_all = (uint64_t)-1; // tracks flags that were set in all entries

        for (size_t i = 0; i < PAGE_ENTRIES_PER_TABLE; i++) {
            // if there is at least one Present/Writable then parent should have it as well
            flags_at_least_once |= page_dir[i];

            // if all cache-disable, no-execute then parent should have it as well
            flags_all &= page_dir[i];
        }
        *parent_entry = (*parent_entry & PAGE_ENTRY_ADDR_MASK) | (flags_at_least_once & (PAGE_PRESENT | PAGE_WRITABLE)) |
                        (flags_all & (PAGE_CACHE_DISABLE | PAGE_NO_EXECUTABLE));
    }
}

static void page_dir_traverse(page_entry *page_dir, page_entry *parent_entry, size_t level, size_t offset, size_t *length, uint64_t mask,
                              uint64_t flags) {
    size_t page_entry_size = PAGE_ENTRY_SIZES[level - 1];
    size_t page_index = offset / page_entry_size;
    PANIC_IF(page_index >= PAGE_ENTRIES_PER_TABLE, "Page index %ld is bigger than entries count %ld", page_index, PAGE_ENTRIES_PER_TABLE);
    offset %= page_entry_size;

    // printf("pe_traverse dir=0x%lx offset=0x%lx length=0x%lx level=%ld page_size=0x%lx\n", (uintptr_t)page_dir, offset, *length, level,
    //       page_entry_size);

    for (; *length && page_index < PAGE_ENTRIES_PER_TABLE; page_index++, offset = 0) {
        page_entry entry = page_dir[page_index];

        if (level == 1) {
            // this page points to address rather than to the next level of page tables
            *length -= page_entry_size;
            page_dir[page_index] = (entry & ~mask) | flags;
            continue;
        }

        page_entry *child_pd = (page_entry *)(entry & PAGE_ENTRY_ADDR_MASK);
        if (level == 4) {
            // this L4->L3 directory pointer is not initialized yet, do it now
            if (!child_pd) {
                uint64_t addr = L4_PAGE_ENTRY_SIZE * page_index; // address
                addr |= (entry & ~PAGE_ENTRY_ADDR_MASK);         // and parent flags as well
                child_pd = page_entry_split(&page_dir[page_index], level - 1, addr);
            }
            page_dir_traverse(child_pd, &page_dir[page_index], level - 1, offset, length, mask, flags);
            continue;
        }

        if (!(entry & PAGE_LARGE)) {
            page_dir_traverse(child_pd, &page_dir[page_index], level - 1, offset, length, mask, flags);
            continue;
        }

        if ((entry & mask) == flags) {
            // printf("No need to split the page as the target flags 0x%lx are the same as dir\n", flags);
            // optimization: if new flags are the same as existing then no need to split/modify the entry
            size_t consumed_length = page_entry_size - offset;
            if (*length < consumed_length)
                consumed_length = *length;

            *length -= consumed_length;
            continue;
        }

        if (offset || *length < page_entry_size) {
            page_entry *child_pd = page_entry_split(&page_dir[page_index], level - 1, page_dir[page_index]);
            page_dir_traverse(child_pd, &page_dir[page_index], level - 1, offset, length, mask, flags);
            continue;
        }

        *length -= page_entry_size;
        page_dir[page_index] = (entry & ~mask) | flags;
        continue;
    }

    page_dir_normalize(page_dir, parent_entry, level);
}

const uint64_t flags[] = {PAGE_PRESENT, PAGE_WRITABLE, PAGE_CACHE_DISABLE, PAGE_NO_EXECUTABLE};
const char *flags_mnemonics = "PWCX";
const uint64_t reverse_flags = PAGE_CACHE_DISABLE | PAGE_NO_EXECUTABLE;

void page_table_set_bit(size_t start, size_t length, uint64_t mask, uint64_t bits) {
    PANIC_IF(start % PAGE_SIZE, "Address is not aligned to page size");
    PANIC_IF(length % PAGE_SIZE, "Range length is not aligned to page size");

    printf("page_table_set_bit [0x%lx-0x%lx) len=0x%lx ", start, start + length, length);
    // Flags that have reverse connatation, e.g. NO_EXECUTABLE flag should be printed as -X
    uint64_t print_bits = bits ^ reverse_flags;
    for (size_t i = 0; i < ARRAY_SIZE(flags); i++) {
        if (!(mask & flags[i]))
            continue;
        char sign = print_bits & flags[i] ? '+' : '-';
        printf("%c%c", sign, flags_mnemonics[i]);
    }
    printf("\n");

    page_dir_traverse(p4_table, NULL, 4, start, &length, mask, bits);
    PANIC_IF(length, "Region is not completely consumed");
}

void page_table_set_readable(size_t start, size_t length, bool readable) {
    page_table_set_bit(start, length, PAGE_PRESENT, readable ? PAGE_PRESENT : 0);
}

void page_table_set_writable(size_t start, size_t length, bool writable) {
    page_table_set_bit(start, length, PAGE_WRITABLE, writable ? PAGE_WRITABLE : 0);
}

void page_table_set_cacheable(size_t start, size_t length, bool cacheable) {
    page_table_set_bit(start, length, PAGE_CACHE_DISABLE, cacheable ? 0 : PAGE_CACHE_DISABLE);
}

void page_table_set_executable(size_t start, size_t length, bool executable) {
    page_table_set_bit(start, length, PAGE_NO_EXECUTABLE, executable ? 0 : PAGE_NO_EXECUTABLE);
}

static void page_table_dump_level(page_entry *page_dir, size_t level) {
    for (size_t i = 0; i < PAGE_ENTRIES_PER_TABLE; i++) {
        for (size_t n = level; n < 4; n++) {
            printf("  "); // indentation
        }

        page_entry ent = page_dir[i];
        uint64_t addr = ent & PAGE_ENTRY_ADDR_MASK;
        bool recurse = false;

        if (ent & PAGE_LARGE || level == 1) {
            printf("%lx ", addr);
        } else if (level == 4 && !addr) {
            printf("0 ");
        } else {
            printf("- ");
            recurse = true;
        }

        uint64_t bits = ent ^ reverse_flags;
        for (size_t i = 0; i < ARRAY_SIZE(flags); i++) {
            if (!(bits & flags[i]))
                continue;

            printf("%c", flags_mnemonics[i]);
        }

        printf("\n");

        if (recurse)
            page_table_dump_level((page_entry *)addr, level - 1);
    }
}

void page_table_dump(void) { page_table_dump_level(p4_table, 4); }
