// SPDX-License-Identifier: MIT

#include "buddy.h"
#include "asan.h"
#include "lock.h"
#include "mem.h"
#include <stdint.h>

// Low 24 bit of this field represent index in the buddy array.
// Top 8 bits contain order of the largest available space under this buddy.
//
// Index with all bits set to '1' (i.e. 0xffffff) is a 'special' value and it means
// that pointer does not contain a valid index, instead top 8 bits contain state of the
// buddy (e.g. AVAILABLE, UNAVAILABLE, ..)
typedef uint32_t buddy_ptr;

struct buddy {
    buddy_ptr left;  // lower half of buddy
    buddy_ptr right; // upper half of buddy
};

#define BUDDY_INDEX_SPECIAL 0xffffff // 24bit index is all ones
#define BUDDY_UNAVAILABLE 0x01ffffff
#define BUDDY_AVAILABLE 0x02ffffff

// Protects buddy data structures
lock_t buddy_lock = lock_init();

buddy_ptr buddy_root = BUDDY_UNAVAILABLE;
uint32_t buddy_root_order = 0;

// Dynamically allocated array that holds buddies information
struct buddy *buddy_array;
uint64_t *freebits;
size_t freebits_size = 0;
#define FREEBITS_PER_ELEMENT (sizeof(freebits[0]) * 8)

// Size that we pre-allocate for buddy_array during bootstrap
#define BUDDY_BOORSTRAP_ARRAY_ORDER 15
#define BUDDY_BOORSTRAP_ARRAY_SIZE PAGE_ORDER(BUDDY_BOORSTRAP_ARRAY_ORDER)

#define BUDDY_SIZE_ORDER_MIN ILOG2(BUDDY_SIZE_GRANULARITY)
#define BUDDY_SIZE_ORDER_MAX 64

#define BUDDY_PTR_INDEX_MASK 0xffffff
#define BUDDY_PTR_ORDER_MASK 0xff000000
#define BUDDY_PTR_ORDER(x) (((x)&BUDDY_PTR_ORDER_MASK) >> 24)
#define BUDDY_PTR_INDEX(ptr) (((ptr)&BUDDY_PTR_INDEX_MASK))
#define BUDDY_PTR(order, idx) (((order) << 24) | (idx))

static uint32_t buddy_ptr_order(buddy_ptr ptr, uint32_t page_order) {
    if (ptr == BUDDY_UNAVAILABLE)
        return 0;
    else if (ptr == BUDDY_AVAILABLE)
        return page_order;
    else
        return BUDDY_PTR_ORDER(ptr);
}

static uint32_t alloc_buddy_struct_alloc(void) {
    for (size_t i = 0; i < freebits_size; i++) {
        if (freebits[i]) {
            size_t bit = FFS(freebits[i]) - 1;
            freebits[i] &= ~BIT(bit);
            return i * FREEBITS_PER_ELEMENT + bit;
        }
    }

    PANIC("Buddy array is full, cannot allocate a new buddy element");
    // TODO expand the buddy array instead of panicing
}

static void alloc_buddy_struct_free(uint32_t index) {
    size_t idx = index / FREEBITS_PER_ELEMENT;
    size_t bit = index % FREEBITS_PER_ELEMENT;

    SHOUT_IF(idx >= freebits_size, "Trying to free element %d outside of array %ld", index, FREEBITS_PER_ELEMENT * freebits_size);

    SHOUT_IF(freebits[idx] & BIT(bit), "Trying to free element that is not been used");
    freebits[idx] |= BIT(bit);
}

static void validate_buddy_node(buddy_ptr ptr, uint32_t level) {
    if (ptr == BUDDY_AVAILABLE || ptr == BUDDY_UNAVAILABLE)
        return;

    uint32_t index = BUDDY_PTR_INDEX(ptr);
    uint32_t order = BUDDY_PTR_ORDER(ptr);

    struct buddy *buddy = &buddy_array[index];

    // Following line checks for 3 possible invalid situations:
    //   both children point to the same buddy node
    //   both children are available
    //   both children are unavailable
    PANIC_IF(buddy->right == buddy->left);

    uint32_t left_order = buddy_ptr_order(buddy->left, level - 1);
    uint32_t right_order = buddy_ptr_order(buddy->right, level - 1);
    PANIC_IF(order != MAX(left_order, right_order), "order=0x%x, left=0x%x right=0x%x level=0x%x\n", order, buddy->left, buddy->right,
             level);

    validate_buddy_node(buddy->left, level - 1);
    validate_buddy_node(buddy->right, level - 1);
}

static void validate_buddy_array(void) {
    lock(&buddy_lock);
    validate_buddy_node(buddy_root, buddy_root_order);
    unlock(&buddy_lock);
}

// Calculate range order by the biggest address (i.e. end address)
static uint32_t calculate_range_order(uintptr_t end) { return ILOG2_UP(end); }

static void alloc_buddy_append_area(buddy_ptr *ptr, uint32_t page_order, uintptr_t begin, uintptr_t end) {
    PANIC_IF(*ptr == BUDDY_AVAILABLE, "Current buddy is already available, can't add a new space");
    PANIC_IF(begin >= end, "Invalid range adding to buddy: [%lu, %lu)", begin, end);
    PANIC_IF(page_order < BUDDY_SIZE_ORDER_MIN, "Skipping range of a very small order %u\n", page_order);

    // IFVV printf("Inserting range [%lu,%lu) order %u\n", begin, end, page_order);
    if (begin == 0 && end == PAGE_ORDER(page_order)) {
        // XXX if buddy is AVAILABLE then we double add free space, must be some error
        // If buddy is a pointer to other struct - we need to merge buddies, this functionality is not available at bootstrap
        // and at bootstrap we should add non-adjustent areas only
        PANIC_IF(*ptr != BUDDY_UNAVAILABLE, "Expected a buddy in UNAVAILABLE state");
        *ptr = BUDDY_AVAILABLE;
        // IFVV printf("Marking range [%lu,%lu) order %d as AVAILABLE\n", begin, end, page_order);
        return;
    }

    PANIC_IF(page_order < calculate_range_order(end), "Address range is larger than provided page order: %d vs %d", page_order,
             calculate_range_order(end));

    // current buddy_ptr points to a valid struct - reuse it, otherwise allocate a new buddy
    uint32_t buddy_index = BUDDY_PTR_INDEX(*ptr);
    struct buddy *buddy;
    if (buddy_index == BUDDY_INDEX_SPECIAL) {
        buddy_index = alloc_buddy_struct_alloc();
        // IFVV printf("Allocating a new buddy at index %ld\n", buddy_index);
        buddy = &buddy_array[buddy_index];
        buddy->left = BUDDY_UNAVAILABLE;
        buddy->right = BUDDY_UNAVAILABLE;
    } else {
        // IFVV printf("Buddy already exists at index %d\n", buddy_index);
        buddy = &buddy_array[buddy_index];
    }

    uintptr_t half = PAGE_ORDER(page_order - 1);
    if (end <= half) {
        // IFVV printf("Checking left child only\n");
        // the added range belongs to the left child
        alloc_buddy_append_area(&buddy->left, page_order - 1, begin, end);
    } else if (begin >= half) {
        // IFVV printf("Checking right child only\n");
        // the added range belongs to the left child
        alloc_buddy_append_area(&buddy->right, page_order - 1, begin - half, end - half);
    } else {
        // IFVV printf("Checking left and right children, split into [%lu,%lu) and [%lu,%lu)\n", begin, half, half, end);
        // range belongs to 2 buddies, we split the range into 2 parts and insert it separately
        alloc_buddy_append_area(&buddy->left, page_order - 1, begin, half);
        alloc_buddy_append_area(&buddy->right, page_order - 1, 0, end - half);
    }

    // calculate buddy order
    uint32_t left_order = buddy_ptr_order(buddy->left, page_order - 1);
    uint32_t right_order = buddy_ptr_order(buddy->right, page_order - 1);
    uint32_t order = MAX(left_order, right_order); // order of the current buddy
    *ptr = BUDDY_PTR(order, buddy_index);

    if (buddy->left == BUDDY_UNAVAILABLE && buddy->right == BUDDY_UNAVAILABLE) {
        // merge unavailable children
        *ptr = BUDDY_UNAVAILABLE;
        alloc_buddy_struct_free(buddy_index);
    }
    if (buddy->left == BUDDY_AVAILABLE && buddy->right == BUDDY_AVAILABLE) {
        // merge available children
        *ptr = BUDDY_AVAILABLE;
        alloc_buddy_struct_free(buddy_index);
    }
}

// Initialize 'freebits' bitset with 1s. All the elements of buddy_array are free initialy
static void buddy_array_freebits_init(size_t elements) {
    for (size_t i = 0; i < elements / FREEBITS_PER_ELEMENT; i++)
        freebits[i] = ~(uint64_t)0;

    size_t leftover_bits = elements % FREEBITS_PER_ELEMENT;
    if (leftover_bits)
        freebits[elements / FREEBITS_PER_ELEMENT] = PAGE_ORDER(leftover_bits) - 1;
}

void alloc_buddy_expand_root_order(uint32_t new_order) {
    SHOUT_IF(new_order <= buddy_root_order, "New page order need to be bigger than the current one");
    PANIC_IF(buddy_root == BUDDY_UNAVAILABLE, "Expanding uninitialized buddy root");

    uint32_t expansion_num = new_order - buddy_root_order;
    for (uint32_t i = 0; i < expansion_num; i++) {
        uint32_t new_buddy = alloc_buddy_struct_alloc();
        struct buddy *buddy = &buddy_array[new_buddy];
        buddy->left = buddy_root;
        buddy->right = BUDDY_UNAVAILABLE;

        buddy_root = BUDDY_PTR(BUDDY_PTR_ORDER(buddy_root), new_buddy);
    }

    buddy_root_order = new_order;
}

// XXX: at x86 RAM physical address starts at 0. And this algorithm assumes begin is somewhere close to 0.
// But some ARM platform use RAM address that differs from 0. TODO: introduce some const that specifies
// beginning of RAM address.
void alloc_buddy_append(uintptr_t begin, uintptr_t end) {
    if (!IS_ROUNDED(begin, BUDDY_SIZE_GRANULARITY)) {
        IFD printf("Buddy range begin (0x%lx) have to be aligned by 0x%x\n", begin, BUDDY_SIZE_GRANULARITY);
        begin = ROUND_UP(begin, BUDDY_SIZE_GRANULARITY);
    }
    if (!IS_ROUNDED(end, BUDDY_SIZE_GRANULARITY)) {
        IFD printf("Buddy range end (0x%lx) have to be aligned by 0x%x\n", end, BUDDY_SIZE_GRANULARITY);
        end = ROUND_DOWN(end, BUDDY_SIZE_GRANULARITY);
    }

    if (begin == 0) {
        // Address zero has special meaning in many places it is a NULL pointer essentially.
        // Let's not use this area for allocation to catch NULL pointer access errors.
        SHOUT("Trying to add a range that starts at zero");
        begin += BUDDY_SIZE_GRANULARITY;
    }

    if (begin >= end) {
        printf("Adding empty range [%lu,%lu)\n", begin, end);
        // adding empty range
        return;
    }

    // Now we split this address range into blocks of 2^N size and
    // insert to buddy allocator using alloc_buddy_free
    uint32_t range_order = calculate_range_order(end);
    IFVV printf("Buddy: add range begin=0x%lx end=0x%lx range_order=%u\n", begin, end, range_order);

    PANIC_IF(range_order >= BUDDY_SIZE_ORDER_MAX, "Adding range that is bigger than a range we can handle");

    asan_mark_memory_region(begin, end - begin, ASAN_TAG_UNINITIALIZED);

    if (!buddy_array) {
        // Buddy allocator is not initialized, adding its first area requires allocating feebits array from this area

        buddy_root_order = range_order;

        // allocate space for buddy array
        uintptr_t buddy_array_begin = ROUND_UP(begin, BUDDY_BOORSTRAP_ARRAY_SIZE);
        uintptr_t buddy_array_end = buddy_array_begin + BUDDY_BOORSTRAP_ARRAY_SIZE;
        PANIC_IF(buddy_array_end >= end, "Initial range is too small for buddy bootstrap");
        asan_mark_memory_region(buddy_array_begin, BUDDY_BOORSTRAP_ARRAY_SIZE, ASAN_TAG_RW);

        freebits = (uint64_t *)buddy_array_begin;
        // Find how many buddy elements fits this area, note that we need some space for freebits[] array
        freebits_size = DIV_ROUND_UP(BUDDY_BOORSTRAP_ARRAY_SIZE, FREEBITS_PER_ELEMENT * sizeof(struct buddy) + 8);
        size_t buddy_array_size = (BUDDY_BOORSTRAP_ARRAY_SIZE - sizeof(freebits[0]) * freebits_size) / sizeof(struct buddy);
        buddy_array_freebits_init(buddy_array_size);
        IFD printf("Bootstrap buddy allocator with area size 0x%lx. freebits_size is %ld array elements %ld\n", BUDDY_BOORSTRAP_ARRAY_SIZE,
                   freebits_size, buddy_array_size);

        buddy_array = (struct buddy *)(buddy_array_begin + freebits_size * sizeof(freebits[0]));

        // add space [begin, end) to buddy allocator
        if (buddy_array_begin > begin) {
            // begin was not aligned to BUDDY_BOORSTRAP_ARRAY_SIZE and when we allocated space for
            // bootstrap space we've left some space in front this slab
            // adding this space back to buddy allocator
            alloc_buddy_append_area(&buddy_root, buddy_root_order, begin, buddy_array_begin);
        }
        alloc_buddy_append_area(&buddy_root, buddy_root_order, buddy_array_end, end);
    } else {
        if (range_order > buddy_root_order) {
            if (buddy_root == BUDDY_UNAVAILABLE) {
                buddy_root_order = range_order;
            } else {
                // root buddy exists but its order is smaller that area we are trying to add
                // we need to add a few more levels of buddy elements
                alloc_buddy_expand_root_order(range_order);
            }
        }
        alloc_buddy_append_area(&buddy_root, buddy_root_order, begin, end);
    }

    IFD validate_buddy_array();
}

void *alloc_buddy_allocate_ptr(buddy_ptr *ptr, uint32_t current_order, uint32_t requested_order, uintptr_t address) {
    PANIC_IF(current_order < requested_order, "Went too low down the tree");

    // printf("alloc_buddy_allocate_ptr: ptr=0x%x current_order=0x%lx\n", *ptr, current_order);

    void *result;
    if (*ptr == BUDDY_UNAVAILABLE) {
        PANIC("Trying to allocate from an unavailable buddy");
        return NULL;
    } else if (*ptr == BUDDY_AVAILABLE) {
        if (current_order == requested_order) {
            // given buddy is exactly requested size
            *ptr = BUDDY_UNAVAILABLE;
            address <<= current_order;
            result = (void *)address;
        } else {
            // split current buddy struct
            uint32_t new_buddy = alloc_buddy_struct_alloc();
            *ptr = BUDDY_PTR(current_order - 1, new_buddy);
            struct buddy *buddy = &buddy_array[new_buddy];
            buddy->left = BUDDY_AVAILABLE;
            buddy->right = BUDDY_AVAILABLE;

            // allocate from the left (lower address) range
            address <<= 1;
            result = alloc_buddy_allocate_ptr(&buddy->left, current_order - 1, requested_order, address);
        }
    } else {
        uint32_t buddy_idx = BUDDY_PTR_INDEX(*ptr);
        struct buddy *buddy = &buddy_array[buddy_idx];

        uint32_t left_available_order = buddy_ptr_order(buddy->left, current_order - 1);
        uint32_t right_available_order = buddy_ptr_order(buddy->right, current_order - 1);

        PANIC_IF(left_available_order > BUDDY_PTR_ORDER(*ptr), "Order of a left child %d bigger than the parent one %d",
                 left_available_order, BUDDY_PTR_ORDER(*ptr));
        PANIC_IF(right_available_order > BUDDY_PTR_ORDER(*ptr), "Order of a right child %d bigger than the parent one %d",
                 right_available_order, BUDDY_PTR_ORDER(*ptr));

        SHOUT_IF(MAX(left_available_order, right_available_order) < requested_order, "Buddy's children have low available order %d %d",
                 MAX(left_available_order, right_available_order), requested_order);

        // Choose a child that is big enough to handle request but as small as possible.
        // We allocate area from more fragmented subtrees thus avoiding excessive fragmentation.
        // If both children have the same availability order then choose left one.
        bool choose_left;
        if (left_available_order < requested_order)
            choose_left = false;
        else if (right_available_order < requested_order)
            choose_left = true;
        else if (right_available_order < left_available_order)
            choose_left = false;
        else
            choose_left = true;

        address <<= 1;
        if (choose_left) {
            result = alloc_buddy_allocate_ptr(&buddy->left, current_order - 1, requested_order, address);
        } else {
            // right child is upper half of address space and it has the bit set
            address |= 1;
            result = alloc_buddy_allocate_ptr(&buddy->right, current_order - 1, requested_order, address);
        }
    }

    if (BUDDY_PTR_INDEX(*ptr) != BUDDY_INDEX_SPECIAL) {
        uint32_t buddy_idx = BUDDY_PTR_INDEX(*ptr);
        struct buddy *buddy = &buddy_array[buddy_idx];

        // We just allocated area in one of the children and it might turned its ptr to UNAVAILABLE
        if (buddy->left == BUDDY_UNAVAILABLE && buddy->right == BUDDY_UNAVAILABLE) {
            // if both children are marked as UNAVALIBLE then we can merge it and free the current buddy
            *ptr = BUDDY_UNAVAILABLE;
            alloc_buddy_struct_free(buddy_idx);
        } else {
            // update availability order for the parent buddy_ptr
            uint32_t left_available_order = buddy_ptr_order(buddy->left, current_order - 1);
            uint32_t right_available_order = buddy_ptr_order(buddy->right, current_order - 1);
            uint32_t new_avail_order = MAX(left_available_order, right_available_order);
            *ptr = BUDDY_PTR(new_avail_order, buddy_idx);
        }
    }

    return result;
}

void *alloc_buddy_allocate(uint32_t page_order) {
    lock(&buddy_lock);

    uint32_t max_order = buddy_ptr_order(buddy_root, buddy_root_order);
    if (max_order < page_order) {
        SHOUT("Buddy allocator does not have available space for request of order %d\n", page_order);
        return NULL;
    }

    uintptr_t addr = PAGE_ORDER(sizeof(uintptr_t) - buddy_root_order);

    // printf("alloc_buddy_allocate order is %u\n", page_order);
    void *ptr = alloc_buddy_allocate_ptr(&buddy_root, buddy_root_order, page_order, addr);
    unlock(&buddy_lock);

    // printf("alloc_buddy_allocate allocated 0x%p\n", ptr);
    IFD validate_buddy_array();
    return ptr;
}

void alloc_buddy_free_ptr(buddy_ptr *ptr, uint32_t current_order, uint32_t requested_order, uintptr_t address) {
    PANIC_IF(current_order < requested_order);

    // printf("alloc_buddy_free_ptr: ptr=0x%x current_order=%u\n", *ptr, current_order);

    if (*ptr == BUDDY_AVAILABLE) {
        PANIC("Trying to free AVAILABLE buddy");
        return;
    } else if (*ptr == BUDDY_UNAVAILABLE) {
        if (current_order == requested_order) {
            *ptr = BUDDY_AVAILABLE;
        } else {
            // We have a large UNAVAILABLE buddy and we need to split it
            // One part will be marked as AVAILABLE another stays UNAVAILABLE

            uint32_t new_buddy = alloc_buddy_struct_alloc();
            *ptr = BUDDY_PTR(current_order - 1, new_buddy);
            struct buddy *buddy = &buddy_array[new_buddy];
            buddy->left = BUDDY_UNAVAILABLE;
            buddy->right = BUDDY_UNAVAILABLE;

            if (address & BIT(current_order - 1)) {
                alloc_buddy_free_ptr(&buddy->right, current_order - 1, requested_order, address);
            } else {
                alloc_buddy_free_ptr(&buddy->left, current_order - 1, requested_order, address);
            }
        }
    } else {
        uint32_t buddy_idx = BUDDY_PTR_INDEX(*ptr);
        struct buddy *buddy = &buddy_array[buddy_idx];

        buddy_ptr *branch = address & BIT(current_order - 1) ? &buddy->right : &buddy->left;
        alloc_buddy_free_ptr(branch, current_order - 1, requested_order, address);
    }

    if (BUDDY_PTR_INDEX(*ptr) != BUDDY_INDEX_SPECIAL) {
        uint32_t buddy_idx = BUDDY_PTR_INDEX(*ptr);
        struct buddy *buddy = &buddy_array[buddy_idx];

        /// After freeing it might happen that both children become AVAILABLE
        if (buddy->left == BUDDY_AVAILABLE && buddy->right == BUDDY_AVAILABLE) {
            // if both children are marked as AVAILABLE then we can merge it and free the current buddy
            *ptr = BUDDY_AVAILABLE;
            alloc_buddy_struct_free(buddy_idx);
        } else {
            // update availability order for the parent buddy_ptr
            uint32_t left_available_order = buddy_ptr_order(buddy->left, current_order - 1);
            uint32_t right_available_order = buddy_ptr_order(buddy->right, current_order - 1);
            uint32_t new_avail_order = MAX(left_available_order, right_available_order);
            *ptr = BUDDY_PTR(new_avail_order, buddy_idx);
        }
    }
}

void alloc_buddy_free(void *area, uint32_t page_order) {
    PANIC_IF(!area, "Trying to free NULL address");

    uintptr_t address = (uintptr_t)area;

    PANIC_IF(address & (PAGE_ORDER(page_order) - 1), "Requested freeing address 0x%lx, expecting it to be page_order=%d", address,
             page_order);

    PANIC_IF(address & ~(PAGE_ORDER(buddy_root_order) - 1),
             "Requested freeing address 0x%lx, but it has an order (%ld) bigger that currently served by the allocator (%d)", address,
             ILOG2_UP(address), buddy_root_order);

    // printf("Trying to free buddy with address 0x%lx and order %d\n", address, page_order);
    lock(&buddy_lock);
    alloc_buddy_free_ptr(&buddy_root, buddy_root_order, page_order, address);
    unlock(&buddy_lock);

    IFD validate_buddy_array();
}
