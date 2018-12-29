// SPDX-License-Identifier: MIT

#include "acutest.h"
#include "buddy.h"
#include "slab.h"
#include <stdlib.h>

// Buddy allocator internal structures
extern uint32_t buddy_root;
extern size_t buddy_root_order;
extern struct buddy *buddy_array;
extern uint64_t *freebits;
extern size_t freebits_size;

#define BUDDY_PTR_ORDER(x) (((x)&0xff000000) >> 24)
#define BUDDY_PTR_INDEX(ptr) (((ptr)&0xffffff))

void test_buddy(void) {
    const size_t malloc_size = 0x10000000; // 10 MiB
    void *area = aligned_alloc(malloc_size, malloc_size);
    TEST_CHECK(area != NULL);
    alloc_buddy_append((uintptr_t)area, (uintptr_t)area + malloc_size);

    TEST_CHECK((uintptr_t)area <= (uintptr_t)freebits && (uintptr_t)freebits < (uintptr_t)area + malloc_size);
    TEST_CHECK(freebits_size == 64);
    TEST_CHECK(freebits[0] == 0xffffffff00000000);

    // Part of the area been allocated to buddy_array thus maximum available order is one less that added order
    TEST_CHECK_(BUDDY_PTR_ORDER(buddy_root) == 27, "Expected buddy root order is 0x%x, got 0x%x", 27, BUDDY_PTR_ORDER(buddy_root));

    void *ptr = alloc_buddy_allocate(27);
    TEST_CHECK(ptr != NULL);
    uintptr_t expected_ptr = (uintptr_t)area + malloc_size / 2; // second half of available area will be allocated for this buddy
    TEST_CHECK_(expected_ptr == (uintptr_t)ptr, "Expected address %p, got %p", expected_ptr, ptr);
    TEST_CHECK_(BUDDY_PTR_ORDER(buddy_root) == 26, "Expected buddy root order is 0x%x, got 0x%x", 26, BUDDY_PTR_ORDER(buddy_root));

    // Second allocation should fail as we do not have enough space available
    TEST_CHECK(alloc_buddy_allocate(27) == NULL);

    // freeing buddy should increase available order back to 27
    alloc_buddy_free(ptr, 27);
    TEST_CHECK(BUDDY_PTR_ORDER(buddy_root) == 27);

    free(area);
}

void test_buddy_expanding_root_order(void) {
    const size_t malloc_size = 0x10000;
    void *area = aligned_alloc(malloc_size, malloc_size);
    TEST_CHECK(area != NULL);
    alloc_buddy_append((uintptr_t)area, (uintptr_t)area + malloc_size);
    TEST_CHECK_(BUDDY_PTR_ORDER(buddy_root) == 27, "Expected buddy free root order is 0x%x, got 0x%x", 27, BUDDY_PTR_ORDER(buddy_root));
    TEST_CHECK_(buddy_root_order == 27, "Expected buddy root order is 0x%x, got 0x%x", 27, buddy_root_order);

    area = (uintptr_t)area << 1;
    alloc_buddy_append((uintptr_t)area, (uintptr_t)area + malloc_size);
    TEST_CHECK_(BUDDY_PTR_ORDER(buddy_root) == 27, "Expected buddy free root order is 0x%x, got 0x%x", 27, BUDDY_PTR_ORDER(buddy_root));
    TEST_CHECK_(buddy_root_order == 28, "Expected buddy root order is 0x%x, got 0x%x", 28, buddy_root_order);

    area = (uintptr_t)area << 1;
    alloc_buddy_append((uintptr_t)area, (uintptr_t)area + malloc_size);
    TEST_CHECK_(BUDDY_PTR_ORDER(buddy_root) == 27, "Expected buddy free root order is 0x%x, got 0x%x", 27, BUDDY_PTR_ORDER(buddy_root));
    TEST_CHECK_(buddy_root_order == 29, "Expected buddy root order is 0x%x, got 0x%x", 29, buddy_root_order);
}

// Slab allocator internal structures
struct bucket {
    struct slab_head *slab_head;
    size_t total_capacity; // total number of elements that fit all the slabs
    size_t used;           // number of elements used in this bucket
    size_t foreign_num;
};

struct slab_head {
    void *slab;            // area for objects
    uint32_t slab_order;   // page order of the slab area
    uint32_t freeobj_size; // number of elements in freeobj
    struct slab_head *next;
    uint64_t freeobj[]; // bit field, bit per each object
};

#define BUCKETS_NUM (32 * 1024 / 1024 + 116)
extern __thread struct bucket buckets[BUCKETS_NUM];

void test_slab(void) {
    const size_t malloc_size = 0x10000000; // 10 MiB
    void *area = aligned_alloc(malloc_size, malloc_size);
    TEST_CHECK(area != NULL);
    alloc_buddy_append((uintptr_t)area, (uintptr_t)area + malloc_size);

    TEST_CHECK(buckets[1].used == 0);
    const size_t obj_size = 12;  // 12-byte object
    const size_t obj_bucket = 1; // object size 12 belongs to bucket with index 1
    void *ptr = alloc_slab_allocate(obj_size);
    TEST_CHECK(ptr != NULL);
    TEST_CHECK(area <= ptr && ptr < area + malloc_size);

    TEST_CHECK(buckets[obj_bucket].used == 1);
    alloc_slab_free(ptr, obj_size);
    // Freeing the object should bring used count back to 0
    TEST_CHECK(buckets[obj_bucket].used == 0);

    free(area);
}

TEST_LIST = {{"buddy allocator", test_buddy},
             {"buddy allocator expands root order", test_buddy_expanding_root_order},
             {"slab allocator", test_slab},
             {NULL, NULL}};
