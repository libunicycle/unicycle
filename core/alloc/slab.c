// SPDX-License-Identifier: MIT

#include "slab.h"
#include "buddy.h"
#include "compiler.h"
#include "config.h"
#include "lock.h"
#include "mem.h"
#include "shout.h"
#include "stdio.h"
#include <stdbool.h>

// Fast scalable slab allocator for physical memory

// it corresponds to index in the last if() condition at bucket_idx()
#define BUCKETS_NUM (32 * 1024 / 1024 + 116)
#define INVALID_BUCKETS_NUM (BUCKETS_NUM + 1)

#define BUCKET_SIZE_KNEE1 512
#define BUCKET_SIZE_STEP1 8
#define BUCKET_SIZE_NUM1 (BUCKET_SIZE_KNEE1 / BUCKET_SIZE_STEP1)

#define BUCKET_SIZE_KNEE2 4096
#define BUCKET_SIZE_STEP2 64
#define BUCKET_SIZE_NUM2 ((BUCKET_SIZE_KNEE2 - BUCKET_SIZE_KNEE1) / BUCKET_SIZE_STEP1 + BUCKET_SIZE_NUM1)

#define BUCKET_SIZE_KNEE3 32768
#define BUCKET_SIZE_STEP3 1024
#define BUCKET_SIZE_NUM3 ((BUCKET_SIZE_KNEE3 - BUCKET_SIZE_KNEE2) / BUCKET_SIZE_STEP2 + BUCKET_SIZE_NUM2)

// size - size of the object, can't be zero
// XXX: ideally if bucket_idx/bucket_obj_size functions get inlined
// Most allocation sizes are statically known so we want to tell compiler to inline these functions
// for better optimization
static inline size_t bucket_idx(size_t size) {
    if (size <= BUCKET_SIZE_KNEE1) {
        // in (0..512] range we have buckets with step 8B
        return (size - 1) / BUCKET_SIZE_STEP1;
    } else if (size <= BUCKET_SIZE_KNEE2) {
        // in (512..4KiB] range we have buckets with step 64B
        return (size - 1) / BUCKET_SIZE_STEP2 + 56;
    } else if (size <= BUCKET_SIZE_KNEE3) {
        // in (4KiB..32KiB] range we have buckets with step 1KiB
        return (size - 1) / BUCKET_SIZE_STEP3 + 116;
    } else {
        // allocations more than 32K are not handled by the slab allocator
        PANIC("Big objects (%ld bytes) are not served by the slab allocator", size);
    }
}

static inline size_t bucket_obj_size(size_t size) {
    if (size <= BUCKET_SIZE_KNEE1) {
        // in (0..512] range we have buckets with step 8B
        return ROUND_UP(size, BUCKET_SIZE_STEP1);
    } else if (size <= BUCKET_SIZE_KNEE2) {
        // in (512..4KiB] range we have buckets with step 64B
        return ROUND_UP(size, BUCKET_SIZE_STEP2);
    } else if (size <= BUCKET_SIZE_KNEE3) {
        // in (4KiB..32KiB] range we have buckets with step 1KiB
        return ROUND_UP(size, BUCKET_SIZE_STEP3);
    } else {
        // allocations more than 32K are not handled by the slab allocator
        PANIC("Such big objects are not served by the slab allocator");
    }
}

static inline size_t bucket_obj_size_by_idx(size_t idx) {
    if (idx < BUCKET_SIZE_NUM1)
        return (idx + 1) * BUCKET_SIZE_STEP1;
    else if (idx < BUCKET_SIZE_NUM2)
        return (idx + 1 - 56) * BUCKET_SIZE_STEP2;
    else
        return (idx + 1 - 116) * BUCKET_SIZE_STEP3;
}

struct slab_head {
    void *slab;            // area for objects
    uint32_t slab_order;   // page order of the slab area
    uint32_t freeobj_size; // number of elements in freeobj
    struct slab_head *next;
    uint64_t freeobj[]; // bit field, bit per each object
};
// Number of bits (and tracked objects) per freeobj array elements
#define FREEOBJ_GRANULARITY (8 * SIZEOF_FIELD(struct slab_head, freeobj[0]))

#define LOCAL_FOREIGN_NUM 16
struct bucket {
    struct slab_head *slab_head;
    size_t total_capacity; // total number of elements that fit all the slabs
    size_t used;           // number of elements used in this bucket

#ifdef CONFIG_SMP
    // foreign_num is going to be hot data (we check it at every allocation)
    // keep it together with other hot data
    size_t foreign_num;
#endif
};

PERCPU struct bucket buckets[BUCKETS_NUM];

#ifdef CONFIG_SMP

#define GLOBAL_FOREIGN_NUM 1024

PERCPU void *foreign[BUCKETS_NUM][LOCAL_FOREIGN_NUM];
void *global_foreign[GLOBAL_FOREIGN_NUM];
size_t global_foreign_num = 0; // number of elements in the global foreign array
// lock that protects access to global structure
lock_t global_foreign_lock = lock_init();

#endif

#define FLAG_ALLOCATE_NO_FOREIGN BIT(0)

// freeobj_size - number of elements in freeobj array
static size_t slab_head_size(size_t freeobj_size) { return sizeof(struct slab_head) + freeobj_size * FREEOBJ_GRANULARITY / 8; }

static void *allocate_from_bucket(size_t idx, uint64_t flags) {
    struct bucket *bucket = &buckets[idx];

#ifdef CONFIG_SMP
    if (bucket->foreign_num && !(flags & FLAG_ALLOCATE_NO_FOREIGN)) {
        // we have foreign objects available, allocate one of them
        return foreign[idx][bucket->foreign_num--];
    }
#else
    (void)flags; // silence 'unused variable' warning
#endif

    size_t obj_size = bucket_obj_size_by_idx(idx);

    if (!bucket->slab_head) {
        PANIC_IF(bucket->total_capacity, "Bucket has no slabs but total_capacity is not 0");
    }
    PANIC_IF(bucket->total_capacity < bucket->used, "Bucket %lu: number of used elements %lu larger than bucket capacity %lu", idx,
             bucket->used, bucket->total_capacity);
    if (bucket->total_capacity <= bucket->used) {
        size_t new_slab_order;
        // No more free objects, allocate a new slab that twice bigger than current capacity
        if (bucket->total_capacity) {
            new_slab_order = ILOG2_UP(bucket->total_capacity * obj_size) + 1;
        } else {
            // first slab is 32KiB for smaller objects and 64KiB for larger objects
            if (idx == 87) {
                // special case 2048 bytes - receive network buffer.
                new_slab_order = 19;
            } else if (idx < 64) {
                new_slab_order = 15;
            } else {
                new_slab_order = 16;
            }
        }

        void *slab = alloc_buddy_allocate(new_slab_order);
        if (!slab) {
            // memory pressure
            SHOUT("Memory pressure, cannot allocate a new slab");
            return NULL;
        }

        size_t objs_num = PAGE_ORDER(new_slab_order) / obj_size;
        size_t freeobj_size = DIV_ROUND_UP(objs_num, FREEOBJ_GRANULARITY);

        // slab_head has a variale length, we need to calculate the scturct size and then allocate the object.
        size_t head_struct_size = slab_head_size(freeobj_size);
        size_t head_bucket_idx = bucket_idx(head_struct_size);

        // For head struct we need to allocate memory dynamically. So we have a recursive dependency here.
        // We are going to break this dependency in following way:
        //   - check if new bucket has free object for 'head'
        //   - if yes: allocate it and we are done
        //   - if no then it will create another head struct maybe from our current bucket that does not have objects yet
        //     to avoid it we allocate a temporary head struct from buddy allocator and initialize head with it
        //     then allocate *one more* head from slab allocator, copy temporary head into the new one and free temporary
        //     buddy.
        struct bucket *new_bucket = &buckets[head_bucket_idx];
        struct slab_head *head;
        size_t temp_head_order = 0;
        if (new_bucket->total_capacity > new_bucket->used) {
            // we have space in the new slab, allocate it
            // we want to keep local slab_head in CPU-local cache, hence FLAG_ALLOCATE_NO_FOREIGN
            head = allocate_from_bucket(head_bucket_idx, FLAG_ALLOCATE_NO_FOREIGN);
        } else {
            // allocate a temporary slab_head from buddy
            temp_head_order = ILOG2_UP(MAX(BUDDY_SIZE_GRANULARITY, head_struct_size));
            head = alloc_buddy_allocate(temp_head_order);
            if (!head)
                PANIC("Cannot allocate buddy area for temporary slab");
        }

        head->slab = slab;
        head->slab_order = new_slab_order;
        head->freeobj_size = freeobj_size;
        head->next = bucket->slab_head;
        IFVV printf("Initialized slab head %p with slab %p and slab_order %ld\n", head, slab, new_slab_order);

        // init freeobj[] with '1' bits to mark all objects in the slab are free
        for (size_t i = 0; i < objs_num / FREEOBJ_GRANULARITY; i++)
            head->freeobj[i] = ~(uint64_t)0;

        // because of rounding, number of bits in freeobj array is bigger than actual number of objects.
        // we mark out-of-range bits with '0' to avoid accidental allocation
        size_t leftover_bits = objs_num % FREEOBJ_GRANULARITY;
        if (leftover_bits)
            head->freeobj[objs_num / FREEOBJ_GRANULARITY] = PAGE_ORDER(leftover_bits) - 1;

        // insert the slab_head into the bucket
        bucket->slab_head = head;
        IFVV printf("slab: expanding bucket[%lu] %lu->%lu\n", idx, bucket->total_capacity, bucket->total_capacity + objs_num);
        bucket->total_capacity += objs_num;

        if (temp_head_order) {
            struct slab_head *real_head = allocate_from_bucket(head_bucket_idx, FLAG_ALLOCATE_NO_FOREIGN);
            memcpy(real_head, head, head_struct_size);
            bucket->slab_head = real_head;
            // printf("Copy temp head from %p to %p\n", head, real_head);

            alloc_buddy_free(head, temp_head_order);
        }
    }

    struct slab_head *slab_head = bucket->slab_head;
    PANIC_IF(!slab_head, "No slab head exists in the bucked %ld", idx);

    do {
        // find a free object in the slab
        for (size_t i = 0; i < slab_head->freeobj_size; i++) {
            if (slab_head->freeobj[i]) {
                // it contains free objects, let's find its index
                int freeidx = FFS(slab_head->freeobj[i]) - 1;

                // mark this object as used by setting it to zero
                slab_head->freeobj[i] &= ~BIT(freeidx);

                bucket->used++;

                return slab_head->slab + (i * FREEOBJ_GRANULARITY + freeidx) * obj_size;
            }
        }
        slab_head = slab_head->next;
    } while (slab_head);

    SHOUT("Was not able to find a free object in bucket %ld (size=%ld). total_count=%ld used=%ld freeobj_size=%d", idx,
          bucket_obj_size_by_idx(idx), bucket->total_capacity, bucket->used, bucket->slab_head->freeobj_size);
    return NULL;
}

void *alloc_slab_allocate(size_t size) {
    if (size == 0) {
        SHOUT("Allocating 0 bytes?");
        return NULL;
    }

    if (size > ALLOC_SLAB_MAX_SIZE) {
        SHOUT("Requested size is too large %ld", size);
        return NULL;
    }

    size_t idx = bucket_idx(size);
    return allocate_from_bucket(idx, 0);
}

void alloc_slab_free(void *obj, size_t size) {
    size_t idx = bucket_idx(size);
    size = bucket_obj_size(size);

    struct bucket *bucket = &buckets[idx];

    struct slab_head *head = bucket->slab_head;
    while (head) {
        // printf("head=%p slab=%p slab_order=%d freeobj_size=%d\n", head, head->slab, head->slab_order, head->freeobj_size);
        uintptr_t addrmask = PAGE_ORDER(head->slab_order) - 1;
        if (((uintptr_t)obj & ~addrmask) == (uintptr_t)head->slab) {
            // we've found the owner slab
            uintptr_t offset = (uintptr_t)obj & addrmask;
            PANIC_IF(offset % size, "Freeing object is not properly aligned. Addr=%p slab=%p bucket_size=%ld", obj, head->slab, size);
            size_t obj_idx = offset / size;

            size_t freeobj_idx = obj_idx / FREEOBJ_GRANULARITY;
            size_t freeobj_bit = obj_idx % FREEOBJ_GRANULARITY;

            PANIC_IF(freeobj_idx >= head->freeobj_size, "Freeing index %ld is too big, slab freeobj_size=%d", freeobj_idx,
                     head->freeobj_size);
            if (head->freeobj[freeobj_idx] & BIT(freeobj_bit)) {
                // TODO fix it, looks like it a bug in slab or double-free?
                SHOUT("Freeing object %p in bucket %lu, but the object is marked as free", obj, idx);
            } else {
                head->freeobj[freeobj_idx] |= BIT(freeobj_bit); // Mark the object as free
                bucket->used--;
            }

            return;
        }

        head = head->next;
    }

#ifdef CONFIG_SMP
    // Current bucket does not have slabs that contain given object
    // It probably belongs to other CPU. Add the object to foreign array
    if (bucket->foreign_num < LOCAL_FOREIGN_NUM) {
        foreign[idx][bucket->foreign_num++] = obj;
        return;
    } else {
        // else local foreign cache is full and we need to flash it to global foreign cache
        // XXX: implement it
        SHOUT("Trying to add object into local foreign cache, but it is full");

        // if global foreign is full as well - send interruption to all CPU's and ask them to clean the globalforeign
    }
#else
    SHOUT("Freeing object %p does not belong to bucket %ld", obj, idx);
#endif
}
