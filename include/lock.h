// SPDX-License-Identifier: MIT

#pragma once

#include "compiler.h"
#include "config.h"
#include "shout.h"
#include <stdbool.h>

#if IS_ENABLED(CONFIG_SMP)

#include <stdatomic.h>

typedef atomic_bool lock_t;

#define lock_init() ATOMIC_VAR_INIT(false)

static inline void lock(lock_t *l) {
    bool expected = false;
    while (!atomic_compare_exchange_weak_explicit(l, &expected, true, memory_order_acquire, memory_order_relaxed)) {
        expected = false;
        if (CONFIG_ARCH_X86) {
            // x86 spin lock hint
            __asm__ volatile("pause");
        }
    };
}

static inline bool trylock(lock_t *l) {
    bool expected = false;
    return atomic_compare_exchange_strong_explicit(l, &expected, true, memory_order_acquire, memory_order_relaxed);
}

static inline void unlock(lock_t *l) {
    bool expected = true;
    bool was_locked = atomic_compare_exchange_strong_explicit(l, &expected, false, memory_order_release, memory_order_relaxed);
    PANIC_IF(!was_locked, "Trying to unlock non-locked object");
}

#else

typedef struct lock {
} lock_t;

#define lock_init() \
    {}

static inline void lock(UNUSED lock_t *l) {}
static inline bool trylock(UNUSED lock_t *l) { return true; }
static inline void unlock(UNUSED lock_t *l) {}

#endif
