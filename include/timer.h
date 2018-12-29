// SPDX-License-Identifier: MIT

#pragma once

#include "compiler.h"
#include "tree.h"
#include <stdbool.h>
#include <stdint.h>

void timer_system_init(void);

// An architecture might have multiple timers with different characteristics (first of all time granularity)
// Following type is timer-specific, its granularity depends on the timer used by the system
typedef uint64_t time_t;
struct timer;

// TODO: or maybe use more generic event_handler_t?
typedef void (*timer_callback)(void *context);

struct timer *timer_add(time_t alarm_time, timer_callback callback, void *context);
void timer_change(struct timer *timer, time_t alarm_time);
void timer_delete(struct timer *timer);

time_t time_now(void);
time_t time_ns_from_now(uint64_t ns);
time_t time_us_from_now(uint64_t us);
time_t time_ms_from_now(uint64_t ms);
time_t time_sec_from_now(uint64_t sec);
time_t time_min_from_now(uint64_t min);
time_t time_hours_from_now(uint64_t hours);
time_t time_days_from_now(uint64_t days);

void sleep_us(uint64_t value);
void sleep_ns(uint64_t value);

// return true if timeout, false otherwise
bool wait_for_clear(__mmio const uint32_t *reg, uint32_t mask, time_t timeout);
// return true if timeout, false otherwise
bool wait_for_set(__mmio const uint32_t *reg, uint32_t mask, time_t timeout);
