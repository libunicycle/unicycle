// SPDX-License-Identifier: MIT

#include "timer.h"
#include "arch_timer.h"
#include "kalloc.h"
#include <stddef.h>

struct timer {
    time_t alarm_time;
    timer_callback callback;
    void *context;
    RB_ENTRY(timer) rbnode;
};
RB_HEAD(timer_list, timer) timers_head = RB_INITIALIZER(&timers_head);
time_t next_alarm_time = 0;

static int timer_compare(struct timer *a, struct timer *b) {
    // There can be multiple timers with the same alarm time
    // We should allow entries with the same key (alarm_time) thus never return
    // '0' from this function.
    return a->alarm_time < b->alarm_time ? -1 : 1;
}

RB_PROTOTYPE(timer_list, timer, rbnode, timer_compare);
RB_GENERATE(timer_list, timer, rbnode, timer_compare);

static void timer_next_alarm_update(void) {
    if (RB_EMPTY(&timers_head)) {
        arch_timer_disable();
        return;
    }

    struct timer *next_timer = RB_MIN(timer_list, &timers_head);
    if (next_timer->alarm_time != next_alarm_time) {
        arch_timer_set_alarm(next_timer->alarm_time);
        next_alarm_time = next_timer->alarm_time;

        // TODO: we should check that the time we set is in the future
        // Some timers (like HPET) do not work if the time is in the past
    }
}

struct timer *timer_add(time_t alarm_time, timer_callback callback, void *context) {
    struct timer *timer = kalloc(struct timer);
    timer->alarm_time = alarm_time;
    timer->callback = callback;
    timer->context = context;

    struct timer *existing = RB_INSERT(timer_list, &timers_head, timer);
    IFD SHOUT_IF(existing, "Found existing timer");

    timer_next_alarm_update();

    return timer;
}

void timer_change(struct timer *timer, time_t alarm_time) {
    if (timer->alarm_time == alarm_time)
        return;

    RB_REMOVE(timer_list, &timers_head, timer);
    timer->alarm_time = alarm_time;
    RB_INSERT(timer_list, &timers_head, timer);

    timer_next_alarm_update();
}

void timer_delete(struct timer *timer) {
    RB_REMOVE(timer_list, &timers_head, timer);
    kfree(timer);

    timer_next_alarm_update();
}

static void timer_irq_handler(UNUSED void *context) {
    while (true) {
        struct timer *timer = RB_MIN(timer_list, &timers_head);
        if (!timer)
            return;

        if (timer->alarm_time > time_now())
            break;

        timer->callback(timer->context);
        RB_REMOVE(timer_list, &timers_head, timer);
        kfree(timer);
    }

    timer_next_alarm_update();
}

void timer_system_init(void) { arch_timer_init(timer_irq_handler); }

void sleep_us(uint64_t value) {
    time_t end = time_us_from_now(value);

    // TODO: check for overflow here and everywhere else where we compare with time_now()
    while (time_now() < end)
        ;
}

void sleep_ns(uint64_t value) {
    time_t end = time_ns_from_now(value);

    // TODO: check for overflow here and everywhere else where we compare with time_now()
    while (time_now() < end)
        ;
}

bool wait_for_clear(__mmio const uint32_t *reg, uint32_t mask, time_t timeout) {
    do {
        if (!(*reg & mask))
            return false;
        sleep_us(10);
    } while (time_now() < timeout);
    return true;
}

bool wait_for_set(__mmio const uint32_t *reg, uint32_t mask, time_t timeout) {
    do {
        if (*reg & mask)
            return false;
        sleep_us(10);
    } while (time_now() < timeout);
    return true;
}
