// SPDX-License-Identifier: MIT

#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef void (*event_handler_t)(void *data);

struct event {
    event_handler_t handler;
    void *data;
};

struct event *event_peek(bool wait);

// Number of events available in the buffer
uint16_t deferredevent_count(void);

// it will halt CPU if no events available
struct event deferredevent_peek(void);

// Puts a new event to buffer. Safe to call from interrupt context.
void deferredevent_queue(struct event);