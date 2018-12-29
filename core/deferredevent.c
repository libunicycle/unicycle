// SPDX-License-Identifier: MIT

#include "compiler.h"
#include "event.h"
#include "shout.h"
#include <stdint.h>

#define BUFFER_SIZE 1024 // must be power of 2

PERCPU struct {
    uint16_t event_idx; // next event to process
    uint16_t avail_idx; // space to add next event
    struct event ring[BUFFER_SIZE];
} buffer;

uint16_t deferredevent_count(void) {
    uint16_t num = buffer.avail_idx - buffer.event_idx;
    return num % BUFFER_SIZE; // handle situation when avail_idx overflowed to 0
}

struct event deferredevent_peek(void) {
    PANIC_IF(buffer.avail_idx == buffer.event_idx, "Work buffer is empty");
    return buffer.ring[buffer.event_idx++ % BUFFER_SIZE];
}

void deferredevent_queue(struct event e) {
    IFD SHOUT_IF(deferredevent_count() == BUFFER_SIZE - 1, "Work buffer overflow");
    buffer.ring[buffer.avail_idx++ % BUFFER_SIZE] = e;
}