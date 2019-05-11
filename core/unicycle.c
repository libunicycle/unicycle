// SPDX-License-Identifier: MIT

#include "unicycle.h"
#include "compiler.h"
#include "cpu.h"
#include "event.h"
#include "shout.h"

#include "stdio.h"
#include <stdbool.h>
#include <stdint.h>

#if defined(CONFIG_DEBUG) && defined(CONFIG_SMP)

#define PERCPU_MARKER 0xbeef5520

PERCPU uint32_t percpu_marker = PERCPU_MARKER;

// Setting up per-CPU data area is a bit tricky. Let's check that it works correctly.
// Make sure that .tdata value is exactly as expected.
static void check_percpu_data_location(void) {
    PANIC_IF(percpu_marker != PERCPU_MARKER, "Invalid .tdata value. Check that percpu area is initialized correctly.");
}
#else
static void check_percpu_data_location(void) {}
#endif

NORETURN void unicycle_loop(void) {
    check_percpu_data_location();

    bool wait_for_irq = true; // wait for interruption if there are no deferred events to process
    while (true) {
        struct event *irq = event_peek(wait_for_irq);
        if (irq) {
            irq->handler(irq->data);
        }

        if (deferredevent_count() != 0) {
            struct event e = deferredevent_peek();
            e.handler(e.data);
            wait_for_irq = (deferredevent_count() == 0);
        } else {
            wait_for_irq = true;
        }
    };
}
