// SPDX-License-Identifier: MIT

#pragma once

#include "event.h"

// Architecture specific API for timer implementation

void arch_timer_init(event_handler_t irq_handler);
void arch_timer_set_alarm(uint64_t time);
void arch_timer_disable(void);