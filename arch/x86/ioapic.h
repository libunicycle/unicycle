// SPDX-License-Identifier: MIT

#include <stdint.h>

void ioapic_init(void);
void ioapic_route_irq(uint8_t irq, uint8_t vector);