// SPDX-License-Identifier: MIT

#pragma once

#include <compiler.h>
#include <stddef.h>
#include <stdint.h>

struct apic_ioapic {
    uint8_t id;       // IO APIC id
    uint32_t pin_num; // number of pins
    uint32_t irq_base;
    __mmio void *addr;
};

struct apic_irq_override {
    uint8_t source; // Original IRQ
    uint32_t irq;
};

extern size_t apic_ioapic_num;
extern struct apic_ioapic *apic_ioapics;

extern size_t apic_irq_override_num;
extern struct apic_irq_override *apic_irq_overrides;

void apic_init(void);
uint32_t apic_cpu_id(void);
void apic_interrupt_ack(void);
void apic_ap_init(uint32_t apic_id);
void apic_ap_start(uint32_t apic_id, uint32_t address);
