// SPDX-License-Identifier: MIT

#include "ioapic.h"
#include "apic.h"
#include "compiler.h"
#include "mmio.h"
#include "mmu.h"
#include "shout.h"
#include "stdio.h"
#include <stddef.h>

#define IOAPIC_REGSEL 0x0
#define IOAPIC_WIN 0x10

#define IOAPIC_ID 0
#define IOAPIC_VER 1

#define IOAPIC_REDTLB 0x10
#define IOAPIC_IRQ_MASK BIT(16)

size_t apic_ioapic_num = 0;
struct apic_ioapic *apic_ioapics = NULL;

size_t apic_irq_override_num;
struct apic_irq_override *apic_irq_overrides;

// IO APIC documentation can be found at https://pdos.csail.mit.edu/6.828/2016/readings/ia32/ioapic.pdf
static inline uint32_t ioapic_read(__mmio void *addr, uint32_t reg) {
    MMIO32(addr + IOAPIC_REGSEL) = reg & 0xff;
    return MMIO32(addr + IOAPIC_WIN);
}

static inline void ioapic_write(__mmio void *addr, uint32_t reg, uint32_t data) {
    MMIO32(addr + IOAPIC_REGSEL) = reg & 0xff;
    MMIO32(addr + IOAPIC_WIN) = data;
}

void ioapic_init(void) {
    for (size_t i = 0; i < apic_ioapic_num; i++) {
        struct apic_ioapic *ioapic = &apic_ioapics[i];

        page_table_set_bit((uintptr_t)ioapic->addr, PAGE_SIZE, PAGE_PRESENT | PAGE_WRITABLE | PAGE_CACHE_DISABLE,
                           PAGE_PRESENT | PAGE_WRITABLE | PAGE_CACHE_DISABLE);

        uint32_t data = ioapic_read(ioapic->addr, IOAPIC_VER);
        uint8_t version = data & 0xff;
        uint8_t pin_num = ((data >> 16) & 0xff) + 1;

        ioapic->pin_num = pin_num;

        printf("IOAPIC id=%d addr=%p version=%d irq_base=%d pin_num=%d\n", ioapic->id, ioapic->addr, ioapic->irq_base, version, pin_num);

        for (size_t i = 0; i < pin_num; i++) {
            uint32_t reg = IOAPIC_REDTLB + i * 2;
            // mask all irq
            ioapic_write(ioapic->addr, reg, IOAPIC_IRQ_MASK);
        }
    }
}

static uint8_t remap_irq(uint8_t irq) {
    for (size_t i = 0; i < apic_irq_override_num; i++) {
        struct apic_irq_override *remap = &apic_irq_overrides[i];

        if (remap->source == irq)
            return remap->irq;
    }

    return irq;
}

void ioapic_route_irq(uint8_t original_irq, uint8_t vector) {
    uint8_t irq = remap_irq(original_irq);

    for (size_t i = 0; i < apic_ioapic_num; i++) {
        struct apic_ioapic *ioapic = &apic_ioapics[i];
        uint8_t irq_begin = ioapic->irq_base;
        uint8_t irq_end = ioapic->irq_base + ioapic->pin_num;
        if (irq < irq_begin || irq >= irq_end)
            continue;

        uint32_t reg = IOAPIC_REDTLB + irq * 2;

        ioapic_write(ioapic->addr, reg, vector);
        ioapic_write(ioapic->addr, reg + 1, 0); // apic # 0

        return;
    }
    SHOUT("Cannot find IO APIC for irq %d\n", irq);
}
