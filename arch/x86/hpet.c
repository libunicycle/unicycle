// SPDX-License-Identifier: MIT

#include "acpi.h"
#include "arch_timer.h"
#include "asan.h"
#include "compiler.h"
#include "cpu.h"
#include "interrupt.h"
#include "mmio.h"
#include "mmu.h"
#include "pci.h"
#include "stdio.h"
#include "timer.h"
#include <stdint.h>

// HPET spec https://www.intel.com/content/dam/www/public/us/en/documents/technical-specifications/software-developers-hpet-spec-1-0a.pdf

// HPET registers
#define REG_ID 0x0
#define REG_CONFIG 0x10
#define REG_INTR_STATUS 0x20
#define REG_COUNTER_VALUE 0xf0

// Timer-specific registers at base address == g_hpet_addr + 0x100 + 0x20 * N
#define REG_TIMER_CONFIG 0x0
#define REG_TIMER_COMPARATOR_VALUE 0x8
#define REG_TIMER_FSB_IRQ_ROUTE 0x10

// Bitfields for HPET_REG(REG_CONFIG)
#define HPET_COUNTER_ENABLE BIT(0)
#define HPET_LEGACY_REPLACEMENT BIT(1)

// Bitfields for HPET_TIMER_REG(XXX, REG_TIMER_CONFIG)
#define HPET_TIMER_INTR_EN BIT(2)
#define HPET_TIMER_ROUTE_SFT 9
#define HPET_TIMER_ROUTE (0 << HPET_TIMER_ROUTE_SFT)
#define HPET_TIMER_FSB_EN BIT(14) // Send interrupt messages over FSB (it is MSI essentially)
#define HPET_TIMER_FSB_SUPPORTED BIT(15)

#define HPET_REG(reg) MMIO64(g_hpet_addr + reg)
#define HPET_TIMER_REG(n, reg) MMIO64(g_hpet_addr + 0x100 + 0x20 * n + reg)

#define HPET_TICK_SCALE 1000000000000000 // HPET reports tick period in femto-seconds
uint32_t hpet_tick_per_ms;

static uint64_t hpet_ticks(uint64_t msec) { return hpet_tick_per_ms * msec; }

time_t time_now(void) { return HPET_REG(REG_COUNTER_VALUE); }
time_t time_ns_from_now(uint64_t ns) { return time_now() + hpet_ticks(ns) / 1000000; }
time_t time_us_from_now(uint64_t us) { return time_now() + hpet_ticks(us) / 1000; }
time_t time_ms_from_now(uint64_t ms) { return time_now() + hpet_ticks(ms); }
time_t time_sec_from_now(uint64_t sec) { return time_now() + hpet_ticks(1000 * sec); }
time_t time_min_from_now(uint64_t min) { return time_now() + hpet_ticks(60 * 1000 * min); }
time_t time_hours_from_now(uint64_t hours) { return time_now() + hpet_ticks(3600 * 1000 * hours); }
time_t time_days_from_now(uint64_t days) { return time_now() + hpet_ticks(24 * 3600 * 1000 * days); }

void arch_timer_init(event_handler_t irq_handler) {
    PANIC_IF(!g_hpet_addr, "HPET address is not initialized");

    page_table_set_bit(g_hpet_addr, PAGE_SIZE, PAGE_PRESENT | PAGE_WRITABLE | PAGE_CACHE_DISABLE,
                       PAGE_PRESENT | PAGE_WRITABLE | PAGE_CACHE_DISABLE);
    asan_mark_memory_region(g_hpet_addr, PAGE_SIZE, ASAN_TAG_RW);

    uint64_t id = HPET_REG(REG_ID);
    uint64_t config = HPET_REG(REG_CONFIG);
    uint32_t hpet_clock_period = id >> 32;
    hpet_tick_per_ms = HPET_TICK_SCALE / hpet_clock_period / 1000;

    printf("HPET cap=0x%lx config=0x%lx ticks_per_ms=%d\n", id, config, hpet_tick_per_ms);

    uint64_t timercfg = HPET_TIMER_REG(0, REG_TIMER_CONFIG);
    if (timercfg & HPET_TIMER_FSB_SUPPORTED) {
        uint8_t vector = interrupt_register(irq_handler, NULL);

        uint32_t addr;
        uint16_t val;
        pci_msi_addr(vector, &addr, &val);
        HPET_TIMER_REG(0, REG_TIMER_FSB_IRQ_ROUTE) = ((uint64_t)addr << 32) | val;
        HPET_TIMER_REG(0, REG_TIMER_CONFIG) = timercfg | HPET_TIMER_FSB_EN;
    } else {
        // vmware does not support HPET FSB delivery method...
        HPET_REG(REG_CONFIG) |= HPET_LEGACY_REPLACEMENT;
        irq_register(IRQ_TIMER, irq_handler, NULL);
    }
    HPET_REG(REG_CONFIG) |= HPET_COUNTER_ENABLE;
}

// arch_timer_init need to be run first, otherwise result is undefined
void arch_timer_set_alarm(time_t time) {
    // enable timer at comparator 0
    HPET_TIMER_REG(0, REG_TIMER_COMPARATOR_VALUE) = time;
    HPET_TIMER_REG(0, REG_TIMER_CONFIG) |= HPET_TIMER_INTR_EN;
}

void arch_timer_disable(void) { HPET_TIMER_REG(0, REG_TIMER_CONFIG) &= ~HPET_TIMER_INTR_EN; }
