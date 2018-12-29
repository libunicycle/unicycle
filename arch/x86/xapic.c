// SPDX-License-Identifier: MIT

#include "acpi.h"
#include "apic.h"
#include "compiler.h"
#include "interrupt.h"
#include "mmio.h"
#include "mmu.h"
#include "stdio.h"
#include "x86.h"
#include <stdint.h>

#define REG_ID 0x20      // Local APIC ID
#define REG_VERSION 0x30 // Local APIC Version
#define REG_TPR 0x80     // Task Priority
#define REG_EOI 0xb0
#define REG_LOGIC_DEST 0xd0  // Loginc Destination
#define REG_DEST_FORMAT 0xe0 // Destination Format
#define REG_SPURIOUS_INT_VECTOR 0xf0
#define REG_ICR_LOW 0x300
#define REG_ICR_HIGH 0x310
#define REG_LVT_TIMER 0x320
#define REG_TIMER_INIT_COUNT 0x380
#define REG_TIMER_CURRENT_COUNT 0x390
#define REG_TIMER_DIVIDER 0x3e0

#define APIC_ENABLE BIT(8) // set in REG_SPURIOUS_INT_VECTOR register

#define TIMER_ONE_SHOT (0 << 17)
#define TIMER_PERIODIC (1 << 17)
#define TIMER_TSC_DEADLINE (2 << 17)

#define ICR_DEST_NOSHORTHAND (0 << 18)
#define ICR_DEST_SELF (1 << 18)
#define ICR_DEST_ALLINCLUDINGSELF (2 << 18)
#define ICR_DEST_ALLEXCLUDINGSELF (3 << 18)

#define ICR_TRIGGER_LEVEL BIT(15)
#define ICR_ASSERT BIT(14)
#define ICR_DESTMODEL_LOGICAL BIT(11)

#define ICR_MODE_FIXED (0b000 << 8)
#define ICR_MODE_LOWESTPRIO (0b001 << 8)
#define ICR_MODE_SMI (0b010 << 8)
#define ICR_MODE_NMI (0b100 << 8)
#define ICR_MODE_INIT (0b101 << 8)
#define ICR_MODE_STARTUP (0b110 << 8)

#define APIC_REG(reg) MMIO32(g_apic_addr + reg)

UNUSED static void apic_timer_setup(void) {
    uint32_t eax, unused;
    x86_cpuid(CPUID_THERMAL_N_POWER, &eax, &unused, &unused, &unused);
    if (!(eax & BIT(2))) {
        printf("The device does not support constant frequency APIC timer");
        return;
    }

    uint32_t tsc_denominator, tsc_numerator, crystal_freq;
    x86_cpuid(CPUID_TSC_FREQ, &tsc_denominator, &tsc_numerator, &crystal_freq, &unused);
    // printf("Crystal freq %ld HZ, tsc freq %ld HZ\n", crystal_freq, crystal_freq * tsc_numerator / tsc_denominator);

    APIC_REG(REG_TIMER_DIVIDER) = 0xa;         // divider is 128
    APIC_REG(REG_TIMER_INIT_COUNT) = 30000000; // ~5 seconds delay on my 4GHz computer
    mb();
    uint8_t INTERRUPT_TIMER = 100; // XXX: instead of hardcoding this number we need to use one from interrupt_register()
    APIC_REG(REG_LVT_TIMER) = INTERRUPT_TIMER | TIMER_PERIODIC;
}

void apic_init(void) {
    // according to x2apic spec section 2.3.2 MMIO address space size is 0xc00
    page_table_set_bit(g_apic_addr, 0x1000, PAGE_PRESENT | PAGE_WRITABLE, PAGE_PRESENT | PAGE_WRITABLE);

    uint64_t msr = x86_rdmsr(MSR_APIC_BASE);
    msr |= MSR_APIC_ENABLE;
    x86_wrmsr(MSR_APIC_BASE, msr);

    // Specify spurious intr vector and enable APIC
    APIC_REG(REG_SPURIOUS_INT_VECTOR) = INTERRUPT_APIC_SPURIOUS | APIC_ENABLE;

    // XXX: do we need followinig init code?
    // APIC_REG(REG_DEST_FORMAT) = 0xffffffff; // Flat mode
    // APIC_REG(REG_LOGIC_DEST) = 0x01000000;  // All cpus use logical id 1
    // APIC_REG(REG_TPR) &= ~0xff;
    // enable APIC
    // APIC_REG(REG_SPURIOUS_INT_VECTOR) |= APIC_ENABLE;

    // apic_timer_setup();
}

uint32_t apic_cpu_id(void) { return APIC_REG(REG_ID) >> 24; }

void apic_interrupt_ack(void) { APIC_REG(REG_EOI) = 1; }

void apic_ap_init(uint32_t apic_id) {
    PANIC_IF(apic_id >= 256, "xapic id must be 8 bits");
    // First we write to high word
    APIC_REG(REG_ICR_HIGH) = (apic_id << 24);
    // writing to low word causes the IPI
    APIC_REG(REG_ICR_LOW) = ICR_ASSERT | ICR_MODE_INIT;
};

void apic_ap_start(uint32_t apic_id, uint32_t address) {
    PANIC_IF(apic_id >= 256, "xapic id must be 8 bits");

    uint8_t vector = address >> PAGE_SIZE_SFT;
    APIC_REG(REG_ICR_HIGH) = (apic_id << 24);
    APIC_REG(REG_ICR_LOW) = ICR_ASSERT | ICR_MODE_STARTUP | vector;
}
