// SPDX-License-Identifier: MIT

#include "apic.h"
#include "compiler.h"
#include "config.h"
#include "cpu.h"
#include "interrupt.h"
#include "stdio.h"
#include "x86.h"

#define REG_ID 0x2      // Local APIC ID
#define REG_VERSION 0x3 // Local APIC Version
#define REG_TPR 0x8     // Task Priority
#define REG_EOI 0xb
#define REG_LOGIC_DEST 0xd  // Loginc Destination
#define REG_DEST_FORMAT 0xe // Destination Format
#define REG_SPURIOUS_INT_VECTOR 0xf
#define REG_ICR 0x30
#define REG_LVT_TIMER 0x32
#define REG_TIMER_INIT_COUNT 0x38
#define REG_TIMER_CURRENT_COUNT 0x39
#define REG_TIMER_DIVIDER 0x3e
#define REG_SELF_IPI 0x3f

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
#define ICR_MODE_SMI (0b010 << 8)
#define ICR_MODE_NMI (0b100 << 8)
#define ICR_MODE_INIT (0b101 << 8)
#define ICR_MODE_STARUP (0b110 << 8)

#define APIC_BASE_ADDR 0x800 // start of APIC MSR register space

#define APIC_READ(reg) x86_rdmsr(APIC_BASE_ADDR + reg)
#define APIC_WRITE(reg, val) x86_wrmsr(APIC_BASE_ADDR + reg, val)

static void apic_timer_handler(UNUSED void *data) {
    static uint32_t counter = 0;
    printf("Hello from APIC timer #%d, counter %d\n", current_cpu_id, counter++);
    apic_interrupt_ack();
}

static void apic_timer_setup(void) {
    uint32_t eax, unused;
    x86_cpuid(CPUID_THERMAL_N_POWER, &eax, &unused, &unused, &unused);
    if (!(eax & BIT(2))) {
        printf("The device does not support constant frequency APIC timer");
        return;
    }

    // register APIC timer
    interrupt_register_with_vector(INTERRUPT_APIC_TIMER, apic_timer_handler, NULL);

    APIC_WRITE(REG_TIMER_DIVIDER, 0xa); // divider is 128
    APIC_WRITE(REG_LVT_TIMER, INTERRUPT_APIC_TIMER | TIMER_PERIODIC);
    APIC_WRITE(REG_TIMER_INIT_COUNT, 10000000); // ~5 seconds delay on my 4GHz computer
}

void apic_init(void) {
    uint32_t ecx, unused;
    x86_cpuid(CPUID_FEATURES, &unused, &unused, &ecx, &unused);
    PANIC_IF(!(ecx & CPUID_ECX_X2APIC), "Hardware does not support x2APIC mode");

    uint64_t msr = x86_rdmsr(MSR_APIC_BASE);
    msr |= MSR_APIC_ENABLE;
    msr |= MSR_APIC_X2MODE;
    x86_wrmsr(MSR_APIC_BASE, msr);

    // Specify spurious intr vector and enable APIC
    APIC_WRITE(REG_SPURIOUS_INT_VECTOR, INTERRUPT_APIC_SPURIOUS | APIC_ENABLE);

    uint32_t data = APIC_READ(REG_VERSION);
    uint8_t version = data & 0xff;
    uint32_t max_lvt = (data >> 16) & 0xff;
    IFD printf("Local x2APIC: id=0x%lx ver=0x%x max_lvt=%d\n", APIC_READ(REG_ID), version, max_lvt);

    // apic_timer_setup();
}

uint32_t apic_cpu_id(void) { return APIC_READ(REG_ID); }

void apic_interrupt_ack(void) { APIC_WRITE(REG_EOI, 0); }

void apic_ap_init(uint32_t apic_id) {
    uint64_t dest = (uint64_t)apic_id << 32;
    APIC_WRITE(REG_ICR, dest | ICR_ASSERT | ICR_MODE_INIT);
}

void apic_ap_start(uint32_t apic_id, uint32_t address) {
    uint8_t vector = address >> PAGE_SIZE_SFT;
    uint64_t dest = (uint64_t)apic_id << 32;
    APIC_WRITE(REG_ICR, dest | ICR_ASSERT | ICR_MODE_STARUP | vector);
}
