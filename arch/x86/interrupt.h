// SPDX-License-Identifier: MIT

#pragma once

#define INTERRUPT_DIVIDE 0x0
#define INTERRUPT_DEBUG 0x1
#define INTERRUPT_NON_MASKABLE 0x2
#define INTERRUPT_BREAKPOINT 0x3
#define INTERRUPT_OVERFLOW 0x4
#define INTERRUPT_BOUND_RANGE 0x5
#define INTERRUPT_INVALID_OPCODE 0x6
#define INTERRUPT_DEVICE_NOT_AVAILABLE 0x7
#define INTERRUPT_DOUBLE_FAULT 0x8 // with errorcode (always zero)
#define INTERRUPT_COPROCESSOR_SEGMENT_OVERRUN 0x9
#define INTERRUPT_INVALID_TSS 0xa              // with errorcode (selector index)
#define INTERRUPT_SEGMENT_NOT_PRESENT 0xb      // with errorcode (selector index)
#define INTERRUPT_STACK_SEGMENT_FAULT 0xc      // with errorcode (selector index)
#define INTERRUPT_GENERAL_PROTECTION_FAULT 0xd // with errorcode (segment selector index or zero)
#define INTERRUPT_PAGE_FAULT 0xe               // with errorcode (see http://wiki.osdev.org/Exceptions for description)
#define INTERRUPT_FPU_EXCEPTION 0x10
#define INTERRUPT_ALIGNMENT_CHECK 0x11 // with errorcode
#define INTERRUPT_MACHINE_CHECK 0x12
#define INTERRUPT_SIMD_FPU_EXCEPTION 0x13
#define INTERRUPT_VRTUALIZATION_EXCEPTION 0x14
#define INTERRUPT_SECURITY_EXCEPTION 0x1e // with errorcode

// Range IRQ_BASE..INTERRUPT_LOCAL_APIC_BASE is allocated for dynamically registered interrupts
#define IRQ_BASE 0x20

#define IRQ_TIMER 0x0
#define IRQ_KEYBOARD 0x1
#define IRQ_SERIAL 0x4
#define IRQ_RTC 0x8
#define IRQ_ATA1 0xe
#define IRQ_ATA2 0xf

// Range INTERRUPT_LOCAL_APIC_BASE..INTERRUPTS_NUM is for predefined APIC interrupts
#define INTERRUPT_LOCAL_APIC_BASE 0xf0
#define INTERRUPT_APIC_SPURIOUS 0xf0
#define INTERRUPT_APIC_TIMER 0xf1

#define INTERRUPTS_NUM 256

#ifndef __ASSEMBLER__

#include "event.h"
#include <stdint.h>

int interrupt_reserve(uint8_t size);
// Returns number of registered interrupt.
// Negative number means no handler registered.
int interrupt_register(event_handler_t handler, void *data);
void interrupt_register_with_vector(uint16_t vector, event_handler_t handler, void *data);
void interrupt_unregister(uint8_t num);

// Registers handler for an IRQ line
int irq_register(uint8_t irq_line, event_handler_t handler, void *data);

void idt_struct_setup(void);
void idt_load(void);

#endif /* ! __ASSEMBLER__ */