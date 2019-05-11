// SPDX-License-Identifier: MIT

#include "interrupt.h"
#include "acpi.h"
#include "apic.h"
#include "compiler.h"
#include "event.h"
#include "ioapic.h"
#include "mmu.h"
#include "shout.h"
#include "stacktrace.h"
#include <stddef.h>
#include <stdint.h>

struct PACKED idt_entry {
    uint16_t handler_0_15;
    uint16_t gdt_selector;
    uint8_t ist; // Interrupt stack table
    uint8_t attributes;
    uint16_t handler_16_31;
    uint32_t handler_32_63;
    uint32_t _unused;
};
BUILD_PANIC_IF(sizeof(struct idt_entry) != 16);

// IDT is initialized at start time and never modified afterwards
const struct idt_entry idt[INTERRUPTS_NUM] ALIGNED(8);

const struct PACKED {
    uint16_t length;
    uint64_t base;
} idtr = {.length = sizeof(idt) - 1, .base = (uint64_t)idt};

struct event interrupt_handlers[INTERRUPTS_NUM];
// some irq can be in use but do not have handlers yet, e.g. MSI that allocates a range of irqs
uint64_t interrupt_available[INTERRUPTS_NUM / 64];

PERCPU volatile uint8_t irq_ready_num = 0; // Number of hardware interrupt that has ready to process

struct event *event_peek(bool wait) {
    uint8_t ret;
    while (true) {
        ret = irq_ready_num;
        if (ret)
            break;
        if (!wait)
            return NULL;

        // following cli/sti section tries to eliminate race condition with interrupt handler that sets irq_ready_num
        x86_cli();
        ret = irq_ready_num;
        if (ret) {
            break;
        } else { // sleep
            COMPILER_BARRIER;
            x86_sti(); // sti guaranties that IRQ is not fired until the end of the next instruction
            x86_hlt(); // thus this sti/hlt pair runs atomically
        }
    }

    SHOUT_IF(ret < IRQ_BASE, "Unexpected IRQ number %d", ret);
    SHOUT_IF(!interrupt_handlers[ret].handler, "Requested IRQ %d does not have a handler", ret);
    irq_ready_num = 0;
    x86_sti(); // cli is set by the irq handler
    return &interrupt_handlers[ret];
}

struct PACKED interrupt_frame {
    uint64_t di, si, bp, bx, dx, cx, ax;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
    uint64_t vector;
    uint64_t err_code;
    uint64_t ip, cs, flags;
};

static void dump_frame(struct interrupt_frame *frame) {
    char page_fault_code[10] = {0};
    if (frame->vector == INTERRUPT_PAGE_FAULT && frame->err_code) {
        const char codes[] = "PWURI";
        uint64_t code = frame->err_code;
        int i = 0;
        page_fault_code[i++] = '(';
        while (code) {
            size_t pos = FFS(code) - 1;
            SHOUT_IF(pos >= ARRAY_SIZE(codes), "error code for page fault is out of range");
            page_fault_code[i++] = codes[pos];
            code &= ~BIT(pos);
        }

        page_fault_code[i++] = ')';
    }

    printf(" CS: %lx RIP: %lx FLAGS: %lx\n", frame->cs, frame->ip, frame->flags);
    printf(" RAX: %lx RBX: %lx RCX: %lx RDX: %lx\n", frame->ax, frame->bx, frame->cx, frame->dx);
    printf(" RSI: %lx RDI: %lx RBP: %lx RSP: %lx\n", frame->si, frame->di, frame->bp, (uintptr_t)(frame + 1));
    printf(" R8: %lx R9: %lx R10: %lx R11: %lx\n", frame->r8, frame->r9, frame->r10, frame->r11);
    printf(" R12: %lx R13: %lx R14: %lx R15: %lx\n", frame->r12, frame->r13, frame->r14, frame->r15);
    printf(" CR0: %lx CR2: %lx CR3: %lx CR4: %lx\n", x86_get_cr0(), x86_get_cr2(), x86_get_cr3(), x86_get_cr4());
    printf(" vector: %lx code: %lx%s\n", frame->vector, frame->err_code, page_fault_code);
}

static void exception_die(const char *msg, struct interrupt_frame *frame) {
    printf("%s\n", msg);
    dump_frame(frame);
    if (IS_ENABLED(CONFIG_FRAME_POINTER)) {
        print_stack_trace(frame->bp);
    }
    x86_stop();
}

void x86_exception_handler(struct interrupt_frame *frame) { exception_die("An exception occurred, halting:", frame); }

INIT_CODE int interrupt_reserve(uint8_t size) {
    PANIC_IF(!ISPOW2(size), "Number of requested MSI vectors (%d) need to be power of 2", size);

    if (size == 1) {
        for (size_t i = 0; i < ARRAY_SIZE(interrupt_available); i++) {
            size_t idx = FFS(interrupt_available[i]);
            if (idx) {
                idx--; // idx index starts with 1
                int irq_num = i * 64 + idx;

                // we found an available irq, reserve it
                interrupt_available[i] &= ~BIT(idx);
                if (irq_num >= INTERRUPT_LOCAL_APIC_BASE) {
                    // the top part of irq range is for APIC
                    break;
                }
                return irq_num;
            }
        }
    } else {
        // MSI requires that multiple vectors need to be power of 2, aligned on power of 2 border
        for (size_t i = 0; i < ARRAY_SIZE(interrupt_available); i++) {
            uint64_t mask = (1ULL << size) - 1;
            for (size_t j = 0; j < 64 / size; j++) {
                if ((interrupt_available[i] & mask) == mask) {
                    int irq_num = i * 64 + j * 64 / size;
                    if (irq_num + size > INTERRUPT_LOCAL_APIC_BASE) {
                        // the top part of irq range is for APIC
                        break;
                    }
                    interrupt_available[i] &= ~mask;
                    return irq_num;
                }

                mask <<= size;
            }
        }
    }

    PANIC("Cannot find %d IRQs for reservation", size);
    return -1;
}

INIT_CODE int interrupt_register(event_handler_t handler, void *data) {
    // Right now we just walk around interrupt_handlers table and pick the first available
    // interrupt. It assumes that there is no interrupt sharing, it might sound a bit crazy
    // as a lot of legacy devices hardcode interrupt# and clash happen sooner or later. But for
    // now we focus on PCIe device that have flexible MSI-X assignment mechanism. If we will
    // need to support legacy devices then we need to come up with something better than this.
    int irq_num = interrupt_reserve(1);
    if (irq_num == -1)
        return -1;

    // XXX: interrupt_handlers is globally modifiable struct, add synchronization
    struct event *entry = &interrupt_handlers[irq_num];
    if (entry->handler) {
        PANIC("IRQ %d is no marked as inuse but has non-NULL handler", irq_num);
        return -1;
    }
    entry->handler = handler;
    entry->data = data;

    return irq_num;
}

INIT_CODE void interrupt_register_with_vector(uint16_t vector, event_handler_t handler, void *data) {
    // PANIC_IF(vector < INTERRUPT_LOCAL_APIC_BASE, "Only APIC-specific interrupts can be statically assigned");
    // XXX: interrupt_handlers is globally modifiable struct, add synchronization
    struct event *entry = &interrupt_handlers[vector];
    if (entry->handler) {
        PANIC("Trying to register handler for interrupt %d but it is already registered", vector);
        return;
    }
    entry->handler = handler;
    entry->data = data;

    interrupt_available[vector / 64] &= ~BIT(vector % 64);
}

void interrupt_unregister(uint8_t num) {
    SHOUT_IF(!interrupt_handlers[num].handler, "Interrupt handler %d is not registered", num);

    interrupt_handlers[num].handler = NULL;
    interrupt_handlers[num].data = NULL;

    interrupt_available[num / 64] |= BIT(num % 64);
}

INIT_CODE int irq_register(uint8_t irq_line, event_handler_t handler, void *data) {
    // XXX: interrupt lines are hardcoded in hardware and might clash
    // we need to find a way to resolve the problem:
    //   - add 'shared handlers' functionality
    //   - or avoid using IRQ and use MSI as much as possible

    int intr = interrupt_register(handler, data);
    if (intr < 0) // failure to register
        return intr;
    ioapic_route_irq(irq_line, intr);
    return intr;
}

INIT_CODE static void idt_handler_setup(struct idt_entry *entry, uintptr_t addr, bool exception) {
    entry->gdt_selector = CODE_SELECTOR;
    entry->ist = 0;
    if (exception) {
        entry->attributes = 0x8e; /* present, ring 0, 64-bit interrupt gate */
    } else {
        // we use trap gate here as irq handler is going to mask hardware interrupts and we do not want
        // iret to restore the original IF value
        entry->attributes = 0x8f; /* present, ring 0, 64-bit trap gate */
    }

    entry->handler_0_15 = (uint16_t)addr;
    entry->handler_16_31 = (uint16_t)(addr >> 16);
    entry->handler_32_63 = (uint32_t)(addr >> 32);
}

INIT_CODE void idt_struct_setup(void) {
    struct idt_entry *entry = (struct idt_entry *)idt; // we cast it from const to mutable for one-time initialization

    extern uint8_t exception_handlers, exception_handlers_end;
    uintptr_t addr = (uintptr_t)&exception_handlers;
    size_t handler_len = (&exception_handlers_end - &exception_handlers) / IRQ_BASE;
    for (int i = 0; i < IRQ_BASE; i++, entry++, addr += handler_len) {
        // printf("exception %d addr %lx\n", i, addr);
        idt_handler_setup(entry, addr, true);
    }

    extern uint8_t irq_handlers, irq_handlers_end;
    addr = (uintptr_t)&irq_handlers;
    handler_len = (&irq_handlers_end - &irq_handlers) / (INTERRUPTS_NUM - IRQ_BASE);
    for (int i = IRQ_BASE; i < INTERRUPTS_NUM; i++, entry++, addr += handler_len) {
        idt_handler_setup(entry, addr, false);
    }

    for (size_t i = 0; i < ARRAY_SIZE(interrupt_available); i++) {
        interrupt_available[i] = ~(uint64_t)0;
    }
    // Mark first IRQ_BASE as unavailable for IRQ
    interrupt_available[0] &= ~((1ULL << IRQ_BASE) - 1);
}

INIT_CODE void idt_load(void) { __asm__ volatile("lidt %0" ::"m"(idtr)); }
