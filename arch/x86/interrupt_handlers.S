# SPDX-License-Identifier: MIT

#include "interrupt.h"
#include "compiler.h"
#include "config.h"

.text

.global exception_handlers
.global exception_handlers_end

# Handlers for exceptions
exception_handlers:
.set i, 0
.rept IRQ_BASE

.if i == 8 || (i >= 10 && i <= 14) || i == 17 || i == 30
    nop  # nop filling to make all interrupt handlers text of the same size
    nop
.else
    pushq $0  # this interrupt has no code soe fill it to zero
.endif

    pushq $i  # interrupt number
    jmp exception_common

.set i, i + 1
.endr
exception_handlers_end:


.global irq_handlers
.global irq_handlers_end

# implementation of apic_interrupt_ack() in ASM
.macro apic_eoi
#if IS_ENABLED(CONFIG_X2APIC)
    push %rax
    push %rcx
    push %rdx
    mov $0x80b, %ecx
    mov $0, %eax
    mov $0, %edx
    wrmsr
    pop %rdx
    pop %rcx
    pop %rax
#else
    push %rax
    mov g_apic_addr, %rax
    movl $1, 0xb0(%rax) # REG_EOI == 0xb0
    pop %rax
#endif
.endm


# Handlers for hardware interrupts
irq_handlers:
.set i, IRQ_BASE
.rept INTERRUPTS_NUM-IRQ_BASE

    cli # we serialize IRQ handlers and mask all interruptsion until we process the current IRQ
#if IS_ENABLED(CONFIG_SMP)
    movq $i, %fs:irq_ready_num@tpoff
#else
    movq $i, irq_ready_num
#endif
    # Acknowledge APIC interruption here
    # It is a bit fuzzy when this ack should be called, Intel docs mentions that it should be done before IRET
    # but our experiments show that it also can be called from the main context (function event_peek) -
    # it works with qemu and vmware.
    apic_eoi
    iretq

.set i, i + 1
.endr
irq_handlers_end:

# We put this section far enough from exception_handlers so assembler does not use short jumps,
# instead it uses near jumps for all handlers and the handler code has the same size
exception_common:
    push %r15
    push %r14
    push %r13
    push %r12
    push %r11
    push %r10
    push %r9
    push %r8
    push %rax
    push %rcx
    push %rdx
    push %rbx
    push %rbp
    push %rsi
    push %rdi

    # TODO: save/restore SSE registers
    # TODO: stack alignment for SSE?

    mov %rsp, %rdi # pass pointer to iframe as first argument

    call x86_exception_handler

    pop %rdi
    pop %rsi
    pop %rbp
    pop %rbx
    pop %rdx
    pop %rcx
    pop %rax
    pop %r8
    pop %r9
    pop %r10
    pop %r11
    pop %r12
    pop %r13
    pop %r14
    pop %r15

    # drop vector number and error code
    add $16, %rsp
    iretq
