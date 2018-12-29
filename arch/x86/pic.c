// SPDX-License-Identifier: MIT

#include "pic.h"
#include "x86.h"

// Disable 8259a interrupt controller
void pic_disable(void) {
    // Set ICW1
    outb(0x20, 0x11);
    outb(0xa0, 0x11);

    // Set ICW2 (IRQ base offset)
    outb(0x21, 0x20);
    outb(0xa1, 0x28);

    // Set ICW3
    outb(0x21, 4);
    outb(0xa1, 2);

    // Set ICW4
    outb(0x21, 1);
    outb(0xa1, 1);

    // Set OCW1 (mask all interrupts)
    outb(0x21, 0xff);
    outb(0xa1, 0xff);
}