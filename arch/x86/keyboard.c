// SPDX-License-Identifier: MIT

#include "keyboard.h"
#include "interrupt.h"
#include "stdio.h"
#include "x86.h"
#include <stdint.h>

static void handle_keyboard(UNUSED void *data) {
    uint8_t key = inb(0x60);
    printf("Keyboard key %d\n", key);

    // reset the keyboard controller
    uint8_t a = inb(0x61);
    a |= 0x82;
    outb(0x61, a);
    a &= 0x7f;
    outb(0x61, a);
}

void keyboard_init(void) { irq_register(IRQ_KEYBOARD, handle_keyboard, NULL); }