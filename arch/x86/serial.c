// SPDX-License-Identifier: MIT

#include "console.h"
#include "x86.h"

#define PORT 0x3f8 /* COM1 */

void console_init(void) {
    outb(PORT + 1, 0x00); // Disable all interrupts
    outb(PORT + 3, 0x80); // Enable DLAB (set baud rate divisor)
    outb(PORT + 0, 0x01); // Set divisor to 1 (lo byte) 115200 baud
    outb(PORT + 1, 0x00); //                  (hi byte)
    outb(PORT + 3, 0x03); // 8 bits, no parity, one stop bit
    outb(PORT + 2, 0xc7); // Enable FIFO, clear them, with 14-byte threshold
    outb(PORT + 4, 0x0b); // IRQs enabled, RTS/DSR set
}

static uint8_t is_transmit_empty() { return inb(PORT + 5) & BIT(5); }

static void symbol_write(char ch) {
    while (is_transmit_empty() == 0)
        ;

    outb(PORT, ch);
}

void console_write(const char *str, size_t len) {
    for (size_t i = 0; i < len; i++) {
        char ch = *str++;
        if (ch == '\n')
            symbol_write('\r');
        symbol_write(ch);
    }
}

static uint8_t serial_received() { return inb(PORT + 5) & BIT(0); }

char console_read() {
    while (serial_received() == 0)
        ;

    return inb(PORT);
}