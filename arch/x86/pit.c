// SPDX-License-Identifier: MIT

// Programmable Interval Timer

#include "x86.h"
#include <stdint.h>

#define FREQ 1193182

#define PORT_COUNTER0 0x40
#define PORT_CMD 0x43

// Command Register

// BCD
#define CMD_BINARY 0x00 // Use Binary counter values
#define CMD_BCD 0x01    // Use Binary Coded Decimal counter values

// Mode
#define CMD_MODE0 0x00 // Interrupt on Terminal Count
#define CMD_MODE1 0x02 // Hardware Retriggerable One-Shot
#define CMD_MODE2 0x04 // Rate Generator
#define CMD_MODE3 0x06 // Square Wave
#define CMD_MODE4 0x08 // Software Triggered Strobe
#define CMD_MODE5 0x0a // Hardware Triggered Strobe

// Read/Write
#define CMD_LATCH 0x00
#define CMD_RW_LOW 0x10  // Least Significant Byte
#define CMD_RW_HI 0x20   // Most Significant Byte
#define CMD_RW_BOTH 0x30 // Least followed by Most Significant Byte

// Counter Select
#define CMD_COUNTER0 0x00
#define CMD_COUNTER1 0x40
#define CMD_COUNTER2 0x80
#define CMD_READBACK 0xc0

void pit_init(void) {
    uint16_t hz = 100;
    uint16_t divisor = FREQ / hz;
    outb(PORT_CMD, CMD_BINARY | CMD_MODE3 | CMD_RW_BOTH | CMD_COUNTER0);
    outb(PORT_COUNTER0, (uint8_t)divisor);
    outb(PORT_COUNTER0, (uint8_t)(divisor >> 8));
}