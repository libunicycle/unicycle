// SPDX-License-Identifier: MIT

#include "vga_console.h"
#include "console.h"
#include "mem.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VIDEO_MEM ((volatile uint16_t *)0xb8000)

#define WIDTH 80
#define HEIGHT 25

enum color {
    BLACK,
    BLUE,
    GREEN,
    CYAN,
    RED,
    MAGENTA,
    BROWN,
    GRAY,
    DARK_GRAY,
    BRIGHT_BLUE,
    BRIGHT_GREEN,
    BRIGHT_CYAN,
    BRIGHT_RED,
    BRIGHT_MAGENTA,
    YELLOW,
    WHITE
};

#define DEFAULT_COLOR (vga_color(WHITE, BLACK, false))
#define BLANK ' '

volatile uint16_t *cursor = VIDEO_MEM;
size_t column = 0, row = 0;

void console_init(void) {
    memset16((uint16_t *)VIDEO_MEM, BLANK, WIDTH * HEIGHT);
    cursor = VIDEO_MEM;
}

static inline uint16_t vga_color(enum color foreground, enum color background, bool blinking) {
    uint16_t color = 0;
    color |= ((foreground & 0xf) << 8);
    color |= ((background & 0x8) << 12);
    if (blinking)
        color |= (1 << 15);
    return color;
}

static void console_newline(void) {
    row++;

    if (row == HEIGHT) {
        memcpy16((uint16_t *)VIDEO_MEM, (uint16_t *)VIDEO_MEM + WIDTH, WIDTH * (HEIGHT - 1));
        row--;

        cursor = VIDEO_MEM + (HEIGHT - 1) * WIDTH;
        // blank the last line
        for (size_t i = 0; i < column; i++) {
            *(cursor + i) = BLANK;
        }
    } else {
        cursor = VIDEO_MEM + row * WIDTH;
    }

    column = 0;
}

void console_write(const char *str, size_t len) {
    // TODO: put this function into critical section

    for (size_t i = 0; i < len; i++) {
        const char c = *str++;
        if (c == '\n') {
            console_newline();
        } else {
            *cursor++ = DEFAULT_COLOR + c; // set only ASCII part, for color use default value
            column++;
            if (column == WIDTH) {
                console_newline();
            }
        }
    }
}
