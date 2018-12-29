// SPDX-License-Identifier: MIT

#pragma once

#define SMP_AP_INIT_AREA 0x1000  // AP trampoline should be below 1M and aligned to PAGE_SIZE
#define SMP_AP_STACK_SIZE 0x1000 // 4K for AP stack

#define STA_X 0x8 // Executable segment
#define STA_E 0x4 // Expand down (non-executable segments)
#define STA_C 0x4 // Conforming code segment (executable only)
#define STA_W 0x2 // Writeable (non-executable segments)
#define STA_R 0x2 // Readable (executable segments)
#define STA_A 0x1 // Accessed

#ifdef __ASSEMBLER__

#define RELOC(sym) ((sym)-smp_entry + SMP_AP_INIT_AREA)
#define SEG_NULL \
    .word 0, 0;  \
    .byte 0, 0, 0, 0

#define SEG(type, base, lim)             \
    .word(((lim) >> 12) & 0xffff);       \
    .word((base)&0xffff);                \
    .byte(((base) >> 16) & 0xff);        \
    .byte(0x90 | (type));                \
    .byte(0xC0 | (((lim) >> 28) & 0xf)); \
    .byte(((base) >> 24) & 0xff)

#endif
