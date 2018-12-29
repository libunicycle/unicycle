#pragma once

#include "x86.h"

static inline void fpu_init(void) {
    regsize_t cr0 = x86_get_cr0();
    cr0 &= ~CR0_EM; // clear coprocessor emulation
    cr0 |= CR0_MP;  // set coprocessor monitoring
    cr0 |= CR0_NE;  // set native exceptions
    x86_set_cr0(cr0);

    __asm__ volatile("fninit");
}

static inline void sse_init(void) {
    regsize_t cr4 = x86_get_cr4();
    cr4 |= (CR4_OSFXSR | CR4_OSXMMEXCPT);
    x86_set_cr4(cr4);
}