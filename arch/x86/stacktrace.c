// SPDX-License-Identifier: MIT

#include "stacktrace.h"
#include "elf.h"
#include "stdio.h"
#include <stdint.h>

/*const char *elf_symbol_name(uintptr_t ptr) {
    // This function does not work as linker does not want to put .symtab into data section
    extern Elf_Sym __symtab_begin, __symtab_end;
    extern char __strtab_begin;

    Elf_Sym *sym = &__symtab_begin;

    while (sym < &__symtab_end) {
        if (ptr >= sym->st_value && ptr < (sym->st_value + sym->st_size)) {
            return &__strtab_begin + sym->st_name;
        }
        sym++;
    }

    return "?";
}*/

void dump_stack(void) {
    intptr_t ebp;
    __asm__ volatile("mov %%rbp, %0" : "=r"(ebp));
    print_stack_trace(ebp);
}

void print_stack_trace(uint64_t bp) {
    printf("Stacktrace:\n");
    while (bp) {
        uint64_t *ip = (uint64_t *)bp + 1;
        if (*ip) {
            printf(" 0x%lx [bp=0x%lx]\n", *ip, bp);
        }
        bp = *(uint64_t *)bp;
    }
}