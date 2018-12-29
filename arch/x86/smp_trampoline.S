# SPDX-License-Identifier: MIT

# This is the very first code executed by an AP during SMP initialization.
# AP initialization starts in 16-bit mode and no stack is set.
# We need to switch AP to 32-bit mode, setup stack pointer
# and then we can use initialization logic implemented in C
# See more info about AP initialization in Intel documentation 8.4.4.2

#include "smp.h"

.section .smp.trampoline
.global smp_entry

.code16
smp_entry:
  cli

  # Switch to protected mode. See Intel documentation chapter 9.8
  lgdt RELOC(smp.gdt.pointer)

  mov %cr0, %eax
  or $1, %eax # set BIT(0) to enable protected mode
  mov %eax, %cr0

  jmp $0x8, $(RELOC(protected_mode))

.code32
protected_mode:
  mov $0x10, %ax
  mov %ax, %ds
  mov %ax, %es
  mov %ax, %fs
  mov %ax, %gs
  mov %ax, %ss

  # 1024 is size of the AP stack, it should be equal to SMP_AP_STACK_SIZE
  mov $SMP_AP_STACK_SIZE, %eax
  # each initialized AP atomically increases the counter and uses the allocated area
  # for its stack
  lock xadd %eax, smp_stack_pointer
  mov %eax, %esp

  jmp $0x8, $(smp_ap_start)

.p2align 2
smp.gdt:
  SEG_NULL                           # null
  SEG(STA_X | STA_R, 0, 0xffffffff)  # code
  SEG(STA_W, 0, 0xffffffff)          # data
smp.gdt.pointer:
  .word smp.gdt.pointer - smp.gdt - 1
  .long RELOC(smp.gdt)
