// SPDX-License-Identifier: MIT

#include "compiler.h"
#include "config.h"
#include "mmu.h"
#include "multiboot1.h"
#include "stdio.h"
#include "x86.h"
#include "x86_init.h"
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

// Number of AP already initialized
INIT_DATA atomic_int ap_count = 0;

void start_ap_64(void);

// Starting point of execution for AP
INIT_CODE NORETURN void smp_ap_start(void) {
    atomic_fetch_add_explicit(&ap_count, 1, memory_order_relaxed);

    fpu_init();
    sse_init();

    x86_set_cr3((uintptr_t)p4_table);
    // enable PAE
    x86_set_cr4(x86_get_cr4() | CR4_PAE);

    // set long mode bit
    uint64_t mode_msr = x86_rdmsr(MSR_EXT_FEATURES);
    mode_msr |= MSR_EXT_FEATURES_LONG_MODE | MSR_EXT_FEATURES_NO_EXECUTE;
    x86_wrmsr(MSR_EXT_FEATURES, mode_msr);

    // enable paging
    x86_set_cr0(x86_get_cr0() | CR0_PG);

    // load global description table
    __asm__ volatile("lgdt %0" ::"m"(gdt64_pointer));

    // We jump to 64-bit function and its ABI requires 16-byte stack alignment (to make SSE work properly with stack-located data).
    // Make it aligned according to the spec.
    // It is an equivalent of using ((force_align_arg_pointer)) function attribute in the callee,
    // unfortunately Clang does not support the attribute for x86_64 callees http://lists.llvm.org/pipermail/cfe-dev/2017-June/054359.html
    __asm__ volatile("and %0, %%esp" ::"irm"(-16));
    __asm__ volatile("sub %0, %%esp" ::"irm"(8)); // 8 bytes that x86_64 ABI uses for %eip and %cs values
    // jump to long mode. 'call' does not work in qemu https://bugs.launchpad.net/qemu/+bug/1699867
    __asm__("jmp %0, %1" ::"i"(CODE_SELECTOR), "p"(start_ap_64));
    __builtin_unreachable();
}