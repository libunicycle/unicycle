#include "compiler.h"
#include "mmu.h"
#include "multiboot1.h"
#include "start.h"
#include "x86.h"
#include "x86_init.h"
#include <stdint.h>

static void print(const char *msg) {
    static volatile uint16_t *cursor = (uint16_t *)0xb8000;

    for (const char *p = msg; *p; p++, cursor++) {
        *cursor = *p | (0x4f << 8);
    }
}

NORETURN static void error(const char *msg) {
    print("Boot error: ");
    print(msg);
    x86_stop();
}

static void setup_identity_page_table(void) {
    // setup page table root
    // TODO, make P3 huge pages working both in Qemu and VmWare
    p4_table[0] = (uintptr_t)p3_table | PAGE_WRITABLE | PAGE_PRESENT;
    // initialize p3-level entries
    uint32_t address = PAGE_WRITABLE | PAGE_PRESENT | PAGE_LARGE; // large P3 page is 1G size (1^30)
    for (size_t i = 0; i < ARRAY_SIZE(p3_table); i++) {
        p3_table[i] = address;
        address += (1 << 30);
    }

    __asm__ volatile("mov %0, %%cr3" ::"r"(p4_table));
}

static void memmove(void *dest, const void *src, size_t n) {
    uint8_t *d = dest + n - 1;
    const uint8_t *s = src + n - 1;
    for (size_t i = 0; i < n; i++) {
        *d-- = *s--;
    }
}

static void memzero(void *dest, size_t n) {
    uint8_t *d = dest;
    for (size_t i = 0; i < n; i++) {
        *d++ = 0;
    }
}

// Entry point for multiboot interface
// This function can be marked as 'naked', unfortunately gcc supports it for x86 only starting from version 8 (GCC8).
// https://gcc.gnu.org/bugzilla/show_bug.cgi?id=25967
// TODO: find if it is possible to specify registers for input arguments (multiboot magic and info structure)
NORETURN void _entry(void) {
    // multiboot provides stack that can be temporary used during initialization

    // set stack pointer to the end of stack array minus 32 bytes that are used by current stack frame
    //__asm__ volatile("mov %0, %%esp" ::"i"(boot_stack + BOOT_STACK_SIZE));

    uint32_t multiboot_magic, multiboot_info;
    // Given bizarre asm assigns %eax, %ebx to local variables
    __asm__ volatile("" : "=a"(multiboot_magic), "=b"(multiboot_info));

    if (multiboot_magic != MULTIBOOT_BOOTLOADER_MAGIC) {
        error("Bootloader did not provide Multiboot information");
    }

    // data, bss, tdata, tbss, init
    extern uint8_t __kernel_bss_start, __kernel_tdata_start, __kernel_tbss_start, __kernel_init_start, __kernel_end;
    size_t bss_size = &__kernel_tdata_start - &__kernel_bss_start;
    size_t tdata_size = &__kernel_tbss_start - &__kernel_tdata_start;
    size_t tbss_size = &__kernel_init_start - &__kernel_tbss_start;
    size_t init_size = &__kernel_end - &__kernel_init_start;
    memmove(&__kernel_init_start, &__kernel_init_start - tbss_size - bss_size, init_size);
    memzero(&__kernel_tbss_start, tbss_size);
    memmove(&__kernel_tdata_start, &__kernel_tdata_start - bss_size, tdata_size);
    memzero(&__kernel_bss_start, bss_size);

    // check if cpuid operation is supported
    regsize_t flags = x86_get_flags();
    x86_set_flags(flags ^ EFLAGS_SUPPORTS_CPUID);
    regsize_t new_flags = x86_get_flags();
    if (flags == new_flags) {
        error("This CPU does not support CPUID operation");
    }
    x86_set_flags(flags); // restore original flags

    // check if long mode is supported
    uint32_t max_id, unused;
    x86_cpuid(CPUID_MAX_NO, &max_id, &unused, &unused, &unused);
    if (max_id < CPUID_EXTENDED_SIGNATURE) {
        error("This CPU does not support required CPUID (0x80000001)");
    }

    uint32_t features;
    x86_cpuid(CPUID_EXTENDED_SIGNATURE, &unused, &unused, &unused, &features);
    if (!(features & CPUID_FEATURE_LONG_MODE)) {
        error("This CPU does not support long mode (64bit)");
    }

    uint32_t ecx, edx;
    x86_cpuid(CPUID_FEATURES, &unused, &unused, &ecx, &edx);
    if (!(edx & CPUID_EDX_FPU)) {
        error("No FPU is available at this system");
    }
    if (!(edx & CPUID_EDX_SSE) || !(edx & CPUID_EDX_SSE2)) {
        //  || !(ecx & CPUID_ECX_SSE3) || !(ecx & CPUID_ECX_SSSE3) || !(ecx & CPUID_ECX_SSE41) || !(ecx & CPUID_ECX_SSE42)
        error("No SSE available at this system");
    }
    if (!(edx & CPUID_EDX_APIC)) {
        error("No APIC present at the system");
    }
    if (CONFIG_X2APIC && !(ecx & CPUID_ECX_X2APIC)) {
        error("x2APIC mode is not supported");
    }

    if (!(features & CPUID_FEATURE_1G_PAGE)) {
        // Default QEMU configuration does not enable 1GiB pages support.
        // You need to specify cpu that has this feature support, e.g. '-cpu host' or '-cpu phenom'
        error("This CPU does not support 1GiB pages");
    }

    fpu_init();
    sse_init();

    // enable PAE
    x86_set_cr4(x86_get_cr4() | CR4_PAE);

    // set long mode bit
    uint64_t mode_msr = x86_rdmsr(MSR_EXT_FEATURES);
    mode_msr |= MSR_EXT_FEATURES_LONG_MODE;
    x86_wrmsr(MSR_EXT_FEATURES, mode_msr);

    // enable paging
    setup_identity_page_table();
    x86_set_cr0(x86_get_cr0() | CR0_PG);

    // load global description table
    __asm__ volatile("lgdt %0" ::"m"(gdt64_pointer));

    // We jump to 64-bit function and its ABI requires 16-byte stack alignment (to make SSE work properly
    // with stack-located data). Make it aligned according to the spec. It is an equivalent of using
    // ((force_align_arg_pointer)) function attribute in the callee, unfortunately Clang does not support
    // the attribute for x86_64 callees http://lists.llvm.org/pipermail/cfe-dev/2017-June/054359.html
    __asm__ volatile("and %0, %%esp" ::"irm"(-16));
    __asm__ volatile("sub %0, %%esp" ::"irm"(8)); // 8 bytes that x86_64 ABI uses for %eip and %cs values
    __asm__ volatile("" ::"D"(multiboot_info));   // first argument in ARM64 calling convention
    // jump to long mode. 'call' does not work in qemu https://bugs.launchpad.net/qemu/+bug/1699867
    __asm__ volatile("jmp %0, %1" ::"i"(CODE_SELECTOR), "p"(start));
    __builtin_unreachable();
}
