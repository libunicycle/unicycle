// SPDX-License-Identifier: MIT

#pragma once

#include "compiler.h"
#include "shout.h"
#include <stdbool.h>
#include <stdint.h>

#define PAGE_SIZE_SFT 12
#define PAGE_SIZE (1 << PAGE_SIZE_SFT)
#define STACK_ALIGNMENT 16
#define CACHE_LINE_SIZE 64

// type that represents size of register
#ifdef __x86_64__
typedef uint64_t regsize_t;
#else
typedef uint32_t regsize_t;
#endif

#define EFLAGS_SUPPORTS_CPUID BIT(21)

#define CR0_PE BIT(0)  // Protected Mode Enable
#define CR0_MP BIT(1)  // Monitor co-processor
#define CR0_EM BIT(2)  // Emulation
#define CR0_TS BIT(3)  // Task switched
#define CR0_NE BIT(5)  // Native FPU exception handling
#define CR0_PG BIT(31) // Paging

#define CR4_PAE BIT(5)         // Physical Address Extension
#define CR4_OSFXSR BIT(9)      // Operating system support for FXSAVE and FXRSTOR instructions
#define CR4_OSXMMEXCPT BIT(10) // Operating System Support for Unmasked SIMD Floating-Point Exceptions

#define CPUID_FEATURES 1
#define CPUID_CACHE_INFO 2
#define CPUID_SERIALNO 3
#define CPUID_CACHE 4
#define CPUID_MONITOR 5
#define CPUID_THERMAL_N_POWER 6
#define CPUID_EXTENDED_FEATURES 7
#define CPUID_DIRECT_CACHE_ACCESS 9
#define CPUID_TSC_FREQ 15
#define CPUID_MAX_NO 0x80000000
#define CPUID_EXTENDED_SIGNATURE 0x80000001

// CPUID eax = 1 flags
#define CPUID_EDX_FPU BIT(0)
#define CPUID_EDX_APIC BIT(9)
#define CPUID_EDX_SSE BIT(25)
#define CPUID_EDX_SSE2 BIT(26)
#define CPUID_ECX_SSE3 BIT(0)
#define CPUID_ECX_SSSE3 BIT(9)
#define CPUID_ECX_SSE41 BIT(19)
#define CPUID_ECX_SSE42 BIT(20)
#define CPUID_ECX_X2APIC BIT(21)

// CPUID eax = 0x80000001 flags
#define CPUID_FEATURE_1G_PAGE BIT(26)
#define CPUID_FEATURE_LONG_MODE BIT(29)

static inline regsize_t x86_get_cr0(void) {
    regsize_t val;
    __asm__ volatile("mov %%cr0, %0" : "=r"(val));
    return val;
}

static inline void x86_set_cr0(regsize_t val) { __asm__ volatile("mov %0, %%cr0" ::"r"(val)); }

static inline regsize_t x86_get_cr2(void) {
    regsize_t val;
    __asm__ volatile("mov %%cr2, %0" : "=r"(val));
    return val;
}

static inline void x86_set_cr2(regsize_t val) { __asm__ volatile("mov %0, %%cr2" ::"r"(val)); }

static inline regsize_t x86_get_cr3(void) {
    regsize_t val;
    __asm__ volatile("mov %%cr3, %0" : "=r"(val));
    return val;
}

static inline void x86_set_cr3(regsize_t val) { __asm__ volatile("mov %0, %%cr3" ::"r"(val)); }

static inline regsize_t x86_get_cr4(void) {
    regsize_t val;
    __asm__ volatile("mov %%cr4, %0" : "=r"(val));
    return val;
}

static inline void x86_set_cr4(regsize_t val) { __asm__ volatile("mov %0, %%cr4" ::"r"(val)); }

static inline regsize_t x86_get_flags(void) {
    regsize_t val;
    __asm__ volatile("pushf; pop %0" : "=r"(val));
    return val;
}

static inline void x86_set_flags(regsize_t val) { __asm__ volatile("push %0; popf;" ::"r"(val)); }

static inline void x86_cli() { __asm__ volatile("cli"); }
static inline void x86_sti() { __asm__ volatile("sti"); }

static inline void x86_hlt() { __asm__ volatile("hlt"); }
static inline void x86_pause() { __asm__ volatile("pause"); }

NORETURN static inline void x86_stop(void) {
    while (true) {
        x86_cli();
        x86_hlt();
    }
}

static inline void x86_cpuid(uint32_t id, uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    __asm__ volatile("cpuid" : "=a"(*a), "=b"(*b), "=c"(*c), "=d"(*d) : "a"(id));
}

#define MSR_PLATFORM_ID 0x17
#define MSR_APIC_BASE 0x1b
#define MSR_BIOS_UPDT_TRIG 0x79
#define MSR_BIOS_SIGN_ID 0x8b
#define MSR_EXT_FEATURES 0xc0000080
#define MSR_FS_BASE 0xc0000100

// flags for MSR_APIC_BASE
#define MSR_APIC_BSP BIT(8)     // is processor BSP
#define MSR_APIC_X2MODE BIT(10) // enable x2APIC mode
#define MSR_APIC_ENABLE BIT(11) // enable APIC

// flags for MSR_EXT_FEATURES
#define MSR_EXT_FEATURES_LONG_MODE BIT(8)   // Long mode (64 bits)
#define MSR_EXT_FEATURES_NO_EXECUTE BIT(11) // enables NXE paging bit

// read model specific register output edx:eax
static inline uint64_t x86_rdmsr(uint32_t id) {
    uint32_t eax, edx;
    __asm__ volatile("rdmsr" : "=a"(eax), "=d"(edx) : "c"(id));

    uint64_t ret = edx;
    ret <<= 32;
    ret |= eax;

    return ret;
}

// write model specific register, set value into edx:eax
static inline void x86_wrmsr(uint32_t id, uint64_t val) {
    uint32_t eax = (uint32_t)val;
    uint32_t edx = (uint32_t)(val >> 32);
    __asm__ volatile("wrmsr" ::"c"(id), "a"(eax), "d"(edx));
}

static inline uint64_t x86_rdtsc() {
    uint32_t eax, edx;
    __asm__ volatile("rdtsc" : "=a"(eax), "=d"(edx));

    uint64_t ret = edx;
    ret <<= 32;
    ret |= eax;

    return ret;
}

static inline void outb(uint16_t port, uint8_t data) { __asm__ volatile("out %1, %0" ::"dN"(port), "a"(data)); }
static inline void outw(uint16_t port, uint16_t data) { __asm__ volatile("out %1, %0" ::"dN"(port), "a"(data)); }
static inline void outd(uint16_t port, uint32_t data) { __asm__ volatile("out %1, %0" ::"dN"(port), "a"(data)); }

static inline uint8_t inb(uint16_t port) {
    uint8_t data;
    __asm__ volatile("in %1, %0" : "=a"(data) : "dN"(port));
    return data;
}

static inline uint16_t inw(uint16_t port) {
    uint16_t data;
    __asm__ volatile("in %1, %0" : "=a"(data) : "dN"(port));
    return data;
}

static inline uint32_t ind(uint16_t port) {
    uint32_t data;
    __asm__ volatile("in %1, %0" : "=a"(data) : "dN"(port));
    return data;
}

#define mb() __asm__ volatile("mfence" ::: "memory")
#define wmb() __asm__ volatile("sfence" ::: "memory")
#define rmb() __asm__ volatile("lfence" ::: "memory")

#define rdrand(arg) __asm__("rdrand %0" ::"mr"(arg))
#define rdseed(arg) __asm__("rdseed %0" ::"mr"(arg))

static inline void set_percpu_area(void *area) { x86_wrmsr(MSR_FS_BASE, (uintptr_t)area); }
static inline uintptr_t get_percpu_area() { return x86_rdmsr(MSR_FS_BASE); }
