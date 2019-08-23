// SPDX-License-Identifier: MIT

#include "acpi.h"
#include "alloca.h"
#include "apic.h"
#include "asan.h"
#include "buddy.h"
#include "compiler.h"
#include "config.h"
#include "cpu.h"
#include "elf.h"
#include "init.h"
#include "interrupt.h"
#include "ioapic.h"
#include "keyboard.h"
#include "mem.h"
#include "microcode.h"
#include "mmu.h"
#include "pci.h"
#include "pic.h"
#include "rand.h"
#include "shout.h"
#include "smp.h"
#include "sort.h"
#include "stdio.h"
#include "timer.h"
#include "uniboot.h"
#include "unicycle.h"
#include "vga_console.h"
#include "x86.h"
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef CONFIG_SMP

INIT_DATA struct uniboot_segment uniboot_tls_segment;

#define MAX_TRAMPOLINE_TEXT 4096

INIT_DATA uint32_t smp_stack_pointer = SMP_AP_INIT_AREA + MAX_TRAMPOLINE_TEXT + SMP_AP_STACK_SIZE;
extern uint8_t __smp_trampoline_start, __smp_trampoline_end;

BUILD_PANIC_IF(SMP_AP_INIT_AREA >= 64 * 1024, "Realtime mode can access lower 64K only");
BUILD_PANIC_IF(!IS_ROUNDED(SMP_AP_INIT_AREA, PAGE_SIZE), "AP trampoline should be aligned to page size");

// Start and initialize non-boot processors, see Intel manual section 8.4.4.1
// Wait until all the CPUs are up and initialized
INIT_CODE static void smp_ap_init() {
    // Copy SMP AP trampoline code to memory address space below 1M. It is needed as AP starts in real-time mode and can access only low
    // address space.
    PANIC_IF(&__smp_trampoline_end - &__smp_trampoline_start > MAX_TRAMPOLINE_TEXT, "AP trampoline text bigger than allocated memory");
    memcpy8((void *)SMP_AP_INIT_AREA, &__smp_trampoline_start, &__smp_trampoline_end - &__smp_trampoline_start);

    // Try to wakeup SMP cores 3 times
    for (int t = 0; t < 3; t++) {
        printf("Found %ld SMP cores, waking it up\n", cpu_nodes_num);
        for (size_t i = 0; i < cpu_nodes_num; i++) {
            bool online = atomic_load(&cpu_nodes[i].online);
            if (!online) {
                uint32_t apic_id = cpu_nodes[i].apic_id;
                apic_ap_init(apic_id);
                apic_ap_start(apic_id, SMP_AP_INIT_AREA);
            }
        }

        // Now we wait until all SMP cores get online. Intel docs say it might take up to 200ms
        for (int i = 0; i < 20; i++) {
            // check cores state 20 time with 10ms sleep between checks
            size_t offline_count = 0;
            for (size_t i = 0; i < cpu_nodes_num; i++) {
                if (!atomic_load(&cpu_nodes[i].online))
                    offline_count++;
            }

            if (!offline_count) {
                // All cores online now, yay!
                return;
            }
            sleep_us(10000); // sleep 10ms
        }
    }

    printf("Cannot wake up cores: ");
    for (size_t i = 0; i < cpu_nodes_num; i++) {
        bool online = atomic_load(&cpu_nodes[i].online);
        if (!online) {
            printf("#%ld(acpi_id=%d) ", i, cpu_nodes[i].apic_id);
        }
    }
    printf("\n");
}

#else
INIT_CODE static void smp_ap_init() {}
#endif

INIT_DATA struct uniboot_segment uniboot_init_segment;

// Initializes per-cpu area (TLS data, bss, stack)
// Returns pointer to top of the per-CPU stack
INIT_CODE static void *percpu_area_setup(void) {
    // 'Cut' TLS area from buddy allocator
    BUILD_PANIC_IF(!ISPOW2(CONFIG_PER_CPU_AREA_SIZE), "PER_CPU_AREA_SIZE config should be power of two");
    void *percpu_area = alloc_buddy_allocate(ILOG2(CONFIG_PER_CPU_AREA_SIZE));

#ifdef CONFIG_SMP
    // It is an equivalent of thread_info struct.
    // Some (e.g. x86_64) TLS ABIs keep it above TLS area some other below TLS
    struct cpu_info {
        struct cpu_info *self; // XXX: x86_64 ABI expect first field to be a pointer to self
    };

    // TODO: add memory sanitizer that checks CPU access only its own per-cpu area
    size_t stack_size = CONFIG_PER_CPU_AREA_SIZE - uniboot_tls_segment.memsz - sizeof(struct cpu_info);
    PANIC_IF(stack_size < CONFIG_MIN_STACK_SIZE, "Allocated stack (%ld) is too small", stack_size);

    // initialize cpu_info
    uint64_t cpu_info_offset = ROUND_UP(uniboot_tls_segment.memsz, uniboot_tls_segment.align);
    struct cpu_info *cpu = (struct cpu_info *)(percpu_area + cpu_info_offset);
    cpu->self = cpu;

    // Setup TLS %fs area
    set_percpu_area(cpu);

    // copy tdata
    memcpy8(percpu_area, (void *)uniboot_tls_segment.vaddr, uniboot_tls_segment.filesz);
    // clear .tbss
    memset8(percpu_area + uniboot_tls_segment.filesz, 0, uniboot_tls_segment.memsz - uniboot_tls_segment.filesz);
#else
    BUILD_PANIC_IF(CONFIG_PER_CPU_AREA_SIZE < CONFIG_MIN_STACK_SIZE, "Configured stack is too small");
#endif

    // TODO: currently we mark stack area as readable/writable
    //       in the future we need to mark it as unintialized and enable ASAN for stack
    asan_mark_memory_region((uintptr_t)percpu_area, CONFIG_PER_CPU_AREA_SIZE, ASAN_TAG_RW);

    return percpu_area;
}

INIT_CODE static void cpu_mark_online(uint32_t cpu_id, void *percpu_area) {
    PANIC_IF(cpu_id >= cpu_nodes_num, "Requested CPU #%d is larger than number of total CPUs %ld", cpu_id, cpu_nodes_num);
    PANIC_IF(cpu_nodes[cpu_id].online, "CPU #%d is already marked online", cpu_id);
    printf("CPU #%d is online\n", cpu_id);
    atomic_store(&cpu_nodes[cpu_id].online, true);
    cpu_nodes[cpu_id].percpu_area = percpu_area;
}

INIT_CODE static void *find_uniboot_entry(void *boot_info, uint32_t entry_type) {
    struct uniboot_info *hdr = boot_info;
    size_t length = hdr->length;
    void *ptr = boot_info + sizeof(struct uniboot_info);

    while (ptr < boot_info + length) {
        struct uniboot_entry *entry = ptr;
        ptr += sizeof(struct uniboot_entry);

        if (entry->type == entry_type)
            return ptr;

        ptr += entry->length;
    }

    return NULL;
}

INIT_CODE static void load_segments_info(struct uniboot_info *boot_info) {
    struct uniboot_segment_list *segs = find_uniboot_entry(boot_info, UNIBOOT_ENTRY_SEGMENT_LIST);
    SHOUT_IF(!segs, "ELF segments information is not provided");
    for (uint16_t i = 0; i < segs->num; i++) {
        if (segs->segments[i].type == UNIBOOT_SEGTYPE_TLS) {
#ifdef CONFIG_SMP
            uniboot_tls_segment = segs->segments[i];
#else
            SHOUT_IF(segs->segments[i].memsz, "SMP is disabled but application has a TLS segment of size %ld", segs->segments[i].memsz);
#endif
            break;
        }
    }

    // By convention the last loadable segment is the .init. Save info about it as we need to unload it later
    for (int i = (int)segs->num; i >= 0; i--) {
        if (segs->segments[i].type == UNIBOOT_SEGTYPE_LOAD) {
            // Also by convention the init section has RWX bits set, let's check it
            uint32_t flags_expected = UNIBOOT_SEGFLAG_R | UNIBOOT_SEGFLAG_W | UNIBOOT_SEGFLAG_X;
            if ((segs->segments[i].flags & flags_expected) != flags_expected) {
                printf("Init segment has incorrect flags");
                break;
            }
            uniboot_init_segment = segs->segments[i];

            break;
        }
    }
}

INIT_CODE void memory_allocator_init(struct uniboot_info *bootinfo) {
    struct uniboot_memory_map *mmap = find_uniboot_entry(bootinfo, UNIBOOT_ENTRY_MEMORY_MAP);
    struct uniboot_memory_area *area;
    size_t i;

    // By convention we load our kernel at 1MiB. Skip area below 1MiB for now.
    // TODO: replace these extern vars coming from linker script with data read from segments_info
    extern uint8_t __kernel_start, __kernel_end;

    uintptr_t max_addr = 0;
    for (i = 0, area = mmap->areas; i < mmap->num; i++, area++) {
        if (area->type != UNIBOOT_MEM_RAM)
            continue;
        uintptr_t end = (uintptr_t)area->start + area->length;
        if (end > max_addr)
            max_addr = end;
    }

#ifdef CONFIG_ASAN
    uintptr_t asan_shadow_addr = asan_init_shadow(max_addr);

    // mark mem area used by kernel's .text/.bss as initialized right away
    asan_mark_memory_region((uintptr_t)&__kernel_start, (uintptr_t)&__kernel_end - (uintptr_t)&__kernel_start, ASAN_TAG_RW);

    // TODO: find out a place where we stop using the bootinfo memory, then mark it as UNINITIALIZED
    asan_mark_memory_region((uintptr_t)bootinfo, bootinfo->length, ASAN_TAG_RW);

    // TODO: find a way to detect memory area used for stack and mark it as ASAN RW here
    // e.g. QEMU uses static allocation (500K-580K) for stack
    // but UEFI uses different address space
    // asan_mark_memory_region(500 * 1024, 80 * 1024, ASAN_TAG_RW);

    // If we enable ASAN here then it will complain as we access stack data
    // asan_enable_reporting();
#endif

    for (i = 0, area = mmap->areas; i < mmap->num; i++, area++) {
        printf("Discovered memory area, type: %ld 0x%lx-0x%lx\n", area->type, (uintptr_t)area->start,
               (uintptr_t)area->start + area->length);

        if (area->type == UNIBOOT_MEM_ACPI || area->type == UNIBOOT_MEM_RESERVED) {
            // reserved is usually MMIO areas, so mark it as RW
            if (area->start < max_addr)
                asan_mark_memory_region(area->start, area->length, ASAN_TAG_RW);
            continue;
        }

        uintptr_t area_begin = (uintptr_t)area->start;
        uintptr_t area_end = (uintptr_t)area->start + area->length;

        if (area_end <= (uintptr_t)&__kernel_end)
            continue;

#ifdef CONFIG_ASAN
        if (area_end > asan_shadow_addr) {
            PANIC_IF(area_begin > area_end);
            area_end = asan_shadow_addr;
        }
#endif

        // One thing to remember that the first area added to buddy allocator is going to be used for freebits
        // And this area should be big enough (32KiB currently)

        // Check if it is the area where we loaded kernel binary
        if ((uintptr_t)&__kernel_end > area_begin && (uintptr_t)&__kernel_start < area_end) {
            // We can't add area used by the kernel to dynamic memory pool, find parts of the area not used by kernel
            if ((uintptr_t)&__kernel_start > area_begin) {
                alloc_buddy_append(area_begin, (uintptr_t)&__kernel_start);
            }
            if ((uintptr_t)&__kernel_end < area_end) {
                alloc_buddy_append((uintptr_t)&__kernel_end, area_end);
            }
        } else {
            alloc_buddy_append(area_begin, area_end);
        }
    }
}

// Max virtual address supported by L4 page directory
#define MAX_PHYS_ADDR (1ULL << 48)

INIT_CODE static int memareas_cmp(const void *_a, const void *_b) {
    const struct uniboot_memory_area *a = _a, *b = _b;
    if (a->start > b->start)
        return 1;
    else if (a->start < b->start)
        return -1;
    else
        return 0;
}

INIT_CODE static size_t merge_memory_areas(struct uniboot_memory_area *areas, size_t num) {
    size_t out_num = 0;
    for (size_t i = 0; i < num; i++) {
        // skip zero memory area
        if (!areas[i].length)
            continue;

        if (i && areas[out_num].type == areas[i].type && areas[out_num].start + areas[out_num].length == areas[i].start) {
            // Two areas are adjusted and have the same type. Let's merge it.
            areas[out_num].length += areas[i].length;
        } else {
            if (out_num != i)
                areas[out_num] = areas[i];
            out_num++;
        }
    }
    return out_num;
}

INIT_CODE static int segments_cmp(const void *_a, const void *_b) {
    const struct uniboot_segment *a = _a, *b = _b;
    if (a->vaddr > b->vaddr)
        return 1;
    else if (a->vaddr < b->vaddr)
        return -1;
    else
        return 0;
}

INIT_CODE static void normalize_bootinfo(struct uniboot_info *bootinfo) {
    struct uniboot_memory_map *mmap = find_uniboot_entry(bootinfo, UNIBOOT_ENTRY_MEMORY_MAP);
    PANIC_IF(mmap->num == 0, "Memory map is empty");
    sort(mmap->areas, mmap->num, sizeof(struct uniboot_memory_area), memareas_cmp);
    size_t num = merge_memory_areas(mmap->areas, mmap->num);
    mmap->num = num;

    struct uniboot_segment_list *segs = find_uniboot_entry(bootinfo, UNIBOOT_ENTRY_SEGMENT_LIST);
    sort(segs->segments, segs->num, sizeof(struct uniboot_segment), segments_cmp);
}

INIT_CODE static void page_mapping_reload_root(void) {
    // Load table into CR3 register to get the new page mapping into effect
    x86_set_cr3((uintptr_t)p4_table);
}

INIT_CODE static void page_mapping_setup(struct uniboot_info *bootinfo) {
    // Initially the whole address space is non-readable, non-executable, cacheable
    for (size_t i = 0; i < PAGE_ENTRIES_PER_TABLE; i++) {
        p4_table[i] = PAGE_NO_EXECUTABLE;
    }

    struct uniboot_memory_map *mmap = find_uniboot_entry(bootinfo, UNIBOOT_ENTRY_MEMORY_MAP);
    struct uniboot_memory_area *areas = mmap->areas;

    // Go over memory areas and set correct cacheble/writable paging bits
    for (size_t i = 0; i < mmap->num; i++) {
        uint64_t flags = PAGE_PRESENT | PAGE_WRITABLE;

        // only RAM type is cacheable, all other types (ACPI, MMIO) have cache disabled
        if (areas[i].type != UNIBOOT_MEM_RAM)
            flags |= PAGE_CACHE_DISABLE;

        page_table_set_bit(areas[i].start, areas[i].length, PAGE_PRESENT | PAGE_WRITABLE | PAGE_CACHE_DISABLE, flags);
    }

    // Go over segments and set correct cacheble/writable/executable paging bits
    struct uniboot_segment_list *segs = find_uniboot_entry(bootinfo, UNIBOOT_ENTRY_SEGMENT_LIST);
    struct uniboot_segment *seg = segs->segments;

    size_t prev_end = 0;
    for (uint16_t i = 0; i < segs->num; i++, seg++) {
        if (seg->type == UNIBOOT_SEGTYPE_LOAD) {
            // by convention segment start is always page aligned and segments never overlap
            size_t start = seg->vaddr;
            PANIC_IF(!IS_ROUNDED(start, PAGE_SIZE), "Loadable segment start address 0x%lx is not page-aligned", start);
            size_t length = ROUND_UP(seg->memsz, PAGE_SIZE);
            PANIC_IF(start + length < prev_end, "Loadable segment with start address 0x%lx overlaps with previous segment", start);
            prev_end = start + length;

            uint64_t flags = 0;
            if (!(seg->flags & UNIBOOT_SEGFLAG_X))
                flags |= PAGE_NO_EXECUTABLE;
            if (seg->flags & UNIBOOT_SEGFLAG_W)
                flags |= PAGE_WRITABLE;
            if (seg->flags & UNIBOOT_SEGFLAG_R)
                flags |= PAGE_PRESENT;

            page_table_set_bit(start, length, PAGE_NO_EXECUTABLE | PAGE_WRITABLE | PAGE_PRESENT, flags);
        }
    }

    // disable first page (at address 0x0) to catch NULL pointer errors
    page_table_set_bit(0, PAGE_SIZE, PAGE_PRESENT | PAGE_WRITABLE, 0);

    // page_table_dump();
    page_mapping_reload_root();
}

INIT_CODE void print_build_id(void) {
    extern uint8_t __build_id_note_start[], __build_id_note_end[];

    Elf_Nhdr *build_id = (Elf_Nhdr *)__build_id_note_start;
    PANIC_IF(build_id->n_type != 3, "Invalid build_id type");
    uint8_t *data = (uint8_t *)(build_id + 1);

    // account for 'name' field aligned to size of 4
    data = data + ROUND_UP(build_id->n_namesz, 4);

    printf("BuildId: ");
    for (uint8_t *p = data; p < __build_id_note_end; p++) {
        printf("%02x", *p);
    }
    printf("\n");
}

// Do not inline the function to avoid putting it to '.init' section
NOINLINE NORETURN void bootstrap_unicycle_loop(void *stack_addr) {
    // Unload the .init segment
    uintptr_t init_start = uniboot_init_segment.vaddr;
    size_t init_length = ROUND_UP(uniboot_init_segment.memsz, PAGE_SIZE);

    if (IS_ENABLED(CONFIG_DEBUG)) {
        // Make the segment area unreadable, any access to thjis area will cause an exception
        page_table_set_bit(init_start, init_length, PAGE_NO_EXECUTABLE | PAGE_WRITABLE | PAGE_PRESENT, PAGE_NO_EXECUTABLE);
    } else {
        // Remove executable flag
        page_table_set_bit(init_start, init_length, PAGE_NO_EXECUTABLE, PAGE_NO_EXECUTABLE);
        // And return back to buddy allocator
        alloc_buddy_append(init_start, init_start + init_length);
    }
    page_mapping_reload_root();

    // It would be great to enable ASAN earlier in memory_allocator_init.
    // For that we need to mark stack as RW but currently we do not know exact area for the boot stack.
    // So for now we enable ASAN right before we set our own stack with known location.
    asan_enable_reporting();

    __asm__ volatile("mov %0, %%rsp" ::"ir"(stack_addr));

    // Now back to unicycle loop
    unicycle_loop();
}

// Initialization code run by boot CPU
// We are in 64 bit mode, now we can do more advanced hardware initialization
NORETURN INIT_CODE void start(struct uniboot_info *bootinfo) {
    // load global description table
    __asm__ volatile("lgdt %0" ::"m"(gdt64_pointer));
    // load code segment selector by doing long jump to self
    __asm__ volatile("pushq %0; pushq $self; lretq; self:" ::"i"(CODE_SELECTOR));

    // 64bit mode does not use selectors, set it to null value
    __asm__ volatile("mov %0, %%ds; mov %0, %%es; mov %0, %%fs; mov %0, %%gs; mov %0, %%ss" ::"r"(NULL_SELECTOR));

    // Initialize console at the beginning to get early boot crash info
    console_init();

    // Setup exception handler early to catch possible exceptions at boot process
    idt_struct_setup();
    idt_load();

    printf("*** Booting Unicycle ***\n");
    print_build_id();

    PANIC_IF(bootinfo->magic != UNIBOOT_MAGIC, "Invalid magic number for boot params");
    normalize_bootinfo(bootinfo);

    // Go over all memory regions and add it to buddy allocator
    memory_allocator_init(bootinfo);

    load_segments_info(bootinfo);
    void *percpu_area = percpu_area_setup();
    // Slab memory allocator is available at this point

    // Go over all memory regions and set access bits
    page_mapping_setup(bootinfo);

    struct uniboot_acpi_info *acpi = find_uniboot_entry(bootinfo, UNIBOOT_ENTRY_ACPI_INFO);
    acpi_init(acpi ? (void *)acpi->acpi_root : NULL);

    apic_init(); // APIC require g_apic_addr initialized

    current_cpu_id = cpu_id_get(); // cpu_id_get() requires that APIC is initialized
    PANIC_IF(!(x86_rdmsr(MSR_APIC_BASE) & MSR_APIC_BSP), "Booting processor is marked as BSP");
    bootstrap_cpu_id = current_cpu_id;
    cpu_mark_online(bootstrap_cpu_id, percpu_area);
    rand_mixin_cpu_jitter();

    pic_disable();
    ioapic_init();
    keyboard_init();
    timer_system_init();

    if (IS_ENABLED(CONFIG_INTEL_MICROCODE)) {
        microcode_load();
    }
    x86_sti();
    pci_init();

    application_init();
    smp_ap_init();

    // Set per-cpu stack and use it starting NOW
    void *stack_addr = percpu_area + CONFIG_PER_CPU_AREA_SIZE;
    PANIC_IF(!IS_ROUNDED((uintptr_t)stack_addr, STACK_ALIGNMENT), "Stack pointer is not aligned according x86_64 ABI");
    bootstrap_unicycle_loop(stack_addr);

    __builtin_unreachable();
}

#ifdef CONFIG_SMP

NORETURN INIT_CODE void start_ap_64(void) {
    // 64bit mode does not use selectors, set it to null value
    __asm__ volatile("mov %0, %%ds; mov %0, %%es; mov %0, %%fs; mov %0, %%gs; mov %0, %%ss" ::"r"(NULL_SELECTOR));

    idt_load();

    void *percpu_area = percpu_area_setup();
    apic_init();
    current_cpu_id = cpu_id_get();
    if (IS_ENABLED(CONFIG_INTEL_MICROCODE)) {
        microcode_load();
    }
    cpu_mark_online(current_cpu_id, percpu_area);
    x86_sti();

    // Set per-cpu stack and use it starting NOW
    void *stack_addr = percpu_area + CONFIG_PER_CPU_AREA_SIZE;
    PANIC_IF(!IS_ROUNDED((uintptr_t)stack_addr, STACK_ALIGNMENT), "Stack pointer is not aligned according x86_64 ABI");
    __asm__ volatile("mov %0, %%rsp" ::"ir"(stack_addr));
    unicycle_loop();

    __builtin_unreachable();
}

#endif
