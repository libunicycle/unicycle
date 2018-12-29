/* SPDX-License-Identifier: MIT */

ENTRY(start)

SECTIONS {
    . = 1M;
    PROVIDE_HIDDEN(__kernel_start = .);

    .text : ALIGN(4096) {
        KEEP(*(.multiboot.header))
        *(.text .text.*)
    } :code

    .rodata : ALIGN(4096) {
        *(.rodata .rodata.*)
    } :rodata

    .note.gnu.build-id : {
        PROVIDE_HIDDEN(__build_id_note_start = .);
        *(.note.gnu.build-id)
        PROVIDE_HIDDEN(__build_id_note_end = .);
    } :rodata

    .data : ALIGN(4096) {
        *(.data .data.*)
    } :data

    PROVIDE_HIDDEN(__kernel_bss_start = .);
    .bss : {
        *(.bss .bss.*)
    } :data

    .init : ALIGN(4096) {
        /* Segment for data that is needed only during the initial phase and can be dropped once application is initialized */

        /* TODO: put microcode into this section as well */

        *(.init .init.*)

        PROVIDE_HIDDEN(__smp_trampoline_start = smp_entry);
        KEEP(*(.smp.trampoline))
        PROVIDE_HIDDEN(__smp_trampoline_end = .);

        /* Different compiler have different alignment rules for struct(pci_device):
          clang - 8 bytes
          gcc - 16 bytes
          TODO: find compiler independent way to find alignment requirements for it */
        . = ALIGN(16);
        PROVIDE_HIDDEN(__drivers_pci_start = .);
        KEEP(*(.drivers.pci))
        PROVIDE_HIDDEN(__drivers_pci_end = .);
    } :init

    /* End of runtime kernel text/data, the rest of the loaded sections are needed only during
     * initialization and can be unloaded afterwards */
    PROVIDE_HIDDEN(__kernel_end = .);

    PROVIDE_HIDDEN(__kernel_tdata_start = .);
    .tdata : {
        *(.tdata .tdata.*)
    } :init :tls

    PROVIDE_HIDDEN(__kernel_tbss_start = .);
    .tbss : {
        *(.tbss .tbss.*)
    } :init :tls
}

PHDRS {
    code PT_LOAD FLAGS(5); /* PF_R|PF_X */
    rodata PT_LOAD FLAGS(4); /* PF_R */
    data PT_LOAD FLAGS(6); /* PF_R|PF_W */
    init PT_LOAD FLAGS(7); /* PF_R|PF_W|PF_X, contains code/rodata/data that is needed at initialization only */
    tls PT_TLS;
}
