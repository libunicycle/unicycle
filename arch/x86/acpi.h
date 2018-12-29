// SPDX-License-Identifier: MIT

#pragma once

#include "compiler.h"
#include <stdint.h>

// TODO: this memory region need to be configured as 'strong uncachable'
extern uintptr_t g_apic_addr;
extern uintptr_t g_hpet_addr;

// It is the same as ACPI_MCFG_ALLOCATION
struct PACKED acpi_mcfg_baseaddr_alloc {
    uint64_t base_addr;
    uint16_t segment_group_num;
    uint8_t start_bus_num;
    uint8_t end_bus_num;
    uint32_t __reserved0;
};
extern __mmio const struct acpi_mcfg_baseaddr_alloc *g_pci_ext_config;

void acpi_init(void *root);
