// SPDX-License-Identifier: MIT

#include "acpi.h"
#include "apic.h"
#include "compiler.h"
#include "cpu.h"
#include "kalloc.h"
#include "mem.h"
#include "mmu.h"
#include "shout.h"
#include "stdio.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// ACPI specification can be found here http://www.uefi.org/sites/default/files/resources/ACPI_6_2.pdf

#define RSDP_SIGNATURE 0x2052545020445352 // 'RSD PTR '
#define RSDT_SIGNATURE 0x54445352         // 'RSDT'
#define XSDT_SIGNATURE 0x54445358         // 'XSDT'
#define FACP_SIGNATURE 0x50434146         // 'FACP'
#define APIC_SIGNATURE 0x43495041         // 'APIC'
#define HPET_SIGNATURE 0x54455048         // 'HPET'
#define MCFG_SIGNATURE 0x4746434d         // 'MCFG'

struct PACKED __le acpi_rsdp {
    uint64_t signature; // RSDP_SIGNATURE
    uint8_t checksum;
    uint8_t oem[6];
    uint8_t revision;
    uint32_t rsdt_addr;
    // rev2 fields start from here
    uint32_t length;
    uint64_t xsdt_addr;
    uint8_t extended_checksum;
};

struct PACKED __le acpi_header {
    uint32_t signature;
    uint32_t length; // header can be embed into other structures, this is the length of the whole structure
    uint8_t revision;
    uint8_t checksum;
    uint8_t oem[6];
    uint8_t oem_table[8];
    uint32_t oem_revision;
    uint32_t creator_id;
    uint32_t creator_revision;
};

struct PACKED __le acpi_fadt {
    struct acpi_header header;
    uint32_t firmware_ctrl;
    uint32_t dsdt;
    uint8_t _reserved0;
    uint8_t preferred_pm_profile;
    uint16_t sci_int;
    uint32_t smi_cmd;
    uint8_t acpi_enable;
    uint8_t acpi_disable;
    uint8_t s4bios_req;
    uint8_t pstate_cnt;
    uint32_t pm1a_evt_blk;
    uint32_t pm1b_evt_blk;
    uint32_t pm1a_cnt_blk;
    uint32_t pm1b_cnt_blk;
    uint32_t pm2_cnt_blk;
    uint32_t pm_tmr_blk;
    uint32_t gpe0_blk;
    uint32_t gpe1_blk;
    uint8_t pm1_evt_len;
    uint8_t pm1_cnt_len;
    uint8_t pm2_cnt_len;
    uint8_t pm_tmr_len;
    uint8_t gpe0_blk_len;
    uint8_t gpe1_blk_len;
    uint8_t gpe1_base;
    uint8_t cst_cnt;
    uint16_t p_lvl2_lat;
    uint16_t p_lvl3_lat;
    uint16_t flush_size;
    uint16_t flush_stride;
    uint8_t duty_offset;
    uint8_t duty_width;
    uint8_t day_alarm;
    uint8_t mon_alarm;
    uint8_t century;
    uint16_t iapc_boot_arch;
    uint8_t _reserved1;
    uint32_t flags;
    uint8_t reset_reg[12];
    uint8_t reset_value;
    uint16_t arm_boot_arch;
    uint8_t fadt_minor_version;
    uint64_t x_firmware_ctrl;
    uint64_t x_dsdt;
    uint8_t x_pm1a_evt_blk[12];
    uint8_t x_pm1b_evt_blk[12];
    uint8_t x_pm1a_cnt_blk[12];
    uint8_t x_pm1b_cnt_blk[12];
    uint8_t x_pm2_cnt_blk[12];
    uint8_t x_pm_tmr_blk[12];
    uint8_t x_gpe0_blk[12];
    uint8_t x_gpe1_blk[12];
    uint8_t sleep_control_reg[12];
    uint8_t sleep_status_reg[12];
    uint64_t hypervisor_vendor_id;
};
BUILD_PANIC_IF(sizeof(struct acpi_fadt) != 276);

struct PACKED __le acpi_madt {
    struct acpi_header header;
    uint32_t apic_addr;
    uint32_t flags;
    // Dynamic list of interrupt controller structures
};

struct PACKED __le apic_header {
    uint8_t type;
    uint8_t length;
};

struct PACKED __le apic_local_apic {
    struct apic_header header;
    uint8_t acpi_processor_id;
    uint8_t apic_id;
    uint32_t flags;
};

#define APIC_PROCESSOR_ENABLED BIT(0)

struct PACKED __le apic_io_apic {
    struct apic_header header;
    uint8_t io_apic_id;
    uint8_t __reservred;
    uint32_t io_apic_addr;
    uint32_t interrupt_base;
};

struct PACKED __le apic_intr_override {
    struct apic_header header;
    uint8_t bus;
    uint8_t source; // IRQ
    uint32_t interrupt;
    uint16_t flags;
};

#define APIC_TYPE_LOCAL_APIC 0
#define APIC_TYPE_IO_APIC 1
#define APIC_TYPE_INTR_OVERRIDE 2
#define APIC_TYPE_NMI 3
#define APIC_TYPE_APIC_NMI 4
#define APIC_TYPE_APIC_ADDR_OVERRIDE 5
#define APIC_TYPE_IO_SAPIC 6
#define APIC_TYPE_LOCAL_SAPIC 7
#define APIC_TYPE_INTR_SOURCE 8
#define APIC_TYPE_LOCAL_X2APIC 9
#define APIC_TYPE_X2APIC_NMI 10
#define APIC_TYPE_GIC_CPU 11
#define APIC_TYPE_GIC_DISTRIB 12
#define APIC_TYPE_GIC_MSI 13
#define APIC_TYPE_GIC_REDISTRIB 14
#define APIC_TYPE_GIC_INTR_TRANSLTION 15

// https://www.intel.com/content/dam/www/public/us/en/documents/technical-specifications/software-developers-hpet-spec-1-0a.pdf
struct PACKED __le acpi_hpet {
    struct acpi_header header;
    uint8_t hardware_rev_id;
    uint8_t comparators_num : 5;
    uint8_t counter_size : 1;
    uint8_t __reserved0 : 1;
    uint8_t legacy_replacement : 1;
    uint16_t pci_id;
    uint8_t addr_space_id; // 0 - system memory, 1 - I/O
    uint8_t register_bit_width;
    uint8_t register_bit_offset;
    uint8_t __reserved1;
    uint64_t base_addr;
    uint8_t hpet_number;
    uint16_t counter_min; // the minimum clock ticks that can be set in periodic mode
    uint8_t oem_attr;
};

// PCI Firmware specification
struct PACKED __le acpi_mcfg {
    struct acpi_header header;
    uint64_t __reserverd0;
    struct acpi_mcfg_baseaddr_alloc alloc[];
};

uintptr_t g_apic_addr;
uintptr_t g_hpet_addr;

static void acpi_parse_facp(UNUSED const struct acpi_fadt *fadt) {}

const struct acpi_madt *g_madt;

static void acpi_parse_apic(const struct acpi_madt *madt) {
    printf("Local apic address 0x%x\n", madt->apic_addr);

    PANIC_IF(g_madt, "APIC MADT is already initialized"); // check that nobody set it before
    g_madt = madt;

    PANIC_IF(g_apic_addr, "APIC base address is already initialized");
    g_apic_addr = madt->apic_addr;

    uint8_t *p, *end;

    // First iteration is to count number of entries for IOAPIC/
    p = (uint8_t *)(madt + 1);
    end = (uint8_t *)madt + madt->header.length;
    cpu_nodes_num = 0, apic_ioapic_num = 0, apic_irq_override_num = 0;
    while (p < end) {
        struct apic_header *header = (struct apic_header *)p;
        uint8_t type = header->type;
        uint8_t length = header->length;
        if (type == APIC_TYPE_LOCAL_APIC) {
            const struct apic_local_apic *apic = (struct apic_local_apic *)p;
            if (apic->flags & APIC_PROCESSOR_ENABLED)
                cpu_nodes_num++;
        } else if (type == APIC_TYPE_IO_APIC) {
            apic_ioapic_num++;
        } else if (type == APIC_TYPE_INTR_OVERRIDE) {
            apic_irq_override_num++;
        }

        p += length;
    }

    // Allocate data structures to keep the ACPI information
    if (cpu_nodes_num) {
        cpu_nodes = kalloca(struct cpu_node, cpu_nodes_num);
        memset(cpu_nodes, 0, cpu_nodes_num * sizeof(struct cpu_node));
    }
    if (apic_ioapic_num)
        apic_ioapics = kalloca(struct apic_ioapic, apic_ioapic_num);
    if (apic_irq_override_num)
        apic_irq_overrides = kalloca(struct apic_irq_override, apic_irq_override_num);

    // Do the struct initialization
    struct cpu_node *cpu = cpu_nodes;
    struct apic_ioapic *ioapic = apic_ioapics;
    struct apic_irq_override *irq = apic_irq_overrides;
    p = (uint8_t *)(madt + 1);
    end = (uint8_t *)madt + madt->header.length;
    while (p < end) {
        struct apic_header *header = (struct apic_header *)p;
        uint8_t type = header->type;
        uint8_t length = header->length;

        if (type == APIC_TYPE_LOCAL_APIC) {
            const struct apic_local_apic *apic = (struct apic_local_apic *)p;
            printf("CPU found: ACPI_ID=%d APIC_ID=%d Flags=0x%x\n", apic->acpi_processor_id, apic->apic_id, apic->flags);

            if (apic->flags & APIC_PROCESSOR_ENABLED) {
                // found an active CPU
                cpu->apic_id = apic->apic_id;
                cpu++;
            }
        } else if (type == APIC_TYPE_IO_APIC) {
            const struct apic_io_apic *io_apic = (struct apic_io_apic *)p;

            ioapic->id = io_apic->io_apic_id;
            ioapic->addr = (void *)(uintptr_t)io_apic->io_apic_addr;
            ioapic->irq_base = io_apic->interrupt_base;

            ioapic++;
        } else if (type == APIC_TYPE_INTR_OVERRIDE) {
            const struct apic_intr_override *intr = (struct apic_intr_override *)p;
            printf("APIC interrupt override: bus=%d source=%d interrupt=%d flags=0x%x\n", intr->bus, intr->source, intr->interrupt,
                   intr->flags);

            irq->source = intr->source;
            irq->irq = intr->interrupt;

            irq++;
        } else {
            printf("Unknown APIC header type %d\n", type);
        }

        p += length;
    }
}

static void acpi_parse_hpet(const struct acpi_hpet *hpet) {
    PANIC_IF(g_hpet_addr, "HPET address is already initialized");
    g_hpet_addr = hpet->base_addr;

    printf("HPET comparators_num=%d addr=0x%lx number=%d counter_min=%d oem_attr=0x%x\n", hpet->comparators_num, hpet->base_addr,
           hpet->hpet_number, hpet->counter_min, hpet->oem_attr);
}

__mmio const struct acpi_mcfg_baseaddr_alloc *g_pci_ext_config;

static void acpi_parse_mcfg(const struct acpi_mcfg *mcfg) {
    size_t num = (mcfg->header.length - offsetof(struct acpi_mcfg, alloc)) / sizeof(struct acpi_mcfg_baseaddr_alloc);
    SHOUT_IF(num != 1, "It is expected exactly one MCFG struct"); // TODO: add support for multiple MCFG records
    if (num > 0 && mcfg->alloc[0].segment_group_num == 0) {
        g_pci_ext_config = mcfg->alloc;

        printf("Found MKFG signature, number of baseaddr is %zu. Base address = 0x%lx segment=%d start_bus=%d end_bus=%d\n", num,
               g_pci_ext_config->base_addr, g_pci_ext_config->segment_group_num, g_pci_ext_config->start_bus_num,
               g_pci_ext_config->end_bus_num);
    }
}

static void acpi_parse_dt(const struct acpi_header *dt) {
    if (dt->signature == FACP_SIGNATURE) {
        acpi_parse_facp((const struct acpi_fadt *)dt);
    } else if (dt->signature == APIC_SIGNATURE) {
        acpi_parse_apic((const struct acpi_madt *)dt);
    } else if (dt->signature == HPET_SIGNATURE) {
        acpi_parse_hpet((const struct acpi_hpet *)dt);
    } else if (dt->signature == MCFG_SIGNATURE) {
        acpi_parse_mcfg((const struct acpi_mcfg *)dt);
    } else {
        printf("Found ACPI header %p with unknown signature 0x%x (%.4s)\n", dt, dt->signature, (char *)&dt->signature);
    }
}

// rsdt structure is a header plus some number of uint32_t pointers
static void acpi_parse_rsdt(const struct acpi_header *header) {
    uint32_t *p = (uint32_t *)(header + 1);
    uint32_t *end = (uint32_t *)((uint8_t *)header + header->length);

    while (p < end) {
        acpi_parse_dt((const struct acpi_header *)(uintptr_t)*p);
        p++;
    }
}

// xsdt structure is a header plus some number of uint64_t pointers
static void acpi_parse_xsdt(const struct acpi_header *header) {
    uint64_t *p = (uint64_t *)(header + 1);
    uint64_t *end = (uint64_t *)((uint8_t *)header + header->length);

    while (p < end) {
        acpi_parse_dt((const struct acpi_header *)*p);
        p++;
    }
}

static bool acpi_parse_rsdp(const struct acpi_rsdp *rsdp) {
    // verify checksum
    printf("Parsing ACPI RSDP at address %p\n", rsdp);

    uint8_t sum = 0;
    for (int i = 0; i < 20; i++) {
        // Only first 20 byts are used for checksum
        sum += ((uint8_t *)rsdp)[i];
    }
    if (sum != 0) {
        printf("RSDP checksum failed\n");
        return false;
    }

    printf("ACPI data found, revision=%d OEM=%.6s\n", rsdp->revision, rsdp->oem);

    if (rsdp->revision >= 2 && rsdp->xsdt_addr) {
        acpi_parse_xsdt((const struct acpi_header *)rsdp->xsdt_addr);
    } else {
        acpi_parse_rsdt((const struct acpi_header *)(uintptr_t)rsdp->rsdt_addr);
    }

    return true;
}

static void *find_acpi_root(void) {
    // See http://wiki.osdev.org/RSDP for explanation
    for (uint64_t *p = (uint64_t *)0xe0000; p < (uint64_t *)0x100000; p++) {
        if (*p == RSDP_SIGNATURE)
            return p;
    }
    PANIC("RSDP root is not found at address 0x000e0000-0x00100000");
}

INIT_CODE void acpi_init(void *root) {
    if (root) {
        SHOUT_IF(*(uint64_t *)root != RSDP_SIGNATURE, "ACPI RSDP root has incorrect signature");
    } else {
        // 0xe0000 - 0xfffff
        page_table_set_bit(0xe0000, 0x20000, PAGE_PRESENT, PAGE_PRESENT);
        root = find_acpi_root();
    }

    bool success = acpi_parse_rsdp((const struct acpi_rsdp *)root);
    SHOUT_IF(!success, "Unable to parse RSDP root");
}
