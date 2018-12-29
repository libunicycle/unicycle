// SPDX-License-Identifier: MIT

#include "../acpi.h"
#include "acpi.h"
#include "apic.h"
#include "cpu.h"
#include "mmu.h"
#include "shout.h"
#include "stdio.h"
#include <limits.h>

#define ACPI_MAX_INIT_TABLES 16

#define GPE_HID_STRING "ACPI0006"
#define HID_LENGTH 8
#define GPE_CID_STRING "ACPI0006"
#define CID_LENGTH 8

uintptr_t g_apic_addr;
uintptr_t g_hpet_addr;
ACPI_TABLE_MADT *g_madt;

__mmio const struct acpi_mcfg_baseaddr_alloc *g_pci_ext_config;
BUILD_PANIC_IF(sizeof(struct acpi_mcfg_baseaddr_alloc) != sizeof(ACPI_MCFG_ALLOCATION), "ACPI MCFG allocation structs do not match");

// See ACPI specification section 5.8.1
static ACPI_STATUS acpi_set_interrupt_mode(void) {
    ACPI_OBJECT selector = {
        .Integer.Type = ACPI_TYPE_INTEGER,
        .Integer.Value = 1,
    };
    ACPI_OBJECT_LIST params = {
        .Count = 1,
        .Pointer = &selector,
    };
    return AcpiEvaluateObject(NULL, (char *)"\\_PIC", &params, NULL);
}

static int is_gpe_device(ACPI_HANDLE object) {
    ACPI_DEVICE_INFO *info = NULL;
    ACPI_STATUS acpi_status = AcpiGetObjectInfo(object, &info);
    if (acpi_status == AE_OK) {
        // These length fields count the trailing NUL.
        if ((info->Valid & ACPI_VALID_HID) && info->HardwareId.Length <= HID_LENGTH + 1) {
            if (!strncmp(info->HardwareId.String, GPE_HID_STRING, HID_LENGTH)) {
                return 1;
            }
        }
        if ((info->Valid & ACPI_VALID_CID) && info->CompatibleIdList.Count > 0) {
            ACPI_PNP_DEVICE_ID *id = &info->CompatibleIdList.Ids[0];
            if (!strncmp(id->String, GPE_CID_STRING, CID_LENGTH)) {
                return 1;
            }
        }
        ACPI_FREE(info);
    }
    return 0;
}

static ACPI_STATUS acpi_prw_walk(ACPI_HANDLE obj, UNUSED UINT32 level, UNUSED void *context, UNUSED void **out_value) {
    ACPI_BUFFER buffer = {
        // Request that the ACPI subsystem allocate the buffer
        .Length = ACPI_ALLOCATE_BUFFER,
        .Pointer = NULL,
    };
    ACPI_STATUS status = AcpiEvaluateObject(obj, (char *)"_PRW", NULL, &buffer);
    if (status != AE_OK) {
        return AE_OK; // Keep walking the tree
    }
    ACPI_OBJECT *prw_res = buffer.Pointer;

    // _PRW returns a package with >= 2 entries. The first entry indicates what type of
    // event it is. If it's a GPE event, the first entry is either an integer indicating
    // the bit within the FADT GPE enable register or it is a package containing a handle
    // to a GPE block device and the bit index on that device. There are other event
    // types with (handle, int) packages, so check that the handle is a GPE device by
    // checking against the CID/HID required by the ACPI spec.
    if (prw_res->Type != ACPI_TYPE_PACKAGE || prw_res->Package.Count < 2) {
        return AE_OK; // Keep walking the tree
    }

    ACPI_HANDLE gpe_block;
    UINT32 gpe_bit;
    ACPI_OBJECT *event_info = &prw_res->Package.Elements[0];
    if (event_info->Type == ACPI_TYPE_INTEGER) {
        gpe_block = NULL;
        gpe_bit = prw_res->Package.Elements[0].Integer.Value;
    } else if (event_info->Type == ACPI_TYPE_PACKAGE) {
        if (event_info->Package.Count != 2) {
            goto bailout;
        }
        ACPI_OBJECT *handle_obj = &event_info->Package.Elements[0];
        ACPI_OBJECT *gpe_num_obj = &event_info->Package.Elements[1];
        if (handle_obj->Type != ACPI_TYPE_LOCAL_REFERENCE || !is_gpe_device(handle_obj->Reference.Handle)) {
            goto bailout;
        }
        if (gpe_num_obj->Type != ACPI_TYPE_INTEGER) {
            goto bailout;
        }
        gpe_block = handle_obj->Reference.Handle;
        gpe_bit = gpe_num_obj->Integer.Value;
    } else {
        goto bailout;
    }
    if (AcpiSetupGpeForWake(obj, gpe_block, gpe_bit) != AE_OK) {
        printf("Acpi failed to setup wake GPE\n");
    }

bailout:
    ACPI_FREE_SIZE(buffer.Pointer, buffer.Length);

    return AE_OK; // We want to keep going even if we bailed out
}

static void init_apic_base_addr() {
    ACPI_TABLE_HEADER *header = NULL;

    // Initialize apic/ioapic base addresses
    ACPI_STATUS status = AcpiGetTable(ACPI_SIG_MADT, 1, &header);
    if (status != AE_OK) {
        PANIC("Could not find MADT table");
        return;
    }
    g_madt = (ACPI_TABLE_MADT *)header;
    g_apic_addr = g_madt->Address;

    uint8_t *start = (uint8_t *)(g_madt + 1);
    uint8_t *end = (uint8_t *)g_madt + g_madt->Header.Length;

    cpu_nodes_num = 0;
    apic_ioapic_num = 0;
    apic_irq_override_num = 0;

    uint8_t *p = start;
    while (p < end) {
        ACPI_SUBTABLE_HEADER *header = (ACPI_SUBTABLE_HEADER *)p;
        if (header->Type == ACPI_MADT_TYPE_LOCAL_APIC) {
            const ACPI_MADT_LOCAL_APIC *apic = (ACPI_MADT_LOCAL_APIC *)p;
            if (apic->LapicFlags & ACPI_MADT_ENABLED)
                cpu_nodes_num++;
        } else if (header->Type == ACPI_MADT_TYPE_IO_APIC) {
            apic_ioapic_num++;
        } else if (header->Type == ACPI_MADT_TYPE_INTERRUPT_OVERRIDE) {
            apic_irq_override_num++;
        }

        p += header->Length;
    }

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

    p = start;
    while (p < end) {
        ACPI_SUBTABLE_HEADER *header = (ACPI_SUBTABLE_HEADER *)p;
        if (header->Type == ACPI_MADT_TYPE_LOCAL_APIC) {
            const ACPI_MADT_LOCAL_APIC *apic = (ACPI_MADT_LOCAL_APIC *)p;
            printf("CPU found: ACPI_ID=%d APIC_ID=%d Flags=0x%x\n", apic->ProcessorId, apic->Id, apic->LapicFlags);

            if (apic->LapicFlags & ACPI_MADT_ENABLED) {
                // found an active CPU
                cpu->apic_id = apic->Id;
                cpu++;
            }
        } else if (header->Type == ACPI_MADT_TYPE_IO_APIC) {
            const ACPI_MADT_IO_APIC *io_apic = (ACPI_MADT_IO_APIC *)p;

            ioapic->id = io_apic->Id;
            ioapic->addr = (void *)(uintptr_t)io_apic->Address;
            ioapic->irq_base = io_apic->GlobalIrqBase;

            ioapic++;
        } else if (header->Type == ACPI_MADT_TYPE_INTERRUPT_OVERRIDE) {
            const ACPI_MADT_INTERRUPT_OVERRIDE *intr = (ACPI_MADT_INTERRUPT_OVERRIDE *)p;
            printf("APIC interrupt override: bus=%d source=%d interrupt=%d flags=0x%x\n", intr->Bus, intr->SourceIrq, intr->GlobalIrq,
                   intr->IntiFlags);

            irq->source = intr->SourceIrq;
            irq->irq = intr->GlobalIrq;

            irq++;
        }

        p += header->Length;
    }
}

static void init_pci_config_addr() {
    ACPI_TABLE_HEADER *header = NULL;
    ACPI_STATUS status = AcpiGetTable(ACPI_SIG_MCFG, 1, &header);
    if (status != AE_OK) {
        printf("WARN: Could not find MCFG table\n");
        return;
    }
    ACPI_TABLE_MCFG *mcfg = (ACPI_TABLE_MCFG *)header;
    size_t num = (mcfg->Header.Length - sizeof(ACPI_TABLE_MCFG)) / sizeof(ACPI_MCFG_ALLOCATION);
    SHOUT_IF(num != 1, "It is expected exactly one MCFG struct"); // TODO: add support for multiple MCFG records
    ACPI_MCFG_ALLOCATION *alloc = (ACPI_MCFG_ALLOCATION *)(mcfg + 1);
    if (num > 0 && alloc->PciSegment == 0) {
        g_pci_ext_config = (struct acpi_mcfg_baseaddr_alloc *)alloc;

        printf("Found MKFG signature, number of baseaddr is %zu. Base address = 0x%lx segment=%d start_bus=%d end_bus=%d\n", num,
               g_pci_ext_config->base_addr, g_pci_ext_config->segment_group_num, g_pci_ext_config->start_bus_num,
               g_pci_ext_config->end_bus_num);
    }
}

static void init_hpet_addr() {
    PANIC_IF(g_hpet_addr, "HPET address is already initialized");

    ACPI_TABLE_HEADER *header = NULL;
    ACPI_STATUS status = AcpiGetTable(ACPI_SIG_HPET, 1, &header);
    if (status != AE_OK) {
        PANIC("Could not find MCFG table");
        return;
    }
    ACPI_TABLE_HPET *hpet = (ACPI_TABLE_HPET *)header;
    g_hpet_addr = hpet->Address.Address;

    /*    printf("HPET comparators_num=%d addr=0x%lx number=%d counter_min=%d oem_attr=0x%x\n", hpet->comparators_num, hpet->base_addr,
               hpet->hpet_number, hpet->counter_min, hpet->oem_attr);
    */
}

// Unicycle provides pointer to acpi root but ACPICA uses its own way to find root table
void acpi_init(UNUSED void *acpi_root) {
    // TODO: maybe move 'setbit code' into AcpiOsMapMemory hook?
    page_table_set_bit(0xe0000, 0x20000, PAGE_PRESENT, PAGE_PRESENT);

    if (CONFIG_ACPI_DEBUG_OUTPUT) {
        AcpiDbgLevel = ACPI_LV_VERBOSITY3 | ACPI_LV_VERBOSE;
        AcpiDbgLayer = ACPI_TRACE_LAYER_ALL;
    }

    printf("Start parsing ACPI tables\n");
    ACPI_STATUS status = AcpiInitializeSubsystem();
    if (ACPI_FAILURE(status)) {
        PANIC("Could not initialize ACPI: %d", status);
        return;
    }

    status = AcpiInitializeTables(NULL, ACPI_MAX_INIT_TABLES, FALSE);
    if (ACPI_FAILURE(status)) {
        PANIC("Could not initialize ACPI tables: %d", status);
        return;
    }

    status = AcpiLoadTables();
    if (ACPI_FAILURE(status)) {
        PANIC("Could not load ACPI tables: %d", status);
        return;
    }

    status = AcpiEnableSubsystem(ACPI_FULL_INITIALIZATION);
    if (ACPI_FAILURE(status)) {
        PANIC("Could not enable ACPI: %d", status);
        return;
    }

    status = AcpiInitializeObjects(ACPI_FULL_INITIALIZATION);
    if (ACPI_FAILURE(status)) {
        PANIC("Could not initialize ACPI objects: %d", status);
        return;
    }

    status = acpi_set_interrupt_mode();
    if (status == AE_NOT_FOUND) {
        printf("WARN: Could not find ACPI IRQ mode switch\n");
    } else if (status != AE_OK) {
        PANIC("Failed to set APIC IRQ mode");
        return;
    }

    AcpiWalkNamespace(ACPI_TYPE_DEVICE, ACPI_ROOT_OBJECT, INT_MAX, acpi_prw_walk, NULL, NULL, NULL);

    status = AcpiUpdateAllGpes();
    if (status != AE_OK) {
        PANIC("Could not initialize ACPI GPEs");
        return;
    }

    init_apic_base_addr();
    init_pci_config_addr();
    init_hpet_addr();
}

uint8_t ioapic_remap_irq(uint8_t irq) {
    PANIC_IF(!g_madt, "Trying to remap APIC IRQ before APIC MADT initialized");

    uint8_t *p = (uint8_t *)(g_madt + 1);
    uint8_t *end = (uint8_t *)g_madt + g_madt->Header.Length;

    while (p < end) {
        ACPI_SUBTABLE_HEADER *header = (ACPI_SUBTABLE_HEADER *)p;

        if (header->Type == ACPI_MADT_TYPE_INTERRUPT_OVERRIDE) {
            const ACPI_MADT_INTERRUPT_OVERRIDE *intr = (ACPI_MADT_INTERRUPT_OVERRIDE *)p;
            if (intr->SourceIrq == irq)
                return intr->GlobalIrq;
        }

        p += header->Length;
    }
    return irq;
}
