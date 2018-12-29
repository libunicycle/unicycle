// SPDX-License-Identifier: MIT

#pragma once

#include "compiler.h"
#include "event.h"
#include "shout.h"
#include "x86.h"
#include <stddef.h>
#include <stdint.h>

#define PCI_INVALID_VENDOR_ID 0xffff

#define PCI_CONFIG_ADDRESS 0xcf8
#define PCI_CONFIG_DATA 0xcfc

#define PCI_ADDRESS_EN BIT(31)

// PCI Config offsets
#define PCI_CONFIG_VENDOR_ID 0x0
#define PCI_CONFIG_DEVICE_ID 0x2
#define PCI_CONFIG_COMMAND 0x4
#define PCI_CONFIG_STATUS 0x6
#define PCI_CONFIG_REVISION_ID 0x8
#define PCI_CONFIG_PROG_IF 0x9
#define PCI_CONFIG_SUBCLASS 0xa
#define PCI_CONFIG_CLASS 0xb
#define PCI_CONFIG_CACHE_LINE_SIZE 0xc
#define PCI_CONFIG_LATENCY_TIMER 0xd
#define PCI_CONFIG_HEADER_TYPE 0xe
#define PCI_CONFIG_BIST 0xf
#define PCI_CONFIG_CAPABILITIES 0x34

// Type is 00
#define PCI_CONFIG_BAR0 0x10
#define PCI_CONFIG_BAR1 0x14
#define PCI_CONFIG_BAR2 0x18
#define PCI_CONFIG_BAR3 0x1c
#define PCI_CONFIG_BAR4 0x20
#define PCI_CONFIG_BAR5 0x24
#define PCI_CONFIG_INTR_LINE 0x3c
#define PCI_CONFIG_INTR_PIN 0x3d

// Type is 02
#define PCI_CONFIG_SECONDARY_BUS 0x19
#define PCI_CONFIG_CB_CAPABILITIES 0x14
// ...

// PCI_CONFIG_HEADER_TYPE
#define PCI_TYPE_NORMAL 0x0
#define PCI_TYPE_BRIDGE_PCI 0x1
#define PCI_TYPE_BRIDGE_CARDBUS 0x2
#define PCI_TYPE_MULTIFUNC BIT(7)

#define PCI_CLASS_UNKNOWN 0x0
#define PCI_CLASS_STORAGE 0x1
#define PCI_CLASS_NETWORK 0x2
#define PCI_CLASS_DISPLAY 0x3
#define PCI_CLASS_MULTIMEDIA 0x4
#define PCI_CLASS_MEMORY 0x5
#define PCI_CLASS_BRIDGE 0x6
#define PCI_CLASS_SIMPLE_COMMUNICATION 0x7
#define PCI_CLASS_BASE_PERIPHERALS 0x8
#define PCI_CLASS_INPUT 0x9
#define PCI_CLASS_DOCKING 0xa
#define PCI_CLASS_PROCESSOR 0xb
#define PCI_CLASS_SERIAL_BUS 0xc
#define PCI_CLASS_WIRELESS 0xd
#define PCI_CLASS_INTELLIGENT_IO 0xe
#define PCI_CLASS_SATELLITE_COMMUNICATION 0xf
#define PCI_CLASS_ENCRYPTION 0x10
#define PCI_CLASS_DSP 0x11

// Subclasses, see http://wiki.osdev.org/PCI#Class_Codes

// PCI_CLASS_BRIDGE
#define PCI_SUBCLASS_PCI2PCI 0x4

// PCI_CONFIG_COMMAND
#define PCI_COMMAND_IO BIT(0)
#define PCI_COMMAND_MEMORY BIT(1)
#define PCI_COMMAND_BUS_MASTER BIT(2)
#define PCI_COMMAND_PARITY_ERROR BIT(6)
#define PCI_COMMAND_INTR_DISABLE BIT(10)

// PCI_CONFIG_STATUS
#define PCI_STATUS_INTR BIT(3)
#define PCI_STATUS_CAP BIT(4)

#define PCI_CAPLIST_ID 0
#define PCI_CAPLIST_NEXT 1

#define PCI_CAP_POWER_MANAGEMENT 0x1
#define PCI_CAP_AGP 0x2
#define PCI_CAP_VPD 0x3
#define PCI_CAP_SLOT_ID 0x4
#define PCI_CAP_MSI 0x5
#define PCI_CAP_HOT_SWAP 0x6
#define PCI_CAP_PCIX 0x7
#define PCI_CAP_HYPER_TRANSPORT 0x8
#define PCI_CAP_VENDOR_SPECIFIC 0x9
#define PCI_CAP_DEBUG_PORT 0xa
#define PCI_CAP_RES_CONTROL 0xb
#define PCI_CAP_HOT_PLUG 0xc
#define PCI_CAP_BRIDGE_VENDOR_ID 0xd
#define PCI_CAP_AGP_8X 0xe
#define PCI_CAP_SECURE_DEVICE 0xf
#define PCI_CAP_PCIE 0x10
#define PCI_CAP_MSIX 0x11
#define PCI_CAP_SATA 0x12
#define PCI_CAP_ADVANCED_FEATURES 0x13
#define PCI_CAP_ENHANCED_ALLOC 0x14

#define PCI_CAP_NUM 0x15 // number of defined PCI caps

struct pci_capability {
    uint8_t id;
    uint8_t offset;
};

struct PACKED pci_ext_capability {
    uint16_t id;
    uint8_t version : 4;
    uint16_t offset : 12;
};
BUILD_PANIC_IF(sizeof(struct pci_ext_capability) != 4);

// MSI Capability
#define PCI_MSI_ENABLE BIT(0)
#define PCI_MSI_64BIT BIT(7)
#define PCI_MSI_PERVECTOR_MASKING BIT(8)

#define PCI_MSI_MULTIPLE_MSG_CAPABLE_SFT 1
#define PCI_MSI_MULTIPLE_MSG_ENABLE_SFT 4

#define PCI_MSI_MULTIPLE_MSG_CAPABLE (0x7 << PCI_MSI_MULTIPLE_MSG_CAPABLE_SFT)
#define PCI_MSI_MULTIPLE_MSG_ENABLE (0x7 << PCI_MSI_MULTIPLE_MSG_ENABLE_SFT)

// MSI-X capability
#define PCI_DEVICE_CAPS_MAX 10

#define PCI_MSIX_FUNCTION_MASK BIT(14)
#define PCI_MSIX_ENABLE BIT(15)

#define PCI_MSIX_BIR_MASK 0x7
#define PCI_MSIX_TBL_SIZE_MASK 0x7ff

#define PCI_MSIX_ENTRY_MASK BIT(0)

enum pci_intr_type {
    PCI_INTR_NONE = 0,
    PCI_INTR_LEGACY,
    PCI_INTR_MSI,
    PCI_INTR_MSIX,
};

struct pci_interrupt_legacy {
    uint8_t line;
    uint8_t pin;
};

struct pci_interrupt_msi {
    uint16_t size; // number of vectors available
    uint32_t cap_addr;
    uint16_t msg_control;
    // MSI requests IRQ by block of power-of-2, this field points to the first IRQ # of that block or 0 if the block was not requested yet
    uint8_t irq_block_start;
};

struct PACKED pci_msix_table {
    uint32_t addr_low;
    uint32_t addr_high;
    uint32_t msg_data;
    uint32_t control;
};

struct pci_interrupt_msix {
    uint16_t size; // number of vectors available
    __mmio struct pci_msix_table *table;
    __mmio uint64_t *pba; // pending bit array
};

struct pci_device_info {
    uint32_t id; // bus, dev, func
    uint16_t vendor_id;
    uint16_t device_id;
    uint8_t prog_if;
    uint8_t class;
    uint8_t subclass;
    uint8_t revision;

    enum pci_intr_type intr_type;
    union {
        struct pci_interrupt_legacy intr_legacy;
        struct pci_interrupt_msi intr_msi;
        struct pci_interrupt_msix intr_msix;
    };

    __mmio void *extended_config_space;
    // TODO: convert it to an SLIST
    uint8_t caps_num;
    struct pci_capability caps[PCI_DEVICE_CAPS_MAX];
    uint8_t ext_caps_num;
    struct pci_ext_capability ext_caps[PCI_DEVICE_CAPS_MAX];
};

struct pci_device {
    uint16_t vendor_id;
    uint16_t device_id;
    void (*probe)(struct pci_device_info *);
};

void pci_init(void);

#define PCI_DEVICE(vendor, device, probe_fn)                                                       \
    USED SECTION(".drivers.pci") struct pci_device pci_device_##vendor##_##device##_##probe_fn = { \
        .vendor_id = vendor,                                                                       \
        .device_id = device,                                                                       \
        .probe = probe_fn,                                                                         \
    };

#define PCI_BAR_IO 0x1
#define PCI_BAR_64BIT 0x4
#define PCI_BAR_PREFETCH 0x8

struct pci_bar {
    union {
        __mmio void *address; // memory space
        uint16_t port;        // IO space
    };
    uint64_t size;
    uint8_t flags;
};

void pci_bar_get(struct pci_bar *bar, uint32_t id, uint32_t index);
void pci_enable_bus_master(struct pci_device_info *dev, bool enable);

__mmio void *pci_extended_config_space(uint32_t id);

void pci_register_msi_irq(struct pci_device_info *dev, uint8_t msi_intr, event_handler_t handler, void *data);
void pci_register_msix_irq(struct pci_device_info *dev, uint8_t msix_intr, event_handler_t handler, void *data);

void pci_msi_addr(uint8_t vector, uint32_t *addr, uint16_t *value);

uint8_t pci_read8(uint32_t id, uint8_t offset);
uint16_t pci_read16(uint32_t id, uint8_t offset);
uint32_t pci_read32(uint32_t id, uint8_t offset);