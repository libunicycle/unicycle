// SPDX-License-Identifier: MIT

#include "pci.h"
#include "acpi.h"
#include "config.h"
#include "cpu.h"
#include "interrupt.h"
#include "mem.h"
#include "mmio.h"
#include "mmu.h"
#include "shout.h"
#include "stdio.h"
#include <stdint.h>

static inline uint32_t pci_id(uint8_t bus /* 8 bits */, uint8_t device /* 5 bits */, uint8_t function /* 3 bits */) {
    return (bus & 0xff) << 16 | (device & 0x1f) << 11 | (function & 0x7) << 8;
}

static inline uint8_t pci_id_to_bus(uint32_t id) { return (id >> 16) & 0xff; }

uint32_t pci_address(uint32_t id, uint8_t offset) { return PCI_ADDRESS_EN | id | offset; }

uint32_t pci_read32_addr(uint32_t addr) {
    outd(PCI_CONFIG_ADDRESS, addr);
    return ind(PCI_CONFIG_DATA);
}

uint32_t pci_read32(uint32_t id, uint8_t offset) {
    uint32_t addr = pci_address(id, offset);
    return pci_read32_addr(addr);
}

void pci_write32_addr(uint32_t addr, uint32_t data) {
    outd(PCI_CONFIG_ADDRESS, addr);
    outd(PCI_CONFIG_DATA, data);
}

void pci_write32(uint32_t id, uint8_t offset, uint32_t data) {
    uint32_t addr = pci_address(id, offset);
    pci_write32_addr(addr, data);
}

uint16_t pci_read16_addr(uint32_t addr) {
    outd(PCI_CONFIG_ADDRESS, addr);
    return inw(PCI_CONFIG_DATA + (addr & 2));
}

uint16_t pci_read16(uint32_t id, uint8_t offset) {
    uint32_t addr = pci_address(id, offset);
    return pci_read16_addr(addr);
}

void pci_write16_addr(uint32_t addr, uint16_t data) {
    outd(PCI_CONFIG_ADDRESS, addr);
    outw(PCI_CONFIG_DATA + (addr & 2), data);
}

void pci_write16(uint32_t id, uint8_t offset, uint16_t data) {
    uint32_t addr = pci_address(id, offset);
    pci_write16_addr(addr, data);
}

uint8_t pci_read8_addr(uint32_t addr) {
    outd(PCI_CONFIG_ADDRESS, addr);
    return inb(PCI_CONFIG_DATA + (addr & 3));
}

uint8_t pci_read8(uint32_t id, uint8_t offset) {
    uint32_t addr = pci_address(id, offset);
    return pci_read8_addr(addr);
}

void pci_write8_addr(uint32_t addr, uint8_t data) {
    outd(PCI_CONFIG_ADDRESS, addr);
    outb(PCI_CONFIG_DATA + (addr & 3), data);
}

void pci_write8(uint32_t id, uint8_t offset, uint8_t data) {
    uint32_t addr = pci_address(id, offset);
    pci_write8_addr(addr, data);
}

static inline void pci_bar_read(uint32_t id, uint32_t index, uint32_t *addr, uint32_t *mask) {
    uint8_t offset = PCI_CONFIG_BAR0 + index * sizeof(uint32_t); // each BAR is 32bit

    *addr = pci_read32(id, offset);

    // to find out size we need to write all 1's to the bar, read value again and restore original one
    pci_write32(id, offset, ~0x0);
    *mask = pci_read32(id, offset);
    pci_write32(id, offset, *addr);
}

void pci_bar_get(struct pci_bar *bar, uint32_t id, uint32_t index) {
    uint32_t addr_low, mask_low;
    pci_bar_read(id, index, &addr_low, &mask_low);

    if (addr_low & PCI_BAR_IO) {
        bar->port = addr_low & ~0x3;
        bar->size = ~(mask_low & ~0x3) + 1;
        bar->flags = addr_low & 0x3;
    } else if (addr_low & PCI_BAR_64BIT) {
        uint32_t addr_high, mask_high;
        pci_bar_read(id, index + 1, &addr_high, &mask_high);
        bar->address = (void *)((uintptr_t)addr_high << 32 | (addr_low & ~0xf));
        bar->size = ~((uint64_t)mask_high << 32 | (mask_low & ~0xf)) + 1;
        bar->flags = addr_low & 0xf;
    } else {
        // 32bit addr space
        bar->address = (void *)(uintptr_t)(addr_low & ~0xf);
        bar->size = ~(mask_low & ~0xf) + 1;
        bar->flags = addr_low & 0xf;
    }
}

static inline void pci_read_caps(struct pci_device_info *dev_info) {
    uint8_t offset = pci_read8(dev_info->id, PCI_CONFIG_CAPABILITIES);

    while (offset && dev_info->caps_num < PCI_DEVICE_CAPS_MAX) {
        struct pci_capability *cap = &dev_info->caps[dev_info->caps_num++];

        uint8_t id = pci_read8(dev_info->id, offset + PCI_CAPLIST_ID);
        SHOUT_IF(id >= PCI_CAP_NUM, "Capability ID %d is out of range", id);
        uint8_t new_offset = pci_read8(dev_info->id, offset + PCI_CAPLIST_NEXT);

        cap->id = id;
        cap->offset = offset;

        offset = new_offset & ~0x3; // lower 2 bits have to be zeros
    }

    SHOUT_IF(offset && dev_info->caps_num >= PCI_DEVICE_CAPS_MAX, "Too many capabilities added to the device");
}

static inline void pci_read_ext_caps(struct pci_device_info *dev_info) {
    if (!dev_info->extended_config_space)
        return;

    // location for the first ext capability is 0x100
    __mmio void *addr = dev_info->extended_config_space + 0x100;

    union {
        struct pci_ext_capability cap;
        uint32_t value;
    } cap_ptr;

    while (true) {
        cap_ptr.value = MMIO32(addr);

        // capability list ends with element that has all fields set to 0
        // but some boards use -1 as a final cap element
        if (cap_ptr.value == 0 || cap_ptr.value == ~(uint32_t)0)
            break;

        dev_info->ext_caps[dev_info->ext_caps_num++] = cap_ptr.cap;
        addr = dev_info->extended_config_space + cap_ptr.cap.offset;
    }

    if (dev_info->ext_caps_num)
        printf("%d extended capabilities was found\n", dev_info->ext_caps_num++);
}

// Returns first capability offset by given capability id
static inline uint8_t pci_cap_get(struct pci_device_info *dev_info, uint8_t id) {
    uint8_t num = dev_info->caps_num;
    for (int i = 0; i < num; i++) {
        if (dev_info->caps[i].id == id)
            return dev_info->caps[i].offset;
    }
    return 0;
}

void pci_msi_addr(uint8_t vector, uint32_t *addr, uint16_t *value) {
    // base | destination | redirect hint | phisical mode
    *addr = (0xfee << 20) | (0xff << 12) | (1 << 3) | (1 << 2); // lowest priority
    // edge trigger mode | fixed delivery mode | vector
    *value = (0 << 15) | (0 << 8) | vector;
}

UNUSED static void pci_msix_mask(struct pci_device_info *dev, size_t vector) {
    __mmio struct pci_msix_table *entry = dev->intr_msix.table + vector;
    entry->control |= PCI_MSIX_ENTRY_MASK;
}

static void pci_msix_unmask(struct pci_device_info *dev, size_t vector) {
    __mmio struct pci_msix_table *entry = dev->intr_msix.table + vector;
    entry->control &= ~PCI_MSIX_ENTRY_MASK;
}

UNUSED static void pci_msix_reset_pending(struct pci_device_info *dev, size_t vector) {
    __mmio uint64_t *pba = dev->intr_msix.pba;
    pba[vector / 64] &= ~BIT(vector % 64);
}

void pci_register_msix_irq(struct pci_device_info *dev, uint8_t msix_intr, event_handler_t handler, void *data) {
    uint8_t vector = interrupt_register(handler, data);
    SHOUT_IF(vector <= 0x0f || vector == 0xff, "Incorrect vector number");

    uint32_t addr;
    uint16_t val;
    pci_msi_addr(vector, &addr, &val);

    __mmio struct pci_msix_table *entry = dev->intr_msix.table + msix_intr;
    entry->addr_low = addr;
    entry->addr_high = 0;
    entry->msg_data = val;

    pci_msix_unmask(dev, msix_intr);
}

void pci_register_msi_irq(struct pci_device_info *dev, uint8_t msi_intr, event_handler_t handler, void *data) {
    if (!dev->intr_msi.irq_block_start) {
        int irq_start = interrupt_reserve(dev->intr_msi.size);
        if (irq_start == -1) {
            printf("No IRQ available for MSI");
            return;
        }
        dev->intr_msi.irq_block_start = irq_start;
    }
    uint8_t vector = dev->intr_msi.irq_block_start + msi_intr;
    interrupt_register_with_vector(vector, handler, data);

    uint32_t addr;
    uint16_t val;
    pci_msi_addr(vector, &addr, &val);

    pci_write32_addr(dev->intr_msi.cap_addr + 4, addr);

    int msg_data_addr = 0x8;
    if (dev->intr_msi.msg_control & PCI_MSI_64BIT) {
        msg_data_addr += 4;
        pci_write32_addr(dev->intr_msi.cap_addr + 0x8, 0);
    }
    pci_write32_addr(dev->intr_msi.cap_addr + msg_data_addr, val);

    // Unmask the vector
    if (dev->intr_msi.msg_control & PCI_MSI_PERVECTOR_MASKING) {
        int mask_addr = dev->intr_msi.msg_control & PCI_MSI_64BIT ? 0x10 : 0xc;
        uint32_t mask = pci_read32_addr(dev->intr_msi.cap_addr + mask_addr);
        mask &= ~BIT(msi_intr);
        pci_write32_addr(dev->intr_msi.cap_addr + mask_addr, mask);
    }
}

static inline void pci_bus_scan(int bus) {
    IFD printf("Scanning PCI bus 0x%x\n", bus);
    for (uint8_t dev = 0; dev < 32; dev++) {
        uint8_t header_type = pci_read8(pci_id(bus, dev, 0), PCI_CONFIG_HEADER_TYPE);
        uint8_t func_count = header_type & PCI_TYPE_MULTIFUNC ? 8 : 1;
        // uint8_t type = header_type & 0x7f;
        for (uint8_t func = 0; func < func_count; func++) {
            uint32_t id = pci_id(bus, dev, func);
            struct pci_device_info dev_info;
            memzero(&dev_info);

            dev_info.vendor_id = pci_read16(id, PCI_CONFIG_VENDOR_ID);

            // Skip invalid id
            if (dev_info.vendor_id == PCI_INVALID_VENDOR_ID) {
                // If first function does not exist then no device connected
                // Valid functions might have gaps e.g. 0,3,6
                if (func == 0)
                    break;
                continue;
            }

            dev_info.id = id;
            dev_info.device_id = pci_read16(id, PCI_CONFIG_DEVICE_ID);
            dev_info.prog_if = pci_read8(id, PCI_CONFIG_PROG_IF);
            dev_info.class = pci_read8(id, PCI_CONFIG_CLASS);
            dev_info.subclass = pci_read8(id, PCI_CONFIG_SUBCLASS);
            dev_info.revision = pci_read8(id, PCI_CONFIG_REVISION_ID);
            dev_info.extended_config_space = pci_extended_config_space(id);

            // PCI device list https://raw.githubusercontent.com/pciutils/pciids/master/pci.ids
            printf("PCI device %02x:%02x:%d 0x%x 0x%04x/0x%04x\n", bus, dev, func, dev_info.class, dev_info.vendor_id, dev_info.device_id);

            uint16_t cmd = pci_read16(id, PCI_CONFIG_COMMAND);
            cmd |= PCI_COMMAND_IO | PCI_COMMAND_MEMORY;
            pci_write16(id, PCI_CONFIG_COMMAND, cmd);

            uint16_t status = pci_read16(id, PCI_CONFIG_STATUS);
            if (status & PCI_STATUS_CAP) {
                pci_read_caps(&dev_info);
            }
            pci_read_ext_caps(&dev_info);

            uint8_t msi_cap, msix_cap;
            if ((msix_cap = pci_cap_get(&dev_info, PCI_CAP_MSIX))) {
                uint16_t msg_control = pci_read16(id, msix_cap + 2);
                SHOUT_IF(msg_control & PCI_MSIX_ENABLE, "MSI-X is already enabled");
                pci_write16(id, msix_cap + 2, msg_control | PCI_MSIX_FUNCTION_MASK);

                uint32_t table_offset = pci_read32(id, msix_cap + 4);
                uint32_t pba_offset = pci_read32(id, msix_cap + 8);

                dev_info.intr_msix.size = (msg_control & PCI_MSIX_TBL_SIZE_MASK) + 1;
                SHOUT_IF(dev_info.intr_msix.size > 32, "Too big MSI-X vector");

                struct pci_bar bar;

                pci_bar_get(&bar, id, table_offset & PCI_MSIX_BIR_MASK);
                dev_info.intr_msix.table = bar.address + (table_offset & ~PCI_MSIX_BIR_MASK);
                page_table_set_bit((uintptr_t)bar.address, bar.size, PAGE_PRESENT | PAGE_WRITABLE | PAGE_CACHE_DISABLE,
                                   PAGE_PRESENT | PAGE_WRITABLE | PAGE_CACHE_DISABLE);
                // SHOUT_IF((table_offset & ~PCI_MSIX_BIR_MASK) == 0, "Incorrect MSIX table offset");

                pci_bar_get(&bar, id, pba_offset & PCI_MSIX_BIR_MASK);
                dev_info.intr_msix.pba = bar.address + (pba_offset & ~PCI_MSIX_BIR_MASK);
                page_table_set_bit((uintptr_t)bar.address, bar.size, PAGE_PRESENT | PAGE_WRITABLE | PAGE_CACHE_DISABLE,
                                   PAGE_PRESENT | PAGE_WRITABLE | PAGE_CACHE_DISABLE);

                // SHOUT_IF((pba_offset & ~PCI_MSIX_BIR_MASK) == 0, "Incorrect MSIX pba offset");

                IFD printf("MSIX size=%d table=%p pba=%p\n", dev_info.intr_msix.size, dev_info.intr_msix.table, dev_info.intr_msix.pba);

                // disable legacy interrupts
                cmd |= PCI_COMMAND_INTR_DISABLE;
                pci_write16(id, PCI_CONFIG_COMMAND, cmd);

                // Enable MSI-X interrupts
                pci_write16(id, msix_cap + 2, msg_control | PCI_MSIX_ENABLE);

                dev_info.intr_type = PCI_INTR_MSIX;
            } else if ((msi_cap = pci_cap_get(&dev_info, PCI_CAP_MSI))) {
                uint16_t msg_control = pci_read16(id, msi_cap + 2);
                SHOUT_IF(msg_control & PCI_MSI_ENABLE, "MSI is already enabled");

                if (msg_control & PCI_MSI_MULTIPLE_MSG_CAPABLE) {
                    // The MSI multiple msg value is power of two
                    uint16_t power = (msg_control & PCI_MSI_MULTIPLE_MSG_CAPABLE) >> PCI_MSI_MULTIPLE_MSG_CAPABLE_SFT;
                    if (power > 5) {
                        printf("Device requests %d MSI vectors that is larger than supported (32)", 1 << power);
                        // 32 msi vectors is max per specification
                        power = 5;
                    }
                    dev_info.intr_msi.size = 1 << power;
                } else {
                    dev_info.intr_msi.size = 1;
                }

                dev_info.intr_msi.msg_control = msg_control;
                dev_info.intr_msi.cap_addr = pci_address(id, msi_cap);

                IFD printf("MSI size=%d\n", dev_info.intr_msi.size);

                // disable legacy interrupts
                cmd |= PCI_COMMAND_INTR_DISABLE;
                pci_write16(id, PCI_CONFIG_COMMAND, cmd);

                // Enable MSI interrupts
                pci_write16(id, msi_cap + 2, msg_control | PCI_MSI_ENABLE);

                dev_info.intr_type = PCI_INTR_MSI;
            } else {
                // legacy interrupts
                dev_info.intr_legacy.line = pci_read8(id, PCI_CONFIG_INTR_LINE);
                dev_info.intr_legacy.pin = pci_read8(id, PCI_CONFIG_INTR_PIN);

                dev_info.intr_type = PCI_INTR_LEGACY;
            }

            extern struct pci_device __drivers_pci_start, __drivers_pci_end;
            for (struct pci_device *drv = &__drivers_pci_start; drv < &__drivers_pci_end; drv++) {
                if (drv->vendor_id == dev_info.vendor_id && drv->device_id == dev_info.device_id) {
                    drv->probe(&dev_info);
                    break;
                }
            }

            if (dev_info.class == PCI_CLASS_BRIDGE && dev_info.subclass == PCI_SUBCLASS_PCI2PCI) {
                // XXX: how PCI_CLASS_BRIDGE differs from PCI_TYPE_BRIDGE_PCI ??
                uint8_t subbus = pci_read8(id, PCI_CONFIG_SECONDARY_BUS);
                pci_bus_scan(subbus);
            }
        }
    }
}

__mmio void *pci_extended_config_space(uint32_t id) {
    if (!g_pci_ext_config)
        return NULL;

    uint8_t bus = pci_id_to_bus(id);

    if (g_pci_ext_config->start_bus_num > bus || g_pci_ext_config->end_bus_num < bus)
        return NULL;

    return (void *)g_pci_ext_config->base_addr + (id << 4); // space for extended config is 2^8 bigger then for legacy config
}

void pci_enable_bus_master(struct pci_device_info *dev, bool enable) {
    uint16_t cmd = pci_read16(dev->id, PCI_CONFIG_COMMAND);

    if (enable)
        cmd |= PCI_COMMAND_BUS_MASTER;
    else
        cmd &= ~PCI_COMMAND_BUS_MASTER;

    pci_write16(dev->id, PCI_CONFIG_COMMAND, cmd);
};

void pci_init(void) {
    if (IS_ENABLED(CONFIG_DEBUG)) {
        printf("Following PCI devices are registered:\n");
        extern struct pci_device __drivers_pci_start, __drivers_pci_end;
        for (struct pci_device *drv = &__drivers_pci_start; drv < &__drivers_pci_end; drv++) {
            printf("  0x%04x/0x%04x\n", drv->vendor_id, drv->device_id);
        }
    }
    pci_bus_scan(0);
}
