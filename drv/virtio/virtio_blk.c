// SPDX-License-Identifier: MIT

#define VIRTIO_PCI_NO_LEGACY

#include "virtio_blk.h"
#include "blk.h"
#include "compiler.h"
#include "interrupt.h"
#include "kalloc.h"
#include "mem.h"
#include "mmu.h"
#include "pci.h"
#include "queue.h"
#include "virtio.h"
#include "virtio_config.h"
#include "virtio_pci.h"

#define VIRTIO_PCI_VENDOR 0x1af4
#define VIRTIO_PCI_DEVICE 0x1042
#define VIRTIO_PCI_DEVICE_LEGACY 0x1001

#define SECTOR_SIZE 512

struct virtio_blk_op_callback {
    uint16_t desc_idx; // index of the head descriptor that executes this block operation
    void *data;
    void *context;
    blk_op_callback callback;
    LIST_ENTRY(virtio_blk_op_callback) next;
};

struct virtio_blk_device {
    struct blk_device blk_dev;

    __mmio struct virtio_pci_common_cfg *cfg;
    __mmio uint8_t *isr_status; // It is needed only when INT#x is enabled (i.e. MSI is disabled)
    __mmio struct virtio_blk_config *device_cfg;

    struct virtq queue;
    LIST_HEAD(, virtio_blk_op_callback) callbacks;
};

static enum blk_op_status virtio_status_to_blk_status(uint8_t status) {
    switch (status) {
    case VIRTIO_BLK_S_OK:
        return BLK_OP_SUCCESS;
    case VIRTIO_BLK_S_IOERR:
        return BLK_OP_ERROR;
    case VIRTIO_BLK_S_UNSUPP:
        return BLK_OP_UNSUPPORTED;
    default:
        PANIC("Unknown virtio blk status %d", status);
    }
}

static void virtio_blk_handler(void *data) {
    // After data has been transmitted we need to return buffer back to the pool
    struct virtio_blk_device *dev = data;
    struct virtq *q = &dev->queue;

    while (q->last_used_idx != q->used->idx) {
        struct virtq_used_elem *e = &q->used->ring[q->last_used_idx % q->size];

        // The TX elemnent might contain multiple descriptors
        // we need to free() the memory buffers and returns descriptors itself to the unused list
        uint16_t head_idx = e->id;
        struct virtq_desc *desc = &q->desc[head_idx];

        // header
        kfree((struct virtio_blk_outhdr *)desc->addr);
        desc = &q->desc[desc->next];
        // nothing to do for area
        desc = &q->desc[desc->next];
        // status
        uint8_t status = virtio_status_to_blk_status(*(uint8_t *)desc->addr);
        kfree((uint8_t *)desc->addr);

        // Currently TX transaction has only 3 descriptors, so we are done iterating used elements
        // but in the future we might have more
        SHOUT_IF(desc->flags & VIRTQ_DESC_F_NEXT, "More descriptors is not expected");

        desc->next = q->unused_desc_idx;
        q->unused_desc_idx = head_idx;
        q->unused_desc_size += 3; // 1 descriptor is for header, another is for data area and 3rd is for status

        q->last_used_idx++;

        // Now find callback for this operation
        struct virtio_blk_op_callback *cb = NULL;
        LIST_FOREACH(cb, &dev->callbacks, next) {
            if (cb->desc_idx == head_idx) {
                LIST_REMOVE(cb, next);
                break;
            }
        }
        SHOUT_IF(cb->desc_idx != head_idx, "Did not find block operation callback");
        cb->callback(&dev->blk_dev, cb->data, status, cb->context);
        kfree(cb);
    }

    IFVV printf("Virtio blk TX completion handler\n");
}

static void virtio_blk_send(struct blk_device *blk, void *data, size_t data_size, size_t start_sector, bool write,
                            blk_op_callback on_complete, void *context) {
    SHOUT_IF(data_size % SECTOR_SIZE != 0, "Data size need to be multiple of sector size (%d)", SECTOR_SIZE);
    PANIC_IF(!on_complete, "A completion handler is required");

    struct virtio_blk_device *dev = container_of(blk, struct virtio_blk_device, blk_dev);
    struct virtq *q = &dev->queue;
    uint16_t need_descs_num = 3; // 1 for virtio header, 1 for the data buffer and 1 for status
    if (q->unused_desc_size < need_descs_num) {
        // let's check if we can free some space from completed transactions
        virtio_blk_handler(dev);

        if (q->unused_desc_size < need_descs_num) {
            // The queue is still full.
            // TODO: implement a dynamic list of transactions that user wants to send after the device queue become available
            PANIC("TX buffer overflow");
            return;
        }
    }

    uint16_t head_idx = q->unused_desc_idx;
    uint16_t desc_idx = head_idx;
    q->avail->ring[q->avail->idx % q->size] = desc_idx;

    // blk header
    struct virtio_blk_outhdr *hdr = kalloc(struct virtio_blk_outhdr);
    hdr->type = write ? VIRTIO_BLK_T_OUT : VIRTIO_BLK_T_IN;
    hdr->ioprio = 0;
    hdr->sector = start_sector;

    q->desc[desc_idx].addr = (uintptr_t)hdr;
    q->desc[desc_idx].len = sizeof(struct virtio_blk_outhdr);
    q->desc[desc_idx].flags = VIRTQ_DESC_F_NEXT;
    desc_idx = q->desc[desc_idx].next;

    // data
    q->desc[desc_idx].addr = (uintptr_t)data;
    q->desc[desc_idx].len = data_size;
    q->desc[desc_idx].flags = VIRTQ_DESC_F_NEXT | (write ? 0 : VIRTQ_DESC_F_WRITE);
    desc_idx = q->desc[desc_idx].next;

    // status
    uint8_t *status = kalloc(uint8_t);
    *status = VIRTIO_BLK_S_UNSUPP;
    q->desc[desc_idx].addr = (uintptr_t)status;
    q->desc[desc_idx].len = sizeof(uint8_t);
    q->desc[desc_idx].flags = VIRTQ_DESC_F_WRITE;
    desc_idx = q->desc[desc_idx].next;

    q->unused_desc_idx = desc_idx;
    q->unused_desc_size -= need_descs_num;

    // Append callback for this operation
    struct virtio_blk_op_callback *cb = kalloc(struct virtio_blk_op_callback);
    cb->desc_idx = head_idx;
    cb->data = data;
    cb->callback = on_complete;
    cb->context = context;
    LIST_INSERT_HEAD(&dev->callbacks, cb, next);

    wmb();
    q->avail->idx++;
    mb();
    *q->notify = q->index; // if flag VRING_USED_F_NO_NOTIFY is set
}

INIT_CODE static void virtio_blk_probe(struct pci_device_info *info) {
    struct virtio_blk_device *dev = kalloc(struct virtio_blk_device);
    memzero(dev);
    LIST_INIT(&dev->callbacks);

    SHOUT_IF(info->intr_type != PCI_INTR_MSIX, "Virtio BLK driver supports MSIX interrupt model only");
    SHOUT_IF(info->intr_msix.size < 1, "Size of MSIX vector is too small");

    struct pci_capability *cap = info->caps;
    __mmio void *notify_base = NULL;
    uint32_t notify_off_multiplier = 0;
    for (int i = 0; i < info->caps_num; i++, cap++) {
        if (cap->id == PCI_CAP_VENDOR_SPECIFIC) {
            // it is struct virtio_pci_cap
            uint8_t cfg_type = pci_read8(info->id, cap->offset + offsetof(struct virtio_pci_cap, cfg_type));
            uint8_t bar_id = pci_read8(info->id, cap->offset + offsetof(struct virtio_pci_cap, bar));
            uint32_t offset = pci_read32(info->id, cap->offset + offsetof(struct virtio_pci_cap, offset));

            struct pci_bar bar;
            pci_bar_get(&bar, info->id, bar_id);
            if (bar.flags & PCI_BAR_IO && cfg_type != VIRTIO_PCI_CAP_PCI_CFG) {
                printf("VirtioBlk (type=%d) IO space is not supported\n", cfg_type);
                return;
            }

            switch (cfg_type) {
            case VIRTIO_PCI_CAP_COMMON_CFG:
                dev->cfg = bar.address + offset;
                break;
            case VIRTIO_PCI_CAP_NOTIFY_CFG:
                notify_base = bar.address + offset;
                notify_off_multiplier = pci_read32(info->id, cap->offset + offsetof(struct virtio_pci_notify_cap, notify_off_multiplier));
                break;
            case VIRTIO_PCI_CAP_ISR_CFG:
                dev->isr_status = bar.address + offset;
                break;
            case VIRTIO_PCI_CAP_DEVICE_CFG:
                dev->device_cfg = bar.address + offset;
                break;
                // XXX: handle following types
                // VIRTIO_PCI_CAP_PCI_CFG
            default:
                continue; // to the next pci cap
            }

            page_table_set_bit((uintptr_t)bar.address, bar.size, PAGE_PRESENT | PAGE_WRITABLE | PAGE_CACHE_DISABLE,
                               PAGE_PRESENT | PAGE_WRITABLE | PAGE_CACHE_DISABLE);
        }
    }

    PANIC_IF(!dev->cfg, "VirtioBlk requires configuration capability");

    // Spec section 3.1, device initialization

    // reset device
    dev->cfg->device_status = 0;

    // ack
    dev->cfg->device_status |= VIRTIO_CONFIG_S_ACKNOWLEDGE | VIRTIO_CONFIG_S_DRIVER;

    // negotiate features
    uint64_t features = virtio_read_device_features(dev->cfg);
    printf("Device features are 0x%lx status %d\n", features, dev->cfg->device_status);
    uint64_t wanted_features = BIT(VIRTIO_F_VERSION_1);

    uint64_t missed_features = ~features & wanted_features;
    if (missed_features) {
        // some features we want are not supported by the device
        PANIC("VirtioBlk requested features 0x%lx are not supported by the device", missed_features);
        return;
    }
    virtio_write_driver_features(dev->cfg, wanted_features);
    dev->cfg->device_status |= VIRTIO_CONFIG_S_FEATURES_OK;

    if (!(dev->cfg->device_status & VIRTIO_CONFIG_S_FEATURES_OK)) {
        PANIC("virtio device did not accept our features");
        return;
    }

    // device initialization, section 5.1.5
    virtio_init_queue(dev->cfg, 0, &dev->queue, notify_base, notify_off_multiplier);

    printf("Receive virtq size is %d notify=%p\n", dev->queue.size, dev->queue.notify);
    virtio_queue_desc_link(&dev->queue);

    if (info->intr_type == PCI_INTR_MSIX) {
        pci_register_msix_irq(info, 0, virtio_blk_handler, dev);
    } else {
        // use legacy interruptions
        PANIC("VirtioBlk legacy interrupt handler is not implemented");
    }

    virtio_enable_queue(dev->cfg, &dev->queue);

    // the device is ready now
    dev->cfg->device_status |= VIRTIO_CONFIG_S_DRIVER_OK;

    __mmio struct virtio_blk_config *cfg = dev->device_cfg;
    printf("Found a new disk capacity=%lu, segment size=%u, segment max=%u block size=%u\n", cfg->capacity, cfg->size_max, cfg->seg_max,
           cfg->blk_size);

    dev->blk_dev.send = virtio_blk_send;
    blk_dev_register(&dev->blk_dev);
}

PCI_DEVICE(VIRTIO_PCI_VENDOR, VIRTIO_PCI_DEVICE, virtio_blk_probe);
// PCI_DEVICE(VIRTIO_PCI_VENDOR, VIRTIO_PCI_DEVICE_LEGACY, virtio_blk_probe);