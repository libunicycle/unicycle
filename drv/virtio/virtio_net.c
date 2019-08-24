// SPDX-License-Identifier: MIT

#define VIRTIO_PCI_NO_LEGACY

#include "virtio_net.h"
#include "buddy.h"
#include "buffer.h"
#include "interrupt.h"
#include "kalloc.h"
#include "mem.h"
#include "mmu.h"
#include "net/eth.h"
#include "pci.h"
#include "shout.h"
#include "stdio.h"
#include "virtio.h"
#include "virtio_config.h"
#include "virtio_pci.h"
#include "virtio_virtq.h"
#include "x86.h"
#include <stdbool.h>
#include <stddef.h>

#define VIRTIO_PCI_VENDOR 0x1af4
#define VIRTIO_PCI_DEVICE 0x1041
#define VIRTIO_PCI_DEVICE_LEGACY 0x1000

#define RX_BUFFER_SIZE 2048 // keep it the same as BUFFER_NET_SIZE
#define BUFFER_ALIGNMENT 64 // It is unclear if spec says what alignment the buffer should have, let's set to cacheline size for now

struct virtio_net_device {
    struct eth_device eth_dev;

    __mmio struct virtio_pci_common_cfg *cfg;
    __mmio uint8_t *isr_status; // It is needed only when INT#x is enabled (i.e. MSI is disabled)
    __mmio struct virtio_net_config *device_cfg;

    struct virtq rx_q;
    struct virtq tx_q;
    struct virtq cmd_q;

    uint16_t pci_id;
};

static void virtio_init_rx_buffer(struct virtq *queue) {
    // Note that packages are transmitted/received in gather/scattered list,
    // the first descriptor points to header of type virtio_net_hdr_v1 and the second
    // descriptor points to the data buffer area. We are going to reuse a block
    // for both header and data.
    size_t buffers_num = queue->size / 2;

    struct virtq_desc *desc = queue->desc;
    struct virtio_net_hdr_v1 *hdrs = kalloc_size(sizeof(struct virtio_net_hdr_v1) * buffers_num);
    for (uint16_t i = 0; i < buffers_num; i++) {
        // desc for header
        desc->addr = (uintptr_t)hdrs;
        desc->len = sizeof(struct virtio_net_hdr_v1);
        desc->flags = VIRTQ_DESC_F_WRITE | VIRTQ_DESC_F_NEXT;
        desc->next = 2 * i + 1;
        hdrs++;
        desc++;

        // desc for data
        desc->addr = (uintptr_t)kalloc_size_flags(RX_BUFFER_SIZE, KALLOC_ASAN_SKIP_INIT);
        desc->len = RX_BUFFER_SIZE;
        desc->flags = VIRTQ_DESC_F_WRITE;
        desc->next = 0;
        desc++;

        queue->avail->ring[i] = 2 * i;
    }

    wmb();
    queue->avail->idx = buffers_num;

    // notify the device that we modified RX queue
    if (!(queue->used->flags & VIRTQ_USED_F_NO_NOTIFY)) {
        mb();
        *queue->notify = queue->index;
    }
}

static void virtio_net_rx_handler(void *data) {
    struct virtio_net_device *dev = data;

    // dequeue a received buffer
    struct virtq *q = &dev->rx_q;
    bool packages_to_process = q->last_used_idx != q->used->idx;
    while (q->last_used_idx != q->used->idx) {
        struct virtq_used_elem *e = &q->used->ring[q->last_used_idx % q->size];

        // virtio_net header and payload descriptors follow each other
        struct virtq_desc *hdr_desc = &q->desc[e->id];
        struct virtq_desc *payload_desc = hdr_desc + 1;
        SHOUT_IF(hdr_desc->next != e->id + 1, "virtio descriptor chain has chainged");

        // struct virtio_net_hdr_v1 *hdr = (void *)hdr_desc->addr;

        buffer_t *buff = kalloc(buffer_t);
        buff->area = (void *)payload_desc->addr;
        buff->pos = buff->area;
        buff->area_size = RX_BUFFER_SIZE;
        buff->data_size = e->len - sizeof(struct virtio_net_hdr_v1);
        asan_mark_memory_region((uintptr_t)buff->area, buff->data_size, ASAN_TAG_RW);
        eth_receive(&dev->eth_dev, buff);
        q->avail->ring[q->avail->idx % q->size] = e->id;
        // the old buffer been consumed by higher network level handler, allocate a new buffer
        payload_desc->addr = (uintptr_t)kalloc_size_flags(RX_BUFFER_SIZE, KALLOC_ASAN_SKIP_INIT);

        q->last_used_idx++;
        q->avail->idx++;
    }

    if (packages_to_process) {
        mb();
        *q->notify = q->index; /* if flag VRING_USED_F_NO_NOTIFY is set */
    }
}

static void virtio_net_tx_handler(void *data) {
    // After data has been transmitted we need to return buffer back to the pool
    struct virtio_net_device *dev = data;
    struct virtq *q = &dev->tx_q;

    while (q->last_used_idx != q->used->idx) {
        struct virtq_used_elem *e = &q->used->ring[q->last_used_idx % q->size];

        // The TX elemnent might contain multiple descriptors
        // we need to free() the memory buffers and returns descriptors itself to the unused list
        uint16_t head_idx = e->id;
        struct virtq_desc *desc = &q->desc[head_idx];

        // header
        kfree((struct virtio_net_hdr_v1 *)desc->addr);
        desc = &q->desc[desc->next];
        // area
        kfree_size_flags((void *)desc->addr, RX_BUFFER_SIZE, KALLOC_ASAN_SKIP_INIT);

        // Currently TX transaction has only 2 descriptors, so we are done iterating used elements
        // but in the future we might have more
        SHOUT_IF(desc->flags & VIRTQ_DESC_F_NEXT, "More descriptors is not expected");

        desc->next = q->unused_desc_idx;
        q->unused_desc_idx = head_idx;
        q->unused_desc_size += 2; // 1 descriptor is for header, another is for data area

        q->last_used_idx++;
    }

    IFVV printf("Virtio net TX completion handler\n");
}

// Send data over virtio
static void virtio_net_send(struct eth_device *eth, buffer_t *buff) {
    SHOUT_IF(buff->pos != buff->area, "incorrect virtio tx buffer offset, difference is %ld", buff->pos - buff->area);
    SHOUT_IF(buff->data_size > buff->area_size, "Packet data overflows buffer area");

    struct virtio_net_device *dev = container_of(eth, struct virtio_net_device, eth_dev);
    struct virtq *q = &dev->tx_q;
    uint16_t need_descs_num = 2; // 1 for virtio header and 1 for the data buffer
    if (q->unused_desc_size < need_descs_num) {
        // let's check if we can free some space from completed transactions
        virtio_net_tx_handler(dev);

        if (q->unused_desc_size < need_descs_num) {
            // The queue is still full.
            // TODO: implement a dynamic list of transactions that user wants to send after the device queue become available
            PANIC("TX buffer overflow");
            return;
        }
    }

    // this buffer is in process of sending out, from now on nobody should ever write to it
    asan_mark_memory_region((uintptr_t)buff->area, buff->area_size, ASAN_TAG_SLAB_FREED);

    uint16_t desc_idx = q->unused_desc_idx;
    q->avail->ring[q->avail->idx % q->size] = desc_idx;

    // net header
    q->desc[desc_idx].addr = (uintptr_t)kalloc(struct virtio_net_hdr_v1);
    q->desc[desc_idx].len = sizeof(struct virtio_net_hdr_v1);
    q->desc[desc_idx].flags = VIRTQ_DESC_F_NEXT;
    desc_idx = q->desc[desc_idx].next;

    // data
    q->desc[desc_idx].addr = (uintptr_t)buff->pos;
    q->desc[desc_idx].len = buff->data_size;
    q->desc[desc_idx].flags = 0;
    desc_idx = q->desc[desc_idx].next;

    q->unused_desc_idx = desc_idx;
    q->unused_desc_size -= need_descs_num;

    wmb();
    q->avail->idx++;
    mb();
    *q->notify = q->index; // if flag VRING_USED_F_NO_NOTIFY is set
    kfree(buff);           // freeing buffer head here. The area will be freed in tx completion handler
}

static void virtio_net_cmd_handler(UNUSED void *data) { printf("Virtio net CMD handler\n"); }

static void virtio_legacy_handler(void *data) {
    struct virtio_net_device *dev = data;

    uint16_t status = pci_read16(dev->pci_id, PCI_CONFIG_STATUS);
    if (!(status & PCI_STATUS_INTR))
        return;

    // reading from this field also clears ISR
    uint8_t isr = *dev->isr_status;
    // BIT(0) - queue intr, BIT(1) - device intr
    if (!isr)
        return;

    printf("Virtio net LEGACY handler\n");
}

INIT_CODE static void virtio_net_probe(struct pci_device_info *info) {
    struct virtio_net_device *dev = kalloc(struct virtio_net_device);
    memzero(dev);
    dev->pci_id = info->id;

    /*    bool legacy = (info->device_id == VIRTIO_PCI_DEVICE_LEGACY);

        if (legacy) {
            SHOUT_IF(info->revision != 0, "Legacy VirtIO expects revision zero");
        }
    */
    SHOUT_IF(info->intr_type != PCI_INTR_MSIX && info->intr_type != PCI_INTR_LEGACY,
             "Virtio Net driver supports MSIX or LEGACY interrupt model only");
    if (info->intr_type == PCI_INTR_MSIX)
        SHOUT_IF(info->intr_msix.size < 3, "Size of MSIX vector is too small");

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
                printf("VirtioNet (type=%d) IO space is not supported\n", cfg_type);
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

    SHOUT_IF(!dev->cfg, "VirtioNet requires configuration capability");

    // Spec section 3.1, device initialization

    // reset device
    dev->cfg->device_status = 0;

    // ack
    dev->cfg->device_status |= VIRTIO_CONFIG_S_ACKNOWLEDGE | VIRTIO_CONFIG_S_DRIVER;

    // negotiate features
    uint64_t features = virtio_read_device_features(dev->cfg);
    printf("Device features are 0x%lx status %d\n", features, dev->cfg->device_status);
    uint64_t wanted_features = BIT(VIRTIO_F_VERSION_1) | BIT(VIRTIO_NET_F_MAC) | BIT(VIRTIO_NET_F_STATUS);

    uint64_t missed_features = ~features & wanted_features;
    if (missed_features) {
        // some features we want are not supported by the device
        PANIC("virtionet requested features 0x%lx are not supported by the device", missed_features);
        return;
    }
    virtio_write_driver_features(dev->cfg, wanted_features);
    dev->cfg->device_status |= VIRTIO_CONFIG_S_FEATURES_OK;

    if (!(dev->cfg->device_status & VIRTIO_CONFIG_S_FEATURES_OK)) {
        PANIC("virtio device did not accept our features");
        return;
    }

    // device initialization, section 5.1.5
    virtio_init_queue(dev->cfg, 0, &dev->rx_q, notify_base, notify_off_multiplier);
    virtio_init_queue(dev->cfg, 1, &dev->tx_q, notify_base, notify_off_multiplier);
    if (features & BIT(VIRTIO_NET_F_CTRL_VQ)) {
        virtio_init_queue(dev->cfg, 2, &dev->cmd_q, notify_base, notify_off_multiplier);
    }

    printf("Receive virtq size is %d notify=%p\n", dev->rx_q.size, dev->rx_q.notify);
    virtio_init_rx_buffer(&dev->rx_q);
    virtio_queue_desc_link(&dev->tx_q);

    if (info->intr_type == PCI_INTR_MSIX) {
        pci_register_msix_irq(info, 0, virtio_net_rx_handler, dev);
        pci_register_msix_irq(info, 1, virtio_net_tx_handler, dev);

        if (features & BIT(VIRTIO_NET_F_CTRL_VQ)) {
            pci_register_msix_irq(info, 2, virtio_net_cmd_handler, dev);
        }
    } else if (info->intr_type == PCI_INTR_LEGACY) {
        // use legacy interruptions
        irq_register(info->intr_legacy.line, virtio_legacy_handler, dev);
    }

    virtio_enable_queue(dev->cfg, &dev->rx_q);
    virtio_enable_queue(dev->cfg, &dev->tx_q);
    if (features & BIT(VIRTIO_NET_F_CTRL_VQ)) {
        virtio_enable_queue(dev->cfg, &dev->cmd_q);
    }

    // the device is ready now
    dev->cfg->device_status |= VIRTIO_CONFIG_S_DRIVER_OK;

    __mmio struct virtio_net_config *cfg = dev->device_cfg;
    dev->eth_dev.addr = *(ethaddr_t *)&cfg->mac;
    printf("MAC addr " ETHADDR_PRINT_FMT " status %d, virtq_pairs %d\n", ETHADDR_PRINT_PARAMS(dev->eth_dev.addr), cfg->status,
           cfg->max_virtqueue_pairs);

    if (dev->device_cfg->status & VIRTIO_NET_S_LINK_UP) {
        printf("Link is up\n");
    }

    dev->eth_dev.send = virtio_net_send;
    eth_dev_register(&dev->eth_dev);
}

PCI_DEVICE(VIRTIO_PCI_VENDOR, VIRTIO_PCI_DEVICE, virtio_net_probe);
// PCI_DEVICE(VIRTIO_PCI_VENDOR, VIRTIO_PCI_DEVICE_LEGACY, virtio_net_probe);
