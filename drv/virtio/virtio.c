// SPDX-License-Identifier: MIT

#include "virtio.h"
#include "kalloc.h"
#include "mem.h"

uint64_t virtio_read_device_features(__mmio struct virtio_pci_common_cfg *cfg) {
    // read low 32 bits
    cfg->device_feature_select = 0;
    uint64_t features = cfg->device_feature;

    // read top 32 bits
    cfg->device_feature_select = 1;
    features |= (uint64_t)cfg->device_feature << 32;

    return features;
}

void virtio_write_driver_features(__mmio struct virtio_pci_common_cfg *cfg, uint64_t features) {
    // write low 32 bits
    cfg->driver_feature_select = 0;
    cfg->driver_feature = (uint32_t)features;

    // write top 32 bits
    cfg->driver_feature_select = 1;
    cfg->driver_feature = (uint32_t)(features >> 32);
}

void virtio_enable_queue(__mmio struct virtio_pci_common_cfg *cfg, struct virtq *queue) {
    cfg->queue_select = queue->index;
    cfg->queue_enable = 1;
}

void virtio_init_queue(__mmio struct virtio_pci_common_cfg *cfg, uint16_t index, struct virtq *queue, __mmio void *notify_base,
                       uint32_t notify_off_multiplier) {
    cfg->queue_select = index;
    uint16_t size = cfg->queue_size;

    queue->size = size;
    queue->index = index;
    queue->last_used_idx = 0;

    queue->desc = kalloc_align(16 * size, 16);
    memset(queue->desc, 0, 16 * size);

    queue->avail = kalloc_align(6 + 2 * size, 2);
    memset(queue->avail, 0, 6 + 2 * size);

    queue->used = kalloc_align(6 + 8 * size, 4);
    memset(queue->used, 0, 6 + 8 * size);

    if (notify_base) {
        queue->notify = notify_base + notify_off_multiplier * cfg->queue_notify_off;
    }

    cfg->queue_desc_lo = (uintptr_t)queue->desc;
    cfg->queue_desc_hi = ((uintptr_t)queue->desc) >> 32;
    cfg->queue_avail_lo = (uintptr_t)queue->avail;
    cfg->queue_avail_hi = ((uintptr_t)queue->avail) >> 32;
    cfg->queue_used_lo = (uintptr_t)queue->used;
    cfg->queue_used_hi = ((uintptr_t)queue->used) >> 32;

    cfg->queue_msix_vector = index;
}

void virtio_queue_desc_link(struct virtq *queue) {
    // free descriptors are linked together
    queue->unused_desc_idx = 0;
    queue->unused_desc_size = queue->size;
    for (int i = 0; i < queue->size - 1; i++) {
        queue->desc[i].next = i + 1;
    }
}