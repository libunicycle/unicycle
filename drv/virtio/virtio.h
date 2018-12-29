// SPDX-License-Identifier: MIT

#pragma once

#include "compiler.h"
#include "virtio_pci.h"
#include "virtio_virtq.h"
#include <stdint.h>

uint64_t virtio_read_device_features(__mmio struct virtio_pci_common_cfg *cfg);
void virtio_write_driver_features(__mmio struct virtio_pci_common_cfg *cfg, uint64_t features);

void virtio_enable_queue(__mmio struct virtio_pci_common_cfg *cfg, struct virtq *queue);
void virtio_init_queue(__mmio struct virtio_pci_common_cfg *cfg, uint16_t index, struct virtq *queue, __mmio void *notify_base,
                       uint32_t notify_off_multiplier);
void virtio_queue_desc_link(struct virtq *queue);