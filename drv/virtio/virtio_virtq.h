#pragma once

/*
 *
 * Virtual I/O Device (VIRTIO) Version 1.0
 * Committee Specification 04
 * 03 March 2016
 * Copyright (c) OASIS Open 2016. All Rights Reserved.
 * Source: http://docs.oasis-open.org/virtio/virtio/v1.0/cs04/listings/
 * Link to latest version of the specification documentation: http://docs.oasis-open.org/virtio/virtio/v1.0/virtio-v1.0.html
 *
 */
#include "compiler.h"
#include "shout.h"
#include <stdint.h>

/* This marks a buffer as continuing via the next field. */
#define VIRTQ_DESC_F_NEXT BIT(0)
/* This marks a buffer as write-only (otherwise read-only). */
#define VIRTQ_DESC_F_WRITE BIT(1)
/* This means the buffer contains a list of buffer descriptors. */
#define VIRTQ_DESC_F_INDIRECT BIT(2)

/* The device uses this in used->flags to advise the driver: don't kick me
 * when you add a buffer.  It's unreliable, so it's simply an
 * optimization. */
#define VIRTQ_USED_F_NO_NOTIFY 1
/* The driver uses this in avail->flags to advise the device: don't
 * interrupt me when you consume a buffer.  It's unreliable, so it's
 * simply an optimization.  */
#define VIRTQ_AVAIL_F_NO_INTERRUPT 1

/* Support for indirect descriptors */
#define VIRTIO_F_INDIRECT_DESC 28

/* Support for avail_event and used_event fields */
#define VIRTIO_F_EVENT_IDX 29

/* Arbitrary descriptor layouts. */
#define VIRTIO_F_ANY_LAYOUT 27

/* Virtqueue descriptors: 16 bytes.
 * These can chain together via "next". */
struct __le virtq_desc {
    /* Address (guest-physical). */
    uint64_t addr;
    /* Length. */
    uint32_t len;
    /* The flags as indicated above. */
    uint16_t flags;
    /* We chain unused descriptors via this, too */
    uint16_t next;
};
BUILD_PANIC_IF(sizeof(struct virtq_desc) != 16);

struct __le virtq_avail {
    uint16_t flags;
    uint16_t idx;
    uint16_t ring[];
    /* Only if VIRTIO_F_EVENT_IDX: uint16_t used_event; */
};

/* uint32_t is used here for ids for padding reasons. */
struct __le virtq_used_elem {
    /* Index of start of used descriptor chain. */
    uint32_t id;
    /* Total length of the descriptor chain which was written to. */
    uint32_t len;
};

struct __le virtq_used {
    uint16_t flags;
    uint16_t idx;
    struct virtq_used_elem ring[];
    /* Only if VIRTIO_F_EVENT_IDX: uint16_t avail_event; */
};

struct virtq {
    uint16_t index;
    uint16_t size;
    __mmio uint16_t *notify; // writing virtq index to this address notifies device

    uint16_t last_used_idx;    // last item consumed by driver
    uint16_t unused_desc_idx;  // free descriptors are linked to each other, this index points to the first unused descriptor
    uint16_t unused_desc_size; // number of descriptors in the 'unused' list

    struct virtq_desc *desc;
    struct virtq_avail *avail;
    struct virtq_used *used;
};

static inline int virtq_need_event(uint16_t event_idx, uint16_t new_idx, uint16_t old_idx) {
    return (uint16_t)(new_idx - event_idx - 1) < (uint16_t)(new_idx - old_idx);
}

/* Get location of event indices (only with VIRTIO_F_EVENT_IDX) */
static inline uint16_t *virtq_used_event(struct virtq *vq) {
    /* For backwards compat, used event index is at *end* of avail ring. */
    return &vq->avail->ring[vq->size];
}

static inline uint16_t *virtq_avail_event(struct virtq *vq) {
    /* For backwards compat, avail event index is at *end* of used ring. */
    return (uint16_t *)&vq->used->ring[vq->size];
}