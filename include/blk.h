// SPDX-License-Identifier: MIT

#pragma once

#include "buffer.h"
#include "queue.h"
#include <stdint.h>

enum blk_op_status { BLK_OP_SUCCESS, BLK_OP_ERROR, BLK_OP_UNSUPPORTED };

struct blk_device;
typedef void (*blk_op_callback)(struct blk_device *blk, void *data, enum blk_op_status status, void *context);

struct blk_device {
    // Ops
    void (*send)(struct blk_device *blk, void *data, size_t data_size, size_t start_sector, bool write, blk_op_callback on_complete,
                 void *callback_context);

    SLIST_ENTRY(blk_device) next;
};

void blk_dev_register(struct blk_device *dev);
struct blk_device *blk_dev_get(size_t idx);
void blk_read(struct blk_device *blk, void *data, size_t size, size_t start_sector, blk_op_callback on_complete, void *context);
void blk_write(struct blk_device *blk, void *data, size_t size, size_t start_sector, blk_op_callback on_complete, void *context);