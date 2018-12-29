// SPDX-License-Identifier: MIT

#include "blk.h"
#include "queue.h"
#include "stdio.h"

SLIST_HEAD(, blk_device) devices = SLIST_HEAD_INITIALIZER(&devices);

void blk_dev_register(struct blk_device *dev) { SLIST_INSERT_HEAD(&devices, dev, next); }

struct blk_device *blk_dev_get(size_t idx) {
    size_t i = 0;
    struct blk_device *dev;

    // find idx element in the list
    SLIST_FOREACH(dev, &devices, next) {
        if (i == idx) {
            return dev;
        }
        i++;
    }
    return NULL;
}

void blk_read(struct blk_device *blk, void *data, size_t size, size_t start_sector, blk_op_callback on_complete, void *context) {
    blk->send(blk, data, size, start_sector, false, on_complete, context);
}
void blk_write(struct blk_device *blk, void *data, size_t size, size_t start_sector, blk_op_callback on_complete, void *context) {
    blk->send(blk, data, size, start_sector, true, on_complete, context);
}
