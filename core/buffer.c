// SPDX-License-Identifier: MIT

#include "buffer.h"
#include "compiler.h"
#include "kalloc.h"
#include "shout.h"
#include <stdint.h>

// allocate buffer and buffer area
buffer_t *buffer_allocate(uint32_t size, uint32_t prefix_size) {
    void *area = kalloc_size(size);
    buffer_t *buf = kalloc(buffer_t);
    buf->area = area;
    buf->pos = area + prefix_size;
    buf->area_size = size;
    buf->data_size = prefix_size;
    return buf;
}

// frees buffer *and* undelying buffer area
void buffer_free(buffer_t *buf) {
    kfree_size(buf->area, buf->area_size);
    kfree(buf);
}

bool buffer_has_more_data(buffer_t *buf) { return buffer_data_available(buf) != 0; }

size_t buffer_data_available(buffer_t *buf) {
    IFD SHOUT_IF(buf->pos > buf->area + buf->data_size);
    return buf->data_size - (buf->pos - buf->area);
}

size_t buffer_free_space(buffer_t *buf) { return buf->area_size - buf->data_size; }
