// SPDX-License-Identifier: MIT

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    void *area;         // beginning of the buffer area
    void *pos;          // currently processed position
    uint32_t area_size; // total size of the buffer area
    uint32_t data_size; // size of data available in the buffer
} buffer_t;

// allocate buffer and buffer area
buffer_t *buffer_allocate(uint32_t size, uint32_t prefix_size);

// frees buffer *and* undelying buffer area
void buffer_free(buffer_t *buffer);

bool buffer_has_more_data(buffer_t *buf);
size_t buffer_data_available(buffer_t *buf);

// Returns how much free space this buffer has
size_t buffer_free_space(buffer_t *buf);

#define BUFFER_NET_SIZE 2048 // default size for network buffer, it should fit one IP datagram with ethernet header

#define HDR_LEN_RAW 0
#define HDR_LEN_ETH (HDR_LEN_RAW + 14U)
#define HDR_LEN_IP4 (HDR_LEN_ETH + 20U)
#define HDR_LEN_UDP (HDR_LEN_IP4 + 8U)
#define HDR_LEN_TCP (HDR_LEN_IP4 + 20U)