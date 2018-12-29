// SPDX-License-Identifier: MIT

#pragma once

#include "buffer.h"
#include "compiler.h"
#include "ip4.h"
#include "ip6.h"
#include "queue.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t addr[6];
} ethaddr_t;

struct eth_device {
    ethaddr_t addr;
    struct ip4if ip4if;
    struct ip6if ip4if6;

    // Ops
    void (*send)(struct eth_device *eth, buffer_t *buff);
};

#define ETHADDR_PRINT_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define ETHADDR_PRINT_PARAMS(var) (var.addr)[0], (var.addr)[1], (var.addr)[2], (var.addr)[3], (var.addr)[4], (var.addr)[5]

extern const ethaddr_t ETH_BROADCAST;

// eth_hdr.type field
#define ETH_TYPE_IP4 0x0800
#define ETH_TYPE_ARP 0x0806
#define ETH_TYPE_IP6 0x86dd

void eth_dev_register(struct eth_device *dev);
void eth_receive(struct eth_device *dev, buffer_t *buf);
void eth_send(struct eth_device *dev, const ethaddr_t *dest, uint16_t type, buffer_t *buff);

void ethaddr_cpy(uint8_t *dest, const uint8_t *src);
