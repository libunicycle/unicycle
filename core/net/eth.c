// SPDX-License-Identifier: MIT

#include "net/eth.h"
#include "buffer.h"
#include "compiler.h"
#include "kalloc.h"
#include "mem.h"
#include "net/arp.h"
#include "net/ip4.h"
#include "net/ip6.h"
#include "queue.h"
#include "shout.h"
#include "stdio.h"

struct __be PACKED eth_hdr {
    ethaddr_t dest;
    ethaddr_t src;
    uint16_t type;
};
BUILD_PANIC_IF(sizeof(struct eth_hdr) != HDR_LEN_ETH - HDR_LEN_RAW, "HDR_LEN_ETH is not specified correctly");

const ethaddr_t ETH_BROADCAST = {.addr = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};

static struct eth_device *eth_dev_from_ip4if(struct ip4if *ip4if) { return container_of(ip4if, struct eth_device, ip4if); };

void eth_dev_register(struct eth_device *dev) {
    dev->ip4if.eth_dev = eth_dev_from_ip4if;
    ip4if_register(&dev->ip4if);
}

void eth_dev_unregister(UNUSED struct eth_device *dev) {}

void eth_receive(struct eth_device *dev, buffer_t *buff) {
    struct eth_hdr *hdr = buff->pos;
    buff->pos += sizeof(struct eth_hdr);

    IFD printf("Received eth src=" ETHADDR_PRINT_FMT " dest=" ETHADDR_PRINT_FMT " type=%x\n", ETHADDR_PRINT_PARAMS(hdr->src),
               ETHADDR_PRINT_PARAMS(hdr->dest), hdr->type);

    if (hdr->type == ETH_TYPE_IP4) {
        arp_cache_add(ip4_src_addr((struct ip4_hdr *)buff->pos), hdr->src);
        ip4_receive(&dev->ip4if, buff);
    } else if (hdr->type == ETH_TYPE_IP6) {
        ip6_receive(&dev->ip4if6, buff);
    } else if (hdr->type == ETH_TYPE_ARP) {
        arp_receive(dev, buff);
    } else {
        IFD printf("Unknown eth frame type %d\n", hdr->type);
        buffer_free(buff);
    }
}

void eth_send(struct eth_device *dev, const ethaddr_t *dest, uint16_t type, buffer_t *buff) {
    buff->pos -= sizeof(struct eth_hdr);
    struct eth_hdr *hdr = buff->pos;

    hdr->type = type;
    hdr->src = dev->addr;
    hdr->dest = *dest;

    IFD printf("Sent eth src=" ETHADDR_PRINT_FMT " dest=" ETHADDR_PRINT_FMT " type=%x\n", ETHADDR_PRINT_PARAMS(hdr->src),
               ETHADDR_PRINT_PARAMS(hdr->dest), hdr->type);

    dev->send(dev, buff);
}

void ethaddr_cpy(uint8_t *dest, const uint8_t *src) { memcpy(dest, src, sizeof(ethaddr_t)); }