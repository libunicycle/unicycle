// SPDX-License-Identifier: MIT

#include "net/arp.h"
#include "compiler.h"
#include "kalloc.h"
#include "net/eth.h"
#include "net/ip4.h"
#include "stdio.h"
#include "tree.h"
#include <stdint.h>

#define APR_OP_REQUEST 1
#define APR_OP_REPLY 2

#define HWTYPE_ETH 1

struct __be PACKED arp_hdr {
    uint16_t hw_type;
    uint16_t protocol_type;
    uint8_t eth_addr_len;
    uint8_t ip_addr_len;
    uint16_t operation;
    ethaddr_t sender_eth_addr;
    ip4addr_t sender_ip_addr;
    ethaddr_t target_eth_addr;
    ip4addr_t target_ip_addr;
};

struct arp_entry {
    ethaddr_t eth;
    ip4addr_t ip;
    // (type)
    RB_ENTRY(arp_entry) entries;
};

// (name, type)
RB_HEAD(arp_cache, arp_entry) arp_tree;

static int compare(struct arp_entry *a, struct arp_entry *b) {
    if (a->ip < b->ip)
        return -1;
    else if (a->ip > b->ip)
        return 1;

    return 0;
}

// (name, type, field, cmp)
RB_PROTOTYPE(arp_cache, arp_entry, entries, compare);
RB_GENERATE(arp_cache, arp_entry, entries, compare);

void arp_cache_add(ip4addr_t ip, ethaddr_t eth) {
    struct arp_entry *new = kalloc(struct arp_entry);
    new->ip = ip;
    new->eth = eth;

    struct arp_entry *existing = RB_INSERT(arp_cache, &arp_tree, new);
    if (existing) {
        // if the address already exist then update that one instead
        kfree(new);
        existing->eth = eth;
    }
}

bool arp_cache_lookup(ip4addr_t ip, ethaddr_t *eth) {
    struct arp_entry e;
    e.ip = ip;

    struct arp_entry *found = RB_FIND(arp_cache, &arp_tree, &e);
    if (found) {
        *eth = found->eth;
    }
    return found;
}

void arp_receive(struct eth_device *dev, buffer_t *buff) {
    struct arp_hdr *hdr_in = buff->pos;

    IFVV printf("ARP hw_type=%d proto_type=0x%x sender_ip=" IPADDR_PRINT_FMT " target_ip=" IPADDR_PRINT_FMT " op=%d\n", hdr_in->hw_type,
                hdr_in->protocol_type, IPADDR_PRINT_PARAMS(hdr_in->sender_ip_addr), IPADDR_PRINT_PARAMS(hdr_in->target_ip_addr),
                hdr_in->operation);

    if (hdr_in->target_ip_addr != dev->ip4if.addr)
        return; // not for us

    if (hdr_in->operation == APR_OP_REQUEST) {
        buffer_t *outbuff = buffer_allocate(BUFFER_NET_SIZE, HDR_LEN_ETH);
        struct arp_hdr *hdr_out = outbuff->pos;
        outbuff->data_size += sizeof(*hdr_out);

        hdr_out->operation = APR_OP_REPLY;
        hdr_out->hw_type = HWTYPE_ETH;
        hdr_out->protocol_type = ETH_TYPE_IP4;
        hdr_out->eth_addr_len = sizeof(ethaddr_t);
        hdr_out->ip_addr_len = sizeof(ip4addr_t);

        hdr_out->target_ip_addr = hdr_in->sender_ip_addr;
        hdr_out->target_eth_addr = hdr_in->sender_eth_addr;
        hdr_out->sender_ip_addr = dev->ip4if.addr;
        hdr_out->sender_eth_addr = dev->addr;

        eth_send(dev, &hdr_out->target_eth_addr, ETH_TYPE_ARP, outbuff);
    } else if (hdr_in->operation == APR_OP_REPLY) {
        arp_cache_add(hdr_in->sender_ip_addr, hdr_in->sender_eth_addr);
    } else {
        printf("Unknown ARP operation %d\n", hdr_in->operation);
    }
}
