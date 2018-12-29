// SPDX-License-Identifier: MIT

#include "net/ip4.h"
#include "buffer.h"
#include "compiler.h"
#include "mem.h"
#include "net/arp.h"
#include "net/dhcp.h"
#include "net/eth.h"
#include "net/icmp.h"
#include "net/tcp.h"
#include "net/udp.h"
#include "shout.h"
#include "stdio.h"
#include <stdint.h>

struct __be PACKED ip4_hdr {
    uint8_t version : 4;
    uint8_t hdr_length : 4; // size of this header == 4 * hdr_length
    uint8_t dscp : 6;       // differentiated service
    uint8_t __unused : 2;
    uint16_t length;
    uint16_t id;
    uint8_t flags : 3;
    uint16_t frag_offset : 13;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t hdr_checksum;
    ip4addr_t src_ip;
    ip4addr_t dest_ip;
    // options size is  4 * (hdr_length - 5)
};
BUILD_PANIC_IF(sizeof(struct ip4_hdr) != HDR_LEN_IP4 - HDR_LEN_ETH, "HDR_LEN_IP4 is not specified correctly");

#define IP_HDR_VERSION 4
#define IP_TTL 64

// TODO think about better solution for registering IP4 interfaces
// In case of static IP address, ip4 interface can come earlier than application tries to add an init callback for it
// in case of dynamic IP address the interface usually becomes available later
static struct ip4if *ip4if_saved;
void ip4if_register(struct ip4if *ip4if) {
    // TODO: make initialization configurable, static vs dynamic

    // Static IP binding is needed in you test the device in a local network without DHCP

    ip4if->addr = IPADDR(10, 0, 0, 45);
    ip4if->mask = IPADDR(255, 255, 255, 0);
    ip4if->router_addr = IPADDR(10, 0, 0, 1);
    ip4if_saved = ip4if;
    ip4if_init_complete(ip4if);

    // It is needed if you run the app with QEMU + DHCP enabled
    // dhcp_init(ip4if);
}

// XXX in the future we might have multiple init function
// so we might need a LIST
static ip4if_init_callback_t ip4if_init_callback = NULL;
void ip4if_on_init(ip4if_init_callback_t callback) {
    PANIC_IF(ip4if_init_callback, "ip4if init callback is already set");

    ip4if_init_callback = callback;
    if (ip4if_saved)
        ip4if_init_callback(ip4if_saved);
}

void ip4if_init_complete(struct ip4if *ip4if) {
    if (ip4if_init_callback)
        ip4if_init_callback(ip4if);
}

// complimentary sum of 16-bit words
static uint64_t checksum_block(void *data, uint16_t length) {
    uint64_t sum = 0;

    // TODO: speedup the checksum calculations using 64bit or vector instructions
    while (length > 1) {
        sum += *(uint16_t *)data;
        data += 2;
        length -= 2;
    }
    if (length > 0) {
        sum += *(uint8_t *)data;
    }

    return sum;
}

// fold and perform binary complement
static uint16_t checksum_final(uint64_t sum) {
    // folding
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return ~be_to_cpu((uint16_t)sum);
}

static uint16_t ip4_checksum_calculate(struct ip4_hdr *hdr, uint32_t length) {
    uint64_t sum = checksum_block(hdr, length);
    return checksum_final(sum);
}

ip4addr_t ip4_src_addr(struct ip4_hdr *hdr) { return hdr->src_ip; }

void ip4_receive(struct ip4if *ip4if, buffer_t *buff) {
    struct ip4_hdr *hdr = buff->pos;
    size_t hdr_length = hdr->hdr_length * 4;

    IFD printf("IP version=%d hdr_len=%d protocol=%d\n", hdr->version, hdr->hdr_length, hdr->protocol);

    if (hdr->hdr_length < 5) {
        IFD printf("IP header length field is too small\n");
        // ip4 header is too small
        goto free_buff;
    }
    if (HDR_LEN_ETH + hdr_length > buff->data_size) {
        IFD printf("Received IP data is too small\n");
        //  header_len points outside of valid package data, it is an invalid package
        goto free_buff;
    }
    uint32_t expected_length = HDR_LEN_ETH + hdr->length; // Data length calculated from IP header
    if (expected_length > buff->data_size) {
        IFD printf("IP packet length differs from what reported by eth (%d vs %d)\n", expected_length, buff->data_size);
        goto free_buff;
    } else if (expected_length < buff->data_size) {
        // Ethernet requires minimum frame size to be 64b.
        // Some eth devices (e.g. Qemu e1000e) add padding to small frames.
        // Drop the padding and use IP length if it is smaller than ETH length
        buff->data_size = expected_length;
    }
    if (ip4_checksum_calculate(hdr, hdr_length) != 0) {
        IFD printf("Invalid IP header checksum\n");
        goto free_buff;
    }
    if (hdr->version != IP_HDR_VERSION) {
        IFD printf("Bogus IP package version %d\n", hdr->version);
        goto free_buff;
    }
    if (ip4if->addr == IPADDR_INVALID) { // if the network interface is not initialized yet
        if (hdr->dest_ip != IPADDR_BROADCAST)
            goto free_buff;
    } else {
        // for now allow broadcast only for UDP
        if (ip4_broadcast(ip4if, hdr->dest_ip) && hdr->protocol != IP_PROTO_UDP)
            goto free_buff;
        if (hdr->dest_ip != ip4if->addr)
            goto free_buff;
    }

    buff->pos += hdr_length;

    if (hdr->protocol == IP_PROTO_TCP) {
        // TCP is unicast and always 'dest_ip == ip4if->addr'
        tcp_receive(ip4if, hdr->src_ip, buff);
        return;
    } else if (hdr->protocol == IP_PROTO_UDP) {
        // TCP can do multicast and sometimes 'dest_ip != ip4if->addr',
        // to calculate UDP checksum properly we need to pass original dest_ip
        // to this function
        udp_receive(ip4if, hdr->src_ip, hdr->dest_ip, buff);
        return;
    } else if (hdr->protocol == IP_PROTO_ICMP) {
        icmp_receive(ip4if, buff);
        return;
    } else {
        IFD printf("Unknown IP protocol %d\n", hdr->protocol);
    }

free_buff:
    buffer_free(buff);
}

void ip4_send(struct ip4if *ip4if, buffer_t *buff, ip4addr_t dest, uint8_t protocol) {
    buff->pos -= sizeof(struct ip4_hdr);
    struct ip4_hdr *hdr = buff->pos;

    memzero(hdr);
    hdr->version = IP_HDR_VERSION;
    hdr->hdr_length = sizeof(struct ip4_hdr) / 4;
    hdr->length = buff->data_size - HDR_LEN_ETH;
    hdr->ttl = IP_TTL;
    hdr->protocol = protocol;
    hdr->src_ip = ip4if->addr;
    hdr->dest_ip = dest;
    hdr->hdr_checksum = ip4_checksum_calculate(hdr, sizeof(struct ip4_hdr));

    ethaddr_t eth_addr;
    const ethaddr_t *eth_addr_ptr;
    if (dest == IPADDR_BROADCAST) {
        eth_addr_ptr = &ETH_BROADCAST;
    } else {
        bool found = arp_cache_lookup(dest, &eth_addr);
        if (found) {
            eth_addr_ptr = &eth_addr;
        } else {
            IFD printf("Destination IP4 address (" IPADDR_PRINT_FMT ") is not recognized\n", IPADDR_PRINT_PARAMS(dest));
            buffer_free(buff);
            return;
        }
    }
    struct eth_device *eth = ip4if->eth_dev(ip4if);
    eth_send(eth, eth_addr_ptr, ETH_TYPE_IP4, buff);
}

bool ip4_broadcast(struct ip4if *ip4if, ip4addr_t addr) {
    ip4addr_t addr_mask = ~ip4if->mask;
    return (addr & addr_mask) == addr_mask;
}

uint16_t checksum_calculate(void *payload, uint16_t length, uint16_t proto, ip4addr_t src, ip4addr_t dest) {
    struct __be PACKED pseudo_hdr {
        ip4addr_t src;
        ip4addr_t dest;
        uint16_t proto;
        uint16_t length;
    };

    struct pseudo_hdr pseudo_hdr;
    pseudo_hdr.src = src;
    pseudo_hdr.dest = dest;
    pseudo_hdr.length = length;
    pseudo_hdr.proto = proto;

    uint64_t sum = 0;
    // calculate sum in Big Endian to avoid bswapping "data"
    sum += checksum_block(&pseudo_hdr, sizeof(struct pseudo_hdr));
    sum += checksum_block(payload, length);

    return checksum_final(sum);
}
