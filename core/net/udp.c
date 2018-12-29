// SPDX-License-Identifier: MIT

#include "net/udp.h"
#include "buffer.h"
#include "compiler.h"
#include "kalloc.h"
#include "net/arp.h"
#include "net/eth.h"
#include "net/ip4.h"
#include "shout.h"
#include "stdio.h"
#include <stdbool.h>

struct __be PACKED udp_hdr {
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t length; // datagram length
    uint16_t checksum;
};
BUILD_PANIC_IF(sizeof(struct udp_hdr) != HDR_LEN_UDP - HDR_LEN_IP4, "HDR_LEN_UDP is not specified correctly");

void udp_receive(struct ip4if *ip4if, ip4addr_t src_ip, ip4addr_t dest_ip, buffer_t *buff) {
    struct udp_hdr *hdr = buff->pos;
    buff->pos += sizeof(struct udp_hdr);

    if (checksum_calculate(hdr, hdr->length, IP_PROTO_UDP, src_ip, dest_ip) != 0) {
        IFD printf("UDP checksum failed\n");
        goto buff_free;
    }

    struct udp_listener *l;
    LIST_FOREACH(l, &ip4if->udp_listeners, next) {
        if (l->port == hdr->dest_port) {
            l->handler(l, buff);
            goto buff_free;
        }
    }
    IFD printf("No listeners found for UDP port %d\n", hdr->dest_port);

buff_free:
    buffer_free(buff);
}

void udp_send(struct ip4if *ip4if, buffer_t *buff, ip4addr_t dest, uint16_t src_port, uint16_t dest_port) {
    buff->pos -= sizeof(struct udp_hdr);
    struct udp_hdr *hdr = buff->pos;

    hdr->src_port = src_port;
    hdr->dest_port = dest_port;
    hdr->length = buff->data_size - HDR_LEN_IP4; // size of UDP header + payload
    hdr->checksum = 0;                           // set it to zero before calculating checksum
    hdr->checksum = checksum_calculate(hdr, hdr->length, IP_PROTO_UDP, ip4if->addr, dest);

    ip4_send(ip4if, buff, dest, IP_PROTO_UDP);
}

err_t udp_bind(struct ip4if *ip4if, uint16_t port, udp_handler_t handler) {
    struct udp_listener *l;
    LIST_FOREACH(l, &ip4if->udp_listeners, next) {
        if (l->port == port)
            return E_INUSE;
    }

    struct udp_listener *listener = kalloc(struct udp_listener);
    listener->ip4if = ip4if;
    listener->port = port;
    listener->handler = handler;

    LIST_INSERT_HEAD(&ip4if->udp_listeners, listener, next);
    return SUCCESS;
}

void udp_unbind(struct udp_listener *listener) { LIST_REMOVE(listener, next); }