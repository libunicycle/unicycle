// SPDX-License-Identifier: MIT

#pragma once

#include "buffer.h"
#include "queue.h"
#include <stdbool.h>
#include <stdint.h>

typedef uint32_t ip4addr_t;

#define IPADDR_PRINT_FMT "%d.%d.%d.%d"
#define IPADDR_PRINT_PARAMS(addr) ((uint8_t)(addr >> 24)), ((uint8_t)(addr >> 16)), ((uint8_t)(addr >> 8)), ((uint8_t)addr)

#define IPADDR(p1, p2, p3, p4) (ip4addr_t)((p1 << 24) | (p2 << 16) | (p3 << 8) | (p4))
#define IPADDR_ANY IPADDR(0, 0, 0, 0)
#define IPADDR_INVALID IPADDR_ANY
#define IPADDR_BROADCAST IPADDR(255, 255, 255, 255)

bool ipaddr_isbroadcaset(ip4addr_t mask, ip4addr_t addr);
bool ipaddr_ismulticast(ip4addr_t addr);

struct udp_listener;
struct tcp_listener;
struct tcp_connection;
struct ip4_hdr;

struct ip4if {
    ip4addr_t addr;
    ip4addr_t mask;
    ip4addr_t router_addr;

    // valid only if DHCP is used
    ip4addr_t dhcp_server_addr;
    uint32_t dhcp_lease_time; // in seconds

    struct eth_device *(*eth_dev)(struct ip4if *ip4if);

    LIST_HEAD(, udp_listener) udp_listeners;
    LIST_HEAD(, tcp_listener) tcp_listeners;
    LIST_HEAD(, tcp_connection) tcp_connections;
};

// https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
#define IP_PROTO_HOPOPT 0
#define IP_PROTO_ICMP 1
#define IP_PROTO_IGMP 2
#define IP_PROTO_GGP 3
#define IP_PROTO_IPinIP 4
#define IP_PROTO_ST 5
#define IP_PROTO_TCP 6
#define IP_PROTO_CBT 7
#define IP_PROTO_EGP 8
#define IP_PROTO_IGP 9
#define IP_PROTO_UDP 17
#define IP_PROTO_HMP 20
#define IP_PROTO_IP6 41 // encapsulation

typedef void (*ip4if_init_callback_t)(struct ip4if *);
void ip4if_register(struct ip4if *ip4if);
void ip4if_on_init(ip4if_init_callback_t callback);
void ip4if_init_complete(struct ip4if *ip4if);

ip4addr_t ip4_src_addr(struct ip4_hdr *hdr);
void ip4_receive(struct ip4if *ip4if, buffer_t *buf);
void ip4_send(struct ip4if *ip4if, buffer_t *buf, ip4addr_t dest, uint8_t protocol);
bool ip4_broadcast(struct ip4if *ip4if, ip4addr_t addr);

// It includes pseudo-header and used for UDP and TCP checksumming
uint16_t checksum_calculate(void *payload, uint16_t length, uint16_t proto, ip4addr_t src, ip4addr_t dest);