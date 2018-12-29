// SPDX-License-Identifier: MIT

#include "net/icmp.h"
#include "buffer.h"
#include "compiler.h"
#include "stdio.h"
#include <stdbool.h>

struct __be PACKED icmp_hdr {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    // rest of the header, content meaning depends on type
};

#define ICMP_TYPE_ECHO_REPLY 0
#define ICMP_TYPE_DEST_UNREACHABLE 3
#define ICMP_TYPE_SRC_QUENCH 4
#define ICMP_TYPE_REDIRECT 5
#define ICMP_TYPE_ECHO_REQUEST 8
#define ICMP_TYPE_ROUTER_AD 9
#define ICMP_TYPE_ROUTER_SOLICIT 10
#define ICMP_TYPE_TIME_EXCEEDED 11
#define ICMP_TYPE_BAD_IP_HDR 12
#define ICMP_TYPE_TIMESTAMP 13
#define ICMP_TYPE_TIMESTAMP_REPLY 14

// code for ICMP_TYPE_DEST_UNREACHABLE type
#define ICMP_UNREACH_NETWORK 0
#define ICMP_UNREACH_HOST 1
#define ICMP_UNREACH_PROTOCOL 2
#define ICMP_UNREACH_PORT 3
#define ICMP_UNREACH_FRAG_REQUIRED 4
#define ICMP_UNREACH_SRC_ROUTE_FAILED 5
#define ICMP_UNREACH_DEST_NET_UNKNOWN 6
#define ICMP_UNREACH_DEST_HOST_UNKNOWN 7
#define ICMP_UNREACH_SRC_ISOLATED 8
#define ICMP_UNREACH_NET_PROHIBITED 9
#define ICMP_UNREACH_HOST_PROHIBITED 10
#define ICMP_UNREACH_NET_TOS 11
#define ICMP_UNREACH_HOST_TOS 12
#define ICMP_UNREACH_COMM_PROHIBITED 13
#define ICMP_UNREACH_PRECEDENCE_VIOLATION 14
#define ICMP_UNREACH_PRECEDENCE_CUTOFF 15

// code for ICMP_TYPE_REDIRECT type
#define ICMP_REDIR_NET 0
#define ICMP_REDIR_HOST 1
#define ICMP_REDIR_TOS_NET 2
#define ICMP_REDIR_TOS_HOST 3

void icmp_receive(UNUSED struct ip4if *ip4if, buffer_t *buff) {
    struct icmp_hdr *hdr = buff->pos;
    buff->pos += sizeof(struct icmp_hdr);

    printf("ICMP type=%d, code=%d\n", hdr->type, hdr->code);

    buffer_free(buff);
}
