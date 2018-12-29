// SPDX-License-Identifier: MIT

#include "net/ip6.h"
#include "buffer.h"
#include "compiler.h"
#include "net/icmp6.h"
#include "net/tcp.h"
#include "net/udp.h"
#include "stdio.h"
#include <stdint.h>

struct __be PACKED ip6_hdr {};

void ip6_receive(UNUSED struct ip6if *ip6if, UNUSED buffer_t *buff) {
    // struct ip6_hdr *hdr = buff->pos;

    // printf("IP6\n");
}
