// SPDX-License-Identifier: MIT

#include "net/icmp6.h"
#include "buffer.h"
#include "compiler.h"
#include "stdio.h"
#include <stdbool.h>

struct __be PACKED icmp6_hdr {};

bool icmp6_receive(UNUSED struct ip4if *ip4if, UNUSED buffer_t *buff) {
    // struct icmp6_hdr *hdr = buff->pos;
    // buff->pos += sizeof(struct icmp6_hdr);

    printf("ICMP6\n");

    return true;
}
