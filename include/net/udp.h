// SPDX-License-Identifier: MIT

#pragma once

#include "buffer.h"
#include "err.h"
#include "net/ip4.h"
#include <stdbool.h>

struct ip4if;
void udp_receive(struct ip4if *ip4if, ip4addr_t src_ip, ip4addr_t dest_ip, buffer_t *buf);
void udp_send(struct ip4if *ip4if, buffer_t *buf, ip4addr_t dest_ip4, uint16_t src_port, uint16_t dest_port);

typedef void (*udp_handler_t)(struct udp_listener *listener, buffer_t *buf);
struct udp_listener {
    struct ip4if *ip4if;
    uint16_t port;
    udp_handler_t handler;
    LIST_ENTRY(udp_listener) next;
};

err_t udp_bind(struct ip4if *ip4if, uint16_t port, udp_handler_t handler);
void udp_unbind(struct udp_listener *listener);