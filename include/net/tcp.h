// SPDX-License-Identifier: MIT

#pragma once

#include "buffer.h"
#include "err.h"
#include "ip4.h"
#include <stdbool.h>

struct ip4_hdr;

enum tcp_state {
    TCP_STATE_SYN_CLOSED = 0,
    TCP_STATE_SYN_RECEIVED,
    TCP_STATE_SYN_SENT,
    TCP_STATE_ESTABLISHED,
    TCP_STATE_FIN_WAIT_1,
    TCP_STATE_FIN_WAIT_2,
    TCP_STATE_CLOSING,
    TCP_STATE_TIME_WAIT,
    TCP_STATE_CLOSE_WAIT,
    TCP_STATE_LAST_ACK,
};

struct tcp_connection {
    struct ip4if *ip4if;
    uint16_t port; // local port
    ip4addr_t remote_ip;
    uint16_t remote_port;
    uint32_t local_seq;  // *next* byte that we will send
    uint32_t remote_seq; // *next* byte remote peer will sent
    // XXX: add delayed ACK mechanism
    enum tcp_state state : 4;
    uint16_t flags : 12;
    const struct tcp_ops *ops;
    void *user_data; // Pointer that can be used by user to preserve per-connection data
    LIST_ENTRY(tcp_connection) next;
};

struct tcp_ops {
    // Returns true if user successfully accepted the connection, false otherwise
    // If false is returned then the TCP connection will be closed and *conn pointer destroyed
    bool (*accept)(struct tcp_connection *conn);
    void (*receive)(struct tcp_connection *conn, buffer_t *buf);
    void (*finish)(struct tcp_connection *conn);
};

err_t tcp_bind(struct ip4if *ip4if, uint16_t port, const struct tcp_ops *ops);
void tcp_unbind(struct tcp_listener *listener);

void tcp_receive(struct ip4if *ip4if, ip4addr_t src_ip, buffer_t *buf);
void tcp_send(struct tcp_connection *conn, buffer_t *buf);
void tcp_close(struct tcp_connection *conn);