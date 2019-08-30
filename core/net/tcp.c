// SPDX-License-Identifier: MIT

#include "net/tcp.h"
#include "buffer.h"
#include "compiler.h"
#include "kalloc.h"
#include "mem.h"
#include "rand.h"
#include "shout.h"
#include "stdio.h"
#include <stdbool.h>

struct tcp_listener {
    struct ip4if *ip4if;
    uint16_t port;
    const struct tcp_ops *ops;
    LIST_ENTRY(tcp_listener) next;
};

struct __be PACKED tcp_hdr {
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t sequence;
    uint32_t ack;
    uint8_t data_offset : 4; // size of TCP headers in 4-byte words
    uint16_t flags : 12;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;
    // possible options
};
BUILD_PANIC_IF(sizeof(struct tcp_hdr) != HDR_LEN_TCP - HDR_LEN_IP4, "HDR_LEN_TCP is not specified correctly");

#define TCP_FLAG_FIN BIT(0)
#define TCP_FLAG_SYN BIT(1)
#define TCP_FLAG_RST BIT(2)
#define TCP_FLAG_PSH BIT(3)
#define TCP_FLAG_ACK BIT(4)
#define TCP_FLAG_URG BIT(5)
#define TCP_FLAG_ECE BIT(6)
#define TCP_FLAG_CWR BIT(7)
#define TCP_FLAG_NS BIT(8)

static void tcp_send_flags(struct tcp_connection *conn, buffer_t *buff, uint16_t flags);

static struct tcp_listener *tcp_find_listener(struct ip4if *ip4if, uint16_t port) {
    struct tcp_listener *l;
    LIST_FOREACH(l, &ip4if->tcp_listeners, next) {
        if (l->port == port) {
            return l;
        }
    }
    return NULL;
}

err_t tcp_bind(struct ip4if *ip4if, uint16_t port, const struct tcp_ops *ops) {
    PANIC_IF(!ops);

    struct tcp_listener *listener = tcp_find_listener(ip4if, port);
    if (listener)
        return E_INUSE;

    listener = kalloc(struct tcp_listener);
    memzero(listener);

    listener->ip4if = ip4if;
    listener->port = port;
    listener->ops = ops;

    LIST_INSERT_HEAD(&ip4if->tcp_listeners, listener, next);

    return SUCCESS;
}

void tcp_unbind(struct tcp_listener *listener) { LIST_REMOVE(listener, next); }

void tcp_receive(struct ip4if *ip4if, ip4addr_t src_ip, buffer_t *buff) {
    struct tcp_hdr *hdr = buff->pos;
    size_t data_offset = hdr->data_offset * 4;

    if (hdr->data_offset < 5) {
        IFD printf("TCP header size is too small\n");
        // tcp header is too small
        goto free_buff;
    }
    if (HDR_LEN_IP4 + data_offset > buff->data_size) {
        IFD printf("Received TCP data size is smaller than specified in the header %ld vs %d\n", HDR_LEN_IP4 + data_offset,
                   buff->data_size);
        //  header_len points outside of valid package data, it is an invalid package
        goto free_buff;
    }

    IFD printf("TCP src_port=%u dest_port=%u sequence=%u ack=%u window_size=%u checksum=0x%x flags=0x%x\n", hdr->src_port, hdr->dest_port,
               hdr->sequence, hdr->ack, hdr->window_size, hdr->checksum, hdr->flags);

    uint16_t segment_length = buff->data_size - HDR_LEN_IP4;
    if (checksum_calculate(hdr, segment_length, IP_PROTO_TCP, src_ip, ip4if->addr) != 0) {
        IFD printf("TCP checksum failed\n");
        goto free_buff;
    }

    buff->pos += data_offset;

    struct tcp_connection *c, *conn = NULL;
    LIST_FOREACH(c, &ip4if->tcp_connections, next) {
        if (c->ip4if == ip4if && c->port == hdr->dest_port && c->remote_ip == src_ip && c->remote_port == hdr->src_port) {
            conn = c;
            break;
        }
    }

    if (!conn) {
        // no connection exists, we expect SYN segment
        if (!(hdr->flags & TCP_FLAG_SYN))
            goto free_buff;

        struct tcp_listener *listener = tcp_find_listener(ip4if, hdr->dest_port);

        if (listener) {
            // initiate new connection
            conn = kalloc(struct tcp_connection);
            conn->state = TCP_STATE_SYN_RECEIVED;
            conn->ip4if = ip4if;
            conn->port = hdr->dest_port;
            conn->remote_ip = src_ip;
            conn->remote_port = hdr->src_port;
            conn->local_seq = rand32();
            // remote peer announces its current seq number
            // but we track the *next* byte that peer send to us
            // thus increment the sequence by 1
            conn->remote_seq = hdr->sequence + 1;
            conn->ops = listener->ops;

            LIST_INSERT_HEAD(&ip4if->tcp_connections, conn, next);

            // second step of initialization handshake - return SYN+ACK
            buffer_t *out = buffer_allocate(BUFFER_NET_SIZE, HDR_LEN_TCP);
            tcp_send_flags(conn, out, TCP_FLAG_SYN);

            // SYN package sent our current sequence number, now we need to update
            // local_seq counter to point to the *next* expected byte
            conn->local_seq++;
        } else {
            // no listeners, return "connection refused error"
            IFD printf("No TCP listeners on port %d\n", hdr->dest_port);
        }
    } else {
        if (conn->state == TCP_STATE_SYN_RECEIVED) {
            if (hdr->flags & TCP_FLAG_SYN) {
                // SYN without ACK - resending SYN answer
                buffer_t *out = buffer_allocate(BUFFER_NET_SIZE, HDR_LEN_TCP);
                tcp_send_flags(conn, out, TCP_FLAG_SYN);
                // for now we just drop the invalid segment, but maybe we should send NACK back?
                goto free_buff;
            }

            // Third step of initial handshake
            if ((hdr->flags & TCP_FLAG_ACK) && conn->local_seq == hdr->ack) {
                bool accepted = conn->ops->accept(conn);
                if (!accepted) {
                    // close this TCP connection
                    LIST_REMOVE(conn, next);
                    kfree(conn);
                    goto free_buff;
                }
                conn->state = TCP_STATE_ESTABLISHED;
            } else {
                // Invalid ACK segment
                goto free_buff;
            }
        }

        if (conn->state == TCP_STATE_LAST_ACK) {
            if (hdr->flags & TCP_FLAG_ACK) {
                // close this TCP connection
                LIST_REMOVE(conn, next);
                kfree(conn);
            } else {
                // we are expecting ACK from the peer, other segments are invalid
            }
            goto free_buff;
        }

        bool consumed = false;
        uint16_t tcp_flags = hdr->flags;
        // XXX: process incoming data segments only if state is ESTABLISHED/FIN_WAIT_1/FIN_WAIT_2
        if (buff->data_size > HDR_LEN_TCP) {
            // Send ACK for received data
            // XXX: think about combining ACKs into response
            conn->remote_seq += buff->data_size - HDR_LEN_TCP;
            // buffer_t *out = buffer_allocate(BUFFER_NET_SIZE, HDR_LEN_TCP);
            // tcp_send(conn, out);

            // Note that 'buff' is freed inside the client receiver so any data associated with 'buff' (like hdr) is invalid after this
            // point.
            conn->ops->receive(conn, buff);
            consumed = true;
        }

        if (tcp_flags & TCP_FLAG_FIN) {
            conn->remote_seq++;

            // send ACK for the received FIN
            buffer_t *ack = buffer_allocate(BUFFER_NET_SIZE, HDR_LEN_TCP);
            tcp_send(conn, ack);

            conn->state = TCP_STATE_CLOSE_WAIT;

            if (conn->ops->finish) {
                conn->ops->finish(conn);
            } else {
                // default to tcp_close
                tcp_close(conn);
            }
        }

        if (consumed)
            return;
    }

free_buff:
    buffer_free(buff);
}

void tcp_close(struct tcp_connection *conn) {
    buffer_t *ack = buffer_allocate(BUFFER_NET_SIZE, HDR_LEN_TCP);
    tcp_send_flags(conn, ack, TCP_FLAG_FIN);

    conn->state = TCP_STATE_LAST_ACK;
}

static void tcp_send_flags(struct tcp_connection *conn, buffer_t *buff, uint16_t flags) {
    buff->pos -= sizeof(struct tcp_hdr);
    struct tcp_hdr *hdr = buff->pos;
    memzero(hdr);

    hdr->src_port = conn->port;
    hdr->dest_port = conn->remote_port;
    hdr->sequence = conn->local_seq;
    hdr->ack = conn->remote_seq;
    hdr->data_offset = sizeof(struct tcp_hdr) / 4;
    hdr->flags = flags | TCP_FLAG_ACK; // XXX
    hdr->window_size = 60 * 1024;      // for now we do not have any flow control, use a large window
    hdr->urgent_pointer = 0;           // XXX
    hdr->checksum = 0;                 // set it to zero before calculating checksum
    hdr->checksum = checksum_calculate(hdr, buff->data_size - HDR_LEN_IP4, IP_PROTO_TCP, conn->ip4if->addr, conn->remote_ip);

    // XXX: send data segments only if state is ESTABLISHED/CLOSE_WAIT
    size_t data_size = buff->data_size - HDR_LEN_TCP;
    conn->local_seq += data_size;

    ip4_send(conn->ip4if, buff, conn->remote_ip, IP_PROTO_TCP);
}

void tcp_send(struct tcp_connection *conn, buffer_t *buff) { tcp_send_flags(conn, buff, 0); }
