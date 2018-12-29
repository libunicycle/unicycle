// SPDX-License-Identifier: MIT

#include "net/dhcp.h"
#include "arch.h"
#include "compiler.h"
#include "mem.h"
#include "net/eth.h"
#include "net/ip4.h"
#include "net/udp.h"
#include "rand.h"
#include "string.h"
#include <stdint.h>

#define OP_BOOTREQUEST 1
#define OP_BOOTREPLY 2

// https://tools.ietf.org/html/rfc1700
#define HTYPE_ETH 1

struct __be PACKED dhcp_pkt {
    uint8_t op;
    uint8_t htype;
    uint8_t hlen; // mac address length, 6 for ethernet
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    ip4addr_t ciaddr;
    ip4addr_t yiaddr;
    ip4addr_t siaddr;
    ip4addr_t giaddr;
    uint8_t chaddr[16];
    char sname[64]; // server name
    char file[128];
    // options
};

struct __be PACKED dhcp_option {
    uint8_t code;
    uint8_t length;
    uint8_t data[];
};

enum dhcp_state {
    STATE_INIT,
    STATE_SELECTING,
    STATE_REQUESTING,
    STATE_INIT_REBOOT,
    STATE_REBOOTING,
    STATE_BOUND,
    STATE_RENEWING,
    STATE_REBINDING,
};

#define DHCP_PORT_SERVER 67
#define DHCP_PORT_CLIENT 68

#define DHCP_FLAG_BROADCAST BIT(15)

#define DHCP_OPTIONS_MAGIC 0x63825363

#define DHCP_CODE_PAD 0                // padding, length 0
#define DHCP_CODE_SUBNET_MASK 1        // length 4
#define DHCP_CODE_ROUTER 3             // length 4 * N
#define DHCP_CODE_HOSTNAME 12          // length N
#define DHCP_CODE_REQUESTED_IP_ADDR 50 // length 4
#define DHCP_CODE_LEASE_TIME 51        // length 4
#define DHCP_CODE_MSGTYPE 53           // length 1
#define DHCP_CODE_SERVER 54            // length 4
#define DHCP_CODE_REQUESTED_PARAM_LIST 55
#define DHCP_CODE_CLIENT_IDENTIFIER 61 // length type + sizeof(addr)
#define DHCP_CODE_END 255              // length 1

// options DHCP_CODE_MSGTYPE data
#define DHCP_MSGTYPE_DHCPDISCOVER 1
#define DHCP_MSGTYPE_DHCPOFFER 2
#define DHCP_MSGTYPE_DHCPREQUEST 3
#define DHCP_MSGTYPE_DHCPDECLINE 4
#define DHCP_MSGTYPE_DHCPACK 5
#define DHCP_MSGTYPE_DHCPNAK 6
#define DHCP_MSGTYPE_DHCPRELEASE 7
#define DHCP_MSGTYPE_DHCPINFORM 8

#define DEFAULT_LEASE_TIME (24 * 3600) // 1 day

static enum dhcp_state state = STATE_INIT;
static uint32_t transaction_id;

static void dhcp_send_request(struct ip4if *ip4if, uint8_t code) {
    buffer_t *out = buffer_allocate(BUFFER_NET_SIZE, HDR_LEN_UDP);

    struct dhcp_pkt *pkt = out->pos;
    memzero(pkt);

    pkt->op = OP_BOOTREQUEST;
    pkt->htype = HTYPE_ETH;
    pkt->hlen = sizeof(ethaddr_t);
    pkt->xid = transaction_id;
    pkt->flags = DHCP_FLAG_BROADCAST;

    struct eth_device *eth = ip4if->eth_dev(ip4if);
    ethaddr_cpy(&pkt->chaddr[0], &eth->addr.addr[0]);

    // fill options
    void *options = (void *)pkt + sizeof(struct dhcp_pkt);
    *(uint32_t *)options = cpu_to_be((uint32_t)DHCP_OPTIONS_MAGIC);
    options += 4;

    // msg type - discover
    *(uint8_t *)options++ = DHCP_CODE_MSGTYPE;
    *(uint8_t *)options++ = 1;
    *(uint8_t *)options++ = code;

    // msg type - client identifier
    *(uint8_t *)options++ = DHCP_CODE_CLIENT_IDENTIFIER;
    *(uint8_t *)options++ = 7;
    *(uint8_t *)options++ = HTYPE_ETH;
    ethaddr_cpy(options, &eth->addr.addr[0]);
    options += sizeof(ethaddr_t);

    // msg type - request ip addr
    *(uint8_t *)options++ = DHCP_CODE_REQUESTED_IP_ADDR;
    *(uint8_t *)options++ = sizeof(ip4addr_t);
    *(ip4addr_t *)options = 0;
    options += sizeof(ip4addr_t);

    // msg type - request params
    *(uint8_t *)options++ = DHCP_CODE_REQUESTED_PARAM_LIST;
    *(uint8_t *)options++ = 3;
    *(uint8_t *)options++ = DHCP_CODE_SUBNET_MASK;
    *(uint8_t *)options++ = DHCP_CODE_ROUTER;
    *(uint8_t *)options++ = DHCP_CODE_LEASE_TIME;

    // msg type - end
    *(uint8_t *)options++ = DHCP_CODE_END;

    out->data_size += (options - (void *)pkt);
    udp_send(ip4if, out, IPADDR_BROADCAST, DHCP_PORT_CLIENT, DHCP_PORT_SERVER);
}

static void udp_dhcp_handle(struct udp_listener *listener, buffer_t *buf) {
    struct dhcp_pkt *pkt = buf->pos;
    void *pkt_end = buf->area + buf->data_size;

    if (pkt->xid != transaction_id)
        return;

    // XXX verify received HW addr

    if (state == STATE_SELECTING) {
        // select the first offer

        // verify the msg type
        void *options = (void *)pkt + sizeof(struct dhcp_pkt);
        if (*(uint32_t *)options != cpu_to_be((uint32_t)DHCP_OPTIONS_MAGIC))
            return;
        options += 4;

        while (true) {
            uint8_t code = *(uint8_t *)options++;
            if (code == DHCP_CODE_PAD) {
                continue;
            } else if (code == DHCP_CODE_END) {
                break;
            } else if (code == DHCP_CODE_MSGTYPE) {
                options++; // length that is always 1
                uint8_t type = *(uint8_t *)options++;

                if (type != DHCP_MSGTYPE_DHCPOFFER)
                    continue;

                state = STATE_REQUESTING;
                dhcp_send_request(listener->ip4if, DHCP_MSGTYPE_DHCPREQUEST);
            }
        }
    } else if (state == STATE_REQUESTING) {
        ip4addr_t server_addr = pkt->siaddr;
        ip4addr_t client_addr = pkt->yiaddr;
        ip4addr_t router_addr;
        ip4addr_t mask;
        uint32_t lease_time; // default lease time is 1 day
        bool bound = false;

        void *options = (void *)pkt + sizeof(struct dhcp_pkt);
        if (*(uint32_t *)options != cpu_to_be((uint32_t)DHCP_OPTIONS_MAGIC))
            return;
        options += 4;

        while (true) {
            uint8_t code = *(uint8_t *)options++;
            if (options > pkt_end)
                break; // length points outside of the packet data

            // special non-length options padding and ending
            if (code == DHCP_CODE_PAD) {
                continue;
            } else if (code == DHCP_CODE_END) {
                break;
            }

            uint8_t length = *(uint8_t *)options++;
            if (options + length > pkt_end)
                break; // the option length is more than the packet length

            if (code == DHCP_CODE_MSGTYPE) {
                if (length != 1)
                    continue;
                uint8_t type = *(uint8_t *)options;
                bound = (type == DHCP_MSGTYPE_DHCPACK);
            } else if (code == DHCP_CODE_ROUTER) {
                if (length != 4)
                    continue;
                router_addr = be_to_cpu(*(ip4addr_t *)options);
            } else if (code == DHCP_CODE_SUBNET_MASK) {
                if (length != 4)
                    continue;
                mask = be_to_cpu(*(ip4addr_t *)options);
            } else if (code == DHCP_CODE_LEASE_TIME) {
                if (length != 4)
                    continue;
                lease_time = be_to_cpu(*(uint32_t *)options);
            } else if (code == DHCP_CODE_HOSTNAME) {
                IFD printf("Hostname is '%.*s'\n", length, (char *)options);
            } else {
                IFD printf("Unrecognized DHCP option at offset %lx code %d length %d\n",
                           (uintptr_t)options - 2 - (uintptr_t)pkt + HDR_LEN_UDP, code, length);
            }
            options += length;
        }

        if (bound) {
            state = STATE_BOUND;
            struct ip4if *ip4if = listener->ip4if;

            ip4if->dhcp_server_addr = server_addr;
            ip4if->addr = client_addr;
            ip4if->mask = mask;
            ip4if->router_addr = router_addr;
            ip4if->dhcp_lease_time = lease_time;

            IFD printf("DHCP lease acquired ip=" IPADDR_PRINT_FMT " mask=" IPADDR_PRINT_FMT " server=" IPADDR_PRINT_FMT
                       " router=" IPADDR_PRINT_FMT " leasetime=%d sec\n",
                       IPADDR_PRINT_PARAMS(ip4if->addr), IPADDR_PRINT_PARAMS(ip4if->mask), IPADDR_PRINT_PARAMS(ip4if->dhcp_server_addr),
                       IPADDR_PRINT_PARAMS(ip4if->router_addr), ip4if->dhcp_lease_time);

            ip4if_init_complete(ip4if);
        }

        IFD printf("Got DHCP message\n");
    }
}

void dhcp_init(struct ip4if *ip4if) {
    // TODO listen UDP port 68
    udp_bind(ip4if, DHCP_PORT_CLIENT, udp_dhcp_handle);

    do {
        transaction_id = rand32();
        IFD SHOUT_IF(!transaction_id, "Transaction ID can't be zero");
    } while (!transaction_id);

    state = STATE_SELECTING;
    dhcp_send_request(ip4if, DHCP_MSGTYPE_DHCPDISCOVER);
}