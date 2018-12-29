// SPDX-License-Identifier: MIT

#pragma once

#include "buffer.h"
#include "net/eth.h"
#include "net/ip4.h"
#include <stdbool.h>

void arp_receive(struct eth_device *eth, buffer_t *buff);
void arp_cache_add(ip4addr_t ip, ethaddr_t eth);
// looks up MAC address by given ip address
// if ip address found in ARP cache then it fills in eth structure
// and return true. Otherwise it return false.
bool arp_cache_lookup(ip4addr_t ip, ethaddr_t *eth);