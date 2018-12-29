// SPDX-License-Identifier: MIT

#pragma once

#include "buffer.h"
#include <stdbool.h>

struct ip4if;
struct ip4_hdr;
void icmp_receive(struct ip4if *ip4if, buffer_t *buf);