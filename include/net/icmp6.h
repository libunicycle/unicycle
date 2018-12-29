// SPDX-License-Identifier: MIT

#pragma once

#include "buffer.h"
#include <stdbool.h>

struct ip4if;
bool icmp6_receive(struct ip4if *ip4if, buffer_t *buf);