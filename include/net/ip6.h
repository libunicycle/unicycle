// SPDX-License-Identifier: MIT

#pragma once

#include "buffer.h"
#include <stdbool.h>

struct ip6if {};

void ip6_receive(struct ip6if *ip6if, buffer_t *buff);
