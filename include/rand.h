// SPDX-License-Identifier: MIT

#pragma once

#include <stddef.h>
#include <stdint.h>

// This method increases entropy of RNG by using CPU jitter information
void rand_mixin_cpu_jitter(void);

uint8_t rand8(void);
uint16_t rand16(void);
uint32_t rand32(void);
uint64_t rand64(void);
// generates double between 0 and 1
double rand_double(void);
void rand_array(void *array, size_t length);