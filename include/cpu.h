// SPDX-License-Identifier: MIT

#pragma once

#include "compiler.h"
#include "stdio.h"
#include <stdint.h>

#define CPU_NODE_ID_INVALID ((uint32_t)-1)

struct cpu_node {
    uint32_t apic_id;
    void *percpu_area;
    bool online; // SMP initialized it
};

extern size_t cpu_nodes_num;
extern struct cpu_node *cpu_nodes;

extern PERCPU uint32_t current_cpu_id; // CPU identifier, the index in 'cpu' array
extern uint32_t bootstrap_cpu_id;

// Return value for CPU cycle counter
uint64_t cpu_cycles(void);
uint32_t cpu_id_get(void);
