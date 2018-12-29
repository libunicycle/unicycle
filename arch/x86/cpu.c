// SPDX-License-Identifier: MIT

#include "cpu.h"
#include "apic.h"
#include "x86.h"

size_t cpu_nodes_num = 0;
struct cpu_node *cpu_nodes = NULL;

PERCPU uint32_t current_cpu_id;
uint32_t bootstrap_cpu_id;

uint64_t cpu_cycles(void) { return x86_rdtsc(); }

uint32_t cpu_id_get(void) {
    uint32_t apic_id = apic_cpu_id();
    for (size_t i = 0; i < cpu_nodes_num; i++) {
        if (cpu_nodes[i].apic_id == apic_id)
            return i;
    }
    PANIC("Current CPU node with apic_id=%d is not registered", apic_id);
}
