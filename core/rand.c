// SPDX-License-Identifier: MIT

#include "rand.h"
#include "compiler.h"
#include "cpu.h"
#include "sha3.h"
#include "shout.h"
#include "stdio.h"

// Pseudo Random Generator based on maximally equidistributed combined lfsr generator algorithm
// See http://www.ams.org/journals/mcom/1999-68-225/S0025-5718-99-01039-X/S0025-5718-99-01039-X.pdf

PERCPU uint64_t st[5];

#define c1 0xFFFFFFFFFFFFFFFEULL // 18446744073709551614ULL
#define c2 0xFFFFFFFFFFFFFE00ULL // 18446744073709551104ULL
#define c3 0xFFFFFFFFFFFFF000ULL // 18446744073709547520ULL
#define c4 0xFFFFFFFFFFFE0000ULL // 18446744073709420544ULL
#define c5 0xFFFFFFFFFF800000ULL // 18446744073701163008ULL

static uint64_t lfsr258(void) {
    st[0] = ((st[0] & c1) << 10) ^ (((st[0] << 1) ^ st[0]) >> 53);
    st[1] = ((st[1] & c2) << 5) ^ (((st[1] << 24) ^ st[1]) >> 50);
    st[2] = ((st[2] & c3) << 29) ^ (((st[2] << 3) ^ st[2]) >> 23);
    st[3] = ((st[3] & c4) << 23) ^ (((st[3] << 5) ^ st[3]) >> 24);
    st[4] = ((st[4] & c5) << 8) ^ (((st[4] << 3) ^ st[4]) >> 33);
    return st[0] ^ st[1] ^ st[2] ^ st[3] ^ st[4];
}

uint64_t rand64(void) { return lfsr258(); }
uint32_t rand32(void) { return (uint32_t)lfsr258(); }
uint16_t rand16(void) { return (uint16_t)lfsr258(); }
uint8_t rand8(void) { return (uint8_t)lfsr258(); }
double rand_double(void) { return lfsr258() * 5.4210108624275221e-20; }

void rand_array(void *array, size_t length) {
    for (; length >= sizeof(uint64_t); length -= sizeof(uint64_t)) {
        *(uint64_t *)array = rand64();
    }
    for (; length >= sizeof(uint8_t); length -= sizeof(uint8_t)) {
        *(uint8_t *)array = rand8();
    }
}

#define CYCLES_ENTROPY_SIZE 64

// Modern multiscalar, out-of-order CPUs are devices with a large number of hardware blocks.
// Examples of hardware blocks are: TLB cache, write buffer, branch prediction, hyperthreading,
// pipeline, memory controller.
// And each block has a complex internal state that affects instruction execution time.
// It is hard to predict instructions execution time unless one has a full access to CPU internal state.
// See more information here http://www.chronox.de/jent/doc/CPU-Jitter-NPTRNG.html
// We can use instruction execution time jitter as a source of entropy for our Random Number Generator.
void rand_mixin_cpu_jitter(void) {
    sha3_context ctx;
    sha3_Init512(&ctx);

    uint64_t entropy_buffer[CYCLES_ENTROPY_SIZE];

    for (int i = 0; i < CYCLES_ENTROPY_SIZE; i++) {
        // Each call to cpu_cycles() has execution time jitter. It is going to be used as a source of entropy.
        // Bigger CYCLES_ENTROPY_SIZE more entropy will be added.
        // Leter we use a hash alrorithm to whitening entropy of this array.
        entropy_buffer[i] = cpu_cycles();
    }
    // Use cryptographically strong hash algorithm (SHA3) to whitening CPU cycle jitter
    sha3_Update(&ctx, &entropy_buffer, sizeof(entropy_buffer));
    sha3_Finalize(&ctx); // SHA3 algorithm results in 25 64-bit words

    // Mixing in the whitened entropy
    size_t i, c;
    for (i = 0, c = 0; i < ARRAY_SIZE(st); i++) {
        do {
            st[i] ^= ctx.s[c++];
            // LSFR generator needs a non zero value for its state, otherwise it generates only zeros
            // if st[i] is zero let's get the next word from jitter entropy and XOR it with state again
        } while (!st[i] && c < ARRAY_SIZE(ctx.s));

        if (c == ARRAY_SIZE(ctx.s)) {
            SHOUT_IF(i < ARRAY_SIZE(st), "Whitening entropy ran out of data\n");
            break;
        }
    }
}