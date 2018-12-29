// SPDX-License-Identifier: MIT

#pragma once

#include <stddef.h>
#include <stdint.h>

void memset(void *p, uint8_t c, size_t n);
void memset8(uint8_t *p, uint8_t c, size_t n);
void memset16(uint16_t *p, uint16_t c, size_t n);
void memset32(uint32_t *p, uint32_t c, size_t n);
void memset64(uint64_t *p, uint64_t c, size_t n);

void memcpy(void *dest, const void *src, size_t n);
void memcpy8(uint8_t *dest, const uint8_t *src, size_t n);
void memcpy16(uint16_t *dest, const uint16_t *src, size_t n);
void memcpy32(uint32_t *dest, const uint32_t *src, size_t n);
void memcpy64(uint64_t *dest, const uint64_t *src, size_t n);

// Clears memory specified by the pointer
// TODO: check that ptr is not void* type
#define memzero(ptr) memset(ptr, 0, sizeof(*ptr))

const void *memchr(const void *s, char c, size_t n);
const void *memrchr(const void *s, char c, size_t n);

int memcmp(const void *vl, const void *vr, size_t n);
