// SPDX-License-Identifier: MIT

#include "acutest.h"
#include "asan.h"

void test_asan(void) { asan_init_shadow(uintptr_t max_addr); }

TEST_LIST = {{"asan allocator", test_asan}, {NULL, NULL}};
