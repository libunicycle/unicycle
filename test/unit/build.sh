#!/bin/sh
# SPDX-License-Identifier: MIT

set -e

CC=${CC:-gcc}

$CC -g -W -Wall -Wextra -Wno-incompatible-library-redeclaration -iquote ../acutest -iquote ../../include -iquote . ./allocator_test.c ../../core/alloc/buddy.c ../../core/alloc/slab.c -o allocator_test
./allocator_test
