# SPDX-License-Identifier: MIT

#include "multiboot1.h"

.code32
.section ".multiboot.header"

#define MULTIBOOT_HEADER_FLAGS (MULTIBOOT_MEMORY_INFO | MULTIBOOT_AOUT_KLUDGE)

.type multiboot_header,STT_OBJECT
multiboot_header:
  .int MULTIBOOT_HEADER_MAGIC /* magic */
  .int MULTIBOOT_HEADER_FLAGS /* flags */
  .int -(MULTIBOOT_HEADER_MAGIC + MULTIBOOT_HEADER_FLAGS) /* checksum */

  .int multiboot_header /* header_addr */
  .int __kernel_start /* load_addr */
  .int __kernel_end /* load_end_addr */ /* TODO minus .bss .tbss */
  .int 0 /* bss_end_addr */
  .int _entry /* entry_addr */