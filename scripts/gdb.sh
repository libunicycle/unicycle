#!/bin/sh

CMD=gdb
#TOOLCHAIN_GDB=../toolchains/x86_64-elf-7.3.0-Linux-x86_64/bin/x86_64-elf-gdb

if [ -f "$TOOLCHAIN_GDB" ]
then
  CMD=$TOOLCHAIN_GDB
fi

$CMD --command=scripts/gdb.init
