# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2023 MCST

#
# Makefile for E2K-specific library files
#

obj-y = delay.o usercopy.o builtin.o checksum.o

# Put these two together (they reference each other so should be close
# in memory, in the same page if possible)
obj-y += string.o recovery_string.o

# Remove profiling from low-level functions as they are used by arch/e2k/p2v/
CFLAGS_REMOVE_string.o = $(CC_FLAGS_FTRACE)
