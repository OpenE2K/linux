 # SPDX-License-Identifier: GPL-2.0
 # Copyright (c) 2023 MCST
 
#
# Makefile for E2K-specific library files
#

subdir-ccflags-y := -Werror -Wswitch -Wenum-compare

lib-y = delay.o usercopy.o builtin.o checksum.o

# Put these two together (they reference each other so should be close
# in memory, in the same page if possible)
lib-y += string.o recovery_string.o

# Remove -pg from low-level functions as they are used by arch/e2k/p2v/
CFLAGS_REMOVE_string.o = -pg

CFLAGS_usercopy.o = $(call cc-option,-fno-semi-spec-ld)
