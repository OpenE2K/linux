# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2023 MCST

#
# Makefile for "Physical-to-Virtual Switch".
#

KASAN_SANITIZE := n
GCOV_PROFILE := n

subdir-ccflags-y := -DE2K_P2V -fno-semi-spec-ld -fno-spec-ld \
		    -ftrivial-auto-var-init=uninitialized
ccflags-remove-$(CONFIG_FUNCTION_TRACER) += $(CC_FLAGS_FTRACE) -fprofile-generate-kernel

obj-y = boot_head.o boot_init.o boot_map.o boot_phys.o boot_param.o \
	boot_string.o boot_find_bit.o boot_e2k_sic.o machdep.o pic.o \
	boot_printk/ cpu/

obj-$(CONFIG_SMP)		+= boot_smp.o
obj-$(CONFIG_RECOVERY)		+= boot_recovery.o
obj-$(CONFIG_BOOT_TRACE)	+= boot_profiling.o
