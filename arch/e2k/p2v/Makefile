# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2023 MCST

#
# Makefile for "Physical-to-Virtual Switch".
#

KASAN_SANITIZE := n
GCOV_PROFILE := n

subdir-ccflags-y := -DE2K_P2V $(call lcc-option,-fno-semi-spec-ld) \
		    $(call lcc-option,-fno-spec-ld) \
		    -ftrivial-auto-var-init=uninitialized
ccflags-remove-$(CONFIG_FUNCTION_TRACER) += $(CC_FLAGS_FTRACE)
ccflags-remove-y += -fprofile-generate-kernel

obj-y = boot_head.o boot_init.o boot_map.o boot_phys.o boot_param.o \
	boot_string.o boot_find_bit.o boot_e2k_sic.o machdep.o pic.o \
	boot_printk/ cpu/

# Silence warnings for code that will be eliminated during
# compiler optimization pass
CFLAGS_machdep.o = -Wno-shift-count-overflow -Wno-shift-count-negative

obj-$(CONFIG_SMP)		+= boot_smp.o
obj-$(CONFIG_RECOVERY)		+= boot_recovery.o
obj-$(CONFIG_BOOT_TRACE)	+= boot_profiling.o

# Do not use gregs before initialization in ttable_entry12
CFLAGS_boot_head.o := $(call lcc-option,-fno-global-regs)