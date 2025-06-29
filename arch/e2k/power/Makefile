# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2023 MCST

KASAN_SANITIZE_hibernate.o := n

subdir-ccflags-y += -Werror -Wswitch -Wenum-compare -Wmaybe-uninitialized

obj-$(CONFIG_PM_SLEEP)		+= cpu.o
obj-$(CONFIG_HIBERNATION)	+= hibernate.o
