# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2023 MCST

KASAN_SANITIZE := n
GCOV_PROFILE := n

ccflags-remove-$(CONFIG_FUNCTION_TRACER) += $(CC_FLAGS_FTRACE)
ccflags-remove-y += -fprofile-generate-kernel

obj-$(CONFIG_SERIAL_AM85C30_BOOT_CONSOLE) += am85c30.o
obj-$(CONFIG_BOOT_PRINTK) += console.o
obj-$(CONFIG_EARLY_VIRTIO_CONSOLE) += boot_hvc_l.o
