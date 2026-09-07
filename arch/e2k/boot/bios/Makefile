# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2023 MCST

KASAN_SANITIZE := n
ccflags-y := -DCONFIG_BOOT_E2K -fno-semi-spec-ld -fno-spec-ld

obj-y := bios.o southbridge.o superio.o init_kbd.o newpci.o linuxpci.o io.o \
	 jumpstart.o keyboard.o romloader.o zip.o malloc.o console/stdio.o \
	 pic/epic.o string.o recovery_string.o recovery_string_v5.o cpu_features.o

CFLAGS_cpu_features.o += -Wno-shift-count-overflow -Wno-shift-count-negative

AFLAGS_REMOVE_recovery_string_v5.o = $(CFLAGS_ALL_CPUS)
AFLAGS_recovery_string_v5.o += -march=elbrus-v5

obj-$(CONFIG_ENABLE_BIOS_MPTABLE)	+= mpspec.o mptable.o
obj-$(CONFIG_ENABLE_MGA)		+= mga.o
obj-$(CONFIG_SMP) 			+= aploader.o smp.o

obj-$(CONFIG_SERIAL_AM85C30_BOOT_CONSOLE) += console/Am85C30.o
obj-$(CONFIG_VGA_CONSOLE)		+= console/vga.o
obj-$(CONFIG_LMS_CONSOLE)		+= console/console.o

obj-$(CONFIG_L_LOCAL_APIC)		+= pic/apic.o

obj-y += video/
