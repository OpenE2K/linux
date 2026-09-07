# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2023 MCST

#
# Makefile for local APIC drivers and for the IO-APIC code
#

# Leads to non-deterministic coverage that is not a function of syscall inputs.

obj-$(CONFIG_L_LOCAL_APIC)	+= apic.o apic_timer.o apic_nmi.o \
				   apic_irqchip.o apic_lvt.o debug.o

obj-$(CONFIG_L_IO_APIC)	+= io_apic.o

obj-$(CONFIG_SMP)		+= apic_ipi.o

