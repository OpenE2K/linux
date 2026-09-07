# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2023 MCST

#
# Makefile for local EPIC drivers and for the IO-EPIC code
#

# Leads to non-deterministic coverage that is not a function of syscall inputs.
# In particular, smp_apic_timer_interrupt() is called in random places.
KCOV_INSTRUMENT		:= n

obj-$(CONFIG_EPIC)	+= epic.o epic_irqchip.o epic_ipi.o epic_linp.o \
			   epic_timer.o io_epic.o epic_nmi.o debug.o

obj-$(CONFIG_SMP)	+= epic_ipi.o
