# SPDX-License-Identifier: GPL-2.0
#
# Makefile for local APIC drivers and for the IO-APIC code
#

# Leads to non-deterministic coverage that is not a function of syscall inputs.
# In particular, smp_apic_timer_interrupt() is called in random places.
KCOV_INSTRUMENT		:= n

obj-y += vector.o pic_irq.o pic.o io_pic.o

obj-$(CONFIG_PCI_MSI)		+= msi.o
obj-$(CONFIG_SMP)		+= pic_smp.o

obj-$(CONFIG_L_LOCAL_APIC)	+= apic/
obj-$(CONFIG_EPIC)	+= epic/
