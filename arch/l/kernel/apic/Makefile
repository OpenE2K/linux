#
# Makefile for local APIC drivers and for the IO-APIC code
#

obj-$(CONFIG_L_LOCAL_APIC)	+= apic.o ipi.o irq.o probe_64.o
obj-$(CONFIG_L_IO_APIC)		+= io_apic.o
obj-$(CONFIG_L_X86_64)		+= apic_flat_64.o
obj-$(CONFIG_SMP)		+= smp.o
obj-$(CONFIG_IRQ_WORK)		+= irq_work.o
