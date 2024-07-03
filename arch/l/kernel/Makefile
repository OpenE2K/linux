 # SPDX-License-Identifier: GPL-2.0
 # Copyright (c) 2023 MCST
 
#
# Makefile for the Elbrus linux kernel.
# /arch/l/kernel
#
obj-y += l-i2c2.o l-iommu.o procshow.o mpparse.o setup.o procregs.o \
	l-mcmonitor.o pic_irq.o cpufreq.o clk_rt.o
obj-y += apic/
obj-y += pmc/

obj-$(CONFIG_L_EARLY_PRINTK) += console.o
obj-$(CONFIG_NVRAM_PANIC) += panic2nvram.o
obj-$(CONFIG_L_LOCAL_APIC) += lt.o
obj-$(CONFIG_SERIAL_AM85C30_CONSOLE) += am85c30.o
obj-$(CONFIG_CLKR_CLOCKSOURCE) += clkr.o

obj-$(CONFIG_IOHUB_GPIO) += gpio.o
obj-$(CONFIG_BOOT_TRACE) += boot_profiling.o
obj-$(CONFIG_I2C_SPI_RESET_CONTROLLER) += i2c-spi/
obj-$(CONFIG_ACPI) += acpi/
obj-$(CONFIG_ACPI_L_SPMC) += acpi_tainted/
obj-$(CONFIG_OF) += devtree.o
obj-$(CONFIG_EPIC) += epic/

ifdef CONFIG_FUNCTION_TRACER
# Do not profile debug and lowlevel utilities
  CFLAGS_REMOVE_console.o = -pg 
  CFLAGS_REMOVE_am85c30.o = -pg 
  CFLAGS_REMOVE_ns16550.o = -pg 
endif
