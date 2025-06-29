# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2023 MCST

#
# Makefile for the Elbrus linux kernel.
# /arch/l/kernel
#
obj-y += procshow.o mpparse.o setup.o procregs.o \
	l-mcmonitor.o cpufreq.o clk_rt.o
obj-y += pmc/
obj-y += irq/

obj-$(CONFIG_L_EARLY_PRINTK) += console.o
KASAN_SANITIZE_console.o := n
obj-$(CONFIG_NVRAM_PANIC) += panic2nvram.o
obj-$(CONFIG_L_LOCAL_APIC) += lt.o
obj-$(CONFIG_SERIAL_AM85C30_CONSOLE) += am85c30.o
KASAN_SANITIZE_am85c30.o := n
obj-$(CONFIG_CLKR_CLOCKSOURCE) += clkr.o

obj-$(CONFIG_BOOT_TRACE) += boot_profiling.o

ifdef CONFIG_FUNCTION_TRACER
# Do not profile debug and lowlevel utilities
  CFLAGS_REMOVE_console.o = -pg 
  CFLAGS_REMOVE_am85c30.o = -pg 
  CFLAGS_REMOVE_ns16550.o = -pg 
endif
