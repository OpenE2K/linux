#
# Makefile for the Elbrus linux kernel.
# /arch/l/kernel
#
obj-y += iommu.o procshow.o mpparse.o setup.o
obj-y += apic/

obj-$(CONFIG_L_PMC) += pmc.o
obj-$(CONFIG_SERIAL_PRINTK) += console.o
obj-$(CONFIG_L_LOCAL_APIC) += lt.o
obj-$(CONFIG_L_SIC_IPLINK_OFF) += procipcc2.o
obj-$(CONFIG_SERIAL_AM85C30_CONSOLE) += am85c30.o
obj-$(CONFIG_SERIAL_NS16550_CONSOLE) += ns16550.o
obj-$(CONFIG_E2K) += nmi.o
obj-$(CONFIG_CLKR_CLOCKSOURCE) += clkr.o
CFLAGS_sclkr.o += -mcpu=elbrus-4c
obj-$(CONFIG_SCLKR_CLOCKSOURCE) += sclkr.o
obj-$(CONFIG_SCLKR_CLOCKSOURCE) += proc_sclkr.o
obj-$(CONFIG_SCLKR_CLOCKSOURCE) += sclkr_init.o
obj-$(CONFIG_IOHUB_GPIO) += gpio.o
obj-$(CONFIG_BOOT_TRACE) += boot_profiling.o
obj-$(CONFIG_I2C_SPI_RESET_CONTROLLER) += i2c-spi/
obj-$(CONFIG_ACPI) += acpi/
obj-$(CONFIG_ACPI_L_SPMC) += acpi_tainted/
#obj-$(CONFIG_LTT) += ltt_trace.o

ifdef CONFIG_FUNCTION_TRACER
# Do not profile debug and lowlevel utilities
  CFLAGS_REMOVE_console.o = -pg 
  CFLAGS_REMOVE_am85c30.o = -pg 
  CFLAGS_REMOVE_ns16550.o = -pg 
endif
