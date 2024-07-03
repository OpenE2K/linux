 # SPDX-License-Identifier: GPL-2.0
 # Copyright (c) 2023 MCST
 
GCOV_PROFILE := n

obj-y := boot_iset_v3.o boot_iset_v6.o

CFLAGS_REMOVE_boot_iset_v3.o = $(CFLAGS_ALL_CPUS)
CFLAGS_REMOVE_boot_iset_v6.o = $(CFLAGS_ALL_CPUS)

CFLAGS_boot_iset_v3.o := -march=elbrus-v3
CFLAGS_boot_iset_v6.o := -march=elbrus-v6

CFLAGS_e2s.o			= $(CFLAGS_E2S)
CFLAGS_e8c.o			= $(CFLAGS_E8C)
CFLAGS_e1cp.o			= $(CFLAGS_E1CP)
CFLAGS_e8c2.o			= $(CFLAGS_E8C2)
CFLAGS_e12c.o			= $(CFLAGS_E12C)
CFLAGS_e16c.o			= $(CFLAGS_E16C)
CFLAGS_e2c3.o			= $(CFLAGS_E2C3)
CFLAGS_e48c.o			= $(CFLAGS_E48C)
CFLAGS_e8v7.o			= $(CFLAGS_E8V7)
obj-$(CONFIG_CPU_E2S)		+= e2s.o
obj-$(CONFIG_CPU_E8C)		+= e8c.o
obj-$(CONFIG_CPU_E1CP)		+= e1cp.o
obj-$(CONFIG_CPU_E8C2)		+= e8c2.o
obj-$(CONFIG_CPU_E12C)		+= e12c.o
obj-$(CONFIG_CPU_E16C)		+= e16c.o
obj-$(CONFIG_CPU_E2C3)		+= e2c3.o
obj-$(CONFIG_CPU_E48C)		+= e48c.o
obj-$(CONFIG_CPU_E8V7)		+= e8v7.o
