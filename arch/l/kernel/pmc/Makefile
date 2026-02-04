# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2023 MCST

obj-$(CONFIG_L_PMC)	:= pmc.o
pmc-$(CONFIG_L_PMC)	:= pmc_drv.o pmc_hwmon.o
pmc-$(CONFIG_CPU_FREQ)	+= pmc_e1cp.o pmc_cpufreq.o
obj-$(CONFIG_S2_PMC)	:= pmc.o
pmc-$(CONFIG_S2_PMC)	:= pmc_drv.o pmc_hwmon.o pmc_s2.o
