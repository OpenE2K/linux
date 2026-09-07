# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2023 MCST

ccflags-remove-$(CONFIG_FUNCTION_TRACER) += $(CC_FLAGS_FTRACE)

obj-y := perf_event.o uncore.o uncore_sic.o uncore_l3_v6.o uncore_l3_v7.o uncore_hmu.o \
	 uncore_iommu.o uncore_hc.o uncore_mc.o uncore_prepic.o uncore_ha.o dimtp_trace.o
