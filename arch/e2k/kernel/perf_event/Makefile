 # SPDX-License-Identifier: GPL-2.0
 # Copyright (c) 2023 MCST
 
ifdef CONFIG_FUNCTION_TRACER
# Do not profile debug and lowlevel utilities
CFLAGS_REMOVE_perf_event.o = -pg
CFLAGS_REMOVE_uncore.o = -pg
CFLAGS_REMOVE_uncore_sic.o = -pg
CFLAGS_REMOVE_uncore_hmu.o = -pg
CFLAGS_REMOVE_uncore_iommu.o = -pg
CFLAGS_REMOVE_uncore_hc.o = -pg
CFLAGS_REMOVE_uncore_mc.o = -pg
CFLAGS_REMOVE_uncore_prepic.o = -pg
endif

obj-y := perf_event.o uncore.o uncore_sic.o uncore_hmu.o uncore_iommu.o \
	 uncore_hc.o uncore_mc.o uncore_prepic.o dimtp_trace.o
