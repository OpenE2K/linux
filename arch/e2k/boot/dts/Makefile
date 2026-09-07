# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2023 MCST

# enable creation of __symbols__ node
# DTC_FLAGS += -@

DTC_CPP_FLAGS += -D LINUX_PATCH

DTC_CPP_FLAGS_e2s_a1s1_1x1 += -D NODES=1
DTC_CPP_FLAGS_e2s_a1s1_2x2 += -D NODES=2
DTC_CPP_FLAGS_e2s_a1s1_4x4 += -D NODES=4

DTC_CPP_FLAGS_e2s_a2s2_1x1 += -D NODES=1 -D CELLS=2 -DSIZE_CELLS=2
DTC_CPP_FLAGS_e2s_a2s2_2x2 += -D NODES=2 -D CELLS=2 -DSIZE_CELLS=2
DTC_CPP_FLAGS_e2s_a2s2_4x4 += -D NODES=4 -D CELLS=2 -DSIZE_CELLS=2

DTC_CPP_FLAGS_e8c_a1s0_1x1 += -D NODES=1 -DSIZE_CELLS=0
DTC_CPP_FLAGS_e8c_a1s0_2x2 += -D NODES=2 -DSIZE_CELLS=0
DTC_CPP_FLAGS_e8c_a1s0_4x4 += -D NODES=4 -DSIZE_CELLS=0

DTC_CPP_FLAGS_e8c_a1s1_1x1 += -D NODES=1 -DSIZE_CELLS=1
DTC_CPP_FLAGS_e8c_a1s1_2x2 += -D NODES=2 -DSIZE_CELLS=1
DTC_CPP_FLAGS_e8c_a1s1_4x4 += -D NODES=4 -DSIZE_CELLS=1

DTC_CPP_FLAGS_e8c_a2s2_1x1 += -D NODES=1 -D CELLS=2 -DSIZE_CELLS=2
DTC_CPP_FLAGS_e8c_a2s2_2x2 += -D NODES=2 -D CELLS=2 -DSIZE_CELLS=2
DTC_CPP_FLAGS_e8c_a2s2_4x4 += -D NODES=4 -D CELLS=2 -DSIZE_CELLS=2

DTC_CPP_FLAGS_e1cp_a2s2 += -D NODES=1 -D CELLS=2 -DSIZE_CELLS=2

DTC_CPP_FLAGS_e8c2_a1s0_1x1 += -D NODES=1 -DSIZE_CELLS=0
DTC_CPP_FLAGS_e8c2_a1s0_2x2 += -D NODES=2 -DSIZE_CELLS=0
DTC_CPP_FLAGS_e8c2_a1s0_4x4 += -D NODES=4 -DSIZE_CELLS=0

DTC_CPP_FLAGS_e8c2_a1s1_1x1 += -D NODES=1 -DSIZE_CELLS=1
DTC_CPP_FLAGS_e8c2_a1s1_2x2 += -D NODES=2 -DSIZE_CELLS=1
DTC_CPP_FLAGS_e8c2_a1s1_4x4 += -D NODES=4 -DSIZE_CELLS=1

DTC_CPP_FLAGS_e8c2_a2s2_1x1 += -D NODES=1 -D CELLS=2 -DSIZE_CELLS=2
DTC_CPP_FLAGS_e8c2_a2s2_2x2 += -D NODES=2 -D CELLS=2 -DSIZE_CELLS=2
DTC_CPP_FLAGS_e8c2_a2s2_4x4 += -D NODES=4 -D CELLS=2 -DSIZE_CELLS=2

DTC_CPP_FLAGS_e16c_a1s1_1x1 += -D NODES=1 -D E16C
DTC_CPP_FLAGS_e16c_a1s1_2x2 += -D NODES=2 -D E16C
DTC_CPP_FLAGS_e16c_a1s1_4x4 += -D NODES=4 -D E16C

DTC_CPP_FLAGS_e16c_a2s2_1x1 += -D NODES=1 -D CELLS=2
DTC_CPP_FLAGS_e16c_a2s2_2x2 += -D NODES=2 -D CELLS=2
DTC_CPP_FLAGS_e16c_a2s2_4x4 += -D NODES=4 -D CELLS=2

DTC_CPP_FLAGS_e2c3_a1s1 += -D NODES=1 -D E2C3
DTC_CPP_FLAGS_e2c3_a2s2 += -D NODES=1 -D E2C3 -D CELLS=2


obj-y	 := default.dtb.o

obj-$(CONFIG_CPU_E2S) += e2s_a1s1_1x1.dtb.o e2s_a1s1_2x2.dtb.o e2s_a1s1_4x4.dtb.o \
		e2s_a2s2_1x1.dtb.o e2s_a2s2_2x2.dtb.o e2s_a2s2_4x4.dtb.o
obj-$(CONFIG_CPU_E1CP) += e1cp_a1s1.dtb.o e1cp_a2s2.dtb.o
obj-$(CONFIG_CPU_E2C3) += e2c3_a1s1.dtb.o e2c3_a2s2.dtb.o
obj-$(CONFIG_KVM) += epic-guest.dtb.o apic-guest.dtb.o

ifneq ($(filter y,$(CONFIG_CPU_E8C)),)
obj-y += e8c_a1s0_1x1.dtb.o e8c_a1s0_2x2.dtb.o e8c_a1s0_4x4.dtb.o
obj-y += e8c_a1s1_1x1.dtb.o e8c_a1s1_2x2.dtb.o e8c_a1s1_4x4.dtb.o
obj-y += e8c_a2s2_1x1.dtb.o e8c_a2s2_2x2.dtb.o e8c_a2s2_4x4.dtb.o
endif
ifneq ($(filter y,$(CONFIG_CPU_E8C2)),)
obj-y += e8c2_a1s0_1x1.dtb.o e8c2_a1s0_2x2.dtb.o e8c2_a1s0_4x4.dtb.o
obj-y += e8c2_a1s1_1x1.dtb.o e8c2_a1s1_2x2.dtb.o e8c2_a1s1_4x4.dtb.o
obj-y += e8c2_a2s2_1x1.dtb.o e8c2_a2s2_2x2.dtb.o e8c2_a2s2_4x4.dtb.o
endif
ifneq ($(filter y,$(CONFIG_CPU_E12C) $(CONFIG_CPU_E16C)),)
obj-y += e16c_a1s1_1x1.dtb.o e16c_a1s1_2x2.dtb.o e16c_a1s1_4x4.dtb.o
obj-y += e16c_a2s2_1x1.dtb.o e16c_a2s2_2x2.dtb.o e16c_a2s2_4x4.dtb.o
endif
ifneq ($(filter y,$(CONFIG_CPU_E8V7)),)
obj-y += e8v7_a2s2.dtb.o
endif
