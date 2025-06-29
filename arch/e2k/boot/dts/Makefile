# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2023 MCST

# enable creation of __symbols__ node
# DTC_FLAGS += -@

DTC_CPP_FLAGS_e2s_1x1 += -D NODES=1
DTC_CPP_FLAGS_e2s_2x2 += -D NODES=2
DTC_CPP_FLAGS_e2s_4x4 += -D NODES=4

DTC_CPP_FLAGS_e8c_1x1 += -D NODES=1 -DSIZE_CELLS=0
DTC_CPP_FLAGS_e8c_2x2 += -D NODES=2 -DSIZE_CELLS=0
DTC_CPP_FLAGS_e8c_4x4 += -D NODES=4 -DSIZE_CELLS=0

DTC_CPP_FLAGS_e8c_11_1x1 += -D NODES=1 -DSIZE_CELLS=1
DTC_CPP_FLAGS_e8c_11_2x2 += -D NODES=2 -DSIZE_CELLS=1
DTC_CPP_FLAGS_e8c_11_4x4 += -D NODES=4 -DSIZE_CELLS=1

DTC_CPP_FLAGS_e16c_1x1 += -D NODES=1
DTC_CPP_FLAGS_e16c_2x2 += -D NODES=2
DTC_CPP_FLAGS_e16c_4x4 += -D NODES=4

DTC_CPP_FLAGS_e2c3 += -D NODES=1 -D GRAPHIC_DEVICES
DTC_CPP_FLAGS_e2c3_addr_cells2 += -D NODES=1 -D GRAPHIC_DEVICES -D CELLS=2


$(obj)/e2s_%.dtb: $(src)/e2s.dts FORCE
	$(call if_changed,dtb)

$(obj)/e8c_%.dtb: $(src)/e8c.dts FORCE
	$(call if_changed,dtb)

$(obj)/e2c3_%.dtb: $(src)/e2c3.dts FORCE
	$(call if_changed,dtb)

$(obj)/e16c_%.dtb: $(src)/e2c3.dts FORCE
	$(call if_changed,dtb)


obj-y	 := default.dtb.o

obj-$(CONFIG_CPU_E2S) += e2s_1x1.dtb.o e2s_2x2.dtb.o e2s_4x4.dtb.o
obj-$(CONFIG_CPU_E1CP) += e1cp.dtb.o
obj-$(CONFIG_CPU_E2C3) += e2c3.dtb.o e2c3_addr_cells2.dtb.o
obj-$(CONFIG_KVM) += epic-guest.dtb.o apic-guest.dtb.o

ifneq ($(filter y,$(CONFIG_CPU_E8C) $(CONFIG_CPU_E8C2)),)
obj-y += e8c_1x1.dtb.o e8c_2x2.dtb.o e8c_4x4.dtb.o
obj-y += e8c_11_1x1.dtb.o e8c_11_2x2.dtb.o e8c_11_4x4.dtb.o
endif
ifneq ($(filter y,$(CONFIG_CPU_E12C) $(CONFIG_CPU_E16C)),)
obj-y += e16c_1x1.dtb.o e16c_2x2.dtb.o e16c_4x4.dtb.o
endif
ifneq ($(filter y,$(CONFIG_CPU_E48C) $(CONFIG_CPU_E8V7)),)
obj-y += e48c.dtb.o
endif


