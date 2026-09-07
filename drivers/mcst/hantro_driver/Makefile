# SPDX-License-Identifier: GPL-2.0
#
#    Hantro vcmd driver.
#
#    Copyright (c) 2017, VeriSilicon Inc.
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License, version 2, as
#    published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License version 2 for more details.
#
#    You may obtain a copy of the GNU General Public License
#    Version 2 at the following locations:
#    https://opensource.org/licenses/gpl-2.0.php



# Customer poring maybe need replace following macro
# PCIE_EN and VSI_FPGA_PCIE
# VSI_FPGA_MEM
# USE_CMA

include  $(srctree)/$(src)/ipoffset/project_config.mk

# Get kernel version
KERNEL_VER_MAJOR := $(VERSION)
KERNEL_VER_MINOR := $(PATCHLEVEL)

obj-m := hantrodriver.o
hantrodriver-objs = hantro_drv.o hantro_fence.o \
	vcmdswhwregisters.o bidirect_list.o devicemgr.o hantro_fs.o

hantrodriver-objs += v$(KERNEL_VER_MAJOR)/hantro_drm.o
# compile hantro_dmaduf.o only when kernel version >= 4.20
hantrodriver-objs += v$(KERNEL_VER_MAJOR)/hantro_dmabuf.o

ifeq ($(VSI_FPGA_MEM),y)
	hantrodriver-objs += hantro_fpga_mem.o
	HANTRO_CFLAGS += -DVSI_FPGA_MEM -DVSI_FPGA_PCIE
	PCIE=y
endif

ifeq ($(PCIE),y)
	hantrodriver-objs += hantro_pcie.o
	HANTRO_CFLAGS += -DPCIE_EN
endif

ifeq ($(USE_PLATFORM_GEN7),y)
	HANTRO_CFLAGS += -DPLATFORM_GEN7
endif

ifeq ($(VSI_VCE),y)
	hantrodriver-objs += hx280enc.o
	HANTRO_CFLAGS += -DHAS_VCE
endif

ifeq ($(VSI_VCD),y)
	hantrodriver-objs += hantrodec.o
	HANTRO_CFLAGS += -DHAS_VCD
endif

ifeq ($(VSI_VCMD),y)
	hantrodriver-objs += hantro_vcmd.o hantro_vcmd_slice.o
	HANTRO_CFLAGS += -DHAS_VCMD
endif

ifeq ($(VSI_CACHE),y)
	hantrodriver-objs += hantrocache.o
	HANTRO_CFLAGS += -DHAS_CACHECORE
endif

ifeq ($(VSI_DEC400),y)
	hantrodriver-objs += hantrodec400.o
	HANTRO_CFLAGS += -DHAS_DEC400
endif

ifeq ($(VSI_AXIFE),y)
	hantrodriver-objs += hantro_axife.o
	HANTRO_CFLAGS += -DHAS_AXIFE
endif

ifeq ($(VSI_MMU),y)
	hantrodriver-objs += hantro_mmu.o
	HANTRO_CFLAGS += -DHAS_MMU
endif

ifeq ($(VSI_SUPPORT_PM),y)
	HANTRO_CFLAGS += -DVSI_CONFIG_PM
endif

SIMICS=n
ifeq ($(SIMICS),y)
	HANTRO_CFLAGS += -DSIMICS_TEST
endif

ifeq ($(DEBUG),y)
	HANTRO_CFLAGS += -DDEBUG
	HANTRO_CFLAGS += -DHANTRODEC_DEBUG -DENABLE_DEBUG
	HANTRO_CFLAGS += -DHANTRO_VCMD_DRIVER_DEBUG -DVCMD_DEBUG_INTERNAL
	HANTRO_CFLAGS += -DREGISTER_DEBUG -DDEBUG_PRINT_REGS
endif

ccflags-y += $(HANTRO_CFLAGS) -I$(srctree)/$(src)

#KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
default:
	$(MAKE) -C $(KDIR) M=$(PWD) CC=$(CC) modules

clean::
	$(MAKE) -C $(KDIR) M=$(PWD) CC=$(CC) clean
	-rm -f .version
