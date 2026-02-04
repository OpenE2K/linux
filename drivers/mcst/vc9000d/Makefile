################################################################################
# Copyright (c) 2015, Verisilicon Inc. - All Rights Reserved
#
# This software is dual licensed, either GPL-2.0 or BSD-3-Clause, at your
# option.
#
################################################################################
#
# GPL-2.0
#
################################################################################
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; version 2.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 51 Franklin
# Street, Fifth Floor, Boston, MA 02110-1301, USA.
#
################################################################################
#
# Alternatively, This software may be distributed under the terms of
# BSD-3-Clause, in which case the following provisions apply instead of the ones
# mentioned above :
#
################################################################################
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors
# may be used to endorse or promote products derived from this software without
# specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
################################################################################
dec_dev ?= vc9000d
SUPPORT_DEBUGFS ?= y
SUPPORT_VCMD_ENABLE_IP = y
USE_PLATFORM_GEN7 = n
DEBUG ?= n
PCIE_EN ?= y
ddr_offset ?= 0x0
EMU ?= n
# Support to read HW resources from DTB
SUPPORT_DTB ?= n

# set it to 'y' to enable SW watchdog
USE_WATCHDOG ?= n
# set it to 'y' to enable power managemnt
SUPPORT_PM ?= n

# set it to 'y' to enable MMU
SUPPORT_MMU ?= n
# set it to 'y' to enable 48PA MMU
SUPPORT_48PA_MMU ?= n
# MMU VA lenth
MMU_VA_BITS ?= 40
# set it to 'y' to enable 48PA MMU page table switch
MMU_PAGE_TABLE_SWITCH ?= y

# set it to 'y' to enable AXIFE
SUPPORT_AXIFE ?= y
# set it to 'y' to enable AXI2TO1
SUPPORT_AXI2TO1 ?= n

# set it to 'y' to enable AFBC
SUPPORT_AFBC ?= n

#if need request vcarb, set it to 'y'
#VCARB_REQUEST ?= n

ifeq ($(DEBUG),y)
#  DEBFLAGS = -O0 -g
  DEBFLAGS += -DHANTRODEC_DEBUG
  DEBFLAGS += -DHANTROMMU_DEBUG

# Extra debug info:
  DEBFLAGS += -DREGISTER_DEBUG -DDEBUG_PRINT_REGS
  DEBFLAGS += -DVALIDATE_REGS_WRITE
  DEBFLAGS += -DVCMD_DEBUG_INTERNAL
  DEBFLAGS += -DTEST_DATA  # print VCMD register description
#else
#  DEBFLAGS = -O2
endif
ifeq ($(strip $(PCIE_EN)),y)
  DEBFLAGS += -DPCIE_EN
endif

ifeq ($(EMU),y)
  DEBFLAGS += -DEMU
endif

ifeq ($(SUPPORT_DEBUGFS),y)
  DEBFLAGS += -DSUPPORT_DBGFS
endif

ifeq ($(USE_WATCHDOG),y)
  DEBFLAGS += -DSUPPORT_WATCHDOG
endif

ifeq ($(SUPPORT_MMU),y)
  ifeq ($(SUPPORT_48PA_MMU),y)
    DEBFLAGS += -DSUPPORT_48PA_MMU
    DEBFLAGS += -DMMU_VA_BITS=$(MMU_VA_BITS)
    ifeq ($(MMU_PAGE_TABLE_SWITCH),y)
      DEBFLAGS += -DMMU_PAGE_TABLE_SWITCH
    endif
  endif
endif

ifeq ($(SUPPORT_AFBC),y)
  DEBFLAGS += -DSUPPORT_AFBC
endif

ifeq ($(VCARB_REQUEST),y)
  DEBFLAGS += -DVCARB_REQUEST
endif

ccflags-y += $(DEBFLAGS)
#ccflags-y += -I$(PWD)/../dwl

ifeq ($(strip $(SUPPORT_VCMD_ENABLE_IP)),y)
ccflags-y   += -DHANTROVCMD_ENABLE_IP_SUPPORT
endif
ifeq ($(strip $(USE_PLATFORM_GEN7)),y)
ccflags-y   += -DPLATFORM_GEN7
endif

ifeq ($(strip $(SUPPORT_DTB)),y)
ccflags-y   += -DDTB_SUPPORT
endif

ifeq ($(strip $(SUPPORT_PM)),y)
ccflags-y   += -DCONFIG_DEC_PM
endif

ifeq ($(strip $(SUPPORT_AXI2TO1)),y)
ccflags-y   += -DAXI2TO1_SUPPORT
endif

ifeq ($(strip $(SUPPORT_AXIFE)),y)
ccflags-y   += -DSUPPORT_AXIFE
endif

ifeq ($(strip $(SUPPORT_MMU)),y)
ccflags-y   += -DSUPPORT_MMU
endif

ifneq ($(KERNELRELEASE),)
# recursive call from kernel build system

$(dec_dev)-objs := hantro_dec.o hantro_vcmd.o bidirect_list.o vcmdswhwregisters.o subsys.o hantro_abnormal_irq.o
obj-$(CONFIG_MCST_VC9000D) += $(dec_dev).o

ifeq ($(SUPPORT_DEBUGFS),y)
$(dec_dev)-objs += hantro_vcmd_dbgfs.o
endif

ifeq ($(strip $(SUPPORT_AXI2TO1)),y)
$(dec_dev)-objs += hantro_axi2to1.o
endif

ifeq ($(strip $(SUPPORT_AXIFE)),y)
$(dec_dev)-objs += hantro_axife.o
endif

ifeq ($(strip $(SUPPORT_MMU)),y)
$(dec_dev)-objs += hantro_mmu.o
endif

ifeq ($(SUPPORT_AFBC),y)
  $(dec_dev)-objs += hantro_afbc.o
endif

else

#KDIR := /mnt/export/Testing/Board_Version_Control/SW_Common/SOCLE_MDK-3D/openlinux/2.6.29/v0_5/android_linux-2.6.29
KVER := $(shell uname -r)
KDIR ?= /lib/modules/$(KVER)/build
#ifeq ($(KVER), 5.10.4-051004-generic)
#  CC   := gcc-8
#else
#  CC   := gcc
#endif
PWD  := $(shell pwd)

all:
	@if [ -e ./subsys_cfg.h ]; \
  	then \
		$(MAKE) -C $(KDIR) M=$(PWD) modules CC=$(CC); \
	else \
       		echo "Please contact Verisilicon to provide subsys_cfg.h"; \
	fi

endif

clean:
	rm -rf *.o .*.o.d *~ core .depend .*.cmd *.ko *.mod.c *.mod .tmp_versions *.o.ur-safe
	rm -rf modules.order Module.symvers
