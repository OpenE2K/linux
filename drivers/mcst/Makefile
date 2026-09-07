# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2023 MCST

#
# Makefile for the Linux kernel device drivers.
#
ccflags-y := -Werror

obj-$(CONFIG_E2K) += l-iommu.o e2k-iommu.o l-pci.o l-i2c2.o

obj-$(CONFIG_GPIO_MPV) += gpio-mpv.o
obj-$(CONFIG_MCST_LTD) += ltd.o
obj-$(CONFIG_ACPI_L_SPMC) += l-spmc.o
obj-$(CONFIG_IOHUB_GPIO) += l-gpio.o
obj-$(CONFIG_I2C_SPI_RESET_CONTROLLER) += i2c-spi/

obj-$(CONFIG_R2000P_EDAC) += r2000p-edac/
obj-y += mpv/
obj-y += mmrse/
obj-$(CONFIG_MCST_GPU_IMGTEC_R4991288) += gpu-imgtec.r4991288/
obj-$(CONFIG_MCST_GPU_IMGTEC_R5878540) += gpu-imgtec.r5878540/
obj-$(CONFIG_MCST_GPU_VIV) += gpu-viv/
obj-$(CONFIG_MCST_GPU_VIV_E8V7) += gpu-viv-e8v7/
obj-$(CONFIG_DRM_MGA2) += mga2/
obj-y += hantrodec/
obj-$(CONFIG_MCST_VC9000D) += vc9000d/
obj-$(CONFIG_MCST_HANTRO_DRIVER) += hantro_driver/
obj-y += BigEv2/
obj-$(CONFIG_E2K) += pcs/
obj-$(CONFIG_E2K) += pcsm/
obj-$(CONFIG_E2K) += ddrmem/
obj-$(CONFIG_PMC_R2KP) += pmc-r2kp/
obj-$(CONFIG_IMGTEC) += video-imgtec/
obj-$(CONFIG_DRM_SMI) += smi/
obj-$(CONFIG_MEM2ALLOC) += mem2alloc/
obj-$(CONFIG_HW_CHECK) += hw_check/
obj-$(CONFIG_FATAL_TEMP) += fatal_temp/
obj-$(CONFIG_L_I2S) += i2s/
obj-$(CONFIG_DS125DF111) += ds125df111/
obj-$(CONFIG_I2C_V7) += i2c_v7/
obj-$(CONFIG_E2C3_DEVFREQ) += e2c3_devfreq_provider/
obj-m += qdma/
