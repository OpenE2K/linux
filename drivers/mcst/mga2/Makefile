# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2023 MCST

#
# Makefile for the drm device driver.  This driver provides support for the
# Direct Rendering Infrmga2ructure (DRI) in XFree86 4.1.0 and higher.

ccflags-y := -Werror

mga2-y := drv.o main.o crtc.o fb.o irq.o \
		hdmi.o lvds.o rgb.o dsi.o \
		clk.o clk-div.o  clk-tsmc.o clk-cy22394.o \
		gpio.o pwm.o gpio-pwm.o \
		mga20.dtb.o mga25-pci-proto.dtb.o mga25.dtb.o mga26-pcie.dtb.o \
		mga26-pcie-proto.dtb.o mga27-pci-proto.dtb.o

obj-$(CONFIG_DRM_MGA2)  += mga2.o

