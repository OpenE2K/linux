 # SPDX-License-Identifier: GPL-2.0
 # Copyright (c) 2023 MCST
 
#
# Makefile for the drm device driver.  This driver provides support for the
# Direct Rendering Infrmga2ructure (DRI) in XFree86 4.1.0 and higher.

ccflags-y := -Werror -D_MCU_ -I$(srctree)/drivers/mcst/mga25/it6613

mga25-y := drv.o main.o crtc.o fb.o irq.o \
		hdmi.o lvds.o rgb.o dsi.o \
		clk.o clk-div.o  clk-tsmc.o clk-cy22394.o \
		gpio.o pwm.o gpio-pwm.o \
		hdmi-it6613.o \
		it6613/HDMI_TX/HDMI_TX.o  it6613/HDMI_TX/it6613_drv.o \
		it6613/HDMI_TX/it6613_sys.o it6613/HDMI_TX/EDID.o \
		mga20.dtb.o mga25-pci-proto.dtb.o mga26-pcie.dtb.o \
		mga26-pcie-proto.dtb.o


obj-$(CONFIG_DRM_MGA25)  += mga25.o
