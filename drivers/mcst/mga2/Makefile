 # SPDX-License-Identifier: GPL-2.0
 # Copyright (c) 2023 MCST
 
#
# Makefile for the drm device driver.  This driver provides support for the
# Direct Rendering Infrmga2ructure (DRI) in XFree86 4.1.0 and higher.

ccflags-y += -Werror -Wno-implicit-fallthrough

mga2-y := mga2_drv.o mga2_main.o mga2_mode.o mga2_fb.o mga2_irq.o \
		 mga2_i2c.o mga2_pll.o mga2_dvi.o mga2_lvds.o		\
		mga2_layer.o

obj-$(CONFIG_DRM_MGA2) := mga2.o

