#
# Makefile for the drm device driver.  This driver provides support for the
# Direct Rendering Infrmga2ructure (DRI) in XFree86 4.1.0 and higher.

EXTRA_CFLAGS += -Werror -D_MCU_
ccflags-y := -I$(srctree)/drivers/mcst/mga2/it6613

mga2-y := drv.o main.o crtc.o fb.o irq.o \
		hdmi.o lvds.o rgb.o dsi.o \
		clk.o clk-div.o  clk-tsmc.o clk-cy22394.o \
		gpio.o pwm.o gpio-pwm.o

obj-$(CONFIG_DRM_MGA2)  += mga2.o
