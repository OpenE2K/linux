#
# Makefile for the drm device driver.  This driver provides support for the
# Direct Rendering Infrmga2ructure (DRI) in XFree86 4.1.0 and higher.

EXTRA_CFLAGS += -Werror
ccflags-y := -Iinclude/drm

mga2-y := mga2_drv.o mga2_main.o mga2_mode.o mga2_fb.o mga2_irq.o

obj-$(CONFIG_DRM_MGA2) := mga2.o
