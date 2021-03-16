#
# Makefile for the drm device driver.  This driver provides support for the
# Direct Rendering Infrmga2ructure (DRI) in XFree86 4.1.0 and higher.

EXTRA_CFLAGS += -Werror -D_MCU_
ccflags-y := -I$(srctree)/drivers/mcst/mga2/it6613

mga2-y := mga2_drv.o mga2_main.o mga2_mode.o mga2_fb.o mga2_irq.o \
		 mga2_i2c.o mga2_pll.o mga2_dvi.o mga2_lvds.o		\
		mga2_layer.o mga2_hdmi_it6613.o \
		it6613/HDMI_TX/HDMI_TX.o  it6613/HDMI_TX/it6613_drv.o \
		it6613/HDMI_TX/it6613_sys.o it6613/HDMI_TX/EDID.o

obj-$(CONFIG_DRM_MGA2) := mga2.o
