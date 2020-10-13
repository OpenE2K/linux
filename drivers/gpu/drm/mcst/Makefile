#
# Makefile for the drm device driver.  This driver provides support for the
# Direct Rendering Infrastructure (DRI) in XFree86 4.1.0 and higher.

ccflags-y := -Iinclude/drm
#ccflags-y := -Iinclude/drm -Wall -Wextra

mcst-y := mcst_drv.o mcst_main.o mcst_mode.o mcst_fb.o \
          mcst_ttm.o mcst_pll.o mcst_irq.o mcst_util.o

mcst-$(CONFIG_DRM_MCST_DEBUG) += mcst_debugfs.o

obj-$(CONFIG_DRM_MCST) := mcst.o