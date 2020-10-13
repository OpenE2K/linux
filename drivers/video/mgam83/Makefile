#
# Makefile for the MGA/M-83 framebuffer driver
#

# for pci
obj-$(CONFIG_PCI_FB_MGAM83) += mgam83fb.o
obj-$(CONFIG_SBUS_FB_MGAM83) += sbus_mgam83fb.o

mgam83fb-objs := mgam83fb_base.o mgam83fb_ramdac.o

# for sbus and pci-to-sbus module

sbus_mgam83fb-objs := sbus_mgam83fb_base.o sbus_ramdac.o

ifeq ($(CONFIG_SBUS), y)
EXTRA_CFLAGS += -DMY_DRIVER_BIG_ENDIAN
endif

