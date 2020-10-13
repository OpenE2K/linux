#
# Makefile for the Linux kernel device drivers.
#

# for sbus and pci-to-sbus module

obj-$(CONFIG_MBK3)	+= mbk3.o

mbk3-objs		:= mbk3_drv.o mbk3_intr.o mbk3_reset.o

EXTRA_CFLAGS += -DMODULE
EXTRA_CFLAGS += -D_WITHOUT_MP_INTERRUPT_
EXTRA_CFLAGS += -D__DRV_TRANSL__
EXTRA_CFLAGS += -D__CNTR_DEV_BOARD_TYPE__
EXTRA_CFLAGS += -D__HIGH_INTERDRIVER_AREA_USED__
EXTRA_CFLAGS += -D__TRANS_SPEC_INTO_BUF__

ifeq ($(CONFIG_SBUS), y)
EXTRA_CFLAGS += -DMY_DRIVER_BIG_ENDIAN
endif

