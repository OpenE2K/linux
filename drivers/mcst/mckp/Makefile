#
# Makefile for the Linux kernel device drivers.
#

# for sbus and pci-to-sbus module

obj-$(CONFIG_MCKP)	+= mckp.o

mckp-objs		:= linux_mckp.o linux_mckp_ioctl.o

EXTRA_CFLAGS += -D_WITHOUT_MP_INTERRUPT_
EXTRA_CFLAGS += -D__DRV_TRANSL__
EXTRA_CFLAGS += -D__MCKP_BOARD_DRIVER__
EXTRA_CFLAGS += -D__GENERAL_RESET_TURN_ON__
EXTRA_CFLAGS += -D__BLOCK_BUFFER_USE__

ifeq ($(CONFIG_SBUS), y)
EXTRA_CFLAGS += -DMY_DRIVER_BIG_ENDIAN
endif

#CFLAGS += -DMCKA_DBG
#CFLAGS += -DDEBUG


