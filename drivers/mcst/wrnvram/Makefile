
#
# Ported in Linux by Alexey Mukhin, MCST, 2006
#

# for sbus and pci-to-sbus module

obj-$(CONFIG_WRNVRAM)	+= wrnvram.o

ifeq ($(CONFIG_SBUS), y)
EXTRA_CFLAGS += -D_KERNEL
endif

