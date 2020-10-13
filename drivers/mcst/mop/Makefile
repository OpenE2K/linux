
# for sbus and pci-to-sbus module

obj-$(CONFIG_MOP)	+= mop.o
ifeq ($(CONFIG_SBUS), y)
EXTRA_CFLAGS += -DMY_DRIVER_BIG_ENDIAN
endif



