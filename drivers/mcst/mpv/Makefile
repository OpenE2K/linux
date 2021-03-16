
#
# Ported in Linux by Alexey V. Sitnikov, alexmipt@mcst.ru, MCST, 2006
#

# for sbus and pci-to-sbus module

obj-$(CONFIG_MPV)	+= mpv.o
ifeq ($(CONFIG_SBUS), y)
EXTRA_CFLAGS += -D_KERNEL
endif

