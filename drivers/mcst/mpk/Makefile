
#
# Ported in Linux by Alexey V. Sitnikov, alexmipt@mcst.ru, MCST, 2006
#

# for sbus and pci-to-sbus module

obj-$(CONFIG_MPK)	+= mpk.o
ifeq ($(CONFIG_SBUS), y)
EXTRA_CFLAGS += -D_KERNEL
endif
ifneq ($(CONFIG_MPK_OLD_VERSION), y)
EXTRA_CFLAGS += -DMPK_SEPARATE_ADDR_SPACE
endif

