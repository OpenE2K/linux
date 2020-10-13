#
# Makefile for "Physical-to-Virtual Switch".
#

# remove profile flags
ORIG_CFLAGS := $(KBUILD_CFLAGS)
KBUILD_CFLAGS = $(subst -pg,,$(ORIG_CFLAGS)) -DE2K_P2V -fno-control-spec

obj-y = boot_head.o boot_init.o boot_map.o boot_phys.o boot_param.o \
	boot_printk/

obj-$(CONFIG_SMP)		+= boot_smp.o
obj-$(CONFIG_RECOVERY)		+= boot_restart.o boot_recovery.o
