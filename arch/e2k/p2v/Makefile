#
# Makefile for "Physical-to-Virtual Switch".
#

GCOV_PROFILE := n

# remove profile flags
ORIG_CFLAGS := $(KBUILD_CFLAGS)
KBUILD_CFLAGS = $(subst -pg,,$(ORIG_CFLAGS)) -DE2K_P2V -fno-ld-spec

empty:=
space:= $(empty) $(empty)
ORIG_CFLAGS := $(KBUILD_CFLAGS)
ORIG_CFLAGS := $(subst $(space)-fprofile-generate-kernel$(space),$(space),$(ORIG_CFLAGS))
KBUILD_CFLAGS = $(ORIG_CFLAGS)

obj-y = boot_head.o boot_init.o boot_map.o boot_phys.o boot_param.o \
	boot_string.o boot_find_bit.o boot_e2k_sic.o machdep.o \
	boot_printk/ cpu/

obj-$(CONFIG_SMP)		+= boot_smp.o
obj-$(CONFIG_RECOVERY)		+= boot_recovery.o
obj-$(CONFIG_BOOT_TRACE)	+= boot_profiling.o
