 # SPDX-License-Identifier: GPL-2.0
 # Copyright (c) 2023 MCST
 
subdir-ccflags-y := -DE2K_FAST_SYSCALL -Werror -Wswitch -Wenum-compare

empty:=
space:= $(empty) $(empty)
ORIG_CFLAGS := $(KBUILD_CFLAGS)
ORIG_CFLAGS := $(subst $(space)-fprofile-generate-kernel$(space),$(space),$(ORIG_CFLAGS))
ORIG_CFLAGS := $(subst $(space)-fprofile-use="$(PROFILE_USE)"$(space),$(space),$(ORIG_CFLAGS))
KBUILD_CFLAGS = $(ORIG_CFLAGS)

obj-y += fast_clock_gettime.o fast_syscalls.o sclkr.o
obj-y += fast_getcpu.o fast_siggetmask.o fast_set_return.o
obj-$(CONFIG_COMPAT) += compat.o
obj-$(CONFIG_PROTECTED_MODE) += protected.o

CFLAGS_REMOVE_sclkr.o = $(CFLAGS_ALL_CPUS)
CFLAGS_sclkr.o += -march=elbrus-v3
