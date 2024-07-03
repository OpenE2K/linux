 # SPDX-License-Identifier: GPL-2.0
 # Copyright (c) 2023 MCST
 
obj-y := libkeprof.o
CFLAGS_REMOVE_libkeprof.o := -pg

empty:=
space:= $(empty) $(empty)
ORIG_CFLAGS := $(KBUILD_CFLAGS)
ORIG_CFLAGS := $(subst $(space)-fprofile-generate-kernel$(space),$(space),$(ORIG_CFLAGS))
ORIG_CFLAGS := $(subst $(space)-fprofile-use="$(PROFILE_USE)"$(space),$(space),$(ORIG_CFLAGS))
KBUILD_CFLAGS = $(ORIG_CFLAGS)
