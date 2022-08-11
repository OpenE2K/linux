
ifeq ($(LCC_124),y)
obj-y := libkeprof_24.o
else
obj-y := libkeprof_cur.o
endif

empty:=
space:= $(empty) $(empty)
ORIG_CFLAGS := $(KBUILD_CFLAGS)
ORIG_CFLAGS := $(subst $(space)-fprofile-generate-kernel$(space),$(space),$(ORIG_CFLAGS))
ORIG_CFLAGS := $(subst $(space)-fprofile-use="$(PROFILE_USE)"$(space),$(space),$(ORIG_CFLAGS))
KBUILD_CFLAGS = $(ORIG_CFLAGS)

ifeq ($(LCC_124),y)
CFLAGS_REMOVE_libkeprof_24.o := -pg
else
CFLAGS_REMOVE_libkeprof_cur.o := -pg
endif
