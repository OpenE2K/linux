#
# Makefile for E2K-specific library files..
#

# compile  with -O3 since only performance-sensitive functions are here
empty:=
space:= $(empty) $(empty)
ORIG_CFLAGS := $(KBUILD_CFLAGS)
ORIG_CFLAGS := $(subst $(space)-O2$(space),$(space),$(ORIG_CFLAGS))
ORIG_CFLAGS := $(subst $(space)-Os$(space),$(space),$(ORIG_CFLAGS))
KBUILD_CFLAGS = $(ORIG_CFLAGS) -O3


lib-y = delay.o usercopy.o builtin.o checksum.o

# Put these two together (they reference each other so should be close
# in memory, in the same page if possible)
lib-y += string.o recovery_string.o

# Remove -pg from low-level functions as they are used by arch/e2k/p2v/
CFLAGS_REMOVE_string.o = -pg
