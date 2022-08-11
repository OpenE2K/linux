# SPDX-License-Identifier: GPL-2.0
#
# sparc/Makefile
#
# Makefile for the architecture dependent flags and dependencies on the
# Sparc and sparc64.
#
# Copyright (C) 1994,1996,1998 David S. Miller (davem@caip.rutgers.edu)
# Copyright (C) 1998 Jakub Jelinek (jj@ultra.linux.cz)

# We are not yet configured - so test on arch
ifeq ($(ARCH),sparc)
        KBUILD_DEFCONFIG ?= sparc32_defconfig
else
        KBUILD_DEFCONFIG ?= sparc64_defconfig
endif

ifeq ($(CONFIG_SPARC32),y)
#####
# sparc32
#

CHECKFLAGS     += -D__sparc__
KBUILD_LDFLAGS := -m elf32_sparc
export BITS    := 32
UTS_MACHINE    := sparc

# We are adding -Wa,-Av8 to KBUILD_CFLAGS to deal with a specs bug in some
# versions of gcc.  Some gcc versions won't pass -Av8 to binutils when you
# give -mcpu=v8.  This silently worked with older bintutils versions but
# does not any more.
KBUILD_CFLAGS  += -m32 -mcpu=v8 -pipe -mno-fpu -fcall-used-g5 -fcall-used-g7
KBUILD_CFLAGS  += -Wa,-Av8

KBUILD_AFLAGS  += -m32 -Wa,-Av8

else
#####
# sparc64
#

CHECKFLAGS    += -D__sparc__ -D__sparc_v9__ -D__arch64__
KBUILD_LDFLAGS := -m elf64_sparc
export BITS   := 64
UTS_MACHINE   := sparc64

KBUILD_CFLAGS += -m64 -pipe -mno-fpu -mcpu=ultrasparc3 -mcmodel=medlow
KBUILD_CFLAGS += -ffixed-g4 -ffixed-g5 -fcall-used-g7 -Wno-sign-compare
ifeq ($(call cc-lcc-yn),y)
  KBUILD_CFLAGS += -fkernel
  KBUILD_CFLAGS += -Wno-unused-result -Wno-reduced-alignment
  KBUILD_CFLAGS += -Wno-builtin-functions-redefined -Wa,--undeclared-regs
  KBUILD_CFLAGS += -Wno-alignment-reduction-ignored
# to reduce image size
  KBUILD_CFLAGS += -fno-align-functions -finline-functions-called-once
endif
KBUILD_CFLAGS += $(call cc-option,-mtune=ultrasparc3)
KBUILD_AFLAGS += -m64 -mcpu=ultrasparc -Wa,--undeclared-regs

ifeq ($(CONFIG_MCOUNT),y)
  KBUILD_CFLAGS += -pg
endif

endif

head-y                 := arch/sparc/kernel/head_$(BITS).o

# See arch/sparc/Kbuild for the core part of the kernel
core-y                 += arch/sparc/

ifdef CONFIG_E90S
# Elbrus common modules
core-y                         += arch/l/
drivers-$(CONFIG_PCI)          += arch/l/pci/
# e90s can boot an image no larger then 16MiB
define e90s_check_image_size
	e=$$($(AWK) '$$3 == "_end" { print "0x"$$1 }' System.map);	\
	d=$$((e - 0x1400000));						\
	[ $$d -le 0 ] || { echo "Linux image too large (by $$d  bytes)" && \
				false; }
endef
else
e90s_check_image_size = true
endif

ifndef CONFIG_E90S
libs-$(CONFIG_OF)                 += arch/sparc/prom/
endif
libs-y                 += arch/sparc/lib/

drivers-$(CONFIG_PM) += arch/sparc/power/
drivers-$(CONFIG_OPROFILE)	+= arch/sparc/oprofile/

boot := arch/sparc/boot

# Default target
all: zImage

image zImage uImage tftpboot.img vmlinux.aout: vmlinux
	$(Q)$(MAKE) $(build)=$(boot) $(boot)/$@
	$(Q)$(call e90s_check_image_size)


install:
	$(Q)$(MAKE) $(build)=$(boot) $@

archclean:
	$(Q)$(MAKE) $(clean)=$(boot)

archheaders:
	$(Q)$(MAKE) $(build)=arch/sparc/kernel/syscalls all

build-install: FORCE
	$(CONFIG_SHELL) scripts/gen-osl-build -l $(srctree) -m $(MODLIB)

ifndef CONFIG_E90S
PHONY += vdso_install
vdso_install:
	$(Q)$(MAKE) $(build)=arch/sparc/vdso $@
endif

# This is the image used for packaging
KBUILD_IMAGE := $(boot)/zImage

# Don't use tabs in echo arguments.
ifeq ($(ARCH),sparc)
define archhelp
  echo  '* image        - kernel image ($(boot)/image)'
  echo  '* zImage       - stripped kernel image ($(boot)/zImage)'
  echo  '  uImage       - U-Boot SPARC32 Image (only for LEON)'
  echo  '  tftpboot.img - image prepared for tftp'
endef
else
define archhelp
  echo  '* vmlinux      - standard sparc64 kernel'
  echo  '* zImage       - stripped and compressed sparc64 kernel ($(boot)/zImage)'
  echo  '  vmlinux.aout - a.out kernel for sparc64'
  echo  '  tftpboot.img - image prepared for tftp'
endef
endif
