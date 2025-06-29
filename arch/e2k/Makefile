# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2023 MCST

#			 e2k/Makefile
#
# This file is included by the global makefile so that you can add your own
# architecture-specific flags and dependencies. Remember to do have actions
# for "archclean" and "archdep" for cleaning up and making dependencies for
# this architecture
#
# This file is subject to the terms and conditions of the GNU General Public
# License.  See the file "COPYING" in the main directory of this archive
# for more details.

# Check compiler just in case
PHONY += check_e2k_compiler
check_e2k_compiler:
	$(Q)if $(CC) -dumpmachine 2>&1 | grep -v e2k > /dev/null; then \
		echo 'Specified compiler is not for e2k architecture' >&2; \
		exit 1; \
	fi
check-targets := image bootimage zImage vmlinux modules \
	config nconfig menuconfig xconfig gconfig oldconfig \
	localmodconfig localyesconfig defconfig \
	allnoconfig allyesconfig allmodconfig alldefconfig randconfig \
	yes2modconfig mod2yesconfig mod2noconfig listnewconfig helpnewconfig \
	olddefconfig tinyconfig
$(check-targets): check_e2k_compiler

KBUILD_DEFCONFIG ?= defconfig

KBUILD_CFLAGS += $(call cc-option,-fmax-errors=5) \
		 $(call cc-option,-finline-functions-called-once) \
		 $(call cc-option,-mdmodel=large)

# "-fno-devirtualize" - performance on average is the same but .text size -2%
KBUILD_CFLAGS += -fkernel -gline -masm-inline -fno-ident -pipe -fno-devirtualize

# Must go after -fkernel
ifeq ($(CONFIG_HALF_SPECULATIVE_KERNEL),y)
KBUILD_CFLAGS += $(call cc-option,-fsemi-spec-ld)
# There is no `-floop-apb` option, just `-fno-loop-apb`
ifneq ($(CONFIG_AAU_IN_KERNEL),y)
KBUILD_CFLAGS += $(call cc-option,-fno-loop-apb)
endif
else
KBUILD_CFLAGS += $(call cc-option,-fno-loop-apb) $(call cc-option,-fno-semi-spec-ld)
endif

ifeq ($(PROFILE_GENERATE),1)
KBUILD_CFLAGS += -fprofile-generate-kernel
endif
ifeq ($(origin PROFILE_USE), undefined)
else
 KBUILD_CFLAGS += -fprofile-use="$(PROFILE_USE)" -Wno-missing-profile
 ifeq ($(call cc-option-yn,-O3 -fprofile-correction),y)
  KBUILD_CFLAGS += -fprofile-correction
 endif
endif

KBUILD_CFLAGS += -Werror=return-type -Wno-maybe-uninitialized
ifdef CONFIG_CC_IS_LCC
KBUILD_CFLAGS += -Werror=bad-initializer-type
# Some uninteresting or broken warnings can be disabled with #pragma's only
KBUILD_CFLAGS += -Wno-reduced-alignment -Wno-overflow -Wno-signed-one-bit-field \
		 -Wno-alignment-reduction-ignored \
		 -include $(srctree)/arch/e2k/include/asm/override-lcc-warnings.h
# TODO 152797 temporary workaround
KBUILD_CFLAGS += -Wno-error=coverage-mismatch
endif

LDFLAGS_vmlinux :=
# ASM_SAVE_GREG() relies on speicific __iset__ values, just define 3 here for simplicity
CHECKFLAGS	+= -D__e2k__ -D__iset__=3

CFLAGS_GENERIC	:= -march=elbrus-v$(CONFIG_CPU_ISET_MIN)
CFLAGS_E2S	:= -mtune=elbrus-4c
CFLAGS_E8C	:= -mtune=elbrus-8c
CFLAGS_E1CP	:= -mtune=elbrus-1c+
CFLAGS_E8C2	:= -mtune=elbrus-8c2
CFLAGS_E12C	:= -mtune=elbrus-12c
CFLAGS_E16C	:= -mtune=elbrus-16c
CFLAGS_E2C3	:= -mtune=elbrus-2c3
CFLAGS_E48C	:= -mtune=elbrus-48c
CFLAGS_E8V7	:= -mtune=elbrus-8v7

CFLAGS_ALL_CPUS	:= $(CFLAGS_E2S) $(CFLAGS_E8C) $(CFLAGS_E1CP) $(CFLAGS_E8C2) \
		   $(CFLAGS_E12C) $(CFLAGS_E16C) $(CFLAGS_E2C3) $(CFLAGS_E48C) \
		   $(CFLAGS_E8V7)

export	CFLAGS_E2S CFLAGS_E8C CFLAGS_E1CP CFLAGS_E8C2 CFLAGS_E2C3 CFLAGS_E12C \
	CFLAGS_E16C CFLAGS_E48C CFLAGS_E8V7 CFLAGS_ALL_CPUS

ifneq ($(CONFIG_E2K_MACHINE),y)
  KBUILD_CFLAGS	+= $(CFLAGS_GENERIC) -ffix-lcc-bug123567
  KBUILD_AFLAGS	+= $(CFLAGS_GENERIC)
  TARGET_MDL    := 00
else
  ifeq ($(CONFIG_E2K_E2S),y)
    KBUILD_CFLAGS += $(CFLAGS_E2S)
    KBUILD_AFLAGS += $(CFLAGS_E2S)
    TARGET_MDL    := 03
  else ifeq ($(CONFIG_E2K_E8C),y)
    KBUILD_CFLAGS += $(CFLAGS_E8C)
    KBUILD_AFLAGS += $(CFLAGS_E8C)
    TARGET_MDL    := 07
  else ifeq ($(CONFIG_E2K_E1CP),y)
    KBUILD_CFLAGS += $(CFLAGS_E1CP)
    KBUILD_AFLAGS += $(CFLAGS_E1CP)
    TARGET_MDL    := 08
  else ifeq ($(CONFIG_E2K_E8C2),y)
    KBUILD_CFLAGS += $(CFLAGS_E8C2) -ffix-lcc-bug123567
    KBUILD_AFLAGS += $(CFLAGS_E8C2)
    TARGET_MDL    := 09
  else ifeq ($(CONFIG_E2K_E12C),y)
    KBUILD_CFLAGS += $(CFLAGS_E12C) -ffix-lcc-bug123567
    KBUILD_AFLAGS += $(CFLAGS_E12C)
    TARGET_MDL    := 0a
  else ifeq ($(CONFIG_E2K_E16C),y)
    KBUILD_CFLAGS += $(CFLAGS_E16C) -ffix-lcc-bug123567
    KBUILD_AFLAGS += $(CFLAGS_E16C)
    TARGET_MDL    := 0b
  else ifeq ($(CONFIG_E2K_E2C3),y)
    KBUILD_CFLAGS += $(CFLAGS_E2C3)
    KBUILD_AFLAGS += $(CFLAGS_E2C3)
    TARGET_MDL    := 0c
  else ifeq ($(CONFIG_E2K_E48C),y)
    KBUILD_CFLAGS += $(CFLAGS_E48C)
    KBUILD_AFLAGS += $(CFLAGS_E48C)
    TARGET_MDL    := 0d
  else ifeq ($(CONFIG_E2K_E8V7),y)
    KBUILD_CFLAGS += $(CFLAGS_E8V7)
    KBUILD_AFLAGS += $(CFLAGS_E8V7)
    TARGET_MDL    := 0e
  else
    $(error Invalid e2k machine type)
  endif
endif

KBUILD_LDFLAGS	+= --relaxed-e2k-machine-check
KBUILD_CFLAGS	+= $(cflags-y)

libs-y += arch/e2k/lib/

drivers-$(CONFIG_OF)			+= arch/e2k/boot/dts/
drivers-$(CONFIG_PCI)			+= arch/e2k/pci/ 

# suspend and hibernation support
drivers-$(CONFIG_PM)			+= arch/e2k/power/

# Elbrus common modules
core-y					+= arch/l/
drivers-$(CONFIG_PCI)			+= arch/l/pci/

boot :=   arch/e2k/boot
all: zImage

MAKEBOOT = $(MAKE) -C arch/$(ARCH)/boot

.PHONY:	clean archclean archmrproper archdep bootimage image zImage

e2sboot: vmlinux
	$(Q)$(MAKE) $(build)=$(boot) need-builtin=1 CONFIG_E2S=y boot

e4cboot: vmlinux
	$(Q)$(MAKE) $(build)=$(boot) need-builtin=1 CONFIG_E2S=y boot

e8cboot: vmlinux
	$(Q)$(MAKE) $(build)=$(boot) need-builtin=1 CONFIG_E8C=y boot

e1cpboot: vmlinux
	$(Q)$(MAKE) $(build)=$(boot) need-builtin=1 CONFIG_E1CP=y boot

e8c2boot: vmlinux
	$(Q)$(MAKE) $(build)=$(boot) need-builtin=1 CONFIG_E8C2=y CONFIG_E8C=y boot

e12cboot: vmlinux
	$(Q)$(MAKE) $(build)=$(boot) need-builtin=1 CONFIG_E12C=y boot

e16cboot: vmlinux
	$(Q)$(MAKE) $(build)=$(boot) need-builtin=1 CONFIG_E16C=y boot

e2c3boot: vmlinux
	$(Q)$(MAKE) $(build)=$(boot) need-builtin=1 CONFIG_E2C3=y boot

e48cboot: vmlinux
	$(Q)$(MAKE) $(build)=$(boot) need-builtin=1 CONFIG_E48C=y boot

e8v7boot: vmlinux
	$(Q)$(MAKE) $(build)=$(boot) need-builtin=1 CONFIG_E8V7=y boot

define build_image
	$(Q)$(MAKE) $(build)=$(boot) CONFIG_BOOT=y $(objtree)/$(1)
	$(Q)echo 00000000 | xxd -r -p | \
		dd of=$(objtree)/$(1) bs=1 seek=1588 count=4 conv=notrunc 2>/dev/null; \
	e2k_kernel_csum=`cksum $(objtree)/$(1) | awk '{ printf "%08x\n", $$1 }'`; \
	echo "Kernel image check sum: $$e2k_kernel_csum"; \
	echo $$e2k_kernel_csum | \
		sed 's/\(.\)\(.\)\(.\)\(.\)\(.\)\(.\)\(.\)\(.\)/\7\8\5\6\3\4\1\2/' | \
		xxd -r -p | \
		dd of=$(objtree)/$(1) bs=1 seek=1588 count=4 conv=notrunc 2>/dev/null; \
	echo 'Kernel: $(1) is ready' ' (#'`cat .version`')'
endef

image: vmlinux
	$(call build_image,image.boot)

zImage: vmlinux
	$(call build_image,zImage)

image.boot: bootimage
bootimage: image

archclean:
	$(Q)$(MAKE) $(clean)=arch/e2k/boot

archmrproper:

archdep:
	@$(MAKEBOOT) dep

PHONY += install
install:
	$(Q)$(MAKE) $(build)=$(boot) $@

install-includes: include/linux/version.h arch/e2k/include FORCE
	$(CONFIG_SHELL) scripts/gen-osl-include -l $(srctree) -r $(ROOT_WA)

build-install: FORCE
	$(CONFIG_SHELL) scripts/gen-osl-build -l $(srctree) -m $(MODLIB)

define archhelp
  echo  '* image/bootimage	- Kernel boot image (image.boot)'
  echo  '  zImage		- Compressed kernel boot image (image.boot)'
  echo  '  e4cboot/e2sboot	- Build kernel boot image with small embedded boot for e4c/e2s simulator'
  echo  '  e8cboot		- Build kernel boot image with small embedded boot for e8c simulator'
  echo  '  e1cpboot		- Build kernel boot image with small embedded boot for e1cp simulator'
  echo  '  e8c2boot		- Build kernel boot image with small embedded boot for e8c2 simulator'
  echo  '  e12cboot		- Build kernel boot image with small embedded boot for e12c simulator'
  echo  '  e16cboot		- Build kernel boot image with small embedded boot for e16c simulator'
  echo  '  e2c3boot		- Build kernel boot image with small embedded boot for e2c3 simulator'
  echo  '  e48cboot		- Build kernel boot image with small embedded boot for e48c simulator'
  echo  '  e8v7boot		- Build kernel boot image with small embedded boot for e8v7 simulator'
  echo  '  [with_kernel=1]	- When building boot, build in compressed kernel into the boot image'
  echo  ''
  echo  '  lms.config		- Tune Kconfig items for faster compilation and simulation runs'
  echo  '  mcst_debug.config	- Enable Kconfig items for debugging (both boot-time and runtime checks)'
  echo  '  [with_kernel=1]	- When building boot, build in compressed kernel into the boot image'
  echo  ''
  echo  'Note that compiler version can change which options are available, so do not forget to set CC environment variable together with ARCH'
endef
