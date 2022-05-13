# e2k/Makefile
#
# This file is included by the global makefile so that you can add your own
# architecture-specific flags and dependencies. Remember to do have actions
# for "archclean" and "archdep" for cleaning up and making dependencies for
# this architecture
#
# This file is subject to the terms and conditions of the GNU General Public
# License.  See the file "COPYING" in the main directory of this archive
# for more details.

KBUILD_DEFCONFIG ?= defconfig

AS	= $(shell $(CC) -print-prog-name=as)
OBJDUMP	= $(shell $(CC) -print-prog-name=objdump)
LD	= $(shell $(CC) -print-prog-name=ld)
OBJCOPY	= $(shell $(CC) -print-prog-name=objcopy)

KBUILD_CFLAGS += -fkernel -gline -masm-inline $(call cc-option,-fforbid-fp) \
		 $(call cc-option,-fmax-errors=5) $(call cc-option,-fno-loop-apb) \
		 -fno-ident

ifeq ($(PROFILE_GENERATE), 1)
KBUILD_CFLAGS += -fprofile-generate-kernel
endif
ifeq ($(origin PROFILE_USE), undefined)
else
KBUILD_CFLAGS += -fprofile-use="$(PROFILE_USE)"
endif

KBUILD_CFLAGS += $(call cc-option,-finline-functions,) \
                 $(call cc-option,-finline-functions-called-once,)

# Some uninteresting or broken warnings can be disabled with #pragma's only
KBUILD_CFLAGS += -Wno-array-bounds -Wno-builtin-functions-redefined \
		 -Wno-reduced-alignment -Wno-overflow -Wno-signed-one-bit-field \
		 -Wno-alignment-reduction-ignored \
		 -include $(srctree)/arch/e2k/include/asm/override-lcc-warnings.h

LDFLAGS_vmlinux :=
CHECKFLAGS	+= -D__e2k__

CFLAGS += -pipe -D__linux__

KBUILD_CFLAGS += $(CFLAGS)

CFLAGS_GENERIC	:= -march=elbrus-v3
CFLAGS_E2S	:= -mtune=elbrus-4c
CFLAGS_E8C	:= -mtune=elbrus-8c
CFLAGS_E1CP	:= -mtune=elbrus-1c+
CFLAGS_E8C2	:= -mtune=elbrus-8c2
CFLAGS_E12C	:= -mtune=elbrus-12c
CFLAGS_E16C	:= -mtune=elbrus-16c
CFLAGS_E2C3	:= -mtune=elbrus-2c3

CFLAGS_ALL_CPUS	:= $(CFLAGS_E2S) $(CFLAGS_E8C) $(CFLAGS_E1CP) $(CFLAGS_E8C2) \
		   $(CFLAGS_E12C) $(CFLAGS_E16C) $(CFLAGS_E2C3)

export	CFLAGS_E2S CFLAGS_E8C CFLAGS_E1CP CFLAGS_E8C2 CFLAGS_E2C3 CFLAGS_E12C \
	CFLAGS_E16C CFLAGS_ALL_CPUS

ifeq ($(CONFIG_E2K_MACHINE),y)
 ifeq ($(CONFIG_E2K_E2S),y)
 KBUILD_CFLAGS += $(CFLAGS_E2S)
 KBUILD_AFLAGS += $(CFLAGS_E2S)
 TARGET_MDL    := 03
 else
  ifeq ($(CONFIG_E2K_E8C),y)
  KBUILD_CFLAGS += $(CFLAGS_E8C)
  KBUILD_AFLAGS += $(CFLAGS_E8C)
  TARGET_MDL    := 07
  else
   ifeq ($(CONFIG_E2K_E1CP),y)
   KBUILD_CFLAGS += $(CFLAGS_E1CP)
   KBUILD_AFLAGS += $(CFLAGS_E1CP)
   TARGET_MDL    := 08
   else
    ifeq ($(CONFIG_E2K_E8C2),y)
    KBUILD_CFLAGS += $(CFLAGS_E8C2)
    KBUILD_AFLAGS += $(CFLAGS_E8C2)
    TARGET_MDL    := 09
    else
     ifeq ($(CONFIG_E2K_E12C),y)
     KBUILD_CFLAGS += $(CFLAGS_E12C)
     KBUILD_AFLAGS += $(CFLAGS_E12C)
     TARGET_MDL    := 0a
     else
      ifeq ($(CONFIG_E2K_E16C),y)
      KBUILD_CFLAGS += $(CFLAGS_E16C)
      KBUILD_AFLAGS += $(CFLAGS_E16C)
      TARGET_MDL    := 0b
      else
       ifeq ($(CONFIG_E2K_E2C3),y)
       KBUILD_CFLAGS += $(CFLAGS_E2C3)
       KBUILD_AFLAGS += $(CFLAGS_E2C3)
       TARGET_MDL    := 0c
       else
        error "Invalid e2k machine type"
       endif	# ifeq ($(CONFIG_E2K_E2C3),y)
      endif	# ifeq ($(CONFIG_E2K_E16C),y)
     endif	# ifeq ($(CONFIG_E2K_E12C),y)
    endif	# ifeq ($(CONFIG_E2K_E8C2),y)
   endif	# ifeq ($(CONFIG_E2K_E1CP),y)
  endif		# ifeq ($(CONFIG_E2K_E8C),y)
 endif		# ifeq ($(CONFIG_E2K_E2S),y)
else		# ! ifeq ($(CONFIG_E2K_MACHINE),y)
KBUILD_CFLAGS	+= $(CFLAGS_GENERIC)
KBUILD_AFLAGS	+= $(CFLAGS_GENERIC)
TARGET_MDL      := 00
endif

KBUILD_LDFLAGS	+= --relaxed-e2k-machine-check
KBUILD_CFLAGS	+= $(cflags-y)

libs-y 					+= arch/e2k/lib/
core-y					+= arch/e2k/kernel/ \
					   arch/e2k/mm/ \
					   arch/e2k/p2v/ \
					   arch/e2k/fast_syscalls/

core-$(CONFIG_PROTECTED_MODE)		+= arch/e2k/3p/

drivers-$(CONFIG_PCI)			+= arch/e2k/pci/ 

# suspend and hibernation support
drivers-$(CONFIG_PM)			+= arch/e2k/power/

#KVM hypervisor and guest support
core-$(CONFIG_KVM)			+= arch/e2k/kvm/

# Elbrus common modules
core-y					+= arch/l/
drivers-$(CONFIG_PCI)			+= arch/l/pci/

boot :=   arch/e2k/boot
all: e2sboot

MAKEBOOT = $(MAKE) -C arch/$(ARCH)/boot

.PHONY:	clean archclean archmrproper archdep bootimage image zImage

e2sboot: vmlinux
	$(Q)$(MAKE) $(build)=$(boot) CONFIG_E2S=y boot

e8cboot: vmlinux
	$(Q)$(MAKE) $(build)=$(boot) CONFIG_E8C=y boot

e1cpboot: vmlinux
	$(Q)$(MAKE) $(build)=$(boot) CONFIG_E1CP=y boot

e8c2boot: vmlinux
	$(Q)$(MAKE) $(build)=$(boot) CONFIG_E8C2=y CONFIG_E8C=y boot

e12cboot: vmlinux
	$(Q)$(MAKE) $(build)=$(boot) CONFIG_E12C=y boot

e16cboot: vmlinux
	$(Q)$(MAKE) $(build)=$(boot) CONFIG_E16C=y boot

e2c3boot: vmlinux
	$(Q)$(MAKE) $(build)=$(boot) CONFIG_E2C3=y boot

image: vmlinux
	$(Q)$(MAKE) $(build)=$(boot) CONFIG_BOOT=y $(objtree)/image.boot
	$(Q)echo "Target mdl: $(TARGET_MDL)"; \
	echo $(TARGET_MDL) | \
		xxd -r -p | \
		dd of=$(objtree)/image.boot bs=1 seek=258 count=1 conv=notrunc 2>/dev/null; \
	echo 00000000 | xxd -r -p | \
		dd of=$(objtree)/image.boot bs=1 seek=1588 count=4 conv=notrunc 2>/dev/null; \
	e2k_kernel_csum=`cksum $(objtree)/image.boot | awk '{ printf "%08x\n", $$1 }'`; \
	echo "Kernel image check sum: $$e2k_kernel_csum"; \
	echo $$e2k_kernel_csum | \
		sed 's/\(.\)\(.\)\(.\)\(.\)\(.\)\(.\)\(.\)\(.\)/\7\8\5\6\3\4\1\2/' | \
		xxd -r -p | \
		dd of=$(objtree)/image.boot bs=1 seek=1588 count=4 conv=notrunc 2>/dev/null; \
	echo 'Kernel: image.boot is ready' ' (#'`cat .version`')'

zImage: vmlinux
	$(Q)$(MAKE) $(build)=$(boot) CONFIG_BOOT=y $(objtree)/zImage
	$(Q)echo "Target mdl: $(TARGET_MDL)"; \
	echo $(TARGET_MDL) | \
		xxd -r -p | \
		dd of=$(objtree)/zImage bs=1 seek=258 count=1 conv=notrunc 2>/dev/null; \
	echo 00000000 | xxd -r -p | \
		dd of=$(objtree)/zImage bs=1 seek=1588 count=4 conv=notrunc 2>/dev/null; \
	e2k_kernel_csum=`cksum $(objtree)/zImage | awk '{ printf "%08x\n", $$1 }'`; \
	echo "Kernel image check sum: $$e2k_kernel_csum"; \
	echo $$e2k_kernel_csum | \
		sed 's/\(.\)\(.\)\(.\)\(.\)\(.\)\(.\)\(.\)\(.\)/\7\8\5\6\3\4\1\2/' | \
		xxd -r -p | \
		dd of=$(objtree)/zImage bs=1 seek=1588 count=4 conv=notrunc 2>/dev/null; \
	echo 'Kernel: zImage is ready' ' (#'`cat .version`')'

image.boot: bootimage
bootimage: image

archclean:
	$(Q)$(MAKE) $(clean)=arch/e2k/boot

archmrproper:

archdep:
	@$(MAKEBOOT) dep

install-headers: 
	@$(MAKEBOOT) install-headers

install-includes: include/linux/version.h arch/e2k/include FORCE
	$(CONFIG_SHELL) scripts/gen-osl-include -l $(srctree) -r $(ROOT_WA)

build-install: FORCE
	$(CONFIG_SHELL) scripts/gen-osl-build -l $(srctree) -m $(MODLIB)

define archhelp
  echo  '* image/bootimage	- Kernel boot image (image.boot)'
  echo  '  zImage		- Compressed kernel boot image (image.boot)'
  echo  '  install-headers	- Install kernel headers in '
  echo  '                          <basedir>/usr/include'
  echo  '  e2sboot		- Build kernel boot image with small embedded boot for e2s simulator'
  echo  '  e8cboot		- Build kernel boot image with small embedded boot for e8c simulator'
  echo  '  e1cpboot		- Build kernel boot image with small embedded boot for e1cp simulator'
  echo  '  e8c2boot		- Build kernel boot image with small embedded boot for e8c2 simulator'
  echo  '  e12cboot		- Build kernel boot image with small embedded boot for e12c simulator'
  echo  '  e16cboot		- Build kernel boot image with small embedded boot for e16c simulator'
  echo  '  e2c3boot		- Build kernel boot image with small embedded boot for e2c3 simulator'
  echo  '  [with_kernel=1]	- When building boot, build in compressed kernel into the boot image'
endef
