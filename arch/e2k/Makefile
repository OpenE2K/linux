
#
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
#

# SHELL := $(shell if [ -x "$$BASH" ]; then echo $$BASH; \
#	  else if [ -x /bin/bash ]; then echo /bin/bash; \
#	  else if [ -x /usr/local/bin/bash ]; then echo /usr/local/bin/bash; \
#	  else echo sh; fi ; fi ; fi)

AS	= $(shell $(CC) -print-prog-name=as)
OBJDUMP	= $(shell $(CC) -print-prog-name=objdump)
LD	= $(shell $(CC) -print-prog-name=ld)
OBJCOPY	= $(shell $(CC) -print-prog-name=objcopy)

KBUILD_CFLAGS += -fkernel -gline -masm-inline

KBUILD_CFLAGS += $(call cc-option,-finline-functions,) \
                 $(call cc-option,-finline-functions-called-once,)

# Some uninteresting or broken warnings can be disabled with #pragma's only
KBUILD_CFLAGS += -Wno-array-bounds -Wno-duplicate-type-qualifier \
		-Wno-builtin-functions-redefined \
		-include $(srctree)/arch/e2k/include/asm/override-lcc-warnings.h

LDFLAGS_vmlinux :=
CHECKFLAGS	+= -D__e2k__

CFLAGS += -pipe -D_PMD_ACCESS_DEBUG_ -D_MULTI_PMD_PAGE_TABLE_ -D__linux__

KBUILD_CFLAGS += -D__builtin_return_address=__e2k_kernel_return_address
KBUILD_CFLAGS += $(CFLAGS)

ifeq  ($(call cc-lcc-yn),y)
  LCC_VERSION := $(shell $(CC) -v 2>&1 | grep lcc | cut -d. -f 2)
  LCC_120 := $(shell if [[ $(LCC_VERSION) > 19 ]] || [[ "$(LCC_VERSION)" == "A" ]]; \
    then echo "y"; else echo "n"; fi; )
  ifeq ($(LCC_120),n)
    ifdef CONFIG_E2S_CPU_RF_BUG
     KBUILD_CFLAGS += -ffix-hw-bug67911
    endif
  endif
endif
ifdef CONFIG_SMP_DAM_BUG
 KBUILD_CFLAGS += -fno-dam-call
endif

CFLAGS_E3S	:= -mcpu=elbrus-2c+
CFLAGS_E3M	:= -mcpu=elbrus
CFLAGS_ES2	:= $(CFLAGS_E3S)
CFLAGS_E2S	:= -mcpu=elbrus-4c
CFLAGS_E8C	:= -mcpu=elbrus-4c	# FIXME: should be elbrus-8c
CFLAGS_E1CP	:= -mcpu=elbrus-4c	# FIXME: should be elbrus-1c+
CFLAGS_E8C2	:= -mcpu=elbrus-4c	# FIXME: should be elbrus-8c2
CFLAGS_E2K_SIC	:= $(CFLAGS_E3S)

export		CFLAGS_E3S CFLAGS_E3M CFLAGS_ES2 CFLAGS_E2S CFLAGS_E8C \
		CFLAGS_E1CP CFLAGS_E8C2 CFLAGS_E2K_SIC

ifeq ($(CONFIG_E2K_MACHINE),y)
 ifeq ($(CONFIG_E2K_E3M),y)
 KBUILD_CFLAGS		+= $(CFLAGS_E3M)
 KBUILD_AFLAGS		+= $(CFLAGS_E3M)
 else
  ifeq ($(CONFIG_E2K_E3M_SIM),y)
  KBUILD_CFLAGS		+= $(CFLAGS_E3M)
  KBUILD_AFLAGS		+= $(CFLAGS_E3M)
  else
   ifeq ($(CONFIG_E2K_E3M_IOHUB),y)
   KBUILD_CFLAGS	+= $(CFLAGS_E3M)
   KBUILD_AFLAGS	+= $(CFLAGS_E3M)
   else
    ifeq ($(CONFIG_E2K_E3M_IOHUB_SIM),y)
    KBUILD_CFLAGS	+= $(CFLAGS_E3M)
    KBUILD_AFLAGS	+= $(CFLAGS_E3M)
    else
     ifeq ($(CONFIG_E2K_E3S),y)
     KBUILD_CFLAGS	+= $(CFLAGS_E3S)
     KBUILD_AFLAGS	+= $(CFLAGS_E3S)
     else
      ifeq ($(CONFIG_E2K_E3S_SIM),y)
      KBUILD_CFLAGS	+= $(CFLAGS_E3S)
      KBUILD_AFLAGS	+= $(CFLAGS_E3S)
      else
       ifeq ($(CONFIG_E2K_ES2_DSP),y)
       KBUILD_CFLAGS	+= $(CFLAGS_ES2)
       KBUILD_AFLAGS	+= $(CFLAGS_ES2)
       else
        ifeq ($(CONFIG_E2K_ES2_DSP_SIM),y)
        KBUILD_CFLAGS	+= $(CFLAGS_ES2)
        KBUILD_AFLAGS	+= $(CFLAGS_ES2)
        else
         ifeq ($(CONFIG_E2K_ES2_RU),y)
         KBUILD_CFLAGS	+= $(CFLAGS_ES2)
         KBUILD_AFLAGS	+= $(CFLAGS_ES2)
         else
          ifeq ($(CONFIG_E2K_ES2_RU_SIM),y)
          KBUILD_CFLAGS	+= $(CFLAGS_ES2)
          KBUILD_AFLAGS	+= $(CFLAGS_ES2)
          else
           ifeq ($(CONFIG_E2K_E2S),y)
           KBUILD_CFLAGS += $(CFLAGS_E2S)
           KBUILD_AFLAGS += $(CFLAGS_E2S)
           else
            ifeq ($(CONFIG_E2K_E2S_SIM),y)
            KBUILD_CFLAGS += $(CFLAGS_E2S)
            KBUILD_AFLAGS += $(CFLAGS_E2S)
            else
             ifeq ($(CONFIG_E2K_E8C),y)
             KBUILD_CFLAGS += $(CFLAGS_E8C)
             KBUILD_AFLAGS += $(CFLAGS_E8C)
             else
              ifeq ($(CONFIG_E2K_E8C_SIM),y)
              KBUILD_CFLAGS += $(CFLAGS_E8C)
              KBUILD_AFLAGS += $(CFLAGS_E8C)
              else
               ifeq ($(CONFIG_E2K_E1CP),y)
               KBUILD_CFLAGS += $(CFLAGS_E1CP)
               KBUILD_AFLAGS += $(CFLAGS_E1CP)
               else
                ifeq ($(CONFIG_E2K_E1CP_SIM),y)
                KBUILD_CFLAGS += $(CFLAGS_E1CP)
                KBUILD_AFLAGS += $(CFLAGS_E1CP)
		else
                 ifeq ($(CONFIG_E2K_E8C2),y)
                 KBUILD_CFLAGS += $(CFLAGS_E8C2)
                 KBUILD_AFLAGS += $(CFLAGS_E8C2)
                 else
                  ifeq ($(CONFIG_E2K_E8C2_SIM),y)
                  KBUILD_CFLAGS += $(CFLAGS_E8C2)
                  KBUILD_AFLAGS += $(CFLAGS_E8C2)
                  else
                   error "Invalid e2k machine type"
                  endif	# ifeq ($(CONFIG_E2K_E8C2_SIM),y)
                 endif	# ifeq ($(CONFIG_E2K_E8C2),y)
                endif	# ifeq ($(CONFIG_E2K_E1CP_SIM),y)
               endif	# ifeq ($(CONFIG_E2K_E1CP),y)
              endif	# ifeq ($(CONFIG_E2K_E8C_SIM),y)
             endif	# ifeq ($(CONFIG_E2K_E8C),y)
            endif	# ifeq ($(CONFIG_E2K_E2S_SIM),y)
           endif	# ifeq ($(CONFIG_E2K_E2S),y)
          endif	# ifeq ($(CONFIG_E2K_ES2_RU_SIM),y)
         endif	# ifeq ($(CONFIG_E2K_ES2_RU),y)
        endif	# ifeq ($(CONFIG_E2K_ES2_DSP_SIM),y)
       endif	# ifeq ($(CONFIG_E2K_ES2_DSP),y)
      endif	# ifeq ($(CONFIG_E2K_E3S_SIM),y)
     endif	# ifeq ($(CONFIG_E2K_E3S),y)
    endif	# ifeq ($(CONFIG_E2K_E3M_IOHUB_SIM),y)
   endif	# ifeq ($(CONFIG_E2K_E3M_IOHUB),y)
  endif		# ifeq ($(CONFIG_E2K_E3M_SIM),y)
 endif		# ifeq ($(CONFIG_E2K_E3M),y)
else		# ! ifeq ($(CONFIG_E2K_MACHINE),y)
KBUILD_CFLAGS	+= -mcpu=generic
LDFLAGS		+= --relaxed-e2k-machine-check
endif


obj-$(CONFIG_KPROBES)	+= kprobes.o

KBUILD_CFLAGS += $(cflags-y)

libs-y 					+= arch/e2k/lib/
core-y					+= arch/e2k/kernel/ \
					   arch/e2k/mm/ \
					   arch/e2k/p2v/ \
					   arch/e2k/fast_syscalls/

core-$(CONFIG_PROTECTED_MODE)		+= arch/e2k/3p/

drivers-$(CONFIG_PCI)			+= arch/e2k/pci/ 

# suspend and hibernation support
drivers-$(CONFIG_PM)			+= arch/e2k/power/

# Elbrus common modules
core-y					+= arch/l/
drivers-$(CONFIG_PCI)			+= arch/l/pci/	

boot :=   arch/e2k/boot
BOOTIMAGE_NAME=image.boot
BOOTIMAGE=arch/e2k/boot/$(BOOTIMAGE_NAME)
ROMIMAGE=arch/e2k/boot/image.bios
FLASHIMAGE=arch/e2k/boot/image.flash
E3SBOOT=e3sboot
E3SROM=e3srom
E3SFASTROM=e3sfastrom
ES2ROM=es2rom
E2SROM=e2srom
E8CROM=e8crom
E1CPROM=e1cprom
E8C2ROM=e8c2rom

all: romimage

MAKEBOOT = $(MAKE) -C arch/$(ARCH)/boot

.PHONY:	clean archclean archmrproper archdep romimage bootimage image flash

romimage: vmlinux 
	$(Q)$(MAKE) $(build)=$(boot) CONFIG_E3M=y $(ROMIMAGE)

e3sboot:
	$(Q)$(MAKE) $(build)=$(boot) CONFIG_E3S=y $(E3SBOOT)

e3srom: vmlinux  
	$(Q)$(MAKE) $(build)=$(boot) CONFIG_E3S=y $(E3SROM)

e3sfastrom:
	$(Q)$(MAKE) $(build)=$(boot) CONFIG_E3S=y $(E3SFASTROM)

es2rom: vmlinux  
	$(Q)$(MAKE) $(build)=$(boot) CONFIG_ES2=y $(ES2ROM)

ve3srom: vmlinux
	$(Q)$(MAKE) $(build)=$(boot) CONFIG_ES2=y CONFIG_VIRT_E3S=y $(ES2ROM)

e2srom: vmlinux
	$(Q)$(MAKE) $(build)=$(boot) CONFIG_E2S=y $(E2SROM)

e8crom: vmlinux
	$(Q)$(MAKE) $(build)=$(boot) CONFIG_E8C=y $(E8CROM)

e1cprom: vmlinux
	$(Q)$(MAKE) $(build)=$(boot) CONFIG_E1CP=y $(E1CPROM)

e8c2rom: vmlinux
	$(Q)$(MAKE) $(build)=$(boot) CONFIG_E8C2=y $(E8C2ROM)

bootimage: vmlinux
	$(Q) \
	$(MAKE) $(build)=$(boot) CONFIG_BOOT=y E2K_KERNEL_CSUM=0 $(BOOTIMAGE); \
	e2k_kernel_csum=`cksum $(BOOTIMAGE_NAME) | awk '{print $$1;}'`; \
	echo "Kernel image check sum: " $$e2k_kernel_csum; \
	$(MAKE) $(build)=$(boot) CONFIG_BOOT=y E2K_KERNEL_CSUM=$$e2k_kernel_csum $(BOOTIMAGE)


image: bootimage

flash: vmlinux
	$(Q)$(MAKE) $(build)=$(boot) CONFIG_E3M=y $(FLASHIMAGE)

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

install-mroot: 
	@$(MAKEBOOT) BOOTIMAGE=bzImage install-mroot

define archhelp
  echo  '* romimage	        - Kernel ROM image '
  echo  '                          (arch/$(ARCH)/boot/image.bios)'
  echo  '  bootimage or image	- Kernel disk boot image'
  echo  '                          (arch/$(ARCH)/boot/image.boot)'
  echo  '  flash                - Kernel flash image'
  echo  '                          (arch/$(ARCH)/boot/image.flash)'
  echo  '  install-headers	- Install kernel headers in '
  echo  '                          <basedir>/usr/include'
  echo  '  install-mroot        - Install kernel in Mini-Root tree'
  echo  '  e3sboot		- Only e3s boot '
  echo  '  e3srom		- Build kernel ROM image with existing boot (see e3sboot)'
  echo  '  e3sfastrom		- Link existing vmlinux (make vmlinux) with existing boot (see e3sboot)'
  echo  '  es2rom		- Build kernel ROM image with existing boot for es2 (cubic)'
  echo  '  e2srom		- Build kernel ROM image with existing boot for e2s'
  echo  '  e8crom		- Build kernel ROM image with existing boot for e8c'
  echo  '  e1cprom		- Build kernel ROM image with existing boot for e1c+'
  echo  '  e8c2rom		- Build kernel ROM image with existing boot for e8c2'
endef
