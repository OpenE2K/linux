 # SPDX-License-Identifier: GPL-2.0
 # Copyright (c) 2023 MCST
 
GCOV_PROFILE := n

OBJCOPY		+= -O binary -R .note -R .comment -S
OBJCOPYFLAGS	:= -O binary -R .note -R .comment -S

ccflags-y := -DCONFIG_BOOT_E2K
ifeq ($(call cc-option-yn,-fno-semi-spec-ld -fno-spec-ld),y)
	ccflags-y += -fno-semi-spec-ld -fno-spec-ld
else
	ccflags-y += -fno-ld-spec
endif


targets := vmlinux vmlinux.bin vmlinux.bin.gz vmlinux.bin.bz2 vmlinux.bin.xz \
	   vmlinux.bin.lzma vmlinux.bin.lzo vmlinux.bin.lz4 cimage image \
	   bimage cpiggy.o bpiggy.o epiggy.o zpiggy.o piggy.o System.map

empty:=
space:= $(empty) $(empty)
ORIG_CFLAGS := $(KBUILD_CFLAGS)
ORIG_CFLAGS := $(subst $(space)-fprofile-generate-kernel$(space),$(space),$(ORIG_CFLAGS))
ORIG_CFLAGS := $(subst $(space)-fprofile-use="$(PROFILE_USE)"$(space),$(space),$(ORIG_CFLAGS))
KBUILD_CFLAGS = $(ORIG_CFLAGS)

RANLIB = $(shell $(CC) -print-prog-name=ranlib)

ROMSCRIPT = $(obj)/aploader.lds
KBUILD_CFLAGS += -DCONFIG_E2K_SIC
KBUILD_AFLAGS += -DCONFIG_E2K_SIC

FLAGS_EPIC_EIOH := -DCONFIG_BOOT_EPIC -DCONFIG_EIOH

ifeq ($(CONFIG_E2S),y)
	KBUILD_CFLAGS += -DCONFIG_E2S -DCONFIG_E2K_FULL_SIC
	KBUILD_AFLAGS += -DCONFIG_E2S -DCONFIG_E2K_FULL_SIC
else
 ifeq ($(CONFIG_E8C),y)
	KBUILD_CFLAGS += -DCONFIG_E8C \
			 -DCONFIG_E2K_FULL_SIC \
			 -DCONFIG_L_IOH2
	KBUILD_AFLAGS += -DCONFIG_E8C \
			 -DCONFIG_E2K_FULL_SIC \
			 -DCONFIG_L_IOH2
 else
  ifeq ($(CONFIG_E1CP),y)
	KBUILD_CFLAGS += -DCONFIG_E1CP \
			 -DCONFIG_E2K_LEGACY_SIC \
			 -DCONFIG_L_IOH2
	KBUILD_AFLAGS += -DCONFIG_E1CP \
			 -DCONFIG_E2K_LEGACY_SIC \
			 -DCONFIG_L_IOH2
  else
   ifeq ($(CONFIG_E8C2),y)
	KBUILD_CFLAGS += -DCONFIG_E8C2 \
			 -DCONFIG_E2K_FULL_SIC \
			 -DCONFIG_L_IOH2
	KBUILD_AFLAGS += -DCONFIG_E8C2 \
			 -DCONFIG_E2K_FULL_SIC \
			 -DCONFIG_L_IOH2
   else
    ifeq ($(CONFIG_E12C),y)
	KBUILD_CFLAGS += -DCONFIG_E12C \
			 -DCONFIG_E2K_FULL_SIC \
			 -DCONFIG_L_IOH2 \
			 $(FLAGS_EPIC_EIOH)
	KBUILD_AFLAGS += -DCONFIG_E12C \
			 -DCONFIG_E2K_FULL_SIC \
			 -DCONFIG_L_IOH2 \
			 $(FLAGS_EPIC_EIOH)
    else
     ifeq ($(CONFIG_E16C),y)
	KBUILD_CFLAGS += -DCONFIG_E16C \
			 -DCONFIG_E2K_FULL_SIC \
			 -DCONFIG_L_IOH2 \
			 $(FLAGS_EPIC_EIOH)
	KBUILD_AFLAGS += -DCONFIG_E16C \
			 -DCONFIG_E2K_FULL_SIC \
			 -DCONFIG_L_IOH2 \
			 $(FLAGS_EPIC_EIOH)
     else
      ifeq ($(CONFIG_E2C3),y)
	 KBUILD_CFLAGS += -DCONFIG_E2C3 \
			  -DCONFIG_E2K_FULL_SIC \
			  -DCONFIG_L_IOH2 \
			  $(FLAGS_EPIC_EIOH)
	 KBUILD_AFLAGS += -DCONFIG_E2C3 \
			  -DCONFIG_E2K_FULL_SIC \
			  -DCONFIG_L_IOH2 \
			  $(FLAGS_EPIC_EIOH)
      else
       ifeq ($(CONFIG_E48C),y)
	  KBUILD_CFLAGS += -DCONFIG_E48C \
			   -DCONFIG_E2K_FULL_SIC \
			   -DCONFIG_L_IOH2 \
			   $(FLAGS_EPIC_EIOH)
	  KBUILD_AFLAGS += -DCONFIG_E48C \
			   -DCONFIG_E2K_FULL_SIC \
			   -DCONFIG_L_IOH2 \
			   $(FLAGS_EPIC_EIOH)
       else
        ifeq ($(CONFIG_E8V7),y)
	 KBUILD_CFLAGS += -DCONFIG_E8V7 \
			  -DCONFIG_E2K_FULL_SIC \
			  -DCONFIG_L_IOH2 \
			  $(FLAGS_EPIC_EIOH)
	 KBUILD_AFLAGS += -DCONFIG_E8V7 \
			  -DCONFIG_E2K_FULL_SIC \
			  -DCONFIG_L_IOH2 \
			  $(FLAGS_EPIC_EIOH)
	endif
       endif
      endif
     endif
    endif
   endif
  endif
 endif
endif

# remove profile flags
ORIG_CFLAGS := $(KBUILD_CFLAGS)
KBUILD_CFLAGS =$(subst -pg,,$(ORIG_CFLAGS))

START_OBJ = $(obj)/romstartup.o $(obj)/apstartup.o
targets += romstartup.o apstartup.o

obj-y := romloader.o jumpstart.o keyboard.o zip.o malloc.o stdio.o \
	 string.o recovery_string.o recovery_string_v5.o epic.o
 
AFLAGS_REMOVE_recovery_string_v5.o = $(CFLAGS_ALL_CPUS)
AFLAGS_recovery_string_v5.o += -march=elbrus-v5

obj-$(CONFIG_SMP) 			+= aploader.o smp.o
obj-$(CONFIG_L_LOCAL_APIC)		+= apic.o

obj-$(CONFIG_SERIAL_AM85C30_BOOT_CONSOLE) += Am85C30.o

obj-$(CONFIG_VGA_CONSOLE)		+= vga.o
obj-$(CONFIG_LMS_CONSOLE)		+= console.o

obj-$(CONFIG_BIOS)			+= bios/

BIOS_ELF   = image
ROM_LDFLAGS  = -e start -T $(TOPDIR)/$(ROMSCRIPT)


# lcc option '-fvisibility=hidden' allows us to reduce
# .got section size - this is a small optimization.
CFLAGS_decompress.o += -fpic -fvisibility=hidden -DE2K_P2V -O4
CFLAGS_machdep_fpic.o += -fpic -fvisibility=hidden -DE2K_P2V -O4
CFLAGS_string_fpic.o += -fpic -fvisibility=hidden -DE2K_P2V -O4
CFLAGS_string_guest_fpic.o += -fpic -fvisibility=hidden -DE2K_P2V -O4
AFLAGS_recovery_string_fpic.o += -fpic -fvisibility=hidden -DE2K_P2V
AFLAGS_REMOVE_recovery_string_v5_fpic.o = $(CFLAGS_ALL_CPUS)
AFLAGS_recovery_string_v5_fpic.o += -march=elbrus-v5 -fpic \
				    -fvisibility=hidden -DE2K_P2V

CFLAGS_bootblock.o += -fno-toplevel-reorder

targets += bootblock.o decompress.o machdep_fpic.o string_fpic.o \
	   recovery_string_fpic.o recovery_string_v5_fpic.o

TOPDIR = $(srctree)
SYSTEM = vmlinux
SYSTEM_IMAGE = $(objtree)/image.boot
CVS_TOPDIR = ../../../../..

ifdef CONFIG_BLK_DEV_INITRD
INITRD	= /tmp/initrd
INITRDO = initrd.o
else
INITRD  = 
INITRDO = 
endif

PIGGYO    = $(obj)/piggy.o

targets += $(objtree)/image.boot

targets += image.bios $(objtree)/image.bios $(objtree)/vmlinux.bin

all:	boot

dep:
	$(TOPDIR)/scripts/mkdep *.[Sch] > .depend

clean:
	rm -rf $(obj)/built-in-sym.o $(START_OBJ) $(BIOS_ELF) $(BIOS_IMAGE) _tmp_*
	$(Q)$(MAKE) $(build)=arch/e2k/boot/bios clean


$(INITRDO):
	tmpinitrd=_tmp_$$$$initrd; \
	rm -f $$tmpinitrd $$tmpinitrd.lnk; \
	if [ -x $(INITRD) ]; then \
		cp $(INITRD) $$tmpinitrd; \
	else \
		> $$tmpinitrd; \
	fi; \
	echo "SECTIONS { .initrd : { initrd_len = .; initrd_data = .; *(.data) initrd_data_end = .; }}" \
	> $$tmpinitrd.lnk; \
	$(LD) -r -o $(INITRDO) -b binary $$tmpinitrd -b elf64-e2k \
	-T $$tmpinitrd.lnk; \
	rm -f $$tmpinitrd $$tmpinitrd.lnk

bios: FORCE
	$(Q)$(MAKE) $(build)=arch/e2k/boot/bios bios

# piggy is gzipped kernel
LDFLAGS_zpiggy.o = -r -b binary --oformat elf64-e2k -T $(srctree)/$(src)/vmlinux.bin.lds \
-defsym input_data_noncomp_size=$(shell wc -c < $(objtree)/$(obj)/vmlinux.bin) \
-defsym boot_mode=0
$(obj)/zpiggy.o: $(obj)/vmlinux.bin.gz FORCE
	$(call if_changed,ld)

# piggy is empty
LDFLAGS_epiggy.o = -r -b binary --oformat elf64-e2k -T $(srctree)/$(src)/epiggy.lds \
-defsym input_data_noncomp_size=$(shell wc -c < $(objtree)/$(obj)/vmlinux.bin) \
-defsym boot_mode=1 -defsym input_data=0 -defsym input_data_end=0
$(obj)/epiggy.o: $(obj)/vmlinux.bin FORCE
	$(call if_changed,ld)


ifeq ($(with_kernel), 1)
$(PIGGYO): $(obj)/zpiggy.o
	@cp $(obj)/zpiggy.o $(obj)/piggy.o; \
	rm -f $(obj)/epiggy.o

$(objtree)/vmlinux.bin: ;
else
$(PIGGYO): $(obj)/epiggy.o
	@cp $(obj)/epiggy.o $(obj)/piggy.o; \
	rm -f $(obj)/zpiggy.o

$(objtree)/vmlinux.bin: $(obj)/vmlinux.bin
	@cp $(obj)/vmlinux.bin $(objtree)/vmlinux.bin
endif

$(obj)/built-in-sym.o: $(obj)/built-in.a
	@cp $(obj)/built-in.a $(obj)/built-in-sym.o; \
	$(RANLIB) $(obj)/built-in-sym.o

LDFLAGS_bimage := $(ROM_LDFLAGS)
$(obj)/bimage: $(obj)/built-in-sym.o $(START_OBJ) $(PIGGYO) $(INITRDO) FORCE
	$(call if_changed,ld)

$(obj)/image.bios: $(obj)/bimage FORCE
	$(call if_changed,objcopy)

$(objtree)/image.bios: $(obj)/image.bios
	@cp $(obj)/image.bios $(objtree)/image.bios

$(obj)/System.map: $(obj)/bimage
	@$(NM) $(obj)/bimage | grep -v '\(compiled\)\|\(\.o$$\)\|\( [aUw] \)\|\(\<L\)\|\(\.\.ng$$\)\|\(LASH[RL]DI\)' | sort > $(obj)/System.map

boot: $(objtree)/image.bios $(objtree)/vmlinux.bin $(obj)/System.map

$(obj)/vmlinux.bin: vmlinux FORCE
	$(call if_changed,objcopy)
	@ksize=`ls -l $(obj)/vmlinux.bin | awk '{print $$5;}'`; \
	echo "Non-compressed kernel size:" $$ksize

suffix-y :=
suffix-$(CONFIG_KERNEL_GZIP) := .gz
suffix-$(CONFIG_KERNEL_BZIP2) := .bz2
suffix-$(CONFIG_KERNEL_LZ4) := .lz4
suffix-$(CONFIG_KERNEL_LZMA) := .lzma
suffix-$(CONFIG_KERNEL_XZ) := .xz
suffix-$(CONFIG_KERNEL_LZO) := .lzo

$(obj)/vmlinux.bin.gz: $(obj)/vmlinux.bin FORCE
	$(call if_changed,gzip)
	@ksize=`ls -l $(obj)/vmlinux.bin.gz | awk '{print $$5;}'`; \
	echo "Compressed kernel size:" $$ksize
$(obj)/vmlinux.bin.bz2: $(obj)/vmlinux.bin FORCE
	$(call if_changed,bzip2)
	@ksize=`ls -l $(obj)/vmlinux.bin.bz2 | awk '{print $$5;}'`; \
	echo "Compressed kernel size:" $$ksize
$(obj)/vmlinux.bin.lz4: $(obj)/vmlinux.bin FORCE
	$(call if_changed,lz4)
	@ksize=`ls -l $(obj)/vmlinux.bin.lz4 | awk '{print $$5;}'`; \
	echo "Compressed kernel size:" $$ksize
$(obj)/vmlinux.bin.lzma: $(obj)/vmlinux.bin FORCE
	$(call if_changed,lzma)
	@ksize=`ls -l $(obj)/vmlinux.bin.lzma | awk '{print $$5;}'`; \
	echo "Compressed kernel size:" $$ksize
$(obj)/vmlinux.bin.xz: $(obj)/vmlinux.bin FORCE
	$(call if_changed,xzkern)
	@ksize=`ls -l $(obj)/vmlinux.bin.xz | awk '{print $$5;}'`; \
	echo "Compressed kernel size:" $$ksize
$(obj)/vmlinux.bin.lzo: $(obj)/vmlinux.bin FORCE
	$(call if_changed,lzo)
	@ksize=`ls -l $(obj)/vmlinux.bin.lzo | awk '{print $$5;}'`; \
	echo "Compressed kernel size:" $$ksize

LDFLAGS_bpiggy.o := -r -b binary --oformat elf64-e2k -T $(srctree)/$(src)/vmlinux.bin.lds
$(obj)/bpiggy.o: $(obj)/vmlinux.bin FORCE
	$(call if_changed,ld)

LDFLAGS_cpiggy.o := -r -b binary --oformat elf64-e2k -T $(srctree)/$(src)/vmlinux.bin.lds
$(obj)/cpiggy.o: $(obj)/vmlinux.bin$(suffix-y) FORCE
	$(call if_changed,ld)

LDFLAGS_image = -static -e gap -T $(srctree)/$(src)/boot.lds \
 -defsym __kernel_size=$(shell wc -c < $(objtree)/$(obj)/vmlinux.bin)
$(obj)/image: $(obj)/bpiggy.o $(obj)/bootblock.o FORCE
	$(call if_changed,ld)

ifdef CONFIG_KVM_GUEST_KERNEL
targets += string_guest_fpic.o
STRING_GUEST_FPIC_O=$(obj)/string_guest_fpic.o
COMPRESSED_SCRIPT=compressed_guest.lds
else
STRING_GUEST_FPIC_O=
COMPRESSED_SCRIPT=compressed.lds
endif

LDFLAGS_cimage = -static -e decompress_kernel -T $(srctree)/$(src)/$(COMPRESSED_SCRIPT) \
 -defsym __orig_kernel_size=$(shell wc -c < $(objtree)/$(obj)/vmlinux.bin) \
 -defsym __kernel_size=$(shell wc -c < $(objtree)/$(obj)/vmlinux.bin$(suffix-y))
$(obj)/cimage: $(obj)/cpiggy.o $(obj)/bootblock.o $(obj)/decompress.o  \
	       $(obj)/string_fpic.o $(STRING_GUEST_FPIC_O) \
	       $(obj)/recovery_string_fpic.o $(obj)/recovery_string_v5_fpic.o \
	       $(obj)/machdep_fpic.o FORCE
	$(call if_changed,ld)

$(objtree)/image.boot: $(obj)/image FORCE
	$(call if_changed,objcopy)

$(objtree)/zImage: $(obj)/cimage FORCE
	$(call if_changed,objcopy)

#$(objtree)/image.boot
SYS_IMAGE := $(objtree)/zImage
install:
	@sh $(srctree)/$(src)/install.sh $(KERNELRELEASE) $(SYS_IMAGE) $(objtree)/System.map "$(INSTALL_PATH)"
