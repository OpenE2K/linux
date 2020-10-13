OBJCOPY		+= -O binary -R .note -R .comment -S
OBJCOPYFLAGS	:= -O binary -R .note -R .comment -S

EXTRA_CFLAGS += -DCONFIG_BOOT_E2K -fno-control-spec
export	EXTRA_CFLAGS

ifeq ($(CONFIG_E3S),y)
ROMSCRIPT = $(obj)/aploader_e3s.lds
KBUILD_CFLAGS += -DCONFIG_E3S -DCONFIG_E2K_SIC -DCONFIG_E2K_FULL_SIC
KBUILD_AFLAGS += -DCONFIG_E3S -DCONFIG_E2K_SIC -DCONFIG_E2K_FULL_SIC
else
	ifeq ($(CONFIG_ES2),y)
		ROMSCRIPT = $(obj)/aploader_e3s.lds
		KBUILD_CFLAGS += -DCONFIG_ES2 -DCONFIG_E2K_SIC \
				 -DCONFIG_E2K_FULL_SIC
		KBUILD_AFLAGS += -DCONFIG_ES2 -DCONFIG_E2K_SIC \
				 -DCONFIG_E2K_FULL_SIC
		ifeq ($(CONFIG_VIRT_E3S),y)
			KBUILD_CFLAGS += -DCONFIG_VIRT_E3S
			KBUILD_AFLAGS += -DCONFIG_VIRT_E3S
		endif
	else
		ifeq ($(CONFIG_E2S),y)
			ROMSCRIPT = $(obj)/aploader_e3s.lds
			KBUILD_CFLAGS += -DCONFIG_E2S -DCONFIG_E2K_SIC \
					 -DCONFIG_E2K_FULL_SIC
			KBUILD_AFLAGS += -DCONFIG_E2S -DCONFIG_E2K_SIC \
					 -DCONFIG_E2K_FULL_SIC
		else
			ifeq ($(CONFIG_E8C),y)
				ROMSCRIPT = $(obj)/aploader_e3s.lds
				KBUILD_CFLAGS += -DCONFIG_E8C \
						 -DCONFIG_E2K_SIC \
						 -DCONFIG_E2K_FULL_SIC \
						 -DCONFIG_L_IOH2
				KBUILD_AFLAGS += -DCONFIG_E8C \
						 -DCONFIG_E2K_SIC \
						 -DCONFIG_E2K_FULL_SIC \
						 -DCONFIG_L_IOH2
			else
				ifeq ($(CONFIG_E1CP),y)
					ROMSCRIPT = $(obj)/aploader_e1cp.lds
					KBUILD_CFLAGS += -DCONFIG_E1CP \
						-DCONFIG_E2K_SIC \
						-DCONFIG_E2K_LEGACY_SIC \
						-DCONFIG_L_IOH2
					KBUILD_AFLAGS += -DCONFIG_E1CP \
						-DCONFIG_E2K_SIC \
						-DCONFIG_E2K_LEGACY_SIC \
						-DCONFIG_L_IOH2
				else
					ifeq ($(CONFIG_E8C2),y)
						ROMSCRIPT = $(obj)/aploader_e3s.lds
						KBUILD_CFLAGS += -DCONFIG_E8C2 \
							 -DCONFIG_E2K_SIC \
							 -DCONFIG_E2K_FULL_SIC \
							 -DCONFIG_L_IOH2
						KBUILD_AFLAGS += -DCONFIG_E8C2 \
							 -DCONFIG_E2K_SIC \
							 -DCONFIG_E2K_FULL_SIC \
							 -DCONFIG_L_IOH2
					else
						ifeq ($(CONFIG_E3M),y)
							ROMSCRIPT = $(obj)/aploader.lds
							KBUILD_CFLAGS += -DCONFIG_E3M
							KBUILD_AFLAGS += -DCONFIG_E3M
						else
							ROMSCRIPT = $(obj)/aploader.lds
						endif
					endif
				endif
			endif
		endif
	endif
endif
FLASHSCRIPT = $(obj)/flash.lds

# remove profile flags
ORIG_CFLAGS := $(KBUILD_CFLAGS)
KBUILD_CFLAGS =$(subst -pg,,$(ORIG_CFLAGS))

START_OBJ = $(obj)/romstartup.o $(obj)/apstartup.o
obj-y := romloader.o jumpstart.o keyboard.o zip.o malloc.o \
		stdio.o string.o recovery_string.o
 

obj-$(CONFIG_STATE_SAVE) 		+= ide_boot.o
obj-$(CONFIG_SMP) 			+= aploader.o smp.o
obj-$(CONFIG_L_LOCAL_APIC) 		+= apic.o
ifeq ($(CONFIG_E3S),y)
obj-$(CONFIG_SERIAL_AM85C30_BOOT_CONSOLE) += Am85C30.o
else
	ifeq ($(CONFIG_ES2),y)
		obj-$(CONFIG_SERIAL_AM85C30_BOOT_CONSOLE) += Am85C30.o
	else
		ifeq ($(CONFIG_E2S),y)
			obj-$(CONFIG_SERIAL_AM85C30_BOOT_CONSOLE) += Am85C30.o
		else
			ifeq ($(CONFIG_E8C),y)
				obj-$(CONFIG_SERIAL_AM85C30_BOOT_CONSOLE) += \
					Am85C30.o
			else
				ifeq ($(CONFIG_E1CP),y)
					obj-$(CONFIG_SERIAL_AM85C30_BOOT_CONSOLE) += \
						Am85C30.o
				else
					ifeq ($(CONFIG_E8C2),y)
						obj-$(CONFIG_SERIAL_AM85C30_BOOT_CONSOLE) += \
							Am85C30.o
					else
						obj-$(CONFIG_SERIAL_NS16550_BOOT_CONSOLE) += \
							ns16550.o
					endif
				endif
			endif
		endif
	endif
endif
obj-$(CONFIG_VGA_CONSOLE)		+= vga.o
obj-$(CONFIG_LMS_CONSOLE)		+= console.o

obj-$(CONFIG_BIOS)			+= bios/

boot-y		:= $(patsubst %/, %/built-in.o, $(obj)/)

ifeq ($(CONFIG_BOOT),y)
CFLAGS_x86.o  += -D__e2k_kernel_csum=$(E2K_KERNEL_CSUM)
endif

BIOS_ELF   = image
BIOS_IMAGE = image.bios
ROM_LDFLAGS  = -e start -T $(TOPDIR)/$(ROMSCRIPT)

BOOT_OBJS  = $(obj)/x86.o
BOOT_ELF   = image
BOOT_IMAGE = image.boot
BOOT_LDFLAGS = -e x86boot -T $(TOPDIR)/$(obj)/boot.lds

CSUMBOOT_IMAGE = image.csumboot

FLASH_IMAGE = image.flash
MAKEFLASH = make_flash_disk
FLASH_LDFLAGS  = -e start -T $(FLASHSCRIPT)

TOPDIR = $(srctree)
SYSTEM = vmlinux
CVS_TOPDIR = ../../../../..

ifdef CONFIG_BLK_DEV_INITRD
INITRD	= /tmp/initrd
INITRDO = initrd.o
else
INITRD  = 
INITRDO = 
endif

DUMPSYMS =
SYMTABLEO =
STRTABLEO =

PIGGYO    = piggy.o
RPIGGYO   = rpiggy.o
BPIGGYO   = bpiggy.o
FPIGGYO   = fpiggy.o

all:	romimage 

arch/e2k/boot/image.bios: romimage

arch/e2k/boot/image.boot: bootimage

arch/e2k/boot/image.csumboot: csumbootimage

arch/e2k/boot/image.flash: flash

dep:
	$(TOPDIR)/scripts/mkdep *.[Sch] > .depend

clean:
	rm -rf $(boot-y) $(START_OBJ) $(BOOT_OBJS) $(BIOS_ELF) $(BOOT_ELF) \
           $(BIOS_IMAGE) _tmp_*
	$(Q)$(MAKE) $(build)=arch/e2k/boot/bios clean

$(RPIGGYO): $(SYSTEM)
	@tmppiggy=_tmp_$$$$piggy; \
	rm -f $$tmppiggy $$tmppiggy.gz $$tmppiggy.lnk; \
	$(OBJCOPY) $(SYSTEM) $$tmppiggy; \
	echo "SECTIONS { .rodata : { input_data = .; *(.data) input_data_end = .;  } }" > $$tmppiggy.lnk; \
	ksize=`ls -l $$tmppiggy | awk '{print $$5;}'`; \
	echo "Non-compressed kernel size:" $$ksize; \
	if [ $$ksize -gt 15728640 ]; then \
		gzip --best $$tmppiggy; \
		$(LD) -r -o $(RPIGGYO) -b binary $$tmppiggy.gz -b elf64-e2k \
		-T $$tmppiggy.lnk -defsym input_data_noncomp_size=$$ksize   \
		-defsym fmode=0 ; \
	else \
		$(LD) -r -o $(RPIGGYO) -b binary $$tmppiggy -b elf64-e2k \
		-T $$tmppiggy.lnk -defsym input_data_noncomp_size=$$ksize \
		-defsym fmode=0 ; \
	fi; \
	rm -f $$tmppiggy $$tmppiggy.lnk $$tmppiggy.gz


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

$(SYMTABLEO) $(STRTABLEO):  $(SYSTEM)
	tmpsymt=_tmp_$$$$symt; \
	tmpstrt=_tmp_$$$$strt; \
	rm -f $$tmpsymt $$tmpstrt $$tmpsymt.lnk $$tmpstrt.lnk; \
	$(HOSTCC) -o $(DUMPSYMS) $(DUMPSYMS).c; \
	./$(DUMPSYMS) $(SYSTEM) $$tmpsymt $$tmpstrt; \
	echo "SECTIONS { .symtable : { symtable_data = .; *(.data) symtable_data_end = .; }}" \
	> $$tmpsymt.lnk; \
	echo "SECTIONS { .strtable : { strtable_data = .; *(.data) strtable_data_end = .; }}" \
	> $$tmpstrt.lnk; \
	$(LD) -r -o $(SYMTABLEO) -b binary $$tmpsymt -b elf64-e2k \
	-T $$tmpsymt.lnk; \
	$(LD) -r -o $(STRTABLEO) -b binary $$tmpstrt -b elf64-e2k \
	-T $$tmpstrt.lnk; \
	rm -f $$tmpsymt $$tmpstrt $$tmpsymt.lnk $$tmpstrt.lnk $(DUMPSYMS)

bios: FORCE
	$(Q)$(MAKE) $(build)=arch/e2k/boot/bios bios

e3sboot: $(boot-y) $(START_OBJ) Makefile $(ROMSCRIPT)

e3slink: e3sboot $(RPIGGYO) $(INITRDO) $(SYMTABLEO) $(STRTABLEO) Makefile
	mv $(RPIGGYO) $(PIGGYO) ; \
	$(LD) $(ROM_LDFLAGS) $(boot-y) $(START_OBJ) $(PIGGYO) $(INITRDO) $(SYMTABLEO) \
	  $(STRTABLEO) -o $(BIOS_ELF)

e3srom:	e3slink	$(START_OBJ)
	$(OBJCOPY) $(BIOS_ELF) $(BIOS_IMAGE); \
	$(NM) $(BIOS_ELF) | grep -v '\(compiled\)\|\(\.o$$\)\|\( [aUw] \)\|\(\<L\)\|\(\.\.ng$$\)\|\(LASH[RL]DI\)' | sort > $(obj)/System.map
	rm -f $(SYMTABLEO) $(STRTABLEO) $(INITRDO)

e3sfastrom: e3slink $(START_OBJ)
	$(OBJCOPY) $(BIOS_ELF) $(BIOS_IMAGE); \
	$(NM) $(BIOS_ELF) | grep -v '\(compiled\)\|\(\.o$$\)\|\( [aUw] \)\|\(\<L\)\|\(\.\.ng$$\)\|\(LASH[RL]DI\)' | sort > $(obj)/System.map
	rm -f $(SYMTABLEO) $(STRTABLEO) $(INITRDO)

es2rom:	e3slink	$(START_OBJ)
	$(OBJCOPY) $(BIOS_ELF) $(BIOS_IMAGE); \
	$(NM) $(BIOS_ELF) | grep -v '\(compiled\)\|\(\.o$$\)\|\( [aUw] \)\|\(\<L\)\|\(\.\.ng$$\)\|\(LASH[RL]DI\)' | sort > $(obj)/System.map
	rm -f $(SYMTABLEO) $(STRTABLEO) $(INITRDO)

ves2rom: e3slink $(START_OBJ)
	$(OBJCOPY) $(BIOS_ELF) $(BIOS_IMAGE); \
	$(NM) $(BIOS_ELF) | grep -v '\(compiled\)\|\(\.o$$\)\|\( [aUw] \)\|\(\<L\)\|\(\.\.ng$$\)\|\(LASH[RL]DI\)' | sort > $(obj)/System.map
	rm -f $(SYMTABLEO) $(STRTABLEO) $(INITRDO)

e2srom:	e3slink	$(START_OBJ)
	$(OBJCOPY) $(BIOS_ELF) $(BIOS_IMAGE); \
	$(NM) $(BIOS_ELF) | grep -v '\(compiled\)\|\(\.o$$\)\|\( [aUw] \)\|\(\<L\)\|\(\.\.ng$$\)\|\(LASH[RL]DI\)' | sort > $(obj)/System.map
	rm -f $(SYMTABLEO) $(STRTABLEO) $(INITRDO)

e8crom:	e3slink	$(START_OBJ)
	$(OBJCOPY) $(BIOS_ELF) $(BIOS_IMAGE); \
	$(NM) $(BIOS_ELF) | grep -v '\(compiled\)\|\(\.o$$\)\|\( [aUw] \)\|\(\<L\)\|\(\.\.ng$$\)\|\(LASH[RL]DI\)' | sort > $(obj)/System.map
	rm -f $(SYMTABLEO) $(STRTABLEO) $(INITRDO)

e1cprom: e3slink $(START_OBJ)
	$(OBJCOPY) $(BIOS_ELF) $(BIOS_IMAGE); \
	$(NM) $(BIOS_ELF) | grep -v '\(compiled\)\|\(\.o$$\)\|\( [aUw] \)\|\(\<L\)\|\(\.\.ng$$\)\|\(LASH[RL]DI\)' | sort > $(obj)/System.map
	rm -f $(SYMTABLEO) $(STRTABLEO) $(INITRDO)

e8c2rom: e3slink $(START_OBJ)
	$(OBJCOPY) $(BIOS_ELF) $(BIOS_IMAGE); \
	$(NM) $(BIOS_ELF) | grep -v '\(compiled\)\|\(\.o$$\)\|\( [aUw] \)\|\(\<L\)\|\(\.\.ng$$\)\|\(LASH[RL]DI\)' | sort > $(obj)/System.map
	rm -f $(SYMTABLEO) $(STRTABLEO) $(INITRDO)

link:	 $(boot-y) $(START_OBJ) $(RPIGGYO) $(INITRDO) $(SYMTABLEO) $(STRTABLEO) Makefile
	 mv $(RPIGGYO) $(PIGGYO) ; \
	 $(LD) $(ROM_LDFLAGS) $(boot-y) $(START_OBJ) $(PIGGYO) $(INITRDO) $(SYMTABLEO) \
	  $(STRTABLEO) -o $(BIOS_ELF)

romimage: link
	$(OBJCOPY) $(BIOS_ELF) $(BIOS_IMAGE); \
	$(NM) $(BIOS_ELF) | grep -v '\(compiled\)\|\(\.o$$\)\|\( [aUw] \)\|\(\<L\)\|\(\.\.ng$$\)\|\(LASH[RL]DI\)' | sort > $(obj)/System.map
	rm -f $(SYMTABLEO) $(STRTABLEO) $(INITRDO)

$(BPIGGYO): $(SYSTEM)
	@tmppiggy=_tmp_$$$$piggy; \
	rm -f $$tmppiggy $$tmppiggy.gz $$tmppiggy.lnk; \
	$(OBJCOPY) $(SYSTEM) $$tmppiggy; \
	echo "SECTIONS { .rodata : { input_data = .; *(.data) input_data_end = .;  } }" > $$tmppiggy.lnk; \
	ksize=`ls -l $$tmppiggy | awk '{print $$5;}'`; \
	echo "Non-compressed kernel size:" $$ksize; \
	$(LD) -r -o $(BPIGGYO) -b binary $$tmppiggy -b elf64-e2k \
	   -T $$tmppiggy.lnk -defsym input_data_noncomp_size=$$ksize ; \
	rm -f $$tmppiggy $$tmppiggy.lnk $$tmppiggy.gz


linkboot: $(BPIGGYO) Makefile $(BOOT_OBJS)
	 @mv $(BPIGGYO) $(PIGGYO) ; \
	 $(LD) $(BOOT_LDFLAGS) $(PIGGYO) $(BOOT_OBJS) -o $(BOOT_ELF)

bootimage: linkboot
	@$(OBJCOPY) $(BOOT_ELF) $(BOOT_IMAGE); \
	rm -f $(PIGGYO) $(BOOT_ELF); \
	echo 'Kernel: image.boot is ready' ' (#'`cat .version`')'

calccsum:
	rm -f $(BOOT_IMAGE) $(BOOT_OBJS)

csumbootimage: calccsum linkboot
	$(OBJCOPY) $(BOOT_ELF) $(CSUMBOOT_IMAGE); \
	rm -f $(PIGGYO) $(BOOT_ELF)

$(FPIGGYO): $(SYSTEM)
	@tmppiggy=_tmp_$$$$piggy; \
	rm -f $$tmppiggy $$tmppiggy.gz $$tmppiggy.lnk; \
	$(OBJCOPY) $(SYSTEM) $$tmppiggy; \
	echo "SECTIONS { .rodata : { input_data = .; *(.data) input_data_end = .;  } }" > $$tmppiggy.lnk; \
	ksize=`ls -l $$tmppiggy | awk '{print $$5;}'`; \
	echo "Non-compressed kernel size:" $$ksize; \
	$(LD) -r -o $(FPIGGYO) -b binary $$tmppiggy -b elf64-e2k \
	   -T $$tmppiggy.lnk -defsym input_data_noncomp_size=$$ksize \
	   -defsym fmode=1; \
	rm -f $$tmppiggy $$tmppiggy.lnk $$tmppiggy.gz

linkflash: $(boot-y) $(START_OBJ) $(FPIGGYO) $(INITRDO) $(SYMTABLEO) $(STRTABLEO) Makefile
	mv $(FPIGGYO) $(PIGGYO) ; \
	$(LD) $(FLASH_LDFLAGS) $(boot-y) $(PIGGYO) $(START_OBJ) $(INITRDO) $(SYMTABLEO) \
	$(STRTABLEO) -o $(BIOS_ELF)

flash: linkflash
	$(OBJCOPY) $(BIOS_ELF) $(BIOS_IMAGE); \
	$(MAKEFLASH) $(FLASH_IMAGE) $(BIOS_IMAGE); \
	$(NM) $(BIOS_ELF) | grep -v '\(compiled\)\|\(\.o$$\)\|\( [aUw] \)\|\(\.\.ng$$\)\|\(LASH[RL]DI\)' | sort > $(obj)/System.map
	rm -f $(PIGGYO) $(SYMTABLEO) $(STRTABLEO) $(INITRDO) $(BIOS_ELF) $(BIOS_IMAGE);

install-headers:
	rm -rf $(CVS_TOPDIR)/usr/include; \
	mkdir -p $(CVS_TOPDIR)/usr/include; \
	ln -s $(TOPDIR)/include/linux $(CVS_TOPDIR)/usr/include/linux; \
	ln -s $(TOPDIR)/include/asm $(CVS_TOPDIR)/usr/include/asm; \
	ln -s $(TOPDIR)/include/asm-generic $(CVS_TOPDIR)/usr/include/asm-generic


