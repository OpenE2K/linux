
ccflags-y += -DCONFIG_BOOT_E2K

obj-y	:= bios.o southbridge.o superio.o init_kbd.o \
		newpci.o linuxpci.o io.o

obj-$(CONFIG_ENABLE_BIOS_MPTABLE) += mpspec.o mptable.o

obj-$(CONFIG_ENABLE_MGA) += mga.o
	
obj-y += video/
	
