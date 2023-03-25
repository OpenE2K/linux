ifneq ($(KERNELRELEASE),)
  obj-m += imgpcidd.o
else

KDIR	:= /lib/modules/$(shell uname -r)/build
PWD	:= $(shell pwd)


default:
	$(MAKE) -C $(KDIR)  M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR)  M=$(PWD) clean
	rm -f *.ko *.o *.mod.c module* Module*
endif









