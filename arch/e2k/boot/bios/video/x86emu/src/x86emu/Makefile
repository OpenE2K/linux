
obj-y	:= decode.o fpu.o ops.o ops2.o prim_ops.o sys.o debug.o

INCS   = -I$(srctree)/$(src)/. -I$(srctree)/$(src)/../../../../../../../../include -I$(srctree)/$(src)/../../../.. -I$(srctree)/$(src)/../../include -I$(srctree)/$(src)/../../include/x86emu

KBUILD_CFLAGS += -D__DRIVER__ -DFORCE_POST $(INCS)
