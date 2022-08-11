CFLAGS_REMOVE_iset_v2.o = $(CFLAGS_ALL_CPUS)
CFLAGS_REMOVE_iset_v5.o = $(CFLAGS_ALL_CPUS)
CFLAGS_REMOVE_iset_v6.o = $(CFLAGS_ALL_CPUS)

CFLAGS_iset_v2.o := -march=elbrus-v2
CFLAGS_iset_v5.o := -march=elbrus-v5
CFLAGS_iset_v6.o := -march=elbrus-v6

obj-$(CONFIG_VIRTUALIZATION) := iset_v2.o iset_v5.o

ifeq ($(CONFIG_VIRTUALIZATION),y)
obj-$(CONFIG_KVM_HW_VIRTUALIZATION)	+= iset_v6.o
endif	# CONFIG_VIRTUALIZATION
