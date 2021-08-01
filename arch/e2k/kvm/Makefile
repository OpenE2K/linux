subdir-ccflags-y := -Werror -Wswitch -Wenum-compare

ccflags-y += -Iarch/e2k/kvm
EXTRA_CFLAGS += -Wframe-larger-than=4096

KVM := ../../../virt/kvm
KERNEL := ../kernel

obj-$(CONFIG_KVM_GUEST)		+= guest/

kvm-$(CONFIG_KVM_HOST_MODE)	+= $(KVM)/kvm_main.o
kvm-$(CONFIG_KVM_HOST_MODE)	+= $(KVM)/irqchip.o
kvm-$(CONFIG_KVM_HOST_MODE)	+= $(KVM)/eventfd.o
kvm-$(CONFIG_KVM_HOST_MODE)	+= $(KVM)/vfio.o
kvm-$(CONFIG_KVM_ASYNC_PF)	+= $(KVM)/async_pf.o

kvm-$(CONFIG_KVM_HOST_MODE)	+= pt-structs.o switch.o \
				   lapic.o ioapic.o cepic.o ioepic.o \
				   irq_comm.o timer.o virq.o io.o \
				   user_area.o nid.o vmid.o gpid.o \
				   hypercalls.o process.o ttable.o \
				   trap_table.o cpu.o mm.o mmu_flush.o \
				   boot_spinlock.o spinlock.o \
				   runstate.o complete.o \
				   sic-nbsr.o lt.o spmc.o gaccess.o debug.o
kvm-y				+= kvm-e2k.o
obj-y				+= cpu/

kvm-$(CONFIG_KVM_MMIO)         += $(KVM)/coalesced_mmio.o

ifeq ($(CONFIG_KVM_HOST_MODE),y)

# To make sure that AAU is not zeroed before we get to it
CFLAGS_ttable.o := -fexclude-ctpr2

# To compile gregs and ctpr saving for iset v6
AFLAGS_REMOVE_trap_table.o = $(CFLAGS_ALL_CPUS)
AFLAGS_trap_table.o += -march=elbrus-v6

# We should no instrument these files
CFLAGS_REMOVE_ttable.o := -fprofile-generate-kernel

# -fexclude-ctpr2: make sure that AAU is not zeroed before we get to it
# -fno-dam - hardware bug 124206 workaround
CFLAGS_REMOVE_hv_cpu.o = $(CFLAGS_ALL_CPUS)
CFLAGS_hv_cpu.o := -march=elbrus-v6 -fexclude-ctpr2 -fno-dam
CFLAGS_REMOVE_intercepts.o = $(CFLAGS_ALL_CPUS)
CFLAGS_intercepts.o := -march=elbrus-v6

kvm-$(CONFIG_KVM_HW_VIRTUALIZATION) += hv_cpu.o hv_mmu.o intercepts.o

ifeq ($(CONFIG_KVM_PARAVIRTUALIZATION),y)
kvm-y += mmu-pv.o
ifeq ($(CONFIG_KVM_SHADOW_PT_ENABLE),y)
kvm-y += mmu-pv-spt.o
endif	# CONFIG_KVM_SHADOW_PT_ENABLE
endif	# CONFIG_KVM_PARAVIRTUALIZATION

kvm-$(CONFIG_KVM_HV_MMU) += mmu-e2k.o page_track.o

endif	# CONFIG_KVM_HOST_MODE

kvm-$(CONFIG_KVM_HOST_MODE)	+= csd_lock.o

kvm-$(CONFIG_PARAVIRT)		+= paravirt.o

ifdef CONFIG_FUNCTION_TRACER
# Do not profile paravirtualized functions callers
CFLAGS_REMOVE_paravirt.o = -pg
endif

obj-$(CONFIG_KVM)	+= kvm.o

