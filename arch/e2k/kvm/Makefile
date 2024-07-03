 # SPDX-License-Identifier: GPL-2.0
 # Copyright (c) 2023 MCST
 
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
				   hypercalls.o process.o ttable.o priv-hypercalls.o \
				   trap_table.o cpu.o mm.o mmu-flush.o \
				   boot_spinlock.o spinlock.o \
				   complete.o string.o  recovery-ldst.o \
				   sic-nbsr.o lt.o spmc.o gaccess.o debug.o \
				   proc_context_stacks.o ctx_signal_stacks.o
kvm-$(CONFIG_KVM_GVA_CACHE)	+= gva_cache.o
kvm-$(CONFIG_KVM_GVA_CACHE_STAT) += gva_cache_stat.o
kvm-y				+= kvm-e2k.o
kvm-$(CONFIG_DEBUG_VCPU_RUNSTATE) += runstate.o

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

CFLAGS_REMOVE_hv_cpu.o = $(CFLAGS_ALL_CPUS)
CFLAGS_hv_cpu.o := -march=elbrus-v6
CFLAGS_REMOVE_hv_intercepts.o = $(CFLAGS_ALL_CPUS)
CFLAGS_hv_intercepts.o := -march=elbrus-v6
CFLAGS_REMOVE_hv_glaunch.o = $(CFLAGS_ALL_CPUS)
CFLAGS_hv_glaunch.o := -march=elbrus-v6

# "-fexclude-ctpr2" - make sure that AAU is not zeroed before we get to it
# "-fno-dam" - hardware bug 124206 workaround (CPU_HWBUG_L1I_STOPS_WORKING)
CFLAGS_hv_glaunch.o += -fexclude-ctpr2
ifeq ($(CONFIG_MIGHT_HAVE_CPU_HWBUG_L1I_STOPS_WORKING),y)
CFLAGS_hv_glaunch.o += $(call cc-option,-fno-dam)
endif

# Avoid half-speculative loads (both normal and from AAU)
# in kvm_light_hcalls() because it is executed with guest's
# page tables and the can be no unexpected page faults.
# TODO bug 140465 - set attribute((optimize)) on kvm_light_hcalls instead
CFLAGS_hypercalls.o += $(call cc-option,-fno-semi-spec-ld) \
		    $(call cc-option,-fno-loop-apb)

kvm-$(CONFIG_KVM_HW_VIRTUALIZATION) += hv_cpu.o hv_mmu.o hv_intercepts.o hv_glaunch.o

kvm-y += intercepts.o
ifeq ($(CONFIG_KVM_PARAVIRTUALIZATION),y)
kvm-y += mmu-pv.o
ifeq ($(CONFIG_KVM_SHADOW_PT_ENABLE),y)
kvm-y += mmu-pv-spt.o
endif	# CONFIG_KVM_SHADOW_PT_ENABLE
endif	# CONFIG_KVM_PARAVIRTUALIZATION

ifeq ($(CONFIG_DYNAMIC_PT_STRUCT),y)
kvm-y	+= mmu-pt-dynamic.o
else	# !CONFIG_DYNAMIC_PT_STRUCT
kvm-y	+= mmu-pt-v3.o
kvm-y	+= mmu-pt-v5.o
kvm-y	+= mmu-pt-v6.o
kvm-y	+= mmu-pt-v6-v5.o
kvm-y	+= mmu-pt-v6-gp.o
endif	# CONFIG_DYNAMIC_PT_STRUCT

kvm-$(CONFIG_KVM_HV_MMU) += mmu-e2k.o
kvm-$(CONFIG_KVM_HV_MMU) += page_track.o

endif	# CONFIG_KVM_HOST_MODE

kvm-$(CONFIG_KVM_HOST_MODE)	+= csd_lock.o

ifdef CONFIG_FUNCTION_TRACER
# Do not profile paravirtualized functions callers
CFLAGS_REMOVE_paravirt.o = -pg
endif

obj-$(CONFIG_KVM)	+= kvm.o

