# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2023 MCST

ccflags-y += -Iarch/e2k/kvm
EXTRA_CFLAGS += -Wframe-larger-than=4096

KVM := ../../../virt/kvm
KERNEL := ../kernel

obj-$(CONFIG_KVM_GUEST)		+= guest/

kvm-$(CONFIG_KVM_HOST_KERNEL)	+= $(KVM)/kvm_main.o
kvm-$(CONFIG_KVM_HOST_KERNEL)	+= $(KVM)/irqchip.o
kvm-$(CONFIG_KVM_HOST_KERNEL)	+= $(KVM)/eventfd.o
kvm-$(CONFIG_KVM_HOST_KERNEL)	+= $(KVM)/vfio.o
kvm-$(CONFIG_KVM_ASYNC_PF)	+= $(KVM)/async_pf.o async_pf.o
kvm-$(CONFIG_KVM_HOST_KERNEL)	+= $(KVM)/binary_stats.o

kvm-$(CONFIG_KVM_HOST_KERNEL)	+= pt-structs.o lapic.o ioapic.o ioepic.o \
				   irq_comm.o sclkr.o io.o user_area.o \
				   hypercalls.o process.o trap_table.o cpu.o \
				   sic-nbsr.o lt.o spmc.o
kvm-y				+= kvm-e2k.o

obj-y				+= cpu/

kvm-$(CONFIG_KVM_MMIO)		+= $(KVM)/coalesced_mmio.o

ifeq ($(CONFIG_KVM_HOST_KERNEL),y)
ifeq ($(shell test $(CONFIG_CPU_ISET_MIN) -lt 6; echo $$?),0)
# To compile gregs and ctpr saving for iset v6
AFLAGS_REMOVE_trap_table.o = $(CFLAGS_ALL_CPUS)
AFLAGS_trap_table.o += -march=elbrus-v6

CFLAGS_REMOVE_hv_cpu.o = $(CFLAGS_ALL_CPUS)
CFLAGS_hv_cpu.o := -march=elbrus-v6
CFLAGS_REMOVE_hv_intercepts.o = $(CFLAGS_ALL_CPUS)
CFLAGS_hv_intercepts.o := -march=elbrus-v6
CFLAGS_REMOVE_hv_glaunch.o = $(CFLAGS_ALL_CPUS)
CFLAGS_hv_glaunch.o := -march=elbrus-v6
endif


# "-fexclude-ctpr2" - make sure that AAU is not zeroed before we get to it
# "-fno-global-regs" - to switch global registers in C instead of asm
# "-fno-dam" - see CPU_HWBUG_L1I_RBRANCH_CALLS
CFLAGS_hv_glaunch.o += $(call lcc-option,-fexclude-ctpr2) $(call lcc-option,-fno-global-regs)
ifeq ($(CONFIG_MIGHT_HAVE_CPU_HWBUG_L1I_RBRANCH_CALLS),y)
CFLAGS_hv_glaunch.o += $(call lcc-option,-fno-dam)
endif

# "-fno-semi-spec-ld -fno-loop-apb" - avoid semi-speculative loads (both
#   normal and from AAU) in kvm_light_hcalls() because it is executed with
#   guest's page tables and the can be no unexpected page faults.
#   TODO bug 140465 - set attribute((optimize)) on kvm_light_hcalls instead
# "-fno-global-regs" - to switch global registers in C instead of asm
CFLAGS_hypercalls.o += $(call lcc-option,-fno-semi-spec-ld) \
		       $(call lcc-option,-fno-loop-apb) $(call lcc-option,-fno-global-regs)

kvm-$(CONFIG_KVM_HW_VIRTUALIZATION) += hv_cpu.o hv_mmu.o hv_intercepts.o hv_glaunch.o

ifeq ($(CONFIG_KVM_PARAVIRTUALIZATION),y)
# To make sure that AAU is not zeroed before we get to it
CFLAGS_ttable.o := $(call lcc-option,-fexclude-ctpr2)
# We should not instrument these files
CFLAGS_REMOVE_ttable.o := -fprofile-generate-kernel

kvm-$(CONFIG_DEBUG_VCPU_RUNSTATE)  += paravirt_sw/runstate.o
kvm-$(CONFIG_KVM_GVA_CACHE)	   += paravirt_sw/gva_cache.o
kvm-$(CONFIG_KVM_GVA_CACHE_STAT)   += paravirt_sw/gva_cache_stat.o
kvm-$(CONFIG_KVM_SHADOW_PT_ENABLE) += paravirt_sw/mmu-pv-spt.o
kvm-$(CONFIG_KVM_HOST_KERNEL)      += paravirt_sw/ttable.o
kvm-y += paravirt_sw/mmu-pv.o paravirt_sw/proc_context_stacks.o paravirt_sw/string.o \
	 paravirt_sw/boot_spinlock.o paravirt_sw/spinlock.o paravirt_sw/csd_lock.o \
	 paravirt_sw/switch.o paravirt_sw/ctx_signal_stacks.o paravirt_sw/debug.o \
	 paravirt_sw/gaccess.o paravirt_sw/mm.o paravirt_sw/gpid.o paravirt_sw/complete.o \
	 paravirt_sw/recovery-ldst.o paravirt_sw/nid.o paravirt_sw/cepic.o \
	 paravirt_sw/mmu-flush.o paravirt_sw/cpu.o paravirt_sw/process.o \
	 paravirt_sw/timer.o paravirt_sw/virq.o paravirt_sw/intercepts.o \
	 paravirt_sw/priv-hypercalls.o
endif  # CONFIG_KVM_PARAVIRTUALIZATION

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

endif	# CONFIG_KVM_HOST_KERNEL

ifdef CONFIG_FUNCTION_TRACER
# Do not profile paravirtualized functions callers
CFLAGS_REMOVE_paravirt.o = $(CC_FLAGS_FTRACE)
endif

obj-$(CONFIG_KVM)	+= kvm.o

