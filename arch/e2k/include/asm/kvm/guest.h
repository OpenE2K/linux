/*
 * Kernel-based Virtual Machine driver for Linux
 *
 * This header defines architecture specific interfaces, e2k version
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#ifndef _ASM_E2K_KVM_GUEST_H
#define _ASM_E2K_KVM_GUEST_H

#include <linux/types.h>

#include <asm/cpu_regs_types.h>
#include <asm/aau_regs_types.h>
#include <asm/apicdef.h>
#include <asm/epicdef.h>
#include <asm/mmu_regs_types.h>
#include <asm/mmu_types.h>
#include <asm/kvm/vcpu-regs-debug.h>
#include <asm/kvm/irq.h>
#include <uapi/asm/sigcontext.h>

typedef	struct kvm_cpu_regs {
#if	defined(CONFIG_KVM_GUEST_KERNEL) && \
		defined(CONFIG_KVM_GUEST_HW_PV) && defined(CONFIG_KVM_HV_MMU)
	u64 __pad1[24];
#else	/* ! CONFIG_KVM_GUEST_KERNEL || |
		! CONFIG_KVM_GUEST_HW_PV || ! CONFIG_KVM_HV_MMU */
	e2k_cud_lo_t	CPU_CUD_lo;	/* Compilation Unit Descriptor */
	e2k_cud_hi_t	CPU_CUD_hi;
	e2k_gd_lo_t	CPU_GD_lo;	/* CU Globals Descriptor */
	e2k_gd_hi_t	CPU_GD_hi;
	e2k_oscud_lo_t	CPU_OSCUD_lo;	/* OS Compilation Unit Descriptor */
	e2k_oscud_hi_t	CPU_OSCUD_hi;
	e2k_osgd_lo_t	CPU_OSGD_lo;	/* OS CU Globals Descriptor */
	e2k_osgd_hi_t	CPU_OSGD_hi;
	e2k_cutd_t	CPU_CUTD;	/* Compilation Unit Table Register */
	e2k_cuir_t	CPU_CUIR;	/* Compilation Unit Index Register */
	e2k_tsd_t	CPU_TSD;	/* Compilation Unit Types Descriptor */

	e2k_usd_lo_t	CPU_USD_lo;	/* User Stack Descriptor Register */
	e2k_usd_hi_t	CPU_USD_hi;
	e2k_sbr_t	CPU_SBR;	/* Stack Base Register */
	e2k_psp_lo_t	CPU_PSP_lo;	/* Procedure Stack Pointer */
	e2k_psp_hi_t	CPU_PSP_hi;
	e2k_pshtp_t	CPU_PSHTP;	/* Procedure Stack Hardware */
      					/* Top Pointer */
	e2k_pcsp_lo_t	CPU_PCSP_lo;	/* Procedure Chain Stack Pointer */
	e2k_pcsp_hi_t	CPU_PCSP_hi;
	e2k_cr0_lo_t	CPU_CR0_lo;	/* Current Chain Register */
	e2k_cr0_hi_t	CPU_CR0_hi;
	e2k_cr1_lo_t	CPU_CR1_lo;
	e2k_cr1_hi_t	CPU_CR1_hi;
	e2k_pcshtp_t	CPU_PCSHTP;	/* Procedure Chain Stack Hardware */
					/* Top Pointer */
#endif	/* CONFIG_KVM_GUEST_KERNEL && \
		CONFIG_KVM_GUEST_HW_PV && CONFIG_KVM_HV_MMU */
	e2k_ctpr_t	CPU_CTPR1;	/* Control Transfer Preparation */
	e2k_ctpr_t	CPU_CTPR2;	/* Registers */
	e2k_ctpr_t	CPU_CTPR3;
	e2k_tir_t	CPU_TIRs[MAX_TIRs_NUM];	/* Trap Info Registers */
	int		CPU_TIRs_num;	/* number of occupied TIRs */
	u64		CPU_SBBP[SBBP_ENTRIES_NUM];
	e2k_wd_t	CPU_WD;		/* Window Descriptor Register */
	e2k_bgr_t	CPU_BGR;	/* Base Global Register */
	e2k_aasr_t	CPU_AASR;
	e2k_lsr_t	CPU_LSR;	/* Loop Status Register */
	e2k_lsr_t	CPU_LSR1;	/* */
	e2k_ilcr_t	CPU_ILCR;	/* Initial Loop Counters Register */
	e2k_ilcr_t	CPU_ILCR1;	/* */
	e2k_rpr_lo_t	CPU_RPR_lo;	/* Recovery point register */
	e2k_rpr_hi_t	CPU_RPR_hi;
	e2k_cutd_t	CPU_OSCUTD;	/* CUTD Register of OS */
	e2k_cuir_t	CPU_OSCUIR;	/* CUI register of OS */
	u64		CPU_OSR0;	/* OS register #0 */
	u32		CPU_OSEM;	/* OS Entries Mask */
	e2k_psr_t	CPU_E2K_PSR;	/* Processor State Register */
	e2k_upsr_t	CPU_UPSR;	/* User Processor State Register */
	e2k_pfpfr_t	CPU_PFPFR;	/* floating point control registers */
	e2k_fpcr_t	CPU_FPCR;
	e2k_fpsr_t	CPU_FPSR;
	u64		CPU_CLKR;	/* CPU current clock regigister */
	u64		CPU_SCLKR;	/* CPU system clock regigister */
	u64		CPU_SCLKM1;	/* CPU system clock regigister 1 */
	u64		CPU_SCLKM2;	/* CPU system clock regigister 2 */
	u64		CPU_SCLKM3;	/* CPU system clock regigister 3 */
	u64		CPU_CU_HW0;	/* Control Unit HardWare registers 0 */
	u64		CPU_CU_HW1;	/* Control Unit HardWare registers 1 */
	u64		CPU_IP;		/* Instruction Pointer register */
	e2k_idr_t	CPU_IDR;	/* Processor Identification Register */
	e2k_core_mode_t	CPU_CORE_MODE;	/* Processor Core Modes Register */
	u32		CPU_DIBCR;	/* diagnostic and monitors registers */
	u32		CPU_DIBSR;
	u64		CPU_DIMCR;
	u64		CPU_DIBAR0;
	u64		CPU_DIBAR1;
	u64		CPU_DIBAR2;
	u64		CPU_DIBAR3;
	u64		CPU_DIMAR0;
	u64		CPU_DIMAR1;
	u64		CPU_CS_lo;	/* Intel Segments registers */
	u64		CPU_CS_hi;
	u64		CPU_DS_lo;
	u64		CPU_DS_hi;
	u64		CPU_ES_lo;
	u64		CPU_ES_hi;
	u64		CPU_FS_lo;
	u64		CPU_FS_hi;
	u64		CPU_GS_lo;
	u64		CPU_GS_hi;
	u64		CPU_SS_lo;
	u64		CPU_SS_hi;
	/* virtual register only to support paravirtualization mode */
	u32		CPU_VCPU_ID;	/* VCPU # is set by host and can not */
					/* be modified */
} kvm_cpu_regs_t;

/*
 * CPU registers status flags
 */
/* the next flags mark updating of some VCPU registers by guest and */
/* host should recovere physical CPU registers from the memory copy */
#define	WD_UPDATED_CPU_REGS		0x00000001UL	/* register WD */
#define	USD_UPDATED_CPU_REGS		0x00000002UL	/* USD/SBR */
#define	CRS_UPDATED_CPU_REGS		0x00000004UL	/* CR0/CR1 */
#define	HS_REGS_UPDATED_CPU_REGS	0x00000008UL	/* PSP/PCSP/PSHTP */
							/* PCSHTP */
#define	MASK_UPDATED_CPU_REGS		0x0000ffffUL	/* mask of all */
							/* updating flags */

#define	KVM_SET_CPU_REGS_FLAGS(regs_status, flags_to_add)		\
		((regs_status) | (flags_to_add))
#define	KVM_CLEAR_CPU_REGS_FLAGS(regs_status, flags_to_clear)		\
		(((regs_status) | (flags_to_clear)) ^ (flags_to_clear))
#define	KVM_TEST_CPU_REGS_FLAGS(regs_status, flags_to_test)		\
		(((regs_status) & (flags_to_test)) != 0)
#define	KVM_TEST_CPU_REGS_STATUS(regs_status)				\
		((regs_status) != 0)
#define	TO_UPDATED_CPU_REGS_FLAGS(flags)				\
		((flags) & MASK_UPDATED_CPU_REGS)
#define	KVM_SET_UPDATED_CPU_REGS_FLAGS(regs_status, flags_to_add)	\
		KVM_SET_CPU_REGS_FLAGS(regs_status,			\
				TO_UPDATED_CPU_REGS_FLAGS(flags_to_add))
#define	KVM_CLEAR_UPDATED_CPU_REGS_FLAGS(regs_status, flags_to_clear)	\
		KVM_CLEAR_CPU_REGS_FLAGS(regs_status,			\
				TO_UPDATED_CPU_REGS_FLAGS(flags_to_clear))
#define	KVM_TEST_UPDATED_CPU_REGS_FLAG(regs_status, flag)		\
		KVM_TEST_CPU_REGS_FLAGS(regs_status,			\
				TO_UPDATED_CPU_REGS_FLAGS(flag))
#define	KVM_TEST_UPDATED_CPU_REGS_FLAGS(regs_status)			\
		KVM_TEST_CPU_REGS_FLAGS(regs_status, MASK_UPDATED_CPU_REGS)
#define	KVM_INIT_UPDATED_CPU_REGS_FLAGS(regs_status)			\
		KVM_CLEAR_CPU_REGS_FLAGS(regs_status, MASK_UPDATED_CPU_REGS)

typedef	struct kvm_cpu_state {
	unsigned long	regs_status;	/* CPU register status flags */
	kvm_cpu_regs_t	regs;		/* CPU registers state */
	e2k_aau_t	aau;		/* AAU registers state */
	u64		aaldi[AALDIS_REGS_NUM]; /* AALDI registers state */
	e2k_aalda_t	aalda[AALDAS_REGS_NUM]; /* AALDA registers state */
} kvm_cpu_state_t;

typedef	struct kvm_mmu_state {
	mmu_reg_t	regs[MMU_REGS_NUM];	/* MMU registers state */
	mmu_reg_t	debug_regs[MMU_DEBUG_REGS_NUM];	/* MMU DEBUG */
						/* registers state */
	trap_cellar_t	tcellar[MAX_TC_SIZE];	/* trap cellar */
	int		tc_count;		/* number of entries in */
						/* trap cellar */
} kvm_mmu_state_t;

typedef	struct kvm_apic_state {
	u8		regs[APIC_REGS_SIZE];
	atomic_t	virqs_num;	/* Local APIC unhendled and in */
					/* progress VIRQs number */
} kvm_apic_state_t;

typedef	struct kvm_epic_state {
	u8		regs[EPIC_REGS_SIZE];
	atomic_t	virqs_num;	/* CEPIC unhandled and in */
					/* progress VIRQs number */
} kvm_epic_state_t;

/*
 * Guest Local APIC is virtual and emulates on host.
 * So it can access to any local APIC from any virtual CPUs.
 * Base address of local APIC is expanded by follow flag and CPU #
 * to enable such access.
 */
#define	KVM_LAPIC_BASE_CPU_FLAG		0x4000000000000000UL	/* [62] */
#define	KVM_LAPIC_BASE_CPU_NUM_MASK	0x0fff000000000000UL	/* [59:48] */
#define	KVM_LAPIC_BASE_CPU_NUM_SHIFT	48
#define	KVM_CPU_TO_LAPIC_BASE(cpu_id)	\
		((cpu_id) << KVM_LAPIC_BASE_CPU_NUM_SHIFT)
#define	KVM_CPU_FROM_LAPIC_BASE(base)	\
		((((e2k_addr_t)(base)) & KVM_LAPIC_BASE_CPU_NUM_MASK) >> \
						KVM_LAPIC_BASE_CPU_NUM_SHIFT)
#define	KVM_GET_LAPIC_REG_ADDR(addr)	\
		((addr) & MAX_PA_MASK)
#define	KVM_SET_LAPIC_BASE_CPU(base, cpu_id)	\
		((((e2k_addr_t)(base)) & ~(KVM_LAPIC_BASE_CPU_FLAG | \
			KVM_LAPIC_BASE_CPU_NUM_MASK)) | \
				KVM_LAPIC_BASE_CPU_FLAG | \
					KVM_CPU_TO_LAPIC_BASE(cpu_id))

typedef	struct kvm_virqs_state {
	atomic_t	timer_virqs_num;	/* timer VIRQs unhendled and */
						/* in progress number */
	atomic_t	hvc_virqs_num;		/* Hypervisor Virtual Console */
						/* VIRQs unhendled and */
						/* in progress number */
} kvm_virqs_state_t;

typedef	struct kvm_timespec {
	long	tv_sec;			/* seconds */
	long	tv_nsec;		/* nanoseconds */
} kvm_timespec_t;

typedef	struct kvm_time {
	kvm_timespec_t	wall_time;	/* boot time */
	kvm_timespec_t	sys_time;	/* current system time */
} kvm_time_t;

/*
 * Host machine info
 */
typedef struct kvm_host_info {
	int		mach_id;	/* host machine ID */
	int		cpu_rev;	/* host CPU revision */
	int		cpu_iset;	/* host CPU instruction set version */
	bool		mmu_support_pt_v6; /* host MMU support new MMU Page */
					   /* Tables structures V6 */
	bool		is_hv;		/* host is hardware virtualized */
	bool		support_hw_hc;	/* host support hardware hypercals */
	unsigned long	features;	/* KVM and hypervisor features */
					/* see details <asm/kvm/hypervisor.h> */
	kvm_time_t	time;		/* current host time state */
} kvm_host_info_t;

/*
 * Information about the state and running time of a VCPU.
 * Based on Xen interface include/xen/interface/vcpu.h
 */

/*
 * VCPU is not runnable, but it is not blocked.
 * This is a 'catch all' state for things like hotplug and pauses by the
 * system administrator (or for critical sections in the hypervisor).
 * RUNSTATE_blocked dominates this state (it is the preferred state).
 */
#define RUNSTATE_offline	0

/* VCPU is currently running on a physical CPU. */
#define RUNSTATE_running	1

/* VCPU is runnable, but not currently scheduled on any physical CPU. */
#define RUNSTATE_runnable	2

/* VCPU is blocked (a.k.a. idle). It is therefore not runnable. */
#define RUNSTATE_blocked	3

/* VCPU execute hypercall */
#define RUNSTATE_in_hcall	4

/* VCPU is exited to handle exit request by QEMU. */
#define RUNSTATE_in_QEMU	5

/* VCPU is interrupted and execute trap handler. */
#define RUNSTATE_in_trap	6

/* VCPU is intercepted and is handling interception */
#define RUNSTATE_in_intercept	7
#define	RUNSTATES_num		(RUNSTATE_in_intercept + 1)

typedef struct kvm_runstate_info {
	/* VCPU's current state (RUNSTATE_*). */
	/* volatile */ int	 state;
	/* When was current state entered (system time, ns)? */
	/* volatile */ uint64_t state_entry_time;
	/*
	 * Time spent in each RUNSTATE_* (ns). The sum of these times is
	 * guaranteed not to drift from system time.
	 */
	/* volatile */ uint64_t time[RUNSTATES_num];
} kvm_runstate_info_t;

typedef struct kvm_vcpu_state {
	kvm_cpu_state_t		cpu;	/* virtual CPU state */
	kvm_mmu_state_t		mmu;	/* virtual MMU state */
	kvm_apic_state_t	lapic;	/* virtual Local APIC state */
	kvm_epic_state_t	cepic;	/* virtual CEPIC state */
	kvm_virqs_state_t	virqs;	/* virtual IRQs state */
					/* (excluding VIRQs from LAPIC) */
	kvm_host_info_t		*host;	/* host machine and kernel info */
	/* VCPU's current running state */
	kvm_runstate_info_t	runstate;
	bool			debug_mode_on;
	bool			irqs_under_upsr;
	bool			do_dump_state;	/* dump all stacks */
	bool			do_dump_stack;	/* dump only active stack */
#ifdef	VCPU_REGS_DEBUG
	vcpu_regs_trace_t	trace;	/* VCPU state trace */
#endif	/* VCPU_REGS_DEBUG */
} kvm_vcpu_state_t;

#define	DEBUG_MODE_ON		(vcpu->arch.kmap_vcpu_state->debug_mode_on)
#define	DO_DUMP_VCPU_STATE(vcpu)	\
		((vcpu)->arch.kmap_vcpu_state->do_dump_state)
#define	DO_DUMP_VCPU_STACK(vcpu)	\
		((vcpu)->arch.kmap_vcpu_state->do_dump_stack)
#define	DO_DUMP_VCPU(vcpu)		\
		(DO_DUMP_VCPU_STATE(vcpu) || DO_DUMP_VCPU_STACK(vcpu))
#define	VCPU_IRQS_UNDER_UPSR(vcpu)	\
		(vcpu->arch.kmap_vcpu_state->irqs_under_upsr)

/*
 * Basic macroses to access to VCPU state from guest
 */
#ifdef	CONFIG_USE_GD_TO_VCPU_ACCESS
#define	KVM_GET_VCPU_STATE_BASE(res)					\
({									\
	e2k_osgd_lo_t osgd_lo = native_read_OSGD_lo_reg();		\
	res = osgd_lo.GD_lo_base;					\
	res;								\
})

#define	E2K_LOAD_GUEST_VCPU_STATE_W(offset)	E2K_LOAD_GLOBAL_W(offset)
#define	E2K_LOAD_GUEST_VCPU_STATE_D(offset)	E2K_LOAD_GLOBAL_D(offset)
#define	E2K_STORE_GUEST_VCPU_STATE_W(offset, value)			\
			E2K_STORE_GLOBAL_W(offset, value)
#define	E2K_STORE_GUEST_VCPU_STATE_D(offset, value)			\
			E2K_STORE_GLOBAL_D(offset, value)
#else	/* ! CONFIG_USE_GD_TO_VCPU_ACCESS */

#define	DO_GET_VCPU_STATE_BASE(vcpu_state_greg_no, res)			\
		E2K_MOVE_DGREG_TO_DREG(vcpu_state_greg_no, res)
#define	KVM_GET_VCPU_STATE_BASE(res)					\
		DO_GET_VCPU_STATE_BASE(GUEST_VCPU_STATE_GREG, res)
#define	KVM_SAVE_VCPU_STATE_BASE(res)	KVM_GET_VCPU_STATE_BASE(res)

#define	DO_SET_VCPU_STATE_BASE(vcpu_state_greg_no, res)			\
		E2K_MOVE_DREG_TO_DGREG(vcpu_state_greg_no, res)
#define	KVM_SET_VCPU_STATE_BASE(res)					\
		DO_SET_VCPU_STATE_BASE(GUEST_VCPU_STATE_GREG, res)
#define	KVM_RESTORE_VCPU_STATE_BASE(res) KVM_SET_VCPU_STATE_BASE(res)

#define	E2K_LOAD_GUEST_VCPU_STATE_W(offset)				\
		E2K_LOAD_GREG_BASED_W(GUEST_VCPU_STATE_GREG, offset)
#define	E2K_LOAD_GUEST_VCPU_STATE_D(offset)				\
		E2K_LOAD_GREG_BASED_D(GUEST_VCPU_STATE_GREG, offset)
#define	E2K_STORE_GUEST_VCPU_STATE_W(offset, value)			\
		E2K_STORE_GREG_BASED_W(GUEST_VCPU_STATE_GREG, offset, value)
#define	E2K_STORE_GUEST_VCPU_STATE_D(offset, value)			\
		E2K_STORE_GREG_BASED_D(GUEST_VCPU_STATE_GREG, offset, value)
#endif	/* CONFIG_USE_GD_TO_VCPU_ACCESS */

#endif /* _ASM_E2K_KVM_GUEST_H */
