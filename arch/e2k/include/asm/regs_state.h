#ifndef _E2K_REGS_STATE_H
#define _E2K_REGS_STATE_H

/*
 * Some macroses (start with PREFIX_) can use in three modes and can operate
 * with virtualized or paravirtualized functions, resorces, other macroses.
 * Such macroses should not be used directly instead of it need use:
 *	NATIVE_XXX macroses for native, host and hypervisor kernel mode
 *			in all functions which can be called only on native
 *			running mode;
 *	KVM_XXX macroses for guest virtualized kernel in all functions,
 *			which can be called only on guest running mode;
 *	PV_XXX macroses for paravirtualized kernel and such macroses use
 *			pv_ops structures to call paravirtualized actions.
 *			These macroses can be used in all functions, which can
 *			be called only on paravirtualized running mode and
 *			structures pv_ops_yyy exist.
 *	XXX (pure macros without prefix) macroses for host and guest virtualized
 *			kernel mode in all functions, which can be called
 *			both running mode host and guest. These macroses depend
 *			on configuration (compilation) mode and turn into one
 *			of above three macroses type
 *			If kernel configured and compiled as native with or
 *			without virtualization support/ then XXX turn into
 *			NATIVE_XXX.
 *			if kernel configured and compiled as pure guest, then
 *			XXX turn into KVM_XXX
 *			if kernel configured and compiled as paravirtualized and
 *			can be run both mode as host and as guest, then
 *			XXX turn into PV_XXX
 * PV_TYPE argument in macroses is prefix and can be as above:
 *	NATIVE		native kernel with or without virtualization support
 *	KVM		guest kernel (can be run only as paravirtualized
 *			guest kernel)
 *	PV		paravirtualized kernel (can be run as host and as guest
 *			paravirtualized kernels)
 */

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/signal.h>
#include <linux/irqflags.h>

#ifndef __ASSEMBLY__
#include <asm/e2k_api.h>
#include <asm/cpu_regs_access.h>
#include <asm/gregs.h>
#include <asm/monitors.h>
#include <asm/mmu.h>
#include <asm/mmu_regs.h>
#include <asm/system.h>
#include <asm/ptrace.h>
#include <asm/p2v/boot_head.h>
#include <asm/head.h>
#include <asm/tags.h>
#include <asm/traps.h>
#include <asm/kvm/regs_state.h>
#ifdef CONFIG_MLT_STORAGE
#include <asm/mlt.h>
#endif

#endif /* __ASSEMBLY__ */

#include <asm/e2k_syswork.h>

//#define	CONTROL_USD_BASE_SIZE

#ifdef	CONTROL_USD_BASE_SIZE
#define	CHECK_USD_BASE_SIZE(regs)					\
({									\
	u64 base = (regs)->stacks.usd_lo.USD_lo_base;			\
	u64 size = (regs)->stacks.usd_hi.USD_hi_size;			\
	if ((base - size) & ~PAGE_MASK)	 {				\
		printk("Not page size aligned USD_base 0x%lx - "	\
			"USD_size 0x%lx = 0x%lx\n",			\
			base, size, base - size);			\
		dump_stack();						\
	}								\
})
#else
#define	CHECK_USD_BASE_SIZE(regs)
#endif

/* set/restore some kernel state registers to initial state */

static inline void native_set_kernel_CUTD(void)
{
	e2k_cutd_t	k_cutd;

	k_cutd.CUTD_reg = 0;
	k_cutd.CUTD_base = (e2k_addr_t)kernel_CUT;
	NATIVE_NV_NOIRQ_WRITE_CUTD_REG(k_cutd);
}

#define NATIVE_CLEAR_DAM	\
({ \
	NATIVE_SET_MMUREG(dam_inv, 0); \
})

/*
 * Macros to save and restore registers.
 */

#define COPY_U_HW_STACKS_FROM_TI(__stacks, ti) \
do { \
	e2k_psp_lo_t __psp_lo = ti->tmp_user_stacks.psp_lo; \
	e2k_psp_hi_t __psp_hi = ti->tmp_user_stacks.psp_hi; \
	e2k_pshtp_t __pshtp = ti->tmp_user_stacks.pshtp; \
	e2k_pcsp_lo_t __pcsp_lo = ti->tmp_user_stacks.pcsp_lo; \
	e2k_pcsp_hi_t __pcsp_hi = ti->tmp_user_stacks.pcsp_hi; \
	e2k_pcshtp_t __pcshtp = ti->tmp_user_stacks.pcshtp; \
\
	(__stacks)->psp_lo = __psp_lo; \
	(__stacks)->psp_hi = __psp_hi; \
	(__stacks)->psp_hi.PSP_hi_ind += GET_PSHTP_MEM_INDEX(__pshtp); \
	(__stacks)->pcsp_lo = __pcsp_lo; \
	(__stacks)->pcsp_hi = __pcsp_hi; \
	(__stacks)->pcsp_hi.PCSP_hi_ind += PCSHTP_SIGN_EXTEND(__pcshtp); \
	(__stacks)->pshtp = __pshtp; \
	(__stacks)->pcshtp = __pcshtp; \
} while (0)

#define COPY_U_HW_STACKS_TO_STACKS(__stacks_to, __stacks_from) \
do { \
	e2k_stacks_t *stacks_to = (__stacks_to); \
	e2k_stacks_t *stacks_from = (__stacks_from); \
\
	stacks_to->psp_lo = stacks_from->psp_lo; \
	stacks_to->psp_hi = stacks_from->psp_hi; \
	stacks_to->pcsp_lo = stacks_from->pcsp_lo; \
	stacks_to->pcsp_hi = stacks_from->pcsp_hi; \
	stacks_to->pshtp = stacks_from->pshtp; \
	stacks_to->pcshtp = stacks_from->pcshtp; \
} while (0)

/* usd regs are saved already */
#define PREFIX_SAVE_STACK_REGS(PV_TYPE, regs, ti, from_ti, flushc)	\
do {									\
	/* This flush reserves space for the next trap. */		\
	if (flushc)							\
		PV_TYPE##_FLUSHC;					\
	if (from_ti) {							\
		COPY_U_HW_STACKS_FROM_TI(&(regs)->stacks, ti);		\
	} else {							\
		u64 pshtp;						\
		u32 pcshtp;						\
		u64 psp_hi;						\
		u64 pcsp_hi;						\
		pshtp = PV_TYPE##_NV_READ_PSHTP_REG_VALUE();		\
		pcshtp = PV_TYPE##_READ_PCSHTP_REG_SVALUE();		\
		(regs)->stacks.psp_lo.PSP_lo_half =			\
				PV_TYPE##_NV_READ_PSP_LO_REG_VALUE();	\
		psp_hi = PV_TYPE##_NV_READ_PSP_HI_REG_VALUE();	\
		pcsp_hi = PV_TYPE##_NV_READ_PCSP_HI_REG_VALUE();	\
		(regs)->stacks.pcsp_lo.PCSP_lo_half =			\
				PV_TYPE##_NV_READ_PCSP_LO_REG_VALUE();\
		if (!flushc)						\
			pcsp_hi += pcshtp;				\
		psp_hi += GET_PSHTP_MEM_INDEX((e2k_pshtp_t)pshtp);	\
		AW((regs)->stacks.pshtp) = pshtp;			\
		(regs)->stacks.pcshtp = pcshtp;				\
		AW((regs)->stacks.psp_hi) = psp_hi;			\
		AW((regs)->stacks.pcsp_hi) = pcsp_hi;			\
	}								\
	AW((regs)->crs.cr0_lo) = PV_TYPE##_NV_READ_CR0_LO_REG_VALUE(); \
	AW((regs)->crs.cr0_hi) = PV_TYPE##_NV_READ_CR0_HI_REG_VALUE(); \
	AW((regs)->crs.cr1_lo) = PV_TYPE##_NV_READ_CR1_LO_REG_VALUE(); \
	AW((regs)->crs.cr1_hi) = PV_TYPE##_NV_READ_CR1_HI_REG_VALUE(); \
	AW((regs)->wd) = PV_TYPE##_READ_WD_REG_VALUE();		\
	CHECK_USD_BASE_SIZE(regs);					\
} while (0)

/* Save stack registers on kernel native/host/hypervisor mode */
#define NATIVE_SAVE_STACK_REGS(regs, ti, from_ti, flushc) \
		PREFIX_SAVE_STACK_REGS(NATIVE, regs, ti, from_ti, flushc)

#define STORE_USER_REGS_TO_THREAD_INFO(thread_info,			\
					stk_bottom, stk_top, stk_sz)	\
({									\
	(thread_info)->u_stack.bottom = stk_bottom;			\
	(thread_info)->u_stack.top = stk_top;				\
	(thread_info)->u_stack.size = stk_sz;				\
})

/*
 * Interrupts should be disabled by caller to read all hardware
 * stacks registers in coordinated state
 * Hardware stacks do not copy or flush to memory
 */
#define ATOMIC_SAVE_CURRENT_STACK_REGS(stacks, crs)			\
({									\
	ATOMIC_SAVE_ALL_STACKS_REGS(stacks, &(crs)->cr1_hi);		\
									\
	(stacks)->top = NATIVE_NV_READ_SBR_REG_VALUE();			\
	(crs)->cr0_lo = NATIVE_NV_READ_CR0_LO_REG();			\
	(crs)->cr0_hi = NATIVE_NV_READ_CR0_HI_REG();			\
	(crs)->cr1_lo = NATIVE_NV_READ_CR1_LO_REG();			\
									\
	/*								\
	 * Do not copy copy_user_stacks()'s kernel data stack frame	\
	 */								\
	(stacks)->usd_lo.USD_lo_base +=					\
		(((crs)->cr1_hi.CR1_hi_ussz << 4) -			\
			(stacks)->usd_hi.USD_hi_size);			\
	(stacks)->usd_hi.USD_hi_size =					\
		((crs)->cr1_hi.CR1_hi_ussz << 4);			\
})

#define	NATIVE_DO_SAVE_MONITOR_COUNTERS(sw_regs)			\
do {									\
	sw_regs->ddmar0 = NATIVE_READ_DDMAR0_REG_VALUE();		\
	sw_regs->ddmar1 = NATIVE_READ_DDMAR1_REG_VALUE();		\
	sw_regs->dimar0 = NATIVE_READ_DIMAR0_REG_VALUE();		\
	sw_regs->dimar1 = NATIVE_READ_DIMAR1_REG_VALUE();		\
} while (0)
#define	NATIVE_SAVE_MONITOR_COUNTERS(task)				\
do {									\
	struct sw_regs *sw_regs = &((task)->thread.sw_regs);		\
	NATIVE_DO_SAVE_MONITOR_COUNTERS(sw_regs);			\
} while (0)

/*
 * When we use monitor registers, we count monitor events for the whole system,
 * so DIMAR0, DIMAR1, DDMAR0 and DDMAR1 registers are not depend on process and
 * need not be saved while process switching. DIMCR and DDMCR registers are not
 * depend on process too, but they should be saved while process switching,
 * because they are used to determine monitoring start moment during monitor
 * events counting for a process.
 */
static inline void native_save_user_only_regs(struct sw_regs *sw_regs)
{
	if (machine.save_dimtp)
		machine.save_dimtp(&sw_regs->dimtp);

	/* Skip breakpoints-related fields handled by
	 * ptrace_hbp_triggered() and arch-independent
	 * hardware breakpoints support */
	AW(sw_regs->dibsr) &= E2K_DIBSR_MASK_ALL_BP;
	AW(sw_regs->dibsr) |= NATIVE_READ_DIBSR_REG_VALUE() &
			      ~E2K_DIBSR_MASK_ALL_BP;
	AW(sw_regs->ddbsr) &= E2K_DDBSR_MASK_ALL_BP;
	AW(sw_regs->ddbsr) |= NATIVE_READ_DDBSR_REG_VALUE() &
			      ~E2K_DDBSR_MASK_ALL_BP;

	sw_regs->ddmcr = NATIVE_READ_DDMCR_REG();
	sw_regs->dimcr = NATIVE_READ_DIMCR_REG();
	if (!MONITORING_IS_ACTIVE)
		NATIVE_DO_SAVE_MONITOR_COUNTERS(sw_regs);
}

#if (E2K_MAXGR_d == 32)

/* Save/Restore global registers */
#define	SAVE_GREGS_PAIR(gregs, nolo_save, nohi_save,			\
				nolo_greg, nohi_greg, iset)		\
		NATIVE_SAVE_GREG(&(gregs)[nolo_save],			\
				&(gregs)[nohi_save],			\
				nolo_greg,				\
				nohi_greg,				\
				iset)
#define	SAVE_GREGS_PAIR_V2(gregs, nolo_save, nohi_save,			\
				nolo_greg, nohi_greg)			\
		NATIVE_SAVE_GREG_V2(&(gregs)[nolo_save],		\
				&(gregs)[nohi_save],			\
				nolo_greg,				\
				nohi_greg)
#define	SAVE_GREGS_PAIR_V5(gregs, nolo_save, nohi_save,			\
				nolo_greg, nohi_greg)			\
		NATIVE_SAVE_GREG_V5(&(gregs)[nolo_save],		\
				&(gregs)[nohi_save],			\
				nolo_greg,				\
				nohi_greg)

/*
 * Registers gN-g(N+3) are reserved by ABI. Now N=16.
 * These registers hold pointers to current, so we can skip saving and
 * restoring them on context switch and upon entering/exiting signal handlers
 * (they are stored in thread_info)
 */
#define DO_SAVE_GREGS_ON_MASK(gregs, iset, PAIR_MASK_NOT_SAVE)		\
do {									\
	if (((PAIR_MASK_NOT_SAVE) & ((1 << 0) | (1 << 1))) == 0) {	\
		SAVE_GREGS_PAIR(gregs,  0,  1,  0,  1, iset);		\
	}								\
	if (((PAIR_MASK_NOT_SAVE) & ((1 << 2) | (1 << 3))) == 0) {	\
		SAVE_GREGS_PAIR(gregs,  2,  3,  2,  3, iset);		\
	}								\
	if (((PAIR_MASK_NOT_SAVE) & ((1 << 4) | (1 << 5))) == 0) {	\
		SAVE_GREGS_PAIR(gregs,  4,  5,  4,  5, iset);		\
	}								\
	if (((PAIR_MASK_NOT_SAVE) & ((1 << 6) | (1 << 7))) == 0) {	\
		SAVE_GREGS_PAIR(gregs,  6,  7,  6,  7, iset);		\
	}								\
	if (((PAIR_MASK_NOT_SAVE) & ((1 << 8) | (1 << 9))) == 0) {	\
		SAVE_GREGS_PAIR(gregs,  8,  9,  8,  9, iset);		\
	}								\
	if (((PAIR_MASK_NOT_SAVE) & ((1 << 10) | (1 << 11))) == 0) {	\
		SAVE_GREGS_PAIR(gregs, 10, 11, 10, 11, iset);		\
	}								\
	if (((PAIR_MASK_NOT_SAVE) & ((1 << 12) | (1 << 13))) == 0) {	\
		SAVE_GREGS_PAIR(gregs, 12, 13, 12, 13, iset);		\
	}								\
	if (((PAIR_MASK_NOT_SAVE) & ((1 << 14) | (1 << 15))) == 0) {	\
		SAVE_GREGS_PAIR(gregs, 14, 15, 14, 15, iset);		\
	}								\
	if (((PAIR_MASK_NOT_SAVE) & ((1 << 16) | (1 << 17))) == 0) {	\
		SAVE_GREGS_PAIR(gregs, 16, 17, 16, 17, iset);		\
	}								\
	if (((PAIR_MASK_NOT_SAVE) & ((1 << 18) | (1 << 19))) == 0) {	\
		SAVE_GREGS_PAIR(gregs, 18, 19, 18, 19, iset);		\
	}								\
	if (((PAIR_MASK_NOT_SAVE) & ((1 << 20) | (1 << 21))) == 0) {	\
		SAVE_GREGS_PAIR(gregs, 20, 21, 20, 21, iset);		\
	}								\
	if (((PAIR_MASK_NOT_SAVE) & ((1 << 22) | (1 << 23))) == 0) {	\
		SAVE_GREGS_PAIR(gregs, 22, 23, 22, 23, iset);		\
	}								\
	if (((PAIR_MASK_NOT_SAVE) & ((1 << 24) | (1 << 25))) == 0) {	\
		SAVE_GREGS_PAIR(gregs, 24, 25, 24, 25, iset);		\
	}								\
	if (((PAIR_MASK_NOT_SAVE) & ((1 << 26) | (1 << 27))) == 0) {	\
		SAVE_GREGS_PAIR(gregs, 26, 27, 26, 27, iset);		\
	}								\
	if (((PAIR_MASK_NOT_SAVE) & ((1 << 28) | (1 << 29))) == 0) {	\
		SAVE_GREGS_PAIR(gregs, 28, 29, 28, 29, iset);		\
	}								\
	if (((PAIR_MASK_NOT_SAVE) & ((1 << 30) | (1 << 31))) == 0) {	\
		SAVE_GREGS_PAIR(gregs, 30, 31, 30, 31, iset);		\
	}								\
} while (0)
#define DO_SAVE_LOCAL_GREGS_ON_MASK(gregs, iset, PAIR_MASK_NOT_SAVE)	\
do {									\
	if (((PAIR_MASK_NOT_SAVE) & ((1 << 16) | (1 << 17))) == 0) {	\
		SAVE_GREGS_PAIR(gregs,  0,  1, 16, 17, iset);		\
	}								\
	if (((PAIR_MASK_NOT_SAVE) & ((1 << 18) | (1 << 19))) == 0) {	\
		SAVE_GREGS_PAIR(gregs,  2,  3, 18, 19, iset);		\
	}								\
	if (((PAIR_MASK_NOT_SAVE) & ((1 << 20) | (1 << 21))) == 0) {	\
		SAVE_GREGS_PAIR(gregs,  4,  5, 20, 21, iset);		\
	}								\
	if (((PAIR_MASK_NOT_SAVE) & ((1 << 22) | (1 << 23))) == 0) {	\
		SAVE_GREGS_PAIR(gregs,  6,  7, 22, 23, iset);		\
	}								\
	if (((PAIR_MASK_NOT_SAVE) & ((1 << 24) | (1 << 25))) == 0) {	\
		SAVE_GREGS_PAIR(gregs,  8,  9, 24, 25, iset);		\
	}								\
	if (((PAIR_MASK_NOT_SAVE) & ((1 << 26) | (1 << 27))) == 0) {	\
		SAVE_GREGS_PAIR(gregs, 10, 11, 26, 27, iset);		\
	}								\
	if (((PAIR_MASK_NOT_SAVE) & ((1 << 28) | (1 << 29))) == 0) {	\
		SAVE_GREGS_PAIR(gregs, 12, 13, 28, 29, iset);		\
	}								\
	if (((PAIR_MASK_NOT_SAVE) & ((1 << 30) | (1 << 31))) == 0) {	\
		SAVE_GREGS_PAIR(gregs, 14, 15, 30, 31, iset);		\
	}								\
} while (0)

#define	SAVE_ALL_GREGS(gregs, iset)	\
		DO_SAVE_GREGS_ON_MASK(gregs, iset, 0UL)
#define	SAVE_GREGS_EXCEPT_NO(gregs, iset, GREGS_PAIR_NO_NOT_SAVE)	\
		DO_SAVE_GREGS_ON_MASK(gregs, iset,	\
					(1 << GREGS_PAIR_NO_NOT_SAVE))
#define	SAVE_GREGS_EXCEPT_KERNEL(gregs, iset)			\
		DO_SAVE_GREGS_ON_MASK(gregs, iset, KERNEL_GREGS_MASK)
#define	SAVE_GREGS_EXCEPT_GLOBAL_AND_KERNEL(gregs, iset)		\
		DO_SAVE_GREGS_ON_MASK(gregs, iset,			\
			(GLOBAL_GREGS_USER_MASK | KERNEL_GREGS_MASK))

# define SAVE_GREGS(gregs, save_global, iset)				\
do {									\
	if (save_global) {						\
		SAVE_GREGS_EXCEPT_KERNEL(gregs, iset);			\
	} else {							\
		SAVE_GREGS_EXCEPT_GLOBAL_AND_KERNEL(gregs, iset);	\
	}								\
} while (false)

/* Same as SAVE_GREGS but saves %g16-%g31 registers only */
# define SAVE_GREGS_SIGNAL(gregs, iset)					\
do {									\
	DO_SAVE_LOCAL_GREGS_ON_MASK(gregs, iset,			\
		(GLOBAL_GREGS_USER_MASK | KERNEL_GREGS_MASK));		\
} while (false)

#define	RESTORE_GREGS_PAIR(gregs, nolo_save, nohi_save,			\
					nolo_greg, nohi_greg, iset)	\
		NATIVE_RESTORE_GREG(&(gregs)[nolo_save],		\
					&(gregs)[nohi_save],		\
					nolo_greg,			\
					nohi_greg,			\
					iset)
#define	RESTORE_GREGS_PAIR_V2(gregs, nolo_save, nohi_save,		\
					nolo_greg, nohi_greg)		\
		NATIVE_RESTORE_GREG_V2(&(gregs)[nolo_save],		\
					&(gregs)[nohi_save],		\
					nolo_greg,			\
					nohi_greg)
#define	RESTORE_GREGS_PAIR_V5(gregs, nolo_save, nohi_save,		\
					nolo_greg, nohi_greg)		\
		NATIVE_RESTORE_GREG_V5(&(gregs)[nolo_save],		\
					&(gregs)[nohi_save],		\
					nolo_greg,			\
					nohi_greg)

#define DO_RESTORE_GREGS_ON_MASK(gregs, iset, PAIR_MASK_NOT_RESTORE)	\
do {									\
	if (((PAIR_MASK_NOT_RESTORE) & ((1 << 0) | (1 << 1))) == 0) {	\
		RESTORE_GREGS_PAIR(gregs,  0,  1,  0,  1, iset);	\
	}								\
	if (((PAIR_MASK_NOT_RESTORE) & ((1 << 2) | (1 << 3))) == 0) {	\
		RESTORE_GREGS_PAIR(gregs,  2,  3,  2,  3, iset);	\
	}								\
	if (((PAIR_MASK_NOT_RESTORE) & ((1 << 4) | (1 << 5))) == 0) {	\
		RESTORE_GREGS_PAIR(gregs,  4,  5,  4,  5, iset);	\
	}								\
	if (((PAIR_MASK_NOT_RESTORE) & ((1 << 6) | (1 << 7))) == 0) {	\
		RESTORE_GREGS_PAIR(gregs,  6,  7,  6,  7, iset);	\
	}								\
	if (((PAIR_MASK_NOT_RESTORE) & ((1 << 8) | (1 << 9))) == 0) {	\
		RESTORE_GREGS_PAIR(gregs,  8,  9,  8,  9, iset);	\
	}								\
	if (((PAIR_MASK_NOT_RESTORE) & ((1 << 10) | (1 << 11))) == 0) {	\
		RESTORE_GREGS_PAIR(gregs, 10, 11, 10, 11, iset);	\
	}								\
	if (((PAIR_MASK_NOT_RESTORE) & ((1 << 12) | (1 << 13))) == 0) {	\
		RESTORE_GREGS_PAIR(gregs, 12, 13, 12, 13, iset);	\
	}								\
	if (((PAIR_MASK_NOT_RESTORE) & ((1 << 14) | (1 << 15))) == 0) {	\
		RESTORE_GREGS_PAIR(gregs, 14, 15, 14, 15, iset);	\
	}								\
	if (((PAIR_MASK_NOT_RESTORE) & ((1 << 16) | (1 << 17))) == 0) {	\
		RESTORE_GREGS_PAIR(gregs, 16, 17, 16, 17, iset);	\
	}								\
	if (((PAIR_MASK_NOT_RESTORE) & ((1 << 18) | (1 << 19))) == 0) {	\
		RESTORE_GREGS_PAIR(gregs, 18, 19, 18, 19, iset);	\
	}								\
	if (((PAIR_MASK_NOT_RESTORE) & ((1 << 20) | (1 << 21))) == 0) {	\
		RESTORE_GREGS_PAIR(gregs, 20, 21, 20, 21, iset);	\
	}								\
	if (((PAIR_MASK_NOT_RESTORE) & ((1 << 22) | (1 << 23))) == 0) {	\
		RESTORE_GREGS_PAIR(gregs, 22, 23, 22, 23, iset);	\
	}								\
	if (((PAIR_MASK_NOT_RESTORE) & ((1 << 24) | (1 << 25))) == 0) {	\
		RESTORE_GREGS_PAIR(gregs, 24, 25, 24, 25, iset);	\
	}								\
	if (((PAIR_MASK_NOT_RESTORE) & ((1 << 26) | (1 << 27))) == 0) {	\
		RESTORE_GREGS_PAIR(gregs, 26, 27, 26, 27, iset);	\
	}								\
	if (((PAIR_MASK_NOT_RESTORE) & ((1 << 28) | (1 << 29))) == 0) {	\
		RESTORE_GREGS_PAIR(gregs, 28, 29, 28, 29, iset);	\
	}								\
	if (((PAIR_MASK_NOT_RESTORE) & ((1 << 30) | (1 << 31))) == 0) {	\
		RESTORE_GREGS_PAIR(gregs, 30, 31, 30, 31, iset);	\
	}								\
} while (0)

#define DO_RESTORE_LOCAL_GREGS_ON_MASK(gregs, iset, PAIR_MASK_NOT_RESTORE) \
do {									\
	if (((PAIR_MASK_NOT_RESTORE) & ((1 << 16) | (1 << 17))) == 0) {	\
		RESTORE_GREGS_PAIR(gregs,  0,  1, 16, 17, iset);	\
	}								\
	if (((PAIR_MASK_NOT_RESTORE) & ((1 << 18) | (1 << 19))) == 0) {	\
		RESTORE_GREGS_PAIR(gregs,  2,  3, 18, 19, iset);	\
	}								\
	if (((PAIR_MASK_NOT_RESTORE) & ((1 << 20) | (1 << 21))) == 0) {	\
		RESTORE_GREGS_PAIR(gregs,  4,  5, 20, 21, iset);	\
	}								\
	if (((PAIR_MASK_NOT_RESTORE) & ((1 << 22) | (1 << 23))) == 0) {	\
		RESTORE_GREGS_PAIR(gregs,  6,  7, 22, 23, iset);	\
	}								\
	if (((PAIR_MASK_NOT_RESTORE) & ((1 << 24) | (1 << 25))) == 0) {	\
		RESTORE_GREGS_PAIR(gregs,  8,  9, 24, 25, iset);	\
	}								\
	if (((PAIR_MASK_NOT_RESTORE) & ((1 << 26) | (1 << 27))) == 0) {	\
		RESTORE_GREGS_PAIR(gregs, 10, 11, 26, 27, iset);	\
	}								\
	if (((PAIR_MASK_NOT_RESTORE) & ((1 << 28) | (1 << 29))) == 0) {	\
		RESTORE_GREGS_PAIR(gregs, 12, 13, 28, 29, iset);	\
	}								\
	if (((PAIR_MASK_NOT_RESTORE) & ((1 << 30) | (1 << 31))) == 0) {	\
		RESTORE_GREGS_PAIR(gregs, 14, 15, 30, 31, iset);	\
	}								\
} while (0)

#define	RESTORE_ALL_GREGS(gregs, iset)	\
		DO_RESTORE_GREGS_ON_MASK(gregs, iset, 0UL)
#define	RESTORE_GREGS_EXCEPT_NO(gregs, iset, GREGS_PAIR_NO_NOT_RESTORE)	\
		DO_RESTORE_GREGS_ON_MASK(gregs, iset,			\
					(1 << GREGS_PAIR_NO_NOT_RESTORE))
#define	RESTORE_GREGS_EXCEPT_KERNEL(gregs, iset)	\
		DO_RESTORE_GREGS_ON_MASK(gregs, iset, KERNEL_GREGS_MASK)
#define	RESTORE_GREGS_EXCEPT_GLOBAL_AND_KERNEL(gregs, iset)		\
		DO_RESTORE_GREGS_ON_MASK(gregs, iset,			\
			(GLOBAL_GREGS_USER_MASK | KERNEL_GREGS_MASK))

# define RESTORE_GREGS(gregs, restore_global, iset)			\
do {									\
	if (restore_global) {						\
		RESTORE_GREGS_EXCEPT_KERNEL(gregs, iset);		\
	} else {							\
		RESTORE_GREGS_EXCEPT_GLOBAL_AND_KERNEL(gregs, iset);	\
	}								\
} while (false)

/* Same as RESTORE_GREGS but restores %g16-%g31 registers only */
# define RESTORE_GREGS_SIGNAL(gregs, iset)				\
do {									\
	DO_RESTORE_LOCAL_GREGS_ON_MASK(gregs, iset,			\
		(GLOBAL_GREGS_USER_MASK | KERNEL_GREGS_MASK));		\
} while (false)

#ifdef CONFIG_GREGS_CONTEXT
#define	NATIVE_INIT_G_REGS() \
({ \
	init_BGR_reg(); \
	NATIVE_GREGS_SET_EMPTY(); \
	clear_memory_8(&current_thread_info()->k_gregs, \
			sizeof(current_thread_info()->k_gregs), ETAGEWD); \
})
#else	/* ! CONFIG_GREGS_CONTEXT */
#define	NATIVE_INIT_G_REGS()
#endif	/* CONFIG_GREGS_CONTEXT */

#define	NATIVE_BOOT_INIT_G_REGS()		\
({						\
	native_boot_init_BGR_reg();		\
	E2K_ALL_GREGS_SET_EMPTY();		\
})

/* ptrace related guys: we do not use them on switching. */
# define NATIVE_GET_GREGS_FROM_THREAD(g_user, gtag_user, gbase)		\
({									\
		void * g_u = g_user;					\
		void * gt_u = gtag_user;				\
									\
		E2K_GET_GREGS_FROM_THREAD(g_u, gt_u, gbase);		\
})

# define NATIVE_SET_GREGS_TO_THREAD(gbase, g_user, gtag_user)		\
({									\
		void * g_u = g_user;					\
		void * gt_u = gtag_user;				\
									\
		E2K_SET_GREGS_TO_THREAD(gbase, g_u, gt_u);		\
})

#if defined(CONFIG_PARAVIRT_GUEST)
#include <asm/paravirt/regs_state.h>
#elif defined(CONFIG_KVM_GUEST_KERNEL)
#include <asm/kvm/guest/regs_state.h>
#else /* !CONFIG_PARAVIRT_GUEST && !CONFIG_KVM_GUEST_KERNEL */

#define GET_GREGS_FROM_THREAD(g_user, gtag_user, gbase)         \
	NATIVE_GET_GREGS_FROM_THREAD(g_user, gtag_user, gbase)

#define SET_GREGS_TO_THREAD(gbase, g_user, gtag_user)           \
	NATIVE_SET_GREGS_TO_THREAD(gbase, g_user, gtag_user)

#endif /* !CONFIG_PARAVIRT_GUEST && !CONFIG_KVM_GUEST_KERNEL */

#else /* E2K_MAXGR_d != 32 */

# error        "Unsupported E2K_MAXGR_d value"

#endif /* E2K_MAXGR_d */

static inline void
native_save_local_glob_regs(local_gregs_t *l_gregs, bool is_signal)
{
	void (*save_local_gregs)(struct local_gregs *, bool is_signal);

	save_local_gregs = machine.save_local_gregs;

	copy_k_gregs_to_l_gregs(l_gregs, &current_thread_info()->k_gregs);
	save_local_gregs(l_gregs, is_signal);
}
static inline void
native_restore_local_glob_regs(local_gregs_t *l_gregs, bool is_signal)
{
	void (*restore_local_gregs)(const struct local_gregs *, bool is_signal);

	restore_local_gregs = machine.restore_local_gregs;

	get_k_gregs_from_l_regs(&current_thread_info()->k_gregs, l_gregs);
	restore_local_gregs(l_gregs, is_signal);
}

static inline void
native_get_all_user_glob_regs(global_regs_t *gregs)
{
	machine.save_gregs(gregs);
	copy_k_gregs_to_gregs(gregs, &current_thread_info()->k_gregs);
}

#define DO_SAVE_UPSR_REG_VALUE(upsr_reg, upsr_reg_value)	\
		{ AS_WORD(upsr_reg) = (upsr_reg_value); }

#define NATIVE_DO_SAVE_UPSR_REG(upsr_reg)	\
		DO_SAVE_UPSR_REG_VALUE((upsr_reg),	\
					NATIVE_NV_READ_UPSR_REG_VALUE())
#define DO_SAVE_UPSR_REG(upsr_reg)	\
		DO_SAVE_UPSR_REG_VALUE((upsr_reg), READ_UPSR_REG_VALUE())

#define NATIVE_SAVE_UPSR_REG(regs)	NATIVE_DO_SAVE_UPSR_REG((regs)->upsr)
#define SAVE_UPSR_REG(regs)	DO_SAVE_UPSR_REG((regs)->upsr)

#define DO_RESTORE_UPSR_REG(upsr_reg)	\
		{ WRITE_UPSR_REG(upsr_reg); }
#define NATIVE_DO_RESTORE_UPSR_REG(upsr_reg)	\
		{ NATIVE_WRITE_UPSR_REG(upsr_reg); }

#define NATIVE_RESTORE_UPSR_REG(regs)	NATIVE_DO_RESTORE_UPSR_REG((regs)->upsr)
#define RESTORE_UPSR_REG(regs)	DO_RESTORE_UPSR_REG((regs)->upsr)

#define NATIVE_SAVE_RPR_REGS(regs) \
({ \
	regs->rpr_lo = NATIVE_READ_RPR_LO_REG_VALUE(); \
	regs->rpr_hi = NATIVE_READ_RPR_HI_REG_VALUE(); \
})

#define NATIVE_SAVE_INTEL_REGS(regs)			\
do {							\
	regs->cs_lo = NATIVE_READ_CS_LO_REG_VALUE();	\
	regs->cs_hi = NATIVE_READ_CS_HI_REG_VALUE();	\
	regs->ds_lo = NATIVE_READ_DS_LO_REG_VALUE();	\
	regs->ds_hi = NATIVE_READ_DS_HI_REG_VALUE();	\
	regs->es_lo = NATIVE_READ_ES_LO_REG_VALUE();	\
	regs->es_hi = NATIVE_READ_ES_HI_REG_VALUE();	\
	regs->fs_lo = NATIVE_READ_FS_LO_REG_VALUE();	\
	regs->fs_hi = NATIVE_READ_FS_HI_REG_VALUE();	\
	regs->gs_lo = NATIVE_READ_GS_LO_REG_VALUE();	\
	regs->gs_hi = NATIVE_READ_GS_HI_REG_VALUE();	\
	regs->ss_lo = NATIVE_READ_SS_LO_REG_VALUE();	\
	regs->ss_hi = NATIVE_READ_SS_HI_REG_VALUE();	\
	NATIVE_SAVE_RPR_REGS(regs);			\
	if (IS_ENABLED(CONFIG_TC_STORAGE)) {		\
		NATIVE_FLUSH_ALL_TC;			\
		regs->tcd = NATIVE_GET_TCD();		\
	}						\
} while (0)

#define NATIVE_RESTORE_INTEL_REGS(regs)	\
do { \
	u64 cs_lo = regs->cs_lo; \
	u64 cs_hi = regs->cs_hi; \
	u64 ds_lo = regs->ds_lo; \
	u64 ds_hi = regs->ds_hi; \
	u64 es_lo = regs->es_lo; \
	u64 es_hi = regs->es_hi; \
	u64 fs_lo = regs->fs_lo; \
	u64 fs_hi = regs->fs_hi; \
	u64 gs_lo = regs->gs_lo; \
	u64 gs_hi = regs->gs_hi; \
	u64 ss_lo = regs->ss_lo; \
	u64 ss_hi = regs->ss_hi; \
	u64 rpr_lo = regs->rpr_lo; \
	u64 rpr_hi = regs->rpr_hi; \
	u64 tcd = regs->tcd; \
	NATIVE_CL_WRITE_CS_LO_REG_VALUE(cs_lo);	\
	NATIVE_CL_WRITE_CS_HI_REG_VALUE(cs_hi);	\
	NATIVE_CL_WRITE_DS_LO_REG_VALUE(ds_lo);	\
	NATIVE_CL_WRITE_DS_HI_REG_VALUE(ds_hi);	\
	NATIVE_CL_WRITE_ES_LO_REG_VALUE(es_lo);	\
	NATIVE_CL_WRITE_ES_HI_REG_VALUE(es_hi);	\
	NATIVE_CL_WRITE_FS_LO_REG_VALUE(fs_lo);	\
	NATIVE_CL_WRITE_FS_HI_REG_VALUE(fs_hi);	\
	NATIVE_CL_WRITE_GS_LO_REG_VALUE(gs_lo);	\
	NATIVE_CL_WRITE_GS_HI_REG_VALUE(gs_hi);	\
	NATIVE_CL_WRITE_SS_LO_REG_VALUE(ss_lo);	\
	NATIVE_CL_WRITE_SS_HI_REG_VALUE(ss_hi);	\
	NATIVE_WRITE_RPR_LO_REG_VALUE(rpr_lo);	\
	NATIVE_WRITE_RPR_HI_REG_VALUE(rpr_hi);	\
	if (IS_ENABLED(CONFIG_TC_STORAGE)) \
		NATIVE_SET_TCD(tcd); \
} while (0)

/*
 * Procedure stack (PS) and procedure chain stack (PCS) hardware filling and
 * spilling is asynchronous process. Page fault traps can overlay to this
 * asynchronous process and some filling and spilling requests can be not
 * completed. These requests were dropped by MMU to trap cellar.
 * We should save not completed filling data before starting of spilling
 * current procedure chain stack to preserve from filling data loss
 */

#define	NATIVE_SAVE_TRAP_CELLAR(regs, trap)				\
({									\
	kernel_trap_cellar_t *kernel_tcellar =				\
		(kernel_trap_cellar_t *)KERNEL_TRAP_CELLAR;		\
	kernel_trap_cellar_ext_t *kernel_tcellar_ext =			\
		(kernel_trap_cellar_ext_t *)				\
		((void *) KERNEL_TRAP_CELLAR + TC_EXT_OFFSET);		\
	trap_cellar_t *tcellar = (trap)->tcellar;			\
	int cnt, cs_req_num = 0, cs_a4 = 0, off, max_cnt;		\
	u64 kstack_pf_addr = 0, stack = (u64) current->stack;		\
	bool end_flag = false, is_qp;						\
									\
	max_cnt = NATIVE_READ_MMU_TRAP_COUNT();				\
	if (max_cnt < 3) {						\
		max_cnt = 3 * HW_TC_SIZE;				\
		end_flag = true;					\
	}								\
	(trap)->curr_cnt = -1;						\
	(trap)->ignore_user_tc = 0;					\
	(trap)->tc_called = 0;						\
	(trap)->is_intc = false;					\
	(trap)->from_sigreturn = 0;					\
	CLEAR_CLW_REQUEST_COUNT(regs);					\
	BUG_ON(max_cnt > 3 * HW_TC_SIZE);				\
	for (cnt = 0; 3 * cnt < max_cnt; cnt++) {			\
		tc_opcode_t opcode;					\
		tc_cond_t condition;					\
									\
		if (end_flag)						\
			if (AW(kernel_tcellar[cnt].condition) == -1)	\
				break;					\
									\
		tcellar[cnt].address = kernel_tcellar[cnt].address;	\
		condition = kernel_tcellar[cnt].condition;		\
		tcellar[cnt].condition = condition;			\
		AW(opcode) = AS(condition).opcode;			\
		is_qp = (AS(opcode).fmt == LDST_QP_FMT ||		\
			 cpu_has(CPU_FEAT_QPREG) && AS(condition).fmtc && \
			 AS(opcode).fmt == LDST_QWORD_FMT);		\
		if (AS(condition).clw) {			\
			if (GET_CLW_REQUEST_COUNT(regs) == 0) {		\
				SET_CLW_FIRST_REQUEST(regs, cnt);	\
			}						\
			INC_CLW_REQUEST_COUNT(regs);			\
		}							\
		if (is_qp)						\
			tcellar[cnt].mask = kernel_tcellar_ext[cnt].mask; \
		if (AS(condition).store) {				\
			NATIVE_MOVE_TAGGED_DWORD(			\
				&(kernel_tcellar[cnt].data),		\
				&(tcellar[cnt].data));			\
			if (is_qp) {					\
				NATIVE_MOVE_TAGGED_DWORD(		\
					&(kernel_tcellar_ext[cnt].data), \
					&(tcellar[cnt].data_ext));	\
			}						\
		} else if (AS(condition).s_f && AS(condition).sru) {	\
			if (cs_req_num == 0)				\
				cs_a4 = tcellar[cnt].address & (1 << 4); \
			cs_req_num++;					\
		}							\
		if (unlikely((AS(condition).s_f || IS_SPILL(tcellar[cnt])) && \
		    tcellar[cnt].address >= stack &&			\
		    tcellar[cnt].address < stack + KERNEL_STACKS_SIZE)) \
			kstack_pf_addr = tcellar[cnt].address;		\
		tcellar[cnt].flags = 0;					\
	}								\
	(trap)->tc_count = cnt * 3;					\
	if (unlikely(GET_CLW_REQUEST_COUNT(regs) &&			\
			cpu_has(CPU_HWBUG_CLW_STALE_L1_ENTRY)))		\
		SET_CLW_CPU(regs, raw_smp_processor_id());		\
	if (cs_req_num > 0) {						\
		/* recover chain stack pointers to repeat FILL */	\
		e2k_pcshtp_t pcshtp = NATIVE_READ_PCSHTP_REG_SVALUE();	\
		s64 pcshtp_ext = PCSHTP_SIGN_EXTEND(pcshtp);		\
		e2k_pcsp_hi_t PCSP_hi = NATIVE_NV_READ_PCSP_HI_REG();	\
		if (!cs_a4) {						\
			off = cs_req_num * 32;				\
		} else {						\
			off = (cs_req_num - 1) * 32 + 16;		\
		}							\
		pcshtp_ext -= off;					\
		PCSP_hi.PCSP_hi_ind += off;				\
		NATIVE_WRITE_PCSHTP_REG_SVALUE(pcshtp_ext);		\
		NATIVE_NV_NOIRQ_WRITE_PCSP_HI_REG(PCSP_hi);		\
	}								\
	kstack_pf_addr;							\
})

#ifdef	CONFIG_CLW_ENABLE
/*
 * If requests from CLW unit (user stack window clearing) were not
 * completed, and they were droped to the kernel trap cellar,
 * then we should save CLW unit state before switch to other stack
 * and restore CLW state after return to the user stack
 */
# define CLEAR_CLW_REQUEST_COUNT(regs)		((regs)->clw_count = 0)
# define INC_CLW_REQUEST_COUNT(regs)		((regs)->clw_count++)
# define GET_CLW_REQUEST_COUNT(regs)		((regs)->clw_count)
# define SET_CLW_FIRST_REQUEST(regs, cnt)	((regs)->clw_first = (cnt))
# define GET_CLW_FIRST_REQUEST(regs)		((regs)->clw_first)
# define SET_CLW_CPU(regs, cpu)			((regs)->clw_cpu = (cpu))
#define	ENABLE_US_CLW() \
do { \
	if (!cpu_has(CPU_HWBUG_CLW)) \
		write_MMU_US_CL_D(0); \
} while (0)
# define DISABLE_US_CLW()			write_MMU_US_CL_D(1)
#else	/* !CONFIG_CLW_ENABLE */
# define CLEAR_CLW_REQUEST_COUNT(regs)
# define INC_CLW_REQUEST_COUNT(regs)
# define GET_CLW_REQUEST_COUNT(regs)	(0)
# define SET_CLW_FIRST_REQUEST(regs, cnt)
# define GET_CLW_FIRST_REQUEST(regs)	(0)
# define SET_CLW_CPU(regs, cpu)
# define ENABLE_US_CLW()
# define DISABLE_US_CLW()
#endif	/* CONFIG_CLW_ENABLE */

#define NATIVE_RESTORE_COMMON_REGS(regs) \
do { \
	u64 ctpr1 = AW(regs->ctpr1), ctpr2 = AW(regs->ctpr2), \
	    ctpr3 = AW(regs->ctpr3), ctpr1_hi = AW(regs->ctpr1_hi), \
	    ctpr2_hi = AW(regs->ctpr2_hi), ctpr3_hi = AW(regs->ctpr3_hi), \
	    lsr = regs->lsr, lsr1 = regs->lsr1, \
	    ilcr = regs->ilcr, ilcr1 = regs->ilcr1; \
 \
	NATIVE_RESTORE_COMMON_REGS_VALUES(ctpr1, ctpr2, ctpr3, ctpr1_hi, \
			ctpr2_hi, ctpr3_hi, lsr, lsr1, ilcr, ilcr1); \
} while (0)

#define PREFIX_RESTORE_USER_CRs(PV_TYPE, regs)			\
({									\
	u64 cr0_hi = AS_WORD((regs)->crs.cr0_hi);			\
	u64 cr0_lo = AS_WORD((regs)->crs.cr0_lo);			\
	u64 cr1_hi = AS_WORD((regs)->crs.cr1_hi);			\
	u64 cr1_lo = AS_WORD((regs)->crs.cr1_lo);			\
	PV_TYPE##_NV_NOIRQ_WRITE_CR0_HI_REG_VALUE(cr0_hi);		\
	PV_TYPE##_NV_NOIRQ_WRITE_CR0_LO_REG_VALUE(cr0_lo);		\
	PV_TYPE##_NV_NOIRQ_WRITE_CR1_HI_REG_VALUE(cr1_hi);		\
	PV_TYPE##_NV_NOIRQ_WRITE_CR1_LO_REG_VALUE(cr1_lo);		\
})

#define PREFIX_RESTORE_USER_STACK_REGS(PV_TYPE, regs, in_syscall)	\
({									\
	thread_info_t *ti = current_thread_info();			\
	e2k_stacks_t *stacks;						\
	u64 usd_lo;							\
	u64 usd_hi;							\
	u64 top;							\
									\
	stacks = (in_syscall) ?						\
			syscall_guest_get_restore_stacks(ti, regs)	\
			:						\
			trap_guest_get_restore_stacks(ti, regs);	\
	usd_lo = AS_WORD(stacks->usd_lo);				\
	usd_hi = AS_WORD(stacks->usd_hi);				\
	top = stacks->top;						\
	PREFIX_RESTORE_USER_CRs(PV_TYPE, regs);				\
	CHECK_USD_BASE_SIZE(regs);					\
	PV_TYPE##_NV_WRITE_USBR_USD_REG_VALUE(top, usd_hi, usd_lo);	\
	RESTORE_USER_CUT_REGS(ti, regs, in_syscall);			\
})
#define NATIVE_RESTORE_USER_CRs(regs)	\
		PREFIX_RESTORE_USER_CRs(NATIVE, regs)
#define NATIVE_RESTORE_USER_STACK_REGS(regs, insyscall) \
		PREFIX_RESTORE_USER_STACK_REGS(NATIVE, regs, insyscall)

#if defined(CONFIG_PARAVIRT_GUEST)
/* it is paravirtualized host and guest */
#include <asm/paravirt/regs_state.h>
#elif	defined(CONFIG_KVM_GUEST_KERNEL)
/* it is pure guest kernel (not paravrtualized) */
#include <asm/kvm/guest/regs_state.h>
#else	/* ! CONFIG_PARAVIRT_GUEST && ! CONFIG_KVM_GUEST_KERNEL */
/* it is native kernel without any virtualization */
/* or native host kernel with virtualization support */

/* Save stack registers on kernel native/host/hypervisor mode */
#define SAVE_STACK_REGS(regs, ti, user, trap) \
		NATIVE_SAVE_STACK_REGS(regs, ti, user, trap)

#define RESTORE_USER_STACK_REGS(regs, in_syscall) \
		NATIVE_RESTORE_USER_STACK_REGS(regs, in_syscall)
#define RESTORE_USER_TRAP_STACK_REGS(regs) \
		RESTORE_USER_STACK_REGS(regs, false)
#define RESTORE_USER_SYSCALL_STACK_REGS(regs) \
		RESTORE_USER_STACK_REGS(regs, true)
#define RESTORE_COMMON_REGS(regs) \
		NATIVE_RESTORE_COMMON_REGS(regs)

#define INIT_G_REGS()		NATIVE_INIT_G_REGS()
#define BOOT_INIT_G_REGS()	NATIVE_BOOT_INIT_G_REGS()

static inline void
save_local_glob_regs(local_gregs_t *l_gregs, bool is_signal)
{
	native_save_local_glob_regs(l_gregs, is_signal);
}
static inline void
restore_local_glob_regs(local_gregs_t *l_gregs, bool is_signal)
{
	native_restore_local_glob_regs(l_gregs, is_signal);
}

static inline void
get_all_user_glob_regs(global_regs_t *gregs)
{
	native_get_all_user_glob_regs(gregs);
}

#endif	/* CONFIG_PARAVIRT_GUEST */

#define NATIVE_DO_RESTORE_MONITOR_COUNTERS(sw_regs)			\
do {									\
	e2k_ddmcr_t ddmcr = sw_regs->ddmcr;				\
	u64 ddmar0 = sw_regs->ddmar0;					\
	u64 ddmar1 = sw_regs->ddmar1;					\
	e2k_dimcr_t dimcr = sw_regs->dimcr;				\
	u64 dimar0 = sw_regs->dimar0;					\
	u64 dimar1 = sw_regs->dimar1;					\
									\
	if (machine.restore_dimtp)					\
		machine.restore_dimtp(&sw_regs->dimtp);			\
	NATIVE_WRITE_DDMAR0_REG_VALUE(ddmar0);				\
	NATIVE_WRITE_DDMAR1_REG_VALUE(ddmar1);				\
	NATIVE_WRITE_DIMAR0_REG_VALUE(dimar0);				\
	NATIVE_WRITE_DIMAR1_REG_VALUE(dimar1);				\
	NATIVE_WRITE_DDMCR_REG(ddmcr);					\
	NATIVE_WRITE_DIMCR_REG(dimcr);					\
} while (0)
#define NATIVE_RESTORE_MONITOR_COUNTERS(task)				\
do {									\
	struct sw_regs *sw_regs = &task->thread.sw_regs;		\
	NATIVE_DO_RESTORE_MONITOR_COUNTERS(sw_regs);			\
} while (0)

/*
 * When we use monitor registers, we count monitor events for the whole system,
 * so DIMCR, DDMCR, DIMAR0, DIMAR1, DDMAR0, DDMAR1, DIBSR, DDBSR registers are
 * not dependent on process and should not be restored while process switching.
 */
static inline void native_restore_user_only_regs(struct sw_regs *sw_regs)
{
	e2k_dibsr_t dibsr = sw_regs->dibsr;
	e2k_ddbsr_t ddbsr = sw_regs->ddbsr;

	/* Skip breakpoints-related fields handled by
	 * ptrace_hbp_triggered() and arch-independent
	 * hardware breakpoints support */
	AW(dibsr) &= ~E2K_DIBSR_MASK_ALL_BP;
	AW(dibsr) |= NATIVE_READ_DIBSR_REG_VALUE() & E2K_DIBSR_MASK_ALL_BP;
	AW(ddbsr) &= ~E2K_DDBSR_MASK_ALL_BP;
	AW(ddbsr) |= NATIVE_READ_DDBSR_REG_VALUE() & E2K_DDBSR_MASK_ALL_BP;

	if (!MONITORING_IS_ACTIVE) {
		NATIVE_WRITE_DIBSR_REG(dibsr);
		NATIVE_WRITE_DDBSR_REG(ddbsr);
		NATIVE_DO_RESTORE_MONITOR_COUNTERS(sw_regs);
	}
}

#ifdef	CONFIG_PERF_EVENTS
DECLARE_PER_CPU(u8, perf_monitors_used);
DECLARE_PER_CPU(u8, perf_bps_used);
# define is_perf_using_monitors	__this_cpu_read(perf_monitors_used)
# define is_perf_using_bps	__this_cpu_read(perf_bps_used)
#else	/* ! CONFIG_PERF_EVENTS */
#define	is_perf_using_monitors	false
#define	is_perf_using_bps	false
#endif	/* CONFIG_PERF_EVENTS */

static inline void native_clear_user_only_regs(void)
{
	if (!is_perf_using_bps) {
		NATIVE_WRITE_DIBCR_REG_VALUE(0);
		NATIVE_WRITE_DDBCR_REG_VALUE(0);
	}
	if (!MONITORING_IS_ACTIVE && !is_perf_using_monitors) {
		NATIVE_WRITE_DIMCR_REG_VALUE(0);
		NATIVE_WRITE_DIBSR_REG_VALUE(0);
		NATIVE_WRITE_DDMCR_REG_VALUE(0);
		NATIVE_WRITE_DDBSR_REG_VALUE(0);
	}
}


/*
 * Set some special registers in accordance with
 * E2K API specifications.
 */
#define	GET_FPU_DEFAULTS(fpsr, fpcr, pfpfr)	\
({						\
	AW(fpsr) = 0;				\
	AW(pfpfr) = 0;				\
	AW(fpcr) = 32;				\
						\
	/* masks */				\
	AS_STRUCT(pfpfr).im = 1;		\
	AS_STRUCT(pfpfr).dm = 1;		\
	AS_STRUCT(pfpfr).zm = 1;		\
	AS_STRUCT(pfpfr).om = 1;		\
	AS_STRUCT(pfpfr).um = 1;		\
	AS_STRUCT(pfpfr).pm = 1;		\
						\
	/* flags ! NEEDSWORK ! */		\
	AS_STRUCT(pfpfr).pe = 1;		\
	AS_STRUCT(pfpfr).ue = 1;		\
	AS_STRUCT(pfpfr).oe = 1;		\
	AS_STRUCT(pfpfr).ze = 1;		\
	AS_STRUCT(pfpfr).de = 1;		\
	AS_STRUCT(pfpfr).ie = 1;		\
	/* rounding */				\
	AS_STRUCT(pfpfr).rc = 0;		\
						\
	AS_STRUCT(pfpfr).fz  = 0;		\
	AS_STRUCT(pfpfr).dpe = 0;		\
	AS_STRUCT(pfpfr).due = 0;		\
	AS_STRUCT(pfpfr).doe = 0;		\
	AS_STRUCT(pfpfr).dze = 0;		\
	AS_STRUCT(pfpfr).dde = 0;		\
	AS_STRUCT(pfpfr).die = 0;		\
						\
	AS_STRUCT(fpcr).im = 1;			\
	AS_STRUCT(fpcr).dm = 1;			\
	AS_STRUCT(fpcr).zm = 1;			\
	AS_STRUCT(fpcr).om = 1;			\
	AS_STRUCT(fpcr).um = 1;			\
	AS_STRUCT(fpcr).pm = 1;			\
	/* rounding */				\
	AS_STRUCT(fpcr).rc = 0;			\
	AS_STRUCT(fpcr).pc = 3;			\
						\
	/* flags ! NEEDSWORK ! */		\
	AS_STRUCT(fpsr).pe = 1;			\
	AS_STRUCT(fpsr).ue = 1;			\
	AS_STRUCT(fpsr).oe = 1;			\
	AS_STRUCT(fpsr).ze = 1;			\
	AS_STRUCT(fpsr).de = 1;			\
	AS_STRUCT(fpsr).ie = 1;			\
						\
	AS_STRUCT(fpsr).es = 0;			\
	AS_STRUCT(fpsr).c1 = 0;			\
})
#define	INIT_SPECIAL_REGISTERS()		\
({						\
	e2k_fpsr_t fpsr;			\
	e2k_pfpfr_t pfpfr;			\
	e2k_fpcr_t fpcr;			\
						\
	GET_FPU_DEFAULTS(fpsr, fpcr, pfpfr);	\
						\
	NATIVE_NV_WRITE_PFPFR_REG(pfpfr);	\
	NATIVE_NV_WRITE_FPCR_REG(fpcr);		\
	NATIVE_NV_WRITE_FPSR_REG(fpsr);		\
})

/* Declarate here to prevent loop #include. */
#define PT_PTRACED	0x00000001

static inline void
NATIVE_DO_SAVE_TASK_USER_REGS_TO_SWITCH(struct sw_regs *sw_regs,
		bool task_is_binco, bool task_traced)
{
	if (unlikely(task_is_binco))
		NATIVE_SAVE_INTEL_REGS((sw_regs));

#ifdef CONFIG_MLT_STORAGE
	machine.invalidate_MLT();
#endif

	AS_WORD(sw_regs->fpcr) = NATIVE_NV_READ_FPCR_REG_VALUE();
	AS_WORD(sw_regs->fpsr) = NATIVE_NV_READ_FPSR_REG_VALUE();
	AS_WORD(sw_regs->pfpfr)	= NATIVE_NV_READ_PFPFR_REG_VALUE();
	sw_regs->cutd = NATIVE_NV_READ_CUTD_REG();

	if (unlikely(task_traced))
		native_save_user_only_regs(sw_regs);
}

static inline void
NATIVE_SAVE_TASK_REGS_TO_SWITCH(struct task_struct *task)
{
#ifdef CONFIG_VIRTUALIZATION
	const int task_is_binco = TASK_IS_BINCO(task) || task_thread_info(task)->vcpu;
#else
	const int task_is_binco = TASK_IS_BINCO(task);
#endif
	struct mm_struct *mm = task->mm;
	struct sw_regs *sw_regs = &task->thread.sw_regs;

	WARN_ONCE(!AS(sw_regs->upsr).nmie,
		  "Non-maskable interrupts are disabled\n");

	/* Kernel does not use MLT so skip invalidation for kernel threads */
	NATIVE_DO_SAVE_TASK_USER_REGS_TO_SWITCH(sw_regs, task_is_binco,
			!!(task->ptrace & PT_PTRACED));

	if (mm) {
#ifdef CONFIG_GREGS_CONTEXT
		machine.save_gregs_dirty_bgr(&task->thread.sw_regs.gregs);
#endif

		/*
		 * If AAU was not cleared then at a trap exit of next user
		 * AAU will start working, so clear it explicitly here.
		 */
		native_clear_apb();
	}

	NATIVE_FLUSHCPU;

	sw_regs->top	= NATIVE_NV_READ_SBR_REG_VALUE();
	sw_regs->usd_hi	= NATIVE_NV_READ_USD_HI_REG();
	sw_regs->usd_lo	= NATIVE_NV_READ_USD_LO_REG();

	sw_regs->crs.cr1_lo = NATIVE_NV_READ_CR1_LO_REG();
	sw_regs->crs.cr1_hi = NATIVE_NV_READ_CR1_HI_REG();
	sw_regs->crs.cr0_lo = NATIVE_NV_READ_CR0_LO_REG();
	sw_regs->crs.cr0_hi = NATIVE_NV_READ_CR0_HI_REG();

	/* These will wait for the flush so we give
	 * the flush some time to finish. */
	sw_regs->psp_hi = NATIVE_NV_READ_PSP_HI_REG();
	sw_regs->psp_lo = NATIVE_NV_READ_PSP_LO_REG();
	sw_regs->pcsp_hi = NATIVE_NV_READ_PCSP_HI_REG();
	sw_regs->pcsp_lo = NATIVE_NV_READ_PCSP_LO_REG();
}

/*
 * now lcc has problem with structure on registers
 * (It moves these structures in stack memory)
 */
static inline void
NATIVE_DO_RESTORE_TASK_USER_REGS_TO_SWITCH(struct sw_regs *sw_regs,
					bool task_is_binco, bool task_traced)
{
	u64 fpcr = AS_WORD(sw_regs->fpcr);
	u64 fpsr = AS_WORD(sw_regs->fpsr);
	u64 pfpfr = AS_WORD(sw_regs->pfpfr);
	u64 cutd = AS_WORD(sw_regs->cutd);

	NATIVE_NV_WRITE_FPCR_REG_VALUE(fpcr);
	NATIVE_NV_WRITE_FPSR_REG_VALUE(fpsr);
	NATIVE_NV_WRITE_PFPFR_REG_VALUE(pfpfr);
	NATIVE_NV_NOIRQ_WRITE_CUTD_REG_VALUE(cutd);

	if (unlikely(task_traced))
		native_restore_user_only_regs(sw_regs);
	else	/* Do this always when we don't test prev_task->ptrace */
		native_clear_user_only_regs();

	NATIVE_CLEAR_DAM;

	if (unlikely(task_is_binco)) {
		if (machine.flushts)
			machine.flushts();
		NATIVE_RESTORE_INTEL_REGS(sw_regs);
	}
}
static inline void
NATIVE_RESTORE_TASK_REGS_TO_SWITCH(struct task_struct *task,
		struct thread_info *ti)
{
	struct sw_regs *sw_regs = &task->thread.sw_regs;
	u64 top = sw_regs->top;
	u64 usd_lo = AS_WORD(sw_regs->usd_lo);
	u64 usd_hi = AS_WORD(sw_regs->usd_hi);
	u64 psp_lo = AS_WORD(sw_regs->psp_lo);
	u64 psp_hi = AS_WORD(sw_regs->psp_hi);
	u64 pcsp_lo = AS_WORD(sw_regs->pcsp_lo);
	u64 pcsp_hi = AS_WORD(sw_regs->pcsp_hi);
	e2k_mem_crs_t crs = sw_regs->crs;
#ifdef CONFIG_VIRTUALIZATION
	const int task_is_binco = TASK_IS_BINCO(task) || ti->vcpu;
#else
	const int task_is_binco = TASK_IS_BINCO(task);
#endif
	struct mm_struct *mm = task->mm;

	NATIVE_FLUSHCPU;

	NATIVE_NV_WRITE_USBR_USD_REG_VALUE(top, usd_hi, usd_lo);
	NATIVE_NV_WRITE_PSP_REG_VALUE(psp_hi, psp_lo);
	NATIVE_NV_WRITE_PCSP_REG_VALUE(pcsp_hi, pcsp_lo);

	NATIVE_NV_NOIRQ_WRITE_CR0_LO_REG(crs.cr0_lo);
	NATIVE_NV_NOIRQ_WRITE_CR0_HI_REG(crs.cr0_hi);
	NATIVE_NV_NOIRQ_WRITE_CR1_LO_REG(crs.cr1_lo);
	NATIVE_NV_NOIRQ_WRITE_CR1_HI_REG(crs.cr1_hi);

	NATIVE_DO_RESTORE_TASK_USER_REGS_TO_SWITCH(sw_regs, task_is_binco,
		(task->ptrace & PT_PTRACED) ? true : false);

#ifdef CONFIG_GREGS_CONTEXT
	if (mm)
		machine.restore_gregs(&task->thread.sw_regs.gregs);
#endif
}

static inline void
NATIVE_SWITCH_TO_KERNEL_STACK(e2k_addr_t ps_base, e2k_size_t ps_size,
		e2k_addr_t pcs_base, e2k_size_t pcs_size,
		e2k_addr_t ds_base, e2k_size_t ds_size)
{
	e2k_rwap_lo_struct_t	reg_lo;
	e2k_rwap_hi_struct_t	reg_hi;
	e2k_rwap_lo_struct_t	stack_reg_lo;
	e2k_rwap_hi_struct_t	stack_reg_hi;
	e2k_usbr_t		usbr;

	/*
	 * Set Procedure Stack and Procedure Chain stack registers
	 * to the begining of initial PS and PCS stacks
	 */
	NATIVE_FLUSHCPU;
	reg_lo.PSP_lo_half = 0;
	reg_lo.PSP_lo_base = ps_base;
	reg_lo._PSP_lo_rw = E2K_PSP_RW_PROTECTIONS;
	reg_hi.PSP_hi_half = 0;
	reg_hi.PSP_hi_size = ps_size;
	reg_hi.PSP_hi_ind = 0;
	NATIVE_NV_WRITE_PSP_REG(reg_hi, reg_lo);
	reg_lo.PCSP_lo_half = 0;
	reg_lo.PCSP_lo_base = pcs_base;
	reg_lo._PCSP_lo_rw = E2K_PCSR_RW_PROTECTIONS;
	reg_hi.PCSP_hi_half = 0;
	reg_hi.PCSP_hi_size = pcs_size;
	reg_hi.PCSP_hi_ind = 0;
	NATIVE_NV_WRITE_PCSP_REG(reg_hi, reg_lo);


	/*
	 * Set stack pointers to the begining of kernel initial data stack
	 */

	usbr.USBR_base = ds_base + ds_size;

	/*
	 * Reserve additional 64 bytes for parameters area.
	 * Compiler might use it to temporarily store the function's parameters
	 */

	stack_reg_lo.USD_lo_half = 0;
	stack_reg_lo.USD_lo_p = 0;
	stack_reg_lo.USD_lo_base = ds_base + ds_size - 64;

	stack_reg_hi.USD_hi_half = 0;
	stack_reg_hi.USD_hi_size = ds_size - 64;

	NATIVE_NV_WRITE_USBR_USD_REG(usbr, stack_reg_hi, stack_reg_lo);
}

/*
 * There are TIR_NUM(19) tir regs. Bits 64 - 56 is current tir nr
 * After each E2K_GET_DSREG(tir.lo) we will read next tir.
 * For more info see instruction set doc.
 * Read tir regs order is significant
 */
#define SAVE_TIRS(TIRs, TIRs_num, from_intc)				\
({									\
	unsigned long nr_TIRs = -1, TIR_hi, TIR_lo = 0;			\
	unsigned long all_interrupts = 0;				\
	do {								\
		TIR_hi = NATIVE_READ_TIR_HI_REG_VALUE();		\
		if (unlikely(from_intc && GET_NR_TIRS(TIR_hi) > 18UL))	\
			break;						\
		TIR_lo = NATIVE_READ_TIR_LO_REG_VALUE();		\
		++nr_TIRs;						\
		TIRs[GET_NR_TIRS(TIR_hi)].TIR_lo.TIR_lo_reg = TIR_lo;	\
		TIRs[GET_NR_TIRS(TIR_hi)].TIR_hi.TIR_hi_reg = TIR_hi;	\
		all_interrupts |= TIR_hi;				\
	} while(GET_NR_TIRS(TIR_hi));					\
	TIRs_num = nr_TIRs;						\
									\
	/* un-freeze the TIR's LIFO */					\
	UNFREEZE_TIRs(TIR_lo);						\
									\
	all_interrupts & (exc_all_mask | aau_exc_mask);			\
})
#define UNFREEZE_TIRs(TIR_lo)	NATIVE_WRITE_TIR_LO_REG_VALUE(TIR_lo)
#define SAVE_SBBP(sbbp) \
do { \
	int i; \
	for (i = 0; i < SBBP_ENTRIES_NUM; i++) \
		(sbbp)[i] = NATIVE_READ_SBBP_REG_VALUE(); \
} while (0)

static inline void set_osgd_task_struct(struct task_struct *task)
{
	e2k_gd_lo_t gd_lo;
	e2k_gd_hi_t gd_hi;

	BUG_ON(!IS_ALIGNED((u64) task, E2K_ALIGN_GLOBALS_SZ));

	AW(gd_lo) = 0;
	AW(gd_hi) = 0;
	AS(gd_lo).base = (u64) task;
	AS(gd_lo).rw = E2K_GD_RW_PROTECTIONS;
	AS(gd_hi).size = round_up(sizeof(struct task_struct),
				  E2K_ALIGN_GLOBALS_SZ);
	WRITE_OSGD_LO_REG(gd_lo);
	WRITE_OSGD_HI_REG(gd_hi);
	atomic_load_osgd_to_gd();
}

static inline void
native_set_current_thread_info(struct thread_info *thread,
					struct task_struct *task)
{
	NATIVE_WRITE_CURRENT_REG(thread);
	E2K_SET_DGREG_NV(CURRENT_TASK_GREG, task);
	set_osgd_task_struct(task);
}


static inline void
set_current_thread_info(struct thread_info *thread, struct task_struct *task)
{
	WRITE_CURRENT_REG(thread);
	E2K_SET_DGREG_NV(CURRENT_TASK_GREG, task);
	set_osgd_task_struct(task);
}

#endif /* _E2K_REGS_STATE_H */

