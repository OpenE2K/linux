/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _E2K_REGS_STATE_H
#define _E2K_REGS_STATE_H

/*
 * Some macroses (start with PREFIX_) can use in three modes and can operate
 * with virtualized functions, resources, other macroses.
 * Such macroses should not be used directly instead of it need use:
 *	NATIVE_XXX macroses for native, host and hypervisor kernel mode
 *			in all functions which can be called only on native
 *			running mode;
 *	KVM_XXX macroses for guest virtualized kernel in all functions,
 *			which can be called only on guest running mode;
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
 * PV_TYPE argument in macroses is prefix and can be as above:
 *	NATIVE		native kernel with or without virtualization support
 *	KVM		guest kernel (can be run only as virtualized
 *			guest kernel)
 */

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/signal.h>
#include <linux/irqflags.h>

#ifndef __ASSEMBLY__
#include <asm/e2k_api.h>
#include <asm/cpu_regs.h>
#include <asm/gregs.h>
#include <asm/mmu.h>
#include <asm/mmu_fault.h>
#include <asm/mmu_regs.h>
#include <asm/perf_event_types.h>
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
#include <asm/aau_context.h>

#endif /* __ASSEMBLY__ */

#include <asm/e2k_syswork.h>


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
	e2k_cutd_t k_cutd;

	k_cutd.word = 0;
	k_cutd.base = (e2k_addr_t)kernel_CUT;
	native_write_CUTD_reg(k_cutd);
}

/*
 * Macros to save and restore registers.
 */
static __always_inline void get_u_hw_stacks_from_current(e2k_stacks_t *stacks)
{
	e2k_psp_t psp = current->thread.tmp_user_stacks.psp;
	e2k_pshtp_t pshtp = current->thread.tmp_user_stacks.pshtp;
	e2k_pcsp_t pcsp = current->thread.tmp_user_stacks.pcsp;
	e2k_pcshtp_t pcshtp = current->thread.tmp_user_stacks.pcshtp;

	stacks->psp = incr_psp_ind(psp, PSHTP_MEM_INDEX(pshtp));
	stacks->pcsp = incr_pcsp_ind(pcsp, pcshtp.ind);
	stacks->pshtp = pshtp;
	stacks->pcshtp = pcshtp;
}

static __always_inline void
COPY_U_HW_STACKS_TO_STACKS(e2k_stacks_t *stacks_to, e2k_stacks_t *stacks_from)
{
	stacks_to->psp = stacks_from->psp;
	stacks_to->pcsp = stacks_from->pcsp;
	stacks_to->pshtp = stacks_from->pshtp;
	stacks_to->pcshtp = stacks_from->pcshtp;
}

/* usd regs are saved already */
#define PREFIX_SAVE_STACK_REGS(PV_TYPE, regs, from_current, flushc)	\
do {									\
	/* This flush reserves space for the next trap. */		\
	if (flushc)							\
		PV_TYPE##_FLUSHC;					\
	if (from_current) {						\
		get_u_hw_stacks_from_current(&(regs)->stacks);		\
	} else {							\
		e2k_pshtp_t pshtp = PV_TYPE##_read_PSHTP_reg();		\
		e2k_pcshtp_t pcshtp = PV_TYPE##_read_PCSHTP_reg();	\
		e2k_psp_t psp = PV_TYPE##_read_PSP_reg();		\
		e2k_pcsp_t pcsp = PV_TYPE##_read_PCSP_reg();		\
		if (!flushc)						\
			pcsp = incr_pcsp_ind(pcsp, pcshtp.ind);		\
		psp = incr_psp_ind(psp, PSHTP_MEM_INDEX(pshtp));	\
		(regs)->stacks.pshtp = pshtp;				\
		(regs)->stacks.pcshtp = pcshtp;				\
		(regs)->stacks.psp = psp;				\
		(regs)->stacks.pcsp = pcsp;				\
	}								\
	(regs)->crs.cr0 = PV_TYPE##_read_CR0_reg();			\
	(regs)->crs.cr1 = PV_TYPE##_read_CR1_reg();			\
	(regs)->wd = PV_TYPE##_read_WD_reg();				\
	CHECK_USD_BASE_SIZE(regs);					\
} while (0)

/* Save stack registers on kernel native/host/hypervisor mode */
#define NATIVE_SAVE_STACK_REGS(regs, from_current, flushc) \
		PREFIX_SAVE_STACK_REGS(native, regs, from_current, flushc)

static inline void update_u_stack_limits(unsigned long bottom, unsigned long top)
{
	current_thread_info()->u_stack.bottom = bottom;
	current_thread_info()->u_stack.top = top;
	current_thread_info()->u_stack.size = top - bottom;
}

/*
 * Interrupts should be disabled by caller to read all hardware
 * stacks registers in coordinated state
 * Hardware stacks do not copy or flush to memory
 */


#define ATOMIC_SAVE_CURRENT_STACK_REGS(stacks, crs)			\
do {									\
	ATOMIC_SAVE_ALL_STACKS_REGS(stacks, &(crs)->cr1);		\
									\
	(stacks)->top = native_read_SBR_reg().base;			\
	(crs)->cr0 = native_read_CR0_reg();				\
									\
	/*								\
	 * Do not copy copy_user_stacks()'s kernel data stack frame	\
	 */								\
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {				\
		(stacks)->usd = incr_usd_ind((stacks)->usd, read_USFS_reg());	\
	} else {							\
		(stacks)->usd = new_usd(USD_BASE((stacks)->usd),	\
				(stacks)->top - USD_BASE((stacks)->usd), \
				get_cr1_ussz((crs)->cr1));		\
	}								\
} while (0)

#define	NATIVE_DO_SAVE_MONITOR_COUNTERS(sw_regs)				\
do {										\
	sw_regs->ddmar[0] = NATIVE_READ_DDMAR0_REG();			\
	sw_regs->ddmar[1] = NATIVE_READ_DDMAR1_REG();			\
	sw_regs->dimar[0] = native_read_DIMAR0_reg();			\
	sw_regs->dimar[1] = native_read_DIMAR1_reg();			\
	if (cpu_has(CPU_FEAT_ISET_V7)) {					\
		sw_regs->ddmar[2] = NATIVE_READ_DDMAR2_REG();		\
		sw_regs->ddmar[3] = NATIVE_READ_DDMAR3_REG();		\
		if (!cpu_has(CPU_HWBUG_DIMCR1)) {				\
			sw_regs->dimar[2] = native_read_DIMAR2_reg();	\
			sw_regs->dimar[3] = native_read_DIMAR3_reg();	\
		}								\
	}									\
} while (0)
#define	NATIVE_SAVE_MONITOR_COUNTERS(task)				\
do {									\
	struct sw_regs *sw_regs = &((task)->thread.sw_regs);		\
	NATIVE_DO_SAVE_MONITOR_COUNTERS(sw_regs);			\
} while (0)

static inline void save_dimtp(struct sw_regs *sw_regs)
{
	sw_regs->dimtp = native_read_DIMTP_reg();
}

static inline void native_save_user_only_regs(struct sw_regs *sw_regs)
{
	save_dimtp(sw_regs);

	/* Skip breakpoints-related fields handled by
	 * ptrace_hbp_triggered() and arch-independent
	 * hardware breakpoints support */
	AW(sw_regs->dibsr) &= E2K_DIBSR_MASK_ALL_BP;
	AW(sw_regs->dibsr) |= AW(native_read_DIBSR_reg()) &
			      ~E2K_DIBSR_MASK_ALL_BP;
	AW(sw_regs->ddbsr) &= E2K_DDBSR_MASK_ALL_BP;
	AW(sw_regs->ddbsr) |= NATIVE_READ_DDBSR_REG_VALUE() &
			      ~E2K_DDBSR_MASK_ALL_BP;

	sw_regs->ddmcr = NATIVE_READ_DDMCR_REG();
	sw_regs->dimcr = native_read_DIMCR_reg();
	if (cpu_has(CPU_FEAT_ISET_V7)) {
		sw_regs->ddmcr1 = NATIVE_READ_DDMCR1_REG();
		if (!cpu_has(CPU_HWBUG_DIMCR1))
			sw_regs->dimcr1 = native_read_DIMCR1_reg();
	}
	NATIVE_DO_SAVE_MONITOR_COUNTERS(sw_regs);

	/*
	 * Save IDR register of the cpu on which the traced task was running
	 * before it was preempted.
	 */
	sw_regs->idr = read_IDR_reg();
}

#if (E2K_MAXGR_d == 32)

/* Save/Restore global registers */
#define	SAVE_GREGS_PAIR(gregs, nolo_save, nohi_save, nolo_greg, nohi_greg, iset) \
		NATIVE_SAVE_GREG(&(gregs)[nolo_save], &(gregs)[nohi_save], \
				 nolo_greg, nohi_greg, iset)

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

#define SAVE_LOCAL_GREGS_ON_MASK(gregs, iset, PAIR_MASK_NOT_SAVE)	\
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

#define	RESTORE_GREGS_PAIR(gregs, nolo_save, nohi_save, \
			   nolo_greg, nohi_greg, iset) \
	NATIVE_RESTORE_GREG((gregs), nolo_save * sizeof((gregs)[0]), \
			    nohi_save * sizeof((gregs)[0]), \
			    nolo_greg, nohi_greg, iset)

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

#define RESTORE_LOCAL_GREGS_ON_MASK(gregs, iset, PAIR_MASK_NOT_RESTORE) \
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

#define	NATIVE_INIT_G_REGS(skip_k_gregs) \
({ \
	init_BGR_reg(); \
	clear_memory_8(&current_thread_info()->k_gregs, \
			sizeof(current_thread_info()->k_gregs), ETAGEWD); \
	NATIVE_GREGS_SET_EMPTY(skip_k_gregs); \
})

#define	NATIVE_BOOT_INIT_G_REGS() \
do { \
	native_write_BGR_reg(E2K_INITIAL_BGR); \
	NATIVE_SET_GREGS_EMPTY(true, true); \
} while (0)

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

#define NATIVE_CLEAR_DAM	NATIVE_SET_MMUREG(dam_inv, 0)

/**
 * switch_local_gregs() - switch so called "local" gregs (%g16 - %g31)
 * @dst: save here
 * @src: restore from here
 */
static __always_inline void switch_local_gregs(struct local_gregs *dst,
		const struct local_gregs *src)
{
	dst->bgr = native_read_BGR_reg();
	init_BGR_reg(); /* enable whole GRF */

	/* cpuhas_greg0/1 might be not initialized yet, so use cpu_has_slow() */
	if (cpu_has_slow(CPU_FEAT_ISET_V5)) {
		SAVE_LOCAL_GREGS_ON_MASK(dst->g, E2K_ISET_V5, 0);
		RESTORE_LOCAL_GREGS_ON_MASK(src->g, E2K_ISET_V5, 0);
	} else {
		SAVE_LOCAL_GREGS_ON_MASK(dst->g, E2K_ISET_V3, 0);
		RESTORE_LOCAL_GREGS_ON_MASK(src->g, E2K_ISET_V3, 0);
	}

	native_write_BGR_reg(src->bgr);
}

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is virtualized guest kernel */
#include <asm/kvm/guest/regs_state.h>
#else /* !CONFIG_KVM_GUEST_KERNEL */
/* it is native kernel without any virtualization */
/* or native host kernel with virtualization support */

/**
 * restore_local_gregs() - restore so called "local" gregs (%g16 - %g31)
 * @gregs: restore from here
 *
 * Assumes that %bgr is in empty state already.
 */
static __always_inline void restore_local_gregs(const struct local_gregs *gregs)
{
	if (cpu_has(CPU_FEAT_ISET_V5))
		RESTORE_LOCAL_GREGS_ON_MASK(gregs->g, E2K_ISET_V5, 0);
	else
		RESTORE_LOCAL_GREGS_ON_MASK(gregs->g, E2K_ISET_V3, 0);

	native_write_BGR_reg(gregs->bgr);
}

static inline void get_qpg_single(u64 *__restrict g, u8 *__restrict gtag,
					     u64 *__restrict gext, u8 *__restrict gext_tag,
					     const struct e2k_greg *src)
{
	e2k_qreg_t data;
	u8 tag;

	load_qvalue_and_tagq(src, &data, &tag, 8);
	*g = data.lo;
	*gext = data.hi;
	*gtag = tag & 0xf;
	*gext_tag = tag >> 4;
}

static inline void get_qg_single(u64 *__restrict g, u8 *__restrict gtag,
		u16 *__restrict gext, const struct e2k_greg *src)
{
	e2k_qreg_t data;
	u8 tag;

	load_qvalue_and_tagq(src, &data, &tag, 16);
	g[0] = data.lo;
	g[1] = data.hi;
	gtag[0] = tag & 0xf;
	gtag[1] = tag >> 4;
	gext[0] = src[0].ext;
	gext[1] = src[1].ext;
}

static inline void get_gregs_from_thread(struct user_regs_struct *user,
		const struct global_gregs *g_gregs,
		const struct local_gregs *l_gregs)
{
	if (l_gregs)
		user->bgr = AW(l_gregs->bgr);

	if (cpu_has(CPU_FEAT_QPREG)) {
		for (int i = 0; i < GLOBAL_GREGS_NUM; i++) {
			get_qpg_single(&user->g[i], &user->gtag[i], &user->gext_v5[i],
				       &user->gext_tag_v5[i], &g_gregs->g[i]);
			/* For backwards compatibility */
			user->gext[i] = (u16) user->gext_v5[i];
		}

		for (int i = GLOBAL_GREGS_NUM; i < E2K_MAXGR_d; i++) {
			get_qpg_single(&user->g[i], &user->gtag[i],
				       &user->gext_v5[i], &user->gext_tag_v5[i],
				       &l_gregs->g[i - GLOBAL_GREGS_NUM]);
			/* For backwards compatibility */
			user->gext[i] = (u16) user->gext_v5[i];
		}
	} else {
		for (int i = 0; i < GLOBAL_GREGS_NUM; i += 2) {
			get_qg_single(&user->g[i], &user->gtag[i],
					&user->gext[i], &g_gregs->g[i]);
		}

		for (int i = GLOBAL_GREGS_NUM; i < E2K_MAXGR_d; i += 2) {
			get_qg_single(&user->g[i], &user->gtag[i],
				      &user->gext[i], &l_gregs->g[i - GLOBAL_GREGS_NUM]);
		}
	}
}

static inline void set_qpg_single(struct e2k_greg *__restrict dst, const u64 *g,
				  const u8 *gtag, const u64 *gext, const u8 *gext_tag)
{
	e2k_qreg_t data = (e2k_qreg_t) { .lo = g[0], .hi = gext[0] };
	store_tagged_qword(dst, data, gtag[0] | (gext_tag[0] << 4), 8);
}

static inline void set_qg_single(struct e2k_greg *__restrict dst, u64 g_lo, u64 g_hi,
				 u8 tag_lo, u8 tag_hi, u16 ext_lo, u16 ext_hi)
{
	e2k_qreg_t data = (e2k_qreg_t) { .lo = g_lo, .hi = g_hi };
	store_tagged_qword(dst, data, tag_lo | (tag_hi << 4), 16);
	dst[0].ext = ext_lo;
	dst[1].ext = ext_hi;
}

static inline void set_gregs_to_thread(struct global_gregs *g_gregs, struct local_gregs *l_gregs,
		const struct user_regs_struct *user, bool copy_ext)
{
	AW(l_gregs->bgr) = user->bgr;

	if (cpu_has(CPU_FEAT_QPREG) && copy_ext) {
		for (int i = 0; i < GLOBAL_GREGS_NUM; i++) {
			set_qpg_single(&g_gregs->g[i], &user->g[i], &user->gtag[i],
				       &user->gext_v5[i], &user->gext_tag_v5[i]);
		}

		for (int i = GLOBAL_GREGS_NUM; i < E2K_MAXGR_d; i++) {
			set_qpg_single(&l_gregs->g[i - GLOBAL_GREGS_NUM],
				       &user->g[i], &user->gtag[i],
				       &user->gext_v5[i], &user->gext_tag_v5[i]);
		}
	} else {
		for (int i = 0; i < GLOBAL_GREGS_NUM; i += 2) {
			set_qg_single(&g_gregs->g[i], user->g[i], user->g[i + 1],
				      user->gtag[i], user->gtag[i + 1],
				      user->gext[i], user->gext[i + 1]);
		}

		for (int i = GLOBAL_GREGS_NUM; i < E2K_MAXGR_d; i += 2) {
			set_qg_single(&l_gregs->g[i - GLOBAL_GREGS_NUM],
				      user->g[i], user->g[i + 1],
				      user->gtag[i], user->gtag[i + 1],
				      user->gext[i], user->gext[i + 1]);
		}
	}
}

#define GET_GREGS_FROM_THREAD(g_user, gtag_user, gbase)         \
	NATIVE_GET_GREGS_FROM_THREAD(g_user, gtag_user, gbase)

#define SET_GREGS_TO_THREAD(gbase, g_user, gtag_user)           \
	NATIVE_SET_GREGS_TO_THREAD(gbase, g_user, gtag_user)

#define CLEAR_DAM	NATIVE_CLEAR_DAM

#endif /* CONFIG_KVM_GUEST_KERNEL */

#else /* E2K_MAXGR_d != 32 */

# error        "Unsupported E2K_MAXGR_d value"

#endif /* E2K_MAXGR_d */

#define DO_SAVE_UPSR_REG_VALUE(upsr_reg, upsr_reg_value)	\
		{ AW(upsr_reg) = (upsr_reg_value); }

#define NATIVE_SAVE_BINCO_REGS(regs)			\
do {							\
	(regs)->cs.lo = NATIVE_READ_CS_LO_REG_VALUE();	\
	(regs)->cs.hi = NATIVE_READ_CS_HI_REG_VALUE();	\
	(regs)->ds.lo = NATIVE_READ_DS_LO_REG_VALUE();	\
	(regs)->ds.hi = NATIVE_READ_DS_HI_REG_VALUE();	\
	(regs)->es.lo = NATIVE_READ_ES_LO_REG_VALUE();	\
	(regs)->es.hi = NATIVE_READ_ES_HI_REG_VALUE();	\
	(regs)->fs.lo = NATIVE_READ_FS_LO_REG_VALUE();	\
	(regs)->fs.hi = NATIVE_READ_FS_HI_REG_VALUE();	\
	(regs)->gs.lo = NATIVE_READ_GS_LO_REG_VALUE();	\
	(regs)->gs.hi = NATIVE_READ_GS_HI_REG_VALUE();	\
	(regs)->ss.lo = NATIVE_READ_SS_LO_REG_VALUE();	\
	(regs)->ss.hi = NATIVE_READ_SS_HI_REG_VALUE();	\
	(regs)->rpr = native_read_RPR_reg();		\
	NATIVE_FLUSH_ALL_TC();			\
	(regs)->tcd = NATIVE_GET_TCD();		\
} while (0)

#define NATIVE_RESTORE_BINCO_REGS(regs)	\
do { \
	native_set_binco_regs((regs)->cs, (regs)->ds, (regs)->es, (regs)->fs, \
			      (regs)->gs, (regs)->ss, (regs)->rpr, (regs)->tcd); \
} while (0)

/*
 * Procedure stack (PS) and procedure chain stack (PCS) hardware filling and
 * spilling is asynchronous process. Page fault traps can overlay to this
 * asynchronous process and some filling and spilling requests can be not
 * completed. These requests were dropped by MMU to trap cellar.
 * We should save not completed filling data before starting of spilling
 * current procedure chain stack to preserve from filling data loss
 */
DECLARE_PER_CPU(unsigned long, kernel_trap_cellar[MMU_TRAP_CELLAR_MAX_SIZE]);

#ifdef	CONFIG_CLW_ENABLE
# define CLW_ONLY(...) __VA_ARGS__
#else
# define CLW_ONLY(...)
#endif

#define	NATIVE_SAVE_TRAP_CELLAR(regs, trap)				\
({									\
	kernel_trap_cellar_t *__restrict kernel_tcellar =		\
		(kernel_trap_cellar_t *) raw_cpu_ptr(kernel_trap_cellar); \
	kernel_trap_cellar_ext_t *__restrict kernel_tcellar_ext =	\
		(kernel_trap_cellar_ext_t *)				\
		((void *) kernel_tcellar + TC_EXT_OFFSET);		\
	trap_cellar_t *tcellar = (trap)->tcellar;			\
	int cnt, cs_req_num = 0, cs_a4 = 0, off, max_cnt;		\
	CLW_ONLY(bool clw_entries = false;)				\
	u64 kstack_pf_addr = 0, stack = (u64) current->stack;		\
	bool end_flag = false, is_qp;					\
									\
	max_cnt = NATIVE_READ_MMU_TRAP_COUNT();				\
	if (max_cnt < 3) {						\
		max_cnt = 3 * HW_TC_SIZE;				\
		end_flag = true;					\
	}								\
	BUG_ON(max_cnt > 3 * HW_TC_SIZE);				\
	_Pragma("loop count (2)")					\
	for (cnt = 0; 3 * cnt < max_cnt; cnt++) {			\
		tc_opcode_t opcode;					\
		tc_cond_t condition;					\
									\
		if (end_flag && AW(kernel_tcellar[cnt].condition) == -1) \
				break;					\
									\
		tcellar[cnt].address = kernel_tcellar[cnt].address;	\
		condition = kernel_tcellar[cnt].condition;		\
		tcellar[cnt].condition = condition;			\
		AW(opcode) = condition.opcode;				\
		is_qp = (opcode.fmt == LDST_QP_FMT ||			\
			 cpu_has(CPU_FEAT_QPREG) && condition.fmtc &&	\
			 opcode.fmt == LDST_QWORD_FMT);			\
		CLW_ONLY(						\
			if (condition.clw)				\
				clw_entries = true;			\
		)							\
		if (is_qp)						\
			tcellar[cnt].mask = kernel_tcellar_ext[cnt].mask; \
		if (condition.store) {					\
			NATIVE_MOVE_TAGGED_DWORD(			\
				&(kernel_tcellar[cnt].data),		\
				&(tcellar[cnt].data));			\
			if (is_qp) {					\
				NATIVE_MOVE_TAGGED_DWORD(		\
					&(kernel_tcellar_ext[cnt].data), \
					&(tcellar[cnt].data_ext));	\
			}						\
		} else if (condition.s_f && condition.sru) {		\
			if (cs_req_num == 0)				\
				cs_a4 = tcellar[cnt].address & (1 << 4); \
			cs_req_num++;					\
		}							\
		if (unlikely(condition.s_f || IS_SPILL(tcellar[cnt])) && \
		    tcellar[cnt].address >= stack &&			\
		    tcellar[cnt].address < (stack + KERNEL_STACKS_SIZE)) \
			kstack_pf_addr = tcellar[cnt].address;		\
		tcellar[cnt].flags = 0;					\
	}								\
	(trap)->tc_count = cnt * 3;					\
	CLW_ONLY(							\
		if (unlikely(clw_entries && cpu_has(CPU_HWBUG_CLW_STALE_L1_ENTRY))) \
			(regs)->clw_cpu = raw_smp_processor_id()	\
	);								\
	(trap)->curr_cnt = -1;						\
	(trap)->ignore_user_tc = 0;					\
	(trap)->tc_called = 0;						\
	(trap)->is_intc = false;					\
	if (cs_req_num > 0) {						\
		/* recover chain stack pointers to repeat FILL */	\
		e2k_pcshtp_t pcshtp = native_read_PCSHTP_reg();		\
		e2k_pcsp_t PCSP = native_read_PCSP_reg();		\
		if (!cs_a4) {						\
			off = cs_req_num * 32;				\
		} else {						\
			off = (cs_req_num - 1) * 32 + 16;		\
		}							\
		pcshtp.ind -= off;					\
		PCSP = incr_pcsp_ind(PCSP, off);			\
		native_write_PCSHTP_reg(pcshtp);			\
		native_write_PCSP_reg(PCSP);				\
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
#define	ENABLE_US_CLW() \
do { \
	if (this_cpu_read(clw_enabled)) \
		write_MMU_US_CL_D(0); \
} while (0)
# define DISABLE_US_CLW()			write_MMU_US_CL_D(1)
#else /* !CONFIG_CLW_ENABLE */
# define ENABLE_US_CLW()
# define DISABLE_US_CLW()
#endif /* CONFIG_CLW_ENABLE */

#define NATIVE_RESTORE_COMMON_REGS(regs) \
do { \
	u64 ctpr1 = LO(regs->ctpr1), ctpr2 = LO(regs->ctpr2), \
	    ctpr3 = LO(regs->ctpr3), ctpr1_hi = HI(regs->ctpr1), \
	    ctpr2_hi = HI(regs->ctpr2), ctpr3_hi = HI(regs->ctpr3), \
	    lsr = regs->lsr, lsr1 = regs->lsr1, \
	    ilcr = regs->ilcr, ilcr1 = regs->ilcr1; \
 \
	NATIVE_RESTORE_COMMON_REGS_VALUES(ctpr1, ctpr2, ctpr3, ctpr1_hi, \
			ctpr2_hi, ctpr3_hi, lsr, lsr1, ilcr, ilcr1); \
} while (0)


#define PREFIX_RESTORE_USER_STACK_REGS(PV_TYPE, regs, in_syscall)	\
({									\
	thread_info_t *ti = current_thread_info();			\
	e2k_stacks_t *stacks;						\
	e2k_usd_t usd;							\
	u64 top;							\
									\
	stacks = (in_syscall) ?						\
			syscall_guest_get_restore_stacks(ti, regs)	\
			:						\
			trap_guest_get_restore_stacks(ti, regs);	\
	usd = stacks->usd;						\
	top = stacks->top;						\
	PV_TYPE##_write_cr((regs)->crs.cr0, (regs)->crs.cr1);		\
	CHECK_USD_BASE_SIZE(regs);					\
	PV_TYPE##_write_USBR_USD_regs(TOS(e2k_sbr_t, top), usd);	\
	RESTORE_USER_CUT_REGS(ti, regs, in_syscall);			\
})

#define NATIVE_RESTORE_USER_STACK_REGS(regs, insyscall) \
		PREFIX_RESTORE_USER_STACK_REGS(native, regs, insyscall)

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is virtualized guest kernel */
#include <asm/kvm/guest/regs_state.h>
#else /* !CONFIG_KVM_GUEST_KERNEL */
/* it is native kernel without any virtualization */
/* or native host kernel with virtualization support */

static inline void kvm_trap_init(unsigned long cellar_addr) { }

/* Save stack registers on kernel native/host/hypervisor mode */
#define SAVE_STACK_REGS(regs, user, trap) \
		NATIVE_SAVE_STACK_REGS(regs, user, trap)

#define RESTORE_USER_STACK_REGS(regs, in_syscall) \
		NATIVE_RESTORE_USER_STACK_REGS(regs, in_syscall)
#define RESTORE_USER_TRAP_STACK_REGS(regs) \
		RESTORE_USER_STACK_REGS(regs, false)
#define RESTORE_USER_SYSCALL_STACK_REGS(regs) \
		RESTORE_USER_STACK_REGS(regs, true)
#define RESTORE_COMMON_REGS(regs) \
		NATIVE_RESTORE_COMMON_REGS(regs)

#define INIT_G_REGS(skip_k_gregs)	NATIVE_INIT_G_REGS(skip_k_gregs)
#define BOOT_INIT_G_REGS()	NATIVE_BOOT_INIT_G_REGS()

#endif /* CONFIG_KVM_GUEST_KERNEL */

static inline void restore_monitor_counters(const struct sw_regs *sw_regs)
{
	e2k_ddmcr_t ddmcr = sw_regs->ddmcr;
	e2k_ddmcr_t ddmcr1 = sw_regs->ddmcr1;
	u64 ddmar0 = sw_regs->ddmar[0];
	u64 ddmar1 = sw_regs->ddmar[1];
	u64 __maybe_unused ddmar2 = sw_regs->ddmar[2];
	u64 __maybe_unused ddmar3 = sw_regs->ddmar[3];
	e2k_dimcr_t dimcr = sw_regs->dimcr;
	e2k_dimcr_t dimcr1 = sw_regs->dimcr1;
	u64 dimar0 = sw_regs->dimar[0];
	u64 dimar1 = sw_regs->dimar[1];
	u64 __maybe_unused dimar2 = sw_regs->dimar[2];
	u64 __maybe_unused dimar3 = sw_regs->dimar[3];

	native_write_DIMTP_reg(sw_regs->dimtp);
	NATIVE_WRITE_DDMAR0_REG_VALUE(ddmar0);
	NATIVE_WRITE_DDMAR1_REG_VALUE(ddmar1);
	NATIVE_WRITE_DDMCR_REG(ddmcr);
	if (cpu_has(CPU_FEAT_ISET_V7)) {
		NATIVE_WRITE_DDMAR2_REG_VALUE(ddmar2);
		NATIVE_WRITE_DDMAR3_REG_VALUE(ddmar3);
		NATIVE_WRITE_DDMCR1_REG(ddmcr1);
	}
	native_write_DIMAR0_reg(dimar0);
	native_write_DIMAR1_reg(dimar1);
	native_write_DIMCR_reg(dimcr);
	if (cpu_has(CPU_FEAT_ISET_V7)) {
		if (!cpu_has(CPU_HWBUG_DIMCR1)) {
			native_write_DIMAR2_reg(dimar2);
			native_write_DIMAR3_reg(dimar3);
			native_write_DIMCR1_reg(dimcr1);
		}
	}
}

/*
 * When we use monitor registers, we count monitor events for the whole system,
 * so DIMCR[1], DDMCR[1], DIMAR{0-3}, DDMAR{0-3}, DIBSR, DDBSR registers are not
 * dependent on process and should not be restored while process switching.
 */
static inline void native_restore_user_only_regs(struct sw_regs *sw_regs)
{
	e2k_dibsr_t dibsr = sw_regs->dibsr;
	e2k_ddbsr_t ddbsr = sw_regs->ddbsr;

	/* Skip breakpoints-related fields handled by
	 * ptrace_hbp_triggered() and arch-independent
	 * hardware breakpoints support */
	dibsr.word &= ~E2K_DIBSR_MASK_ALL_BP;
	dibsr.word |= native_read_DIBSR_reg().word & E2K_DIBSR_MASK_ALL_BP;
	AW(ddbsr) &= ~E2K_DDBSR_MASK_ALL_BP;
	AW(ddbsr) |= NATIVE_READ_DDBSR_REG_VALUE() & E2K_DDBSR_MASK_ALL_BP;

	native_write_DIBSR_reg(dibsr);
	NATIVE_WRITE_DDBSR_REG(ddbsr);
	restore_monitor_counters(sw_regs);
}

static inline void native_clear_user_only_regs(void)
{
	u16 monitors_used = perf_read_monitors_used();
	u8 bps_used = perf_read_bps_used();
	if (!bps_used) {
		native_write_DIBCR_reg(TOS(e2k_dibcr_t, 0));
		NATIVE_WRITE_DDBCR_REG_VALUE(0);
	}
	if (!monitors_used) {
		if (cpu_has(CPU_FEAT_ISET_V7)) {
			if (!cpu_has(CPU_HWBUG_DIMCR1))
				native_write_DIMCR1_reg(TOS(e2k_dimcr_t, 0));
			NATIVE_WRITE_DDMCR1_REG_VALUE(0);
			if (!cpu_has(CPU_HWBUG_DIMCR1)) {
				native_write_DIMAR2_reg(0);
				native_write_DIMAR3_reg(0);
			}
			NATIVE_WRITE_DDMAR2_REG_VALUE(0);
			NATIVE_WRITE_DDMAR3_REG_VALUE(0);
		}
		native_write_DIMCR_reg(TOS(e2k_dimcr_t, 0));
		native_write_DIMAR0_reg(0);
		native_write_DIMAR1_reg(0);
		native_write_DIBSR_reg(TOS(e2k_dibsr_t, 0));
		NATIVE_WRITE_DDMCR_REG_VALUE(0);
		NATIVE_WRITE_DDMAR0_REG_VALUE(0);
		NATIVE_WRITE_DDMAR1_REG_VALUE(0);
		NATIVE_WRITE_DDBSR_REG_VALUE(0);
	} else {
		e2k_dimcr_t dimcr = native_read_DIMCR_reg();
		e2k_ddmcr_t ddmcr = NATIVE_READ_DDMCR_REG();
		e2k_dibsr_t dibsr = native_read_DIBSR_reg();
		e2k_ddbsr_t ddbsr = NATIVE_READ_DDBSR_REG();
		if (!(monitors_used & _BITUL(DIM0))) {
			dimcr.half_word[0] = 0;
			dibsr.m0 = 0;
		}
		if (!(monitors_used & _BITUL(DIM1))) {
			dimcr.half_word[1] = 0;
			dibsr.m1 = 0;
		}
		if (!(monitors_used & _BITUL(DDM0))) {
			ddmcr.half_word[0] = 0;
			ddbsr.m0 = 0;
		}
		if (!(monitors_used & _BITUL(DDM1))) {
			ddmcr.half_word[1] = 0;
			ddbsr.m1 = 0;
		}
		dimcr.u_m_en = 0;
		dimcr.mode = 0;
		native_write_DIMCR_reg(dimcr);
		NATIVE_WRITE_DDMCR_REG(ddmcr);
		if (!(monitors_used & _BITUL(DIM0)))
			native_write_DIMAR0_reg(0);
		if (!(monitors_used & _BITUL(DIM1)))
			native_write_DIMAR1_reg(0);
		if (!(monitors_used & _BITUL(DDM0)))
			NATIVE_WRITE_DDMAR0_REG_VALUE(0);
		if (!(monitors_used & _BITUL(DDM1)))
			NATIVE_WRITE_DDMAR1_REG_VALUE(0);
		if (cpu_has(CPU_FEAT_ISET_V7)) {
			e2k_dimcr_t dimcr1;
			e2k_ddmcr_t ddmcr1;
			if (!cpu_has(CPU_HWBUG_DIMCR1))
				dimcr1 = native_read_DIMCR1_reg();
			ddmcr1 = NATIVE_READ_DDMCR1_REG();
			if (!(monitors_used & _BITUL(DIM2))) {
				dimcr1.half_word[0] = 0;
				dibsr.m2 = 0;
			}
			if (!(monitors_used & _BITUL(DIM3))) {
				dimcr1.half_word[1] = 0;
				dibsr.m3 = 0;
			}
			if (!(monitors_used & _BITUL(DDM2))) {
				ddmcr1.half_word[0] = 0;
				ddbsr.m2 = 0;
			}
			if (!(monitors_used & _BITUL(DDM3))) {
				ddmcr1.half_word[1] = 0;
				ddbsr.m3 = 0;
			}
			if (!cpu_has(CPU_HWBUG_DIMCR1))
				native_write_DIMCR1_reg(dimcr1);
			NATIVE_WRITE_DDMCR1_REG(ddmcr1);
			if (!cpu_has(CPU_HWBUG_DIMCR1)) {
				if (!(monitors_used & _BITUL(DIM2)))
					native_write_DIMAR2_reg(0);
				if (!(monitors_used & _BITUL(DIM3)))
					native_write_DIMAR3_reg(0);
			}
			if (!(monitors_used & _BITUL(DDM2)))
				NATIVE_WRITE_DDMAR2_REG_VALUE(0);
			if (!(monitors_used & _BITUL(DDM3)))
				NATIVE_WRITE_DDMAR3_REG_VALUE(0);
		}
		native_write_DIBSR_reg(dibsr);
		NATIVE_WRITE_DDBSR_REG(ddbsr);
	}
	native_clear_DIMTP_reg();
}


/* Declarate here to prevent loop #include. */
#define PT_PTRACED	0x00000001

static inline void invalidate_MLT(void)
{
	NATIVE_SET_MMUREG(mlt_inv, 0);
}

static inline void
DO_SAVE_TASK_USER_REGS_TO_SWITCH(struct sw_regs *sw_regs,
				 bool task_is_binco, bool task_traced)
{
	if (unlikely(task_is_binco))
		NATIVE_SAVE_BINCO_REGS(sw_regs);

	invalidate_MLT();

	if (unlikely(task_traced))
		native_save_user_only_regs(sw_regs);
}

static inline void
NATIVE_DO_SAVE_TASK_USER_REGS_TO_SWITCH(struct sw_regs *sw_regs,
					bool task_is_binco, bool task_traced)
{
	DO_SAVE_TASK_USER_REGS_TO_SWITCH(sw_regs, task_is_binco, task_traced);
	sw_regs->cutd = native_read_CUTD_reg();
}

static inline void NATIVE_SAVE_TASK_REGS_TO_SWITCH(struct task_struct *task)
{
	struct sw_regs *sw_regs = &task->thread.sw_regs;
	save_global_gregs_fn_t save_global_gregs = machine.save_global_gregs;

	sw_regs->osem = read_OSEM_reg_value();
	sw_regs->uaccess_max = uaccess_max;

	/* Kernel does not use MLT so skip invalidation for kernel threads */
	NATIVE_DO_SAVE_TASK_USER_REGS_TO_SWITCH(sw_regs, TASK_IS_BINCO(task),
						!!(task->ptrace & PT_PTRACED));

	if (task->mm) {
		sw_regs->fpu.fpcr = native_read_FPCR_reg();
		sw_regs->fpu.fpsr = native_read_FPSR_reg();
		sw_regs->fpu.pfpfr = native_read_PFPFR_reg();
		save_global_gregs(&task->thread.sw_regs.u_gregs);

		/*
		 * If AAU was not cleared then at a trap exit of next user
		 * AAU will start working, so clear it explicitly here.
		 */
		NATIVE_CLEAR_APB();
	}
	if (cpu_has(CPU_FEAT_MADM)) {
		sw_regs->madmr = native_read_MADMR_reg();
	}
	NATIVE_FLUSHCPU;

	sw_regs->top = native_read_SBR_reg().base;
	sw_regs->usd = native_read_USD_reg();
	sw_regs->crs.cr1 = native_read_CR1_reg();
	sw_regs->crs.cr0 = native_read_CR0_reg();

	/* These will wait for the flush so we give
	 * the flush some time to finish. */
	sw_regs->psp = native_read_PSP_reg();
	sw_regs->pcsp = native_read_PCSP_reg();
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		sw_regs->usincr = native_read_USINCR_reg();
	}
}

/*
 * now lcc does not have problem with 16b structure on registers
 * (It moves these structures in stack memory)
 */
static inline void
DO_RESTORE_TASK_USER_REGS_TO_SWITCH(struct sw_regs *sw_regs,
				    bool task_is_binco, bool task_traced)
{
	if (unlikely(task_traced))
		native_restore_user_only_regs(sw_regs);
	else	/* Do this always when we don't test prev_task->ptrace */
		native_clear_user_only_regs();

	NATIVE_CLEAR_DAM;

	if (unlikely(task_is_binco)) {
		NATIVE_RESTORE_BINCO_REGS(sw_regs);
	}
}

static inline void
NATIVE_DO_RESTORE_TASK_USER_REGS_TO_SWITCH(struct sw_regs *sw_regs,
					   bool task_is_binco, bool task_traced)
{
	e2k_cutd_t cutd = sw_regs->cutd;

	DO_RESTORE_TASK_USER_REGS_TO_SWITCH(sw_regs, task_is_binco, task_traced);
	native_write_CUTD_reg(cutd);
}

static inline void NATIVE_RESTORE_TASK_REGS_TO_SWITCH(struct task_struct *task,
						      bool is_thread_switch)
{
	struct sw_regs *sw_regs = &task->thread.sw_regs;
	struct pt_regs *regs = task->thread_info.pt_regs;
	u32 osem = sw_regs->osem;
	u64 uaccess_max_value = sw_regs->uaccess_max;
	restore_global_gregs_fn_t restore_global_gregs = machine.restore_global_gregs;

	NATIVE_FLUSHCPU;

	native_write_stacks_cr(sw_regs->psp, sw_regs->pcsp, sw_regs->usd,
			TOS(e2k_sbr_t, sw_regs->top), sw_regs->crs.cr0, sw_regs->crs.cr1);
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		native_write_USINCR_reg(sw_regs->usincr);
	}

	write_OSEM_reg_value(osem);
	uaccess_max = uaccess_max_value;

	NATIVE_DO_RESTORE_TASK_USER_REGS_TO_SWITCH(sw_regs, TASK_IS_BINCO(task),
						   !!(task->ptrace & PT_PTRACED));

	if (task->mm) {
		/*
		 * Clear AAU registers so that next task can't peek previous task addresses
		 * from them. We do not need to clear AAU registers during thread switch.
		 * If the next task was stopped in a trap, clear registers under conditions
		 * opposite to the ones used in AAU registers restore in return from trap.
		 * If the next task was stopped in a syscall, always clear AAU registers.
		 */
		if (!is_thread_switch && regs && (from_syscall(regs) || !aau_working(regs->aasr))) {
			clear_aau_context();
			CLEAR_AADS();
		}
		if (!is_thread_switch && regs && (from_syscall(regs) || !aau_stopped(regs->aasr))) {
			native_clear_aau_aaldis_aaldas();
			RESTORE_AAU_MASK_REGS((e2k_aaldm_t) { .word = 0 },
					      (e2k_aaldv_t) { .word = 0 },
					      regs->aasr);
		}

		restore_global_gregs(&task->thread.sw_regs.u_gregs);
		native_write_FPU_regs(sw_regs->fpu.fpcr, sw_regs->fpu.fpsr, sw_regs->fpu.pfpfr);
	}
	if (cpu_has(CPU_FEAT_MADM)) {
		native_write_MADMR_reg(sw_regs->madmr);
	}
}

static inline void
NATIVE_SWITCH_TO_KERNEL_STACK(e2k_addr_t ps_base, e2k_size_t ps_size,
			      e2k_addr_t pcs_base, e2k_size_t pcs_size,
			      e2k_addr_t ds_base, e2k_size_t ds_size)
{
	e2k_pcsp_t pcsp;
	e2k_psp_t psp;
	e2k_usd_t usd;
	e2k_usbr_t usbr;

	/*
	 * Set Procedure Stack and Procedure Chain stack registers
	 * to the begining of initial PS and PCS stacks
	 */
	NATIVE_FLUSHCPU;
	psp = new_psp(ps_base, ps_size, 0);
	pcsp = new_pcsp(pcs_base, pcs_size, 0);

	/*
	 * Set stack pointers to the begining of kernel initial data stack
	 */
	usbr.base = ds_base + ds_size;

	/*
	 * Reserve additional 64 bytes for parameters area.
	 * Compiler might use it to temporarily store the function's parameters
	 */
	usd = new_usd(ds_base, ds_size, ds_size - 64);

	native_write_stacks(psp, pcsp, usd, usbr);
}

/*
 * There are TIR_NUM(19) tir regs. Bits 64 - 56 is current tir nr
 * After each E2K_GET_DSREG(tir.lo) we will read next tir.
 * For more info see instruction set doc.
 * Read tir regs order is significant
 */
#define SAVE_TIRS(TIRs, TIRs_num, from_intc)				\
({									\
	unsigned long nr_TIRs = -1;					\
	unsigned long all_interrupts = 0;				\
	e2k_tir_t TIR;							\
	do {								\
		TIR.hi = native_read_TIR_HI_reg();			\
		if (unlikely(from_intc && TIR.j >= TIR_NUM))		\
			break;						\
		TIR.lo = native_read_TIR_LO_reg();			\
		++nr_TIRs;						\
		TIRs[TIR.j] = TIR;					\
		all_interrupts |= TIR.hi;				\
	} while (TIR.j);							\
	TIRs_num = nr_TIRs;						\
	all_interrupts & (exc_all_mask | aau_exc_mask);			\
})

static __always_inline void save_sbbp(u64 *sbbp)
{
	BUILD_BUG_ON(SBBP_ENTRIES_NUM != 32);
	u64 tmp1, tmp2;

	asm volatile (
		"{rrd %%sbbp, %[tmp1]}"
		"{rrd %%sbbp, %[tmp2]}"
		"{rrd %%sbbp, %[tmp1];"
		" std,2 [ %[sbbp] + 0x0 ], %[tmp1]}"
		"{rrd %%sbbp, %[tmp2];"
		" std,2 [ %[sbbp] + 0x8 ], %[tmp2]}"
		"{rrd %%sbbp, %[tmp1];"
		" std,2 [ %[sbbp] + 0x10 ], %[tmp1]}"
		"{rrd %%sbbp, %[tmp2];"
		" std,2 [ %[sbbp] + 0x18 ], %[tmp2]}"
		"{rrd %%sbbp, %[tmp1];"
		" std,2 [ %[sbbp] + 0x20 ], %[tmp1]}"
		"{rrd %%sbbp, %[tmp2];"
		" std,2 [ %[sbbp] + 0x28 ], %[tmp2]}"
		"{rrd %%sbbp, %[tmp1];"
		" std,2 [ %[sbbp] + 0x30 ], %[tmp1]}"
		"{rrd %%sbbp, %[tmp2];"
		" std,2 [ %[sbbp] + 0x38 ], %[tmp2]}"
		"{rrd %%sbbp, %[tmp1];"
		" std,2 [ %[sbbp] + 0x40 ], %[tmp1]}"
		"{rrd %%sbbp, %[tmp2];"
		" std,2 [ %[sbbp] + 0x48 ], %[tmp2]}"
		"{rrd %%sbbp, %[tmp1];"
		" std,2 [ %[sbbp] + 0x50 ], %[tmp1]}"
		"{rrd %%sbbp, %[tmp2];"
		" std,2 [ %[sbbp] + 0x58 ], %[tmp2]}"
		"{rrd %%sbbp, %[tmp1];"
		" std,2 [ %[sbbp] + 0x60 ], %[tmp1]}"
		"{rrd %%sbbp, %[tmp2];"
		" std,2 [ %[sbbp] + 0x68 ], %[tmp2]}"
		"{rrd %%sbbp, %[tmp1];"
		" std,2 [ %[sbbp] + 0x70 ], %[tmp1]}"
		"{rrd %%sbbp, %[tmp2];"
		" std,2 [ %[sbbp] + 0x78 ], %[tmp2]}"
		"{rrd %%sbbp, %[tmp1];"
		" std,2 [ %[sbbp] + 0x80 ], %[tmp1]}"
		"{rrd %%sbbp, %[tmp2];"
		" std,2 [ %[sbbp] + 0x88 ], %[tmp2]}"
		"{rrd %%sbbp, %[tmp1];"
		" std,2 [ %[sbbp] + 0x90 ], %[tmp1]}"
		"{rrd %%sbbp, %[tmp2];"
		" std,2 [ %[sbbp] + 0x98 ], %[tmp2]}"
		"{rrd %%sbbp, %[tmp1];"
		" std,2 [ %[sbbp] + 0xa0 ], %[tmp1]}"
		"{rrd %%sbbp, %[tmp2];"
		" std,2 [ %[sbbp] + 0xa8 ], %[tmp2]}"
		"{rrd %%sbbp, %[tmp1];"
		" std,2 [ %[sbbp] + 0xb0 ], %[tmp1]}"
		"{rrd %%sbbp, %[tmp2];"
		" std,2 [ %[sbbp] + 0xb8 ], %[tmp2]}"
		"{rrd %%sbbp, %[tmp1];"
		" std,2 [ %[sbbp] + 0xc0 ], %[tmp1]}"
		"{rrd %%sbbp, %[tmp2];"
		" std,2 [ %[sbbp] + 0xc8 ], %[tmp2]}"
		"{rrd %%sbbp, %[tmp1];"
		" std,2 [ %[sbbp] + 0xd0 ], %[tmp1]}"
		"{rrd %%sbbp, %[tmp2];"
		" std,2 [ %[sbbp] + 0xd8 ], %[tmp2]}"
		"{rrd %%sbbp, %[tmp1];"
		" std,2 [ %[sbbp] + 0xe0 ], %[tmp1]}"
		"{rrd %%sbbp, %[tmp2];"
		" std,2 [ %[sbbp] + 0xe8 ], %[tmp2]}"
		"{std,2 [ %[sbbp] + 0xf0 ], %[tmp1]}"
		"{std,2 [ %[sbbp] + 0xf8 ], %[tmp2]}"
		: [tmp1] "=&r" (tmp1), [tmp2] "=&r" (tmp2)
		: [sbbp] "r" (sbbp)
		: "memory");
}

static inline void set_osgd_task_struct(struct task_struct *task)
{
	e2k_gd_t gd;

	/* {ld/st}osrr{d/qp} instructions are used
	 * for entering kernel since iset v7 */
	if (IS_ENABLED(CONFIG_CPU_HAS_OSR1))
		return;

	gd = new_gd((u64) task, round_up(sizeof(struct task_struct), E2K_ALIGN_GLOBALS_SZ));
	BUG_ON(!IS_ALIGNED((u64) task, E2K_ALIGN_GLOBALS_SZ));
	write_OSGD_reg(gd);
	atomic_load_osgd_to_gd();
}

static inline void
native_set_current_thread_info(struct thread_info *thread,
			       struct task_struct *task)
{
	native_write_CURRENT_reg_value((u64) thread);
	E2K_SET_DGREG_NV(CURRENT_TASK_GREG, task);
	set_osgd_task_struct(task);
}

static inline void
set_current_thread_info(struct thread_info *thread, struct task_struct *task)
{
	write_CURRENT_reg_value((u64) thread);
	E2K_SET_DGREG_NV(CURRENT_TASK_GREG, task);
	set_osgd_task_struct(task);
}

#define	SAVE_PSYSCALL_RVAL(regs, _rval, _rval1, _rval2, _rv1_tag,	\
			   _rv2_tag, _return_desk)			\
({									\
	(regs)->sys_rval = (_rval);					\
	(regs)->rval1 = (_rval1);					\
	(regs)->rval2 = (_rval2);					\
	(regs)->rv1_tag = (_rv1_tag);					\
	(regs)->rv2_tag = (_rv2_tag);					\
	(regs)->return_desk = (_return_desk);				\
})

#endif /* _E2K_REGS_STATE_H */

