#ifndef _E2K_REGS_STATE_H
#define _E2K_REGS_STATE_H

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/signal.h>
#include <linux/irqflags.h>

#ifndef __ASSEMBLY__
#include <asm/e2k_api.h>
#include <asm/cpu_regs_access.h>
#include <asm/monitors.h>
#include <asm/mmu.h>
#include <asm/mmu_regs.h>
#include <asm/system.h>
#include <asm/ptrace.h>
#include <asm/sge.h>
#include <asm/head.h>
#include <asm/tags.h>
#include <asm/iset.h>
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
		print_stack(current);					\
	}								\
})
#else
#define	CHECK_USD_BASE_SIZE(regs)
#endif

/*
 * Macros to save and restore registers.
 */

#define CLEAR_DAM       ({ E2K_SET_MMUREG(dam_inv, 0); })

/* usd regs are saved already */
#define SAVE_STACK_REGS(regs, ti, user, trap)				\
do {									\
	u64 pshtp;							\
	u32 pcshtp;							\
	u64 psp_hi;							\
	u64 pcsp_hi;							\
	/* This flush workarounds bug #29263 and */			\
	/* reserves space for the next trap.     */			\
	if (trap)							\
		E2K_FLUSHC;						\
	AW(regs->crs.cr0_lo)	= E2K_GET_DSREG_NV(cr0.lo);		\
	AW(regs->crs.cr0_hi)	= E2K_GET_DSREG_NV(cr0.hi);		\
	AW(regs->crs.cr1_lo)	= E2K_GET_DSREG_NV(cr1.lo);		\
	AW(regs->crs.cr1_hi)	= E2K_GET_DSREG_NV(cr1.hi);		\
	AW(regs->wd)		= E2K_GET_DSREG(wd);			\
	pshtp			= AW(READ_PSHTP_REG());			\
	if (!trap)							\
		pcshtp			= READ_PCSHTP_REG();		\
	regs->stacks.psp_lo		= READ_PSP_LO_REG();		\
	/* Do not add kernel part when saving user registers. */	\
	if (user) {							\
		BUG_ON(sge_checking_enabled());				\
		psp_hi			= AW(RAW_READ_PSP_HI_REG());	\
		pcsp_hi			= AW(RAW_READ_PCSP_HI_REG());	\
	} else {							\
		psp_hi			= AW(READ_PSP_HI_REG());	\
		pcsp_hi			= AW(READ_PCSP_HI_REG());	\
	}								\
	regs->stacks.pcsp_lo	= READ_PCSP_LO_REG();			\
	AW(regs->pshtp)		= pshtp;				\
	if (!trap)							\
		pcsp_hi += PCSHTP_SIGN_EXTEND(pcshtp);			\
	psp_hi += GET_PSHTP_INDEX((e2k_pshtp_t) pshtp);			\
	AW(regs->stacks.psp_hi) = psp_hi;				\
	AW(regs->stacks.pcsp_hi) = pcsp_hi;				\
	if (user) {							\
		regs->stacks.sbr	= (ti)->u_stk_top;		\
	} else {							\
		regs->stacks.sbr	= READ_SBR_REG_VALUE();		\
	}								\
	CHECK_USD_BASE_SIZE(regs);					\
	(regs)->stacks.valid = 0;					\
} while (0)

#define SAVE_USER_USD_REGS(regs, ti, protected_mode, psl)		\
({									\
	e2k_addr_t ussz;						\
	ussz = AS_STRUCT((regs)->crs.cr1_hi).ussz << 4;			\
	if (protected_mode) {						\
		e2k_pusd_lo_t pusd_lo = {{ 0 }};			\
		pusd_lo.PUSD_lo_base = (ti)->u_stk_base + ussz;		\
		pusd_lo.PUSD_lo_psl = (psl);				\
		pusd_lo.PUSD_lo_p = 1;					\
		(regs)->stacks.usd_hi.USD_hi_size = ussz;		\
		(regs)->stacks.usd_lo.USD_lo_half = pusd_lo.PUSD_lo_half; \
	} else {							\
		(regs)->stacks.usd_hi.USD_hi_half = 0;			\
		(regs)->stacks.usd_hi.USD_hi_size = ussz;		\
		(regs)->stacks.usd_lo.USD_lo_half = 0;			\
		(regs)->stacks.usd_lo.USD_lo_base = (ti)->u_stk_base + ussz; \
	}								\
	CPY_USER_USD_REGS_TO_THREAD_INFO(ti, regs);			\
})

#define CPY_USER_USD_REGS_TO_THREAD_INFO(thread_info, regs)		\
({									\
	(thread_info)->u_usd_hi = (regs)->stacks.usd_hi;		\
	(thread_info)->u_usd_lo = (regs)->stacks.usd_lo;		\
})

#define RESTORE_USER_REGS_TO_THREAD_INFO(thread_info, regs)		\
({	if (regs && regs->stacks.valid &&				\
	    (thread_info->alt_stack | regs->stacks.alt_stack_old)) {	\
		(thread_info)->u_stk_base = (regs)->stacks.u_stk_base_old; \
		(thread_info)->alt_stack = (regs)->stacks.alt_stack_old;\
		(thread_info)->u_stk_top = (regs)->stacks.u_stk_top_old;\
		(thread_info)->u_stk_sz = (regs)->stacks.u_stk_sz_old;	\
	}								\
})

#define SAVE_USER_REGS_FROM_THREAD_INFO(thread_info, regs)		\
({	if (regs) {							\
		(regs)->stacks.u_stk_base_old = (thread_info)->u_stk_base; \
		(regs)->stacks.u_stk_top_old = (thread_info)->u_stk_top;\
		(regs)->stacks.u_stk_sz_old = (thread_info)->u_stk_sz;	\
		(regs)->stacks.alt_stack_old = (thread_info)->alt_stack;\
		(regs)->stacks.valid = 1;				\
	}								\
})

#define STORE_USER_REGS_TO_THREAD_INFO(thread_info, stk_base, top, stk_sz) \
({									\
	(thread_info)->u_stk_base = stk_base;				\
	(thread_info)->u_stk_top = top;					\
	(thread_info)->u_stk_sz = stk_sz;				\
	(thread_info)->alt_stack = 1;				\
})


#define	SAVE_MONITOR_COUNTERS(task)					\
do {									\
	task->thread.sw_regs.ddmar0 = E2K_GET_MMUREG(ddmar0);		\
	task->thread.sw_regs.ddmar1 = E2K_GET_MMUREG(ddmar1);		\
	task->thread.sw_regs.dimar0 = E2K_GET_DSREG(dimar0);		\
	task->thread.sw_regs.dimar1 = E2K_GET_DSREG(dimar1);		\
} while (0)

/*
 * When we use monitor registers, we count monitor events for the whole system,
 * so DIMAR0, DIMAR1, DDMAR0 and DDMAR1 registers are not depend on process and
 * need not be saved while process switching. DIMCR and DDMCR registers are not
 * depend on process too, but they should be saved while process switching,
 * because they are used to determine monitoring start moment during monitor
 * events counting for a process.
 */
#define SAVE_USER_ONLY_REGS(task)					\
do {									\
	AW(task->thread.sw_regs.dibcr)	= E2K_GET_SREG(dibcr);		\
	AW(task->thread.sw_regs.dibsr)	= E2K_GET_SREG(dibsr);		\
	task->thread.sw_regs.dibar0	= E2K_GET_DSREG(dibar0);	\
	task->thread.sw_regs.dibar1	= E2K_GET_DSREG(dibar1);	\
	task->thread.sw_regs.dibar2	= E2K_GET_DSREG(dibar2);	\
	task->thread.sw_regs.dibar3	= E2K_GET_DSREG(dibar3);	\
	AW(task->thread.sw_regs.ddbcr)	= E2K_GET_MMUREG(ddbcr);	\
	AW(task->thread.sw_regs.ddbsr)	= E2K_GET_MMUREG(ddbsr);	\
	task->thread.sw_regs.ddbar0	= E2K_GET_MMUREG(ddbar0);	\
	task->thread.sw_regs.ddbar1	= E2K_GET_MMUREG(ddbar1);	\
	task->thread.sw_regs.ddbar2	= E2K_GET_MMUREG(ddbar2);	\
	task->thread.sw_regs.ddbar3	= E2K_GET_MMUREG(ddbar3);	\
	AW(task->thread.sw_regs.ddmcr)	= E2K_GET_MMUREG(ddmcr);	\
	AW(task->thread.sw_regs.dimcr)	= E2K_GET_DSREG(dimcr);		\
	if (!MONITORING_IS_ACTIVE)					\
		SAVE_MONITOR_COUNTERS(task);				\
} while (0)

#if (E2K_MAXGR_d == 32)

/*
 * g16/g17 hold pointers to current, so we can skip saving and restoring
 * them on context switch and upon entering/exiting signal handlers
 * (they are stored in thread_info)
 */
# define SAVE_GREGS(gbase, gext, tag, save_global)			\
do {									\
	if (save_global) {						\
		E2K_SAVE_GREG(&gbase[0], &gext[0], &tag[0], 0, 1);	\
		E2K_SAVE_GREG(&gbase[2], &gext[2], &tag[2], 2, 3);	\
		E2K_SAVE_GREG(&gbase[4], &gext[4], &tag[4], 4, 5);	\
		E2K_SAVE_GREG(&gbase[6], &gext[6], &tag[6], 6, 7);	\
		E2K_SAVE_GREG(&gbase[8], &gext[8], &tag[8], 8, 9);	\
		E2K_SAVE_GREG(&gbase[10], &gext[10], &tag[10], 10, 11);	\
		E2K_SAVE_GREG(&gbase[12], &gext[12], &tag[12], 12, 13); \
		E2K_SAVE_GREG(&gbase[14], &gext[14], &tag[14], 14, 15);	\
	}								\
	/*E2K_SAVE_GREG(&gbase[16], &gext[16], &tag[16], 16, 17);*/	\
	/*E2K_SAVE_GREG(&gbase[18], &gext[18], &tag[18], 18, 19);*/	\
	E2K_SAVE_GREG(&gbase[20], &gext[20], &tag[20], 20, 21);		\
	E2K_SAVE_GREG(&gbase[22], &gext[22], &tag[22], 22, 23);		\
	E2K_SAVE_GREG(&gbase[24], &gext[24], &tag[24], 24, 25);		\
	E2K_SAVE_GREG(&gbase[26], &gext[26], &tag[26], 26, 27);		\
	E2K_SAVE_GREG(&gbase[28], &gext[28], &tag[28], 28, 29);		\
	E2K_SAVE_GREG(&gbase[30], &gext[30], &tag[30], 30, 31);		\
} while (0)

/* Same as SAVE_GREGS but saves %g16-%g31 registers only */
# define SAVE_GREGS_SIGNAL(gbase, gext, tag)				\
do {									\
	/*E2K_SAVE_GREG(&gbase[0], &gext[0], &tag[0], 16, 17);*/	\
	/*E2K_SAVE_GREG(&gbase[2], &gext[2], &tag[2], 18, 19);*/	\
	E2K_SAVE_GREG(&gbase[4], &gext[4], &tag[4], 20, 21);		\
	E2K_SAVE_GREG(&gbase[6], &gext[6], &tag[6], 22, 23);		\
	E2K_SAVE_GREG(&gbase[8], &gext[8], &tag[8], 24, 25);		\
	E2K_SAVE_GREG(&gbase[10], &gext[10], &tag[10], 26, 27);		\
	E2K_SAVE_GREG(&gbase[12], &gext[12], &tag[12], 28, 29);		\
	E2K_SAVE_GREG(&gbase[14], &gext[14], &tag[14], 30, 31);		\
} while (0)


# define RESTORE_GREGS(gbase, gext, tag, restore_global)		\
do {									\
	if (restore_global) {						\
		E2K_RESTORE_GREG(&gbase[0], &gext[0], &tag[0], 0, 1);	\
		E2K_RESTORE_GREG(&gbase[2], &gext[2], &tag[2], 2, 3);	\
		E2K_RESTORE_GREG(&gbase[4], &gext[4], &tag[4], 4, 5);	\
		E2K_RESTORE_GREG(&gbase[6], &gext[6], &tag[6], 6, 7);	\
		E2K_RESTORE_GREG(&gbase[8], &gext[8], &tag[8], 8, 9);	\
		E2K_RESTORE_GREG(&gbase[10], &gext[10], &tag[10], 10, 11); \
		E2K_RESTORE_GREG(&gbase[12], &gext[12], &tag[12], 12, 13); \
		E2K_RESTORE_GREG(&gbase[14], &gext[14], &tag[14], 14, 15); \
	}								\
	/*E2K_RESTORE_GREG(&gbase[16], &gext[16], &tag[16], 16, 17);*/	\
	/*E2K_RESTORE_GREG(&gbase[18], &gext[18], &tag[18], 18, 19);*/	\
	E2K_RESTORE_GREG(&gbase[20], &gext[20], &tag[20], 20, 21);	\
	E2K_RESTORE_GREG(&gbase[22], &gext[22], &tag[22], 22, 23);	\
	E2K_RESTORE_GREG(&gbase[24], &gext[24], &tag[24], 24, 25);	\
	E2K_RESTORE_GREG(&gbase[26], &gext[26], &tag[26], 26, 27);	\
	E2K_RESTORE_GREG(&gbase[28], &gext[28], &tag[28], 28, 29);	\
	E2K_RESTORE_GREG(&gbase[30], &gext[30], &tag[30], 30, 31);	\
} while (0)

/* Same as SAVE_GREGS but restores %g16-%g31 registers only */
# define RESTORE_GREGS_SIGNAL(gbase, gext, tag)				\
do {									\
	/*E2K_RESTORE_GREG(&gbase[0], &gext[0], &tag[0], 16, 17);*/	\
	/*E2K_RESTORE_GREG(&gbase[2], &gext[2], &tag[2], 18, 19);*/	\
	E2K_RESTORE_GREG(&gbase[4], &gext[4], &tag[4], 20, 21);		\
	E2K_RESTORE_GREG(&gbase[6], &gext[6], &tag[6], 22, 23);		\
	E2K_RESTORE_GREG(&gbase[8], &gext[8], &tag[8], 24, 25);		\
	E2K_RESTORE_GREG(&gbase[10], &gext[10], &tag[10], 26, 27);	\
	E2K_RESTORE_GREG(&gbase[12], &gext[12], &tag[12], 28, 29);	\
	E2K_RESTORE_GREG(&gbase[14], &gext[14], &tag[14], 30, 31);	\
} while (0)


/* Slower than SAVE_GREGS(), used when there is a need to access %dg value
 * stored in memory for other purpose than restoring. */
# define SAVE_GREGS_CLEAR_TAG(gbase, gext, tag, save_global) \
do { \
	if (save_global) { \
		E2K_SAVE_GREG_CLEAR_TAG(&gbase[0], &gext[0], &tag[0], 0, 1); \
		E2K_SAVE_GREG_CLEAR_TAG(&gbase[2], &gext[2], &tag[2], 2, 3); \
		E2K_SAVE_GREG_CLEAR_TAG(&gbase[4], &gext[4], &tag[4], 4, 5); \
		E2K_SAVE_GREG_CLEAR_TAG(&gbase[6], &gext[6], &tag[6], 6, 7); \
		E2K_SAVE_GREG_CLEAR_TAG(&gbase[8], &gext[8], &tag[8], 8, 9); \
		E2K_SAVE_GREG_CLEAR_TAG(&gbase[10], &gext[10], &tag[10], \
					10, 11); \
		E2K_SAVE_GREG_CLEAR_TAG(&gbase[12], &gext[12], &tag[12], \
					12, 13); \
		E2K_SAVE_GREG_CLEAR_TAG(&gbase[14], &gext[14], &tag[14], \
					14, 15); \
	} \
	/*E2K_SAVE_GREG_CLEAR_TAG(&gbase[16], &gext[16], &tag[16], 16, 17);*/ \
	/*E2K_SAVE_GREG_CLEAR_TAG(&gbase[18], &gext[18], &tag[18], 18, 19);*/ \
	E2K_SAVE_GREG_CLEAR_TAG(&gbase[20], &gext[20], &tag[20], 20, 21); \
	E2K_SAVE_GREG_CLEAR_TAG(&gbase[22], &gext[22], &tag[22], 22, 23); \
	E2K_SAVE_GREG_CLEAR_TAG(&gbase[24], &gext[24], &tag[24], 24, 25); \
	E2K_SAVE_GREG_CLEAR_TAG(&gbase[26], &gext[26], &tag[26], 26, 27); \
	E2K_SAVE_GREG_CLEAR_TAG(&gbase[28], &gext[28], &tag[28], 28, 29); \
	E2K_SAVE_GREG_CLEAR_TAG(&gbase[30], &gext[30], &tag[30], 30, 31); \
} while (0)

# define INIT_G_REGS()					\
	({						\
		init_BGR_reg();				\
		E2K_GREGS_SET_EMPTY();			\
	})

/* ptrace related guys: we do not use them on switching. */
# define GET_GREGS_FROM_THREAD(g_user, gtag_user, gext_user, gbase,	  \
		       gext, tag)					  \
({									  \
		void * g_u = g_user;					  \
		void * gt_u = gtag_user;				  \
		void * ge_u = gext_user;				  \
									  \
		E2K_GET_GREGS_FROM_THREAD(g_u, gt_u, ge_u, gbase, gext,	  \
								tag);	  \
})

# define SET_GREGS_TO_THREAD(gbase, gext, tag, g_user, gtag_user,	\
							gext_user)	\
({									\
		void * g_u = g_user;					\
		void * gt_u = gtag_user;				\
		void * ge_u = gext_user;				\
									\
		E2K_SET_GREGS_TO_THREAD(gbase, gext, tag,		\
					g_u, gt_u, ge_u);		\
})

#else /* E2K_MAXGR_d != 32 */

# error        "Unsupported E2K_MAXGR_d value"

#endif /* E2K_MAXGR_d */

#ifdef CONFIG_GREGS_CONTEXT

# define DO_SAVE_GLOBAL_REGISTERS(sw_regs, save_global, keep_bgr_val)	\
do {									\
	AS_WORD((sw_regs)->bgr) = E2K_GET_SREG(bgr);			\
	init_BGR_reg(); /* enable whole GRF */				\
	SAVE_GREGS((sw_regs)->gbase, (sw_regs)->gext,			\
		   (sw_regs)->tag, save_global);			\
	if (keep_bgr_val)						\
		E2K_SET_SREG(bgr, AS_WORD((sw_regs)->bgr));		\
} while (0)

# define DO_LOAD_GLOBAL_REGISTERS(sw_regs, restore_global)		\
do {									\
	init_BGR_reg();  /* enable whole GRF */				\
	RESTORE_GREGS((sw_regs)->gbase, (sw_regs)->gext,		\
		      (sw_regs)->tag, restore_global);			\
	E2K_SET_SREG(bgr, AS_WORD((sw_regs)->bgr));			\
} while (0)

# define SAVE_GLOBAL_REGISTERS_CLEAR_TAG(gregs, save_global)		\
do {									\
	AS_WORD((gregs)->bgr) = E2K_GET_SREG(bgr);			\
	init_BGR_reg(); /* enable whole GRF */				\
	SAVE_GREGS_CLEAR_TAG((gregs)->gbase, (gregs)->gext,		\
			     (gregs)->tag, save_global);		\
	E2K_SET_SREG(bgr, AS_WORD((gregs)->bgr));			\
} while (0)

# define SAVE_GLOBAL_REGISTERS_SIGNAL(gregs)				\
do {									\
	AS_WORD((gregs)->bgr) = E2K_GET_SREG(bgr);			\
	init_BGR_reg(); /* enable whole GRF */				\
	SAVE_GREGS_SIGNAL((gregs)->gbase, (gregs)->gext,		\
			  (gregs)->tag);				\
	E2K_SET_SREG(bgr, AW((gregs)->bgr));				\
} while (0)

# define LOAD_GLOBAL_REGISTERS_SIGNAL(gregs)				\
do {									\
	init_BGR_reg();  /* enable whole GRF */				\
	RESTORE_GREGS_SIGNAL((gregs)->gbase, (gregs)->gext,		\
		      (gregs)->tag);					\
	E2K_SET_SREG(bgr, AW((gregs)->bgr));				\
} while (0)



# define SAVE_GLOBAL_REGISTERS(tsk, keep_bgr_val)	\
	DO_SAVE_GLOBAL_REGISTERS((&(tsk)->thread.sw_regs), true, keep_bgr_val)

# define LOAD_GLOBAL_REGISTERS(tsk)    \
	DO_LOAD_GLOBAL_REGISTERS((&(tsk)->thread.sw_regs), true)

# define INIT_GLOBAL_REGISTERS(sw_regs)				\
do {								\
	(sw_regs)->bgr = E2K_INITIAL_BGR;			\
	memset((sw_regs)->gbase, 0, sizeof((sw_regs)->gbase));	\
	memset((sw_regs)->gext, 0, sizeof((sw_regs)->gext));	\
	memset((sw_regs)->tag, 0, sizeof((sw_regs)->tag));	\
} while (0)

# define INIT_TI_GLOBAL_REGISTERS(new_ti)			\
do {								\
	memset(new_ti->gbase, 0, sizeof(new_ti->gbase));	\
	memset(new_ti->gext, 0, sizeof(new_ti->gext));		\
	memset(new_ti->tag, 0, sizeof(new_ti->tag));		\
} while (0)

#else /* ! CONFIG_GREGS_CONTEXT */

# define SAVE_GLOBAL_REGISTERS(task, keep_bgr_val)
# define LOAD_GLOBAL_REGISTERS(task)
# define INIT_GLOBAL_REGISTERS(task)

#endif /* CONFIG_GREGS_CONTEXT */


#define DO_SAVE_UPSR_REG_VALUE(upsr_reg, upsr_reg_value)	\
		{ AS_WORD(upsr_reg) = (upsr_reg_value); }
#define DO_SAVE_UPSR_REG(upsr_reg)	\
		DO_SAVE_UPSR_REG_VALUE((upsr_reg), E2K_GET_SREG_NV(upsr))
#define SAVE_UPSR_REG(regs)	DO_SAVE_UPSR_REG((regs)->upsr)
#define DO_RESTORE_UPSR_REG(upsr_reg)	\
		{ E2K_SET_SREG(upsr, AS_WORD(upsr_reg)); }
#define RESTORE_UPSR_REG(regs)	DO_RESTORE_UPSR_REG((regs)->upsr)

/*
 * Save and restore current state of kernel stacks, which can be changed
 * by handle_signal() to run user signal handler
 */
#ifdef	CONFIG_CHECK_KERNEL_USD_SIZE
#define	CHECK_TI_K_USD_SIZE(ti)					\
({								\
	if ((ti)->k_usd_hi.USD_hi_size > (ti)->k_stk_sz) {	\
		raw_local_irq_disable();			\
		printk("CHECK_TI_K_USD_SIZE() thread info USD size 0x%lx > " \
			" kernel stack size 0x%lx USD base 0x%lx size " \
			"0x%lx\n",				\
			(ti)->k_usd_hi.USD_hi_size, (ti)->k_stk_sz, \
			READ_USD_LO_REG().USD_lo_base,		\
			READ_USD_HI_REG().USD_hi_size);		\
		panic("CHECK_TI_K_USD_SIZE() bad kernel data stack size"); \
	}							\
})
#else	/* ! CONFIG_CHECK_KERNEL_USD_SIZE */
#define	CHECK_TI_K_USD_SIZE(ti)
#endif	/* CONFIG_CHECK_KERNEL_USD_SIZE */

#define DO_SAVE_KERNEL_STACKS_STATE(usd_size, thread_info)	\
({								\
	(usd_size) = (thread_info)->k_usd_hi.USD_hi_size;	\
	CHECK_TI_K_USD_SIZE(thread_info);			\
})
#define SAVE_KERNEL_STACKS_STATE(regs, thread_info)		\
		DO_SAVE_KERNEL_STACKS_STATE((regs)->k_usd_size, thread_info)

#define DO_RESTORE_KERNEL_STACKS_STATE(usd_size, thread_info, restore_k_ds) \
({									    \
	if (restore_k_ds && (thread_info)->k_stk_sz_new) {		    \
		(thread_info)->k_stk_base = thread_info->k_stk_base_new;    \
		(thread_info)->k_stk_sz = thread_info->k_stk_sz_new;	    \
	}								    \
	(thread_info)->k_usd_hi.USD_hi_size = (usd_size);		    \
	(thread_info)->k_usd_lo.USD_lo_base =				    \
		(thread_info)->k_stk_base + (usd_size);			    \
	CHECK_TI_K_USD_SIZE(thread_info);				    \
})
#define RESTORE_KERNEL_STACKS_STATE(regs, thread_info, restore_k_ds)	\
		DO_RESTORE_KERNEL_STACKS_STATE(				\
			(regs)->k_usd_size, thread_info, restore_k_ds)

#define SAVE_RPR_REGS(regs) \
({ \
	regs->rpr_lo = E2K_GET_DSREG(rpr.lo); \
	regs->rpr_hi = E2K_GET_DSREG(rpr.hi); \
})

#define SAVE_INTEL_REGS(regs)	\
	regs->cs_lo = E2K_GET_DSREG(cs.lo);	\
	regs->cs_hi = E2K_GET_DSREG(cs.hi);	\
	regs->ds_lo = E2K_GET_DSREG(ds.lo);	\
	regs->ds_hi = E2K_GET_DSREG(ds.hi);	\
	regs->es_lo = E2K_GET_DSREG(es.lo);	\
	regs->es_hi = E2K_GET_DSREG(es.hi);	\
	regs->fs_lo = E2K_GET_DSREG(fs.lo);	\
	regs->fs_hi = E2K_GET_DSREG(fs.hi);	\
	regs->gs_lo = E2K_GET_DSREG(gs.lo);	\
	regs->gs_hi = E2K_GET_DSREG(gs.hi);	\
	regs->ss_lo = E2K_GET_DSREG(ss.lo);	\
	regs->ss_hi = E2K_GET_DSREG(ss.hi);	\
	regs->rpr_lo = E2K_GET_DSREG(rpr.lo);	\
	regs->rpr_hi = E2K_GET_DSREG(rpr.hi);

#define RESTORE_INTEL_REGS(regs)	\
({ \
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
	E2K_SET_DSREG_CLOSED(cs.lo, cs_lo);	\
	E2K_SET_DSREG_CLOSED(cs.hi, cs_hi);	\
	E2K_SET_DSREG_CLOSED(ds.lo, ds_lo);	\
	E2K_SET_DSREG_CLOSED(ds.hi, ds_hi);	\
	E2K_SET_DSREG_CLOSED(es.lo, es_lo);	\
	E2K_SET_DSREG_CLOSED(es.hi, es_hi);	\
	E2K_SET_DSREG_CLOSED(fs.lo, fs_lo);	\
	E2K_SET_DSREG_CLOSED(fs.hi, fs_hi);	\
	E2K_SET_DSREG_CLOSED(gs.lo, gs_lo);	\
	E2K_SET_DSREG_CLOSED(gs.hi, gs_hi);	\
	E2K_SET_DSREG_CLOSED(ss.lo, ss_lo);	\
	E2K_SET_DSREG_CLOSED(ss.hi, ss_hi);	\
	E2K_SET_DSREG_CLOSED(rpr.lo, rpr_lo);	\
	E2K_SET_DSREG_CLOSED(rpr.hi, rpr_hi);	\
})

/*
 * Procedure stack (PS) and procedure chain stack (PCS) hardware filling and
 * spilling is asynchronous process. Page fault traps can overlay to this
 * asynchronous process and some filling and spilling requests can be not
 * completed. These requests were dropped by MMU to trap cellar.
 * We should save not completed filling data before starting of spilling
 * current procedure chain stack to preserve from filling data loss
 */

#define	SAVE_TRAP_CELLAR(regs, trap)				\
{								\
	kernel_trap_cellar_t *kernel_tcellar =			\
		(kernel_trap_cellar_t *)KERNEL_TRAP_CELLAR;	\
	trap_cellar_t *tcellar = trap->tcellar;			\
	int cnt;						\
	int cs_req_num = 0;					\
	int cs_a4 = 0;						\
	int off;						\
	int max_cnt;						\
								\
	max_cnt = READ_MMU_TRAP_COUNT();			\
	trap->tc_count = max_cnt;				\
	trap->curr_cnt = -1;					\
	trap->ignore_user_tc = 0;				\
	trap->tc_called = 0;					\
	trap->from_sigreturn = 0;				\
	CLEAR_CLW_REQUEST_COUNT(regs);				\
	for (cnt = 0; 3 * cnt < max_cnt; cnt++) {	        \
		tcellar[cnt].address = kernel_tcellar[cnt].address; \
		AW(tcellar[cnt].condition) =			\
			AW(kernel_tcellar[cnt].condition);	\
		if (AS(tcellar[cnt].condition).clw) {		\
			if (GET_CLW_REQUEST_COUNT(regs) == 0) {	\
				SET_CLW_FIRST_REQUEST(regs, cnt); \
			}					\
			INC_CLW_REQUEST_COUNT(regs);		\
		}						\
		if (AS(tcellar[cnt].condition).store) {		\
			E2K_MOVE_TAGGED_DWORD(&(kernel_tcellar[cnt].data),    \
							&(tcellar[cnt].data));\
		} else if (AS(tcellar[cnt].condition).s_f &&	\
			   AS(tcellar[cnt].condition).sru) {	\
			if (cs_req_num == 0)			\
				cs_a4 = tcellar[cnt].address & (1 << 4); \
			cs_req_num ++;				\
		}						\
		tcellar[cnt].flags = 0;				\
	}							\
	if (cs_req_num > 0) {					\
		/* recover chain stack pointers to repeat FILL */ \
		e2k_pcshtp_t pcshtp = READ_PCSHTP_REG();	\
		s64 pcshtp_ext = PCSHTP_SIGN_EXTEND(pcshtp);	\
		e2k_pcsp_hi_t PCSP_hi = READ_PCSP_HI_REG();	\
		if (!cs_a4) {					\
			off = cs_req_num * 32;			\
		} else {					\
			off = (cs_req_num - 1) * 32 + 16;	\
		}						\
		pcshtp_ext -= off;				\
		PCSP_hi.PCSP_hi_ind += off;			\
		WRITE_PCSHTP_REG_SVALUE(pcshtp_ext);		\
		WRITE_PCSP_HI_REG(PCSP_hi);			\
	}							\
}

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
# define ENABLE_US_CLW()
# define DISABLE_US_CLW()
#endif	/* CONFIG_CLW_ENABLE */

#define RESTORE_COMMON_REGS(regs)					\
({									\
	u64     ctpr1 = AW(regs->ctpr1), ctpr2 = AW(regs->ctpr2),	\
		ctpr3 = AW(regs->ctpr3), lsr = regs->lsr,		\
		ilcr = regs->ilcr;					\
	/* ctpr2 is restored first because of tight time constraints	\
	 * on restoring ctpr2 and aaldv. */				\
	E2K_SET_DSREG(ctpr2, ctpr2);					\
	E2K_SET_DSREG(ctpr1, ctpr1);					\
	E2K_SET_DSREG(ctpr3, ctpr3);					\
	E2K_SET_DSREG(lsr, lsr);					\
	E2K_SET_DSREG(ilcr, ilcr);					\
})

#define RESTORE_HS_REGS(regs)						\
({									\
	BUG_ON(sge_checking_enabled());					\
	E2K_FLUSHCPU;							\
	/*								\
	 * We are restoring user registers, so do not add kernel part.	\
	 */								\
	RAW_WRITE_PSP_REG((regs)->stacks.psp_hi,			\
		(regs)->stacks.psp_lo);					\
	RAW_WRITE_PCSP_REG((regs)->stacks.pcsp_hi,			\
		(regs)->stacks.pcsp_lo);				\
})

#define RESTORE_USER_STACK_REGS(regs, restore_hs, protected_mode)	\
({									\
	e2k_wd_t wd;	                				\
	u64 usd_lo = AS_WORD((regs)->stacks.usd_lo);			\
	u64 cr0_hi = AS_WORD((regs)->crs.cr0_hi);			\
	u64 cr0_lo = AS_WORD((regs)->crs.cr0_lo);			\
	u64 cr1_hi = AS_WORD((regs)->crs.cr1_hi);			\
	u64 cr1_lo = AS_WORD((regs)->crs.cr1_lo);			\
	u64 usd_hi = AS_WORD((regs)->stacks.usd_hi);			\
	u64 sbr = (regs)->stacks.sbr;				        \
	CHECK_USD_BASE_SIZE(regs);					\
	AS_WORD(wd) = E2K_GET_DSREG(wd);				\
	AS_STRUCT(wd).psize = AS_STRUCT(regs->wd).psize;		\
	E2K_SET_DSREG(wd, AS_WORD(wd));		        		\
	WRITE_SBR_REG_VALUE(sbr);					\
	WRITE_USD_REG_VALUE(usd_hi, usd_lo);				\
	if (restore_hs)							\
		RESTORE_HS_REGS(regs);					\
	E2K_SET_DSREG_NV_NOIRQ(cr0.hi, cr0_hi);				\
	E2K_SET_DSREG_NV_NOIRQ(cr0.lo, cr0_lo);				\
	E2K_SET_DSREG_NV_NOIRQ(cr1.hi, cr1_hi);				\
	E2K_SET_DSREG_NV_NOIRQ(cr1.lo, cr1_lo);				\
})

#define RESTORE_MONITOR_COUNTERS(sw_regs)	\
do {						\
	u64 ddmcr = AW(sw_regs->ddmcr);		\
	u64 ddmar0 = sw_regs->ddmar0;		\
	u64 ddmar1 = sw_regs->ddmar1;		\
	u64 dimcr = AW(sw_regs->dimcr);		\
	u64 dimar0 = sw_regs->dimar0;		\
	u64 dimar1 = sw_regs->dimar1;		\
						\
	E2K_SET_MMUREG(ddmcr,  ddmcr);		\
	E2K_SET_MMUREG(ddmar0, ddmar0);		\
	E2K_SET_MMUREG(ddmar1, ddmar1);		\
	E2K_SET_DSREG(dimcr,   dimcr);		\
	E2K_SET_DSREG(dimar0,  dimar0);		\
	E2K_SET_DSREG(dimar1,  dimar1);		\
} while (0)

/*
 * When we use monitor registers, we count monitor events for the whole system,
 * so DIMCR, DDMCR, DIMAR0, DIMAR1, DDMAR0, DDMAR1, DIBSR, DDBSR registers are
 * not dependent on process and should not be restored while process switching.
 */
#define RESTORE_USER_ONLY_REGS(sw_regs)			\
do {							\
	u32 dibcr = AW(sw_regs->dibcr);			\
	u32 dibsr = AW(sw_regs->dibsr);			\
	u64 dibar0 = sw_regs->dibar0;			\
	u64 dibar1 = sw_regs->dibar1;			\
	u64 dibar2 = sw_regs->dibar2;			\
	u64 dibar3 = sw_regs->dibar3;			\
	u64 ddbcr = AW(sw_regs->ddbcr);			\
	u64 ddbsr = AW(sw_regs->ddbsr);			\
	u64 ddbar0 = sw_regs->ddbar0;			\
	u64 ddbar1 = sw_regs->ddbar1;			\
	u64 ddbar2 = sw_regs->ddbar2;			\
	u64 ddbar3 = sw_regs->ddbar3;			\
							\
	E2K_SET_SREG(dibcr, dibcr);			\
	E2K_SET_DSREG(dibar0,  dibar0);			\
	E2K_SET_DSREG(dibar1,  dibar1);			\
	E2K_SET_DSREG(dibar2,  dibar2);			\
	E2K_SET_DSREG(dibar3,  dibar3);			\
	E2K_SET_MMUREG(ddbcr,   ddbcr);			\
	E2K_SET_MMUREG(ddbar0,  ddbar0);		\
	E2K_SET_MMUREG(ddbar1,  ddbar1);		\
	E2K_SET_MMUREG(ddbar2,  ddbar2);		\
	E2K_SET_MMUREG(ddbar3,  ddbar3);		\
	if (!MONITORING_IS_ACTIVE) {			\
		E2K_SET_SREG(dibsr, dibsr);		\
		E2K_SET_MMUREG(ddbsr, ddbsr);		\
		RESTORE_MONITOR_COUNTERS(sw_regs);	\
	}						\
} while (0)

#define CLEAR_USER_ONLY_REGS()			\
do {						\
	E2K_SET_SREG(dibcr, 0);			\
	E2K_SET_MMUREG(ddbcr, 0);		\
	if (!MONITORING_IS_ACTIVE) {		\
		E2K_SET_DSREG(dimcr, 0);	\
		E2K_SET_MMUREG(ddmcr, 0);	\
	}					\
} while (0)


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
	E2K_SET_SREG_NV(pfpfr, AS_WORD(pfpfr));	\
	E2K_SET_SREG_NV(fpcr,  AS_WORD(fpcr));	\
	E2K_SET_SREG_NV(fpsr,  AS_WORD(fpsr));	\
})

/* Declarate here to prevent loop #include. */
#define PT_PTRACED	0x00000001

static inline void
SAVE_TASK_REGS_TO_SWITCH(struct task_struct *task, int save_ip)
{
	const int task_is_binco = TASK_IS_BINCO(task);
	struct mm_struct *mm = task->mm;
	struct sw_regs *sw_regs = &task->thread.sw_regs;

	WARN_ONCE(!AS(sw_regs->upsr).nmie,
		  "Non-maskable interrupts are disabled\n");

	if (unlikely(task_is_binco)) {
		SAVE_INTEL_REGS((sw_regs));
#ifdef CONFIG_TC_STORAGE
		E2K_FLUSH_ALL_TC;
		sw_regs->tcd = E2K_GET_TCD();
#endif
	}

#ifdef CONFIG_MLT_STORAGE
	if (mm) {
		/* Kernel does not use MLT so skip this for kernel threads */
		if (unlikely(MLT_NOT_EMPTY())) {
			WARN_ONCE(true, "MLT isn't empty\n");
			invalidate_MLT_context();
		}
	}
#endif

	E2K_FLUSHCPU;

	sw_regs->sbr		= READ_SBR_REG_VALUE();
	sw_regs->usd_hi		= READ_USD_HI_REG();
	sw_regs->usd_lo		= READ_USD_LO_REG();

	AS_WORD(sw_regs->cr_wd)		= E2K_GET_DSREG_NV(cr1.lo);
	AS_WORD(sw_regs->cr_ussz)	= E2K_GET_DSREG_NV(cr1.hi);
	if (likely(save_ip)) {
		AS_WORD(sw_regs->cr0_lo) = E2K_GET_DSREG_NV(cr0.lo);
		AS_WORD(sw_regs->cr0_hi) = E2K_GET_DSREG_NV(cr0.hi);
	}

	AS_WORD(sw_regs->fpcr) = E2K_GET_SREG_NV(fpcr);
	AS_WORD(sw_regs->fpsr) = E2K_GET_SREG_NV(fpsr);
	AS_WORD(sw_regs->pfpfr)	= E2K_GET_SREG_NV(pfpfr);
	AS_WORD(sw_regs->cutd) = E2K_GET_DSREG_NV(cutd);

	if (mm)
		SAVE_GLOBAL_REGISTERS(task, false);

	/* These will wait for the flush so we give
	 * the flush some time to finish. */
	sw_regs->psp_hi		= RAW_READ_PSP_HI_REG();
	sw_regs->psp_lo		= READ_PSP_LO_REG();
	sw_regs->pcsp_hi	= RAW_READ_PCSP_HI_REG();
	sw_regs->pcsp_lo	= READ_PCSP_LO_REG();

	if (unlikely(task->ptrace & PT_PTRACED))
		SAVE_USER_ONLY_REGS(task);
}

/*
 * now lcc has problem with structure on registers
 * (It moves these structures in stack memory)
 */
static inline void
RESTORE_TASK_REGS_TO_SWITCH(struct task_struct *task, int restore_ip)
{
	struct sw_regs *sw_regs = &task->thread.sw_regs;
	u64 sbr = sw_regs->sbr;
	u64 usd_lo = AS_WORD(sw_regs->usd_lo);
	u64 usd_hi = AS_WORD(sw_regs->usd_hi);
	u64 psp_lo = AS_WORD(sw_regs->psp_lo);
	u64 psp_hi = AS_WORD(sw_regs->psp_hi);
	u64 pcsp_lo = AS_WORD(sw_regs->pcsp_lo);
	u64 pcsp_hi = AS_WORD(sw_regs->pcsp_hi);
	u64 cr_wd = AS_WORD(sw_regs->cr_wd);
	u64 cr_ussz = AS_WORD(sw_regs->cr_ussz);
	u64 fpcr = AS_WORD(sw_regs->fpcr);
	u64 fpsr = AS_WORD(sw_regs->fpsr);
	u64 pfpfr = AS_WORD(sw_regs->pfpfr);
	u64 cutd = AS_WORD(sw_regs->cutd);
	const int task_is_binco = TASK_IS_BINCO(task);
	struct mm_struct *mm = task->mm;

	WRITE_SBR_REG_VALUE(sbr);
	WRITE_USD_REG(((e2k_usd_hi_t)usd_hi), ((e2k_usd_lo_t)usd_lo));
	RAW_WRITE_PSP_REG((e2k_psp_hi_t) psp_hi, (e2k_psp_lo_t) psp_lo);
	RAW_WRITE_PCSP_REG((e2k_pcsp_hi_t) pcsp_hi, (e2k_pcsp_lo_t) pcsp_lo);

	E2K_SET_DSREG_NV_NOIRQ(cr1.lo, cr_wd);
	E2K_SET_DSREG_NV_NOIRQ(cr1.hi, cr_ussz);
	if (unlikely(restore_ip)) {
		E2K_SET_DSREG_NV_NOIRQ(cr0.lo, AS_WORD(sw_regs->cr0_lo));
		E2K_SET_DSREG_NV_NOIRQ(cr0.hi, AS_WORD(sw_regs->cr0_hi));
	}
 
	E2K_SET_SREG_NV(fpcr,  fpcr);
	E2K_SET_SREG_NV(fpsr,  fpsr);
	E2K_SET_SREG_NV(pfpfr, pfpfr);
	E2K_SET_DSREG_NV_NOIRQ(cutd, cutd);
 
	if (mm)
                LOAD_GLOBAL_REGISTERS(task);

	if (unlikely(task->ptrace & PT_PTRACED))
		RESTORE_USER_ONLY_REGS(sw_regs);
	else	/* Do this always when we don't test prev_task->ptrace */
		CLEAR_USER_ONLY_REGS();

        CLEAR_DAM;

	if (unlikely(task_is_binco)) {
		flushts();
		RESTORE_INTEL_REGS(sw_regs);
#ifdef CONFIG_TC_STORAGE
		E2K_SET_TCD(sw_regs->tcd);
#endif
	}
}

extern inline void
STORE_TASK_REGS_TO_PT_REGS(struct pt_regs *regs, struct task_struct *task)
{
        regs->stacks.sbr = (task->thread.sw_regs.sbr);
        regs->stacks.usd_hi = task->thread.sw_regs.usd_hi;
        regs->stacks.usd_lo = task->thread.sw_regs.usd_lo;
        regs->stacks.psp_hi = task->thread.sw_regs.psp_hi;
        regs->stacks.psp_lo = task->thread.sw_regs.psp_lo;
        regs->stacks.pcsp_hi= task->thread.sw_regs.pcsp_hi;
        regs->stacks.pcsp_lo= task->thread.sw_regs.pcsp_lo;
        regs->crs.cr1_lo = task->thread.sw_regs.cr_wd;
        regs->crs.cr1_hi = task->thread.sw_regs.cr_ussz;
        regs->crs.cr0_lo = task->thread.sw_regs.cr0_lo;
        regs->crs.cr0_hi = task->thread.sw_regs.cr0_hi;
}


extern inline void 
SWITCH_TO_KERNEL_STACK(e2k_addr_t ps_base, e2k_size_t ps_size,
	e2k_addr_t pcs_base, e2k_size_t pcs_size,
	e2k_addr_t ds_base, e2k_size_t ds_size)
{
	register volatile e2k_rwap_lo_struct_t	reg_lo;
	register volatile e2k_rwap_hi_struct_t	reg_hi;
	register volatile e2k_rwap_lo_struct_t	stack_reg_lo;
	register volatile e2k_rwap_hi_struct_t	stack_reg_hi;
	register volatile usbr_struct_t		usbr;

	/*
	 * Set Procedure Stack and Procedure Chain stack registers
	 * to the begining of initial PS and PCS stacks
	 */
	E2K_FLUSHCPU;
	reg_lo.PSP_lo_half = 0;
	reg_lo.PSP_lo_base = ps_base;
	reg_lo._PSP_lo_rw = E2K_PSP_RW_PROTECTIONS;
	reg_hi.PSP_hi_half = 0;
	reg_hi.PSP_hi_size = ps_size;
	reg_hi.PSP_hi_ind = 0;
	RAW_WRITE_PSP_REG(reg_hi, reg_lo);
	reg_lo.PCSP_lo_half = 0;
	reg_lo.PCSP_lo_base = pcs_base;
	reg_lo._PCSP_lo_rw = E2K_PCSR_RW_PROTECTIONS;
	reg_hi.PCSP_hi_half = 0;
	reg_hi.PCSP_hi_size = pcs_size;
	reg_hi.PCSP_hi_ind = 0;
	RAW_WRITE_PCSP_REG(reg_hi, reg_lo);


	/*
	 * Set stack pointers to the begining of kernel initial data stack
	 */

	usbr.USBR_base = ds_base + ds_size;
	WRITE_USBR_REG(usbr);

	stack_reg_lo.USD_lo_half = 0;
	stack_reg_lo.USD_lo_p = 0;
	stack_reg_lo.USD_lo_base = ds_base + ds_size;

	stack_reg_hi.USD_hi_half = 0;
	stack_reg_hi.USD_hi_size = ds_size;

	WRITE_USD_REG(stack_reg_hi, stack_reg_lo);

//	E2K_WAIT(_all_e);
}

//#undef BKP_GREG
//#undef RTR_GREG


#endif /* _E2K_REGS_STATE_H */

