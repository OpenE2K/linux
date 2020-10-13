/* linux/arch/e2k/kernel/ttable.c, v 1.1 05/28/2001.
 * 
 * Copyright (C) 2001 MCST
 */

//
// Simple E2K trap table implementation written in 'C'.
//
// It uses GCC-for-E2K proprietary __interrupt__ attribuite extension.
// Traps are handling on a private TRAP_GCC_STACK C-stack.
// Since pointers are yet not supported arguments for __interrupt__(),
// TRAP_GCC_STACK was preset to the virtual address of 0x4002000 (64M + 8K).
// This means that it uses ttable_entry1's "back" for the stack purpose.
// This is a kind of ugly software design. It is scheduled to be fixed as
// soon as  __interrupt__() will support the pointer argument.
//
// Updated 30/5/2001: pointer argument for __interrupt__ is now supported too.

/**************************** DEBUG DEFINES *****************************/

#define	DEBUG_TRAP	0	/* Trap trace */
#define	DbgTrap			if (DEBUG_TRAP) printk

#undef	DEBUG_SYSCALL
#define	DEBUG_SYSCALL	0	/* System Calls trace */
#if DEBUG_SYSCALL
# define DbgSC printk
#else
# define DbgSC(...)
#endif

#undef	DEBUG_SYSCALLP
#define	DEBUG_SYSCALLP	0	/*Protected  System Calls trace */
#if DEBUG_SYSCALLP
# define DbgSCP printk
#else
# define DbgSCP(...)
#endif

#define	DEBUG_PtR_MODE	0	/* Print pt_regs */
#define	DebugPtR(str, pt_regs)	if (DEBUG_PtR_MODE) print_pt_regs(str, pt_regs)

#undef	DEBUG_SLJ_MODE
#undef	DebugSLJ
#define	DEBUG_SLJ_MODE		0	/* Signal long jump handling */
#define DebugSLJ(...)		DebugPrint(DEBUG_SLJ_MODE ,##__VA_ARGS__)

#undef	DEBUG_HS_MODE
#undef	DebugHS
#define	DEBUG_HS_MODE		0	/* Hardware stacks */
#define DebugHS(...)		DebugPrint(DEBUG_HS_MODE ,##__VA_ARGS__)

//#define DEBUG_BOOT_INFO		1	/* Print bootblock */

//#define DEBUG_PT_REGS_ADDR	/* calculate pt_regs struct address */
				/* and check with address in list of */
				/* pt_regs structeres from thread_info */

/**************************** END of DEBUG DEFINES ***********************/

#include <linux/context_tracking.h>
#include <linux/getcpu.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <linux/sys.h>		/* NR_syscalls */
#include <linux/linkage.h>
#include <linux/errno.h>
#include <linux/syscalls.h>
#include <linux/interrupt.h>
#include <linux/signal.h>
#include <linux/times.h>
#include <linux/time.h>
#include <linux/tracehook.h>
#include <linux/utsname.h>
#include <linux/sysctl.h>
#include <linux/uio.h>
#ifdef CONFIG_FTRACE_DISABLE_ON_HIGH_LOAD
# include <linux/ftrace.h>
#endif

#ifdef CONFIG_MAC_
#include <linux/mac/mac_kernel.h>
#endif

#ifdef	CONFIG_RECOVERY
#include <asm/cnt_point.h>
#endif	/* CONFIG_RECOVERY */

#include <asm/e2k_api.h>
#include <asm/sections.h>
#include <asm/head.h>
#include <asm/boot_init.h>
#include <asm/boot_recovery.h>
#include <asm/boot_param.h>
#include <asm/traps.h>
#include <asm/process.h>
#include <asm/sigcontext.h>
#include <asm/hardirq.h>
#include <asm/bootinfo.h>
#include <asm/switch_to.h>
#include <asm/system.h>
#include <asm/console.h>
#include <asm/delay.h>
#include <asm/sge.h>
#include <asm/statfs.h>
#include <asm/poll.h>
#include <asm/regs_state.h>
#include <asm/e3m.h>
#include <asm/lms.h>
#include <asm/e3m_iohub.h>
#include <asm/e3m_iohub_lms.h>
#include <asm/e3s.h>
#include <asm/e3s_lms.h>
#include <asm/es2.h>
#include <asm/es2_lms.h>
#include <asm/e2s.h>
#include <asm/e2s_lms.h>
#include <asm/e8c.h>
#include <asm/e8c_lms.h>
#include <asm/e1cp.h>
#include <asm/e1cp_lms.h>
#include <asm/e8c2.h>
#include <asm/e8c2_lms.h>
#include <asm/e2k_sic.h>
#if defined(CONFIG_KERNEL_TIMES_ACCOUNT) || defined(CONFIG_PROFILING) || \
	defined(CONFIG_CLI_CHECK_TIME)
#include <asm/clock_info.h>
#endif
#include <asm/e2k_ptypes.h>
#include <asm/prot_loader.h>
#include <asm/syscalls.h>
#include <asm/ucontext.h>
#include <asm/umalloc.h>

#ifdef CONFIG_USE_AAU
#include <asm/aau_regs.h>
#include <asm/aau_context.h>
#endif

#ifdef CONFIG_PROTECTED_MODE
#include <asm/3p.h>
#endif /* CONFIG_PROTECTED_MODE */

#include <asm/regs_state.h>
#ifdef	CONFIG_COMPAT
#include<linux/compat.h>
#endif

#ifdef GENERATING_HEADER
# define CLEAR_USER_TRAP_HANDLER_WINDOW()	E2K_EMPTY_CMD(: "ctpr3")
# define CLEAR_TTABLE_ENTRY_10_WINDOW(r0) \
		E2K_EMPTY_CMD([_r0] "ir" (r0) : "ctpr3")
# define CLEAR_TTABLE_ENTRY_10_WINDOW_PROT(r0, r1, r2, r3, tag2, tag3) \
		E2K_EMPTY_CMD([_r0] "ir" (r0), [_r1] "ir" (r1), \
			      [_r2] "ir" (r2), [_r3] "ir" (r3), \
			      [_tag2] "ir" (tag2), [_tag3] "ir" (tag3) \
			      : "ctpr3")
# define CLEAR_HARD_SYS_CALLS_WINDOW(r0) \
		E2K_EMPTY_CMD([_r0] "ir" (r0) : "ctpr3")
# define CLEAR_SIMPLE_SYS_CALLS_WINDOW(r0) \
		E2K_EMPTY_CMD([_r0] "ir" (r0) : "ctpr3")
# define USER_TRAP_HANDLER_SIZE 0x8
# define TTABLE_ENTRY_10_SIZE 0x8
# define HARD_SYS_CALLS_SIZE 0x8
# define SIMPLE_SYS_CALLS_SIZE 0x8
#else
# include "ttable_asm.h"
# include"ttable_wbs.h"
#endif

#ifdef	CONFIG_CHECK_KERNEL_USD_SIZE
#define	CHECK_KERNEL_USD_SIZE(ti)					\
({									\
	if ((ti)->flags & _TIF_BAD_USD_SIZE)				\
		panic("CHECK_KERNEL_USD_SIZE() : bad kernel USD size\n"); \
})
#else	/* ! CONFIG_CHECK_KERNEL_USD_SIZE */
#define	CHECK_KERNEL_USD_SIZE(ti)
#endif	/* CONFIG_CHECK_KERNEL_USD_SIZE */

/*
 * There are TIR_NUM(19) tir regs. Bits 64 - 56 is current tir nr
 * After each E2K_GET_DSREG(tir.lo) we will read next tir.
 * For more info see instruction set doc.
 * Read tir regs order is significant
 */
#define SAVE_TIRS(TIRs, TIRs_num)					\
({									\
	unsigned long nr_TIRs = -1, TIR_hi, TIR_lo;			\
	unsigned long all_interrupts = 0;				\
	do {								\
		TIR_hi = E2K_GET_DSREG(tir.hi);				\
	        TIR_lo = E2K_GET_DSREG(tir.lo);				\
		++nr_TIRs;						\
		TIRs[GET_NR_TIRS(TIR_hi)].TIR_lo.TIR_lo_reg = TIR_lo;	\
		TIRs[GET_NR_TIRS(TIR_hi)].TIR_hi.TIR_hi_reg = TIR_hi;	\
		all_interrupts |= TIR_hi;				\
	} while(GET_NR_TIRS(TIR_hi));					\
	TIRs_num = nr_TIRs;						\
									\
	/* un-freeze the TIR's LIFO */					\
	E2K_SET_DSREG(tir.lo,TIR_lo);					\
									\
	all_interrupts & exc_all_mask;					\
})

#define	is_kernel_thread(task)	((task)->mm == NULL || (task)->mm == &init_mm)

                                                    // only  for format 32    
extern	const system_call_func sys_call_table_32[]; // defined in systable.c
extern	const system_call_func sys_call_table_deprecated[];

#define	SAVE_SYSCALL_ARGS(regs, num, a1, a2, a3, a4, a5, a6)		\
({									\
	(regs)->sys_num = (num);					\
	(regs)->arg1 = (a1);						\
	(regs)->arg2 = (a2);						\
	(regs)->arg3 = (a3);						\
	(regs)->arg4 = (a4);						\
	(regs)->arg5 = (a5);						\
	(regs)->arg6 = (a6);						\
})
#define	RESTORE_SYSCALL_ARGS(regs, num, a1, a2, a3, a4, a5, a6)		\
({									\
	(num) = (regs)->sys_num;					\
	(a1) = (regs)->arg1;						\
	(a2) = (regs)->arg2;						\
	(a3) = (regs)->arg3;						\
	(a4) = (regs)->arg4;						\
	(a5) = (regs)->arg5;						\
	(a6) = (regs)->arg6;						\
})
#define	SAVE_SYSCALL_RVAL(regs, rval)					\
({									\
	(regs)->sys_rval = (rval);					\
})
#define	RESTORE_SYSCALL_RVAL(regs, rval)				\
({									\
	(rval) = (regs)->sys_rval;					\
})
#define	SAVE_PSYSCALL_RVAL(regs, rval, rval1, rval2)			\
({									\
	(regs)->sys_rval = (rval);					\
	(regs)->arg1 = (rval1);						\
	(regs)->arg2 = (rval2);						\
})
#define	RESTORE_PSYSCALL_RVAL(regs, rval, rval1, rval2)			\
({									\
	(rval) = (regs)->sys_rval;					\
})


/*
 * Maximum number of hardware interrupts:
 * 1) Interrupt on user - we must open interrupts to handle AAU;
 * 2) Page fault exception in kernel on access to user space;
 * 3) Maskable interrupt or we could have got a page fault exception
 * in execute_mmu_operations();
 * 4) Another maskable interrupt in kernel after preempt_schedule_irq()
 * opened interrupts;
 * 5) Non-maskable interrupt in kernel.
 *
 * Plus we can have MAX_HANDLED_SIGS of signals.
 */
#define	MAX_HW_INTR	(5 + MAX_HANDLED_SIGS)


#ifdef	CONFIG_DEBUG_PT_REGS
#define	DO_NEW_CHECK_PT_REGS_ADDR(prev_regs, regs, usd_lo_reg, usd_size,  \
						new_pt_regs, in_user)	  \
{									  \
									  \
	register struct pt_regs *new_regs;				  \
	register e2k_addr_t	delta_sp;				  \
	register e2k_usd_lo_t	usd_lo_cur;				  \
									  \
	usd_lo_cur = READ_USD_LO_REG();					  \
	delta_sp = usd_lo_cur.USD_lo_base - usd_lo_reg.USD_lo_base;	  \
	new_regs = (pt_regs_t *)(((e2k_addr_t) prev_regs) + delta_sp);	  \
	if (in_user == 1) {						  \
		RESTORE_KERNEL_STACKS_STATE(regs, thread_info, 0);	  \
	} else if (in_user == 2) {					  \
		DO_RESTORE_KERNEL_STACKS_STATE(usd_size, thread_info, 0); \
	}								  \
	if ((regs != new_regs && !(new_pt_regs)) ||			  \
		((new_pt_regs) &&					  \
			((e2k_addr_t)(regs) < (e2k_addr_t)new_regs ||	  \
			(e2k_addr_t)(regs) >=				  \
				thread_info->k_usd_lo.USD_lo_base))) {	  \
		printk("ttable_entry() calculated pt_regs "		  \
			"structure 0x%p is not the same as from "	  \
			"thread_info structure 0x%p\n",			  \
			new_regs, regs);				  \
		print_stack(current);					  \
	}								  \
}

/*
 * pt_regs structure is placed as local data of the
 * trap handler (or system call handler) function
 * into the kernel local data stack
 * Calculate placement of pt_regs structure, it should be
 * same as from thread_info structure
 */
#define	NEW_CHECK_PT_REGS_ADDR(prev_regs, regs, 			\
				usd_lo_reg, new_pt_regs, in_user)	\
	DO_NEW_CHECK_PT_REGS_ADDR(prev_regs, regs, usd_lo_reg, 0,	\
				new_pt_regs, in_user)

#define	NEW_CHECK_USER_PT_REGS_ADDR(prev_regs, regs,			\
				usd_lo_reg, usd_size)			\
	DO_NEW_CHECK_PT_REGS_ADDR(prev_regs, regs, usd_lo_reg,		\
				usd_size, 0, 2)

#else	/* ! CONFIG_DEBUG_PT_REGS */
#define	NEW_CHECK_PT_REGS_ADDR(prev_regs, regs, usd_lo_reg, new_pt_regs, in_user)
#define	NEW_CHECK_USER_PT_REGS_ADDR(prev_regs, regs, usd_lo_reg, usd_size)
#endif	/* CONFIG_DEBUG_PT_REGS */


/*
 * Hardware does not properly clean the register file
 * before returning to user so do the cleaning manually.
 */
extern void clear_rf_9();
extern void clear_rf_18();
extern void clear_rf_27();
extern void clear_rf_36();
extern void clear_rf_45();
extern void clear_rf_54();
extern void clear_rf_63();
extern void clear_rf_78();
extern void clear_rf_90();
extern void clear_rf_108();
const clear_rf_t clear_rf_fn[E2K_MAXSR] = {
	[0 ... 9] = clear_rf_9,
	[10 ... 18] = clear_rf_18,
	[19 ... 27] = clear_rf_27,
	[28 ... 36] = clear_rf_36,
	[37 ... 45] = clear_rf_45,
	[46 ... 54] = clear_rf_54,
	[55 ... 63] = clear_rf_63,
	[64 ... 78] = clear_rf_78,
	[79 ... 90] = clear_rf_90,
	[91 ... 108] = clear_rf_108
};

/*********************************************************************/
//all entries must be in its own section,align in arch/e2k/kernel/vmlinux.lds.S
#define __ttable_entry12__	__attribute__((__section__(".ttable_entry12")))
/***********************ttable_entry0*********************************/

#define printk printk_fixed_args
#define panic panic_fixed_args
__noreturn __interrupt notrace void kernel_data_stack_overflow(void)
{
	/* dump_puts() does not use stack so call it first */
	dump_puts("BUG: kernel data stack overflow\n");

	pr_alert("kernel_data_stack_overflow() USD base 0x%lx K_STK_BASE 0x%lx\n",
			READ_USD_LO_REG().USD_lo_base,
			current_thread_info()->k_stk_base);
#ifdef CONFIG_SERIAL_PRINTK
	/*
	 * We could be executing on the CPU that handles serial port
	 * interrupts, in which case normal printk() won't print from here.
	 */
	use_boot_printk_all = 1;
#endif
	panic("kernel_data_stack_overflow() USD base 0x%lx K_STK_BASE 0x%lx\n",
			READ_USD_LO_REG().USD_lo_base,
			current_thread_info()->k_stk_base);
}
#undef printk
#undef panic

static __noreturn noinline notrace void kernel_stack_overflow()
{
	e2k_usd_lo_t usd_lo = READ_USD_LO_REG();
	e2k_psp_hi_t psp_hi = READ_PSP_HI_REG();
	e2k_pcsp_hi_t pcsp_hi = READ_PCSP_HI_REG();

	pr_alert("kernel_stack_overflow: USD base 0x%lx K_STK_BASE 0x%lx, PSP size %x, ind %x, PCSP size %x, ind %x\n",
			AS(usd_lo).base, current_thread_info()->k_stk_base,
			AS(psp_hi).size, AS(psp_hi).ind,
			AS(pcsp_hi).size, AS(pcsp_hi).ind);

#ifdef CONFIG_SERIAL_PRINTK
	/*
	 * We could be executing on the CPU that handles serial port
	 * interrupts, in which case normal printk() won't print from here.
	 */
	use_boot_printk_all = 1;
#endif

	panic("kernel_stack_overflow: USD base 0x%lx K_STK_BASE 0x%lx, PSP size %x, ind %x, PCSP size %x, ind %x\n",
			AS(usd_lo).base, current_thread_info()->k_stk_base,
			AS(psp_hi).size, AS(psp_hi).ind,
			AS(pcsp_hi).size, AS(pcsp_hi).ind);
}

static void noinline notrace traps_overflow(void)
{
	int traps = current->thread.intr_counter;

	current->thread.intr_counter = 0;
	pr_alert("Too much nested traps: %d\n", traps);
	dump_stack();
}

/*
 * Trap table entry #0 is for hardware interrupts and exceptions.
 * 4K alignment is guaranteed by the linker's script.
 */

extern asmlinkage void ttable_entry0(void);

#ifdef CONFIG_USE_AAU
__section(.entry_handlers)
void notrace _get_aau_context(e2k_aau_t *context)
{
	get_aau_context(context);
}
#endif

/*
 * Do work marked by TIF_NOTIFY_RESUME
 */
void do_notify_resume(struct pt_regs *regs)
{
#ifdef ARCH_RT_DELAYS_SIGNAL_SEND
	if (unlikely(current->forced_info.si_signo)) {
		struct task_struct *t = current;
		force_sig_info(t->forced_info.si_signo, &t->forced_info, t);
		t->forced_info.si_signo = 0;
	}
#endif

	tracehook_notify_resume(regs);
}


static inline struct trap_pt_regs *pt_regs_to_trap_regs(struct pt_regs *regs)
{
	return PTR_ALIGN((void *) regs + sizeof(*regs), 8);
}

#ifdef CONFIG_USE_AAU
static inline e2k_aau_t *pt_regs_to_aau_regs(struct pt_regs *regs)
{
	struct trap_pt_regs *trap;

	trap = pt_regs_to_trap_regs(regs);

	return PTR_ALIGN((void *) trap + sizeof(*trap), 8);
}
#endif


/*
 * Trap occured on user or kernel function but on user's stacks
 * So, it needs to switch to kernel stacks
 */
#define printk printk_fixed_args
#define panic panic_fixed_args
__section(.entry_handlers)
void __interrupt notrace
user_trap_handler(struct pt_regs *regs, thread_info_t *thread_info)
{
	struct trap_pt_regs	*trap;
#if defined(CONFIG_KERNEL_TIMES_ACCOUNT) || defined(CONFIG_PROFILING)
	register e2k_clock_t	clock = E2K_GET_DSREG(clkr);
        register e2k_clock_t    clock1;
        register e2k_clock_t    start_tick;
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */
#ifdef CONFIG_DEBUG_PT_REGS
	e2k_usd_lo_t		usd_lo_prev;
	struct pt_regs		*prev_regs = regs;
#endif
        struct task_struct      *task = current;
#ifdef CONFIG_USE_AAU
	e2k_aau_t		*aau_regs;
	e2k_aasr_t		aasr;
#endif /* CONFIG_USE_AAU */
#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	register trap_times_t	*trap_times;
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */
	e2k_pshtp_t pshtp;
	u64 num_q, exceptions;

	trap = pt_regs_to_trap_regs(regs);
	regs->trap = trap;

#ifdef CONFIG_CLI_CHECK_TIME
	start_tick = E2K_GET_DSREG(clkr);
#endif

#ifdef CONFIG_USE_AAU
	aau_regs = pt_regs_to_aau_regs(regs);
	regs->aau_context = aau_regs;

	/*
	 * We are not using ctpr2 here (compiling with -fexclude-ctpr2)
	 * thus reading of AASR, AALDV, AALDM can be done at any
	 * point before the first call.
	 *
	 * Usage of ctpr2 here is not possible since AALDA and AALDI
	 * registers would be zeroed.
	 */
	AW(aasr) = E2K_GET_AAU_AASR();
#endif /* CONFIG_USE_AAU */

#ifdef CONFIG_DEBUG_PT_REGS
	usd_lo_prev = READ_USD_LO_REG();
#endif

	/*
	 * All actual pt_regs structures of the process are queued.
	 * The head of this queue is thread_info->pt_regs pointer,
	 * it points to the last (current) pt_regs structure.
	 * The current pt_regs structure points to the previous etc
	 * Queue is empty before first trap or system call on the
	 * any process and : thread_info->pt_regs == NULL
	 */
	regs->next = thread_info->pt_regs;
	thread_info->pt_regs = regs;
#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	trap_times = &(thread_info->times[thread_info->times_index].of.trap);
	thread_info->times[thread_info->times_index].type = TRAP_TT;
	INCR_KERNEL_TIMES_COUNT(thread_info);
	trap_times->start = clock;
	trap_times->ctpr1 = E2K_GET_DSREG_NV(cr1.lo);
	trap_times->ctpr2 = E2K_GET_DSREG_NV(cr0.hi);
	trap_times->pshtp = READ_PSHTP_REG();
	trap_times->psp_ind = READ_PSP_HI_REG().PSP_hi_ind;
	E2K_SAVE_CLOCK_REG(trap_times->pt_regs_set);
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */

	/*
	 * Now we can store all needed trap context into the
	 * current pt_regs structure
	 */

        read_ticks(clock1);
	exceptions = SAVE_TIRS(trap->TIRs, trap->nr_TIRs);
        info_save_tir_reg(clock1);

#ifdef CONFIG_USE_AAU
        /*
	 * Put some distance between reading AASR (above) and using it here
	 * since reading of AAU registers is slow.
	 *
	 * This is placed before saving trap cellar since it is done using
	 * 'mmurr' instruction which requires AAU to be stopped.
	 */
	SAVE_AAU_MASK_REGS(aau_regs, aasr);
#endif

	SAVE_TRAP_CELLAR(regs, trap);

        read_ticks(clock1);
	/*
	 * Here (in SAVE_STACK_REGS) hardware bug #29263 is being worked
	 * around with 'flushc' instruction, so NO function calls must
	 * happen and IRQs must not be enabled (even NMIs) until now.
	 */
	SAVE_STACK_REGS(regs, thread_info, true, true);
	if (unlikely(AS(regs->stacks.pcsp_hi).ind >= USER_PC_STACK_INIT_SIZE))
		AW(trap->TIRs[0].hi) |= exc_chain_stack_bounds_mask;
	if (unlikely(AS(regs->stacks.psp_hi).ind >= USER_P_STACK_INIT_SIZE))
		AW(trap->TIRs[0].hi) |= exc_proc_stack_bounds_mask;
        info_save_stack_reg(clock1);

#ifdef CONFIG_USE_AAU
	/* It's important to save AAD before all call operations. */
	if (unlikely(AS(aasr).iab))
		SAVE_AADS(aau_regs);

	/*
	 * If AAU fault happened read aalda/aaldi/aafstr here,
	 * before some call zeroes them.
	 */
	if (unlikely(AS(trap->TIRs[0].hi).aa)) {
		SAVE_AALDA(aau_regs->aalda);
		aau_regs->aafstr = E2K_GET_AAUREG(aafstr, 5);
	}

	/*
	 * Function calls are allowed from this point on,
	 * mark it with a compiler barrier.
	 */
	barrier();

        info_save_mmu_reg(clock1);
#endif

#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	regs->mlt_state.num = 0;

	if (likely(!TASK_IS_BINCO(task))) {
		regs->rp_ret = 0;
	} else {
		u64     rpr_lo = E2K_GET_DSREG(rpr.lo);
		u64     cr0_hi = AS_WORD(regs->crs.cr0_hi);
		long    mlt_not_empty = MLT_NOT_EMPTY();

		if (rpr_lo && (machine.iset_ver >= E2K_ISET_V3 || mlt_not_empty)
				&& cr0_hi >= thread_info->rp_start
				&& cr0_hi < thread_info->rp_end)
			regs->rp_ret = 1;
		else
			regs->rp_ret = 0;

		if (mlt_not_empty)
			get_and_invalidate_MLT_context(&regs->mlt_state);
	}
#endif

	/*
	 * Trap occured on user's stacks
	 * So switch to kernel's stacks.
	 */
	SAVE_KERNEL_STACKS_STATE(regs, thread_info);

	/*
	 * We will switch interrupts control from PSR to UPSR
	 * _after_ we have handled all non-masksable exceptions.
	 * This is needed to ensure that a local_irq_save() call
	 * in NMI handler won't enable non-maskable exceptions.
	 */
	DO_SAVE_UPSR_REG(thread_info->upsr);

	BUILD_BUG_ON(sizeof(enum ctx_state) != sizeof(trap->prev_state));
	trap->prev_state = exception_enter();

	INIT_KERNEL_UPSR_REG(false, true);

	CHECK_TI_K_USD_SIZE(thread_info);
	CHECK_KERNEL_USD_SIZE(thread_info);
	CHECK_PT_REGS_LOOP(thread_info->pt_regs);

	task->thread.intr_counter++;
#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	trap_times->intr_counter = task->thread.intr_counter;
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */

#ifdef CONFIG_USE_AAU
	if (aau_working(aau_regs))
		_get_aau_context(aau_regs);
#endif
#ifdef CONFIG_CLI_CHECK_TIME
	tt0_prolog_ticks(E2K_GET_DSREG(clkr) - start_tick);
#endif

	/*
	 * This will enable interrupts
	 */
	parse_TIR_registers(regs, exceptions);

#ifdef CONFIG_USE_AAU
	if (unlikely(AAU_STOPPED(aau_regs->aasr)))
		/*
		 * We interpret the asynchronous program here, and to do that,
		 * we read user code. So interrupts MUST be enabled here.
		 */
		calculate_aau_aaldis_aaldas(regs, aau_regs);
#endif /* CONFIG_USE_AAU */

	/*
	 * Return control from UPSR register to PSR, if UPSR interrupts
	 * control is used. DONE operation restores PSR state at trap
	 * point and recovers interrupts control.
	 *
	 * This also disables all interrupts including NMIs
	 * and serves as a compiler barrier.
	 */
	RETURN_IRQ_TO_PSR();

	/*
	 * Check under closed interrupts to avoid races
	 */
	while (unlikely(!test_delayed_signal_handling(task, thread_info) &&
			(thread_info->flags & _TIF_SIGPENDING) ||
			(thread_info->flags & _TIF_WORK_MASK_NOSIG))) {
		/* Make sure compiler does not reuse previous checks */
		barrier();

		SWITCH_IRQ_TO_UPSR(false);

		/*
		 * An interrupt can arrive while the signal handler which is
		 * not using AAU is running. If AAU was not cleared, then at
		 * a trap exit of that interrupt AAU will start working - but
		 * it must not work since signal handler is not using it. So
		 * clear it explicitly here. And the same logic applies to
		 * rescheduling.
		 */
		E2K_CLEAR_APB();

		/* here we do signal handling */
		BUG_ON(is_kernel_thread(task));
		if (!test_delayed_signal_handling(task, thread_info) &&
				signal_pending(task)) {
			do_signal(regs);

			/*
			 * We can be here on the new stack and new process,
			 * if signal handler made fork()
			 * So we should reset all pointers
			 */
			thread_info = current_thread_info();
			task = current;
			regs = thread_info->pt_regs;
			trap = regs->trap;
#ifdef CONFIG_USE_AAU
			aau_regs = pt_regs_to_aau_regs(regs);
#endif
			CHECK_TI_K_USD_SIZE(thread_info);
#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
			{
				register int count;
				GET_DECR_KERNEL_TIMES_COUNT(thread_info, count);
				trap_times =
					&(thread_info->times[count].of.trap);
				trap_times->signal_done = clock;
			}
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */

			NEW_CHECK_PT_REGS_ADDR(prev_regs, regs,
					       usd_lo_prev, 0, 1);
		}

		/* and here we do tasks re-scheduling on a h/w interrupt */
		if (need_resched())
			schedule();

		if (test_thread_flag(TIF_NOTIFY_RESUME)) {
			clear_thread_flag(TIF_NOTIFY_RESUME);
			do_notify_resume(regs);
		}

#ifdef CONFIG_USE_AAU
		/*
		 * Signal handler could have changed pt_regs,
		 * so recalculate aau registers with new pt_regs.
		 */
		if (unlikely(AAU_STOPPED(aau_regs->aasr)))
			calculate_aau_aaldis_aaldas(regs, aau_regs);
#endif /* CONFIG_USE_AAU */

		RETURN_IRQ_TO_PSR();
	}

	exception_exit(trap->prev_state);

	pshtp = (e2k_pshtp_t) E2K_GET_DSREG_NV(pshtp);
	num_q = E2K_MAXSR - (USER_TRAP_HANDLER_SIZE +
			GET_PSHTP_INDEX(pshtp) / EXT_4_NR_SZ);

	DO_RESTORE_UPSR_REG(thread_info->upsr);

        read_ticks(start_tick);

#if !defined CONFIG_E2K_MACHINE || defined CONFIG_E2K_ES2_DSP || \
		defined CONFIG_E2K_ES2_RU
	/* Hardware bug 71610 workaround */
	if (cpu_has(CPU_HWBUG_ATOMIC) &&
	    unlikely(AS(regs->ctpr1).ta_base == 0xfffffffffff8ULL)) {
		unsigned long long g23;
		int g23_tag;

		E2K_GET_DGREG_VAL_AND_TAG(23, g23, g23_tag);
		if ((current->thread.flags & E2K_FLAG_32BIT)
				&& !TASK_IS_BINCO(current)) {
			g23 &= 0xffffffffULL;
			g23_tag &= 0x3;
		}
		if (g23_tag == ETAGNVD && access_ok(ACCESS_WRITE, g23, 1))
			flush_DCACHE_line(g23);
	}
#endif

	/*
	 * Clear all other kernel windows, so no function
	 * calls can be made after this.
	 */
	clear_rf_kernel_except_current(num_q);

#ifdef CONFIG_USE_AAU
	E2K_CLEAR_APB();
	if (aau_working(aau_regs)) {
		set_aau_context(aau_regs);

		/*
		 * It's important to restore AAD after
		 * all return operations.
		 */
		if (AS(aau_regs->aasr).iab)
			RESTORE_AADS(aau_regs);
	}
#endif /* CONFIG_USE_AAU */
	info_restore_mmu_reg(start_tick);

	/*
	 * Dequeue current pt_regs structure and previous
	 * regs will be now actuale
	 */
	thread_info->pt_regs = regs->next;
	regs->next = NULL;
	CHECK_PT_REGS_LOOP(thread_info->pt_regs);
	CHECK_TI_K_USD_SIZE(thread_info);

	task->thread.intr_counter--;

        read_ticks(clock);

#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	if (unlikely(regs->rp_ret)) {
		u64 cr0_hi = AS_WORD(regs->crs.cr0_hi);

		WARN_ON(cr0_hi < thread_info->rp_start ||
			cr0_hi >= thread_info->rp_end);
		AS_WORD(regs->crs.cr0_hi) = thread_info->rp_ret_ip;
	}
#endif	/* CONFIG_SECONDARY_SPACE_SUPPORT */

	RESTORE_KERNEL_STACKS_STATE(regs, thread_info, 0);
	RESTORE_USER_STACK_REGS(regs, 0, 0);
	if (task->thread.flags & E2K_FLAG_PROTECTED_MODE)
		ENABLE_US_CLW();

        info_restore_stack_reg(clock);

#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	trap_times->psp_hi_to_done = READ_PSP_HI_REG();
	trap_times->pcsp_hi_to_done = READ_PCSP_HI_REG();
	trap_times->pshtp_to_done = READ_PSHTP_REG();
	trap_times->ctpr1_to_done = AS_WORD(regs->ctpr1);
	trap_times->ctpr2_to_done = AS_WORD(regs->ctpr2);
	trap_times->ctpr3_to_done = AS_WORD(regs->ctpr3);
	E2K_SAVE_CLOCK_REG(trap_times->end);
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */

#ifdef CONFIG_USE_AAU
	/*
	 * There must not be any branches after restoring ctpr register
	 * because of HW bug, so this 'if' is done before restoring %ctpr2
	 * (actually it belongs to set_aau_aaldis_aaldas()).
	 */
	if (likely(!AAU_STOPPED(aau_regs->aasr))) {
#endif
		/*
		 * RESTORE_COMMON_REGS() must be called before
		 * RESTORE_AAU_MASK_REGS() because of ctpr2 and
		 * AAU registers restoring dependencies
		 */
		RESTORE_COMMON_REGS(regs);
#ifdef CONFIG_USE_AAU
		RESTORE_AAU_MASK_REGS(aau_regs);
#endif
		/*
		 * g16/g17 must be restored last as they
		 * hold pointers to current
		 */
		E2K_RESTORE_GREG_IN_TRAP(thread_info->gbase, thread_info->gext,
				16, 17, 18, 19);
#ifdef CONFIG_E2S_CPU_RF_BUG
		E2K_LOAD_TAGGED_DGREGS(&regs->e2s_gbase[0], 16, 17);
		E2K_LOAD_TAGGED_DGREGS(&regs->e2s_gbase[2], 18, 19);
		E2K_LOAD_TAGGED_DGREGS(&regs->e2s_gbase[4], 20, 21);
		E2K_LOAD_TAGGED_DGREGS(&regs->e2s_gbase[6], 22, 23);
#endif
		CLEAR_USER_TRAP_HANDLER_WINDOW();
#ifdef CONFIG_USE_AAU
	} else {
		/*
		 * RESTORE_COMMON_REGS() must be called before
		 * RESTORE_AAU_MASK_REGS() and set_aau_aaldis_aaldas()
		 * because of ctpr2 and AAU registers restoring dependencies
		 */
		RESTORE_COMMON_REGS(regs);
		set_aau_aaldis_aaldas(aau_regs);
		RESTORE_AAU_MASK_REGS(aau_regs);
		/*
		 * g16/g17 must be restored last as they
		 * hold pointers to current */
		E2K_RESTORE_GREG_IN_TRAP(thread_info->gbase, thread_info->gext,
				16, 17, 18, 19);
# ifdef CONFIG_E2S_CPU_RF_BUG
		E2K_LOAD_TAGGED_DGREGS(&regs->e2s_gbase[0], 16, 17);
		E2K_LOAD_TAGGED_DGREGS(&regs->e2s_gbase[2], 18, 19);
		E2K_LOAD_TAGGED_DGREGS(&regs->e2s_gbase[4], 20, 21);
		E2K_LOAD_TAGGED_DGREGS(&regs->e2s_gbase[6], 22, 23);
# endif
		CLEAR_USER_TRAP_HANDLER_WINDOW();
	}
#endif
}
#undef panic
#undef printk

/*
 * Trap occured on kernel function and on kernel's stacks
 * So it does not need to switch to kernel stacks
 */
__section(.entry_handlers)
void notrace
kernel_trap_handler(struct pt_regs *regs, thread_info_t *thread_info)
{
	struct trap_pt_regs *trap;
	e2k_usd_lo_t usd_lo = regs->stacks.usd_lo;
	e2k_psp_hi_t psp_hi;
	e2k_pcsp_hi_t pcsp_hi;
#if defined(CONFIG_KERNEL_TIMES_ACCOUNT) || defined(CONFIG_PROFILING)
	register e2k_clock_t	clock = E2K_GET_DSREG(clkr);
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */
#ifdef CONFIG_DEBUG_PT_REGS  
	e2k_usd_lo_t		usd_lo_prev;
	struct pt_regs		*prev_regs = regs;
#endif
	unsigned long		ret_ip;
#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	register trap_times_t	*trap_times;
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */
        struct task_struct      *task = current;
	e2k_upsr_t		upsr;
	u64 exceptions, nmi;
#ifdef CONFIG_CLI_CHECK_TIME
	register long		start_tick;

	start_tick = E2K_GET_DSREG(clkr);
#endif

	trap = pt_regs_to_trap_regs(regs);
	regs->trap = trap;

#ifdef CONFIG_DEBUG_PT_REGS
	usd_lo_prev = READ_USD_LO_REG();
#endif

#ifdef CONFIG_USE_AAU
	regs->aau_context = NULL;
#endif

	/*
	 * All actual pt_regs structures of the process are queued.
	 * The head of this queue is thread_info->pt_regs pointer,
	 * it points to the last (current) pt_regs structure.
	 * The current pt_regs structure points to the previous etc
	 * Queue is empty before first trap or system call on the
	 * any process and : thread_info->pt_regs == NULL
	 */
	regs->next = thread_info->pt_regs;
	thread_info->pt_regs = regs;
#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	trap_times = &(thread_info->times[thread_info->times_index].of.trap);
	thread_info->times[thread_info->times_index].type = TRAP_TT;
	INCR_KERNEL_TIMES_COUNT(thread_info);
	trap_times->start = clock;
	trap_times->ctpr1 = E2K_GET_DSREG_NV(cr1.lo);
	trap_times->ctpr2 = E2K_GET_DSREG_NV(cr0.hi);
	trap_times->pshtp = READ_PSHTP_REG();
	trap_times->psp_ind = READ_PSP_HI_REG().PSP_hi_ind;
	E2K_SAVE_CLOCK_REG(trap_times->pt_regs_set);
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */

#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	regs->rp_ret = 0;
#endif

	/*
	 * Now we can store all needed trap context into the
	 * current pt_regs structure
	 */
        read_ticks(clock);
	exceptions = SAVE_TIRS(trap->TIRs, trap->nr_TIRs);
	nmi = exceptions & non_maskable_exc_mask;
        info_save_tir_reg(clock);

	SAVE_TRAP_CELLAR(regs, trap);
        read_ticks(clock);
	SAVE_STACK_REGS(regs, thread_info, false, true);
        info_save_stack_reg(clock);
	ret_ip = AS_STRUCT(regs->crs.cr0_hi).ip;

	psp_hi = regs->stacks.psp_hi;
	pcsp_hi = regs->stacks.pcsp_hi;

	/*
	 * We will switch interrupts control from PSR to UPSR
	 * _after_ we have handled all non-masksable exceptions.
	 * This is needed to ensure that a local_irq_save() call
	 * in NMI handler won't enable non-maskable exceptions.
	 */
	DO_SAVE_UPSR_REG(upsr);
	INIT_KERNEL_UPSR_REG(false, true);

	CHECK_TI_K_USD_SIZE(thread_info);
	CHECK_KERNEL_USD_SIZE(thread_info);
	CHECK_PT_REGS_LOOP(thread_info->pt_regs);

	task->thread.intr_counter++;
#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	trap_times->intr_counter = task->thread.intr_counter;
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */

	if (unlikely(task->thread.intr_counter > MAX_HW_INTR))
		traps_overflow();
	if (unlikely(AS(usd_lo).base - 3*PAGE_SIZE < thread_info->k_stk_base ||
		     AS(psp_hi).size - AS(psp_hi).ind < 3 * PAGE_SIZE ||
		     AS(pcsp_hi).size - AS(pcsp_hi).ind < PAGE_SIZE / 2))
		kernel_stack_overflow();

#ifdef CONFIG_CLI_CHECK_TIME
	tt0_prolog_ticks(E2K_GET_DSREG(clkr) - start_tick);
#endif

	/*
	 * This will enable non-maskable interrupts if (!nmi)
	 */
	parse_TIR_registers(regs, exceptions);

#ifdef CONFIG_FTRACE_DISABLE_ON_HIGH_LOAD
	if (!function_trace_stop) {
	        /* 
		 * to avoid problem with tracing 
		 *  tracing may very increase the time of execution 
		 */
		function_trace_stop = 1;

        	printk("ftracing was excluded for very big time of execution tick=%ld ip=%lx task->thread.intr_counter=%d\n",
			E2K_GET_DSREG(clkr),
			E2K_GET_DSREG_NV(cr0.hi), task->thread.intr_counter);
	}
#endif

#ifdef CONFIG_PREEMPT
	/*
	 * Check if we need preemption (the NEED_RESCHED flag could
	 * have been set by another CPU or by this interrupt handler).
	 *
	 * Don't do reschedule on NMIs - we do not want preempt_schedule_irq()
	 * to enable interrupts or local_irq_disable() to enable non-maskable
	 * interrupts. But there is one exception - if we received a maskable
	 * interrupt we must do a reschedule, otherwise we might lose it.
	 */
	if (unlikely(need_resched() && preempt_count() == 0) &&
			(!nmi || (exceptions & exc_interrupt_mask))) {
		local_irq_disable();
		/* Check again under closed interrupts to avoid races */
		if (likely(need_resched()))
			preempt_schedule_irq();
	}
#endif

	/*
	 * Return control from UPSR register to PSR, if UPSR interrupts
	 * control is used. DONE operation restores PSR state at trap
	 * point and recovers interrupts control
	 *
	 * This also disables all interrupts including NMIs.
	 */
	RETURN_TO_KERNEL_UPSR(upsr);

	/*
	 * Dequeue current pt_regs structure and previous
	 * regs will be now actuale
	 */

	thread_info->pt_regs = regs->next;
	regs->next = NULL;
	CHECK_PT_REGS_LOOP(thread_info->pt_regs);
	CHECK_TI_K_USD_SIZE(thread_info);

	task->thread.intr_counter--;

#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	trap_times->psp_hi_to_done = READ_PSP_HI_REG();
	trap_times->pshtp_to_done = READ_PSHTP_REG();
	trap_times->pcsp_hi_to_done = READ_PCSP_HI_REG();
	trap_times->ctpr1_to_done = AS_WORD(regs->ctpr1);
	trap_times->ctpr2_to_done = AS_WORD(regs->ctpr2);
	trap_times->ctpr3_to_done = AS_WORD(regs->ctpr3);
	E2K_SAVE_CLOCK_REG(trap_times->end);
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */

	if (unlikely(ret_ip != AS_STRUCT(regs->crs.cr0_hi).ip))
		E2K_SET_DSREG_NV_NOIRQ(cr0.hi, AS_WORD(regs->crs.cr0_hi));

	RESTORE_COMMON_REGS(regs);

#ifdef CONFIG_E2S_CPU_RF_BUG
	E2K_LOAD_TAGGED_DGREGS(&regs->e2s_gbase[0], 16, 17);
	E2K_LOAD_TAGGED_DGREGS(&regs->e2s_gbase[2], 18, 19);
	E2K_LOAD_TAGGED_DGREGS(&regs->e2s_gbase[4], 20, 21);
	E2K_LOAD_TAGGED_DGREGS(&regs->e2s_gbase[6], 22, 23);
#endif

	E2K_DONE;
}


static inline void init_pt_regs_for_syscall(struct pt_regs *regs)
{
	regs->trap = NULL;

#ifdef CONFIG_USE_AAU
	regs->aau_context = NULL;
#endif

	/* Binco guarantees, that MLT is empty */
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	regs->mlt_state.num = 0;
#endif
}

/***********************************************************************/

#ifdef CONFIG_PROTECTED_MODE
#include <linux/net.h>

#define printk printk_fixed_args
#define __trace_bprintk __trace_bprintk_fixed_args
#define panic panic_fixed_args

extern const system_call_func sys_protcall_table[]; /* defined in systable.c */

/*
 * lcc cannot handle structures in functions with __interrupt attribute
 * so put their handling outside.
 */

static inline
long make_ap_lo(e2k_addr_t base, long size, long offset, int access)
{
	return MAKE_AP_LO(base, size, offset, access);
}

static inline
long make_ap_hi(e2k_addr_t base, long size, long offset, int access)
{
	return MAKE_AP_HI(base, size, offset, access);
}

static inline
int e2k_ptr_itag(long low)
{
	e2k_ptr_t ptr;

	AW(ptr).lo = low;

	return AS(ptr).itag;
}

static inline
int e2k_ptr_rw(long low)
{
	e2k_ptr_t ptr;

	AW(ptr).lo = low;

	return AS(ptr).rw;
}

static inline
unsigned long e2k_ptr_ptr(long low, long hiw, unsigned int min_size)
{
	e2k_ptr_t ptr;
	unsigned int ptr_size;

	AW(ptr).lo = low;
	AW(ptr).hi = hiw;
	ptr_size = AS(ptr).size - AS(ptr).curptr;

	if (ptr_size < min_size) {
		DbgSCP("  Pointer is too small: %d < %d\n", ptr_size, min_size);
		return 0;
	} else {
		return E2K_PTR_PTR(ptr);
	}
}

static inline
unsigned long e2k_ptr_curptr(long low, long hiw)
{
	e2k_ptr_t ptr;

	AW(ptr).lo = low;
	AW(ptr).hi = hiw;

	return AS(ptr).curptr;
}

static inline
unsigned long e2k_ptr_base(long low, long hiw)
{
	e2k_ptr_t ptr;

	AW(ptr).lo = low;
	AW(ptr).hi = hiw;

	return E2K_PTR_BASE(ptr);
}

static inline
unsigned long e2k_ptr_size(long low, long hiw, unsigned int min_size)
{
	e2k_ptr_hi_t hi;
	unsigned int ptr_size;

	AW(hi) = hiw;
	ptr_size = AS(hi).size - AS(hi).curptr;

	if (ptr_size < min_size) {
		DbgSCP("  Pointer is too small: %d < %d\n", ptr_size, min_size);
		return 0;
	} else {
		return ptr_size;
	}
}

static inline
char *e2k_ptr_str(long low, long hiw)
{
	long slen;
	char *str;
	e2k_ptr_hi_t hi;

	AW(hi) = hiw;
	str = (char *) __E2K_PTR_PTR(low, hiw);
	slen = strlen_user(str);

	if (unlikely(slen == 0 ||
			((AS(hi).size - AS(hi).curptr) < slen)))
		return NULL;

	return str;
}


static int convert_array(long __user *prot_array, long *new_array,
		const int size, const int max_prot_len,
		const int new_len, long maska);

static long do_protected_syscall(const long sys_num, const long arg1,
		const long arg2, const long arg3, const long arg4,
		const long arg5, const long arg6, const long tags);

__section(.entry_handlers)
#ifndef CONFIG_E2S_CPU_RF_BUG
__interrupt
#endif
void notrace ttable_entry10_C(const long sys_num_and_psl,
		long arg1, long arg2, long arg3, long arg4,
		long arg5, long arg6, struct pt_regs *regs)
{
#define ARG_TAG(i)	((tags & (0xF << (4*(i)))) >> (4*(i)))
#define NOT_PTR(i)	((tags & (0xFF << (4*(i)))) >> (4*(i)) != ETAGAPQ)
#define NULL_PTR(i) ((ARG_TAG(i) == E2K_NULLPTR_ETAG) && (arg##i == 0))

#define GET_PTR_OR_NUMBER(ptr, size, i, j, min_size, null_is_allowed) \
do { \
	if (unlikely(NULL_PTR(i))) { \
		ptr = 0; \
		size = min_size * !!null_is_allowed; \
		if (!null_is_allowed) \
			DbgSCP(#i " " #j " NULL pointer is not allowed.\n"); \
	} else if (likely(!NOT_PTR(i))) { \
		ptr = e2k_ptr_ptr(arg##i, arg##j, min_size); \
		size = e2k_ptr_size(arg##i, arg##j, min_size); \
	} else { \
		ptr = arg##i; \
		size = 0; \
	} \
} while (0)

#define GET_PTR(ptr, size, i, j, min_size, null_is_allowed) \
do { \
	if (unlikely(NULL_PTR(i))) { \
		ptr = 0; \
		size = min_size * !!null_is_allowed; \
		if (!null_is_allowed) \
			DbgSCP(#i " " #j " NULL pointer is not allowed.\n"); \
	} else if (likely(!NOT_PTR(i))) { \
		ptr = e2k_ptr_ptr(arg##i, arg##j, min_size); \
		size = e2k_ptr_size(arg##i, arg##j, min_size); \
	} else { \
		ptr = 0; \
		size = 0; \
		DbgSCP(#i " " #j " Not a pointer is not allowed.\n"); \
	} \
} while (0)

#define GET_STR(str, i, j)                                              \
	if (likely(!NOT_PTR(i) && !NULL_PTR(i))) {                      \
		str = e2k_ptr_str(arg##i, arg##j);                      \
		if (!str)                                               \
			DbgSCP(#i ":" #j " is not a null-terminated string"); \
	} else {                                                        \
		DbgSCP(#i ":" #j " is NULL or not a valid pointer");    \
		break;                                                  \
	}

	register long rval = -EINVAL;
#ifdef CONFIG_DEBUG_PT_REGS  
	e2k_usd_lo_t usd_lo_prev;
	struct pt_regs *prev_regs = regs;
#endif
	/* Array for storing parameters when they are passed
	 * through another array (usually arg2:arg3 points to it).
	 * Users:
	 * 6 arguments: sys_ipc, sys_futex;
	 * 5 arguments: sys_newselect;
	 * 3 arguments: sys_execve.
	 *
	 * NOTE: some syscalls (namely sys_rt_sigtimedwait, sys_el_posix and
	 * sys_linkat) had to have the order of arguments changed to fit
	 * them all into dr1-dr7 registers because pointers in protected
	 * mode take up two registers dr[2 * n] and dr[2 * n + 1].
	 * In sys_el_posix first and last arguments are even merged into
	 * one. */
	long *args = (long *) ((((unsigned long) regs) + sizeof(struct pt_regs)
			+ 0xfUL) & (~0xfUL));
	const long arg7 = args[0];
	const u32 tags = (u32) args[1];
	long sys_num = sys_num_and_psl & 0xffffffff;
	const int psl = sys_num_and_psl >> 32;
	register thread_info_t *thread_info = current_thread_info();

	register long flag; /* an error flag */
	register long rval1 = 0; /* numerical return value  or */
	register long rval2 = 0; /* both rval1 & rval2  */
	int return_desk = 0;
	int rv1_tag = E2K_NUMERIC_ETAG;
	int rv2_tag = E2K_NUMERIC_ETAG;
	register int new_user_hs = 0;
#ifdef CONFIG_PROFILING
	register long start_tick = E2K_GET_DSREG(clkr);
	register long clock1;
#endif
	char *str, *str2, *str3;
	e2k_addr_t base;
	unsigned long ptr, ptr2, ptr3;
	unsigned int size;
	e2k_pshtp_t pshtp;
	u64 num_q;

#ifdef CONFIG_DEBUG_PT_REGS  
	/*
	 * pt_regs structure is placed as local data of the
	 * trap handler (or system call handler) function
	 * into the kernel local data stack
	 */
	usd_lo_prev = READ_USD_LO_REG();
#endif

	init_pt_regs_for_syscall(regs);

	/*
	 * All actual pt_regs structures of the process are queued.
	 * The head of this queue is thread_info->pt_regs pointer,
	 * it points to the last (current) pt_regs structure.
	 * The current pt_regs structure points to the previous etc
	 * Queue is empty before first trap or system call on the
	 * any process and : thread_info->pt_regs == NULL
	 */
	regs->next = thread_info->pt_regs;
	thread_info->pt_regs = regs;
	CHECK_PT_REGS_LOOP(regs);

#ifdef CONFIG_PROFILING
	read_ticks(clock1);
#endif
	SAVE_STACK_REGS(regs, thread_info, true, false);
	SAVE_USER_USD_REGS(regs, thread_info, true, psl);
#ifdef CONFIG_PROFILING
	info_save_stack_reg(clock1);
#endif

	/*
	 * Hardware system call operation disables interrupts mask in PSR
	 * and PSR becomes main register to control interrupts.
	 * Switch control from PSR register to UPSR, if UPSR
	 * interrupts control is used and all following system call
	 * will be executed under UPSR control
	 */
	SWITCH_TO_KERNEL_UPSR(thread_info->upsr, true, false, false);

	/*
	 * Set new stacks
	 */
	SAVE_KERNEL_STACKS_STATE(regs, thread_info);

	CHECK_KERNEL_USD_SIZE(thread_info);
	DbgSCP("_NR_ %d start. current %p pid %d\n",
			sys_num, current, current->pid);

	/*
	 * 'panic()' can be called only after setting data stack pointer
	 * E2K_SET_USER_STACK()
	 */
	if (unlikely(READ_USD_LO_REG().USD_lo_base < thread_info->k_stk_base)) {
		kernel_stack_overflow();
	}

	/****************END_SYS_PROLOG******************************/

	local_irq_enable();

	if (unlikely(AS(regs->stacks.pcsp_hi).ind >=
				AS(regs->stacks.pcsp_hi).size ||
		     AS(regs->stacks.psp_hi).ind >=
				AS(regs->stacks.psp_hi).size))
		expand_hw_stacks_in_syscall(regs);

	regs->sys_num = sys_num;

restart:
	/* Trace syscall enter */
	if (unlikely(thread_info->flags & _TIF_WORK_SYSCALL_TRACE)) {
		/* Save args for tracer */
		SAVE_SYSCALL_ARGS(regs, sys_num,
				arg1, arg2, arg3, arg4, arg5, arg6);

		/* Call tracer */
		syscall_trace_entry(regs);

		/* Update args, since tracer could have changed them */
		RESTORE_SYSCALL_ARGS(regs, sys_num,
				arg1, arg2, arg3, arg4, arg5, arg6);
	}

	switch (sys_num) {
	case __NR_restart_syscall:
		DbgSC("restart_syscall()\n");
		rval = sys_restart_syscall();
		break;
	case __NR_fork:
		DbgSC("fork() ");
		rval = sys_fork();
		DbgSC("fork rval = %ld\n",rval);
		break;
	case __NR_read:
	case __NR_write:
	case __NR_getdents:
		DbgSCP("__NR_%ld protected: fd = %d, buf = 0x%lx : 0x%lx, "
			"count = 0x%lx", sys_num, (int) arg1, arg2, arg3, arg4);
		GET_PTR(ptr, size, 2, 3, arg4, 0);
		if (!size)
			break;

		if (sys_num == __NR_read)
			rval = sys_read(arg1, (char *) ptr, (size_t) arg4);
		else if (sys_num == __NR_write)
			rval = sys_write(arg1, (char *) ptr, (size_t) arg4);
		else
			rval = sys_getdents((unsigned int) arg1,
					(struct linux_dirent*) ptr,
					(unsigned int) arg4);
		DbgSCP("  rval = %ld\n",rval);
		break;
	case __NR_waitpid:
		DbgSCP("waitpid(): pid = %ld, int * = 0x%lx : 0x%lx, "
				"flag = 0x%lx", arg1, arg2, arg3, arg4);
		GET_PTR(ptr, size, 2, 3, sizeof(int), 1);
		if (!size)
			break;

		rval = sys_waitpid((int) arg1, (int *) ptr, (int) arg4);
		DbgSCP(" rval = %ld\n",rval);
		break;
	case __NR_execve:
#define EXECVE_ARGS 3
#define EXECVE_PROTECTED_LENGTH 8
		/* 3 parameters are passed through array.
		 * maska is a first element of array a[0]. */
		GET_PTR(ptr, size, 2, 3, EXECVE_PROTECTED_LENGTH * 8, 0);
		if (!size)
			break;

		if ((rval = convert_array((long *) ptr, args, size,
				EXECVE_PROTECTED_LENGTH, EXECVE_ARGS, -1))) {
			DbgSCP(" Bad array for __NR_execve\n");
			break;
		}
		rval = e2k_sys_execve((char *) args[0], (char **) args[1],
				      (char **) args[2]);
		DbgSCP("rval = %ld\n", rval);
		break;
	case __NR_time:
		DbgSCP("time(): t = 0x%lx : 0x%lx ", arg2, arg3);
		GET_PTR(ptr, size, 2, 3, sizeof(time_t), 1);
		if (!size)
			break;

		rval = sys_time((time_t *) ptr);
		DbgSCP("rval = %ld\n",rval);
		break;
	case __NR_pipe:
		DbgSCP("pipe(0x%lx : 0x%lx\n) ", arg2, arg3);
		GET_PTR(ptr, size, 2, 3, 2 * sizeof (u32), 0);
		if (!size)
			break;

		rval = sys_pipe((int *) ptr);
		DbgSCP("  rval = %ld\n",rval);
		break;
	case __NR_times:
		DbgSCP("times(): buf = 0x%lx : 0x%lx, ", arg2, arg3);

		GET_PTR(ptr, size, 2, 3, sizeof(struct tms), 1);
		if (!size)
			break;

		rval = sys_times((struct tms *) ptr);
		DbgSCP("rval = %ld\n",rval);
		break;
	case __NR_ustat:
		DbgSCP("ustat(): fd = %ld, statbuf = 0x%lx : 0x%lx, ",
				arg1, arg2, arg3);

		GET_PTR(ptr, size, 2, 3, sizeof(struct ustat), 0);
		if (!size)
			break;

		rval = sys_ustat(arg1, (struct ustat *) ptr);
		DbgSCP("rval = %ld\n",rval);
		break;
	case __NR_setrlimit:
	case __NR_getrlimit:
	case __NR_ugetrlimit:
		DbgSCP("%ld protected(): resource = %ld, rlimit = "
				"0x%lx : 0x%lx, ", sys_num, arg1, arg2, arg3);

		GET_PTR(ptr, size, 2, 3, sizeof(struct rlimit), 0);
		if (!size)
			break;

		if (sys_num == __NR_setrlimit)
			rval = sys_setrlimit(arg1, (struct rlimit *) ptr);
		else
			rval = sys_getrlimit(arg1, (struct rlimit *) ptr);
		DbgSCP("rval = %ld\n",rval);
		break;
	case __NR_getrusage:
		DbgSCP("getrusage(): who = %ld, rusage = 0x%lx : 0x%lx, ",
				arg1, arg2, arg3);

		GET_PTR(ptr, size, 2, 3, sizeof(struct rusage), 0);
		if (!size)
			break;

		rval = sys_getrusage(arg1, (struct rusage *) ptr);
		DbgSCP("rval = %ld\n",rval);
		break;
	case __NR_gettimeofday:
		DbgSCP("gettimeofday(): time = 0x%lx : 0x%lx, "
				"zone = 0x%lX : 0x%lx, ", arg2, arg3, arg4, arg5);

		GET_PTR(ptr, size, 2, 3, sizeof(struct timeval), 1);
		if (!size)
			break;

		GET_PTR(ptr2, size, 4, 5, sizeof(struct timezone), 1);
		if (!size)
			break;

		rval = sys_gettimeofday((struct timeval *) ptr,
				(struct timezone *) ptr2);
		DbgSCP("rval = %ld\n",rval);
		break;
	case __NR_getgroups:
		DbgSCP("getgroups(): cnt = %ld, buf = 0x%lx : 0x%lx, ",
				arg1, arg2, arg3);

		GET_PTR(ptr, size, 2, 3, arg1 * sizeof(gid_t), 1);
		if (arg1 && !size)
			break;

		rval = sys_getgroups(arg1, (gid_t *) ptr);
		DbgSCP("rval = %ld\n",rval);
		break;
	case __NR_readlink:
		DbgSCP("readlink(): path = 0x%lx : 0x%lx, buf = 0x%lx : 0x%lx, sz = %ld",
				arg2, arg3, arg4, arg5, arg6);

		GET_STR(str, 2, 3);
		if (!str)
			break;

		GET_PTR(ptr, size, 4, 5, arg6, 0);
		if (!size)
			break;

		rval = sys_readlink(str, (char *) ptr, (size_t) arg6);
		DbgSCP("rval = %ld\n",rval);
		break;
	case __NR_readdir:
#if 0
		DbgSCP("readdir(): fd = %ld, buf = 0x%lx : 0x%lx, sz = %ld",
				arg1, arg2, arg3, arg4);

		GET_PTR(ptr, size, 2, 3, arg4, 0);
		if (!size)
		break;

		rval = old_readdir((unsigned int) arg1, (char *) ptr,
				(unsigned int) arg4);
#else
		DbgSCP("readdir(): fd = %ld, buf = 0x%lx : 0x%lx, sz = %ld",
				arg1, arg2, arg3, arg4);
		rval = -ENOSYS;
#endif
		DbgSCP("rval = %ld\n",rval);
		break;
	case __NR_mmap: {
		unsigned long mmap_addr;
		unsigned int enable = 0;

		DbgSCP("mmap(): start = %ld, len = %ld, prot = 0x%lx "
				"flags = 0x%lx, fd = 0x%lx, off = %ld",
				arg1, arg2, arg3, arg4, arg5, arg6);
		return_desk = 1;
		rval1 = rval2 = 0;
		rv1_tag = rv2_tag = 0;
		if (arg4 & MAP_FIXED) {
			DbgSC("   flags & MAP_FIXED ");
			goto nr_mmap_out;
		}
		if (arg1 >= TASKP_SIZE) {
			// don't map user to system area
			mmap_addr = 0;
		} else {
			mmap_addr = arg1;
		}
		if ((unsigned long) arg2 > 0xFFFFFFFF) {
			rval = -E2BIG;
			break;
		}
		base = sys_mmap((unsigned long) mmap_addr, (unsigned long) arg2,
				(unsigned long) arg3, (unsigned long) arg4,
				(unsigned long) arg5, (unsigned long) arg6);
		if (base & ~PAGE_MASK) {
			rval = base;
			goto nr_mmap_out;
		}
		base += (unsigned long) arg6 & PAGE_MASK;
		if (arg3 & PROT_READ) {
			enable |= R_ENABLE;
		}
		if (arg3 & PROT_WRITE) {
			enable |= W_ENABLE;
		}
		rval1 = make_ap_lo(base, arg2, 0, enable);
		rval2 = make_ap_hi(base, arg2, 0, enable);
		rv1_tag = E2K_AP_LO_ETAG;
		rv2_tag = E2K_AP_HI_ETAG;
		rval = 0;
nr_mmap_out:
		DbgSCP("   rval = %ld (hex: %lx) - 0x%lx : 0x%lx\n",
				rval, rval, rval1, rval2);
		break;
	}
	case __NR_munmap:
		DbgSCP("munmap(): mem = %lx : %lx, sz = %lx ",
				arg2, arg3, arg4);

		GET_PTR(ptr, size, 2, 3, arg4, 0);
		if (!size)
			break;

		if (e2k_ptr_itag(arg2) != AP_ITAG) {
			DbgSCP("Desc in stack\n");
			break;
		}

		rval = sys_munmap(ptr, arg4);
		DbgSC("rval = %ld (hex: %lx)\n", rval, rval);
		break;
	case __NR_statfs:
		DbgSCP("stat(): path = 0x%lx : 0x%lx, buf = 0x%lx : 0x%lx, ",
				arg2, arg3, arg4, arg5);

		GET_STR(str, 2, 3);
		if (!str)
			break;

		GET_PTR(ptr, size, 4, 5, sizeof(struct statfs), 0);
		if (!size)
			break;

		rval = sys_statfs(str, (struct statfs *) ptr);
		DbgSCP("rval = %ld\n",rval);
		break;
	case __NR_fstatfs:
		DbgSCP("fstat(): fd = %ld, buf = 0x%lx : 0x%lx, ",
				arg1, arg2, arg3);

		GET_PTR(ptr, size, 2, 3, sizeof(struct statfs), 0);
		if (!size)
			break;

		rval = sys_fstatfs(arg1, (struct statfs *) ptr);
		DbgSCP("rval = %ld\n",rval);
		break;
	case __NR_stat:
		DbgSCP("stat(): filename = (0x%lx : 0x%lx, "
			"statbuf = 0x%lx : 0x%lx, ", arg2, arg3, arg4, arg5);

		GET_STR(str, 2, 3);
		if (!str)
			break;

		GET_PTR(ptr, size, 4, 5, sizeof(struct stat), 0);
		if (!size)
			break;

		rval = sys_newstat(str, (struct stat *) ptr);
		DbgSCP("rval = %ld\n", rval);
		break;
	case __NR_syslog:
		DbgSCP("syslogr(): tupe = %ld, buf = 0x%lx : 0x%lx, sz = %ld",
				arg1, arg2, arg3, arg4);

		GET_PTR(ptr, size, 2, 3, arg4, 1);
		if (!size)
			break;

		rval = sys_syslog((int) arg1, (char *) ptr, (int) arg4);
		DbgSCP("rval = %ld\n",rval);
		break;
	case __NR_setitimer:
	case __NR_getitimer:
		DbgSCP("%ld protected: which = %ld,  "
				"val= 0x%lx : 0x%lx, oval= 0x%lx : 0x%lx, ",
				sys_num, arg1, arg2, arg3, arg4, arg5);

		GET_PTR(ptr, size, 2, 3, sizeof(struct itimerval), 0);
		if (!size)
			break;

		if (sys_num == __NR_setitimer) {
			rval = sys_getitimer(arg1, (struct itimerval *) ptr);
		} else {
			GET_PTR(ptr2, size, 4, 5, sizeof(struct itimerval), 1);
			if (!size)
				break;

			rval = sys_setitimer(arg1, (struct itimerval *) ptr,
					(struct itimerval *) ptr2);
		}
		DbgSCP("rval = %ld\n",rval);
		break;
	case __NR_fstat:
		DbgSCP("fstat(): fd = %ld, statbuf = 0x%lx : 0x%lx, ",
				arg1, arg2, arg3);

		GET_PTR(ptr, size, 2, 3, sizeof(struct stat), 0);
		if (!size)
			break;

		rval = sys_newfstat(arg1, (struct stat *) ptr);
		DbgSCP("rval = %ld\n",rval);
		break;
	case __NR_wait4:
		DbgSCP("wait4(): pid = %ld, status= 0x%lx : 0x%lx, "
				"opt = 0x%lx, usage= 0x%lx : 0x%lx, ",
				arg1, arg2, arg3, arg6, arg4, arg5);

		GET_PTR(ptr, size, 2, 3, sizeof(int), 1);
		if (!size)
			break;

		GET_PTR(ptr2, size, 4, 5, sizeof(struct rusage), 1);
		if (!size)
			break;

		rval = sys_wait4((pid_t) arg1, (int *) ptr, (int) arg6,
				(struct rusage *) ptr2);
		DbgSCP("rval = %ld\n",rval);
		break;
	case __NR_sysinfo:
		DbgSCP("sysinfo(): sysinfo = 0x%lx : 0x%lx, ",
				arg2, arg3);

		GET_PTR(ptr, size, 2, 3, sizeof(struct sysinfo), 0);
		if (!size)
			break;

		rval = sys_sysinfo((struct sysinfo *) ptr);
		DbgSCP("rval = %ld\n",rval);
		break;
	case __NR_ipc:
#define IPC_ARGS 6
#define IPC_PROTECTED_LENGTH 10
		/* sys_ipc - last parameter  may be pointer or long -
		 * it depends on the first parameter.
		 * 6 parameters are passed through array.
		 * maska is the first element of array. */
		GET_PTR(ptr, size, 2, 3, IPC_PROTECTED_LENGTH * 8, 0);
		if (!size)
			break;

		if ((rval = convert_array((long *) ptr, args, size,
				IPC_PROTECTED_LENGTH, IPC_ARGS, -1))) {
			DbgSCP(" Bad array for _ipc\n");
			break;
		}
		DbgSCP("ipc(): call:%d first:%d second:%d third:%ld\n"
				"ptr:%p fifth:0x%ld \n", (u32) args[0],
				(int) args[1], (int) args[2], (u64) args[3],
				(void *) (u64) args[4], (u64) args[5]);
		rval = sys_ipc((u32) args[0], (int) args[1], (int) args[2],
				(u64) args[3], (void *) (u64) args[4],
				(u64) args[5]);
		DbgSC("rval = %ld\n", rval);
		break;
	case __NR_clone:
	case __NR_clone2: {
#define CLONE_ARGS 2
#define CLONE_PROTECTED_LENGTH 8
		struct task_struct *current_fork = current;
		size_t sz, top_sz, mmap_sz = 0;
		unsigned long args_ptr, addr, mmap_addr = 0;
		/* Compiler supports only %r16-%r63 when specifying concrete
		 * number (%r0 - %r15 are reserved for arguments, SP and FP).
		 * If we do not set specific register number compiler might
		 * move the value around and lose tags in the process! */
		register volatile u64 tls_lo asm("%r16");
		register volatile u64 tls_hi asm("%r17");
		unsigned int args_size, tls_size;
		int tls_lo_tag = 0, tls_hi_tag = 0;
		union {
			struct {
				u32 curptr :32;
				u32 size :32;
			} hi;
			u64 word;
		} __tls_hi;

		/* Avoid erroneous warnings. */
		tls_lo = tls_hi = -1;

		DbgSCP("clone/clone2(0x%lx, 0x%01lx, 0x%016lx, 0x%lx, 0x%lx)\n",
				arg1, arg2, arg3, arg4, arg5);

		/* Read TLS and TID parameters passed indirectly through
		 * an array at (arg4:arg5). */
		if (sys_num == __NR_clone) {
			/* User may choose to not pass additional arguments
			 * (tls, tid) at all for historical and compatibility
			 * reasons, so we do not fail if (arg4,arg5) pointer
			 * is bad. */
			GET_PTR(args_ptr, args_size, 4, 5,
					CLONE_PROTECTED_LENGTH * 8, 0);
			if (args_size != 0) {
				/* Looks like a good pointer. Flags will later
				 * show whether these arguments are any good.
				 *
				 * The first argument is parent_tidptr and
				 * the second one is child_tidptr. The third
				 * argument (tls) requires special handling. */

				/* Strip all protected mode stuff. */
				convert_array((long *) args_ptr, args,
						args_size,
						CLONE_PROTECTED_LENGTH,
						CLONE_ARGS, -1);

				if (arg1 & CLONE_SETTLS) {
					/* Copy TLS argument with tags. */
					BEGIN_USR_PFAULT("clone_pfault", "0f");
					E2K_LOAD_TAGGED_QWORD_AND_TAGS((
                                                         (u64 *) args_ptr)
							+ 6, tls_lo, tls_hi,
                                                       tls_lo_tag, tls_hi_tag);
					LBL_USR_PFAULT("clone_pfault", "0:");
					if (END_USR_PFAULT) {
						rval = -EFAULT;
						break;
					}
					/* Check that the pointer is good. */
					__tls_hi.word = tls_hi;
					tls_size = __tls_hi.hi.size
							- __tls_hi.hi.curptr;
					if (((tls_hi_tag << 4)
							| tls_lo_tag)
							!= ETAGAPQ || tls_size
							< sizeof(int)) {
						DbgSCP(" Bad TLS pointer: " 
                                                " size=%d, tag=%d\n",
						tls_size,
                                               (tls_hi_tag << 4) | tls_lo_tag);
						break;
					}
				}
			} else {
				if (unlikely(arg1 & CLONE_SETTLS
						|| arg1 & CLONE_PARENT_SETTID
						|| arg1 & CLONE_CHILD_CLEARTID
						|| arg1 & CLONE_CHILD_SETTID)) {
					DbgSCP("Bad tid or tls argument\n");
					break;
				}
			}
		} else {
			/* Additional arguments (tls, tid) are not supported by
			 * sys_clone2() because there are no registers left. */
			if (unlikely(arg1 & CLONE_SETTLS)) {
				DbgSCP("TLS will not be supported by clone2\n");
				break;
			}
		}

		/* Get stack parameters */

		if (NULL_PTR(2)) {
			/* The process is forking. */
			addr = 0;
			sz = 0;
			goto clone_good_stack;
		}
		if (NOT_PTR(2)) {
			DbgSCP(" No desk; EINVAL\n");
			break;
		}

		if (sys_num == __NR_clone) {
			sz = e2k_ptr_curptr(arg2, arg3) + 1;
			addr = e2k_ptr_base(arg2, arg3);
			/* Check that the passed stack
			 * does not cross the 4 Gb boundary. */
			if ((addr & ~0xFFFFFFFFL) !=
					((addr + sz - 1) & ~0xFFFFFFFFL))
				addr = 0;
		} else {
			sz = arg4;
			addr = 0;
		}

		if (sz > 0x100000000) {
			DbgSCP("Stack size = 0x%lx > 4Gb\n", sz);
			rval = -ENOMEM;
			break;
		}

		/* Align passed size */
		sz = sz & ~0xFL;
		if (!sz) {
			DbgSCP("zero-sized stack\n");
			break;
		}

		if (!addr) {
			addr = sys_mmap(0, sz, PROT_READ | PROT_WRITE,
					MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
			if (!addr) {
				DbgSCP("No memory 1\n");
				rval = -ENOMEM;
				break;
			}
			mmap_addr = addr;
			mmap_sz = sz;

			/* Since we have just allocated the stack, we know
			 * precisely where the writable part of it starts
			 * and where it ends, so we can use sys_clone2(). */
			sys_num = __NR_clone2;
		}
		/* Check that the stack does not cross the 4 Gb boundary. */
		if ((addr & ~0xFFFFFFFFL) != ((addr + sz - 1) & ~0xFFFFFFFFL)) {
			/* Bad case. This stack does not fit us.
			 * Check that 2 * sz is less than the maximum possible
			 * value of sz (that there will be no overflow). */
			if (sizeof(sz) <= 4) {
				top_sz = ((addr + sz - 1) & 0xFFFFFFFFL) + 1;
				if (top_sz > (sz - top_sz)) {
					sz = top_sz;
					addr = (addr + sz - 1) & ~0xFFFFFFFFL;
				} else {
					sz -= top_sz;
				}
			} else {
				sys_munmap(mmap_addr, mmap_sz);
				addr = sys_mmap(0, 2 * sz, PROT_READ
						| PROT_WRITE, MAP_PRIVATE
						| MAP_ANONYMOUS, 0, 0);
				if (!addr) {
					DbgSCP("No memory\n");
					rval = -ENOMEM;
					break;
				}
				mmap_addr = addr;
				mmap_sz = 2 * sz;
				if (((addr + sz - 1) & ~0xFFFFFFFFL) != (addr
						& ~0xFFFFFFFFL))
					addr = (addr + 0xFFFFFFFFL)
							& ~0xFFFFFFFFL;
			}

			/* Since we have just allocated the stack, we know
			 * precisely where the writable part of it starts
			 * and where it ends, so we can use sys_clone2(). */
			sys_num = __NR_clone2;
		}

clone_good_stack:
		addr = (addr + 0xFL) & ~0xFL;

		/*
		 * Multithreading support - change all SAP to AP in globals
		 * to guarantee correct access to memory
		 */
		if (arg1 & CLONE_VM)
                        mark_all_global_sp(regs, current->pid);

		if (sys_num == __NR_clone) {
			DbgSCP("calling e2k_sys_clone(0x%lx, 0x%lx)\n",
					arg1, addr ? (addr + sz - 16) : 0);
			rval = e2k_sys_clone(arg1, addr ? (addr + sz - 16) : 0,
					(struct pt_regs *) regs,
					(int __user *) args[0],
					(int __user *) args[1], 0);
		} else {
			DbgSCP("calling sys_clone2(0x%lx, 0x%lx, 0x%lx)\n",
					arg1, addr, sz);
			rval = sys_clone2(arg1, (long) addr, sz,
					(struct pt_regs *) regs,
					(int __user *) args[0],
					(int __user *) args[1], 0);
		}
		if (current_fork != current) {
			current_thread_info()->user_stack_addr = mmap_addr;
			current_thread_info()->user_stack_size = mmap_sz;

			/*
			 * e2k_sys_clone and sys_clone2 assume not protected
			 * mode, so to avoid mess with storing and passing
			 * protected pointer (i.e. a structure) around from
			 * the function with __interrupt attribute we set
			 * TLS right here.
			 */
			if (arg1 & CLONE_SETTLS) {
				/* Write tagged pointer into (g12:g13). */
				E2K_SET_DGREG_VAL_AND_TAG(12, tls_lo,
							  tls_lo_tag);
				E2K_SET_DGREG_VAL_AND_TAG(13, tls_hi,
							  tls_hi_tag);
			}
			DbgSCP("son rval = %ld, sys_num = %d\n", rval, sys_num);
		} else {
			if (rval < 0) {
				/* Failed, free the stack
				 * if it was allocated. */
				if (mmap_addr)
					sys_munmap(mmap_addr, mmap_sz);
			}
			DbgSCP("father rval = %ld, sys_num = %d\n",
					rval, sys_num);
		}
		break;
	}
	case __NR_uname:
		DbgSCP("uname(): struct = 0x%lx : 0x%lx ",
				arg2, arg3);

		GET_PTR(ptr, size, 2, 3, sizeof(struct new_utsname), 0);
		if (!size)
			break;

		rval = sys_newuname((struct new_utsname *) ptr);
		DbgSCP("rval = %ld\n",rval);
		break;
	case __NR_adjtimex:
		DbgSCP("adjmutex(): struct = 0x%lx : 0x%lx ",
				arg2, arg3);

		GET_PTR(ptr, size, 2, 3, sizeof(struct timex), 0);
		if (!size)
			break;

		rval = sys_adjtimex((struct timex *) ptr);
		DbgSCP("rval = %ld\n",rval);
		break;
	case __NR_mprotect:
		DbgSCP("mprotect(): void* = 0x%lx : 0x%lx,"
				"len = 0x%lx; prot = 0x%lx ",
				arg2, arg3, arg4, arg5);

		GET_PTR(ptr, size, 2, 3, arg4, 0);
		if (!size)
			break;

		rval = sys_mprotect((unsigned long) ptr, (size_t) arg4,
				(unsigned long) arg5);
		DbgSCP("rval = %ld\n",rval);
		break;
	case __NR_init_module:
		GET_PTR(ptr, size, 2, 3, 0, 0);
		if (!size)
			break;

		GET_STR(str, 4, 5);
		if (!str)
			break;
		DbgSCP("init_module(): umod:%p, len:0x%lx, uargs:%p\n",
				(void*) ptr, arg1, str);

		rval = sys_init_module((void *) ptr, (u64) arg1, str);
		DbgSC("rval = %ld\n", rval);
		break;
	case __NR_sysfs:
		/* arg2 may be pnt or long (depend on arg1) */
		DbgSCP("system call %d arg1=%ld (arg{2,3} = 0x%lx : 0x%lx),"
				" (arg{4,5} = 0x%lx : 0x%lx)",
				sys_num, arg1, arg2, arg3, arg4, arg5);
		GET_PTR(ptr, size, 2, 3, 0, 1);
		GET_PTR(ptr2, size, 4, 5, 0, 1);
		rval = sys_sysfs(arg1, ptr, ptr2);
		DbgSCP("sys_sysfs rval = %ld\n",rval);
		break;
	case __NR__llseek:
		DbgSCP("llseek(): fd = 0x%lx, hi = 0x%lx,lo = 0x%lx; "
				"res = 0x%lx : 0x%lx, wh = 0x%lx",
				arg1, arg2, arg3, arg4, arg5, arg6);

		GET_PTR(ptr, size, 4, 5, sizeof(loff_t), 0);
		if (!size)
			break;

		rval = sys_llseek((unsigned int) arg1, (unsigned long) arg2,
				(unsigned long) arg3, (loff_t *) ptr,
				(unsigned int) arg6);
		DbgSCP("rval = %ld\n",rval);
		break;
	case __NR__newselect:
#define NEWSELECT_ARGS 5
#define NEWSELECT_PROTECTED_LENGTH 12
		GET_PTR(ptr, size, 2, 3, NEWSELECT_PROTECTED_LENGTH * 8, 0);
		if (!size)
			break;

		rval = convert_array((long *) ptr, args, size,
				NEWSELECT_PROTECTED_LENGTH, NEWSELECT_ARGS, -1);
		if (rval) {
			DbgSCP(" Bad array for newselect\n");
			break;
		}

		rval = sys_select((int) args[0], (fd_set *) args[1],
				(fd_set *) args[2], (fd_set *) args[3],
				(struct timeval *) args[4]);
		DbgSCP("sys_select rval = %ld\n", rval);
		break;
	case __NR_sched_setparam:
	case __NR_sched_getparam:
		GET_PTR(ptr, size, 2, 3, sizeof(struct sched_param), 0);
		if (!size)
			break;

		if (sys_num == __NR_sched_setparam) {
			DbgSCP("sched_setparam(): pid = 0x%lx, "
				"args = 0x%lx : 0x%lx, ", arg1, arg2, arg3);
			rval = sys_sched_setparam((pid_t) arg1,
					(struct sched_param *) ptr);
		} else {
			DbgSCP("sched_getparam(): pid = 0x%lx, "
				"args = 0x%lx : 0x%lx, ", arg1, arg2, arg3);
			rval = sys_sched_getparam((pid_t) arg1,
					(struct sched_param *) ptr);
		}
		DbgSCP("rval = %ld\n",rval);
		break;
	case __NR_sched_setscheduler:
		DbgSCP("sched_setscheduler(): pid = %d, policy=%d, "
				"args = 0x%lx : 0x%lx, ",
				(pid_t) arg1, (int) arg2, arg4, arg5);

		GET_PTR(ptr, size, 4, 5, sizeof(struct sched_param), 0);
		if (!size)
			break;

		rval = sys_sched_setscheduler((pid_t) arg1, (int) arg2,
				(struct sched_param __user *) ptr);
		DbgSCP("rval = %ld\n",rval);
		break;
	case __NR_sched_rr_get_interval:
		DbgSCP("sched_getparam(): pid = 0x%lx, time = 0x%lx : 0x%lx\n",
				arg1, arg2, arg3);

		GET_PTR(ptr, size, 2, 3, sizeof(struct timespec), 0);
		if (!size)
			break;

		rval = sys_sched_rr_get_interval((pid_t) arg1,
				(struct timespec *) ptr);
		DbgSCP("rval = %ld\n",rval);
		break;
	case __NR_nanosleep:
		DbgSCP("nanosleep(): req = 0x%lx : 0x%lx,"
				"rem = 0x%lx :  0x%lx ",
				arg2, arg3, arg4, arg5);

		GET_PTR(ptr, size, 2, 3, sizeof(struct timespec), 0);
		if (!size)
			break;

		GET_PTR(ptr2, size, 4, 5, sizeof(struct timespec), 1);
		if (!size)
			break;

		rval = sys_nanosleep((struct timespec *) ptr,
				(struct timespec *) ptr2);
		DbgSCP("rval = %ld\n",rval);
		break;
	case __NR_mremap:
		DbgSCP("mremap(): void * = 0x%lx, : 0x%lx "
				"o_sz = 0x%lx, n_sz =  0x%lx, flags = 0x%lx",
				arg2, arg3, arg4, arg5, arg6);

		GET_PTR(ptr, size, 2, 3, arg4, 0);
		if (!size)
			break;

		base = sys_mremap((pid_t) arg1, (unsigned long) ptr,
				(unsigned long) arg4, (unsigned long) arg5,
				(unsigned long) arg6);
		if (base & ~PAGE_MASK) {
			rval = base;
		} else {
			rval1 = make_ap_lo(base, arg2, 0, e2k_ptr_rw(arg2));
			rval2 = make_ap_hi(base, arg2, 0, e2k_ptr_rw(arg2));
			rv1_tag = E2K_AP_LO_ETAG;
			rv2_tag = E2K_AP_HI_ETAG;
			return_desk = 1;
			rval = 0;
		}
		DbgSCP("rval = %ld\n",rval);
		break;
	case __NR_poll:
		DbgSCP("poll(): fds = 0x%lx : 0x%lx, "
				"nfds = 0x%lx, timeout = 0x%lx, ",
				arg2, arg3, arg4, arg5);

		GET_PTR(ptr, size, 2, 3, arg4 * sizeof(struct pollfd), 0);
		if (!size)
			break;

		rval = sys_poll((struct pollfd *) ptr, arg4, arg5);
		DbgSCP("rval = %ld\n",rval);
		break;
	case __NR_rt_sigaction: {
		struct sigaction *act = NULL;
		int tg = -1;

		GET_PTR(ptr, size, 2, 3, sizeof(struct sigaction), 1);
		if (!size)
			break;

		if (ptr) {
			act = (struct sigaction *) ptr;
			if (GET_USER_TAGD(tg, &act->sa_handler)) {
				DbgSCP("Bad act->sa_handler = %p\n",
						&act->sa_handler);
				rval = -EFAULT;
				break;
			}
			if (tg != E2K_PL_ETAG) {
				if ((act->sa_handler != SIG_DFL) &&
						(act->sa_handler != SIG_IGN)) {
					DbgSCP("Wrong act->sa_handler %d %p %p\n",
							tg, &act->sa_handler,
							act->sa_handler);
					break;
				}
			}
		}

		GET_PTR(ptr2, size, 4, 5, sizeof(struct sigaction), 1);
		if (!size)
			break;

		rval = sys_rt_sigaction((int) arg1,
				(struct sigaction __user *) ptr,
				(struct sigaction __user *) ptr2,
				(size_t) arg6);
		DbgSCP("sys_rt_sigaction rval = %ld\n", rval);
		break;
	}
	case __NR_rt_sigprocmask:
	case __NR_sigprocmask:
		DbgSCP("sigprocmask(): how = 0x%lx, new = 0x%lx : 0x%lx,"
				"old = 0x%lx :  0x%lx ",
				arg1, arg2, arg3, arg4, arg5);

		GET_PTR(ptr, size, 2, 3, sizeof(sigset_t), 1);
		if (!size)
			break;

		GET_PTR(ptr2, size, 4, 5, sizeof(sigset_t), 1);
		if (!size)
			break;

		rval = sys_rt_sigprocmask((int) arg1, (sigset_t*) ptr,
				(sigset_t*) ptr2, sizeof(sigset_t));
		DbgSCP("rval = %ld\n",rval);
		break;
	case __NR_rt_sigtimedwait:
		DbgSCP("sys_rt_sigtimedwait(): uthese = 0x%lx : 0x%lx, "
				"uinfo = 0x%lx : 0x%lx, uts = 0x%lx : 0x%lx, "
				"sigsetsize %d\n", arg2, arg3, arg4, arg5,
				arg6, arg7, arg1);

		GET_PTR(ptr, size, 2, 3, arg1, 0);
		if (!size)
			break;

		GET_PTR(ptr2, size, 4, 5, sizeof(siginfo_t), 1);
		if (!size)
			break;

		GET_PTR(ptr3, size, 6, 7, sizeof(struct timespec), 1);
		if (!size)
			break;

		rval = sys_rt_sigtimedwait((const sigset_t *) ptr,
				(siginfo_t *) ptr2,
				(const struct timespec *) ptr3,
				(size_t) arg1);
		DbgSC("rval = %ld\n", rval);
		break;
	case __NR_rt_sigpending:
	case __NR_setdomainname:
		DbgSCP("__NR_%ld protected: buf = 0x%lx : 0x%lx, sz = %ld",
				sys_num, arg2, arg3, arg4);
		GET_PTR(ptr, size, 2, 3, arg4, 0);
		if (!size)
			break;

		if (sys_num == __NR_rt_sigpending)
			rval = sys_rt_sigpending((sigset_t *) ptr, arg4);
		else
			rval = sys_setdomainname((char *) ptr, (size_t) arg4);
		DbgSCP("rval = %ld\n",rval);
		break;
	case __NR_rt_sigsuspend:
		DbgSCP("rt_sigsuspend(): sigset = 0x%lx : 0x%lx, sz = %ld",
				arg2, arg3, arg4);

		GET_PTR(ptr, size, 2, 3, arg4, 0);
		if (!size)
			break;

		rval = sys_rt_sigsuspend((sigset_t *) ptr, arg4);
		DbgSCP("rval = %ld\n",rval);
		break;
	case __NR_pread:
		DbgSCP("pread(): fd = 0x%lx, "
				"buf = 0x%lx : 0x%lx, len= 0x%lx, off = 0x%lx",
				arg1, arg2, arg3, arg4, arg5);

		GET_PTR(ptr, size, 2, 3, arg4, 0);
		if (!size)
			break;

		rval = sys_pread64(arg1, (void *) ptr, arg4, arg5);
		DbgSCP("rval = %ld\n",rval);
		break;
	case __NR_pwrite:
		DbgSCP("pwrite(): fd = 0x%lx, "
				"buf = 0x%lx : 0x%lx, len= 0x%lx, off = 0x%lx",
				arg1, arg2, arg3, arg4, arg5);

		GET_PTR(ptr, size, 2, 3, arg4, 0);
		if (!size)
			break;

		rval = sys_pwrite64(arg1, (void *) ptr, arg4, arg5);
		DbgSCP("rval = %ld\n",rval);
		break;
	case __NR_getcwd:
		DbgSCP("getcwd(): char* = 0x%lx : 0x%lx, len = 0x%lx",
				arg2, arg3, arg4);

		GET_PTR(ptr, size, 2, 3, arg4, 0);
		if (!size)
			break;

		rval = sys_getcwd((char *) ptr, (unsigned long) arg4);
		DbgSCP("rval = %ld\n",rval);
		break;
	case __NR_e2k_longjmp2:
		DbgSCP("longjmp2: buf = 0x%lx : 0x%lx, retval = %ld  ",
				arg2, arg3, arg4);

		GET_PTR(ptr, size, 2, 3, sizeof(struct jmp_info), 0);
		if (!size)
			break;

		rval = sys_e2k_longjmp2((struct jmp_info *) ptr, arg4);
		DbgSCP("longjmp2 finish regs %p rval %ld\n",
				regs, rval);
		new_user_hs = 1;
		break;
	case __NR_futex:
#define FUTEX_ARGS 6
#define FUTEX_PROTECTED_LENGTH 11
		GET_PTR(ptr, size, 2, 3, FUTEX_PROTECTED_LENGTH * 8, 0);
		if (!size)
			break;

		/* Strip all protected mode stuff from the passed parameters. */
		rval = convert_array((long *) ptr, args, size,
				FUTEX_PROTECTED_LENGTH, FUTEX_ARGS, -1);
		if (rval) {
			DbgSCP(" Bad array for sys_futex\n");
			break;
		}
		DbgSCP("sys_futex args: 0x%lx %d 0x%x 0x%lx 0x%lx %d\n",
				args[0], (int) args[1], (int) args[2],
				args[3], args[4], (int) args[5]);
		rval = sys_futex((u32 *) args[0], (int) args[1], (int) args[2],
				(struct timespec __user *) args[3],
				(u32 __user *) args[4], (int) args[5]);
		DbgSC("rval = %ld\n", rval);
		break;
	case __NR_sched_setaffinity:
		DbgSCP("sched_setaffinity(): pid %d, len %ld, "
				"ptr 0x%lx : 0x%lx", arg1, arg2, arg4, arg5);
		GET_PTR(ptr, size, 4, 5, arg2, 0);
		if (!size)
			break;

		rval = sys_sched_setaffinity(arg1, arg2,
				(unsigned long __user *) ptr);
		DbgSCP(" rval = %ld\n", rval);
		break;
	case __NR_sched_getaffinity:
		DbgSCP("sched_getaffinity(): pid %d, len %ld, "
				"ptr 0x%lx : 0x%lx", arg1, arg2, arg4, arg5);
		GET_PTR(ptr, size, 4, 5, arg2, 0);
		if (!size)
			break;

		rval = sys_sched_getaffinity(arg1, arg2,
				(unsigned long __user *) ptr);
		DbgSCP(" rval = %ld\n", rval);
		break;
#ifdef CONFIG_HAVE_EL_POSIX_SYSCALL
	case __NR_el_posix:
		DbgSCP("sys_el_posix args: 0x%lx : 0x%lx, 0x%lx : 0x%lx, "
				"0x%lx : 0x%lx, 0x%x\n", arg2, arg3,
				arg4, arg5, arg6, arg7, arg1);

		GET_PTR_OR_NUMBER(ptr, size, 2, 3, 0, 1);
		GET_PTR_OR_NUMBER(ptr2, size, 4, 5, 0, 1);
		GET_PTR_OR_NUMBER(ptr3, size, 6, 7, 0, 1);

		rval = sys_el_posix((int) (unsigned long) arg1,
				(void *) ptr, (void *) ptr2, (void *) ptr3,
				(int) (unsigned long) (arg1 >> 32));
		DbgSC("rval = %ld\n", rval);
		break;
#endif
	case __NR_clock_settime:
	case __NR_clock_gettime:
	case __NR_clock_getres:
		DbgSCP("syscall %d: clock_id = 0x%lx, timespec = "
				"0x%lx : 0x%lx, ", sys_num, arg1, arg2, arg3);

		GET_PTR(ptr, size, 2, 3, sizeof(struct timespec), 0);
		if (!size)
			break;

		switch (sys_num) {
		case __NR_clock_settime:
			rval = sys_clock_settime((clockid_t) arg1,
					(const struct timespec __user *) ptr);
			break;
		case __NR_clock_gettime:
			rval = sys_clock_gettime((clockid_t) arg1,
					(struct timespec __user *) ptr);
			break;
		case __NR_clock_getres:
			rval = sys_clock_getres((clockid_t) arg1,
					(struct timespec __user *) ptr);
			break;
		}
		DbgSCP("rval = %ld\n",rval);
		break;
	case __NR_clock_nanosleep:
		DbgSCP("sys_clock_nanosleep(): clock_id %d, flags %d, "
				"req = 0x%lx : 0x%lx, rem = 0x%lx : 0x%lx\n",
				arg1, arg2, arg4, arg5, arg6, arg7);

		GET_PTR(ptr2, size, 4, 5, sizeof(struct timespec), 0);
		if (!size)
			break;

		GET_PTR(ptr3, size, 6, 7, sizeof(struct timespec), 1);
		if (!size)
			break;

		rval = sys_clock_nanosleep((clockid_t) arg1, (int) arg2,
				(const struct timespec __user *) ptr2,
				(struct timespec __user *) ptr3);
		DbgSC("rval = %ld\n", rval);
		break;
	case __NR_set_tid_address:
		DbgSCP("set_tid_address(): tidptr = 0x%lx : 0x%lx, ",
				arg2, arg3);

		GET_PTR(ptr, size, 2, 3, sizeof(int), 0);
		if (!size)
			break;

		rval = sys_set_tid_address((int *) ptr);
		DbgSCP("rval = %ld\n",rval);
		break;
	case __NR_uselib:
	case __NR__sysctl:
	case __NR_socketcall:
	case __NR_readv:
	case __NR_writev:
	case __NR_select:
		/* These system calls use stack and cannot be called directly
		 * from a function with __interrupt attribute. */
		rval = do_protected_syscall(sys_num, arg1, arg2, arg3,
				arg4, arg5, arg6, tags);
		break;
	case __NR_P_get_mem:
		DbgSCP("get_mem(): size = %ld, ", arg1);
		base = sys_malloc((size_t) arg1);
		DbgSCP("base = 0x%lx ", base);
		if (base == 0) {
			rval = -ENOMEM;
		} else {
			rval1 = make_ap_lo(base, arg1, 0, RW_ENABLE);
			rval2 = make_ap_hi(base, arg1, 0, RW_ENABLE);
			rv1_tag = E2K_AP_LO_ETAG;
			rv2_tag = E2K_AP_HI_ETAG;
			return_desk = 1;
			rval = 0;
		}
		DbgSCP("rval = %ld (0x%02x : 0x%lx  -  0x%02x : 0x%lx)\n",
				rval, rv1_tag, rval1, rv2_tag, rval2);
		break;
	case __NR_P_free_mem:
		DbgSCP("free_mem(): arg2 = %lx, arg3 = %lx, ",
				arg2, arg3);

		GET_PTR(ptr, size, 2, 3, 0, 0);
		if (!size)
			break;

		if (e2k_ptr_itag(arg2) != AP_ITAG) {
			DbgSCP(" Stack pointer; EINVAL\n");
			break;
		}

		sys_free((e2k_addr_t) ptr, (size_t) size);
		rval = 0;
		break;
	case __NR_P_dump_umem:
		rval = 0;
		dump_malloc_cart();
		break;
	case __NR_open:
	case __NR_creat:
	case __NR_unlink:
	case __NR_chdir:
	case __NR_mknod:
	case __NR_chmod:
	case __NR_lchown:
	case __NR_access:
	case __NR_mkdir:
	case __NR_rmdir:
	case __NR_acct:
	case __NR_umount:
	case __NR_chroot:
	case __NR_sethostname:
	case __NR_swapon:
	case __NR_truncate:
	case __NR_swapoff:
	case __NR_chown:
	case __NR_delete_module:
		DbgSCP("system call %d (arg{2,3} = 0x%lx : 0x%lx)",
				sys_num, arg2, arg3);

		GET_STR(str, 2, 3);
		if (!str)
			break;

		rval = (*sys_protcall_table[sys_num])(
				(unsigned long) str, arg4, arg5, arg6, 0, 0);
		DbgSCP(" rval = %ld\n", rval);
		break;
	case __NR_fremovexattr:
		DbgSCP("fremovexattr: 0x%lx, (0x%lx : 0x%lx), 0x%lx, 0x%lx, "
				"0x%lx", arg1, arg2, arg3, arg4, arg5, arg6);

		GET_STR(str, 2, 3);
		if (!str)
			break;

		rval = sys_fremovexattr(arg1, str);
		DbgSCP(" rval = %ld\n", rval);
		break;
	case __NR_link:
	case __NR_rename:
	case __NR_symlink:
	case __NR_pivot_root:
	case __NR_removexattr:
	case __NR_lremovexattr:
		DbgSCP("system call %d (arg{2,3} = 0x%lx : 0x%lx), (arg{4,5} = "
				"0x%lx : 0x%lx)", sys_num, arg2, arg3, arg4, arg5);

		GET_STR(str, 2, 3);
		if (!str)
			break;

		GET_STR(str2, 4, 5);
		if (!str2)
			break;

		rval = (*sys_protcall_table[sys_num])((unsigned long) str,
				(unsigned long) str2, arg6, 0, 0, 0);
		DbgSCP(" rval = %ld\n", rval);
		break;
	case __NR_create_module:
	//	case __NR_init_module :
	//	case __NR_delete_module :
	// ?	case __NR_bdflush :
	// 	case __NR_sysfs :
	//	case __NR__newselect :  - need to say malachov
		DbgSCP("Unimplemented yet system call %d\n", sys_num);
		rval = -ENOSYS;
		break;
	case __NR_getcpu:
		DbgSCP("getcpu(): cpup = 0x%lx : 0x%lx, "
				"nodep = 0x%lx : 0x%lx, "
				"cache = 0x%lx : 0x%lx, ",
				arg2, arg3, arg4, arg5, arg6, arg7);

		GET_PTR(ptr, size, 2, 3, sizeof(unsigned int), 1);
		if (!size)
			break;

		GET_PTR(ptr2, size, 4, 5, sizeof(unsigned int), 1);
		if (!size)
			break;

		GET_PTR(ptr3, size, 6, 7, sizeof(struct getcpu_cache), 1);
		if (!size)
			break;

		rval = sys_getcpu((unsigned *)ptr, (unsigned *)ptr2,
						(struct getcpu_cache *)ptr3);
		DbgSCP("rval = %ld\n", rval);
		break;
	case __NR_rt_tgsigqueueinfo:
		DbgSCP("rt_tgsigqueueinfo(): tgid = %d, pid = %d, sig = %d, "
				"uinfo = 0x%lx : 0x%lx, ",
				arg1, arg2, arg3, arg4, arg5);

		GET_PTR(ptr2, size, 4, 5, sizeof(siginfo_t), 0);
		if (!size)
			break;

		rval = sys_rt_tgsigqueueinfo(arg1, arg2, arg3,
							(siginfo_t *)ptr2);
		DbgSCP("rval = %ld\n", rval);
		break;
	case __NR_openat:
		DbgSCP("openat(): dfd = %d, filename = 0x%lx : 0x%lx, "
				"flags = %x, mode = %x, ",
				arg1, arg2, arg3, arg4, arg5);

		GET_STR(str, 2, 3);
		if (!str)
			break;

		rval = sys_openat(arg1, str, arg4, arg5);
		DbgSCP("rval = %ld\n", rval);
		break;
	case __NR_mkdirat:
		DbgSCP("mkdirat(): dfd = %d, pathname = 0x%lx : 0x%lx, "
				"mode = %x, ", arg1, arg2, arg3, arg4);

		GET_STR(str, 2, 3);
		if (!str)
			break;

		rval = sys_mkdirat(arg1, str, arg4);
		DbgSCP("rval = %ld\n", rval);
		break;
	case __NR_mknodat:
		DbgSCP("mknodat(): dfd = %d, filename = 0x%lx : 0x%lx, "
				"mode = %x, dev = %d, ",
				arg1, arg2, arg3, arg4, arg5);
		GET_STR(str, 2, 3);
		if (!str)
			break;

		rval = sys_mknodat(arg1, str, arg4, arg5);
		DbgSCP("rval = %ld\n", rval);
		break;
	case __NR_fchownat:
		DbgSCP("fchownat(): dfd = %d, filename = 0x%lx : 0x%lx, "
				"user = %d, group = %d, flag = %x, ",
				arg1, arg2, arg3, arg4, arg5, arg6);
		GET_STR(str, 2, 3);
		if (!str)
			break;

		rval = sys_fchownat(arg1, str, arg4, arg5, arg6);
		DbgSCP("rval = %ld\n", rval);
		break;
	case __NR_unlinkat:
		DbgSCP("unlinkat(): dfd = %d, pathname = 0x%lx : 0x%lx, "
				"flag = %x, ", arg1, arg2, arg3, arg4);
		GET_STR(str, 2, 3);
		if (!str)
			break;

		rval = sys_unlinkat(arg1, str, arg4);
		DbgSCP("rval = %ld\n", rval);
		break;
	case __NR_renameat:
		DbgSCP("renameat(): olddfd = %d, oldname = 0x%lx : 0x%lx, "
				"newdfd = %d, newname = 0x%lx : 0x%lx, ",
				arg1, arg2, arg3, arg4, arg6, arg7);
		GET_STR(str, 2, 3);
		if (!str)
			break;
		GET_STR(str3, 6, 7);
		if (!str3)
			break;

		rval = sys_renameat(arg1, str, arg4, str3);
		DbgSCP("rval = %ld\n", rval);
		break;
	case __NR_linkat:
		DbgSCP("linkat(): olddfd = %d, oldname = 0x%lx : 0x%lx, "
			"newdfd = %d, flags = %x, newname = 0x%lx : 0x%lx, ",
				arg1, arg2, arg3, arg4, arg5, arg6, arg7);
		GET_STR(str, 2, 3);
		if (!str)
			break;
		GET_STR(str3, 6, 7);
		if (!str3)
			break;

		rval = sys_linkat(arg1, str, arg4, str3, arg5);
		DbgSCP("rval = %ld\n", rval);
		break;
	case __NR_symlinkat:
		DbgSCP("symlinkat(): oldname = 0x%lx : 0x%lx, "
				"newdfd = %d, newname = 0x%lx : 0x%lx, ",
				arg2, arg3, arg4, arg6, arg7);
		GET_STR(str, 2, 3);
		if (!str)
			break;
		GET_STR(str3, 6, 7);
		if (!str3)
			break;

		rval = sys_symlinkat(str, arg4, str3);
		DbgSCP("rval = %ld\n", rval);
		break;
	case __NR_readlinkat:
		DbgSCP("readlinkat(): dfd = %d, pathname = 0x%lx : 0x%lx, "
				"buf = 0x%lx : 0x%lx, bufsiz = %d, ",
				arg1, arg2, arg3, arg4, arg5, arg6);
		GET_STR(str, 2, 3);
		if (!str)
			break;
		GET_STR(str2, 4, 5);
		if (!str2)
			break;

		rval = sys_readlinkat(arg1, str, str2, arg6);
		DbgSCP("rval = %ld\n", rval);
		break;
	case __NR_fchmodat:
		DbgSCP("fchmodat(): dfd = %d, filename = 0x%lx : 0x%lx, "
				"mode = %x, ", arg1, arg2, arg3, arg4);
		GET_STR(str, 2, 3);
		if (!str)
			break;

		rval = sys_fchmodat(arg1, str, arg4);
		DbgSCP("rval = %ld\n", rval);
		break;
	case __NR_faccessat:
		DbgSCP("faccessat(): dfd = %d, filename = 0x%lx : 0x%lx, "
				"mode = %x, ", arg1, arg2, arg3, arg4);
		GET_STR(str, 2, 3);
		if (!str)
			break;

		rval = sys_faccessat(arg1, str, arg4);
		DbgSCP("rval = %ld\n", rval);
		break;
	case __NR_dup3:
		DbgSCP("dup3(): oldfd= %d, newfd = 0x%d : flags=0x%x\n "
				, arg1, arg2, arg3);
		rval = sys_dup3(arg1, arg2, arg3);
		DbgSCP("rval = %ld\n", rval);
		break;
	case __NR_inotify_init1:
		rval = sys_inotify_init1(arg1);
		DbgSCP("rval = %ld\n", rval);
		break;
	case __NR_epoll_create1:
		DbgSCP("sys_epoll_create1(): flags=0x%x\n ", arg1);
		rval = sys_epoll_create1(arg1);
		DbgSCP("rval = %ld\n", rval);
		break;
	case __NR_fstatat64:
		DbgSCP("sys_fstatat64(): dfd=0x%x filename=0x%lx: 0x%lx",
					" statbuf=0x%lx: 0x%lx,flags=0x%x\n",
			arg1, arg2, arg3, arg4, arg5, arg6);
		GET_STR(str, 2, 3);
		if (!str)
			break;
		GET_STR(str2, 4, 5);
		if (!str2)
			break;
		rval = sys_fstatat64(arg1, str, (struct stat64 *)str2, arg6);
		DbgSCP("rval = %ld\n", rval);
		break;
	case __NR_futimesat:
		DbgSCP("sys_futimesat(): dfd=0x%x filename=0x%lx: 0x%lx",
					" statbuf=0x%lx: 0x%lx,flags=0x%x\n",
			arg1, arg2, arg3, arg4, arg5, arg6);
		GET_STR(str, 2, 3);
		if (!str)
			break;
		GET_STR(str2, 4, 5);
		if (!str2)
			break;
		rval = sys_futimesat(arg1, str, (struct timeval *)str2);
		DbgSCP("rval = %ld\n", rval);
		break;
	case __NR_setcontext:
		DbgSCP("sys_setcontext(): ucp=0x%lx:0x%lx, sigsetsize=%d\n",
				arg2, arg3, arg4);

		GET_PTR(ptr, size, 2, 3, sizeof(struct ucontext_prot), 0);
		if (!size)
			break;

		rval = protected_sys_setcontext((struct ucontext_prot *) ptr,
						arg4);
		if (rval == HW_CONTEXT_NEW_STACKS)
			rval = 0;
		new_user_hs = 1;
		DbgSCP("rval = %d\n", rval);
		break;
	case __NR_makecontext:
		DbgSCP("sys_makecontext(): ucp=0x%lx:0x%lx, func %lx, args_size %llx, args %lx:%lx, sigsetsize=%d\n",
				arg2, arg3, arg4, arg5, arg6, arg7, arg1);

		GET_PTR(ptr, size, 2, 3, sizeof(struct ucontext_prot), 0);
		if (!size)
			break;

		GET_PTR(ptr2, size, 6, 7, 16, 1);
		if (!size)
			ptr2 = 0;

		rval = protected_sys_makecontext(
				(struct ucontext_prot *) ptr,
				(void (*)()) arg4, arg5,
				(void *) ptr2, arg1);
		if (rval == HW_CONTEXT_TAIL) {
			hw_context_tail();
			rval = 0;
		}
		DbgSCP("rval = %d\n", rval);
		break;
	case __NR_swapcontext:
		DbgSCP("sys_swapcontext(): oucp=0x%lx:0x%lx, ucp %lx:%lx, sigsetsize=%d\n",
				arg2, arg3, arg4, arg5, arg6);

		GET_PTR(ptr, size, 2, 3, sizeof(struct ucontext_prot), 0);
		if (!size)
			break;

		GET_PTR(ptr2, size, 4, 5, sizeof(struct ucontext_prot),
				0);
		if (!size)
			break;

		rval = protected_sys_swapcontext(
				(struct ucontext_prot *) ptr,
				(struct ucontext_prot *) ptr2,
				arg6);
		if (rval == HW_CONTEXT_NEW_STACKS) {
			new_user_hs = 1;
			rval = 0;
		}
		DbgSCP("rval = %d\n", rval);
		break;
	case __NR_freecontext:
		DbgSCP("sys_freecontext(): ucp=0x%lx:0x%lx\n",
				arg2, arg3);

		GET_PTR(ptr, size, 2, 3, sizeof(struct ucontext_prot), 0);
		if (!size)
			break;

		rval = protected_sys_freecontext(
				(struct ucontext_prot *) ptr);
		DbgSCP("rval = %d\n", rval);
		break;
	default:
		if (sys_num >= NR_syscalls) {
			rval = -ENOSYS;
			break;
		}
		DbgSCP("system call %d (0x%lx, 0x%lx, 0x%lx, 0x%lx)  ",
				sys_num, arg1, arg2, arg3, arg4);
		rval = (*sys_protcall_table[sys_num])(arg1, arg2, arg3, arg4,
				arg5, arg6);
		DbgSCP(" rval = %ld\n", rval);
		break;
	}

	/* We can be here on the new stack.
	 * So we should set regs poiner
	 */
	thread_info = current_thread_info();
	regs = thread_info->pt_regs;

	/* Trace syscall exit */
	if (unlikely(thread_info->flags & _TIF_WORK_SYSCALL_TRACE)) {
		/* Save return value for tracer */
		SAVE_PSYSCALL_RVAL(regs, rval, rval1, rval2);

		/* Call tracer */
		syscall_trace_leave(regs);

		/* Update return value, since tracer could have changed it */
		RESTORE_PSYSCALL_RVAL(regs, rval, rval1, rval2);
	}

	/* It works only under CONFIG_FTRACE flag */
	add_info_syscall(sys_num, start_tick);

	/* We may skip assigning 'args' here because
	 * it is used only in the switch above.
	 * args = (long *) ((((unsigned long) regs) + sizeof(struct pt_regs)
	 *		+ 0xfUL) & (~0xfUL));
	 */

	NEW_CHECK_PT_REGS_ADDR(prev_regs, regs, usd_lo_prev, new_user_hs, 1);

	DbgSCP("_NR_ %d finish k_stk_base %lx rval %ld pid %d\n",
			sys_num, thread_info->k_stk_base, rval, current->pid);

	/*****************END_OF_SYS_EPILOG****************************/

	/*
	 * Return control from UPSR register to PSR, if UPSR
	 * interrupts control is used.
	 * RETURN operation restores PSR state at system call point and
	 * recovers interrupts control
	 *
	 * This also disables interrupts and serves as a compiler barrier.
	 */
	RETURN_IRQ_TO_PSR();

	pshtp = (e2k_pshtp_t) E2K_GET_DSREG_NV(pshtp);
	num_q = E2K_MAXSR - (TTABLE_ENTRY_10_SIZE +
			GET_PSHTP_INDEX(pshtp) / EXT_4_NR_SZ);

	/*
	 * Check under closed interrupts to avoid races
	 */
	while (unlikely(new_user_hs != 1 &&
			(thread_info->flags & _TIF_SIGPENDING) ||
			(thread_info->flags & _TIF_WORK_MASK_NOSIG))) {
		/* Make sure compiler does not reuse previous checks */
		barrier();

		SWITCH_IRQ_TO_UPSR(false);

		if (signal_pending(current) && new_user_hs != 1) {
			register int ret;
			DebugSig("signal_pending __NR_ %d\n", sys_num);
			SAVE_SYSCALL_ARGS(regs, sys_num,
					arg1, arg2, arg3, arg4, arg5, arg6);
			SAVE_PSYSCALL_RVAL(regs, rval, rval1, rval2);

			ret = do_signal(regs);

			/*
			 * We can be here on the new stack and new process,
			 * if signal handler made fork()
			 * So we should reset all pointers
			 */
			thread_info = current_thread_info();
			regs = thread_info->pt_regs;
			args = (long *) ((((unsigned long) regs) +
				sizeof(struct pt_regs) + 0xfUL) & (~0xfUL));

			NEW_CHECK_PT_REGS_ADDR(prev_regs, regs, usd_lo_prev,
					new_user_hs, 1);

			if (ret == -1) {
				DebugSig("restart of %d pid %d\n",
						sys_num, current->pid);
				goto restart;
			} else if (ret == -ERESTART_RESTARTBLOCK) {
				DebugSig("restart of %d pid %d\n",
						sys_num, current->pid);
				sys_num = __NR_restart_syscall;
				goto restart;
			}
			DebugSig("after signal_pending __NR_ %d\n",
					sys_num);
			/* can be changed by do_signal */
			RESTORE_PSYSCALL_RVAL(regs, rval, rval1, rval2);
		}

		if (need_resched())
			schedule();

		if (test_thread_flag(TIF_NOTIFY_RESUME)) {
			clear_thread_flag(TIF_NOTIFY_RESUME);
			do_notify_resume(regs);
		}

		RETURN_IRQ_TO_PSR();

		pshtp = (e2k_pshtp_t) E2K_GET_DSREG_NV(pshtp);
		num_q = E2K_MAXSR - (TTABLE_ENTRY_10_SIZE +
				GET_PSHTP_INDEX(pshtp) / EXT_4_NR_SZ);
	}

	DO_RESTORE_UPSR_REG(thread_info->upsr);

	/*
	 * Clear all other kernel windows, so no function
	 * calls can be made after this.
	 */
	clear_rf_kernel_except_current(num_q);

	/*
	 * Dequeue current pt_regs structure and previous
	 * regs will be now actuale
	 */
	thread_info->pt_regs = regs->next;
	regs->next = NULL;
	CHECK_PT_REGS_LOOP(thread_info->pt_regs);

	RESTORE_USER_STACK_REGS(regs, new_user_hs, 1);
	ENABLE_US_CLW();

	RESTORE_KERNEL_STACKS_STATE(regs, thread_info, 0);

	/* g16/g17 must be restored last as they
	 * hold pointers to current */
	E2K_RESTORE_GREG_IN_SYSCALL(thread_info->gbase, 16, 17, 18, 19);

	if (return_desk) {
		if (rval < 0) {
			flag = 1;
			rval1 = -rval;
		} else {
			flag = 0;
		}

		CLEAR_TTABLE_ENTRY_10_WINDOW_PROT(flag, 0, rval1, rval2,
						  rv1_tag, rv2_tag);
	}

	CLEAR_TTABLE_ENTRY_10_WINDOW(rval);
}
#undef printk
#undef __trace_bprintk
#undef panic

/*
 * this is a copy of sys_socketcall (net/socket.c)
 *
 * The type of structure  depend on first parameter
 */
notrace __section(.entry_handlers)
static long get_socketcall_maska(long call)
{
        long maska;

	switch(call)
	{
		case SYS_SOCKET:
                        maska = 0x7;
//			err = sys_socket(a0,a1,a[2]);
			break;
		case SYS_BIND:
                        maska = 0x15;
//			err = sys_bind(a0,(struct sockaddr __user *)a1, a[2]);
			break;
		case SYS_CONNECT:
                        maska = 0x15;
//			err = sys_connect(a0, (struct sockaddr __user *)a1, a[2]);
			break;
		case SYS_LISTEN:
                        maska = 0x3;
//			err = sys_listen(a0,a1);
			break;
		case SYS_ACCEPT:
                        maska = 0x15;
//			err = sys_accept(a0,(struct sockaddr __user *)a1, (int __user *)a[2]);
			break;
		case SYS_GETSOCKNAME:
                        maska = 0x15;
//			err = sys_getsockname(a0,(struct sockaddr __user *)a1, (int __user *)a[2]);
			break;
		case SYS_GETPEERNAME:
                        maska = 0x15;
//			err = sys_getpeername(a0, (struct sockaddr __user *)a1, (int __user *)a[2]);
			break;
		case SYS_SOCKETPAIR:
                        maska = 0x17;
//			err = sys_socketpair(a0,a1, a[2], (int __user *)a[3]);
			break;
		case SYS_SEND:
                        maska = 0x35;
//			err = sys_send(a0, (void __user *)a1, a[2], a[3]);
			break;
		case SYS_SENDTO:
                        maska = 0x175;
//			err = sys_sendto(a0,(void __user *)a1, a[2], a[3],
//					 (struct sockaddr __user *)a[4], a[5]);
			break;
		case SYS_RECV:
                        maska = 0x35;
//			err = sys_recv(a0, (void __user *)a1, a[2], a[3]);
			break;
		case SYS_RECVFROM:
                        maska = 0x175;
//			err = sys_recvfrom(a0, (void __user *)a1, a[2], a[3],
//					   (struct sockaddr __user *)a[4], (int __user *)a[5]);
			break;
		case SYS_SHUTDOWN:
                        maska = 0x3;
//			err = sys_shutdown(a0,a1);
			break;
		case SYS_SETSOCKOPT:
                        maska = 0x57;
//			err = sys_setsockopt(a0, a1, a[2], (char __user *)a[3], a[4]);
			break;
		case SYS_GETSOCKOPT:
                        maska = 0x57;
//			err = sys_getsockopt(a0, a1, a[2], (char __user *)a[3], (int __user *)a[4]);
			break;
		case SYS_SENDMSG:
                        maska = 0x15;
//			err = sys_sendmsg(a0, (struct msghdr __user *) a1, a[2]);
			break;
		case SYS_RECVMSG:
                        maska = 0x15;
//			err = sys_recvmsg(a0, (struct msghdr __user *) a1, a[2]);
			break;
		default:
                        maska = 0;
			break;
	}
        return maska;
}

notrace __section(.entry_handlers)
static long check_select_fs(e2k_ptr_t *fds_p, fd_set *fds[3])
{
	int	i;
	register int  res = 0;

	/* Now we'll touch user addresses. Let's do it carefuly */
	BEGIN_USR_PFAULT("TR_SELECT", "1f");
	for (i = 0; i < 3; i++, fds_p++) {
		if (AWP(fds_p).hi == 0) {
			continue;
		}

		if ((E2K_LOAD_TAGD(&AWP(fds_p).hi) != E2K_AP_HI_ETAG) ||
		    (E2K_LOAD_TAGD(&AWP(fds_p).lo) != E2K_AP_LO_ETAG)) {
			DbgSCP(" No desk fds[%d]; EINVAL\n", i);
			res = -EINVAL;
                        break;
		}
		if (ASP(fds_p).size - ASP(fds_p).curptr <
				  sizeof (fd_set)) {
			DbgSCP("  Too small fds[%d];\n", i);
			res = -EINVAL;
                        break;
		}
		fds[i] = (fd_set *)E2K_PTR_PTR(fds_p[i]);
	}
	LBL_USR_PFAULT("TR_SELECT", "1:");
	if (END_USR_PFAULT)
		res = -EINVAL;
	return res;
}

/* System calls that are using stack and prohibit the use
 * of __interrupt attribute are redirected here. */
notrace __section(.entry_handlers)
static long do_protected_syscall(const long sys_num, const long arg1,
		const long arg2, const long arg3, const long arg4,
		const long arg5, const long arg6, const long tags)
{
	long rval = -EINVAL;
	mm_segment_t old_fs;
	unsigned long ptr, ptr2;
	unsigned int size;
	char *str;

	DbgSCP("protected call %ld: 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx",
			sys_num, arg1, arg2, arg3, arg4, arg5);

	switch (sys_num) {
	case __NR_uselib: {
		kmdd_t kmdd;
		umdd_t *umdd;
		int i;

		GET_STR(str, 2, 3);
		if (!str)
			break;

		GET_PTR(ptr, size, 4, 5, MDD_PROT_SIZE, 0);
		if (!size)
			break;

		umdd = (umdd_t *) ptr;
		for (i = 0; i < 3; i++) {
			kmdd.src_gtt_addr[i]
					= (char *) E2K_PTR_PTR(umdd->mdd_gtt[i]);
			kmdd.src_gtt_len[i] = AS(umdd->mdd_gtt[i]).size;
		}

		if (current->thread.flags & E2K_FLAG_3P_ELF32)
			rval = sys_load_cu_elf32_3P(str, &kmdd);
		else
			rval = sys_load_cu_elf64_3P(str, &kmdd);

		if (rval) {
			DbgSCP("  could not load\n");
			break;
		}
		rval |= PUT_USER_AP(&umdd->mdd_got, kmdd.got_addr,
				kmdd.got_len, 0, RW_ENABLE);
		if (kmdd.init_got_point)
			rval |= PUT_USER_PL(&umdd->mdd_init_got,
					kmdd.init_got_point);
		else
			rval |= put_user(0L, &umdd->mdd_init_got.word);

		if (kmdd.entry_point)
			rval |= PUT_USER_PL(&umdd->mdd_start, kmdd.entry_point);
		else
			rval |= put_user(0L, &umdd->mdd_start.word);

		if (kmdd.init_point)
			rval |= PUT_USER_PL(&umdd->mdd_init, kmdd.init_point);
		else
			rval |= put_user(0L, &umdd->mdd_init.word);

		if (kmdd.fini_point)
			rval |= PUT_USER_PL(&umdd->mdd_fini, kmdd.fini_point);
		else
			rval |= put_user(0L, &umdd->mdd_fini.word);
		break;
	}
	case __NR__sysctl: {
		struct __sysctl_args new_arg;

		GET_PTR(ptr, size, 2, 3, sizeof(struct __sysctl_args), 0);
		if (!size)
			return -EINVAL;

		if ((rval = convert_array((long *) ptr, (long *) &new_arg,
				size, 17, 10, -1))) {
			DbgSCP(" Bad array for sys_sysctl  \n");
			return -EINVAL;
		}

		old_fs = get_fs();
		set_fs (KERNEL_DS);
		rval = sys_sysctl(&new_arg);
		set_fs (old_fs);
		break;
	}
	case __NR_socketcall: {
		const long maska = get_socketcall_maska(arg1);
		const int args_num = hweight64(maska);
		long args[args_num];

		if (arg1 < 1 || arg1 > SYS_RECVMSG) {
			DbgSCP("Bad call number %ld\n", arg1);
			return -EINVAL;
		}

		/*
		 *  We don't know true size of this desk.
		 *  But it must be smaller than sizeof(desk)*6
		 *  see net/socket.c
		 *  sizeof(long) - size of deck for protected mode
		 */
		GET_PTR(ptr, size, 2, 3, 2 * sizeof(long), 0);
		if (!size)
			return -EINVAL;

		/* Arguments can take 10 longs at maximum */
		rval = convert_array((long *) ptr, args, size, 10, args_num,
				maska);
		if (rval) {
			DbgSCP(" Bad array for socketcall size=%d\n", size);
			return -EINVAL;
		}
		/* We pass pointer to kernel memory (new_arg) here while syscall
		 * assumes that it points to the user memory, so disable checks.
		 * This is safe because in protected mode user cannot pass
		 * pointers to kernel memory. */
		old_fs = get_fs();
		set_fs (KERNEL_DS);
		rval = sys_socketcall((int) arg1, (unsigned long *) args);
		set_fs (old_fs);
		break;
	}
	case __NR_readv:
	case __NR_writev: {
#define MASKA_WRITEV  0x5555555555555555L
		/*
		 * sys_readv(unsigned long fd, const struct iovec __user *vec,
		 *		unsigned long nr_segs)
		 * struct iovec {
		 *	 void __user *iov_base;
		 *	 __kernel_size_t iov_len;
		 * };
		 */
		const int nr_segs = (int) arg4;
		/* Because of alignment struct iovec in array
		 * will consume 32 bytes, not 24! */
		const int args_protected_length = (nr_segs) ? (4 * nr_segs - 1)
				: 0;
		long *new_arg;

		if (((unsigned int) nr_segs) > UIO_MAXIOV) {
			DbgSCP("Bad nr_segs(%d)\n", nr_segs);
			return -EINVAL;
		}

		GET_PTR(ptr, size, 2, 3, args_protected_length * 8, 0);
		if (!size)
			return -EINVAL;

		new_arg = kmalloc(nr_segs * 2 * 8, GFP_KERNEL);
		if ((rval = convert_array((long *) ptr, new_arg, size,
				args_protected_length, nr_segs * 2,
				MASKA_WRITEV))) {
			kfree(new_arg);
			DbgSCP(" Bad array for sys_sysctl  \n");
			return -EINVAL;
		}

		old_fs = get_fs();
		set_fs (KERNEL_DS);
		rval = (*sys_protcall_table[sys_num])(arg1, (long) new_arg,
				nr_segs, 0, 0, 0);
		DbgSCP(" rval = %ld new_arg=%p\n", rval, new_arg);
		set_fs(old_fs);
		kfree(new_arg);
		break;
	}
	case __NR_select: {
		fd_set *fds[3] = { NULL, NULL, NULL };

		GET_PTR(ptr, size, 2, 3, 3 * sizeof(e2k_ptr_t), 0);
		if (!size)
			return -EINVAL;

		GET_PTR(ptr2, size, 4, 5, sizeof(struct timeval), 1);
		if (!size)
			return -EINVAL;

		rval = check_select_fs((e2k_ptr_t *) ptr, fds);
		if (rval)
			return -EINVAL;

		rval = sys_select(arg1, fds[0], fds[1], fds[2],
				(struct timeval *) ptr2);
		break;
	}
	default:
		WARN_ON(1);
	}

	DbgSCP(" rval = %ld\n", rval);
	return rval;
}


/*
 * maska - bit's numeration are  from 0
 * 1 - get value (pnt or long)
 * 0 - miss one value (long)
 * That is, the number of 1's equals the number of parameters in the passed
 * structure (@prot_array) with i'th '1' corresponding to i-th parameter, and
 * the number of bits in @maska equals the size of that structure (in longs).
 * So every parameter must be at least long (8 bytes) in size. Pointers can
 * be 16 bytes in size.
 * Maska may be in first word of prot_array or as a parameter.
 * If Maska < 0 than the first word is maska and the second one must be empty.
 *
 * Other parameters:
 * @prot_array - array of parameters located in userspace;
 * @new_array - where to put read parameters;
 * @size - size of array;
 * @max_len - maximum number of elements to read;
 * @new_len - how many elements are in the prot_array
 * (i.e. hweight(maska) == new_len).
 */

notrace __section(.entry_handlers)
static int convert_array(long __user *prot_array, long *new_array,
			 const int size, const int max_prot_len,
			 const int new_len, long maska)
{
#define MAX_LOCAL_ARGS 16
	long tmp_array[MAX_LOCAL_ARGS];
	int i, prot_len;
	long *tmp;
	long *ptr_from, *ptr_to, *limit_from, *limit_to;
	long new_maska;

	DbgSCP("convert_array prot_array =%p new_array=%p len=%d "
			"new_len=%d maska=%lx\n",
			prot_array, new_array, max_prot_len, new_len, maska);

	prot_len = min((int) ((size + 7) >> 3), max_prot_len);

	if (prot_len > MAX_LOCAL_ARGS)
		tmp = kmalloc(sizeof(*tmp) * prot_len, GFP_KERNEL);
	else
		tmp = tmp_array;

	if (copy_from_user_with_tags(tmp, prot_array,
				     sizeof(*tmp) * prot_len)) {
		if (prot_len > MAX_LOCAL_ARGS)
			kfree(tmp);
		return -EFAULT;
	}

	if (maska < 0) {
		/* first  word - maska */
		maska = tmp[0];
		tmp = tmp + 2;
	}

	new_maska = maska;

	ptr_from = tmp;
	limit_from = ptr_from + prot_len;
	ptr_to = new_array;
	limit_to = ptr_to + new_len;

	for (i = 0; (i < prot_len) && (ptr_from < limit_from) &&
			(ptr_to < limit_to); i++) {
		if (new_maska & 0x1) {
			long val;
			int tag;

			E2K_LOAD_VAL_AND_TAGD(ptr_from, val, tag);
			DbgSCP("ptr_from=%p, val=0x%lx, "
					"tag=0x%x\n", ptr_from, val, tag);

			++ptr_from;

			if (ptr_from < limit_from) {
				long next_val;
				int dtag;

				E2K_LOAD_VAL_AND_TAGD(ptr_from,
                                                        next_val, dtag);
				dtag = tag | (dtag << 4);

				if (dtag == ETAGAPQ) {
					e2k_ptr_t __ptr__;

					AW(__ptr__).lo = val;
					AW(__ptr__).hi = next_val;
					*ptr_to = E2K_PTR_PTR(__ptr__);

					new_maska = new_maska >> 1;
					++ptr_from;
				} else {
					*ptr_to = val;
				}
			} else {
				*ptr_to = val;
			}

			++ptr_to;
		} else {
			++ptr_from;
		}
		new_maska = new_maska >> 1;
		/*  for sys_wreadv - maska must be unlimited and cyclic */
		if ((ptr_from - tmp) % 64 == 0)
			new_maska = maska;
	}

	for (i = 0; i < new_len; i++)
		DbgSCP("convert_array prot_array[%d]=0x%lx\n", i, new_array[i]);

	if (prot_len > MAX_LOCAL_ARGS)
		kfree(tmp);
	return 0;
}


#endif /* CONFIG_PROTECTED_MODE */

/*********************************************************************/

// I use SCALL 12 as a kernel jumpstart.

#ifdef CONFIG_SMP
static atomic_t __initdata boot_bss_cleaning_finished = ATOMIC_INIT(0);
#endif

void  notrace 
__ttable_entry12__ ttable_entry12(
	int n,
	bootblock_struct_t *bootblock)
{
	boot_info_t	*boot_info = NULL;
	u16     	signature;
#ifndef	CONFIG_E2K_MACHINE
	e2k_upsr_t	upsr;
	int		simul_flag;
	int		iohub_flag;
	int		mach_id = 0;
	int		virt_mach_id = 0;
	unsigned char	cpu_type;
#endif /* ! CONFIG_E2K_MACHINE */
#ifdef	CONFIG_RECOVERY
	int	recovery = bootblock->kernel_flags & RECOVERY_BB_FLAG;
	int	cnt_points = bootblock->kernel_flags & CNT_POINT_BB_FLAG;
#else	/* ! CONFIG_RECOVERY  */
	#define		recovery	0
	#define		cnt_points	0
#endif	/* CONFIG_RECOVERY */

	/* CPU will stall if we have unfinished memory operations.
	 * This shows bootloader problems if they present */
	E2K_WAIT_ALL;

	/* Set current pointers to 0 to indicate that
	 * current_thread_info() is not ready yet */
	E2K_SET_DGREG_NV(16, 0);
	E2K_SET_DGREG_NV(17, 0);
	/* percpu shift for the BSP processor is 0 */
	E2K_SET_DGREG_NV(18, 0);
	/* Initial CPU number for the BSP is 0 */
	E2K_SET_DGREG_NV(19, 0);

	/* Clear BSS ASAP */
	if (!recovery || cnt_points) {
		if (IS_BOOT_STRAP_CPU()) {
			void *bss_p = boot_vp_to_pp(__bss_start);
			unsigned long size = (unsigned long) __bss_stop -
					     (unsigned long) __bss_start;
			do_boot_printk("Kernel BSS segment will be cleared from physical address 0x%p size 0x%lx\n",
					bss_p, size);
			recovery_memset_8(bss_p, 0, 0, size,
				LDST_DWORD_FMT << LDST_REC_OPC_FMT_SHIFT |
				MAS_STORE_PA << LDST_REC_OPC_MAS_SHIFT);
#ifdef CONFIG_SMP
			boot_set_event(&boot_bss_cleaning_finished);
		} else {
			boot_wait_for_event(&boot_bss_cleaning_finished);
#endif
		}
	}

	EARLY_BOOT_TRACEPOINT("Linux kernel entered");	

	if (IS_BOOT_STRAP_CPU())
		EARLY_BOOT_TRACEPOINT("kernel boot-time init started");
	
	if ((!recovery || cnt_points) && IS_BOOT_STRAP_CPU()) {
#ifdef	CONFIG_E2K_MACHINE
#if defined(CONFIG_E2K_E3M_SIM)
		boot_e3m_lms_setup_arch();
#elif defined(CONFIG_E2K_E3M)
		boot_e3m_setup_arch();
#elif defined(CONFIG_E2K_E3M_IOHUB_SIM)
		boot_e3m_iohub_lms_setup_arch();
#elif defined(CONFIG_E2K_E3M_IOHUB)
		boot_e3m_iohub_setup_arch();
#elif defined(CONFIG_E2K_E3S_SIM)
		boot_e3s_lms_setup_arch();
#elif defined(CONFIG_E2K_E3S)
		boot_e3s_setup_arch();
#elif defined(CONFIG_E2K_ES2_DSP_SIM) || defined(CONFIG_E2K_ES2_RU_SIM)
		boot_es2_lms_setup_arch();
#elif defined(CONFIG_E2K_ES2_DSP) || defined(CONFIG_E2K_ES2_RU)
		boot_es2_setup_arch();
#elif defined(CONFIG_E2K_E2S_SIM)
		boot_e2s_lms_setup_arch();
#elif defined(CONFIG_E2K_E2S)
		boot_e2s_setup_arch();
#elif defined(CONFIG_E2K_E8C_SIM)
		boot_e8c_lms_setup_arch();
#elif defined(CONFIG_E2K_E8C)
		boot_e8c_setup_arch();
#elif defined(CONFIG_E2K_E1CP_SIM)
		boot_e1cp_lms_setup_arch();
#elif defined(CONFIG_E2K_E1CP)
		boot_e1cp_setup_arch();
#elif defined(CONFIG_E2K_E8C2_SIM)
		boot_e8c2_lms_setup_arch();
#elif defined(CONFIG_E2K_E8C2)
		boot_e8c2_setup_arch();
#else
#    error "E2K MACHINE type does not defined"
#endif
#else	/* ! CONFIG_E2K_MACHINE */
		bool e3m;

		simul_flag = bootblock->info.mach_flags & SIMULATOR_MACH_FLAG;
		iohub_flag = bootblock->info.mach_flags & IOHUB_MACH_FLAG;
		cpu_type = bootblock->info.bios.cpu_type;
		if (simul_flag)
			mach_id |= MACHINE_ID_SIMUL;
		if (iohub_flag)
			mach_id |= MACHINE_ID_E2K_IOHUB;

		upsr = read_UPSR_reg();
		if (AS_WORD(upsr) & (UPSR_FSM | UPSR_IMPT | UPSR_IUC)) {
			/* Only E3S, ES2, E2S E8C E1C+ E8C2 CPUs have these */
			/* bits */
			e3m = false;
		} else {
			WRITE_UPSR_REG_VALUE(AS_WORD(upsr) | UPSR_FSM);
			if (READ_UPSR_REG_VALUE() & (UPSR_FSM)) {
				/* Only E3S, ES2, E2S E8C E1C+ E8C2 CPUs have */
				/* these bits */
				write_UPSR_reg(upsr);
				e3m = false;
			} else {
				e3m = true;
			}
		}

		if (e3m) {
			mach_id |= MACHINE_ID_E3M;
			boot_machine_id = mach_id;
			if (mach_id == MACHINE_ID_E3M_LMS) {
				boot_e3m_lms_setup_arch();
			} else if (mach_id == MACHINE_ID_E3M) {
				boot_e3m_setup_arch();
			} else if (mach_id == MACHINE_ID_E3M_IOHUB_LMS) {
				boot_e3m_iohub_lms_setup_arch();
			} else {
				boot_e3m_iohub_setup_arch();
			}
		} else {
			mach_id |= boot_get_e2k_machine_id();
			boot_machine_id = mach_id;
			if (mach_id == MACHINE_ID_E3S_LMS) {
				boot_e3s_lms_setup_arch();
			} else if (mach_id == MACHINE_ID_E3S) {
				boot_e3s_setup_arch();
			} else if (mach_id == MACHINE_ID_ES2_DSP_LMS ||
					mach_id == MACHINE_ID_ES2_RU_LMS) {
				boot_es2_lms_setup_arch();
			} else if (mach_id == MACHINE_ID_ES2_DSP ||
					mach_id == MACHINE_ID_ES2_RU) {
				boot_es2_setup_arch();
			} else if (mach_id == MACHINE_ID_E2S_LMS) {
				boot_e2s_lms_setup_arch();
			} else if (mach_id == MACHINE_ID_E2S) {
				boot_e2s_setup_arch();
			} else if (mach_id == MACHINE_ID_E8C_LMS) {
				boot_e8c_lms_setup_arch();
			} else if (mach_id == MACHINE_ID_E8C) {
				boot_e8c_setup_arch();
			} else if (mach_id == MACHINE_ID_E1CP_LMS) {
				boot_e1cp_lms_setup_arch();
			} else if (mach_id == MACHINE_ID_E1CP) {
				boot_e1cp_setup_arch();
			} else if (mach_id == MACHINE_ID_E8C2_LMS) {
				boot_e8c2_lms_setup_arch();
			} else if (mach_id == MACHINE_ID_E8C2) {
				boot_e8c2_setup_arch();
			} else {
				mach_id |= MACHINE_ID_E3M;
				boot_machine_id = mach_id;
				if (mach_id == MACHINE_ID_E3M_LMS) {
					boot_e3m_lms_setup_arch();
				} else if (mach_id == MACHINE_ID_E3M) {
					boot_e3m_setup_arch();
				} else if (mach_id == 
						MACHINE_ID_E3M_IOHUB_LMS) {
					boot_e3m_iohub_lms_setup_arch();
				} else {
					boot_e3m_iohub_setup_arch();
				}
			}
		}
		
		if (IS_CPU_TYPE_VIRT(cpu_type)) {
			virt_mach_id = GET_VIRT_MACHINE_ID(cpu_type);
		} else {
			virt_mach_id = mach_id;
		}
		boot_machine_id = mach_id;
		boot_virt_machine_id = virt_mach_id;
#endif /* CONFIG_E2K_MACHINE */
		boot_machine.id = boot_machine_id;
		boot_machine.virt_id = boot_virt_machine_id;

		/* Initialize this as early as possible (but after
		 * setting cpu id and revision) */
		boot_setup_cpu_features(&boot_machine);
	}

	/*
	 * An early parse of cmd line.
	 */
#ifdef	CONFIG_SMP
	if (IS_BOOT_STRAP_CPU()) {
#endif	/* CONFIG_SMP */
		boot_parse_param(bootblock);
#ifdef	CONFIG_SMP
	}
#endif	/* CONFIG_SMP */

#if defined(CONFIG_SERIAL_BOOT_PRINTK)
	if (!recovery || cnt_points)
		boot_setup_serial_console(&bootblock->info);
#endif

#if defined(DEBUG_BOOT_INFO) && DEBUG_BOOT_INFO
	if (IS_BOOT_STRAP_CPU()) {
		/*
		 * Set boot strap CPU id to enable erly boot print with
		 * nodes and CPUs numbers
		 */
		int cpu_id = READ_APIC_ID();
		boot_smp_set_processor_id(cpu_id);
		do_boot_printk("bootblock 0x%x, flags 0x%x\n",
				bootblock, bootblock->boot_flags);
		print_bootblock(bootblock);
	}
#endif

	/*
	 * BIOS/x86 loader has following incompatibilities with kernel
	 * boot process assumption:
	 *	1. Not set USBR register to C stack high address
	 *	2. Set PSP register size to full procedure stack memory
	 *	   when this size should be without last page (last page
	 *	   used as guard to preserve stack overflow)
	 *	3. Set PCSP register size to full procedure chain stack memory
	 *	   when this size should be without last page (last page
	 *	   used as guard to preserve stack overflow)
	 */
	boot_info = &bootblock->info;
	signature = boot_info->signature;

	if (signature == X86BOOT_SIGNATURE) {
		usbr_struct_t	USBR = {{0}};
		usd_struct_t	USD;
		psp_struct_t	PSP;
		pcsp_struct_t	PCSP;

		if (!recovery) {
			read_USD_reg(&USD);
			USBR.USBR_base = PAGE_ALIGN_DOWN(USD.USD_base);
			write_USBR_reg(USBR);

			PSP = RAW_READ_PSP_REG();
			PSP.PSP_size -= PAGE_SIZE;
			RAW_WRITE_PSP_REG(PSP.PSP_hi_struct, PSP.PSP_lo_struct);

			PCSP = RAW_READ_PCSP_REG();
			PCSP.PCSP_size -= PAGE_SIZE;
			RAW_WRITE_PCSP_REG(PCSP.PCSP_hi_struct,
					PCSP.PCSP_lo_struct);
		}
	}

	INIT_G_REGS();

	/*
	 * Set UPSR register in the initial state (where interrupts
	 * are disabled).
	 * Switch control from PSR register to UPSR if it needs
 	*/
	SET_KERNEL_UPSR(1);

	if (recovery && !cnt_points) {
		boot_recovery(bootblock);
	} else {
		boot_init(bootblock);
	}
}

/*********************************************************************/

#define printk printk_fixed_args
#define __trace_bprintk __trace_bprintk_fixed_args
#define panic panic_fixed_args

__interrupt notrace __section(.entry_handlers)
void do_syscall_exit_work()
{
	/* Allocate space for function parameters */
	E2K_SETSP(-64);

	do {
		raw_all_irq_enable();

		if (need_resched())
			schedule();

		if (test_thread_flag(TIF_NOTIFY_RESUME)) {
			clear_thread_flag(TIF_NOTIFY_RESUME);
			do_notify_resume(NULL);
		}

		raw_all_irq_disable();
	} while (test_thread_flag(TIF_NOTIFY_RESUME) ||
		 test_thread_flag(TIF_NEED_RESCHED));
}

#define SYS_CALL_MASK 0xffffffffffffff  /* 56 bit */

__section(.entry_handlers)
void __interrupt notrace hard_sys_calls(system_call_func sys_call,
		long arg1, long arg2, long arg3, long arg4,
		long arg5, long arg6, struct pt_regs *regs)
{
#if defined(CONFIG_KERNEL_TIMES_ACCOUNT) || defined(CONFIG_CLI_CHECK_TIME) || \
						defined(CONFIG_PROFILING)
	register e2k_clock_t	clock = E2K_GET_DSREG(clkr);
	register u64		start_tick;
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */

	register long		rval = 0;
#ifdef CONFIG_DEBUG_PT_REGS
	e2k_usd_lo_t		usd_lo_prev;
	struct pt_regs		*prev_regs = regs;
#endif
	register thread_info_t	*thread_info = current_thread_info();
	register int		new_user_hs = 0;
	register int		new_kernel_ds = 0;
	register e2k_addr_t	k_stk_base_old;
	register e2k_sbr_t	sbr_old;
	register u64		usd_hi_val_old;
	register u64		usd_lo_val_old;
	unsigned long		sys_num = regs->sys_num, is32;
#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	register scall_times_t	*scall_times;
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */
	u64 num_q;
	e2k_pshtp_t pshtp;

	/******************SYS_PROLOG********************************/

	/*
	 *	as e2k_abi we can pass only 8 param through registers
	 *	and is32 and sys_num was packed in trap_table.S code
	 */
	is32 = ((unsigned long) sys_call >> 56);

#ifdef CONFIG_CLI_CHECK_TIME
	check_cli();
#endif

#ifdef CONFIG_DEBUG_PT_REGS
	/*
	 * pt_regs structure is placed as local data of the
	 * trap handler (or system call handler) function
	 * into the kernel local data stack
	 */
	usd_lo_prev = READ_USD_LO_REG();
#endif

	init_pt_regs_for_syscall(regs);

	CHECK_PT_REGS_LOOP(regs);
#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	scall_times =
		&(thread_info->times[thread_info->times_index].of.syscall);
	thread_info->times[thread_info->times_index].type = SYSTEM_CALL_TT;
	INCR_KERNEL_TIMES_COUNT(thread_info);
	scall_times->start = clock;
	E2K_SAVE_CLOCK_REG(scall_times->pt_regs_set);
	scall_times->syscall_num = sys_num;
	scall_times->signals_num = 0;
	regs->scall_times = scall_times;
	scall_times->pshtp = READ_PSHTP_REG();
	scall_times->psp_ind = READ_PSP_HI_REG().PSP_hi_ind;
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */

	SAVE_STACK_REGS(regs, thread_info, true, false);
	SAVE_USER_USD_REGS(regs, thread_info, false, 0);
	SAVE_KERNEL_STACKS_STATE(regs, thread_info);

	/*
	 * All actual pt_regs structures of the process are queued.
	 * The head of this queue is thread_info->pt_regs pointer,
	 * it points to the last (current) pt_regs structure.
	 * The current pt_regs structure points to the previous etc
	 * Queue is empty before first trap or system call on the
	 * any process and : thread_info->pt_regs == NULL
	 */
	regs->next = thread_info->pt_regs;
	thread_info->pt_regs = regs;

#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	E2K_SAVE_CLOCK_REG(scall_times->save_stack_regs);
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */

	read_ticks(start_tick);
	info_save_stack_reg(start_tick);
#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	E2K_SAVE_CLOCK_REG(scall_times->save_sys_regs);
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */

#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	E2K_SAVE_CLOCK_REG(scall_times->save_stacks_state);
	E2K_SAVE_CLOCK_REG(scall_times->save_thread_state);
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */

	CHECK_TI_K_USD_SIZE(thread_info);
	CHECK_KERNEL_USD_SIZE(thread_info);

	/*
	 * Hardware system call operation disables interrupts mask in PSR
	 * and PSR becomes main register to control interrupts.
	 * Switch control from PSR register to UPSR, if UPSR
	 * interrupts control is used and all following system call
	 * will be executed under UPSR control
	 *
	 * This also enables interrupts
	 */
	E2K_SET_PSR_IRQ_BARRIER(AW(E2K_KERNEL_PSR_ENABLED));

	if (unlikely(AS(regs->stacks.pcsp_hi).ind >=
				AS(regs->stacks.pcsp_hi).size ||
		     AS(regs->stacks.psp_hi).ind >=
				AS(regs->stacks.psp_hi).size))
		expand_hw_stacks_in_syscall(regs);

	DbgSC("_NR_ %d is32:%d current %p pid %d name %s\n",
			sys_num, is32, current, current->pid, current->comm);
	DbgSC("k_usd_hi = 0x%lx\n",
			AW(thread_info->k_usd_hi));
	DbgSC("k_usd_lo = 0x%lx\n",
			AW(thread_info->k_usd_lo));
	DbgSC("k_stk_base = 0x%lx\n",
			thread_info->k_stk_base);
	DbgSC("arg1 0x%ld arg2 0x%lx arg3 0x%lx arg4 0x%lx\n",
			      (u64)arg1, (u64)arg2, (u64)arg3, (u64)arg4);
	/****************END_SYS_PROLOG******************************/

	if (unlikely(((unsigned int) sys_num) >= NR_syscalls)) {
		rval = -ENOSYS;
		goto end;
	}

#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	E2K_SAVE_CLOCK_REG(scall_times->scall_switch);
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */

restart:
	/* Trace syscall enter */
	if (unlikely(thread_info->flags & _TIF_WORK_SYSCALL_TRACE)) {
		/* Save args for tracer */
		SAVE_SYSCALL_ARGS(regs, sys_num,
				arg1, arg2, arg3, arg4, arg5, arg6);

		/* Call tracer */
		syscall_trace_entry(regs);

		/* Update args, since tracer could have changed them */
		RESTORE_SYSCALL_ARGS(regs, sys_num,
				arg1, arg2, arg3, arg4, arg5, arg6);
	}

	/*
	 * sys_xxx()s that needs pt_regs inheritance are handling
	 * separately.
	 */
	switch (sys_num) {
	case __NR_restart_syscall:
		rval = sys_restart_syscall();
		break;
	case __NR_fork:
		rval = sys_fork();
		break;
	case __NR_clone:					      /* 120 */
		DbgSC("clone(): clone_flags:0x%lx, newsp:0x%lx regs:%p\n",
			(u64)arg1, (e2k_addr_t)arg2, (struct pt_regs *)regs);
		rval = e2k_sys_clone((u64) arg1, (e2k_addr_t)arg2,
				(struct pt_regs *)regs,
				(int *)(u64)arg3, (int *)(u64)arg4,
				(u64)arg5);
		DbgSC("rval = %ld\n", rval);
		break;
	case __NR_rt_sigreturn:					/** BUG */
		DbgSC("__NR_rt_sigreturn start\n");
		printk_ratelimited(KERN_INFO "rt_sigreturn() system call should not be used by user process\n");
		rval = -ENOSYS;
		break;
	case __NR_sigaltstack:
		 DbgSC("sigaltstack(): ss:%p oss:%p regs:%p\n",
			(stack_t *)(u64)arg1, (stack_t *)(u64)arg2, regs);
		if (is32)
			rval = compat_sys_sigaltstack(
					(compat_stack_t *) (u64) arg1,
					(compat_stack_t *) (u64) arg2);
		else
			rval = sys_sigaltstack((stack_t *) (u64) arg1,
					       (stack_t *) (u64) arg2);
		DbgSC("rval = %ld\n", rval);
		break;
	case __NR_vfork:					      /* 190 */
		rval = e2k_sys_vfork(regs);
		break;
	case __NR_e2k_sigsetjmp:
	case __NR_e2k_longjmp:
		if (printk_ratelimit())
			printk("system call is obsolete. "
					"Recompile your program\n");
		rval = -ENOSYS;
		break;
	case __NR_clone2:
		DbgSC("clone2(): clone_flags:0x%lx, stack_base:0x%lx "
		      "stack_size:0x%llx, regs:%p\n",
			(u64)arg1, (long)arg2, (u64)arg3, regs);
		rval = sys_clone2((u64)arg1, (long)arg2, (u64)arg3, regs,
					(int *)arg4, (int *)arg5,
					(u64)arg6);
		DbgSC("rval = %ld\n", rval);
		break;
	case __NR_e2k_longjmp2:					      /* 230 */
		/* configured for both 32&64 modes */
		/* struct jmp_info equal for 32&64 */
		DbgSC("e2k_longjmp2(): env:%p retval:%ld\n",
			(struct jmp_info *)(u64)arg1, (u64)arg2);
		rval = sys_e2k_longjmp2((struct jmp_info *)(u64)arg1,
			(u64)arg2);
		DbgSC("rval = %ld\n", rval);
		new_user_hs = 1;
		break;
	case __NR_setcontext:
		DbgSC("setcontext(): ucontext %lx, sigsetsize %d\n",
				arg1, arg2);
#ifdef CONFIG_COMPAT
		if (is32)
			rval = compat_sys_setcontext(
					(struct ucontext_32 *) (u64) arg1,
					(size_t) arg2);
		else
#endif
			rval = sys_setcontext((struct ucontext *) (u64) arg1,
					(size_t) arg2);
		if (rval == HW_CONTEXT_NEW_STACKS)
			rval = 0;
		DbgSC("rval = %ld\n", rval);
		new_user_hs = 1;
		break;
	case __NR_makecontext:
		DbgSC("makecontext(): ucontext %lx, sigsetsize %d\n",
				arg1, arg2);
#ifdef CONFIG_COMPAT
		if (is32)
			rval = compat_sys_makecontext(
					(struct ucontext_32 *) arg1,
					(void *) arg2, (int) arg3,
					(u64 *) arg4, arg5);
		else
#endif
			rval = sys_makecontext((struct ucontext *) arg1,
					(void *) arg2, (int) arg3,
					(u64 *) arg4, arg5);
		if (rval == HW_CONTEXT_TAIL) {
			hw_context_tail();
			rval = 0;
		}
		DbgSC("rval = %ld\n", rval);
		break;
	case __NR_swapcontext:
		DbgSC("swapcontext(): oucp %lx, ucp %lx\n",
				arg1, arg2);
#ifdef CONFIG_COMPAT
		if (is32)
			rval = compat_sys_swapcontext(
					(struct ucontext_32 *) arg1,
					(struct ucontext_32 *) arg2,
					(int) arg3);
		else
#endif
			rval = sys_swapcontext((struct ucontext *) arg1,
					(struct ucontext *) arg2,
					(int) arg3);
		if (rval == HW_CONTEXT_NEW_STACKS) {
			new_user_hs = 1;
			rval = 0;
		}
		DbgSC("rval = %ld\n", rval);
		break;
	case __NR_ioctl:
		DbgSC("ioctl(): fd = %ud, cmd = 0x%uX, arg = 0x%ulX\n",
			(unsigned int) arg1, (unsigned int) arg2,
			(unsigned long) arg3);
		thread_info->k_stk_sz_new = 0;
		rval = sys_ioctl(arg1, arg2, arg3);

		/*
		 * In some cases (for example, in blcr module) someone wants to
		 * send SIGKILL. But signal could not be delivered
		 * before exiting from this system call, because one could not
		 * deliver signals, if user hardware stacks were changed. In
		 * this case we should call do_exit().
		 */
		if (test_ts_flag(TS_KILL_ON_SYSCALL_RETURN)) {
			/*
			 * One need to free new kernel data stack, if new one
			 * was allocated (it is need for blcr module).
			 */
			if (thread_info->k_stk_sz_new)
				free_kernel_c_stack(
					(void *)thread_info->k_stk_base_new);

			do_exit(SIGKILL);
		}

		/*
		 * In some cases (for example, in blcr module) someone knows,
		 * that user hardware stacks were changed, so it sets
		 * TS_NEW_USER_HW_STACKS. In other cases we suppose, that user
		 * hardware stacks were not changed.
		 */
		if (test_ts_flag(TS_NEW_USER_HW_STACKS)) {
			clear_ts_flag(TS_NEW_USER_HW_STACKS);
			new_user_hs = 1;
		}

		new_kernel_ds = 1;
		DbgSC("rval = %ld\n", rval);
		break;
	default: {
		if (unlikely(sys_num >= NR_syscalls)) {
			sys_call = (system_call_func) sys_ni_syscall;
		} else if (is32)
			sys_call = sys_call_table_32[sys_num];
		else
			sys_call = sys_call_table[sys_num];

		/* sys_call_table was merged with fast_sys_call_table */
		sys_call = (system_call_func)
				((unsigned long) sys_call & SYS_CALL_MASK);

		rval = sys_call((unsigned long)arg1,
				(unsigned long)arg2,
				(unsigned long)arg3,
				(unsigned long)arg4,
				(unsigned long)arg5,
				(unsigned long)arg6);
		}
		break;
	}

	/* We can be here on the new stack.
	 * So we should set regs poiner
	 */
	thread_info = current_thread_info();
	regs = thread_info->pt_regs;

	/* Trace syscall exit */
	if (unlikely(thread_info->flags & _TIF_WORK_SYSCALL_TRACE)) {
		/* Save return value for tracer */
		SAVE_SYSCALL_RVAL(regs, rval);

		/* Call tracer */
		syscall_trace_leave(regs);

		/* Update return value, since tracer could have changed it */
		RESTORE_SYSCALL_RVAL(regs, rval);
	}

#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	E2K_SAVE_CLOCK_REG(clock);
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */

	/********************SYS_EPILOG********************************/

	CHECK_TI_K_USD_SIZE(thread_info);
#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	{
		register int count;
		GET_DECR_KERNEL_TIMES_COUNT(thread_info, count);
		scall_times = &(thread_info->times[count].of.syscall);
		scall_times->scall_done = clock;
	}
	E2K_SAVE_CLOCK_REG(scall_times->restore_thread_state);
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */

	NEW_CHECK_PT_REGS_ADDR(prev_regs, regs, usd_lo_prev,
			new_user_hs, 1);
#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	E2K_SAVE_CLOCK_REG(scall_times->check_pt_regs);
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */

	DbgSC("_NR_ %d finish k_stk_base %lx rval %ld pid %d name "
		"%s signal_pending(current)=%d\n",
		sys_num, thread_info->k_stk_base, rval,
		current->pid, current->comm, signal_pending(current));

end:
#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	E2K_SAVE_CLOCK_REG(scall_times->restore_start);
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */


	/*
	 * Return control from UPSR register to PSR, if UPSR
	 * interrupts control is used.
	 * RETURN operation restores PSR state at system call point and
	 * recovers interrupts control
	 *
	 * This also disables interrupts and serves as a compiler barrier.
	 */
	RETURN_IRQ_TO_PSR();

	pshtp = (e2k_pshtp_t) E2K_GET_DSREG_NV(pshtp);
	num_q = E2K_MAXSR - (HARD_SYS_CALLS_SIZE +
			GET_PSHTP_INDEX(pshtp) / EXT_4_NR_SZ);

	/*
	 * Check under closed interrupts to avoid races
	 */
	while (unlikely(new_user_hs != 1 &&
			(thread_info->flags & _TIF_SIGPENDING) ||
			(thread_info->flags & _TIF_WORK_MASK_NOSIG))) {
		/* Make sure compiler does not reuse previous checks */
		barrier();

		SWITCH_IRQ_TO_UPSR(false);

		if (signal_pending(current) && new_user_hs != 1) {
			int ret;
			DebugSig("signal_pending __NR_ %d\n", sys_num);
			SAVE_SYSCALL_ARGS(regs, sys_num,
					  arg1, arg2, arg3, arg4, arg5, arg6);
			SAVE_SYSCALL_RVAL(regs, rval);

#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
			E2K_SAVE_CLOCK_REG(scall_times->do_signal_start);
			scall_times->signals_num++;
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */

			ret = do_signal(regs);

#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
			E2K_SAVE_CLOCK_REG(clock);
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */

			/*
			 * We can be here on the new stack and new process,
			 * if signal handler made fork()
			 * So we should reset all pointers
			 */
			thread_info = current_thread_info();
			regs = thread_info->pt_regs;
			CHECK_TI_K_USD_SIZE(thread_info);
#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
			{
				register int count;
				GET_DECR_KERNEL_TIMES_COUNT(thread_info, count);
				scall_times =
					&(thread_info->times[count].of.syscall);
				scall_times->do_signal_done = clock;
			}
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */

			NEW_CHECK_PT_REGS_ADDR(prev_regs, regs, usd_lo_prev,
					new_user_hs, 1);

			if (ret == -1) {
				DebugSig("restart of %d pid %d\n",
					sys_num, current->pid);
				/* We might be on a new stack after the signal.
				 * Update thread_info with the new information
				 * from pt_regs (clone updates pt_regs only). */
				RESTORE_KERNEL_STACKS_STATE(regs,
							    thread_info, 0);
				goto restart;
			} else if (ret == -ERESTART_RESTARTBLOCK) {
				DebugSig("restart of %d pid %d\n",
					sys_num, current->pid);
				/* We might be on a new stack after the signal.
				 * Update thread_info with the new information
				 * from pt_regs (clone updates pt_regs only). */
				RESTORE_KERNEL_STACKS_STATE(regs,
							    thread_info, 0);
				sys_num = __NR_restart_syscall;
				goto restart;
			}

			DebugSig("after signal_pending __NR_ %d\n", sys_num);
			/* can be changed by do_signal */
			RESTORE_SYSCALL_RVAL(regs, rval);
		}

		if (need_resched())
			schedule();

		if (test_thread_flag(TIF_NOTIFY_RESUME)) {
			clear_thread_flag(TIF_NOTIFY_RESUME);
			do_notify_resume(regs);
		}

		RETURN_IRQ_TO_PSR();

		pshtp = (e2k_pshtp_t) E2K_GET_DSREG_NV(pshtp);
		num_q = E2K_MAXSR - (HARD_SYS_CALLS_SIZE +
				GET_PSHTP_INDEX(pshtp) / EXT_4_NR_SZ);
	}

	DO_RESTORE_UPSR_REG(thread_info->upsr);

	read_ticks(start_tick);

	/*
	 * Clear all other kernel windows, so no function
	 * calls can be made after this.
	 */
	clear_rf_kernel_except_current(num_q);

	/*
	 * Dequeue current pt_regs structure and previous
	 * regs will be now actuale
	 */

	thread_info->pt_regs = regs->next;
	regs->next = NULL;
	CHECK_PT_REGS_LOOP(thread_info->pt_regs);
	CHECK_TI_K_USD_SIZE(thread_info);

	/*
	 * Now we should restore stack's regs if we return to user mode
	 * else it isn't needed because all needed regs was restored
	 * by switch_to() for __NR_clone or all regs are the same
	 * as before sys_call
	 */

	/*****************END_OF_SYS_EPILOG****************************/

	/*
	 * If new kernel data stack was allocated (it is need for blcr module),
	 * one want to free the old one. To perform it later one need:
	 *
	 * - remember the old kernel data stack base, because it will be
	 *   changed;
	 * - remember user data stack's parameters to restore it after the old
	 *   kernel data stack deletion (one need do it there, because one will
	 *   be switched on user data stack later, but these parameters are
	 *   placed in the old kernel data stack).
	 */
	if (new_kernel_ds && (thread_info)->k_stk_sz_new) {
		k_stk_base_old = thread_info->k_stk_base;
		sbr_old = regs->stacks.sbr;
		usd_hi_val_old = AW(regs->stacks.usd_hi);
		usd_lo_val_old = AW(regs->stacks.usd_lo);
	}

	RESTORE_KERNEL_STACKS_STATE(regs, thread_info, new_kernel_ds);
	RESTORE_USER_STACK_REGS(regs, new_user_hs, 0);

	if (new_user_hs && test_ts_flag(TS_MAPPED_HW_STACKS))
		set_ts_flag(TS_MAPPED_HW_STACKS_INVALID);

#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	E2K_SAVE_CLOCK_REG(scall_times->restore_user_regs);
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */

#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	scall_times->pshtp_to_done = READ_PSHTP_REG();
	scall_times->psp_ind_to_done = READ_PSP_HI_REG().PSP_hi_ind;
	E2K_SAVE_CLOCK_REG(scall_times->end);
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */
	info_restore_all_reg(start_tick);

	/*
	 * One need to free kernel data stack, if new one was allocated
	 * (it is need for blcr module). This function doesn't use
	 * kernel data stack any more, so one can switch to new kernel data
	 * stack to free the old one.
	 */
	if (new_kernel_ds && thread_info->k_stk_sz_new) {
		/* Switch to new kernel data stack */
		WRITE_SBR_REG_VALUE(
			thread_info->k_stk_base + thread_info->k_stk_sz);
		WRITE_USD_REG(thread_info->k_usd_hi, thread_info->k_usd_lo);

		/*
		 * Switch control from PSR register to UPSR and enable
		 * interrupts
		 */
		SWITCH_TO_KERNEL_UPSR(thread_info->upsr, true, false, false);
		local_irq_enable();

		/* Free old kernel data stack */
		free_kernel_c_stack((void *)k_stk_base_old);

		/*
		 * Switch control from UPSR register to PSR, this also disables
		 * interrupts
		 */
		RETURN_TO_USER_UPSR(thread_info->upsr);

		/* Switch to user data stack */
		WRITE_SBR_REG_VALUE(sbr_old);
		WRITE_USD_REG_VALUE(usd_hi_val_old, usd_lo_val_old);
	}

	/* g16/g17 must be restored last as they hold pointers to current */
	E2K_RESTORE_GREG_IN_SYSCALL(thread_info->gbase, 16, 17, 18, 19);

	CLEAR_HARD_SYS_CALLS_WINDOW(rval);
}
#undef printk
#undef __trace_bprintk
#undef panic

#define printk printk_fixed_args
#define panic panic_fixed_args
__section(.entry_handlers)
void __interrupt notrace simple_sys_calls(system_call_func sys_call,
			long arg1, long arg2, long arg3, long arg4,
			long arg5, long arg6, struct pt_regs *regs)
{
	int			regs_is_actual = 0;
#if defined(CONFIG_KERNEL_TIMES_ACCOUNT) || defined(CONFIG_PROFILING)
	e2k_clock_t		clock = E2K_GET_DSREG(clkr);
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */
	e2k_pcsp_hi_t		pcsp_hi;
	e2k_psp_hi_t		psp_hi;
	register thread_info_t	*thread_info = current_thread_info();
	long			rval = 0;
#ifdef CONFIG_DEBUG_PT_REGS
	struct pt_regs		*prev_regs = regs;
	e2k_usd_lo_t		usd_lo_prev = READ_USD_LO_REG();
#endif
	e2k_usd_lo_t		usd_lo;
	e2k_usd_hi_t		usd_hi;
	e2k_cr1_hi_t		cr1_hi;
	unsigned long		sys_num, is32;
	unsigned int ptrace = current->ptrace;
	unsigned long ti_flags = thread_info->flags;
#ifdef CONFIG_KERNEL_TIMES_ACCOUNT
	scall_times_t		*scall_times;
	int			count;
#endif
	u64 num_q, sbr;
	e2k_pshtp_t pshtp;

	check_cli();
#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	scall_times =
		&(thread_info->times[thread_info->times_index].of.syscall);
	thread_info->times[thread_info->times_index].type = SYSTEM_CALL_TT;
	INCR_KERNEL_TIMES_COUNT(thread_info);
	scall_times->start = clock;
	E2K_SAVE_CLOCK_REG(scall_times->pt_regs_set);
	scall_times->signals_num = 0;
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */

	is32 = (unsigned long) sys_call >> 56;
	/* sys_call_table was merged with fast_sys_call_table */
	sys_call = (system_call_func)
				((unsigned long) sys_call & SYS_CALL_MASK);

	CHECK_KERNEL_USD_SIZE(thread_info);

	info_save_stack_reg(clock);

#ifdef CONFIG_KERNEL_TIMES_ACCOUNT
	E2K_SAVE_CLOCK_REG(scall_times->save_stack_regs);
	E2K_SAVE_CLOCK_REG(scall_times->save_sys_regs);
	E2K_SAVE_CLOCK_REG(scall_times->save_stacks_state);
	E2K_SAVE_CLOCK_REG(scall_times->save_thread_state);
#endif

	pcsp_hi = RAW_READ_PCSP_HI_REG();
	psp_hi = RAW_READ_PSP_HI_REG();

	sys_num = regs->sys_num;
	AW(cr1_hi) = E2K_GET_DSREG_NV(cr1.hi);

#ifdef CONFIG_KERNEL_TIMES_ACCOUNT
	scall_times->syscall_num = sys_num;
#endif

	if (unlikely(AS(pcsp_hi).ind >= AS(pcsp_hi).size ||
		     AS(psp_hi).ind >= AS(psp_hi).size))
		/* No need to correct pt_regs here */
		expand_hw_stacks_in_syscall(NULL);

	DbgSC("_NR_ %d is32:%d current %p pid %d name %s\n",
		sys_num, is32, current, current->pid, current->comm);
	DbgSC("k_usd_hi = 0x%lx\n",
			AW(thread_info->k_usd_hi));
	DbgSC("k_usd_lo = 0x%lx\n",
			AW(thread_info->k_usd_lo));
	DbgSC("k_stk_base = 0x%lx\n",
			thread_info->k_stk_base);
	DbgSC("arg1 0x%ld arg2 0x%lx arg3 0x%lx arg4 0x%lx\n",
			(u64)arg1, (u64)arg2, (u64)arg3, (u64)arg4);

#ifdef CONFIG_KERNEL_TIMES_ACCOUNT
	E2K_SAVE_CLOCK_REG(scall_times->scall_switch);
#endif

	if (likely(!(ptrace & PT_PTRACED) &&
		   !(ti_flags & _TIF_WORK_SYSCALL_TRACE))) {
		/* Fast path */
		rval = sys_call((unsigned long)arg1, (unsigned long)arg2,
				(unsigned long)arg3, (unsigned long)arg4,
				(unsigned long)arg5, (unsigned long)arg6);
	} else {
		/* Save registers for ptrace */
		unsigned long flags;

		regs->next = thread_info->pt_regs;
		CHECK_PT_REGS_LOOP(regs);
		regs_is_actual = 1;

		raw_all_irq_save(flags);
		SAVE_STACK_REGS(regs, thread_info, true, false);
		raw_all_irq_restore(flags);

		SAVE_USER_USD_REGS(regs, thread_info, false, 0);

		init_pt_regs_for_syscall(regs);

		barrier();
		thread_info->pt_regs = regs;

restart:
		/* Trace syscall enter */
		if (thread_info->flags & _TIF_WORK_SYSCALL_TRACE) {
			/* Save args for tracer */
			SAVE_SYSCALL_ARGS(regs, sys_num,
					arg1, arg2, arg3, arg4, arg5, arg6);

			/* Call tracer */
			syscall_trace_entry(regs);

			/* Update args, since tracer could have changed them */
			RESTORE_SYSCALL_ARGS(regs, sys_num,
					arg1, arg2, arg3, arg4, arg5, arg6);
		}

		rval = sys_call((unsigned long)arg1, (unsigned long)arg2,
				(unsigned long)arg3, (unsigned long)arg4,
				(unsigned long)arg5, (unsigned long)arg6);

		/* Trace syscall exit */
		if (thread_info->flags & _TIF_WORK_SYSCALL_TRACE) {
			/* Save return value for tracer */
			SAVE_SYSCALL_RVAL(regs, rval);

			/* Call tracer */
			syscall_trace_leave(regs);

			/* Update rval, since tracer could have changed it */
			RESTORE_SYSCALL_RVAL(regs, rval);
		}
	}

	add_info_syscall(sys_num, clock);

#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	E2K_SAVE_CLOCK_REG(scall_times->restore_thread_state);
	E2K_SAVE_CLOCK_REG(scall_times->scall_done);
	E2K_SAVE_CLOCK_REG(scall_times->check_pt_regs);
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */

	/********************SYS_EPILOG********************************/

	DbgSC("_NR_ %d finish k_stk_base %lx rval %ld pid %d nam %s\n",
			sys_num, thread_info->k_stk_base, rval,
			current->pid, current->comm);

	/*
	 * Return control from UPSR register to PSR, if UPSR
	 * interrupts control is used.
	 * RETURN operation restores PSR state at system call point and
	 * recovers interrupts control
	 *
	 * This also disables interrupts and serves as a compiler barrier.
	 */
	E2K_SET_PSR_IRQ_BARRIER(AW(E2K_KERNEL_PSR_DISABLED));

	pshtp = (e2k_pshtp_t) E2K_GET_DSREG_NV(pshtp);
	num_q = E2K_MAXSR - (SIMPLE_SYS_CALLS_SIZE +
			GET_PSHTP_INDEX(pshtp) / EXT_4_NR_SZ);

	/*
	 * Check under closed interrupts to avoid races
	 */
	while (unlikely(thread_info->flags & _TIF_WORK_MASK)) {
		/* Make sure compiler does not reuse previous checks */
		barrier();

		E2K_SET_PSR_IRQ_BARRIER(AW(E2K_KERNEL_PSR_ENABLED));

		if (signal_pending(current)) {
			int ret;

			if (!regs_is_actual) {
				unsigned long flags;

				regs->next = thread_info->pt_regs;
				regs_is_actual = 1;

				raw_all_irq_save(flags);
				SAVE_STACK_REGS(regs, thread_info, true, false);
				raw_all_irq_restore(flags);

				SAVE_USER_USD_REGS(regs, thread_info, false, 0);

				init_pt_regs_for_syscall(regs);

				barrier();
				/* This store must be after all previous
				 * initialization: if a trap happens right now,
				 * then the handler must see a consistent
				 * pt_regs structure. */
				thread_info->pt_regs = regs;
				CHECK_PT_REGS_LOOP(regs);
			}

			SAVE_SYSCALL_ARGS(regs, sys_num,
					  arg1, arg2, arg3, arg4, arg5, arg6);
			SAVE_SYSCALL_RVAL(regs, rval);
			do {
				SAVE_KERNEL_STACKS_STATE(regs, thread_info);

#ifdef CONFIG_KERNEL_TIMES_ACCOUNT
				E2K_SAVE_CLOCK_REG(
						scall_times->do_signal_start);
				scall_times->signals_num++;
#endif

				ret = do_signal(regs);

#ifdef CONFIG_KERNEL_TIMES_ACCOUNT
				E2K_SAVE_CLOCK_REG(clock);
#endif

				/*
				 * We can be here on the new stack and new
				 * process if signal handler made fork(),
				 * so reset all pointers
				 */
				thread_info = current_thread_info();
				regs = thread_info->pt_regs;
				CHECK_TI_K_USD_SIZE(thread_info);
#ifdef CONFIG_KERNEL_TIMES_ACCOUNT
				GET_DECR_KERNEL_TIMES_COUNT(thread_info, count);
				scall_times =
					&(thread_info->times[count].of.syscall);
				scall_times->do_signal_done = clock;
#endif

				NEW_CHECK_USER_PT_REGS_ADDR(prev_regs, regs,
						usd_lo_prev, regs->k_usd_size);

				/*
				 * We might be on a new stack after the signal.
				 * Update thread_info with the new information
				 * from pt_regs (clone updates pt_regs only).
				 */
				RESTORE_KERNEL_STACKS_STATE(
						regs, thread_info, 0);

				if (ret == -1) {
					DebugSig("restart of %d pid %d\n",
							sys_num, current->pid);
					goto restart;
				} else if (ret == -ERESTART_RESTARTBLOCK) {
					DebugSig("restart of %d pid %d\n",
							sys_num, current->pid);
					sys_call = (system_call_func)
							sys_restart_syscall;
					goto restart;
				}
				DebugSig("after signal_pending __NR_ %d\n",
						sys_num);
				/* can be changed by do_signal */
				RESTORE_SYSCALL_RVAL(regs, rval);
			} while (signal_pending(current));
		}

		if (need_resched())
			schedule();

		if (test_thread_flag(TIF_NOTIFY_RESUME)) {
			clear_thread_flag(TIF_NOTIFY_RESUME);
			do_notify_resume(regs);
		}

		E2K_SET_PSR_IRQ_BARRIER(AW(E2K_KERNEL_PSR_DISABLED));

		pshtp = (e2k_pshtp_t) E2K_GET_DSREG_NV(pshtp);
		num_q = E2K_MAXSR - (SIMPLE_SYS_CALLS_SIZE +
				GET_PSHTP_INDEX(pshtp) / EXT_4_NR_SZ);
	}

#ifdef CONFIG_KERNEL_TIMES_ACCOUNT
	E2K_SAVE_CLOCK_REG(scall_times->restore_start);
#endif

	/*****************END_OF_SYS_EPILOG****************************/

	sbr = thread_info->u_stk_top;
	AW(usd_lo) = 0;
	AW(usd_hi) = 0;
	usd_hi.USD_hi_size = (AS_STRUCT(cr1_hi).ussz << 4);
	usd_lo.USD_lo_base = thread_info->u_stk_base + usd_hi.USD_hi_size;

	/*
	 * Dequeue current pt_regs structure and previous
	 * regs will be now actuale
	 */
	if (regs_is_actual) {
		thread_info->pt_regs = regs->next;
		regs->next = NULL;
		CHECK_PT_REGS_LOOP(thread_info->pt_regs);
	}

	/*
	 * Clear all other kernel windows, so no function
	 * calls can be made after this.
	 */
	clear_rf_kernel_except_current(num_q);

	/*
	 * This function has __interrupt attribute so it does not use
	 * stack and writing upsr here does not enable interrupts, so
	 * it is possible to use closed GNU ASM since we have more than
	 * 4 instructions before the return to user.
	 */
	E2K_EXIT_SIMPLE_SYSCALL(sbr, AW(usd_hi), AW(usd_lo),
		AW(thread_info->upsr));

#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	E2K_SAVE_CLOCK_REG(scall_times->restore_user_regs);
	E2K_SAVE_CLOCK_REG(scall_times->end);
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */

	/* g16/g17 must be restored last as they hold pointers to current */
	E2K_RESTORE_GREG_IN_SYSCALL(thread_info->gbase, 16, 17, 18, 19);

	CLEAR_SIMPLE_SYS_CALLS_WINDOW(rval);
}
#undef panic
#undef printk
