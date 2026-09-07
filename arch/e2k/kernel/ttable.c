/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/**************************** DEBUG DEFINES *****************************/

#undef	DEBUG_SYSCALL
#define	DEBUG_SYSCALL	0	/* System Calls trace */
#if DEBUG_SYSCALL
#define DbgSC printk
#else
#define DbgSC(...)
#endif

#undef	DEBUG_1SYSCALL
#define	DEBUG_1SYSCALL	0	/* Tracing particular System Call */
#if DEBUG_1SYSCALL
#define Dbg1SC(sys_num, fmt, ...) \
do {	\
	if (sys_num == DEBUG_1SYSCALL)	\
		pr_info("%s: " fmt, __func__,  ##__VA_ARGS__); \
} while (0)
#else
#define Dbg1SC(...)
#endif

/**************************** END of DEBUG DEFINES ***********************/

#include <linux/context_tracking.h>
#include <linux/getcpu.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/mman.h>
#include <linux/unistd.h>
#include <linux/sys.h>		/* NR_syscalls */
#include <linux/linkage.h>
#include <linux/errno.h>
#include <linux/syscalls.h>
#include <linux/interrupt.h>
#include <linux/signal.h>
#include <linux/times.h>
#include <linux/time.h>
#include <linux/utime.h>
#include <linux/utsname.h>
#include <linux/sysctl.h>
#include <linux/uio.h>
#include <linux/futex.h>
#include <linux/resume_user_mode.h>


#include <uapi/linux/sched/types.h>

#include <asm/convert_array.h>
#include <asm/e2k_api.h>
#include <asm/e2k_debug.h>
#include <asm/glob_regs.h>
#include <asm/mmu_context.h>
#include <asm/sections.h>
#include <asm/head.h>
#include <asm/traps.h>
#include <asm/trap_table.h>
#include <asm/process.h>
#include <asm/sigcontext.h>
#include <asm/hardirq.h>
#include <asm/bootinfo.h>
#include <asm/switch_to.h>
#include <asm/system.h>
#include <asm/console.h>
#include <asm/delay.h>
#include <asm/statfs.h>
#include <asm/poll.h>
#include <asm/regs_state.h>
#include <asm/gregs.h>
#if defined(CONFIG_KERNEL_TIMES_ACCOUNT) || defined(CONFIG_E2K_PROFILING) || \
	defined(CONFIG_CLI_CHECK_TIME)
#include <asm/clock_info.h>
#endif
#include <asm/e2k_ptypes.h>
#include <asm/prot_loader.h>
#include <asm/syscalls.h>
#include <asm/protected_syscalls.h>
#include <asm/trace.h>
#include <asm/ucontext.h>
#include <asm/umalloc.h>
#include <asm/kvm/switch.h>
#include <asm/fast_syscalls.h>
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
#include <asm/kvm/paravirt_sw/runstate.h>
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

#ifdef	CONFIG_COMPAT
#include <linux/compat.h>
#endif

#include "ttable-inline.h"

#undef	DEBUG_PV_SYSCALL_MODE
#define	DEBUG_PV_SYSCALL_MODE	0	/* syscall injection debugging */

#if	DEBUG_PV_UST_MODE || DEBUG_PV_SYSCALL_MODE
bool debug_guest_ust = false;
#else
#define	debug_guest_ust	false
#endif /* DEBUG_PV_UST_MODE || DEBUG_PV_SYSCALL_MODE */

#define	is_kernel_thread(task)	((task)->mm == NULL || (task)->mm == &init_mm)

#define	SAVE_SYSCALL_ARGS(regs, a1, a2, a3, a4, a5, a6)			\
({									\
	(regs)->dargs[0] = (a1);						\
	(regs)->dargs[1] = (a2);						\
	(regs)->dargs[2] = (a3);						\
	(regs)->dargs[3] = (a4);						\
	(regs)->dargs[4] = (a5);						\
	(regs)->dargs[5] = (a6);						\
})
#define	RESTORE_SYSCALL_ARGS(regs, a1, a2, a3, a4, a5, a6)		\
({									\
	(a1) = (regs)->dargs[0];						\
	(a2) = (regs)->dargs[1];						\
	(a3) = (regs)->dargs[2];						\
	(a4) = (regs)->dargs[3];						\
	(a5) = (regs)->dargs[4];						\
	(a6) = (regs)->dargs[5];						\
})
#define	RESTORE_PSYSCALL_RVAL(regs, rval, rval1, rval2)			\
({									\
	(rval) = (regs)->sys_rval;					\
	(rval1) = (regs)->rval1;					\
	(rval2) = (regs)->rval2;					\
})

#ifndef CONFIG_CPU_HW_CLEAR_RF
/*
 * Hardware does not properly clean the register file
 * before returning to user so do the cleaning manually.
 */
extern void clear_rf_6(void);
extern void clear_rf_9(void);
extern void clear_rf_18(void);
extern void clear_rf_21(void);
extern void clear_rf_24(void);
extern void clear_rf_27(void);
extern void clear_rf_36(void);
extern void clear_rf_45(void);
extern void clear_rf_54(void);
extern void clear_rf_63(void);
extern void clear_rf_78(void);
extern void clear_rf_90(void);
extern void clear_rf_99(void);
extern void clear_rf_108(void);
/* Add 4 qregs because clear_rf() is called with parameter area of 4 qregs */
const clear_rf_t clear_rf_fn[E2K_MAXSR] = {
	[0 ... 2] = clear_rf_6,
	[3 ... 5] = clear_rf_9,
	[6 ... 14] = clear_rf_18,
	[15 ... 17] = clear_rf_21,
	[18 ... 20] = clear_rf_24,
	[21 ... 23] = clear_rf_27,
	[24 ... 32] = clear_rf_36,
	[33 ... 41] = clear_rf_45,
	[42 ... 50] = clear_rf_54,
	[51 ... 59] = clear_rf_63,
	[60 ... 74] = clear_rf_78,
	[75 ... 86] = clear_rf_90,
	[87 ... 95] = clear_rf_99,
	[96 ... 108] = clear_rf_108
};
#endif

#ifdef CONFIG_SERIAL_PRINTK
/*
 * Use global variables to prevent using data stack
 */
static char hex_numbers_for_debug[16] = { '0', '1', '2', '3', '4', '5', '6',
	'7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
};

static char u64_char[NR_CPUS][17];

static __interrupt notrace void dump_u64_no_stack(u64 num)
{
	int i;
	int cpu_id;
	char *_u64_char;

	cpu_id = raw_smp_processor_id();

	_u64_char = u64_char[cpu_id];
	_u64_char[16] = 0;

	for (i = 0; i < 16; i++) {
		_u64_char[15 - i] = hex_numbers_for_debug[num % 16];
		num = num / 16;
	}
	dump_puts(_u64_char);
}

static arch_spinlock_t dump_lock = __ARCH_SPIN_LOCK_UNLOCKED;
static __always_inline __interrupt notrace void dump_debug_info_no_stack(void)
{
	u64 usd_base;
	e2k_cr0_t cr0;
	e2k_cr1_t cr1;
	u64 ip;
	u64 ussz;
	e2k_mem_crs_t *frame;
	e2k_pcsp_t pcsp;
	u64 cr_ind;
	u64 cr_base;
	int flags;
	struct thread_info *ti = read_CURRENT_reg_value();

	dump_puts("BUG: kernel data stack overflow\n");

	raw_all_irq_save(flags);
	arch_spin_lock(&dump_lock);

	usd_base = USD_PTR(native_read_USD_reg());
	cr0 = native_read_CR0_reg();
	ip = get_cr0_ip(cr0);

	/*
	 * Print IP ASAP before flushc/flushr instructions
	 */
	dump_puts("last IP: 0x");
	dump_u64_no_stack(ip);

	dump_puts("\nUSD base   = 0x");
	dump_u64_no_stack(usd_base);

	dump_puts("\n    bottom = 0x");
	dump_u64_no_stack((u64) thread_info_task(ti)->stack);

	NATIVE_FLUSHC;

	pcsp = native_read_PCSP_reg();
	cr_ind = PCSP_IND(pcsp);
	cr_base = PCSP_BASE(pcsp);

	dump_puts("\nchain stack:                  USD size\n      0x");
	dump_u64_no_stack(ip);
	cr1 = native_read_CR1_reg();
	ussz = get_cr1_ussz(cr1);
	dump_puts("      ");
	dump_u64_no_stack(ussz);

	frame = ((e2k_mem_crs_t *) (cr_base + cr_ind)) - 1;
	while (frame != (e2k_mem_crs_t *) cr_base) {
		dump_puts("\n      0x");
		ip = get_cr0_ip(frame->cr0);
		dump_u64_no_stack(ip);
		ussz = get_cr1_ussz(frame->cr1);
		dump_puts("      ");
		dump_u64_no_stack(ussz);
		frame--;
	}
	dump_puts("\n");


	arch_spin_unlock(&dump_lock);
	raw_all_irq_restore(flags);
}
#else
static inline void dump_debug_info_no_stack(void)
{
}
#endif

__noreturn notrace __interrupt void kernel_data_stack_overflow(void)
{
	dump_debug_info_no_stack();

	for (;;)
		cpu_relax();
}

DEFINE_PER_CPU(void *, reserve_hw_stacks);

static int __init reserve_hw_stacks_init(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		void *stack = alloc_pages_exact_nid(cpu_to_node(cpu),
						    THREAD_SIZE, THREADINFO_GFP);
		BUG_ON(!stack);
		per_cpu(reserve_hw_stacks, cpu) = stack;
	}

	return 0;
}

core_initcall(reserve_hw_stacks_init);

static __always_inline void switch_to_reserve_stacks(void)
{
	unsigned long base;
	e2k_pcsp_t pcsp;
	e2k_psp_t psp;
	e2k_usd_t usd;
	e2k_sbr_t sbr;

	base = (unsigned long)raw_cpu_read(reserve_hw_stacks);
	if (!base) {
		panic(
		    "Stack overflow, could not switch to reserve stack (stack dump can be corrupted)\n");
	}
	pcsp = new_pcsp(base + KERNEL_PC_STACK_OFFSET, KERNEL_PC_STACK_SIZE, 0);
	psp  = new_psp(base + KERNEL_P_STACK_OFFSET, KERNEL_P_STACK_SIZE, 0);
	usd  = new_usd(base + KERNEL_C_STACK_OFFSET, KERNEL_C_STACK_SIZE,
							KERNEL_C_STACK_SIZE - K_DATA_GAP_SIZE);
	sbr.base = base + KERNEL_C_STACK_OFFSET + KERNEL_C_STACK_SIZE;

	native_write_stacks(psp, pcsp, usd, sbr);

	/* Must spill the frame reserved by hardware trap entry before any calls */
	NATIVE_FLUSHC;
}

/* noinline is needed to make sure we use the reserved data stack */
notrace noinline __cold __noreturn
static void kernel_hw_stack_fatal_error(struct pt_regs *regs,
					    u64 exceptions, u64 kstack_pf_addr)
{
	native_write_irq_barrier_PSR_reg(E2K_KERNEL_PSR_ENABLED);
	raw_local_irq_enable();

	/* Enable emergency console and avoid stack print from panic() */
	bust_spinlocks(1);

	if (kstack_pf_addr) {
		print_address_tlb(kstack_pf_addr);
		print_address_page_tables(kstack_pf_addr, true);

		pr_emerg("BUG: page fault on kernel stack at 0x%llx\n",
			 kstack_pf_addr);
	}

	if (exceptions & exc_chain_stack_bounds_mask) {
		e2k_pcsp_t pcsp = regs->stacks.pcsp;
		pcsp = decr_pcsp_ind(pcsp, regs->stacks.pcshtp.ind);
		pr_emerg("BUG: chain stack overflow: pcsp.base 0x%llx pcsp.size 0x%llx pcsp.ind 0x%llx, pcshtp 0x%llx\n",
			 PCSP_BASE(pcsp), PCSP_SIZE(pcsp), PCSP_IND(pcsp),
			 (u64)regs->stacks.pcshtp.ind);
	}

	if (exceptions & exc_proc_stack_bounds_mask) {
		e2k_psp_t psp = regs->stacks.psp;

		psp = decr_psp_ind(psp, PSHTP_MEM_INDEX(regs->stacks.pshtp));
		pr_emerg("BUG: procedure stack overflow: base 0x%llx ind 0x%llx size 0x%llx\n                pshtp 0x%x\n",
			 PSP_BASE(regs->stacks.psp),
			 PSP_IND(psp), PSP_SIZE(psp),
			 PSHTP_MEM_INDEX(regs->stacks.pshtp));
	}

	if (!kstack_pf_addr)
		print_stack_frames(current, regs, 1);

	print_pt_regs(regs);
	if (regs->next != NULL)
		print_pt_regs(regs->next);

	add_taint(TAINT_DIE, LOCKDEP_NOW_UNRELIABLE);
	panic("kernel stack overflow and/or page fault\n");
}

int cf_max_fill_return __read_mostly = 16 * 0x10;

/* Used in !CPU_FEAT_FILL_INSTRUCTION case */
const fill_handler_t fill_handlers_table[E2K_MAXSR] = {
	&fill_handler_0, &fill_handler_1, &fill_handler_2,
	&fill_handler_3, &fill_handler_4, &fill_handler_5,
	&fill_handler_6, &fill_handler_7, &fill_handler_8,
	&fill_handler_9, &fill_handler_10, &fill_handler_11,
	&fill_handler_12, &fill_handler_13, &fill_handler_14,
	&fill_handler_15, &fill_handler_16, &fill_handler_17,
	&fill_handler_18, &fill_handler_19, &fill_handler_20,
	&fill_handler_21, &fill_handler_22, &fill_handler_23,
	&fill_handler_24, &fill_handler_25, &fill_handler_26,
	&fill_handler_27, &fill_handler_28, &fill_handler_29,
	&fill_handler_30, &fill_handler_31, &fill_handler_32,
	&fill_handler_33, &fill_handler_34, &fill_handler_35,
	&fill_handler_36, &fill_handler_37, &fill_handler_38,
	&fill_handler_39, &fill_handler_40, &fill_handler_41,
	&fill_handler_42, &fill_handler_43, &fill_handler_44,
	&fill_handler_45, &fill_handler_46, &fill_handler_47,
	&fill_handler_48, &fill_handler_49, &fill_handler_50,
	&fill_handler_51, &fill_handler_52, &fill_handler_53,
	&fill_handler_54, &fill_handler_55, &fill_handler_56,
	&fill_handler_57, &fill_handler_58, &fill_handler_59,
	&fill_handler_60, &fill_handler_61, &fill_handler_62,
	&fill_handler_63, &fill_handler_64, &fill_handler_65,
	&fill_handler_66, &fill_handler_67, &fill_handler_68,
	&fill_handler_69, &fill_handler_70, &fill_handler_71,
	&fill_handler_72, &fill_handler_73, &fill_handler_74,
	&fill_handler_75, &fill_handler_76, &fill_handler_77,
	&fill_handler_78, &fill_handler_79, &fill_handler_80,
	&fill_handler_81, &fill_handler_82, &fill_handler_83,
	&fill_handler_84, &fill_handler_85, &fill_handler_86,
	&fill_handler_87, &fill_handler_88, &fill_handler_89,
	&fill_handler_90, &fill_handler_91, &fill_handler_92,
	&fill_handler_93, &fill_handler_94, &fill_handler_95,
	&fill_handler_96, &fill_handler_97, &fill_handler_98,
	&fill_handler_99, &fill_handler_100, &fill_handler_101,
	&fill_handler_102, &fill_handler_103, &fill_handler_104,
	&fill_handler_105, &fill_handler_106, &fill_handler_107,
	&fill_handler_108, &fill_handler_109, &fill_handler_110,
	&fill_handler_111
};

static noinline notrace u64 cf_fill_call(int nr)
{
	if (nr > 0) {
		u64 ret;

		ret = cf_fill_call(nr - 1);
		if (ret == -1ULL)
			ret = native_read_PCSHTP_reg().ind;

		return ret;
	}

	NATIVE_FLUSHC;

	return -1ULL;
}

static int init_cf_fill_depth(void)
{
	unsigned long flags;
	u64 cf_fill_depth;

	if (cpu_has(CPU_FEAT_FILLC)) {
		if (cpu_has(CPU_FEAT_FILLR))
			pr_info("Using FILLC/FILLR instructions\n");
		else
			pr_info("Using FILLC instruction\n");
		return 0;
	}

	raw_all_irq_save(flags);
	cf_fill_depth = cf_fill_call(E2K_MAXCR_q / 2);
	raw_all_irq_restore(flags);

	cf_max_fill_return = cf_fill_depth + 32;

	pr_info
	    ("Using software emulation of FILLC instruction, CF FILL depth: %d quadro registers\n",
	     cf_max_fill_return / 16);

	return 0;
}

pure_initcall(init_cf_fill_depth);

#ifdef CONFIG_E2K_DELAYED_SIGNALS
void e2k_deliver_delayed_signals(void)
{
	if (unlikely(current->forced_info.si_signo)) {
		force_sig_info(&current->forced_info);
		current->forced_info.si_signo = 0;
	}
}
#endif

/**
 * on_kernel_entry - called on every transition from user into kernel
 *
 * Must not make any function calls since for trap handlers it
 * is called early when sensitive to function calls context is
 * not saved yet.
 *
 * Is called as early as possible.
 */
static __always_inline void on_kernel_entry(void)
{
	set_max_u_border();
	cpuhas_greg0 = cpu_features[0];
	cpuhas_greg1 = cpu_features[1];
}

void notrace __irq_entry user_trap_handler(struct pt_regs *regs)
{
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
#if defined(CONFIG_KVM_HOST_KERNEL)
	struct thread_info *thread_info = current_thread_info();
#endif
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	struct trap_pt_regs *trap;
#if defined(CONFIG_KERNEL_TIMES_ACCOUNT) || defined(CONFIG_E2K_PROFILING)
	register e2k_clock_t clock = NATIVE_READ_CLKR_REG_VALUE();
	register e2k_clock_t clock1;
	register e2k_clock_t start_tick;
#endif /* CONFIG_KERNEL_TIMES_ACCOUNT */
	e2k_aau_t *aau_regs;
	e2k_aasr_t aasr;
#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	register trap_times_t *trap_times;
#endif /* CONFIG_KERNEL_TIMES_ACCOUNT */
	u64 exceptions;

	trap = pt_regs_to_trap_regs(regs);
	trap->upsr = current_thread_info()->upsr;
	trap->flags = 0;
#if IS_ENABLED(CONFIG_SOFT_PM)
	/* reset mask before iterating over excs */
	trap->corrected_als_mask = 0;
#endif /* CONFIG_SOFT_PM || CONFIG_SOFT_PM_MODULE */
	regs->trap = trap;
	regs->kernel_entry = 0;

	on_kernel_entry();

#ifdef CONFIG_CLI_CHECK_TIME
	start_tick = NATIVE_READ_CLKR_REG_VALUE();
#endif

	/*
	 * We are not using ctpr2 here (compiling with -fexclude-ctpr2)
	 * thus reading of AASR, AALDV, AALDM can be done at any
	 * point before the first call.
	 *
	 * This is placed before saving trap cellar since saving is done
	 * with 'mmurr' instruction which requires AAU to be stopped.
	 *
	 * Usage of ctpr2 here is not possible since AALDA and AALDI
	 * registers would be zeroed.
	 */
	aasr = native_read_aasr_reg();

	/*
	 * All actual pt_regs structures of the process are queued.
	 * The head of this queue is thread_info->pt_regs pointer,
	 * it points to the last (current) pt_regs structure.
	 * The current pt_regs structure points to the previous etc
	 * Queue is empty before first trap or system call on the
	 * any process and : thread_info->pt_regs == NULL
	 */
	regs->next = current_thread_info()->pt_regs;
	current_thread_info()->pt_regs = regs;
#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	trap_times =
	    &(current_thread_info()->
	      times[current_thread_info()->times_index].of.trap);
	current_thread_info()->times[current_thread_info()->times_index].type =
	    TRAP_TT;
	INCR_KERNEL_TIMES_COUNT(current_thread_info());
	trap_times->start = clock;
	trap_times->ctpr1 = NATIVE_NV_READ_CR1_LO_REG_VALUE();
	trap_times->ctpr2 = NATIVE_NV_READ_CR0_HI_REG_VALUE();
	trap_times->pshtp = NATIVE_NV_READ_PSHTP_REG();
	trap_times->psp_ind = NATIVE_NV_READ_PSP_HI_REG().PSP_hi_ind;
	E2K_SAVE_CLOCK_REG(trap_times->pt_regs_set);
#endif /* CONFIG_KERNEL_TIMES_ACCOUNT */

	AW(regs->flags) = 0;
	init_guest_traps_handling(regs, true /* user mode trap */);

	/*
	 * Put some distance between reading AASR (above) and using it here
	 * since reading of AAU registers is slow.
	 */
	aasr = aasr_parse(aasr);
	regs->aasr = aasr;
	/* We cannot rely on %aasr value since interception could have
	 * happened in guest user before "bap" or in guest trap handler
	 * before restoring %aasr, so we must save all AAU registers.
	 * Several macroses use %aasr to determine, which registers to
	 * save/restore, so pass worst-case %aasr to them directly
	 * while saving the actual guest value to regs->aasr. */
	if (IS_ENABLED(CONFIG_KVM_PARAVIRTUALIZATION) &&
	    test_ts_flag(TS_HOST_AT_VCPU_MODE))
		aasr = E2K_FULL_AASR;

	if (aau_has_state(aasr)) {
		aau_regs = __builtin_alloca(sizeof(*aau_regs));
		NATIVE_SAVE_AAU_MASK_REGS(aau_regs, aasr);
	} else {
		aau_regs = NULL;
	}
	regs->aau_context = aau_regs;

	/*
	 * %sbbp LIFO stack is unfreezed by writing %TIR register,
	 * so it must be read before TIRs.
	 */
	save_sbbp(trap->sbbp);

	/*
	 * Now we can store all needed trap context into the
	 * current pt_regs structure
	 */

	read_ticks(clock1);
	exceptions = save_tirs(trap->TIRs, &trap->nr_TIRs, &trap->usincr, false);
	info_save_tir_reg(clock1);

	if (exceptions & have_tc_exc_mask) {
		NATIVE_SAVE_TRAP_CELLAR(regs, trap);
	} else {
		trap->curr_cnt = 0;	/* reset to preserve against negative value */
		trap->tc_count = 0;
	}

	read_ticks(clock1);
	NATIVE_SAVE_STACK_REGS(regs, true, true);
	info_save_stack_reg(clock1);

	/* It's important to save AAD before all call operations. */
	if (unlikely(aasr.iab))
		NATIVE_SAVE_AADS(aau_regs);

	/*
	 * If AAU fault happened read aalda/aaldi/aafstr here,
	 * before some call zeroes them.
	 */
	if (unlikely(trap->TIRs[0].aa))
		aau_regs->aafstr = native_read_aafstr_reg_value();

	/*
	 * Function calls are allowed from this point on, mark it with
	 * a compiler barrier (but see CPU_HWBUG_L1I_RBRANCH_CALLS below).
	 */
	barrier();

	/* Since iset v6 %aaldi must be saved too. */
	if (machine.native_iset_ver >= E2K_ISET_V6 && unlikely(aau_stopped(aasr)))
		save_aaldi(aau_regs->aaldi);

	/*
	 * No atomic/DAM/call operations are allowed before this point.
	 * Note that we cannot do this before saving AAU.
	 */
	if (cpu_has(CPU_HWBUG_L1I_RBRANCH_CALLS))
		E2K_DISP_CTPRS();

	/* Rarely issues a function call */
	raw_get_mmu_pid_irqs_off(&current->mm->context, MMU_PID_RELOAD_CHECK);

	/* un-freeze the TIR's LIFO. Tracing can issue a call
	 * here so we cannot do it earlier. */
	if (trace_tir_ip_trace_enabled() && rcu_is_watching()) {
		int i;
		for (i = 1; i <= TIR_TRACE_PARTS; i++)
			trace_tir_ip_trace(i);
	}
	native_unfreeze_TIRS();

	/* Move user's scratch gregs to final destination */
	copy_local_gregs(&current->thread.u_gregs, &current->thread.tmp_gregs);

	/* Restore some host context if trap is on guest.
	 * This uses function calls so cannot be called earlier. */
	trap_guest_exit(current_thread_info(), regs, trap, 0);

	info_save_mmu_reg(clock1);

#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	if (unlikely(TASK_IS_BINCO(current))) {
		e2k_rpr_t rpr = native_read_RPR_reg();
		e2k_cr0_t cr0 = regs->crs.cr0;

		machine.get_and_invalidate_MLT_context(&trap->mlt_state);

		/* Check if this was a trap in generations mode. */
		if (rpr.ip && get_cr0_ip(cr0) >= current_thread_info()->rp_start &&
		    get_cr0_ip(cr0) < current_thread_info()->rp_end) {
			trap->rp = 1;
		}
	} else {
		trap->mlt_state.num = 0;
	}
#endif

	BUILD_BUG_ON(sizeof(enum ctx_state) != sizeof(trap->prev_state));
	trap->prev_state = exception_enter();

	if (aau_working(aasr))
		machine.get_aau_context(aau_regs, aasr);
#ifdef CONFIG_CLI_CHECK_TIME
	tt0_prolog_ticks(E2K_GET_DSREG(clkr) - start_tick);
#endif

	/*
	 * %pshtp/%pcshtp cannot be negative after entering kernel
	 */
	if (WARN_ON_ONCE((regs->stacks.pshtp.ind < 0) || (regs->stacks.pcshtp.ind < 0))) {
		local_irq_enable();
		native_write_irq_barrier_PSR_reg(E2K_KERNEL_PSR_ENABLED);
		do_exit(SIGKILL);
	}

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	/* Update run state info, if trap occured on guest kernel */
	SET_RUNSTATE_IN_USER_TRAP();
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	/*
	 * This will enable interrupts
	 */
	parse_TIR_registers(regs, exceptions);

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	/* Guest trap handling can be scheduled and migrate to other VCPU */
	/* see comments at arch/e2k/include/asm/process.h */
	/* So: */
	/* 1) host VCPU thread was changed and */
	/* 2) need update thread info and */
	/* 3) regs satructures pointers */
	UPDATE_VCPU_THREAD_CONTEXT(NULL, &thread_info, &regs, NULL, NULL);
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	finish_user_trap_handler(regs, FROM_USER_TRAP);
}

/*
 * We can only get here if either FILLC or FILLR isn't supported.
 * Otherwise finish_user_trap_handler_switched_hw_stacks is called directly.
 */
void notrace __noreturn finish_user_trap_handler_sw_fill(void)
{
	struct pt_regs *regs;
	struct trap_pt_regs *trap;
	restore_caller_t from;

	user_hw_stacks_restore__sw_sequel();

	from = current->thread.fill.from;

	regs = current_thread_info()->pt_regs;
	trap = regs->trap;

	finish_user_trap_handler_switched_hw_stacks(regs, trap, from);

	unreachable();
}

/*
 * Trap occured on kernel function and on kernel's stacks
 * So it does not need to switch to kernel stacks
 */
void notrace __irq_entry
kernel_trap_handler(struct pt_regs *regs, thread_info_t *thread_info)
{
	struct trap_pt_regs *trap;
	e2k_usd_t usd = regs->stacks.usd;
	e2k_psp_t psp;
	e2k_pcsp_t pcsp;
#if defined(CONFIG_KERNEL_TIMES_ACCOUNT) || defined(CONFIG_E2K_PROFILING)
	register u64 clock = native_read_CLKR_reg_value();
#endif /* CONFIG_KERNEL_TIMES_ACCOUNT */
	e2k_cr0_t cr0;
	e2k_cr1_t cr1;
	e2k_aau_t *aau_regs;
	e2k_aasr_t aasr;
#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	register trap_times_t *trap_times;
#endif /* CONFIG_KERNEL_TIMES_ACCOUNT */
	e2k_upsr_t upsr;
	u64 exceptions, nmi, hw_overflow, kstack_pf_addr;
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
#if	defined(CONFIG_VIRTUALIZATION) && !defined(CONFIG_KVM_GUEST_KERNEL)
	int to_save_runstate;
#endif /* CONFIG_VIRTUALIZATION && ! CONFIG_KVM_GUEST_KERNEL */
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	int hrdirqs_enabled = lockdep_hardirqs_enabled();
#ifdef CONFIG_CLI_CHECK_TIME
	register u64 start_tick = native_read_CLKR_reg_value();
#endif

	cpuhas_greg0 = cpu_features[0];
	cpuhas_greg1 = cpu_features[1];

	trap = pt_regs_to_trap_regs(regs);
	trap->upsr = read_UPSR_reg();
	trap->flags = 0;
	regs->trap = trap;

	/*
	 * We are not using ctpr2 here (compiling with -fexclude-ctpr2)
	 * thus reading of AASR, AALDV, AALDM can be done at any
	 * point before the first call.
	 *
	 * Usage of ctpr2 here is not possible since AALDA and AALDI
	 * registers would be zeroed.
	 *
	 * This is placed before saving trap cellar since it is done using
	 * 'mmurr' instruction which requires AAU to be stopped.
	 */
	aasr = native_read_aasr_reg();

	/*
	 * All actual pt_regs structures of the process are queued.
	 * The head of this queue is thread_info->pt_regs pointer,
	 * it points to the last (current) pt_regs structure.
	 * The current pt_regs structure points to the previous etc
	 * Queue is empty before first trap or system call on the
	 * any process and : thread_info->pt_regs == NULL
	 */
	regs->next = current_thread_info()->pt_regs;
	current_thread_info()->pt_regs = regs;
#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	trap_times = &(current_thread_info()->times[current_thread_info()->times_index].of.trap);
	current_thread_info()->times[current_thread_info()->times_index].type = TRAP_TT;
	INCR_KERNEL_TIMES_COUNT(current_thread_info());
	trap_times->start = clock;
	trap_times->ctpr1 = AW(native_read_CTPR1_reg());
	trap_times->ctpr2 = AW(native_read_CTPR2_reg());
	trap_times->ctpr3 = AW(native_read_CTPR3_reg());
	trap_times->pshtp = AW(native_read_PSHTP_reg());
	trap_times->psp_ind = native_read_PSP_reg().ind;
	E2K_SAVE_CLOCK_REG(trap_times->pt_regs_set);
#endif /* CONFIG_KERNEL_TIMES_ACCOUNT */

	AW(regs->flags) = 0;
	init_guest_traps_handling(regs, false /* user mode trap */);

	/*
	 * Put some distance between reading AASR (above) and using it here
	 * since reading of AAU registers is slow.
	 */
	aasr = aasr_parse(aasr);
	regs->aasr = aasr;
	if (aau_has_state(aasr)) {
		aau_regs = __builtin_alloca(sizeof(*aau_regs));
		NATIVE_SAVE_AAU_MASK_REGS(aau_regs, aasr);
	} else {
		aau_regs = NULL;
	}
	regs->aau_context = aau_regs;

	/*
	 * %sbbp LIFO stack is unfreezed by writing %TIR register,
	 * so it must be read before TIRs.
	 */
	save_sbbp(trap->sbbp);

	/*
	 * Now we can store all needed trap context into the
	 * current pt_regs structure
	 */
	read_ticks(clock);
	exceptions = save_tirs(trap->TIRs, &trap->nr_TIRs, &trap->usincr, false);
	nmi = exceptions & non_maskable_exc_mask;
	hw_overflow = unlikely(exceptions & (exc_chain_stack_bounds_mask |
					     exc_proc_stack_bounds_mask));
	info_save_tir_reg(clock);

	if (exceptions & have_tc_exc_mask) {
		kstack_pf_addr = NATIVE_SAVE_TRAP_CELLAR(regs, trap);
	} else {
		trap->tc_count = 0;
		kstack_pf_addr = 0;
	}
	read_ticks(clock);
	NATIVE_SAVE_STACK_REGS(regs, false, likely(!hw_overflow && !kstack_pf_addr));
	info_save_stack_reg(clock);

	/* It's important to save AAD before all call operations. */
	if (unlikely(aasr.iab)) {
		NATIVE_SAVE_AADS(aau_regs);
	}

	/*
	 * If AAU fault happened read aalda/aaldi/aafstr here,
	 * before some call zeroes them.
	 */
	if (unlikely(trap->TIRs[0].aa))
		aau_regs->aafstr = native_read_aafstr_reg_value();

	/*
	 * Function calls are allowed from this point on, mark it with
	 * a compiler barrier (but see CPU_HWBUG_L1I_RBRANCH_CALLS below).
	 */
	barrier();

	/* Since iset v6 %aaldi must be saved too. */
	if (machine.native_iset_ver >= E2K_ISET_V6 && unlikely(aau_stopped(aasr)))
		save_aaldi(aau_regs->aaldi);

	/*
	 * No atomic/DAM/call operations are allowed before this point.
	 * Note that we cannot do this before saving AAU.
	 */
	if (cpu_has(CPU_HWBUG_L1I_RBRANCH_CALLS))
		E2K_DISP_CTPRS();

	/*
	 * Even function calls under _false_ predicate will trigger
	 * hardware SPILL of chain stack.  Use special barrier to
	 * make sure such a spill does not mess emergency stack dump.
	 */
	if (unlikely(hw_overflow || kstack_pf_addr)) {
		switch_to_reserve_stacks();
		kernel_hw_stack_fatal_error(regs, exceptions, kstack_pf_addr);
	}
	barrier_calls();

	/* un-freeze the TIR's LIFO. Tracing can issue a call
	 * here so we cannot do it earlier. */
	if (trace_tir_ip_trace_enabled() && rcu_is_watching()) {
		int i;
		for (i = 1; i <= TIR_TRACE_PARTS; i++)
			trace_tir_ip_trace(i);
	}
	native_unfreeze_TIRS();

	/* Move kernel's scratch gregs to final destination */
	copy_scratch_gregs_from_local(&trap->k_gregs, &current->thread.tmp_gregs);

	psp = regs->stacks.psp;
	pcsp = regs->stacks.pcsp;

	/*
	 * We will switch interrupts control from PSR to UPSR
	 * _after_ we have handled all non-masksable exceptions.
	 * This is needed to ensure that a local_irq_save() call
	 * in NMI handler won't enable non-maskable exceptions.
	 */
	SAVE_INIT_KERNEL_IRQ_MASK_REG(false, true, AW(upsr));

	if (aau_working(aasr))
		machine.get_aau_context(aau_regs, aasr);

	if (is_kernel_data_stack_bounds(true /* trap on kernel */ , usd))
		kernel_data_stack_overflow();

#ifdef CONFIG_CLI_CHECK_TIME
	tt0_prolog_ticks(E2K_GET_DSREG(clkr) - start_tick);
#endif

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	/* Update run state info, if trap occured on guest kernel */
	SET_RUNSTATE_IN_KERNEL_TRAP(to_save_runstate);
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	/*
	 * This will enable non-maskable interrupts if (!nmi)
	 */
	parse_TIR_registers(regs, exceptions);

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	/* Guest trap handling can be scheduled and migrate to other VCPU */
	/* see comments at arch/e2k/include/asm/process.h */
	/* So: */
	/* 1) host VCPU thread was changed and */
	/* 2) need update thread info and */
	/* 3) regs satructures pointers */
	UPDATE_VCPU_THREAD_CONTEXT(NULL, &thread_info, &regs, NULL, NULL);
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

#ifdef CONFIG_PREEMPTION
	/*
	 * Check if we need preemption (the NEED_RESCHED flag could
	 * have been set by another CPU or by this interrupt handler).
	 *
	 * Don't do reschedule on NMIs - we do not want preempt_schedule_irq()
	 * to enable interrupts or local_irq_disable() to enable non-maskable
	 * interrupts. But there is one exception - if we received a maskable
	 * interrupt we must do a reschedule, otherwise we might lose it.
	 */
	if (preempt_count() == 0 && (!nmi || (exceptions & exc_interrupt_mask))) {
		if (unlikely(need_resched())
#ifdef CONFIG_PREEMPT_LAZY
			|| unlikely((current_thread_info()->preempt_lazy_count == 0
			    && test_thread_flag(TIF_NEED_RESCHED_LAZY)))
#endif
		) {
			unsigned long flags;
			raw_all_irq_save(flags);
			/* Check again under closed interrupts to avoid races */
			if (likely(need_resched()
#ifdef CONFIG_PREEMPT_LAZY
				    || ((current_thread_info()->preempt_lazy_count == 0)
					&& test_thread_flag(TIF_NEED_RESCHED_LAZY))
#endif
					)) {
				preempt_schedule_irq();
			}
			raw_all_irq_restore(flags);
		}
	}
#endif

	/* AAU in kernel is not supported */
	BUG_ON(aau_stopped(aasr));

	/*
	 * Return control from UPSR register to PSR, if UPSR interrupts
	 * control is used. DONE operation restores PSR state at trap
	 * point and recovers interrupts control
	 *
	 * This also disables all interrupts including NMIs.
	 */
	if (hrdirqs_enabled) {
		raw_all_irq_disable();
		trace_hardirqs_on();
	}
	RETURN_TO_KERNEL_IRQ_MASK_REG(upsr);

	NATIVE_CLEAR_APB();

	cr0 = regs->crs.cr0;
	cr1 = regs->crs.cr1;

	/*
	 * Hardware can lose singlestep flag on interrupt if it
	 * arrives earlier, so we must always manually reset it.
	 */
	if (cpu_has(CPU_HWBUG_SS) && test_ts_flag(TS_SINGLESTEP_KERNEL))
		cr1.ss = 1;

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	/* Update run state info, if trap occured on guest kernel */
	SET_RUNSTATE_OUT_KERNEL_TRAP(to_save_runstate);
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	/* Dequeue current pt_regs structure */
	current_thread_info()->pt_regs = regs->next;
	regs->next = NULL;

#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	trap_times->psp_to_done = native_read_PSP_reg();
	trap_times->pshtp_to_done = native_read_PSHTP_reg();
	trap_times->pcsp_to_done = native_read_PCSP_reg();
	trap_times->ctpr1_to_done = AW(regs->ctpr1);
	trap_times->ctpr2_to_done = AW(regs->ctpr2);
	trap_times->ctpr3_to_done = AW(regs->ctpr3);
	E2K_SAVE_CLOCK_REG(trap_times->end);
#endif /* CONFIG_KERNEL_TIMES_ACCOUNT */

	/* MMU registers must be written with not active CLW/AAU */
	uaccess_enable_in_kernel_trap(regs);

	machine.restore_scratch_gregs(&trap->k_gregs);

	write_cr(cr0, cr1);

	if (cpu_has(CPU_HWBUG_AAU_AALDV))
		__E2K_WAIT(_ma_c);
	if (aau_working(aasr)) {
		native_set_aau_context(aau_regs, current_thread_info()->aalda, aasr);

		/*
		 * It's important to restore AAD after
		 * all return operations.
		 */
		if (aasr.iab)
			NATIVE_RESTORE_AADS(aau_regs);
	}

	if (!cpu_has(CPU_FEAT_ATOMIC_LDRD) && regs->stacks.usd.P) {
		e2k_usd_t usd_value = read_USD_reg();
		usd_value.P = 1;
		usd_value.Psl += 1;
		write_USD_reg(usd_value);
	}

	TRAP_HANDLER_DONE(regs, 0, 0, NULL, E2K_DONE_ASM);
}

/***********************************************************************/

#ifdef CONFIG_PROTECTED_MODE
#include <linux/net.h>

int handle_futex_death(u32 __user *uaddr, struct task_struct *curr,
		       bool pi, bool pending_op);


/*
 * Fetch a PM robust-list pointer. Bit 0 signals PI futexes:
 */
static inline int
fetch_pm_robust_entry(long __user **entry, long __user *head,
		      unsigned int *pi)
{
	e2k_ptr_t descr;
	long addr;
	int tag;

	if (get_user_tagged_16(descr.qword, tag, head)) {
		pr_debug("%s failed with head == 0x%px\n", __func__, head);
		return -EFAULT;
	}

	if ((descr.lo == 0) && (descr.hi == 0) && (tag == ETAGNPQ)) {
		/* ignoring empty descriptor: */
		addr = 0;
	} else if (!IS_AP(descr, tag)) {
		goto err_out;
	} else {
		/* replacing descriptor with 64-bit pointer: */
		addr = AP_PTR(descr);
	}

	*pi = (unsigned int)addr & 1;
	if (put_user((addr & ~1), (long __user __force *)entry))
		goto err_out;

	return 0;

err_out:
	pr_debug(
	    "%s() failed with AP == <%x> 0x%llx : 0x%llx (head == 0x%px)\n",
	     __func__, tag, descr.lo, descr.hi, head);
	return -EFAULT;
}

static void __user *pm_futex_uaddr(long __user *entry, long futex_offset)
{
	compat_uptr_t base = (unsigned long) entry;
	void __user *uaddr = (void __user __force *)(base + futex_offset);

	return uaddr;
}

/*
 * Walk curr->robust_list (very carefully, it's a userspace list!)
 * and mark any locks found there dead, and notify any waiters.
 *
 * We silently return on any sign of list-walking problem.
 */
void pm_exit_robust_list(struct task_struct *curr)
{
	struct thread_info *ti = task_thread_info(curr);
	long __user *entry, *next_entry, *pending;
	long __user *head = (long __user *)e2k_ptr_objptr(ti->pm_robust_list, 0);
	unsigned int limit = ROBUST_LIST_LIMIT, pi, pip;
	unsigned int next_pi = 0;
	long futex_offset;
	int rc;

	/*
	 * Fetch the list head (which was registered earlier, via
	 * sys_set_robust_list()):
	 */
	if (fetch_pm_robust_entry(&entry, head, &pi))
		return;
	/*
	 * Fetch the relative futex offset.
	 * Note that structures being converted are aligned on 16
	 * byte boundary and have size being a multiple of 16. This is rather
	 * harmless as the FUTEX_OFFSET field in PM `struct robust_list_head'
	 * is aligned on 16 byte boundary and there's an 8-byte gap between it
	 * and the next LIST_OP_PENDING field, however, it makes sense to get
	 * rid of this limitation when (sub)structures containing no APs are
	 * converted.
	 */
	if (get_user(futex_offset, (long __user *)&head[2])) {
		pr_err("FATAL ERROR in %s:%d :\n\t\tError in %s(0x%lx): failed to read from 0x%lx !!!\n",
		     __FILE__, __LINE__, __func__, (uintptr_t) curr,
		     (uintptr_t) & head[2]);
		return;
	}

	/*
	 * Fetch any possibly pending lock-add first, and handle it
	 * if it exists:
	 */
	if (fetch_pm_robust_entry(&pending, &head[4], &pip))
		return;

	next_entry = NULL;	/* avoid warning with gcc */
	while (entry != head) {
		/*
		 * Fetch the next entry in the list before calling
		 * handle_futex_death:
		 */
		rc = fetch_pm_robust_entry(&next_entry, entry, &next_pi);
		/*
		 * A pending lock might already be on the list, so
		 * dont process it twice:
		 */
		if (entry != pending) {
			void __user *uaddr;
			uaddr = pm_futex_uaddr(entry, futex_offset);

			if (handle_futex_death(uaddr, curr, pi, false))
				return;
		}

		if (rc)
			return;

		entry = next_entry;
		pi = next_pi;
		/*
		 * Avoid excessively long or circular lists:
		 */
		if (!--limit)
			break;

		cond_resched();
	}
	if (pending) {
		void __user *uaddr = pm_futex_uaddr(pending, futex_offset);

		handle_futex_death(uaddr, curr, pip, true);
	}
}

/* Looks for arg number which defines the given arg min allowed size: */
static inline u8 get_size_arg_number(const int sys_num, const u8 argnum)
{
	long size;

	switch (argnum) {
	case 1:
		size = prot_syscall_arg_masks[sys_num].size1;
		break;
	case 2:
		size = prot_syscall_arg_masks[sys_num].size2;
		break;
	case 3:
		size = prot_syscall_arg_masks[sys_num].size3;
		break;
	case 4:
		size = prot_syscall_arg_masks[sys_num].size4;
		break;
	case 5:
		size = prot_syscall_arg_masks[sys_num].size5;
		break;
	case 6:
		size = prot_syscall_arg_masks[sys_num].size6;
		break;
	default:
		size = 0;
	}
	return (size < 0) ? -size : argnum;
}

#define MASK_PROT_ARG_LONG		0
#define MASK_PROT_ARG_DSCR		1
#define MASK_PROT_ARG_LONG_OR_DSCR	2
#define MASK_PROT_ARG_STRING		3
#define MASK_PROT_ARG_INT		4
#define MASK_PROT_ARG_FPTR		5
#define MASK_PROT_ARG_LONG_OR_STRING	6
#define MASK_PROT_ARG_INT_OR_STRING	7
#define MASK_PROT_ARG_INT_OR_DSCR	8
#define MASK_PROT_ARG_NOARG		0xf
#define MASK_PROT_NO_MORE_ARGS		0xff
#define MASK_PROT_ARG_NON_EMPTY		0x10 /* Argument must not be 0/NULL */
#define MASK_SET_U_BORDER		0x20 /* ARG is AP and call set_ap_u_border(AP) */
#define MASK_PROT_ARG_OPTIONAL		0x80
#define TAG_PROT_ARG_NOT_SBMTD		0x55 /* Argument was not submitted to syscal */
/* Bits of lower syscall mask byte (mask&0xff) : */
#define ADJUST_SIZE_MASK		1
#define NEGATIVE_DESCR_SIZE_MASK	2


static inline
unsigned long e2k_dscr_ptr_size(e2k_ptr_t dscr, long min_size, long *ptr_size,
				u16 sys_num, u8 argnum, long *fatal, u8 lower_byte_mask)
{
	/* NB> 'min_size' may be negative; this is why it has 'long' type */

	*ptr_size = AP_OBJ_SIZE(dscr);

#if DEBUG_1SYSCALL
	if (cpu_has(CPU_FEAT_ISET_V7))
		Dbg1SC("dscr=0x%llx:0x%llx sys_num=%d arg#%d minSize=0x%lx OBJ_SIZE=0x%lx\n",
			dscr.lo, dscr.hi,
			sys_num, argnum, min_size, *ptr_size);
	else
		Dbg1SC("dscr=0x%llx:0x%.8x.%.8x sys_num=%d arg#%d minSize=0x%lx OBJ_SIZE=0x%lx\n",
			dscr.lo, (u32)(dscr.hi >> 32), (u32)dscr.hi,
			sys_num, argnum, min_size, *ptr_size);
#endif /* DEBUG_1SYSCALL */

	if (min_size < 0) {
		argnum = get_size_arg_number(sys_num, argnum);
		PROTECTED_MODE_WARNING(PMSCERRMSG_NEGATIVE_SIZE_VALUE,
				       sys_num, sys_call_ID_to_name[sys_num],
				       min_size, argnum);
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, 0, EINVAL);
	} else if (likely(!cpu_has(CPU_FEAT_ISET_V7)) && unlikely(min_size >> 31)) {
		argnum = get_size_arg_number(sys_num, argnum);
		PROTECTED_MODE_WARNING(PMSCERRMSG_SC_ARGNUM_VAL_EXCEEDS_DSCR_MAX,
				     sys_num, sys_call_ID_to_name[sys_num],
				     min_size, argnum);
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, 0, EINVAL);
		*ptr_size = 0;
		*fatal = -EINVAL;
		return 0;
	} else if (unlikely(*ptr_size < 0 && (lower_byte_mask & NEGATIVE_DESCR_SIZE_MASK))) {
		PROTECTED_MODE_WARNING(PMSCWARN_NEGATIVE_DSCR_SIZE,
			     sys_num, sys_call_ID_to_name[sys_num], *ptr_size, argnum);
		if (unlikely(!check_pm_sc_debug_mode(PM_SC_DBG_MODE_NO_ERR_MESSAGES))
				&& check_pm_sc_debug_mode(PM_SC_DBG_WARNINGS))
			protected_mode_message(0, PMSCWARN_DSCR_COMPONENTS,
						dscr.lo, AP_SIZE(dscr), AP_IND(dscr));
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, 0, EINVAL);
		*ptr_size = 0;
		if (unlikely(check_pm_sc_debug_mode(PM_SC_DBG_WARNINGS_AS_ERRORS))) {
			*fatal = -EINVAL;
			return 0;
		}
	} else if (*ptr_size < min_size) {
		PROTECTED_MODE_ERROR(PMSCERRMSG_SC_ARG_SIZE_TOO_LITTLE,
				     sys_num, sys_call_ID_to_name[sys_num],
				     *ptr_size, min_size, argnum);
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, 0, EFAULT);
		*ptr_size = 0;
		*fatal = -EFAULT;
		return 0;
	}
	return AP_PTRC(dscr);
}

static inline int null_prot_ptr(u32 tag, u64 arg)
{
	return tag == E2K_NULLPTR_ETAG && !arg;
}

/*
 * This function takes couple of arguments to protected system call,
 * validates these, and outputs corresponding argument for kernel system call.
 * Arguments:
 * sys_num  - system call number;
 * tag      - actual argument tags packed (4 + 4 bits for lo/hi arg component);
 * mask     - system call mask (expected argument types);
 * a_num    - argument number in kernel system call;
 * protarg_lo/hi - protected argument couple;
 * min_size - minimum allowed argument-descriptor size (if known);
 * fatal    - signal to let caller know that this argument is wrong, and
 *                    it would be unsafe to proceed with the system call.
 */
static unsigned long get_protected_ARG(u64 sys_num, u8 tag, u64 mask,
				       u32 a_num, unsigned long protarg_lo,
				       unsigned long protarg_hi, long min_size,
				       long *fatal, struct pt_regs *regs)
{
	u8 msk = (mask >> (a_num * 8)) & 0xff;
	u8 msk_type = msk & 0xf;
	unsigned long ptr;	/* the result */
	long size;
	u32 tag_lo = tag & 0xf;
	u32 optional_arg = msk & MASK_PROT_ARG_OPTIONAL;
	char arg[4] = "#0";
	e2k_ap_t ap_arg = (e2k_ap_t){.lo = protarg_lo, .hi = protarg_hi};

	if (msk_type == MASK_PROT_ARG_NOARG) {
		return 0L;	/* this is not effective syscall arg */
	} else if (tag == ETAGDWQ) {
		if (!optional_arg) {
			arg[1] = '0' + a_num;	/* string # of the argument: "#1" .. "#6" */
			PROTECTED_MODE_WARNING(PMSCERRMSG_SC_WRONG_ARG_VALUE_LX_TAG,
			     sys_call_ID_to_name[regs->sys_num], arg,
			     protarg_lo, tag);
			if (IF_PM_DBG_MODE(PM_SC_DBG_ISSUE_WARNINGS))
				protected_mode_message(0,
						       PMSCERRMSG_SC_ARG_MISSED_OR_UNINIT,
						       a_num);
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, 0, EINVAL);
		}
		return 0L;	/* arg was not passed or irrelevant */
	}

	Dbg1SC("[%d](SC#%lld, tag=0x%x, msk=0x%x, arg=0x%lx:0x%lx, min_size=%lx)\n",
		a_num, sys_num, tag, msk, protarg_lo, protarg_hi, min_size);

	if (msk_type == MASK_PROT_ARG_LONG_OR_DSCR) {
		msk_type = IS_AP(ap_arg, tag) ? MASK_PROT_ARG_DSCR : MASK_PROT_ARG_LONG;
	} else if (unlikely(msk_type == MASK_PROT_ARG_INT_OR_DSCR)) {
		msk_type = IS_AP(ap_arg, tag) ? MASK_PROT_ARG_DSCR : MASK_PROT_ARG_INT;
	} else if (unlikely(msk_type == MASK_PROT_ARG_LONG_OR_STRING
				|| msk_type == MASK_PROT_ARG_INT_OR_STRING)) {
		if (IS_AP(ap_arg, tag))
			msk_type = MASK_PROT_ARG_STRING;
		else
			msk_type = (msk_type == MASK_PROT_ARG_LONG_OR_STRING) ?
						MASK_PROT_ARG_LONG : MASK_PROT_ARG_INT;
	}

	if (!optional_arg && !protarg_lo && (msk & MASK_PROT_ARG_NON_EMPTY)) {
		arg[1] = '0' + a_num; /* string # of the argument: "#1" .. "#6" */
		PROTECTED_MODE_ERROR(PMSCERRMSG_SC_ARG_VAL_UNSUPPORTED,
				     sys_call_ID_to_name[regs->sys_num], arg, 0);
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, 0, EINVAL);
		*fatal = -EINVAL;
	}

	if (((msk_type == MASK_PROT_ARG_INT) || (msk_type == MASK_PROT_ARG_LONG))
		/* The check below does the following:
		 * - in the current ABI syscall argument takes 4 words (16 bytes);
		 * - if syscall argument is of type 'int' or 'long', then only lowest word (word #0)
		 *   gets filled by compiler if arg size allows, while other 3 words rest untouched
		 *   and may contain trash (inherited from previous call);
		 * - if tag of the lowest word is numeric one (i.e. '0'), then
		 *   this argument is definitely of type 'int' and
		 * - we can zero the word #1 to make next checks simpler.
		 */
		&& tag_lo && !(tag_lo & 0x3)) { /* numerical tag in lo-word; trash in hi-word */
		/* this is 'int' argument */
		tag_lo &= 0x3;
		tag = tag_lo;
		protarg_lo = (int) protarg_lo; /* removing trash in higher word */
		msk_type = MASK_PROT_ARG_INT;
	}

#if DEBUG_SYSCALLP_CHECK
	if (optional_arg && ((tag_lo == ETAGDWD) || (tag_lo == ETAGDWS))) {
		return 0L; /* optional arg was not passed or irrelevant */
	} else if ((tag != ETAGDWQ) && (tag_lo != ETAGNUM)
			&& (tag != ETAGAPQ) && (tag != ETAGPL)) {
		DbgSCP("tag=0x%x tag_lo=0x%x msk=0x%x a_num=%d\n",
		       tag, tag_lo, (int)msk, a_num);
		PROTECTED_MODE_ERROR(PMSCERRMSG_UNEXP_ARG_TAG_ID,
			sys_num, sys_call_ID_to_name[sys_num], (u8)tag, a_num);
		if (((tag == ETAGDWD)
				&& ((msk_type == MASK_PROT_ARG_LONG)
					|| (msk_type == MASK_PROT_ARG_INT)))
				|| ((tag == ETAGDWS) && (msk_type == MASK_PROT_ARG_INT)))
			protected_mode_message(0,
					PMSCERRMSG_SC_ARG_MISSED_OR_UNINIT,
					a_num);
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, 0, EINVAL);
		*fatal = -EINVAL;
		return 0L; /* uninitialized or missed arg must me zeroed */
	}
#endif /* DEBUG_SYSCALLP_CHECK */

	if (IS_PL(ap_arg, tag)) {
		e2k_pl_t pl;

		if (msk_type != MASK_PROT_ARG_FPTR) {
			PROTECTED_MODE_ERROR(PMSCERRMSG_SC_UNEXPECTED_FUNC_IN_ARG,
					sys_num, sys_call_ID_to_name[sys_num], tag, a_num);
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, 0, EINVAL);
			*fatal = -EINVAL;
		} else if (cpu_has(CPU_FEAT_ISET_V6)) {
			int cui;
			/* Checking for correct CUI: */
			pl.qword = ap_arg.qword;
			cui = find_cui_by_ip(pl.target);
			if (cui < 0) {
				PROTECTED_MODE_ERROR(PMSCERRMSG_CUI_NOT_FOUND,
						sys_num, sys_call_ID_to_name[sys_num],
						(unsigned long)pl.target);
				PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, 0, EINVAL);
				*fatal = 1;
			} else if (cui != pl.cui) {
				PROTECTED_MODE_ERROR(PMSCERRMSG_CUI_MISMATCH_IN_PL_IP,
						sys_num, sys_call_ID_to_name[sys_num],
						(unsigned long)pl.target, pl.cui, cui);
				PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, 0, EINVAL);
				*fatal = 1;
			}
			return pl.target;
		} else {
			LO(pl) = protarg_lo;
			return pl.target;
		}
	}

	/* First, we check if the argument is non-pointer: */
	if (!IS_AP(ap_arg, tag)) {
		unsigned long ret = (tag == ETAGDWQ) ? 0 : protarg_lo;

		if (unlikely(!AP_NULL(ap_arg, tag) &&
			     (msk_type == MASK_PROT_ARG_DSCR ||
			      msk_type == MASK_PROT_ARG_STRING))) {
			if (PM_SYSCALL_WARN_ONLY == 0)
				*fatal = -EINVAL;
			DbgSCP("tag=0x%x tag_lo=0x%x msk=0x%x protarg_lo=0x%lx\n",
			     tag, tag_lo, (int)msk, protarg_lo);
			PROTECTED_MODE_ERROR(PMSCERRMSG_NOT_DESCR_IN_SC_ARG,
					     sys_num,
					     sys_call_ID_to_name[sys_num],
					     a_num);
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, 0, EINVAL);
		}

		return ret;
	}

	/* Finally, this is descriptor; getting pointer from it: */
	if (msk & MASK_SET_U_BORDER) {
		set_ap_u_border(ap_arg);
		ptr = AP_PTR(ap_arg);
		goto return_ptr;
	}
	ptr = e2k_dscr_ptr_size(ap_arg, min_size, &size,
				sys_num, a_num, fatal, mask & 0xff);

	/* Second, we check if the argument is string: */
	if (msk_type == MASK_PROT_ARG_STRING) {
		if (e2k_ptr_str_check((char __user *)ptr, size)) {
			if (PM_SYSCALL_WARN_ONLY == 0)
				*fatal = -EINVAL;
			PROTECTED_MODE_ERROR(PMSCERRMSG_NOT_STRING_IN_SC_ARG,
					     sys_num,
					     sys_call_ID_to_name[sys_num],
					     a_num);
		}
	} else {
		/* Eventually, we check if this is proper pointer: */
		if (unlikely(sys_num && msk_type != MASK_PROT_ARG_DSCR)) {
			if (PM_SYSCALL_WARN_ONLY == 0)
				*fatal = -EINVAL;
			PROTECTED_MODE_ERROR
			    (PMSCERRMSG_UNEXPECTED_DESCR_IN_SC_ARG, sys_num,
			     sys_call_ID_to_name[sys_num], a_num);
		}
	}
	if (*fatal)
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, 0, EINVAL);
return_ptr:
	return ptr;
}

static inline
long check_arg_descr_size(int sys_num, int arg_num, int neg_size,
			 struct pt_regs *regs, u64 mask)
/* In case of negative size in syscall argument mask,
 * calculate effective argument size and update args3-7
 * If ((neg_size < 0) && adjust_bufsize) :
 *	if calculated descriptor size exceeds the defined max value,
 *	decrease corresponding argument count down to the given max size.
 */
{
	long size, descr_size, index;
	int adjust_bufsize;
	u8 msk;

	if (((regs->tags >> (arg_num * 8)) & 0xff) == ETAGAPQ)
		adjust_bufsize = mask & ADJUST_SIZE_MASK;
	else
		adjust_bufsize = 0; /* this is not descriptor */

	if (neg_size >= 0) {
		pr_alert("FATAL: bad 'neg_size' (%d) at %s:%d !!!\n",
			 neg_size, __FILE__, __LINE__);
		return neg_size; /* nothing to do with this */
	}

	index = -neg_size*2 - 1;
	msk = (mask >> (index * 8)) & 0xf;
	size = (msk == MASK_PROT_ARG_INT) ? (long)(int)regs->dargs[index-1] : regs->dargs[index-1];
	if (!adjust_bufsize)
		return size;

	descr_size = AP_OBJ_SIZE(regs->qargs[arg_num - 1]);

	if (likely(descr_size >= size))
		return size;

	/* Requested size appeared bigger than descriptor size.
	 * Adjusting the requested size value:
	 */
	PROTECTED_MODE_ERROR(PMSCERRMSG_COUNT_EXCEEDS_DESCR_SIZE,
			     sys_num, sys_call_ID_to_name[sys_num],
			     size, descr_size, arg_num);
	if (PM_SYSCALL_WARN_ONLY && adjust_bufsize)
		protected_mode_message(0, PMSCERRMSG_SC_ARG_COUNT_TRUNCATED,
				       descr_size);
	else
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, 0, EINVAL);
	size = descr_size;

	if (PM_SYSCALL_WARN_ONLY == 0) {
		e2k_ap_t ap = regs->qargs[arg_num - 1];
		PROTECTED_MODE_WARNING(PMSCERRMSG_EXECUTION_TERMINATED,
				       current->pid, current->comm, EINVAL);
		force_sig_bnderr(U_AP_PTR(ap),
				 (void __user __force *)AP_BASE(ap),
				 (void __user __force *)(AP_BASE(ap) + AP_SIZE(ap)));
	}

	return size;
}

#if 0
#define SC_MASK_ARRAY_2PRINT 999
static inline void print_prot_syscall_arg_masks(int sys_num)
{
	int i;

	if (!IF_PM_DBG_MODE(PM_SC_DBG_ISSUE_WARNINGS)
	    || sys_num != SC_MASK_ARRAY_2PRINT)
		return;
	pr_info("\n\n##### prot_syscall_arg_masks[%d]: #####\n", NR_syscalls);
	for (i = 0; i <= NR_syscalls; i++) {
		if (sys_call_table_entry8[i] ==
		    (protected_system_call_func) (void *) sys_ni_syscall) {
			pr_info("NR#%d\t[%s]\t\t >>>sys_ni_syscall<<<\n", i,
				sys_call_ID_to_name[i]);
			continue;
		}
		if (prot_syscall_arg_masks[i].size1
		    || prot_syscall_arg_masks[i].size2
		    || prot_syscall_arg_masks[i].size3
		    || prot_syscall_arg_masks[i].size4
		    || prot_syscall_arg_masks[i].size5
		    || prot_syscall_arg_masks[i].size6)
			pr_info("NR#%d\t[%s]\t0x%llx\t [%d:%d:%d:%d:%d:%d]\n",
				i, sys_call_ID_to_name[i],
				prot_syscall_arg_masks[i].mask,
				prot_syscall_arg_masks[i].size1,
				prot_syscall_arg_masks[i].size2,
				prot_syscall_arg_masks[i].size3,
				prot_syscall_arg_masks[i].size4,
				prot_syscall_arg_masks[i].size5,
				prot_syscall_arg_masks[i].size6);
		else
			pr_info("NR#%d\t[%s]\t0x%llx\n",
				i, sys_call_ID_to_name[i],
				prot_syscall_arg_masks[i].mask);
	}
}
#else
#define print_prot_syscall_arg_masks(...)
#endif

static inline
void report_unsupported_prot_syscall(int sys_num)
{
	PROTECTED_MODE_ERROR(PMSCERRMSG_SC_NOT_AVAILABLE_IN_PM,
			     sys_num, SYSCALL_NAME_ON_ID(sys_num));
	if (sys_num < NR_syscalls)
		print_prot_syscall_arg_masks(sys_num);
}

/**
 * add_arg_to_dbg_msg() - Adding debug print of the next syscall arg contents.
 * @msg: message buffer.
 * @length: current message length.
 * @arg: argument value.
 * @msg_max_len: if 'msg' lengths exceeds this number, add new line.
 * @tag: argument tag.
 * @mask: argument type mask.
 * @arg_num: argument ordinal.
 * @regs: pointer to 'struct pt_regs'.
 * Return: total message length.
 */
static inline
int add_arg_to_dbg_msg(char *msg, int length, int msg_max_len,
		       unsigned long arg, u64 mask, int tag, int arg_num, struct pt_regs *regs)
{
	u8 msk = (mask >> (arg_num * 8)) & 0xff;
	u8 msk_type = msk & 0xf;
	int line_num = length / msg_max_len;
	int ret;

	ret = sprintf(&msg[length], "0x%lx", arg);
	if (ret <= 0)
		goto err_out;
	length += ret;
	if (arg && (tag == ETAGAPQ) &&
			(msk_type == MASK_PROT_ARG_STRING ||
			msk_type == MASK_PROT_ARG_LONG_OR_STRING ||
			mask == MASK_PROT_ARG_INT_OR_STRING)) {
		char *kstr =  strcopy_from_user_prot_arg((char __user *) arg, regs, arg_num);

		ret = sprintf(&msg[length], " \"%s\"", kstr);
		if (ret <= 0)
			goto err_out;
		length += ret;
		kfree(kstr);
	}
	if (arg_num < 6) {
		msg[length++] = ',';
		msg[length++] = ' ';
	}
	if ((length / msg_max_len) > line_num) { /* adding new line to the output */
		msg[length++] = '\n';
		msg[length++] = '\t';
		msg[length++] = '\t';
	}
	return length;

err_out:
	pr_err("%s:%d : %s//sprintf() failed with error code (%d)\n",
	       __FILE__, __LINE__, __func__, ret);
	return length;
}

__section(".entry.text")
SYS_RET_TYPE notrace ttable_entry8_C(u64 sys_num, u64 tags, long arg1,
		long arg2, long arg3, long arg4, struct pt_regs *regs)
{
	long rval = -EINVAL;
	long arg5 = regs->dargs[4], arg7 = regs->dargs[6], arg9 = regs->dargs[8];
	unsigned long a1, a2, a3, a4, a5, a6;
	protected_system_call_func sys_call = (protected_system_call_func) (void *) sys_ni_syscall;
	unsigned long ti_flags = current_thread_info()->flags;
	u64 mask = 0;
	long size1 = 0, size2 = 0, size3, size4;
	u16 size5, size6;
	long wrong_res = 0;	/* signal that an argument detected wrong */
#ifdef CONFIG_E2K_PROFILING
	register long start_tick = native_read_CLKR_reg_value();
	register long clock1;
#endif

	init_pt_regs_for_syscall(regs);
	on_kernel_entry();

	raw_get_mmu_pid_irqs_off(&current->mm->context, MMU_PID_RELOAD_CHECK);
	SAVE_STACK_REGS(regs, true, false);
	regs->sys_num = sys_num;
	regs->return_desk = 0;

	/* Important: this must be before the first call
	 * but after saving %wd register.
	 */
	if (cpu_has(CPU_HWBUG_VIRT_PSIZE_INTERCEPTION)) {
		e2k_wd_t wd = read_WD_reg();
		wd.psize = 0x40;
		write_WD_reg(wd);
	}
#ifdef CONFIG_E2K_PROFILING
	read_ticks(clock1);
	info_save_stack_reg(clock1);
#endif

	/* Must be done before opening interrupts: we want kernel to
	 * always have proper pt_regs, even in kernel trap handler. */
	current_thread_info()->pt_regs = regs;
	native_write_irq_barrier_PSR_reg(E2K_KERNEL_PSR_ENABLED);

	/* All other arguments have been saved in assembler already */
	regs->dargs[0] = arg1;
	regs->dargs[1] = arg2;
	regs->dargs[2] = arg3;
	regs->dargs[3] = arg4;
	regs->tags = tags;

	a1 = a2 = a3 = a4 = a5 = a6 = ULONG_MAX;
	if (unlikely(ti_flags & _TIF_WORK_SYSCALL_TRACE)) {
		wrong_res = syscall_trace_entry(regs);
		if (regs->kernel_entry != 8)
			BUG();
		if (wrong_res) {
			syscall_trace_leave(regs);
			goto wrong_res;
		}
		sys_num = regs->sys_num;
	}

	if (sys_num < NR_syscalls) {
		sys_call = sys_call_table_entry8[sys_num];
		mask = prot_syscall_arg_masks[sys_num].mask;
		if (!mask)
			mask = prot_syscall_arg_masks[NR_syscalls].mask;
		size1 = prot_syscall_arg_masks[sys_num].size1;
		size2 = prot_syscall_arg_masks[sys_num].size2;
	}
	if (sys_call == (protected_system_call_func) (void *) sys_ni_syscall) {
		report_unsupported_prot_syscall(sys_num);
		wrong_res = -ENOSYS;
		goto wrong_res;
	}
	if (check_pm_sc_debug_mode(PM_SC_DBG_MODE_DEBUG) &&
			((mask >> 8) & 0xff) != MASK_PROT_NO_MORE_ARGS) {
		u64 arg_tag = tags >> 8;
		u64 arg_msk = mask >> 8;
		if ((arg_msk & 0xff) == MASK_PROT_NO_MORE_ARGS ||
			(arg_msk & MASK_PROT_ARG_OPTIONAL &&
			(arg_tag & 0xff) == TAG_PROT_ARG_NOT_SBMTD))
			goto end_of_args;
		/* Checking if there is a descriptor in args: */
		if ((arg_tag & 0xff) == ETAGAPQ) /* arg1-2 */
			pr_info("\nsys_num = %lld tags = 0x%llx:\n\t\targ1 = 0x%lx, arg2 = 0x%.8x.%.8x",
				sys_num, tags, arg1, (u32)(arg2 >> 32), (u32)arg2);
		else
			pr_info("\nsys_num = %lld tags = 0x%llx: arg1 = 0x%lx, arg2 = 0x%lx",
				sys_num, tags, arg1, arg2);

		arg_tag >>= 8;
		arg_msk >>= 8;
		if ((arg_msk & 0xff) == MASK_PROT_NO_MORE_ARGS ||
			(arg_msk & MASK_PROT_ARG_OPTIONAL &&
			(arg_tag & 0xff) == TAG_PROT_ARG_NOT_SBMTD))
			goto end_of_args;
		if ((arg_tag & 0xff) == ETAGAPQ) /* arg3-4 */
			pr_info("\t\targ3 = 0x%lx, arg4 = 0x%.8x.%.8x ",
				arg3, (u32)(arg4 >> 32), (u32)arg4);
		else
			pr_info("\t\targ3 = 0x%lx, arg4 = 0x%lx ", arg3, arg4);
		arg_tag >>= 8;
		arg_msk >>= 8;
		if ((arg_msk & 0xff)  == MASK_PROT_NO_MORE_ARGS ||
			(arg_msk & MASK_PROT_ARG_OPTIONAL &&
			(arg_tag & 0xff) == TAG_PROT_ARG_NOT_SBMTD))
			goto end_of_args;
		if ((arg_tag & 0xff) == ETAGAPQ) /* arg5-6 */
			pr_cont("\n\t\targ5 = 0x%lx, arg6 = 0x%.8x.%.8x ",
				arg5, (u32)(regs->dargs[5] >> 32), (u32)regs->dargs[5]);
		else
			pr_cont("arg5 = 0x%lx, arg6 = 0x%lx ", arg5, regs->dargs[5]);

		arg_tag >>= 8;
		arg_msk >>= 8;
		if ((arg_msk & 0xff) == MASK_PROT_NO_MORE_ARGS ||
			(arg_msk & MASK_PROT_ARG_OPTIONAL &&
			(arg_tag & 0xff) == TAG_PROT_ARG_NOT_SBMTD))
			goto end_of_args;
		if ((arg_tag & 0xff) == ETAGAPQ) /* arg7-8 */
			pr_cont("\n\t\targ7 = 0x%lx, arg8 = 0x%.8x.%.8x ",
				arg7, (u32)(regs->dargs[7] >> 32), (u32)regs->dargs[7]);
		else
			pr_cont("arg7 = 0x%lx, arg8 = 0x%lx ", arg7, regs->dargs[7]);
		arg_tag >>= 8;
		arg_msk >>= 8;
		if ((arg_msk & 0xff) == MASK_PROT_NO_MORE_ARGS ||
			(arg_msk & MASK_PROT_ARG_OPTIONAL &&
			(arg_tag & 0xff) == TAG_PROT_ARG_NOT_SBMTD))
			goto end_of_args;
		if ((arg_tag & 0xff) == ETAGAPQ) /* arg9-10 */
			pr_cont("\n\t\targ9 = 0x%lx, arg10 = 0x%.8x.%.8x ", arg9,
				(u32)(regs->dargs[9] >> 32), (u32)regs->dargs[9]);
		else
			pr_cont("arg9 = 0x%lx, arg10 = 0x%lx ", arg9, regs->dargs[9]);

		arg_tag >>= 8;
		arg_msk >>= 8;
		if ((arg_msk & 0xff) == MASK_PROT_NO_MORE_ARGS ||
			(arg_msk & MASK_PROT_ARG_OPTIONAL &&
			(arg_tag & 0xff) == TAG_PROT_ARG_NOT_SBMTD))
			goto end_of_args;
		if ((arg_tag & 0xff) == ETAGAPQ) /* arg11-12 */
			pr_cont("\n\t\targ11 = 0x%lx, arg12 = 0x%.8x.%.8x\n", regs->dargs[10],
				(u32)(regs->dargs[11] >> 32), (u32)regs->dargs[11]);
		else
			pr_cont(" arg11 = 0x%lx, arg12 = 0x%lx\n",
				regs->dargs[10], regs->dargs[11]);
end_of_args:
		pr_info("_NR_ %lld/%s start: mask=0x%llx current %px pid %d",
			sys_num, SYSCALL_NAME_ON_ID(sys_num), mask, current, current->pid);
	}
	if (size1 < 0)
		size1 = check_arg_descr_size(sys_num, 1, size1, regs, mask);
	size3 = prot_syscall_arg_masks[sys_num].size3;
	if (size3 < 0)
		size3 = check_arg_descr_size(sys_num, 3, size3, regs, mask);
	size4 = prot_syscall_arg_masks[sys_num].size4;
	if (size4 < 0)
		size4 = check_arg_descr_size(sys_num, 4, size4, regs, mask);
	size5 = prot_syscall_arg_masks[sys_num].size5;
	/* So far we don't have negative size in the 5th row.
	 * To be added in the future if needed:
	 if (size5 < 0)
	 size5 = regs->args[-size5];
	 */
	if (size2 < 0)
		size2 = check_arg_descr_size(sys_num, 2, size2, regs, mask);
	size6 = prot_syscall_arg_masks[sys_num].size6;
	/* So far we don't have negative size in the 6th row.
	 * To be added in the future if needed:
	if (size6 < 0)
		size6 = regs->args[-size6];
	 */
	a1 = get_protected_ARG(sys_num, (regs->tags >> 8) & 0xffU, mask, 1,
	       regs->dargs[0], regs->dargs[1], size1, &wrong_res, regs);
	if (wrong_res)
		goto wrong_res;
	a2 = get_protected_ARG(sys_num, (regs->tags >> 16) & 0xffU, mask, 2,
		       regs->dargs[2], regs->dargs[3], size2, &wrong_res, regs);
	if (wrong_res)
		goto wrong_res;
	a3 = get_protected_ARG(sys_num, (regs->tags >> 24) & 0xffU, mask, 3,
		       regs->dargs[4], regs->dargs[5], size3, &wrong_res, regs);
	if (wrong_res)
		goto wrong_res;
	a4 = get_protected_ARG(sys_num, (regs->tags >> 32) & 0xffU, mask, 4,
		       regs->dargs[6], regs->dargs[7], size4, &wrong_res, regs);
	if (wrong_res)
		goto wrong_res;
	a5 = get_protected_ARG(sys_num, (regs->tags >> 40) & 0xffU, mask, 5,
		       regs->dargs[8], regs->dargs[9], size5, &wrong_res, regs);
	if (wrong_res)
		goto wrong_res;
	a6 = get_protected_ARG(sys_num, (regs->tags >> 48) & 0xffU, mask, 6,
		       regs->dargs[10], regs->dargs[11], size6, &wrong_res, regs);
	if (wrong_res)
		goto wrong_res;
wrong_res:

#if DEBUG_1SYSCALL
	Dbg1SC(sys_num, "system call %lld (0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx) expected res = %ld\n",
			sys_num, a1, a2, a3, a4, a5, a6, wrong_res);
#else
	if (check_pm_sc_debug_mode(PM_SC_DBG_MODE_COMPLEX_WRAPPERS) &&
		current->mm->context.pm_sc_debug_mode & PM_SC_DBG_STRING_ARGS) {
		char bufstr[512];
		int msglen;
		char *msg = bufstr;
#define DBG_MSG_LEN_LIMIT 80

		msglen = add_arg_to_dbg_msg(msg, 0, DBG_MSG_LEN_LIMIT, a1, mask,
					    (tags >> 8) & 0xffUL, 1, regs);
		msglen = add_arg_to_dbg_msg(msg, msglen, DBG_MSG_LEN_LIMIT, a2,
					    mask, (tags >> 16) & 0xffUL, 2, regs);
		msglen = add_arg_to_dbg_msg(msg, msglen, DBG_MSG_LEN_LIMIT, a3,
					    mask, (tags >> 24) & 0xffUL, 3, regs);
		msglen = add_arg_to_dbg_msg(msg, msglen, DBG_MSG_LEN_LIMIT, a4,
					    mask, (tags >> 32) & 0xffUL, 4, regs);
		msglen = add_arg_to_dbg_msg(msg, msglen, DBG_MSG_LEN_LIMIT, a5,
					    mask, (tags >> 40) & 0xffUL, 5, regs);
		msglen = add_arg_to_dbg_msg(msg, msglen, DBG_MSG_LEN_LIMIT, a6,
					    mask, (tags >> 48) & 0xffUL, 6, regs);
		DbgSCPanon("system call %lld %s(%s)\n",
			   sys_num, sys_call_ID_to_name[sys_num], msg);
	} else {
		DbgSCPanon("system call %lld %s(0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx)\n",
			   sys_num, SYSCALL_NAME_ON_ID(sys_num), a1, a2, a3, a4, a5, a6);
	}
#endif
	if (likely(!wrong_res)) {
		/* syscall_trace_entry was called above if _TIF_WORK_SYSCALL_TRACE */
		rval = sys_call(a1, a2, a3, a4, a5, a6, regs);
		regs->sys_rval = rval;
		if (unlikely(ti_flags & _TIF_WORK_SYSCALL_TRACE)) {
			/* Trace syscall exit */
			syscall_trace_leave(regs);
			/* Update rval, since tracer could have changed it */
			rval = regs->sys_rval;
		}
	} else { /* (unlikely(wrong_res)) */

		rval = wrong_res;
		regs->sys_rval = rval;
	}
#if DEBUG_1SYSCALL
	Dbg1SC(sys_num, "syscall %lld : rval = 0x%lx / %ld\n", sys_num, rval,
	       rval);
#else
	if (check_pm_sc_debug_mode(PM_SC_DBG_MODE_DEBUG))
		pr_info("syscall %lld : rval = 0x%lx / %ld\n", sys_num, rval, rval);
#endif
	/* It works only under CONFIG_FTRACE flag */
	add_info_syscall(sys_num, start_tick);

	finish_syscall(regs, FROM_SYSCALL_PROT_8, true);
}

#endif /* CONFIG_PROTECTED_MODE */

#ifdef CONFIG_KERNEL_TIMES_ACCOUNT
static inline void syscall_enter_kernel_times_account(struct pt_regs *regs)
{
	e2k_clock_t clock = NATIVE_READ_CLKR_REG_VALUE();
	scall_times_t *scall_times;
	int count;

	scall_times =
	    &(current_thread_info()->times[current_thread_info()->times_index].of.syscall);
	current_thread_info()->times[current_thread_info()->times_index].type = SYSTEM_CALL_TT;
	INCR_KERNEL_TIMES_COUNT(current_thread_info());
	scall_times->start = clock;
	E2K_SAVE_CLOCK_REG(scall_times->pt_regs_set);
	scall_times->signals_num = 0;

	E2K_SAVE_CLOCK_REG(scall_times->save_stack_regs);
	E2K_SAVE_CLOCK_REG(scall_times->save_sys_regs);
	E2K_SAVE_CLOCK_REG(scall_times->save_stacks_state);
	E2K_SAVE_CLOCK_REG(scall_times->save_thread_state);
	scall_times->syscall_num = regs->sys_num;
	E2K_SAVE_CLOCK_REG(scall_times->scall_switch);
}

static inline void syscall_exit_kernel_times_account(struct pt_regs *regs)
{
	scall_times_t *scall_times;

	scall_times =
	    &(current_thread_info()->times[current_thread_info()->times_index].of.syscall);
	E2K_SAVE_CLOCK_REG(scall_times->restore_thread_state);
	E2K_SAVE_CLOCK_REG(scall_times->scall_done);
	E2K_SAVE_CLOCK_REG(scall_times->check_pt_regs);
}
#else
static inline void syscall_enter_kernel_times_account(struct pt_regs *regs)
{
}

static inline void syscall_exit_kernel_times_account(struct pt_regs *regs)
{
}
#endif

__section(".entry.text")
SYS_RET_TYPE notrace handle_sys_call(system_call_func sys_call,
				     long arg1, long arg2, long arg3, long arg4,
				     long arg5, long arg6, struct pt_regs *regs)
{
	struct mm_struct *mm = current->mm;
	u64 ctx = mm->context.cpumsk[raw_smp_processor_id()];
	u64 last_ctx = raw_cpu_read(last_mmu_context);
	unsigned long ti_flags = current_thread_info()->flags;
	long rval;

	init_pt_regs_for_syscall(regs);
	on_kernel_entry();

	check_cli();
	info_save_stack_reg(native_read_CLKR_reg_value());
	syscall_enter_kernel_times_account(regs);

	SAVE_STACK_REGS(regs, true, false);
	get_mmu_pid_irqs_off_impl(&mm->context, MMU_PID_RELOAD_CHECK, ctx, last_ctx);

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	/* Switch back to host page tables under closed interrupts
	 * (before we can be rescheduled from an interrupt). */
	bool guest_enter = guest_syscall_enter(regs, ts_host_at_vcpu_mode());
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	/* Make sure current_pt_regs() works properly by initializing
	 * pt_regs pointer before enabling any interrupts. */
	current_thread_info()->pt_regs = regs;
	native_write_irq_barrier_PSR_reg(E2K_KERNEL_PSR_ENABLED);

	SAVE_SYSCALL_ARGS(regs, arg1, arg2, arg3, arg4, arg5, arg6);

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	if (unlikely(guest_enter)) {
		/* the system call is from guest and syscall is injecting */
		pv_vcpu_syscall_intc(current_thread_info(), regs);

		/* Disable interrupts:
		 *  - pt_regs must be not NULL while interrupts are enabled;
		 *  - switch to guest page tables under closed interrupts. */
		raw_all_irq_disable();
		current_thread_info()->pt_regs = NULL;
		guest_syscall_inject(current_thread_info(), regs);
		unreachable();
	}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	Dbg1SC(regs->sys_num, "_NR_ %d current %px pid %d name %s\n"
	       "handle_sys_call: k_usd: base 0x%llx, size 0x%llx, sbr 0x%llx\n"
	       "arg1 %lld arg2 0x%llx arg3 0x%llx arg4 0x%llx arg5 0x%llx arg6 0x%llx\n",
	       regs->sys_num, current, current->pid, current->comm,
	       USD_PTR(current_thread_info()->k_usd),
	       USD_IND(current_thread_info()->k_usd),
	       current->stack, (u64) arg1, (u64) arg2, (u64) arg3, (u64) arg4,
	       (u64) arg5, (u64) arg6);

	if (likely(!(ti_flags & _TIF_WORK_SYSCALL_TRACE))) {
		/* Fast path */
		rval = sys_call((unsigned long)arg1, (unsigned long)arg2,
				(unsigned long)arg3, (unsigned long)arg4,
				(unsigned long)arg5, (unsigned long)arg6);
		regs->sys_rval = rval;
		Dbg1SC(regs->sys_num, "\t\t_NR_ %d rval = %ld / 0x%lx\n",
		       regs->sys_num, rval, rval);
	} else {
		/*
		 * The de-facto standard way to skip a system call using ptrace
		 * is to set the system call number to -1 and set x0 to a
		 * suitable error code for consumption by userspace. However,
		 * this cannot be distinguished from a user-issued syscall(-1)
		 * and so we must set sys_rval to -ENOSYS here in case the tracer
		 * doesn't issue the skip and we skip the system call with
		 * sys_rval preserved.
		 *
		 * This is slightly odd because it also means that if a tracer
		 * sets the system call number to -1 but does not initialise
		 * sys_rval, then sys_rval will be preserved for all system calls
		 * apart from a user-issued syscall(-1). However, requesting
		 * a skip and not setting the return value is unlikely to do
		 * anything sensible anyway.
		 */
		if (regs->sys_num == -1)
			regs->sys_rval = -ENOSYS;

		/* Trace syscall enter */
		rval = syscall_trace_entry(regs);

		/* Update args, since tracer could have changed them */
		RESTORE_SYSCALL_ARGS(regs, arg1, arg2, arg3, arg4, arg5, arg6);

		/* Update system call number, since tracer could have changed it */
		if (unlikely(regs->sys_num >= NR_syscalls || regs->sys_num < 0)) {
			sys_call = (system_call_func) (void *) sys_ni_syscall;
			goto call_sys_call;
		}
		if (regs->kernel_entry == 3) {
			sys_call = sys_call_table[regs->sys_num];
#ifdef CONFIG_COMPAT
		} else if (regs->kernel_entry == 1) {
			sys_call = sys_call_table_32[regs->sys_num];
#endif
		} else {
			BUG();
		}
call_sys_call:
		if (!rval && regs->sys_num != -1) {
			rval = sys_call((unsigned long)arg1, (unsigned long)arg2,
						  (unsigned long)arg3, (unsigned long)arg4,
						  (unsigned long)arg5, (unsigned long)arg6);
			regs->sys_rval = rval;
		}
		/* Trace syscall exit */
		syscall_trace_leave(regs);
		rval = regs->sys_rval;
		Dbg1SC(regs->sys_num, "\t\t_NR_ %d rval = %ld / 0x%lx\n",
		       regs->sys_num, rval, rval);
	}

	add_info_syscall(regs->sys_num, clock);
	syscall_exit_kernel_times_account(regs);

	DbgSC("generic_sys_calls:_NR_ %d finish k_stk bottom %lx rval %ld pid %d nam %s\n",
	      regs->sys_num, current->stack, regs->sys_rval, current->pid, current->comm);

	finish_syscall(regs, FROM_SYSCALL_N_PROT, true);
}

/*
 * We can only get here if either FILLC or FILLR isn't supported.
 * Otherwise finish_syscall_switched_hw_stacks is called directly.
 */
void notrace __noreturn finish_syscall_sw_fill(void)
{
	struct pt_regs *regs = current_thread_info()->pt_regs;
	restore_caller_t from = current->thread.fill.from;
	bool return_to_user = current->thread.fill.return_to_user;
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	bool ts_host_at_vcpu_mode = current->thread.fill.ts_host_at_vcpu_mode;
#else
	bool ts_host_at_vcpu_mode = false;
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	user_hw_stacks_restore__sw_sequel();

	finish_syscall_switched_hw_stacks(regs, from, return_to_user, ts_host_at_vcpu_mode);

	unreachable();
}

int copy_context_from_signal_stack(struct pt_regs *regs, struct trap_pt_regs *trap,
		e2k_aau_t *aau_context, struct k_sigaction *ka)
{
	struct signal_stack_context __priv *context;

	context = pop_signal_stack();
	WARN_ON(context == NULL);

	if (copy_from_priv_tagged(regs, &context->regs, sizeof(*regs)))
		return -EFAULT;

	if (likely(trap && regs->trap)) {
		if (copy_from_priv_tagged(trap, &context->trap, sizeof(*trap)))
			return -EFAULT;
		regs->trap = trap;
	}
	if (likely(aau_context && regs->aau_context)) {
		if (copy_from_priv(aau_context, &context->aau_regs,
					sizeof(*aau_context)))
			return -EFAULT;
		regs->aau_context = aau_context;
	}

	if (ka && copy_from_priv(ka, &context->sigact, sizeof(*ka)))
		return -EFAULT;

	return 0;
}

__section(".entry.text")
notrace long __ret_from_fork(struct task_struct *prev)
{
	struct pt_regs *regs = current_thread_info()->pt_regs;
	enum restore_caller from = FROM_RET_FROM_FORK;
	int ret;

	prev = ret_from_fork_get_prev_task(prev);

	e2k_finish_switch(prev);
	schedule_tail(prev);

	local_irq_enable();

	/* Is this a kernel thread? */
	if (unlikely(current->thread.clone.fn)) {
		current->thread.clone.fn(current->thread.clone.fn_arg);
		/*
		 * A kernel thread is allowed to return here after successfully
		 * calling kernel_execve().  Exit to userspace to complete the
		 * execve() syscall.
		 */
	}

	if (TASK_IS_PROTECTED(current))
		from |= FROM_SYSCALL_PROT_8;
	else
		from |= FROM_SYSCALL_N_PROT;

	ret = ret_from_fork_prepare_hv_stacks(regs);
	if (ret) {
		do_exit(SIGKILL);
	}

	finish_syscall(regs, from, true);
}

/*
 * Even after user_hw_stacks_copy_full() kernel's chain stack will
 * have one additional user frame saved at pcsp.base address, which
 * we have to update manually (besides updating pt_regs->crs).
 *
 * See user_hw_stacks_copy_full() for an explanation why this frame
 * is located at (AS(ti->k_pcsp_lo).base).
 */
int copy_user_second_cframe(const struct pt_regs *regs)

{
	e2k_mem_crs_t *k_crs;
	e2k_mem_crs_t __priv *u_cframe;

	BUG_ON(regs->stacks.pcshtp.ind != SZ_OF_CR);

	k_crs = (e2k_mem_crs_t *) PCSP_BASE(current_thread_info()->k_pcsp);
	u_cframe = U_PCSP_PTR(regs->stacks.pcsp);

	return copy_from_user_pcsp_to_current_hw_stack(k_crs, u_cframe - 1, sizeof(*k_crs), regs);
}

__section(".entry.text")
notrace long do_sigreturn(void)
{
	struct pt_regs regs;
	struct pt_regs *cur_regs = current_pt_regs();
	unsigned long cur_ti_flags = current_thread_info()->flags;
	struct trap_pt_regs saved_trap, *trap;
	struct k_sigaction ka;
	e2k_aau_t aau_context;
	e2k_usd_t usd;
	const rt_sigframe_t __user *frame;

	/* Always make any pending restarted system call return -EINTR.
	 * Otherwise we might restart the wrong system call. */
	current->restart_block.fn = do_no_restart_syscall;
	if (copy_context_from_signal_stack(&regs, &saved_trap, &aau_context, &ka)) {
		user_exit();
		do_exit(SIGKILL);
	}

	/* Preserve current p[c]shtp as they indicate how much
	 * to FILL when returning and copy hardware stacks to user */
	preserve_user_hw_stacks_to_copy(&regs.stacks, &regs.crs);

	if (from_trap(&regs))
		regs.trap->prev_state = exception_enter();
	else
		user_exit();

	regs.next = NULL;
	/* Make sure 'pt_regs' are ready before enqueuing them */
	barrier();
	current_thread_info()->pt_regs = &regs;

	if (WARN_ON_ONCE(copy_user_second_cframe(&regs))) {
		/* User's stack is not available, so just exit */
		do_exit(SIGKILL);
	}

	frame = (const rt_sigframe_t __user *) current_thread_info()->u_stack.top;

	usd = regs.stacks.usd;
	update_u_stack_limits(regs.stacks.top - USD_BASE(usd), regs.stacks.top);

	if (restore_rt_frame(frame, &ka)) {
		printk_ratelimited("%s%s[%d] bad frame:%px\n",
				   task_pid_nr(current) > 1 ? KERN_INFO : KERN_EMERG,
				   current->comm, current->pid, frame);

		force_sig(SIGSEGV);
	}

	trap = regs.trap;
	/* Must not happen since copy_context_to_signal_stack()
	 * skips copying completed entries */
	BUG_ON(trap && trap->curr_cnt);
	trap_cellar_resume(&regs);

	clear_restore_sigmask();

	if (unlikely(cur_ti_flags & _TIF_WORK_SYSCALL_TRACE))
		/* Trace syscall exit */
		syscall_trace_leave(cur_regs);

	if (from_trap(&regs)) {
		BUG_ON(regs.kernel_entry);

		finish_user_trap_handler(&regs, FROM_USER_TRAP | FROM_SIGRETURN);
	} else {
		bool restart_needed = false;
		enum restore_caller from = FROM_SIGRETURN;

		switch (regs.sys_rval) {
		case -ERESTART_RESTARTBLOCK:
		case -ERESTARTNOHAND:
			regs.sys_rval = -EINTR;
			break;
		case -ERESTARTSYS:
			if (!(ka.sa.sa_flags & SA_RESTART)) {
				regs.sys_rval = -EINTR;
				break;
			}
			fallthrough;
		case -ERESTARTNOINTR:
			restart_needed = true;
			break;
		}

		switch (regs.kernel_entry) {
		case 1:
		case 3:
		case 4:
			from |= FROM_SYSCALL_N_PROT;
			break;
		case 8:
			from |= FROM_SYSCALL_PROT_8;
			break;
		default:
			BUG();
		}

		finish_syscall(&regs, from, !restart_needed);
	}
}

SYSCALL_DEFINE1(sigreturn, u64, flags)
{
	struct pt_regs *regs = current_pt_regs();
	int ret;

	if (flags)
		return -EINVAL;

	/*
	 * Signal handler can be called not only on exit path from system call,
	 * but also on exit path from user trap.  This means that we can not
	 * just return here back into handle_sys_call() and hope that it will
	 * restore all registers - it won't (because many registers make no
	 * sense in system call context).
	 *
	 * So instead we will return into special function do_sigreturn() which
	 * will do one of the following:
	 *  - call finish_user_trap_handler() (return to user from trap)
	 *  - call finish_syscall() (return to user from syscall)
	 *  - jump to corresponding ttable_entry (restart syscall)
	 */
	ret = switch_kernel_return_function_to((unsigned long) do_sigreturn);

	regs->dargs[0] = flags;

	/* TODO 152711 - temporary workaround */
	NATIVE_RETURN_VALUE(ret);
	return ret;
}

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
__section(".entry.text")
notrace long return_pv_vcpu_trap(void)
{
	return_pv_vcpu_inject(FROM_PV_VCPU_TRAP_INJECT);
	return 0;
}

__section(".entry.text")
notrace long return_pv_vcpu_syscall(void)
{
	return_pv_vcpu_inject(FROM_PV_VCPU_SYSCALL_INJECT);
	return 0;
}

__section(".entry.text")
notrace long return_pv_vcpu_syscall_fork(u64 sys_rval)
{
	pv_vcpu_return_from_fork(sys_rval);
	return 0;
}

__section(".entry.text")
notrace void pv_vcpu_mkctxt_complete(void)
{
	guest_mkctxt_complete();
}

/*
 * We can only get here if either FILLC or FILLR isn't supported.
 * Otherwise return_to_injected_syscall_switched_stacks is called directly.
 */
void notrace __noreturn return_to_injected_syscall_sw_fill(void)
{
	user_hw_stacks_restore__sw_sequel();

	return_to_injected_syscall_switched_stacks();

	unreachable();
}

u64 return_to_injected_syscall_sw_fill_wsz __read_mostly = 0;
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

u64 finish_user_trap_handler_sw_fill_wsz __read_mostly = 0;
u64 finish_syscall_sw_fill_wsz __read_mostly = 0;

static int initialize_sw_fill_window_size(void)
{
	if (cpu_has(CPU_FEAT_FILLC) && cpu_has(CPU_FEAT_FILLR))
		return 0;

	finish_user_trap_handler_sw_fill_wsz = (u64) FINISH_USER_TRAP_HANDLER_SW_FILL_SIZE;
	finish_syscall_sw_fill_wsz = (u64) FINISH_SYSCALL_SW_FILL_SIZE;
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	return_to_injected_syscall_sw_fill_wsz = (u64) RETURN_TO_INJECTED_SYSCALL_SW_FILL_SIZE;
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	return 0;
}

arch_initcall(initialize_sw_fill_window_size);
