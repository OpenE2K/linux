/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/debug_locks.h>
#include <linux/init.h>
#include <linux/hw_breakpoint.h>
#include <linux/kdebug.h>
#include <linux/perf_event.h>
#include <linux/types.h>
#include <linux/ptrace.h>
#include <linux/ring_buffer.h>
#include <linux/irq.h>
#include <linux/extable.h>
#include <linux/percpu.h>
#include <linux/uaccess.h>
#include <linux/unistd.h>
#include <linux/vmalloc.h>
#include <linux/console.h>
#include <linux/sched/debug.h>

#include <asm/cacheflush.h>
#include <asm/e2k_api.h>
#include <asm/getsp_adj.h>
#include <asm/processor.h>
#include <asm/cpu_regs.h>
#include <asm/regs_state.h>
#include <asm/process.h>
#include <asm/ptrace.h>
#include <asm/current.h>
#include <asm/kprobes.h>
#include <asm/traps.h>
#include <asm/trap_table.h>
#include <asm/delay.h>
#include <asm/sections.h>
#include <asm/smp.h>
#include <asm/console.h>
#include <asm/perf_event.h>
#include <asm/pic.h>
#include <asm/hw_breakpoint.h>
#include <asm/trace.h>
#include <asm/sic_regs.h>
#include <asm/sic_regs_access.h>
#include <asm/kvm/hypercall.h>
#include <asm/aau_context.h>

#include <asm/e2k_debug.h>


#ifdef CONFIG_MLT_STORAGE
#include <asm/mlt.h>
#endif

#ifdef CONFIG_KPROBES
#include <linux/kprobes.h>
#endif

#include <trace/events/irq.h>

#include <asm/kvm/trace_kvm.h>
#include <asm/kvm/trace_kvm_pv.h>

#define	DEBUG_TRAP_CELLAR	0	/* DEBUG_TRAP_CELLAR */
#define DbgTC(...)		DebugPrint(DEBUG_TRAP_CELLAR, ##__VA_ARGS__)

#undef	DEBUG_PF_MODE
#undef	DebugPF
#define	DEBUG_PF_MODE		0	/* Page fault */
#define DebugPF(...)		DebugPrint(DEBUG_PF_MODE, ##__VA_ARGS__)

#undef	DEBUG_US_EXPAND
#undef	DebugUS
#define	DEBUG_US_EXPAND		0	/* User stacks */
#define DebugUS(...)		DebugPrint(DEBUG_US_EXPAND, ##__VA_ARGS__)

#undef	DEBUG_MEM_LOCK
#undef	DebugML
#define	DEBUG_MEM_LOCK		0
#define DebugML(...)		DebugPrint(DEBUG_MEM_LOCK, ##__VA_ARGS__)

/* Forward declarations */
static void do_illegal_opcode(struct pt_regs *regs);
static void do_priv_action(struct pt_regs *regs);
static void do_fp_disabled(struct pt_regs *regs);
static void do_fp_stack_u(struct pt_regs *regs);
static void do_d_interrupt(struct pt_regs *regs);
static void do_diag_ct_cond(struct pt_regs *regs);
static void do_diag_instr_addr(struct pt_regs *regs);
static void do_illegal_instr_addr(struct pt_regs *regs);
static void do_instr_debug(struct pt_regs *regs);
static void do_window_bounds(struct pt_regs *regs);
static void do_user_stack_bounds(struct pt_regs *regs);
static void do_proc_stack_bounds(struct pt_regs *regs);
static void do_chain_stack_bounds(struct pt_regs *regs);
static void do_fp_stack_o(struct pt_regs *regs);
static void do_diag_cond(struct pt_regs *regs);
static void do_diag_operand(struct pt_regs *regs);
static void do_illegal_operand(struct pt_regs *regs);
static void do_array_bounds(struct pt_regs *regs);
static void do_access_rights(struct pt_regs *regs);
static void do_addr_not_aligned(struct pt_regs *regs);
static void do_instr_page_miss(struct pt_regs *regs);
static void do_instr_page_prot(struct pt_regs *regs);
static void do_ainstr_page_miss(struct pt_regs *regs);
static void do_ainstr_page_prot(struct pt_regs *regs);
static void do_last_wish(struct pt_regs *regs);
static void do_base_not_aligned(struct pt_regs *regs);
static void do_software_trap(struct pt_regs *regs);
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
static void do_kernel_coredump(struct pt_regs *regs);
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
static void do_data_debug(struct pt_regs *regs);
static void do_data_page(struct pt_regs *regs);
static void do_macp(struct pt_regs *regs);
void do_nm_interrupt(struct pt_regs *regs);
static void do_division(struct pt_regs *regs);
static void do_fp(struct pt_regs *regs);
static void do_mem_lock(struct pt_regs *regs);
static void do_mem_lock_as(struct pt_regs *regs);
static void do_data_error(struct pt_regs *regs);
void do_mem_error(struct pt_regs *regs);
#ifndef CONFIG_KVM_PARAVIRTUALIZATION
static __noreturn void do_unknown_exc(struct pt_regs *regs);
#endif
static void do_recovery_point(struct pt_regs *regs);

#if IS_ENABLED(CONFIG_SOFT_PM)

/* soft_pm handlers */
static soft_pm_handler soft_pm_illegal_operand;
static soft_pm_handler soft_pm_diag_operand;
static soft_pm_handler soft_pm_array_bounds;
static soft_pm_handler soft_pm_illegal_instr_addr;

void soft_pm_init_handlers(soft_pm_handler handle_illegal_operand,
			    soft_pm_handler handle_diag_operand,
			    soft_pm_handler handle_array_bounds,
			    soft_pm_handler handle_illegal_instr_addr)
{
	WRITE_ONCE(soft_pm_illegal_operand, handle_illegal_operand);
	WRITE_ONCE(soft_pm_diag_operand, handle_diag_operand);
	WRITE_ONCE(soft_pm_array_bounds, handle_array_bounds);
	WRITE_ONCE(soft_pm_illegal_instr_addr, handle_illegal_instr_addr);
}
EXPORT_SYMBOL_GPL(soft_pm_init_handlers);

extern void soft_pm_remove_handlers()
{
	WRITE_ONCE(soft_pm_illegal_operand, NULL);
	WRITE_ONCE(soft_pm_diag_operand, NULL);
	WRITE_ONCE(soft_pm_array_bounds, NULL);
	WRITE_ONCE(soft_pm_illegal_instr_addr, NULL);
}
EXPORT_SYMBOL_GPL(soft_pm_remove_handlers);
#endif /* CONFIG_SOFT_PM */

/* Exception table. */
typedef void (*exceptions)(struct pt_regs *regs);
const exceptions exc_tbl[] = {
/*0*/	(exceptions)(do_illegal_opcode),
/*1*/	(exceptions)(do_priv_action),
/*2*/	(exceptions)(do_fp_disabled),
/*3*/	(exceptions)(do_fp_stack_u),
/*4*/	(exceptions)(do_d_interrupt),
/*5*/	(exceptions)(do_diag_ct_cond),
/*6*/	(exceptions)(do_diag_instr_addr),
/*7*/	(exceptions)(do_illegal_instr_addr),
/*8*/	(exceptions)(do_instr_debug),
/*9*/	(exceptions)(do_window_bounds),
/*10*/	(exceptions)(do_user_stack_bounds),
/*11*/	(exceptions)(do_proc_stack_bounds),
/*12*/	(exceptions)(do_chain_stack_bounds),
/*13*/	(exceptions)(do_fp_stack_o),
/*14*/	(exceptions)(do_diag_cond),
/*15*/	(exceptions)(do_diag_operand),
/*16*/	(exceptions)(do_illegal_operand),
/*17*/	(exceptions)(do_array_bounds),
/*18*/	(exceptions)(do_access_rights),
/*19*/	(exceptions)(do_addr_not_aligned),
/*20*/	(exceptions)(do_instr_page_miss),
/*21*/	(exceptions)(do_instr_page_prot),
/*22*/	(exceptions)(do_ainstr_page_miss),
/*23*/	(exceptions)(do_ainstr_page_prot),
/*24*/	(exceptions)(do_last_wish),
/*25*/	(exceptions)(do_base_not_aligned),
/*26*/	(exceptions)(do_software_trap),
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
/*27*/	(exceptions)(do_kernel_coredump),
#else
/*27*/	(exceptions)(do_unknown_exc),
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
/*28*/	(exceptions)(do_data_debug),
/*29*/	(exceptions)(do_data_page),

/* Software-injected interrupt */
/*30*/	(exceptions)(do_macp),

/*31*/	(exceptions)(do_recovery_point),
/*32*/	(exceptions)(void *)(native_do_interrupt),
/*33*/	(exceptions)(do_nm_interrupt),
/*34*/	(exceptions)(do_division),
/*35*/	(exceptions)(do_fp),
/*36*/	(exceptions)(do_mem_lock),
/*37*/	(exceptions)(do_mem_lock_as),
/*38*/	(exceptions)(do_data_error),
/*39*/	(exceptions)(do_mem_error),
/*40*/	(exceptions)(do_mem_error),
/*41*/	(exceptions)(do_mem_error),
/*42*/	(exceptions)(do_mem_error),
/*43*/	(exceptions)(do_mem_error)
};

const char *exc_tbl_name[] = {
/*0*/	"exc_illegal_opcode",
/*1*/	"exc_priv_action",
/*2*/	"exc_fp_disabled",
/*3*/	"exc_fp_stack_u",
/*4*/	"exc_d_interrupt",
/*5*/	"exc_diag_ct_cond",
/*6*/	"exc_diag_instr_addr",
/*7*/	"exc_illegal_instr_addr",
/*8*/	"exc_instr_debug",
/*9*/	"exc_window_bounds",
/*10*/	"exc_user_stack_bounds",
/*11*/	"exc_proc_stack_bounds",
/*12*/	"exc_chain_stack_bounds",
/*13*/	"exc_fp_stack_o",
/*14*/	"exc_diag_cond",
/*15*/	"exc_diag_operand",
/*16*/	"exc_illegal_operand",
/*17*/	"exc_array_bounds",
/*18*/	"exc_access_rights",
/*19*/	"exc_addr_not_aligned",
/*20*/	"exc_instr_page_miss",
/*21*/	"exc_instr_page_prot",
/*22*/	"exc_ainstr_page_miss",
/*23*/	"exc_ainstr_page_prot",
/*24*/	"exc_last_wish",
/*25*/	"exc_base_not_aligned",
/*26*/	"exc_software_trap",
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
/*27*/	"core_dump",
#else
/*27*/	"unknown exception",
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
/*28*/	"exc_data_debug",
/*29*/	"exc_data_page",
/*30*/	"exc_macp",
/*31*/	"exc_recovery_point",
/*32*/	"exc_interrupt",
/*33*/	"exc_nm_interrupt",
/*34*/	"exc_division",
/*35*/	"exc_fp",
/*36*/	"exc_memlock",
/*37*/	"exc_memlock_as",
/*38*/	"exc_data_error",
/*39*/	"exc_mem_error",
/*40*/	"exc_mem_error",
/*41*/	"exc_mem_error",
/*42*/	"exc_mem_error",
/*43*/	"exc_mem_error"
};

int proc_sig_pf_debug_handler(struct ctl_table *ctl, int write, void *buffer, size_t *lenp,
			      loff_t *ppos, int (*func)(char *), int data)
{
	if (write) {
		func(buffer);
		*ppos += *lenp;
	} else {
		struct ctl_table table;

		switch (data) {
		case SIG_PF_DEBUG_OFF:
			table.data = "off";
			break;
		case SIG_PF_DEBUG_ALL:
			table.data = "all";
			break;
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
		case SIG_PF_DEBUG_NOBINCOMP:
			table.data = "nobincomp";
			break;
#endif
		}

		table.maxlen = SIG_PF_DEBUG_STATUS_MAXLEN;
		proc_dostring(&table, 0, buffer, lenp, ppos);
	}

	return 0;
}

static int __sigdebug_setup(char *str)
{
	if (!strncmp(str, "off", 3))
		debug_signal = SIG_PF_DEBUG_OFF;
	else if (!strncmp(str, "all", 3))
		debug_signal = SIG_PF_DEBUG_ALL;
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	else if (!strncmp(str, "nobincomp", 9))
		debug_signal = SIG_PF_DEBUG_NOBINCOMP;
#endif
	else if (!strncmp(str, "1", 1))
		debug_signal = SIG_PF_DEBUG_ALL;

	return 1;
}

int debug_signal = SIG_PF_DEBUG_OFF;
static int sigdebug_setup(char *str)
{
	if (strlen(str) == 0) {
		debug_signal = SIG_PF_DEBUG_ALL;
		return 1;
	}

	if (!strncmp(str, "=", 1))
		str++;

	return __sigdebug_setup(str);
}
__setup("sigdebug", sigdebug_setup);

int proc_sigdebug_handler(struct ctl_table *ctl, int write, void *buffer, size_t *lenp,
			  loff_t *ppos)
{
	return proc_sig_pf_debug_handler(ctl, write, buffer, lenp, ppos,
			__sigdebug_setup, debug_signal);
}

static int sig_on_mem_err = 0;
static int __init sig_on_mem_err_setup(char *str)
{
	sig_on_mem_err = 1;
	return 1;
}
__setup("sig_on_mem_err", sig_on_mem_err_setup);

/* Use 'const' since this really should not be modified. */
const e2k_cute_t kernel_CUT[MAX_KERNEL_CODES_UNITS]
		__aligned(1 << E2K_ALIGN_CUT);

DEFINE_PER_CPU(unsigned long, kernel_trap_cellar[MMU_TRAP_CELLAR_MAX_SIZE])
		__aligned(1 << MMU_ALIGN_TRAP_POINT_BASE);
void trap_init(void)
{
	unsigned long cellar_addr;

	/*
	 * Set Trap Cellar pointer and reset Trap Counter register
	 */
	cellar_addr = node_kernel_address_to_phys(numa_node_id(),
			(unsigned long) raw_cpu_ptr(kernel_trap_cellar));
	BUG_ON(!IS_ALIGNED(cellar_addr, 1 << MMU_ALIGN_TRAP_POINT_BASE));

	set_MMU_TRAP_POINT(cellar_addr);
	reset_MMU_TRAP_COUNT();

	/*
	 * Access from kernel threads to userspace is prohibited by
	 * page tables switch, so it's safe to use user_addr_max().
	 */
	set_max_u_border();

	kvm_trap_init(cellar_addr);
}

#ifdef	CONFIG_DUMP_ALL_STACKS
static void start_dump_print(void)
{
	oops_in_progress = 1;
	flush_TLB_all();
	ftrace_dump(DUMP_ALL);
	console_verbose();
}

static DEFINE_RAW_SPINLOCK(print_lock);
#ifdef CONFIG_SMP
static atomic_t one_finished = ATOMIC_INIT(0);
static unsigned char cpu_is_main[NR_CPUS] = { 0 };
static unsigned char cpu_in_dump[NR_CPUS] = { 0 };

#define my_cpu_is_main	cpu_is_main[raw_smp_processor_id()]
#define my_cpu_in_dump	cpu_in_dump[raw_smp_processor_id()]
#else /* ! CONFIG_SMP */
#define	my_cpu_is_main	1
static unsigned char cpu_in_dump = 0;
#define	my_cpu_in_dump	cpu_in_dump
#endif

static void do_coredump_in_future(void)
{
	unsigned long flags;
	int count = 0;
	bool locked = true;

	/* Sparse cannot follow locking here */
#ifndef __CHECKER__
	while (!raw_spin_trylock_irqsave(&print_lock, flags)) {
		udelay(1000);
		if (count++ >= 3000) {
			locked = false;
			break;
		}
	}
#endif

	dump_stack();

	if (my_cpu_is_main) {
		show_state();
		console_flush_on_panic(CONSOLE_REPLAY_ALL);
	}

#ifndef __CHECKER__
	if (locked)
		raw_spin_unlock_irqrestore(&print_lock, flags);
#endif
}

void coredump_in_future(void)
{
# ifdef CONFIG_SMP
	my_cpu_is_main = (atomic_inc_return(&one_finished) == 1);
# endif

#if defined(CONFIG_SERIAL_PRINTK) && defined(CONFIG_SMP)
	if (my_cpu_in_dump)
		vprint_lock = __BOOT_SPIN_LOCK_UNLOCKED; /* unlocked */

#endif

	my_cpu_in_dump = 1;

	start_dump_print();
	do_coredump_in_future();

# ifdef CONFIG_SMP
	atomic_dec(&one_finished);
# endif
}
#endif /* CONFIG_DUMP_ALL_STACKS */

static inline e2k_tir_t
native_TIR0_clear_false_exceptions(e2k_tir_t TIR, int nr_TIRs)
{
	/*
	 * Hardware features:
	 *
	 * If register TIR0 contains deferred or asynchronous and
	 * precise traps, then some of precise traps can be false.
	 * Trap handler should handle only deferred and asynchronous
	 * traps and return to interrupted command. All precise
	 * exceptions will be thrown again, but this time there will
	 * be no false positives from asynchronous/deferred traps.
	 *
	 * When number of TIRs is greater than 0 precise traps bits
	 * are cleared automatically by hardware.
	 */
	if (nr_TIRs == 0) {
		if (TIR.exc & (async_exc_mask | defer_exc_mask)) {
			/*
			 * Precise traps should be masked.
			 */
			if (TIR.exc & sync_exc_mask)
				DbgTC("ignore precise traps in TIR0 0x%llx\n",
				      TIR.hi);
			TIR.exc &= ~sync_exc_mask;
		} else {
			/*
			 * Precise traps should not be masked.
			 *
			 * But some precise traps can be a consequence
			 * of the others.
			 */
			if (TIR.exc & exc_illegal_opcode_mask)
				TIR.exc &= ~sync_exc_mask | exc_illegal_opcode_mask;
			else if (TIR.exc & (exc_window_bounds_mask
					    | exc_fp_stack_u_mask
					    | exc_fp_stack_o_mask))
				TIR.exc &= ~(exc_diag_operand_mask
					     | exc_illegal_operand_mask
					     | exc_array_bounds_mask
					     | exc_access_rights_mask
					     | exc_addr_not_aligned_mask
					     | exc_base_not_aligned_mask);
		}
	}

	return TIR;
}

#ifdef CONFIG_KERNEL_TIMES_ACCOUNT
# define INCREASE_TRAP_NUM(trap_times) \
	do { trap_times->trap_num++; } while (0)
#else
# define INCREASE_TRAP_NUM(trap_times)
#endif

#define HANDLE_TIR_EXCEPTION(regs, exc_num, func, pass_func, tir) \
do { \
	unsigned long handled = 0; \
\
	read_ticks(start_tick); \
\
	(regs)->trap->nr_trap = exc_num; \
	if (pass_func) \
		handled = pass_func(regs, tir, exc_num); \
	if (!handled) \
		(func)(regs); \
\
	add_info_interrupt(exc_num, start_tick); \
	INCREASE_TRAP_NUM(trap_times); \
} while (0)

static __always_inline void
handle_nm_exceptions(struct pt_regs *regs, e2k_tir_t *TIRS, u64 nmi)
{
	/*
	 * Handle NMIs from TIR0
	 */
	if (nmi & exc_instr_debug_mask)
		HANDLE_TIR_EXCEPTION(regs, exc_instr_debug_num, do_instr_debug,
				     pass_the_trap_to_guest, TIRS[0]);

	/*
	 * Handle NMIs from TIR1
	 */
	if (nmi & exc_data_debug_mask)
		HANDLE_TIR_EXCEPTION(regs, exc_data_debug_num, do_data_debug,
				     pass_the_trap_to_guest, TIRS[0]);

	/*
	 * Handle NMIs from the last TIR
	 */
	if (nmi & exc_nm_interrupt_mask)
		HANDLE_TIR_EXCEPTION(regs, exc_nm_interrupt_num,
				     do_nm_interrupt,
				     pass_nm_interrupt_to_guest, TIRS[0]);
	if (nmi & exc_mem_lock_as_mask)
		HANDLE_TIR_EXCEPTION(regs, exc_mem_lock_as_num, do_mem_lock_as,
				     pass_the_trap_to_guest, TIRS[0]);
}

/**
 * parse_TIR_registers - call handlers for all arrived exceptions
 * @regs: saved context
 * @exceptions: mask of all arrived exceptions
 *
 * Noinline because we update %cr1_lo.psr (so that interrupts are
 * enabled in caller).
 */
noinline __irq_entry
notrace void parse_TIR_registers(struct pt_regs *regs, u64 exceptions)
{
	struct trap_pt_regs	*trap = regs->trap;
	e2k_tir_t		TIR;
	register unsigned long	nr_TIRs = trap->nr_TIRs;
	register unsigned int	nr_intrpt;
	e2k_tir_t		*TIRs = trap->TIRs;
#ifdef	CONFIG_E2K_PROFILING
	register unsigned long	start_tick;
#endif
#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	thread_info_t		*thread_info = current_thread_info();
	register trap_times_t	*trap_times;
	register int count;
#endif
	u64 nmi = exceptions & non_maskable_exc_mask;
	int aa_field;
	bool from_user = user_mode(regs);
	/*
	 * We enable interrupts if this is a user interrupt (required to
	 * handle AAU) or if this is a page fault on a user address that
	 * did not happen in an atomic context.
	 */
	bool enable_irqs = from_user || nr_TIRs > 0 &&
		TIRs[1].exc_data_page && !in_atomic() && !pagefault_disabled();
	/*
	 * Make sure we handle exc_mem_error on the same CPU
	 * for reliable diagnostics and hwpoison
	 */
	bool forbid_migration = enable_irqs && (exceptions & exc_mem_error_mask);
#ifdef CONFIG_DUMP_ALL_STACKS
	bool core_dump = unlikely(nr_TIRs == 0 &&
				  TIRs[0].exc == 0 && TIRs[0].aa == 0);
#endif

	/*
	 * We handle interrupts in the following order:
	 * 1) Open non-maskable interrupts if `from_user`.
	 * 2) Non-maskable interrupts are handled under closed NMIs
	 * 3) Open non-maskable interrupts if `!from_user`.
	 * 4) exc_interrupt
	 * 5) Open maskable interrupts if this is user mode intertupt
	 * 6) Handle everything else.
	 */

#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	GET_DECR_KERNEL_TIMES_COUNT(thread_info, count);
	trap_times = &(thread_info->times[count].of.trap);
	trap_times->nr_TIRs = nr_TIRs;
	trap_times->psp_hi = regs->stacks.psp_hi;
	trap_times->pcsp_hi = regs->stacks.pcsp_hi;
	trap_times->trap_num = 0;
#endif

#ifdef CONFIG_CLI_CHECK_TIME
	check_cli();
#endif

	current->thread.traps_count += 1;

	TIRs[0] = TIR0_clear_false_exceptions(TIRs[0], nr_TIRs);

	/* Initialize info for get_trap_ip() */
	TIR = TIRs[0];
	trap->TIR = TIR;

	/*
	 * 1) Open non-maskable interrupts if `from_user`.
	 *
	 * For NMIs there is a special case: if trap happened in user
	 * code then can call NMI handlers without all the special
	 * casing.  This allows to simplify handling NMIs that do
	 * something only if happened in user (e.g. exc_mem_lock_as).
	 */
	if (from_user) {
		SET_KERNEL_IRQ_MASK_REG(false, nmi && !enable_irqs &&
					!(exceptions & exc_interrupt_mask), true);
		trace_hardirqs_off();
	}

	/*
	 * 2) Handle NMIs
	 */

	if (unlikely(nmi))
		handle_nm_exceptions(regs, TIRs, nmi);


	/*
	 * 3) All NMIs have been handled, now we can open them.
	 * Note that we do not allow NMIs nesting to avoid stack overflow.
	 *
	 *
	 * Hardware trap operation disables interrupts mask in PSR
	 * and PSR becomes main register to control interrupts.
	 * Switch control from PSR register to UPSR, if UPSR
	 * interrupts control is used and all following trap handling
	 * will be executed under UPSR control.
	 *
	 * We disable NMI in UPSR here again in case a local_irq_save()
	 * called from an NMI handler enabled it.
	 */
	if (!from_user) {
		SET_KERNEL_IRQ_MASK_REG(false, nmi && !enable_irqs &&
					!(exceptions & exc_interrupt_mask), true);
		trace_hardirqs_off();
	}


	/*
	 * 4) Handle external interrupts before enabling interrupts
	 */
	if (trace_tir_enabled() && rcu_is_watching()) {
		unsigned long flags;

		psr_all_irq_save(flags);
		for (int i = 0; i <= nr_TIRs; i++)
			trace_tir(TIRs[i].lo, TIRs[i].hi);
		psr_all_irq_restore(flags);
	}

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	if (IS_ENABLED(CONFIG_KVM_HOST_KERNEL) && kvm_test_intc_emul_flag(regs) &&
			rcu_is_watching()) {
		unsigned long flags;

		psr_all_irq_save(flags);
		if (trace_intc_tir_enabled()) {
			for (int i = 0; i <= nr_TIRs; i++)
				trace_intc_tir(TIRs[i].lo, TIRs[i].hi);
		}

		if (trace_intc_trap_cellar_enabled()) {
			for (int cnt = 0; (3 * cnt) < trap->tc_count; cnt++)
				trace_intc_trap_cellar(&trap->tcellar[cnt], cnt);
		}

		trace_intc_ctprs(&regs->ctpr1, &regs->ctpr2, &regs->ctpr3);

		if (trace_intc_aau_enabled()) {
			e2k_aau_t *aau_context = regs->aau_context;

			if (AW(regs->aasr))
				trace_intc_aau(aau_context, regs->aasr, regs->lsr,
					       regs->lsr1, regs->ilcr, regs->ilcr1);
		}
		psr_all_irq_restore(flags);
	}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	if (exceptions & exc_interrupt_mask)
		HANDLE_TIR_EXCEPTION(regs, exc_interrupt_num, handle_interrupt,
				     pass_interrupt_to_guest, TIRs[0]);

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	pass_virqs_to_guest(regs, TIRs[0]);
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	/*
	 * 5) Open interrupts if possible
	 *
	 *
	 * There are several reasons to not enable interrupts in kernel:
	 *
	 *  - Linux does not support NMIs nesting, so do not enable
	 * interrupts when handling them. Otherwise we can have
	 * spurious APIC interrupts.
	 *
	 *  - Besides NMIs there are other non-maskable exceptions:
	 *  exc_instr_debug, exc_data_debug, exc_mem_lock_as. So
	 *  opening non-maskable interrupts can greatly increase
	 *  stack usage.
	 *
	 *  - Opening interrupts in kernel mode increases the maximum
	 * stack usage. This is also true for non-maskable interrupts
	 * (we can have 4 nested interrupts from monitoring registers
	 * only).
	 *
	 *  - We do not want to enable interrupts when get_user() was
	 *  called from a critical section with disabled interrupts.
	 */

	if (forbid_migration) {
		migrate_disable();
	}

	if (enable_irqs) {
		local_irq_enable();
	}

	/*
	 * AAU fault must be handled with open interrupts if it happened in user
	 */
	aa_field = TIR.aa;
	if (aa_field) {
		unsigned long handled;

		/* check is trap occured on guest and */
		/* should be passed to guest kernel */
		handled = pass_aau_trap_to_guest(regs, TIR);
		if (!handled)
			machine.do_aau_fault(aa_field, regs);
	}


	/*
	 * 6) Handle all other exceptions
	 */

#pragma loop count (2)
	do {
		TIR = TIRs[nr_TIRs];
		trap->TIR = TIR;
		trap->TIR_no = nr_TIRs;

#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
		trap_times->TIRs[nr_TIRs] = TIR;
		if (nr_TIRs == 0) {
			trap_times->pcs_bounds =
				!!(TIR.exc & exc_chain_stack_bounds_mask);
			trap_times->ps_bounds =
				!!(TIR.exc & exc_proc_stack_bounds_mask);
		}
#endif /* CONFIG_KERNEL_TIMES_ACCOUNT */

		/*
		 * Define number of interrupt (nr_intrpt) and run needed handler
		 * 	(*exc_tbl[nr_intrpt])(regs);
		 */
		TIR.exc &= exc_all_mask;
#pragma loop count (1)
		for (nr_intrpt = __ffs64(TIR.exc); TIR.exc != 0;
		     TIR.exc &= ~(1UL << nr_intrpt), nr_intrpt = __ffs64(TIR.exc)) {
			BUG_ON(nr_intrpt >= sizeof(exc_tbl) / sizeof(exc_tbl[0]));

			if ((1UL << nr_intrpt) & (non_maskable_exc_mask |
						  exc_interrupt_mask))
				continue;

			HANDLE_TIR_EXCEPTION(regs, nr_intrpt, *exc_tbl[nr_intrpt],
					     pass_the_trap_to_guest, TIRs[0]);
		}
	} while (nr_TIRs-- > 0);

	if (forbid_migration) {
		migrate_enable();
	}

#ifdef	CONFIG_DUMP_ALL_STACKS
	if (unlikely(core_dump)) {
		coredump_in_future();
	}
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	if (unlikely(core_dump || is_injected_guest_coredump(regs))) {
		pass_coredump_trap_to_guest(regs);
	}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
#endif /* CONFIG_DUMP_ALL_STACKS */
}

static DEFINE_RAW_SPINLOCK(die_lock);

static inline int __die(const char *str, struct pt_regs *regs, long err)
{
	int ret;

	pr_alert("die %s: %lx\n", str, err);

	show_regs(regs);

	ret = notify_die(DIE_OOPS, str, regs, err, 0, SIGSEGV);
	if (ret == NOTIFY_STOP)
		return ret;

	return 0;
}

void die(const char *str, struct pt_regs *regs, long err)
{
	int ret;

	oops_enter();
	raw_spin_lock_irq(&die_lock);
	console_verbose();
	bust_spinlocks(1);

	ret = __die(str, regs, err);

	bust_spinlocks(0);
	add_taint(TAINT_DIE, LOCKDEP_NOW_UNRELIABLE);
	raw_spin_unlock_irq(&die_lock);
	oops_exit();

	if (in_interrupt())
		panic("Fatal exception in interrupt");
	if (panic_on_oops)
		panic("Fatal exception");
	if (ret != NOTIFY_STOP)
		do_exit(SIGSEGV);
}

static inline void die_if_kernel(const char *str, struct pt_regs *regs,
				 long err)
{
	/*
	 * Check SBR. This check can be wrong only in one case: when
	 * we get an exc_array_bounds upon entering system call, but
	 * it is OK. This way fast system calls code is also detected
	 * as user mode (as it should).
	 */
	if (!user_mode(regs))
		die(str, regs, err);
}

static inline void die_if_init(const char *str, struct pt_regs *regs, long err)
{
	struct task_struct *tsk = current;

	if (tsk->pid == 1)
		die(str, regs, err);
}

static void do_illegal_opcode(struct pt_regs *regs)
{
#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	thread_info_t *thread_info = current_thread_info();

	sys_e2k_print_kernel_times(current, thread_info->times,
				   thread_info->times_num, thread_info->times_index);
#endif /* CONFIG_KERNEL_TIMES_ACCOUNT */

	if (!user_mode(regs)) {
		u32 *ip;

		if (is_kprobe_break1_trap(regs)) {
			notify_die(DIE_BREAKPOINT, "break", regs, 0,
						exc_illegal_opcode_num, SIGTRAP);
			return;
		}

		ip = (u32 *) (unsigned long) regs->trap->TIRs[0].ip;
		bust_spinlocks(1);
		pr_alert("*0x%llx = 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x\n",
				(u64) ip, ip[0], ip[1], ip[2], ip[3],
				ip[4], ip[5], ip[6], ip[7]);
		bust_spinlocks(0);
		die("illegal_opcode trap in kernel mode", regs, 0);
	} else {
		die_if_init("illegal_opcode trap in init process", regs, SIGILL);

		if (is_gdb_breakpoint_trap(regs)) {
			S_SIG(regs, SIGTRAP, TRAP_BRKPT);
		} else {
			int sig, si_code;
			char *error;
			if (get_trap_ip(regs) >= TASK_SIZE) {
				/* Could happen if user passed incorrent window
				 * in procedure stack.  There is no way to
				 * recover after this, so send SIGKILL. */
				sig = SIGKILL;
				si_code = SI_KERNEL;
				error = "SIGKILL. illegal_opcode in kernel entry/exit";
			} else {
				sig = SIGILL;
				si_code = ILL_ILLOPC;
				error = "SIGILL. illegal_opcode";
			}

			S_SIG(regs, sig, si_code);
			debug_signal_print(error, regs, true);
		}
	}
}

static void do_priv_action(struct pt_regs *regs)
{
	die_if_kernel("priv_action trap in kernel mode", regs, 0);
	S_SIG(regs, SIGILL, ILL_PRVOPC);
	debug_signal_print("SIGILL. priv_action", regs, true);

}

static void do_fp_disabled(struct pt_regs *regs)
{
	if (machine.native_iset_ver >= E2K_ISET_V6)
		panic("fp_disabled trap was removed in iset v6\n");

	die_if_kernel("fp_disabled trap in kernel mode", regs, 0);
	S_SIG(regs, SIGILL, ILL_COPROC);
	debug_signal_print("SIGILL. fp_disabled", regs, true);
}

static void do_fp_stack_u(struct pt_regs *regs)
{
	die_if_kernel("fp_stack_u trap in kernel mode", regs, 0);
	S_SIG(regs, SIGFPE, FPE_FLTINV);
	debug_signal_print("SIGFPE. fp_stack_u", regs, false);
}

static void do_d_interrupt(struct pt_regs *regs)
{
	if (handle_uaccess_trap(regs, true))
		return;
	die_if_kernel("d_interrupt trap in kernel mode", regs, 0);
	S_SIG(regs, SIGBUS, BUS_OBJERR);
	debug_signal_print("SIGBUS. d_interrupt", regs, false);
}

static void do_diag_ct_cond(struct pt_regs *regs)
{
	if (handle_uaccess_trap(regs, true))
		return;

	die_if_kernel("diag_ct_cond trap in kernel mode", regs, 0);

	S_SIG(regs, SIGILL, ILL_ILLOPN);
	debug_signal_print("SIGILL. diag_ct_cond", regs, true);
}

static void do_diag_instr_addr(struct pt_regs *regs)
{
	if (handle_uaccess_trap(regs, true))
		return;

	die_if_kernel("diag_instr_addr trap in kernel mode", regs, 0);

	S_SIG(regs, SIGILL, ILL_ILLADR);
	debug_signal_print("SIGILL. diag_instr_addr", regs, true);
}

static void warn_on_legacy_app(const struct pt_regs *regs)
{
	unsigned long ip = get_cr0_ip(regs->crs.cr0);
	instr_syl_t __user *hs_addr = (instr_syl_t __user __force *) &E2K_GET_INSTR_HS(ip);
	e2k_ctpr_t ctpr;
	instr_hs_t hs;
	instr_ss_t ss;
	instr_cs1_t cs1;

	if (get_user(hs.word, hs_addr))
		return;

	if (!hs.c1 || !hs.s)
		return;

	if (get_user(ss.word, (instr_syl_t __user __force *) &E2K_GET_INSTR_SS(ip)) ||
	    get_user(cs1.word, (instr_syl_t __user *) (hs_addr + hs.mdl)))
		return;

	if (cs1.opc != CS1_OPC_CALL || !ss.ctop)
		return;

	ctpr = (ss.ctop == 1) ? regs->ctpr1 : (ss.ctop == 2) ? regs->ctpr2 : regs->ctpr3;
	if (ctpr.ta_base == E2K_KERNEL_IMAGE_AREA_BASE + 10 * 0x800) {
		pr_info_ratelimited("%s [%d] uses legacy protected mode implementation.  Have you recompiled it with newer compiler?\n",
				current->comm, current->pid);
	}
}

static void do_illegal_instr_addr(struct pt_regs *regs)
{
	die_if_kernel("illegal_instr_addr trap in kernel mode", regs, 0);

	if (cpu_has(CPU_HWBUG_SPURIOUS_EXC_ILL_INSTR_ADDR)) {
		debug_signal_print("Not sending SIGILL: illegal_instr_addr ignored",
				   regs, false);
	} else {
		warn_on_legacy_app(regs);

#if IS_ENABLED(CONFIG_SOFT_PM)
		soft_pm_handler handler = READ_ONCE(soft_pm_illegal_instr_addr);
		if (handler &&
		    !handler(regs, exc_tbl_name[E2K_EXC_ILLEGAL_INSTR_ADDR_IND]))
			return;
#endif /* CONFIG_SOFT_PM */

		S_SIG(regs, SIGILL, SEGV_MAPERR);
		debug_signal_print("SIGILL. illegal_instr_addr", regs, true);
	}
}

static notrace void do_instr_debug(struct pt_regs *regs)
{
	e2k_dibsr_t dibsr;
	e2k_dimcr_t dimcr, dimcr1;
	bool from_user = user_mode(regs);

	if (!from_user)
		nmi_enter();

	dimcr = dimcr_pause();
	dimcr1 = dimcr1_pause();

	/* Make sure gdb sees the new value */
	current->thread.sw_regs.dibsr = read_DIBSR_reg();

	/* Call registered handlers */
	if (!from_user)
		kprobe_instr_debug_handle(regs);
	bp_instr_overflow_handle(regs);
	perf_instr_overflow_handle(regs);

	/* Send SIGTRAP if this was from ptrace */
	dibsr = read_DIBSR_reg();
	if (dibsr.m0 || dibsr.m1 || dibsr.m2 || dibsr.m3 || dibsr.ss ||
	    dibsr.b0 || dibsr.b1 || dibsr.b2 || dibsr.b3) {
		/* ptrace works in user space only */
		struct pt_regs *user_regs = find_user_regs(regs);
		if (!user_regs || !cpu_has(CPU_HWBUG_EXC_DEBUG) && !from_user)
			die("instr_debug trap in kernel mode", regs, 0);

		S_SIG(user_regs, SIGTRAP, TRAP_HWBKPT);

		/* #24785 Customer asks us to avoid this annoying message
		SDBGPRINT("SIGTRAP. Stop on breakpoint"); */

		dibsr.m0 = 0;
		dibsr.m1 = 0;
		dibsr.m2 = 0;
		dibsr.m3 = 0;
		dibsr.b0 = 0;
		dibsr.b1 = 0;
		dibsr.b2 = 0;
		dibsr.b3 = 0;
		dibsr.ss = 0;
		write_DIBSR_reg(dibsr);
	}

	dimcr_continue(dimcr);
	dimcr1_continue(dimcr1);

	if (!from_user)
		nmi_exit();
}

static void do_window_bounds(struct pt_regs *regs)
{
	if (user_mode(regs)) {
		int sig, si_code;
		char *error;
		if (get_trap_ip(regs) >= TASK_SIZE) {
			/* User passed incorrent window.  There is no
			 * way to recover after this, so send SIGKILL. */
			sig = SIGKILL;
			si_code = SI_KERNEL;
			error = "SIGKILL. window_bounds in kernel entry/exit";
		} else {
			sig = SIGSEGV;
			si_code = SEGV_BNDERR;
			error = "SIGSEGV. window_bounds";
		}
		S_SIG(regs, sig, si_code);
		debug_signal_print(error, regs, true);
	} else {
		die("window_bounds trap in kernel mode", regs, 0);
	}
}

/* Since v7 only */
static void force_sigsegv_constrict_stack(struct pt_regs *user_regs)
{
	void __user *addr;
	e2k_usd_t usd = user_regs->stacks.usd;

	/* Pass address of the first byte above the stack */
	addr = (void __user __force *) (USD_BASE(usd) + USD_SIZE_V7(usd));

	force_sig_fault(SIGSEGV, SEGV_BNDERR, addr);
}

static void force_sigsegv_expand_stack(struct pt_regs *user_regs)
{
	void __user *addr;

	/* #100842 Pass address of the first byte below the stack */
	addr = (void __user __force *) (user_stack_pointer(user_regs) -
				USD_IND(user_regs->stacks.usd) - 1);

	force_sig_fault(SIGSEGV, SEGV_BNDERR, addr);
}

/**
 * parse_and_handle_getsp() - manually interpret getsp on CPUs without %usincr
 *			      and handle the requested stack expansion
 * @regs: regs pointing to getsp/getsap
 */
static void parse_and_handle_getsp(struct pt_regs *regs)
{
	void __user *fault_addr;
	s64 incr;

	switch (parse_getsp_operation(regs, &incr, &fault_addr)) {
	case GETSP_OP_INCREMENT:
		if (expand_user_data_stack(regs, incr)) {
			force_sigsegv_expand_stack(regs);
			debug_signal_print("SIGSEGV. expand on array_bounds", regs, true);
		}
		break;
	case GETSP_OP_DECREMENT:
		if (constrict_user_data_stack(regs, incr)) {
			force_sig(SIGSEGV);
			debug_signal_print("SIGSEGV. constrict on array_bounds", regs, true);
		}
		break;
	case GETSP_OP_SIGSEGV:
		force_sig_fault(SIGSEGV, SEGV_BNDERR, fault_addr);
		debug_signal_print("SIGSEGV. array_bounds - could not read getsp instruction",
				regs, true);
		break;
	case GETSP_OP_FAIL: {
#if IS_ENABLED(CONFIG_SOFT_PM)
		soft_pm_handler handler = READ_ONCE(soft_pm_array_bounds);
		if (handler &&
		    !handler(regs, exc_tbl_name[E2K_EXC_ARRAY_BOUNDS_IND]))
			break;
#endif /* CONFIG_SOFT_PM */
		S_SIG(regs, SIGSEGV, SEGV_BNDERR);
		debug_signal_print("SIGSEGV. array_bounds on not a getsp instruction",
				regs, true);
		break;
	}
	default:
		BUG();
	}
}

static void do_user_stack_bounds(struct pt_regs *regs)
{
	die_if_kernel("user_stack_bounds trap in kernel mode", regs, 0);

	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		if (cpu_has(CPU_HWBUG_RRD_USINCR))
			return parse_and_handle_getsp(regs);

		e2k_usincr_t usincr = regs->trap->usincr;
		s64 incr = usincr.incr;
		DebugUS("do_user_stack_bounds. USINCR = %lld (0x%llx)\n", usincr.incr, AW(usincr));

		if (unlikely(incr >= 0)) {
			force_sigsegv_constrict_stack(regs);
			debug_signal_print("SIGSEGV. constrict on USD bounds failed", regs, true);
		} else if (incr < 0 && expand_user_data_stack(regs, (unsigned long)(-incr))) {
			force_sigsegv_expand_stack(regs);
			debug_signal_print("SIGSEGV. expand on USD bounds failed", regs, true);
		}
		return;
	}

	/*
	 * Up to v6, exc_user_stack_bounds is triggered only when USD.psl
	 * (procedure stack level) over- or underflows. TIR0.ip stores
	 * the IP of instruction that caused the exception.
	 */
	S_SIG(regs, SIGSEGV, SEGV_BNDERR);
	debug_signal_print("SIGSEGV. user_stack_bounds: Procedure Stack level over- or underflow",
			   regs, true);
}

static void do_proc_stack_bounds(struct pt_regs *regs)
{
	die_if_kernel("proc_stack_bounds trap in kernel mode", regs, 0);

	if (handle_proc_stack_bounds(&regs->stacks, regs->trap)) {
		debug_signal_print("SIGSEGV. Could not expand procedure stack", regs, true);
		force_sig(SIGSEGV);
		return;
	}
}

static void do_chain_stack_bounds(struct pt_regs *regs)
{
	die_if_kernel("chain_stack_bounds trap in kernel mode", regs, 0);

	if (handle_chain_stack_bounds(&regs->stacks, regs->trap)) {
		debug_signal_print("SIGSEGV. Could not expand chain stack", regs, true);
		force_sig(SIGSEGV);
		return;
	}
}

static void do_fp_stack_o(struct pt_regs *regs)
{
	die_if_kernel("fp_stack_o trap in kernel mode", regs, 0);
	S_SIG(regs, SIGFPE, FPE_FLTINV);
	debug_signal_print("SIGFPE. fp_stack_o", regs, false);
}

static void do_diag_cond(struct pt_regs *regs)
{
	if (handle_uaccess_trap(regs, true))
		return;

	die_if_kernel("diag_cond trap in kernel mode", regs, 0);

	S_SIG(regs, SIGILL, ILL_ILLOPN);
	debug_signal_print("SIGILL. diag_cond", regs, true);
}

static void do_diag_operand(struct pt_regs *regs)
{
	if (handle_uaccess_trap(regs, true))
		return;

	DbgTC("regs->cr0: IP 0x%lx\n", instruction_pointer(regs));
	die_if_kernel("diag_operand trap in kernel mode", regs, 0);
	die_if_init("diag_operand trap in init process", regs, 0);

#if IS_ENABLED(CONFIG_SOFT_PM)
	soft_pm_handler handler = READ_ONCE(soft_pm_diag_operand);
	if (handler &&
	    !handler(regs, exc_tbl_name[E2K_EXC_DIAG_OPERAND_IND]))
		return;
#endif /* CONFIG_SOFT_PM */

	S_SIG(regs, SIGILL, ILL_ILLOPN);
	debug_signal_print("SIGILL. diag_operand", regs, true);
}

static void do_illegal_operand(struct pt_regs *regs)
{
	die_if_kernel("illegal_operand trap in kernel mode", regs, 0);
	die_if_init("illegal_operand trap in init process", regs, 0);

#if IS_ENABLED(CONFIG_SOFT_PM)
	soft_pm_handler handler = READ_ONCE(soft_pm_illegal_operand);
	if (handler &&
	    !handler(regs, exc_tbl_name[E2K_EXC_ILLEGAL_OPERAND_IND]))
		return;
#endif /* CONFIG_SOFT_PM */

	S_SIG(regs, SIGILL, ILL_ILLOPN);
	debug_signal_print("SIGILL. illegal_operand", regs, true);
}

static void do_array_bounds(struct pt_regs *regs)
{
	die_if_kernel("array_bounds trap in kernel mode\n", regs, 0);

	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		S_SIG(regs, SIGSEGV, SEGV_BNDERR);
		debug_signal_print("SIGSEGV. array_bounds", regs, true);
		return;
	}

	parse_and_handle_getsp(regs);
}

static void do_access_rights(struct pt_regs *regs)
{
	die_if_kernel("access_rights trap in kernel mode", regs, 0);

	S_SIG(regs, SIGSEGV, SEGV_ACCERR);
	debug_signal_print("SIGSEGV. access_rights", regs, true);
}

static void do_addr_not_aligned(struct pt_regs *regs)
{
	if (kernel_mode(regs)) {
		e2k_upsr_t upsr = native_read_UPSR_reg();
		if (WARN_ONCE(upsr.ac, "TRAP addr not aligned, UPSR.ac is set\n")) {
			upsr.ac = 0;
			write_UPSR_reg(upsr);
			return;
		}
	}

	die_if_kernel("addr_not_aligned trap in kernel mode", regs, 0);

	S_SIG(regs, SIGBUS, BUS_ADRALN);
	debug_signal_print("SIGBUS. addr_not_aligned", regs, true);
}

static inline void
native_do_instr_page_fault(struct pt_regs *regs, tc_fault_type_t ftype,
			   const int async_instr)
{
	struct trap_pt_regs *trap = regs->trap;
	e2k_addr_t address;
	tc_cond_t condition;
	tc_mask_t mask;
	int ret;

	if (async_instr) {
		trap->nr_page_fault_exc = (ftype.page_miss) ?
			exc_ainstr_page_miss_num : exc_ainstr_page_prot_num;
	} else {
		trap->nr_page_fault_exc = (ftype.page_miss) ?
			exc_instr_page_miss_num : exc_instr_page_prot_num;
	}

	if (!async_instr) {
		e2k_tir_t tir;
		tir = trap->TIR;
		address = tir.ip;
	} else {
		address = regs->ctpr2.ta_base;
	}
	AW(condition) = 0;
	condition.store = 0;
	condition.spec = 0;
	condition.fmt = LDST_DWORD_FMT;
	condition.fmtc = 0;
	condition.fault_type = AW(ftype);
	AW(mask) = 0;
	ret = do_page_fault(regs, address, condition, mask, NULL, NULL);
	if (ret == PFR_SIGPENDING)
		return;

	if (!async_instr && ((address & PAGE_MASK) !=
			     ((address + E2K_INSTR_MAX_SIZE - 1) & PAGE_MASK))) {
		instr_hs_t hs;
		instr_syl_t __user *user_hsp;
		int instr_size;

		user_hsp = (instr_syl_t __user __force *) &E2K_GET_INSTR_HS(address);
		while (unlikely(__get_user(AW(hs), user_hsp)))
			do_page_fault(regs, (e2k_addr_t) user_hsp,
				      condition, mask, NULL, NULL);
		instr_size = E2K_GET_INSTR_SIZE(hs);
		if ((address & PAGE_MASK) != ((address + instr_size - 1) & PAGE_MASK)) {
			address = PAGE_ALIGN_DOWN(address + instr_size);
			DebugPF("instruction on pages "
				"bounds: will start handle_mm_fault()"
				"for next page 0x%lx\n", address);
			(void) do_page_fault(regs, address, condition, mask, NULL, NULL);
		}
	}

	if (async_instr) {
		/* For asynchronous programs ctpr2 points to the beginning
		 * of the program, and we have have to determine its length
		 * by ourselves. So we walk asynchronous program until:
		 * 	(1) we find 'branch' instruction;
		 * 	(2) we walk the maximum asynchronous program's length;
		 * 	(3) we stumble at the end of the page ctpr2 points to.
		 *
		 * If (3) is true then we must load the next page. */
		e2k_fapb_instr_t __user *fapb_addr;
		bool page_boundary_crossed;

		/*
		 * Some trickery here.
		 *
		 * Every instruction takes E2K_ASYNC_INSTR_SIZE (16 bytes).
		 * But instructions are only 8-bytes aligned, so they can
		 * cross pages boundary. 'ct' bit which we are looking for
		 * is located in the first half of an asynchronous instruction.
		 *
		 * So we have to sub (E2K_ASYNC_INSTR_SIZE / 2) to make sure
		 * that even if the instruction with branch crosses page
		 * boundary, we will still check its first half (since it
		 * has already been faulted in).
		 */
		if (PAGE_ALIGN_DOWN(address) == PAGE_ALIGN_DOWN(address - 1 +
				MAX_ASYNC_PROGRAM_INSTRUCTIONS * E2K_ASYNC_INSTR_SIZE)) {
			/* Even the biggest asynchronous program will
			 * fit in this page, no need to do anything */
			page_boundary_crossed = false;
		} else {
			int ct_found = 0;
			for (fapb_addr = (e2k_fapb_instr_t __user *) address;
					(unsigned long) fapb_addr <
						PAGE_ALIGN_DOWN(address - 1 +
						MAX_ASYNC_PROGRAM_INSTRUCTIONS
							* E2K_ASYNC_INSTR_SIZE);
					fapb_addr += 2) {
				e2k_fapb_instr_t fapb;

				while (unlikely(__get_user(AW(fapb), fapb_addr)))
					do_page_fault(regs, (e2k_addr_t) fapb_addr,
						      condition, mask, NULL, NULL);
				if (fapb.ct) {
					ct_found = 1;
					break;
				}
			}

			if (ct_found) {
				/* Special case: even if we have found branch,
				 * the instruction with branch can itself cross
				 * pages boundary. */
				page_boundary_crossed =
					round_down((unsigned long) fapb_addr, PAGE_SIZE) !=
					round_down((unsigned long) fapb_addr +
							E2K_ASYNC_INSTR_SIZE - 1, PAGE_SIZE);
			} else {
				page_boundary_crossed = true;
			}
		}

		if (page_boundary_crossed) {
			address = PAGE_ALIGN_DOWN(address + PAGE_SIZE);
			DebugPF("asynchronous instruction on "
				"pages bounds: will start handle_mm_fault() "
				"for next page 0x%lx\n", address);
			(void) do_page_fault(regs, address, condition, mask, NULL, NULL);
		}
	}
}

void native_instr_page_fault(struct pt_regs *regs, tc_fault_type_t ftype,
			     const int async_instr)
{
	native_do_instr_page_fault(regs, ftype, async_instr);
}

static void do_instr_page_miss(struct pt_regs *regs)
{
	tc_fault_type_t ftype;

	AW(ftype) = 0;
	ftype.page_miss = 1;
	instr_page_fault(regs, ftype, 0);
}

static void do_instr_page_prot(struct pt_regs *regs)
{
	tc_fault_type_t ftype;

	AW(ftype) = 0;
	ftype.illegal_page = 1;
	instr_page_fault(regs, ftype, 0);
}

static void do_ainstr_page_miss(struct pt_regs *regs)
{
	tc_fault_type_t ftype;

	AW(ftype) = 0;
	ftype.page_miss = 1;
	instr_page_fault(regs, ftype, 1);
}

static void do_ainstr_page_prot(struct pt_regs *regs)
{
	tc_fault_type_t ftype;

	AW(ftype) = 0;
	ftype.illegal_page = 1;
	instr_page_fault(regs, ftype, 1);
}

static void do_last_wish(struct pt_regs *regs)
{
	if (user_mode(regs)) {
		getsp_adj_apply(regs);
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	} else if (handle_guest_last_wish(regs)) {
		/* it is wish of host to support guest and it handled */
		return;
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	} else {
		if (!kretprobe_last_wish_handle(regs))
			die("last_wish in kernel mode", regs, 0);
	}

}

static void do_base_not_aligned(struct pt_regs *regs)
{
	die_if_kernel("base_not_aligned in kernel mode", regs, 0);

	S_SIG(regs, SIGBUS, BUS_ADRALN);
	debug_signal_print("SIGBUS. Address base is not aligned", regs, true);
}

int is_valid_bugaddr(unsigned long addr)
{
	return true;
}

static void do_software_trap(struct pt_regs *regs)
{
	if (user_mode(regs)) {
		S_SIG(regs, SIGTRAP, TRAP_BRKPT);
		debug_signal_print("SIGTRAP. Software trap", regs, false);
	} else {
		struct trap_pt_regs *trap = regs->trap;
		enum bug_trap_type btt;

		btt = report_bug(trap->TIRs[0].ip, regs);
		if (btt == BUG_TRAP_TYPE_WARN) {
			unsigned long ip = get_cr0_ip(regs->crs.cr0);
			unsigned long new_ip;
			instr_cs1_t *cs1;

			cs1 = find_cs1((void *) ip);
			if (cs1 && cs1->opc == CS1_OPC_SETEI && cs1->sft) {
				new_ip = ip + get_instr_size_by_vaddr(ip);
				correct_trap_return_ip(regs, new_ip);
			}

			return;
		}

		if (btt == BUG_TRAP_TYPE_BUG)
			panic("Oops - BUG");

		die("software_trap in kernel mode", regs, 0);
	}
}

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
static void do_kernel_coredump(struct pt_regs *regs)
{
#ifdef CONFIG_DUMP_ALL_STACKS
	coredump_in_future();
#endif
}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

static notrace void do_data_debug(struct pt_regs *regs)
{
	bool from_user = user_mode(regs);
	e2k_ddbsr_t ddbsr;
	e2k_ddmcr_t ddmcr, ddmcr1;

	if (!from_user)
		nmi_enter();

	ddmcr = ddmcr_pause();
	ddmcr1 = ddmcr1_pause();

	/* Make sure gdb sees the new value */
	current->thread.sw_regs.ddbsr = READ_DDBSR_REG();

	/* Call registered handlers */
	bp_data_overflow_handle(regs);
	perf_data_overflow_handle(regs);

	ddbsr = READ_DDBSR_REG();
	if (ddbsr.m0 || ddbsr.m1 || ddbsr.m2 || ddbsr.m3 ||
	    ddbsr.b0 || ddbsr.b1 || ddbsr.b2 || ddbsr.b3) {
		if (DATA_BREAKPOINT_ON) {
			/* data breakpoint occured */
			dump_stack();
			goto out;
		}

		/* ptrace works in user space only */
		struct pt_regs *user_regs = find_user_regs(regs);
		if (!user_regs || !cpu_has(CPU_HWBUG_EXC_DEBUG) && !from_user) {
			struct pt_regs *pregs = regs->next;
			bool from_execute_mmu_op = (pregs && pregs->flags.exec_mmu_op);

			if (!from_uaccess_allowed_code(regs) && !from_execute_mmu_op)
				die("data_debug trap in kernel mode", regs, 0);
		}

		if (user_regs)
			S_SIG(user_regs, SIGTRAP, TRAP_HWBKPT);

		/* #24785 Customer asks us to avoid this annoying message
		debug_signal_print("SIGTRAP. Stop on watchpoint", regs, false); */

		ddbsr.m0 = 0;
		ddbsr.m1 = 0;
		ddbsr.m2 = 0;
		ddbsr.m3 = 0;
		ddbsr.b0 = 0;
		ddbsr.b1 = 0;
		ddbsr.b2 = 0;
		ddbsr.b3 = 0;
		WRITE_DDBSR_REG(ddbsr);
	}

out:
	ddmcr_continue(ddmcr);
	ddmcr1_continue(ddmcr1);

	if (!from_user)
		nmi_exit();
}

static void do_data_page(struct pt_regs *regs)
{
	struct trap_pt_regs *trap = regs->trap;

	if (!trap->tc_called) {
		trap->nr_page_fault_exc = exc_data_page_num;
		do_trap_cellar(regs, 1);
		do_trap_cellar(regs, 0);
		trap->tc_called = 1;
	}
	DbgTC("user_mode(regs) %d signal_pending(current) %d\n",
	      user_mode(regs), signal_pending(current));
}



static void do_macp(struct pt_regs *regs)
{
	if (WARN_ON_ONCE(!cpu_has(CPU_FEAT_MADM)))
		return;

	/* Only user data in protected mode are affected by MACP for a whule */
	/* but we can get exc_macp as in user as in kernel mode */
	e2k_madmr_t madmr = read_MADMR_reg();
	if (!TASK_IS_PROTECTED(current)) {
		pr_err("exc_macp interrupt in non-PROTECTED task\n");
		AW(madmr) = 0;
		write_MADMR_reg(madmr);
		force_sig(SIGKILL);
		return;
	}
	if (handle_uaccess_trap(regs, false)) {
		/* Controlled access from kernel to user space failed. */
		/* Flags ev_ld/ev_st need to be reset not to miss next macp exception */
		madmr.ev_ld = 0;
		madmr.ev_st = 0;
		write_MADMR_reg(madmr);
		/* Big chance interrupt is in uaccess borders, but it's not always true */
		/* because this interrupt usualy not preсise */
		return;
	}

	int sig_code = SEGV_ACCERR;
	if (madmr.ev_ld) {
		sig_code = (madmr.mode_ld == 3) ? SEGV_MTESERR : SEGV_MTEAERR;
		madmr.ev_ld = 0;
	}
	if (madmr.ev_st) {
		if (sig_code != SEGV_MTESERR) {
			sig_code = (madmr.mode_st == 3) ? SEGV_MTESERR : SEGV_MTEAERR;
		}
		madmr.ev_st = 0;
	}
	write_MADMR_reg(madmr);
	S_SIG(regs, SIGSEGV, sig_code);
	debug_signal_print("SIGSEGV. exc_macp", regs, true);
	return;
}

static void do_recovery_point(struct pt_regs *regs)
{
	unsigned long ip = get_trap_ip(regs);

	if (!user_mode(regs)) {
		/* We do not warn about ".entry.text" section because
		 * there are places in it where it is legal to receive
		 * exc_recovery_point: between kernel entry (syscall entry,
		 * signal and makecontext trampolines) and up to "crp"
		 * instruction (including it).  False exc_recovery_point
		 * exceptions can be generated by hardware when loading
		 * instructions into L1$ (of course only when the
		 * "generations mode" is active). */
		if (ip < (unsigned long )__entry_handlers_start ||
		    ip >= (unsigned long) __entry_handlers_end) {
			/* Should not happen, error in binco. */
			pr_info("%d [%s]: ERROR: exc_recovery_point received in kernel mode\n",
				current->pid, current->comm);
		}
		return;
	}
	if (!(TASK_IS_BINCO(current) && cpu_has(CPU_FEAT_ISET_V6))) {
		/*
		 * There are several sources of signals in binco.
		 * force_sig_info_to_task() and it's wrappers are
		 * problematic because when these events happen
		 * simultaneously it'll reset to SIG_DFL handler.
		 *
		 * So use the common signal delivery.  We do know
		 * that binco does have handlers for all these signals
		 * so they won't be lost (there won't be SIG_IGN).
		 */
		send_sig_fault(SIGBUS, BUS_OBJERR,
			       (void __user *) get_trap_ip(regs), current);
		debug_signal_print("SIGBUS. exc_recovery_point", regs, false);
	}
}

static notrace void __cpuidle return_from_cpuidle(void) { }

void __cpuidle handle_wtrap(struct pt_regs *regs)
{
	e2k_cr0_t cr0 = regs->crs.cr0;

	if (is_from_C3_wait_trap(regs)) {
		struct c3_state *c3_state = &current->thread.C3;

		/* Instruction prefetch is disabled, re-enable it. */
		e2k_mmu_cr_t mmu_cr = get_MMU_CR();
		mmu_cr.ipd = 1;
		set_MMU_CR(mmu_cr);

		/* NMIs from local exceptions are disabled, re-enable them. */
		WRITE_DDBCR_REG(c3_state->ddbcr);
		write_DIBCR_reg(c3_state->dibcr);
		WRITE_DDMCR_REG(c3_state->ddmcr);
		write_DIMCR_reg(c3_state->dimcr);
		if (cpu_has(CPU_FEAT_ISET_V7)) {
			WRITE_DDMCR1_REG(c3_state->ddmcr1);
			if (!cpu_has(CPU_HWBUG_DIMCR1))
				write_DIMCR1_reg(c3_state->dimcr1);
		}

		/* Prefetchers have been disabled, re-enable them */
		hw_prefetchers_restore(c3_state->pref_state);
	}

	set_cr0_ip(cr0, return_from_cpuidle);
	regs->crs.cr0 = cr0;
}

irqreturn_t native_do_interrupt(struct pt_regs *regs)
{
	int vector = machine.get_irq_vector();

	if (WARN_ONCE(vector == -1, "empty interrupt vector was received\n"))
		return IRQ_NONE;

	/*
	 * Another CPU has written some data before sending this IPI,
	 * wait for that data to arrive.
	 */
	NATIVE_HWBUG_AFTER_LD_ACQ();

	if (unlikely(is_from_wait_trap(regs)))
		handle_wtrap(regs);


	/*
	 * We store the interrupt vector to detect cases when this irq is moved
	 * to another vector. So when the new vector starts arriving, special
	 * function irq_complete_move() will detect that the arrived vector
	 * is for the irq that is being migrated and will send the cleanup
	 * vector to all other cpus from the old configuration of the IRQ.
	 *
	 * Stored vector number is compared with expected vector for this IRQ:
	 * if they are the same (i.e. the actual move was done) and
	 * move_in_progress == 1 (i.e. old configuration structures has not been
	 * freed yet), a cleanup IPI is send.
	 */
	regs->interrupt_vector = vector;

	do_IRQ(regs, vector);

	return IRQ_HANDLED;
}

noinline notrace void do_nm_interrupt(struct pt_regs *regs)
{
	bool from_user = user_mode(regs);
	if (!from_user)
		nmi_enter();

	do_nmi(regs);

	if (!from_user)
		nmi_exit();
}

static void do_division(struct pt_regs *regs)
{
	die_if_kernel("division trap in kernel mode", regs, 0);

	S_SIG(regs, SIGFPE, FPE_INTDIV);
	debug_signal_print("SIGFPE. Division by zero or overflow", regs, false);
}

/*
 * IP for fp exection lay in TIRs
 */
static long get_fp_ip(struct trap_pt_regs *trap)
{
	e2k_tir_t *TIRs = trap->TIRs;
	e2k_tir_t tir;
	int nr_TIRs = trap->nr_TIRs;
	int i;

	for (i = nr_TIRs; i >= 0; i--) {
		tir = TIRs[i];
		/* do_fp exection - 35 BIT */
		if (!tir.exc_fp) {
			continue;
		}
		return tir.ip;
	}
	pr_info(" get_fp_ip not find IP\n");
	print_all_TIRs(trap->TIRs, trap->nr_TIRs);
	return 0;
}

static void do_fp(struct pt_regs *regs)
{
	void __user *addr = (void __user __force *) get_fp_ip(regs->trap);
	int code = 0;
	e2k_fpsr_t FPSR;
	e2k_pfpfr_t PFPFR;

	die_if_kernel("fp trap in kernel mode", regs, 0);

	FPSR = native_read_FPSR_reg();
	PFPFR = native_read_PFPFR_reg();

	if (FPSR.es) {
		if (FPSR.pe)
			code = FPE_FLTRES;
		else if (FPSR.ue)
			code = FPE_FLTUND;
		else if (FPSR.oe)
			code = FPE_FLTOVF;
		else if (FPSR.ze)
			code = FPE_FLTDIV;
		else if (FPSR.de)
			code = FPE_FLTUND;
		else if (FPSR.ie)
			code = FPE_FLTINV;
	} else {
		if (PFPFR.pe)
			code = FPE_FLTRES;
		else if (PFPFR.de)
			code = FPE_FLTUND;
		else if (PFPFR.oe)
			code = FPE_FLTOVF;
		else if (PFPFR.ie)
			code = FPE_FLTINV;
		else if (PFPFR.ze)
			code = FPE_FLTDIV;
		else if (PFPFR.ue)
			code = FPE_FLTUND;
	}

	force_sig_fault(SIGFPE, code, addr);
	debug_signal_print("SIGFPE. Floating point error", regs, false);
}

static void do_mem_lock(struct pt_regs *regs)
{
	if (TASK_IS_BINCO(current)) {
		struct trap_pt_regs *trap = regs->trap;

		DebugML("started\n");
		if (!trap->tc_called) {
			trap->nr_page_fault_exc = exc_mem_lock_num;
			do_trap_cellar(regs, 1);
			do_trap_cellar(regs, 0);
			trap->tc_called = 1;
		}
		DbgTC("user_mode(regs) %d signal_pending(current) %d\n",
		      user_mode(regs), signal_pending(current));
	} else {
		die_if_kernel("mem_lock in kernel mode", regs, 0);
		DebugML("do_mem_lock: send SIGBUS\n");
		S_SIG(regs, SIGBUS, BUS_OBJERR);
		debug_signal_print("SIGBUS. Memory lock signaled", regs, true);
	}
}

static notrace void do_mem_lock_as(struct pt_regs *regs)
{
	if (user_mode(regs)) {
		if (!TASK_IS_BINCO(current))
			return;

		/*
		 * Thanks to user_mode() check we can skip nmi_enter()
		 * and send signal right from here.
		 */
		DebugML("started\n");

		/* See comment in do_recovery_point() */
		send_sig_fault(SIGBUS, BUS_OBJERR,
			       (void __user *) get_trap_ip(regs), current);
		debug_signal_print("SIGBUS. Memory lock AS signaled", regs, false);
	} else {
		nmi_enter();
		/*
		 * Ignore exc_mem_lock_as in kernel, but still
		 * call nmi_enter() for statistics.
		 */
		nmi_exit();
	}
}



static void do_poisoning(struct pt_regs *regs)
{
	struct trap_pt_regs *trap = regs->trap;
	e2k_tir_t tir = trap->TIR;

	if (current->flags & (PF_WQ_WORKER|PF_IO_WORKER|PF_KTHREAD)) {
		goto system_crash;
	}
	if (tir.exc_mem_error_MAU || tir.exc_mem_error_I) {
		goto system_crash;
	}
	/* must be exc_mem_error_L1_35 or exc_mem_error_L1_02 bits in tir */
	/* Examine L1  for fatal error */
	e2k_l1_fault_reg_t fr;
	AW(fr) = READ_L1_FAULT_REG();
	if (fr.val != 0) {
		if (fr.fatal) {
			goto system_crash;
		} else {
			debug_signal_print("SIGKILL. Memory poison: l1_fault.fatal=1",
					regs, false);
			goto kill_user;
		}
	}

	/* Examine L2 regs for fatal error */

	for (int bank = 0; bank < E2K_L2_BANK_NUM; bank++) {
		e2k_l2_err_t l2_err = read_L2_ERR(bank);
		if (!l2_err.fv) {
			continue;
		}
		if (l2_err.err_fatal) {
			goto system_crash;
		} else if (l2_err.val_op_code ==  V_CPU_LD_MAU && cpu_has(CPU_HWBUG_HWPOISON)) {
			goto system_crash;
		} else {
			debug_signal_print("SIGKILL. Memory poison: l2_err.fatal=1",
					regs, false);
			goto kill_user;
		}
	}
	pr_err("Spurious exc_mem_err interrupt. tir.exc_mem_error = 0x%02x.\n",
		tir.exc_mem_error);

	/* kill_user */
kill_user:
	if (!user_mode(regs) && !handle_uaccess_trap(regs, false)) {
		goto system_crash;
	}
	force_sig(SIGKILL);
	return;

system_crash:
	pr_alert("CPU %d, exc_mem_error = %#02x. L1 fault reg = 0x%16llx\n", smp_processor_id(),
				tir.exc_mem_error, (u64)READ_L1_FAULT_REG());
	for (int bank = 0; bank < E2K_L2_BANK_NUM; bank++) {
		pr_alert("CPU %d. L2_ERR bank %d reg =  0x%16llx\n",
				smp_processor_id(), bank, AW(read_L2_ERR(bank)));
	}
	do_sic_error_interrupt();
	panic("Fatal exc_mem_error recieved\n");
}



void do_mem_error(struct pt_regs *regs)
{
	struct trap_pt_regs *trap = regs->trap;
	e2k_tir_t tir;
	u64 exc_mask;
	char s[128], *sep = "";
	bool fr = false;

	if (cpu_has(CPU_FEAT_ISET_V7)) {
		do_poisoning(regs);
		return;
	}

	s[0] = 0;

	tir = trap->TIR;
	exc_mask = tir.exc & exc_mem_error_mask;

	if (exc_mask & exc_mem_error_ICACHE_mask) {
		exc_mask &= ~exc_mem_error_ICACHE_mask;
		strcat(s, "ICACHE");
		sep = "; ";
	}
	if (exc_mask & exc_mem_error_L1_02_mask) {
		exc_mask &= ~exc_mem_error_L1_02_mask;
		fr = true;
		strcat(s, sep);
		strcat(s, "L1 chanel 0, 2");
		sep = "; ";
	}
	if (exc_mask & exc_mem_error_L1_35_mask) {
		exc_mask &= ~exc_mem_error_L1_35_mask;
		fr = true;
		strcat(s, sep);
		strcat(s, "L1 chanel 3, 5");
		sep = "; ";
	}
	if (exc_mask & exc_mem_error_L2_mask) {
		exc_mask &= ~exc_mem_error_L2_mask;
		strcat(s, sep);
		strcat(s, "L2");
		sep = "; ";
	}
	if (exc_mask & exc_mem_error_MAU_mask) {
		exc_mask &= ~exc_mem_error_MAU_mask;
		strcat(s, sep);
		strcat(s, "MAU");
		sep = "; ";
	}
	if (exc_mask & exc_mem_error_out_cpu_mask) {
		exc_mask &= ~exc_mem_error_out_cpu_mask;
		strcat(s, sep);
		strcat(s, "out cpu");
		sep = "; ";
	}
	if (exc_mask) {
		strcat(s, sep);
		strcat(s, "unknown");
	}

	pr_alert("TIR: exc 0x%016llx (%s),  ip 0x%016llx cpu %d\n",
		 tir.exc, s, tir.ip, raw_smp_processor_id());

	if (fr && machine.native_iset_ver >= E2K_ISET_V6)
		pr_alert("DCACHE L1 fault_reg 0x%llx\n", READ_L1_FAULT_REG());

	if (likely(!sig_on_mem_err)) {
		panic("EXCEPTION: exc_mem_error\n");
	} else {
		S_SIG(regs, SIGUSR2, SI_KERNEL);
		debug_signal_print("SIGUSR2. exc_mem_error", regs, false);
	}
}

static void do_data_error(struct pt_regs *regs)
{
	/*
	 * 38 bit of TIRs was reused since iset v6, in iset v3, iset v4 and
	 * iset v5 it's unused.
	 */
	if (machine.native_iset_ver < E2K_ISET_V6)
		BUG();

	S_SIG(regs, SIGBUS, BUS_OBJERR);
	debug_signal_print("SIGBUS. data_error", regs, true);
}

#ifndef CONFIG_KVM_PARAVIRTUALIZATION
__noreturn static void do_unknown_exc(struct pt_regs *regs)
{
	panic("Unknown e2k exception\n");
}
#endif
