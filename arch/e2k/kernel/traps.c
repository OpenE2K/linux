/*
 * Copyright (C) 2001 MCST
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
#include <linux/unistd.h>
#include <linux/vmalloc.h>
#include <linux/console.h>
#include <linux/sched/debug.h>

#include <asm/cacheflush.h>
#include <asm/e2k_api.h>
#include <asm/getsp_adj.h>
#include <asm/processor.h>
#include <asm/cpu_regs_access.h>
#include <asm/regs_state.h>
#include <asm/process.h>
#include <asm/ptrace.h>
#include <asm/current.h>
#include <asm/traps.h>
#include <asm/trap_table.h>
#include <asm/delay.h>
#include <asm/sections.h>
#include <linux/uaccess.h>
#include <asm/smp.h>
#include <asm/console.h>
#include <asm/perf_event.h>
#include <asm/pic.h>
#include <asm/hw_breakpoint.h>
#include <asm/trace.h>
#include <asm/sic_regs.h>
#include <asm/sic_regs_access.h>
#include <asm/kvm/hypercall.h>
#include <asm/delay.h>

#ifdef CONFIG_USE_AAU
#include <asm/aau_context.h>
#endif

#include <asm/e2k_debug.h>

#ifdef CONFIG_PROTECTED_MODE
#include <asm/3p.h>
#endif

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
static void do_data_debug(struct pt_regs *regs);
static void do_data_page(struct pt_regs *regs);
void do_nm_interrupt(struct pt_regs *regs);
static void do_division(struct pt_regs *regs);
static void do_fp(struct pt_regs *regs);
static void do_mem_lock(struct pt_regs *regs);
static void do_mem_lock_as(struct pt_regs *regs);
static void do_data_error(struct pt_regs *regs);
static void do_mem_error(struct pt_regs *regs);
static void do_unknown_exc(struct pt_regs *regs);
static void do_recovery_point(struct pt_regs *regs);

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
/*27*/	(exceptions)(do_unknown_exc),
/*28*/	(exceptions)(do_data_debug),
/*29*/	(exceptions)(do_data_page),
/*30*/	(exceptions)(do_unknown_exc),
/*31*/	(exceptions)(do_recovery_point),
/*32*/	(exceptions)(native_do_interrupt),
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
/*27*/	"exc_unknown_exc",
/*28*/	"exc_data_debug",
/*29*/	"exc_data_page",
/*30*/	"exc_unknown_exc",
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

int debug_signal = false;
bool dump_signal_stack = false;

static int __init sig_debug_setup(char *str)
{
	debug_signal = true;
	return 1;
}
__setup("sigdebug", sig_debug_setup);

static int __init sig_dump_stack_setup(char *str)
{
	dump_signal_stack = true;
	debug_signal = true;
	return 1;
}
__setup("sigdumpstack", sig_dump_stack_setup);

int debug_trap = 0;
static int __init debug_trap_setup(char *str)
{
	debug_trap = 1;
	return 1;
}
__setup("trap_regs", debug_trap_setup);

int sig_on_mem_err = 0;
static int __init sig_on_mem_err_setup(char *str)
{
	sig_on_mem_err = 1;
	return 1;
}
__setup("sig_on_mem_err", sig_on_mem_err_setup);

void __init trap_init(void)
{
}

void  start_dump_print(void)
{
#if defined(CONFIG_EARLY_PRINTK)
	switch_to_early_dump_console();
#endif
	oops_in_progress = 1;
	flush_TLB_all();
	ftrace_dump(DUMP_ALL);
	console_verbose();
}

DEFINE_RAW_SPINLOCK(print_lock);
#ifdef CONFIG_SMP
static atomic_t one_finished = ATOMIC_INIT(0);
static unsigned char cpu_is_main[NR_CPUS] = { 0 };
static unsigned char cpu_in_dump[NR_CPUS] = { 0 };
#define my_cpu_is_main	cpu_is_main[raw_smp_processor_id()]
#define my_cpu_in_dump	cpu_in_dump[raw_smp_processor_id()]
#else	/* ! CONFIG_SMP */
#define	my_cpu_is_main	1
static unsigned char cpu_in_dump = 0;
#define	my_cpu_in_dump	cpu_in_dump
#endif

#ifdef	CONFIG_DUMP_ALL_STACKS
static void do_coredump_in_future(void)
{
	unsigned long flags;
	int count = 0;
	bool locked = true;

	while (!raw_spin_trylock_irqsave(&print_lock, flags)) {
		udelay(1000);
		if (count++ >= 3000) {
			locked = false;
			break;
		}
	}

	dump_stack();

	if (my_cpu_is_main) {
		show_state();
		console_flush_on_panic(CONSOLE_REPLAY_ALL);
	}

	if (locked)
		raw_spin_unlock_irqrestore(&print_lock, flags);
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
#endif	/* CONFIG_DUMP_ALL_STACKS */

static inline u64
native_TIR0_clear_false_exceptions(u64 TIR_hi, int nr_TIRs)
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
		if (TIR_hi & (async_exc_mask | defer_exc_mask)) {
			/*
			 * Precise traps should be masked.
			 */
			if (TIR_hi & sync_exc_mask)
				DbgTC("ignore precise traps in TIR0 0x%llx\n",
					TIR_hi);
			TIR_hi &= ~sync_exc_mask;
		} else {
			/*
			 * Precise traps should not be masked.
			 *
			 * But some precise traps can be a consequence
			 * of the others.
			 */
			if (TIR_hi & exc_illegal_opcode_mask)
				TIR_hi &= ~sync_exc_mask |
						exc_illegal_opcode_mask;
			else if (TIR_hi & (exc_window_bounds_mask
					| exc_fp_stack_u_mask
					| exc_fp_stack_o_mask))
				TIR_hi &= ~(exc_diag_operand_mask
						| exc_illegal_operand_mask
						| exc_array_bounds_mask
						| exc_access_rights_mask
						| exc_addr_not_aligned_mask
						| exc_base_not_aligned_mask);
		}
	}

	return TIR_hi;
}

#ifdef CONFIG_KERNEL_TIMES_ACCOUNT
# define INCREASE_TRAP_NUM(trap_times) \
	do { trap_times->trap_num++; } while (0)
#else
# define INCREASE_TRAP_NUM(trap_times)
#endif

#define HANDLE_TIR_EXCEPTION(regs, exc_num, func, pass_func, tir_hi, tir_lo) \
do { \
	unsigned long handled = 0; \
\
	read_ticks(start_tick); \
\
	(regs)->trap->nr_trap = exc_num; \
	if (pass_func) \
		handled = pass_func(regs, tir_hi, tir_lo, exc_num); \
	if (!handled) \
		(func)(regs); \
\
	add_info_interrupt(exc_num, start_tick); \
	INCREASE_TRAP_NUM(trap_times); \
} while (0)

static __always_inline void
handle_nm_exceptions(struct pt_regs *regs, e2k_tir_t *TIRs, u64 nmi)
{
	/*
	 * Handle NMIs from TIR0
	 */
	if (nmi & exc_instr_debug_mask)
		HANDLE_TIR_EXCEPTION(regs, exc_instr_debug_num, do_instr_debug,
			pass_the_trap_to_guest,
			TIRs[0].TIR_hi.TIR_hi_reg, TIRs[0].TIR_lo.TIR_lo_reg);

	/*
	 * Handle NMIs from TIR1
	 */
	if (nmi & exc_data_debug_mask)
		HANDLE_TIR_EXCEPTION(regs, exc_data_debug_num, do_data_debug,
			pass_the_trap_to_guest,
			TIRs[0].TIR_hi.TIR_hi_reg, TIRs[0].TIR_lo.TIR_lo_reg);

	/*
	 * Handle NMIs from the last TIR
	 */
	if (nmi & exc_nm_interrupt_mask)
		HANDLE_TIR_EXCEPTION(regs, exc_nm_interrupt_num,
							do_nm_interrupt,
			pass_nm_interrupt_to_guest,
			TIRs[0].TIR_hi.TIR_hi_reg, TIRs[0].TIR_lo.TIR_lo_reg);
	if (nmi & exc_mem_lock_as_mask)
		HANDLE_TIR_EXCEPTION(regs, exc_mem_lock_as_num, do_mem_lock_as,
			pass_the_trap_to_guest,
			TIRs[0].TIR_hi.TIR_hi_reg, TIRs[0].TIR_lo.TIR_lo_reg);
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
	struct trap_pt_regs *trap = regs->trap;
	register unsigned long	TIR_hi, TIR_lo;
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
	bool user = user_mode(regs);
	/*
	 * We enable interrupts if this is a user interrupt (required to
	 * handle AAU) or if this is a page fault on a user address that
	 * did not happen in an atomic context.
	 */
	bool enable_irqs = user || nr_TIRs > 0 &&
		(AW(TIRs[1].TIR_hi) & exc_data_page_mask) &&
		!in_atomic() && !pagefault_disabled();
#ifdef CONFIG_DUMP_ALL_STACKS
	bool core_dump = unlikely(nr_TIRs == 0 &&
				  AS(TIRs[0].TIR_hi).exc == 0 &&
				  AS(TIRs[0].TIR_hi).aa == 0);
#endif

	/*
	 * We handle interrupts in the following order:
	 * 1) Non-maskable interrupts are handled under closed NMIs
	 * 2) Open non-maskable interrupts
	 * 3) exc_interrupt
	 * 4) Open maskable interrupts if this is user mode intertupt
	 * 5) Handle everything else.
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

	AW(TIRs[0].TIR_hi) = TIR0_clear_false_exceptions(AW(TIRs[0].TIR_hi),
								nr_TIRs);

	/*
	 * 1) Handle NMIs
	 */

	if (unlikely(nmi))
		handle_nm_exceptions(regs, TIRs, nmi);


	/*
	 * 2) All NMIs have been handled, now we can open them.
	 * Note that we do not allow NMIs nesting to avoid stack overflow.
	 *
	 *
	 * Hardware trap operation disables interrupts mask in PSR
	 * and PSR becomes main register to control interrupts.
	 * Switch control from PSR register to UPSR, if UPSR
	 * interrupts control is used and all following trap handling
	 * will be executed under UPSR control.
	 *
	 * SGE was already disabled by hardware on trap enter.
	 *
	 * We disable NMI in UPSR here again in case a local_irq_save()
	 * called from an NMI handler enabled it.
	 */
	INIT_KERNEL_UPSR_REG(false, nmi && !enable_irqs &&
				    !(exceptions & exc_interrupt_mask));
	SWITCH_IRQ_TO_UPSR(true);
	trace_hardirqs_off();


	/*
	 * 3) Handle external interrupts before enabling interrupts
	 */
	if (trace_tir_enabled()) {
		int i;

		for (i = 0; i <= nr_TIRs; i++)
			trace_tir(AW(TIRs[i].TIR_lo), AW(TIRs[i].TIR_hi));
	}

	if (IS_ENABLED(CONFIG_KVM_HOST_MODE) && kvm_test_intc_emul_flag(regs)) {
		if (trace_intc_tir_enabled()) {
			int i;

			for (i = 0; i <= nr_TIRs; i++)
				trace_intc_tir(AW(TIRs[i].TIR_lo), AW(TIRs[i].TIR_hi));
		}

		if (trace_intc_trap_cellar_enabled()) {
			int cnt;

			for (cnt = 0; (3 * cnt) < trap->tc_count; cnt++)
				trace_intc_trap_cellar(&trap->tcellar[cnt], cnt);
		}

		if (trace_intc_ctprs_enabled()) {
			trace_intc_ctprs(AW(regs->ctpr1), AW(regs->ctpr1_hi),
					AW(regs->ctpr2), AW(regs->ctpr2_hi),
					AW(regs->ctpr3), AW(regs->ctpr3_hi));
		}

#ifdef	CONFIG_USE_AAU
		if (trace_intc_aau_enabled()) {
			e2k_aau_t *aau_context = regs->aau_context;

			if (AW(aau_context->guest_aasr))
				trace_intc_aau(aau_context, regs->lsr, regs->lsr1,
						regs->ilcr, regs->ilcr1);
		}
#endif
	}

	if (exceptions & exc_interrupt_mask)
		HANDLE_TIR_EXCEPTION(regs, exc_interrupt_num,
							handle_interrupt,
			pass_interrupt_to_guest,
			TIRs[0].TIR_hi.TIR_hi_reg, TIRs[0].TIR_lo.TIR_lo_reg);

	pass_virqs_to_guest(regs, TIRs[0].TIR_hi.TIR_hi_reg,
					TIRs[0].TIR_lo.TIR_lo_reg);


	/*
	 * 4) Open interrupts if possible
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
	 *  opening non-maskable interrupts can gretly increase
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
	if (enable_irqs)
		local_irq_enable();

#ifdef CONFIG_USE_AAU
	if (user) {
		int aa_field;

		/*
		 * For SDBGPRINT from do_aau_fault_*() -> do_page_fault()
		 * and for handle_forbidden_aau_load().
		 */
		TIR_lo = AW(TIRs[0].TIR_lo);
		TIR_hi = AW(TIRs[0].TIR_hi);
		trap->TIR_lo = TIR_lo;
		trap->TIR_hi = TIR_hi;

		/*
		 * AAU fault must be handled with open interrupts
		 */
		aa_field = GET_AA_TIRS(TIR_hi);
		if (aa_field) {
			unsigned long handled;

			/* check is trap occured on guest and */
			/* should be passed to guest kernel */
			handled = pass_aau_trap_to_guest(regs,
						TIR_hi, TIR_lo);
			if (!handled)
				machine.do_aau_fault(aa_field, regs);
		}
	}
#endif


	/*
	 * 5) Handle all other exceptions
	 */

#pragma loop count (2)
	do {
		TIR_hi = AW(TIRs[nr_TIRs].TIR_hi);
		TIR_lo = AW(TIRs[nr_TIRs].TIR_lo);

		trap->TIR_hi = TIR_hi;
		trap->TIR_lo = TIR_lo;
		trap->TIR_no = nr_TIRs;

#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
		trap_times->TIRs[nr_TIRs].TIR_hi.TIR_hi_reg = TIR_hi;
		trap_times->TIRs[nr_TIRs].TIR_lo.TIR_lo_reg = TIR_lo;
		if (nr_TIRs == 0) {
			trap_times->pcs_bounds =
				!!(TIR_hi & exc_chain_stack_bounds_mask);
			trap_times->ps_bounds =
				!!(TIR_hi & exc_proc_stack_bounds_mask);
		}
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */

		/*
		 * Define number of interrupt (nr_intrpt) and run needed handler
		 * 	(*exc_tbl[nr_intrpt])(regs);
		 */
		TIR_hi &= exc_all_mask;
#pragma loop count (1)
		for (nr_intrpt = __ffs64(TIR_hi); TIR_hi != 0;
				TIR_hi &= ~(1UL << nr_intrpt),
						nr_intrpt = __ffs64(TIR_hi)) {
			BUG_ON(nr_intrpt >= sizeof(exc_tbl)/sizeof(exc_tbl[0]));

			if ((1UL << nr_intrpt) & (non_maskable_exc_mask |
						  exc_interrupt_mask))
				continue;

			HANDLE_TIR_EXCEPTION(regs, nr_intrpt,
						*exc_tbl[nr_intrpt],
				pass_the_trap_to_guest,
				TIRs[0].TIR_hi.TIR_hi_reg,
				TIRs[0].TIR_lo.TIR_lo_reg);
		}
	} while (nr_TIRs-- > 0);

#ifdef	CONFIG_DUMP_ALL_STACKS
	if (unlikely(core_dump))
		pass_coredump_trap_to_guest(regs);
#endif	/* CONFIG_DUMP_ALL_STACKS */

	/* now it needs handle all traps passed to guest by guest kernel */
	handle_guest_traps(regs);

#ifdef	CONFIG_DUMP_ALL_STACKS
	if (unlikely(core_dump))
		coredump_in_future();
#endif	/* CONFIG_DUMP_ALL_STACKS */
}

DEFINE_RAW_SPINLOCK(die_lock);

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

static __cold void die(const char *str, struct pt_regs *regs, long err)
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

static inline void die_if_init(const char * str, struct pt_regs * regs, 
				 long err)
{
        struct task_struct *tsk = current;

	if (tsk->pid == 1)
		die(str, regs, err);
}

/*
 * The architecture-independent dump_stack generator
 */
void dump_stack(void)
{
	console_verbose();
	bust_spinlocks(1);
	print_stack_frames(current, NULL, 1);
	bust_spinlocks(0);
}
EXPORT_SYMBOL(dump_stack);

static void do_illegal_opcode(struct pt_regs *regs)
{
#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	thread_info_t *thread_info = current_thread_info();

	sys_e2k_print_kernel_times(current, thread_info->times,
		thread_info->times_num, thread_info->times_index);
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */

	if (!user_mode(regs)) {
		u32 *ip;

		if (is_kprobe_break1_trap(regs)) {
			notify_die(DIE_BREAKPOINT, "break", regs, 0,
						exc_illegal_opcode_num, SIGTRAP);
			return;
		}

		ip = (u32 *) AS(regs->trap->TIRs[0].TIR_lo).base;
		pr_alert("*0x%llx = 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x\n",
				(u64) ip, ip[0], ip[1], ip[2], ip[3],
				ip[4], ip[5], ip[6], ip[7]);
		die("illegal_opcode trap in kernel mode", regs, 0);
	} else {
		die_if_init("illegal_opcode trap in init process", regs, SIGILL);

		if (is_gdb_breakpoint_trap(regs)) {
			S_SIG(regs, SIGTRAP, exc_illegal_opcode_num, TRAP_BRKPT);
		} else {
			S_SIG(regs, SIGILL, exc_illegal_opcode_num, ILL_ILLOPC);
			SDBGPRINT_WITH_STACK("SIGILL. illegal_opcode");
		}
	}
}

static void do_priv_action(struct pt_regs *regs)
{
	die_if_kernel("priv_action trap in kernel mode", regs, 0);
	S_SIG(regs, SIGILL, exc_priv_action_num, ILL_PRVOPC);
	SDBGPRINT_WITH_STACK("SIGILL. priv_action");

}

static void do_fp_disabled(struct pt_regs *regs)
{
	if (machine.native_iset_ver >= E2K_ISET_V6)
		panic("fp_disabled trap was removed in iset v6\n");

	die_if_kernel("fp_disabled trap in kernel mode", regs, 0);
	S_SIG(regs, SIGILL, exc_fp_disabled_num, ILL_COPROC);
	SDBGPRINT_WITH_STACK("SIGILL. fp_disabled");
}

static void do_fp_stack_u(struct pt_regs *regs)
{
	die_if_kernel("fp_stack_u trap in kernel mode", regs, 0);
	S_SIG(regs, SIGFPE, exc_fp_stack_u_num, FPE_FLTINV);
	SDBGPRINT("SIGFPE. fp_stack_u");
}

static void *syscall_entry_begin = _t_entry + 0x800;
static void *syscall_entry_end = _t_entry_end;
static void do_d_interrupt(struct pt_regs *regs)
{
	die_if_kernel("d_interrupt trap in kernel mode", regs, 0);

	S_SIG(regs, SIGBUS, exc_d_interrupt_num, BUS_OBJERR);
	SDBGPRINT("SIGBUS. d_interrupt");

	if (TASK_IS_BINCO(current)) {
		/*
		 * UPSR.di == 1, VFDI called, and what must we do here?
		 *
		 * There are two cases:
		 * 1) if VFDI's long instructions does not have a system call
		 * then we just send a SIGSEGV.
		 * 2) if VFDI's long instructions contains a system call then
		 * we will set a special flag forbidding signal handling in
		 * interrupts so that it will be handled only after that
		 * system call.
		 *
		 * For details refer to bug #56664.
		 */
		void *ip = (void *) (AS(regs->crs.cr0_hi).ip << 3);
		if (ip >= syscall_entry_begin && ip < syscall_entry_end)
			set_delayed_signal_handling(current_thread_info());
	}
}

static void do_diag_ct_cond(struct pt_regs *regs)
{
	die_if_kernel("diag_ct_cond trap in kernel mode", regs, 0);

	S_SIG(regs, SIGILL, exc_diag_ct_cond_num, ILL_ILLOPN);
	SDBGPRINT_WITH_STACK("SIGILL. diag_ct_cond");
}

static void do_diag_instr_addr(struct pt_regs *regs)
{
	die_if_kernel("diag_instr_addr trap in kernel mode", regs, 0);

	S_SIG(regs, SIGILL, exc_diag_instr_addr_num, ILL_ILLADR);
	SDBGPRINT_WITH_STACK("SIGILL. diag_instr_addr");
}

static void do_illegal_instr_addr(struct pt_regs *regs)
{
	die_if_kernel("illegal_instr_addr trap in kernel mode", regs, 0);

	if (cpu_has(CPU_HWBUG_SPURIOUS_EXC_ILL_INSTR_ADDR)) {
		SDBGPRINT("Not sending SIGILL: illegal_instr_addr ignored");
	} else {
		S_SIG(regs, SIGILL, exc_illegal_instr_addr_num, SEGV_MAPERR);
		SDBGPRINT_WITH_STACK("SIGILL. illegal_instr_addr");
	}
}

static notrace void do_instr_debug(struct pt_regs *regs)
{
	e2k_dibsr_t dibsr;
	e2k_dimcr_t dimcr;

	nmi_enter();

	dimcr = dimcr_pause();

	/* Make sure gdb sees the new value */
	current->thread.sw_regs.dibsr = READ_DIBSR_REG();

	/* Call registered handlers */
	if (!user_mode(regs))
		kprobe_instr_debug_handle(regs);
	bp_instr_overflow_handle(regs);
	perf_instr_overflow_handle(regs);

	/* Send SIGTRAP if this was from ptrace */
	dibsr = READ_DIBSR_REG();
	if (dibsr.m0 || dibsr.m1 || dibsr.ss || dibsr.b0 ||
			dibsr.b1 || dibsr.b2 || dibsr.b3) {
		/* ptrace works in user space only */
		if ((current->flags & PF_KTHREAD) || !user_mode(regs))
			die("instr_debug trap in kernel mode", regs, 0);
		S_SIG(regs, SIGTRAP, exc_instr_debug_num, TRAP_HWBKPT);
		/* #24785 Customer asks us to avoid this annoying message
		SDBGPRINT("SIGTRAP. Stop on breakpoint"); */

		dibsr.m0 = 0;
		dibsr.m1 = 0;
		dibsr.b0 = 0;
		dibsr.b1 = 0;
		dibsr.b2 = 0;
		dibsr.b3 = 0;
		dibsr.ss = 0;
		WRITE_DIBSR_REG(dibsr);
	}

	dimcr_continue(dimcr);

	nmi_exit();
}

static void do_window_bounds(struct pt_regs *regs)
{
	die_if_kernel("window_bounds trap in kernel mode", regs, 0);
	S_SIG(regs, SIGSEGV, exc_window_bounds_num, SEGV_BOUNDS);
	SDBGPRINT_WITH_STACK("SIGSEGV. window_bounds");
}

static void do_user_stack_bounds(struct pt_regs *regs)
{
	die_if_kernel("user_stack_bounds trap in kernel mode", regs, 0);
	S_SIG(regs, SIGSEGV, exc_user_stack_bounds_num, SEGV_BOUNDS);
	SDBGPRINT_WITH_STACK("SIGSEGV. user_stack_bounds");
}

static void do_proc_stack_bounds(struct pt_regs *regs)
{
	die_if_kernel("proc_stack_bounds trap in kernel mode", regs, 0);

	if (handle_proc_stack_bounds(&regs->stacks, regs->trap)) {
		SDBGPRINT_WITH_STACK("SIGSEGV. Could not expand procedure stack");
		force_sig(SIGSEGV);
		return;
	}
}

static void do_chain_stack_bounds(struct pt_regs *regs)
{
	die_if_kernel("chain_stack_bounds trap in kernel mode", regs, 0);

	if (handle_chain_stack_bounds(&regs->stacks, regs->trap)) {
		SDBGPRINT_WITH_STACK("SIGSEGV. Could not expand chain stack");
		force_sig(SIGSEGV);
		return;
	}
}

static void do_fp_stack_o(struct pt_regs *regs)
{
	die_if_kernel("fp_stack_o trap in kernel mode", regs, 0);
	S_SIG(regs, SIGFPE, exc_fp_stack_o_num, FPE_FLTINV);
	SDBGPRINT("SIGFPE. fp_stack_o");
}

static void do_diag_cond(struct pt_regs *regs)
{
	die_if_kernel("diag_cond trap in kernel mode", regs, 0);

	S_SIG(regs, SIGILL, exc_diag_cond_num, ILL_ILLOPN);
	SDBGPRINT_WITH_STACK("SIGILL. diag_cond");
}

static void do_diag_operand(struct pt_regs *regs)
{
	/* Some history... */
	regs->trap->TIR_lo &= 0x0000ffffffffffff;

	DbgTC("start\n");
	DbgTC("regs->cr0: IP 0x%llx\n", GET_IP_CR0_HI(regs->crs.cr0_hi));
	die_if_kernel("diag_operand trap in kernel mode", regs, 0);
	die_if_init("diag_operand trap in init process", regs, 0);

	S_SIG(regs, SIGILL, exc_diag_operand_num, ILL_ILLOPN);
	SDBGPRINT_WITH_STACK("SIGILL. diag_operand");

	DbgTC("finish");
}

static void do_illegal_operand(struct pt_regs *regs)
{
	die_if_kernel("illegal_operand trap in kernel mode", regs, 0);
	die_if_init("illegal_operand trap in init process", regs, 0);

	S_SIG(regs, SIGILL, exc_illegal_operand_num, ILL_ILLOPN);
	SDBGPRINT_WITH_STACK("SIGILL. illegal_operand");
}

static void force_sigsegv_array_bounds(struct pt_regs *user_regs)
{
	void __user *addr;

	/* #100842 Pass address of the first byte below the stack */
	addr = (void __user *) (user_stack_pointer(user_regs) -
				AS(user_regs->stacks.usd_hi).size - 1);

	force_sig_fault(SIGSEGV, SEGV_ACCERR, addr, exc_array_bounds_num);
}


static void do_array_bounds(struct pt_regs *regs)
{
	void __user *fault_addr;
	int incr;

	die_if_kernel("array_bounds trap in kernel mode\n", regs, 0);

	switch (parse_getsp_operation(regs, &incr, &fault_addr)) {
	case GETSP_OP_INCREMENT:
		if (expand_user_data_stack(regs, (unsigned int) incr)) {
			force_sigsegv_array_bounds(regs);
			SDBGPRINT_WITH_STACK("SIGSEGV. expand on array_bounds");
		}
		break;
	case GETSP_OP_DECREMENT:
		if (constrict_user_data_stack(regs, incr)) {
			force_sig(SIGSEGV);
			SDBGPRINT_WITH_STACK("SIGSEGV. constrict on array_bounds");
		}
		break;
	case GETSP_OP_SIGSEGV:
		force_sig_fault(SIGSEGV, SEGV_BOUNDS, fault_addr, exc_array_bounds_num);
		SDBGPRINT_WITH_STACK("SIGSEGV. array_bounds - could not read getsp instruction");
		break;
	case GETSP_OP_FAIL:
		S_SIG(regs, SIGSEGV, exc_array_bounds_num, SEGV_BOUNDS);
		SDBGPRINT_WITH_STACK("SIGSEGV. array_bounds on not a getsp instruction");
		break;
	default:
		BUG();
	}
}

static void do_access_rights(struct pt_regs *regs)
{
	die_if_kernel("access_rights trap in kernel mode", regs, 0);

	S_SIG(regs, SIGSEGV, exc_access_rights_num, SEGV_ACCERR);
	SDBGPRINT_WITH_STACK("SIGSEGV. access_rights");
}

static void do_addr_not_aligned(struct pt_regs *regs)
{
	if (kernel_mode(regs)) {
		e2k_upsr_t upsr = NATIVE_NV_READ_UPSR_REG();

		pr_err("TRAP addr not aligned, UPSR.ac is %d\n",
			upsr.UPSR_ac);
		if (upsr.UPSR_ac) {
			upsr.UPSR_ac = 0;
			NATIVE_WRITE_UPSR_REG(upsr);
		} else {
			/* goto infinite loop to avoid recursion */
			do {
				mb();	/* to do not delete loop */
					/* by compiler */
				E2K_LMS_HALT_OK;
			} while (true);
		}
	}

	die_if_kernel("addr_not_aligned trap in kernel mode", regs, 0);

	S_SIG(regs, SIGBUS, exc_addr_not_aligned_num, BUS_ADRALN);
	SDBGPRINT_WITH_STACK("SIGBUS. addr_not_aligned");
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
		trap->nr_page_fault_exc = (AS(ftype).page_miss) ?
					exc_ainstr_page_miss_num :
					exc_ainstr_page_prot_num;
	} else {
		trap->nr_page_fault_exc = (AS(ftype).page_miss) ?
					exc_instr_page_miss_num :
					exc_instr_page_prot_num;
	}

	if (!async_instr) {
		e2k_tir_lo_t tir_lo;
		tir_lo.TIR_lo_reg = trap->TIR_lo;
		address = tir_lo.TIR_lo_ip;
	} else {
		address = AS_STRUCT(regs->ctpr2).ta_base;
	}
	AW(condition) = 0;
	AS(condition).store = 0;
	AS(condition).spec = 0;
	AS(condition).fmt = LDST_DWORD_FMT;
	AS(condition).fmtc = 0;
	AS(condition).fault_type = AW(ftype);
	AW(mask) = 0;
	ret = do_page_fault(regs, address, condition, mask, 1);
	if (ret == PFR_SIGPENDING)
		return;

	if (!async_instr && ((address & PAGE_MASK) !=
			((address + E2K_INSTR_MAX_SIZE - 1) & PAGE_MASK))) {
		instr_hs_t hs;
		instr_syl_t *user_hsp;
		int instr_size;

		user_hsp = &E2K_GET_INSTR_HS(address);
		while (unlikely(__get_user(AS_WORD(hs), user_hsp)))
			do_page_fault(regs, (e2k_addr_t) user_hsp,
					condition, mask, 1);
		instr_size = E2K_GET_INSTR_SIZE(hs);
		if ((address & PAGE_MASK) != ((address + instr_size - 1) &
								PAGE_MASK)) {
			address = PAGE_ALIGN_UP(address + instr_size);
			DebugPF("instruction on pages "
				"bounds: will start handle_mm_fault()"
				"for next page 0x%lx\n", address);
			(void) do_page_fault(regs, address, condition, mask, 1);
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
		e2k_fapb_instr_t *fapb_addr;
		int page_boundary_crossed;

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
		if (PAGE_ALIGN_UP(address) == PAGE_ALIGN_UP(address - 1
				+ MAX_ASYNC_PROGRAM_INSTRUCTIONS
					* E2K_ASYNC_INSTR_SIZE)) {
			/* Even the biggest asynchronous program will
			 * fit in this page, no need to do anything */
			page_boundary_crossed = 0;
		} else {
			int ct_found = 0;
			for (fapb_addr = (e2k_fapb_instr_t *) address;
					(unsigned long) fapb_addr <
						PAGE_ALIGN_UP(address - 1 +
						MAX_ASYNC_PROGRAM_INSTRUCTIONS
							* E2K_ASYNC_INSTR_SIZE);
					fapb_addr += 2) {
				e2k_fapb_instr_t fapb;

				while (unlikely(__get_user(AW(fapb),
						fapb_addr)))
					do_page_fault(regs,
							(e2k_addr_t) fapb_addr,
							condition, mask, 1);
				if (AS(fapb).ct) {
					ct_found = 1;
					break;
				}
			}

			if (ct_found) {
				/* Special case: even if we have found branch,
				 * the instruction with branch can itself cross
				 * pages boundary. */
				if (unlikely(PAGE_ALIGN_UP(fapb_addr) !=
						PAGE_ALIGN_UP(((u64) fapb_addr)
						+ E2K_ASYNC_INSTR_SIZE - 1)))
					page_boundary_crossed = 1;
				else
					page_boundary_crossed = 0;
			} else {
				page_boundary_crossed = 1;
			}
		}

		if (page_boundary_crossed) {
			address = PAGE_ALIGN_UP(address + PAGE_SIZE);
			DebugPF("asynchronous instruction on "
				"pages bounds: will start handle_mm_fault() "
				"for next page 0x%lx\n", address);
			(void) do_page_fault(regs, address, condition, mask, 1);
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
	AS(ftype).page_miss = 1;
	instr_page_fault(regs, ftype, 0);
}

static void do_instr_page_prot(struct pt_regs *regs)
{
	tc_fault_type_t ftype;

	AW(ftype) = 0;
	AS(ftype).illegal_page = 1;
	instr_page_fault(regs, ftype, 0);
}

static void do_ainstr_page_miss(struct pt_regs *regs)
{
	tc_fault_type_t ftype;

	AW(ftype) = 0;
	AS(ftype).page_miss = 1;
	instr_page_fault(regs, ftype, 1);
}

static void do_ainstr_page_prot(struct pt_regs *regs)
{
	tc_fault_type_t ftype;

	AW(ftype) = 0;
	AS(ftype).illegal_page = 1;
	instr_page_fault(regs, ftype, 1);
}

static void do_last_wish(struct pt_regs *regs)
{
	struct thread_info *ti = current_thread_info();

	if (user_mode(regs)) {
		getsp_adj_apply(regs);
	} else if (handle_guest_last_wish(regs)) {
		/* it is wish of host to support guest and it handled */
		return;
	} else {
		if (!kretprobe_last_wish_handle(regs))
			die("last_wish in kernel mode", regs, 0);
	}

	if (ti->last_wish && user_mode(regs)) {
		ti->last_wish = false;
		return;
	}

#ifdef CONFIG_PROTECTED_MODE
	/*
	 * "Last wish" exception can be induced either by debugger or 
	 * "SP -> global" handling mechanism.
	 * I will leave some space here for alternative code then execute
	 * the processor of the "global_sp" list.
	 */
	lw_global_sp(regs);
#endif /* CONFIG_PROTECTED_MODE */
}

static void do_base_not_aligned(struct pt_regs *regs)
{
	die_if_kernel("base_not_aligned in kernel mode", regs, 0);

	S_SIG(regs, SIGBUS, exc_base_not_aligned_num, BUS_ADRALN);
	SDBGPRINT_WITH_STACK("SIGBUS. Address base is not aligned");
}

int is_valid_bugaddr(unsigned long addr)
{
	return true;
}

static void do_software_trap(struct pt_regs *regs)
{
	if (user_mode(regs)) {
		S_SIG(regs, SIGTRAP, exc_software_trap_num, TRAP_BRKPT);
		SDBGPRINT("SIGTRAP. Software trap");
	} else {
		struct trap_pt_regs *trap = regs->trap;
		enum bug_trap_type btt;

		btt = report_bug(trap->TIRs[0].TIR_lo.TIR_lo_ip, regs);
		if (btt == BUG_TRAP_TYPE_WARN) {
			unsigned long ip = regs->crs.cr0_hi.CR0_hi_IP;
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

static notrace void do_data_debug(struct pt_regs *regs)
{
	e2k_ddbsr_t ddbsr;
	e2k_ddmcr_t ddmcr;

	nmi_enter();

	ddmcr = ddmcr_pause();

	/* Make sure gdb sees the new value */
	current->thread.sw_regs.ddbsr = READ_DDBSR_REG();

	/* Call registered handlers */
	bp_data_overflow_handle(regs);
	perf_data_overflow_handle(regs);

	ddbsr = READ_DDBSR_REG();
	if (ddbsr.m0 || ddbsr.m1 || ddbsr.b0 || ddbsr.b1 || ddbsr.b2 || ddbsr.b3) {
		if (DATA_BREAKPOINT_ON) {
			/* data breakpoint occured */
			dump_stack();
			goto out;
		}

		/* ptrace works in user space only */
		if ((current->flags & PF_KTHREAD) || !user_mode(regs)) {
			struct pt_regs *pregs = regs->next;
			const struct exception_table_entry *fixup;
			bool from_execute_mmu_op;

			/* get_user/put_user case: */
			fixup = search_exception_tables(
					regs->trap->TIRs[1].TIR_lo.TIR_lo_ip);
			from_execute_mmu_op = (pregs && pregs->flags.exec_mmu_op);

			if (!current_thread_info()->usr_pfault_jump &&
					!fixup && !from_execute_mmu_op)
				die("data_debug trap in kernel mode", regs, 0);
		}
		S_SIG(regs, SIGTRAP, exc_data_debug_num, TRAP_HWBKPT);
		/* #24785 Customer asks us to avoid this annoying message
		SDBGPRINT("SIGTRAP. Stop on watchpoint"); */

		ddbsr.m0 = 0;
		ddbsr.m1 = 0;
		ddbsr.b0 = 0;
		ddbsr.b1 = 0;
		ddbsr.b2 = 0;
		ddbsr.b3 = 0;
		WRITE_DDBSR_REG(ddbsr);
	}

out:
	ddmcr_continue(ddmcr);

	nmi_exit();
}

static void do_data_page(struct pt_regs *regs)
{
	struct trap_pt_regs *trap = regs->trap;

	DbgTC("call do_trap_cellar\n");
	if (!trap->tc_called) {
		trap->nr_page_fault_exc = exc_data_page_num;
		do_trap_cellar(regs, 1);
		do_trap_cellar(regs, 0);
		trap->tc_called = 1;
	}
	DbgTC("after do_trap_cellar\n");
	DbgTC("user_mode(regs) %d signal_pending(current) %d\n",
			user_mode(regs), signal_pending(current));
}

static void do_recovery_point(struct pt_regs *regs)
{
	unsigned long ip = get_trap_ip(regs);

	/* only for e2s/e8c/e1c+ and next */
	if (machine.native_iset_ver < E2K_ISET_V3)
		return do_unknown_exc(regs);

	if (!user_mode(regs)) {
		/* We do not warn about ".entry.text" section because
		 * there are places in it where it is legal to receive
		 * exc_recovery_point: between kernel entry (syscall entry,
		 * signal and makecontext trampolines) and up to "crp"
		 * instruction (including it).  False exc_recovery_point
		 * exceptions can be generated by hardware when loading
		 * instructions into L1$ (of course only when the
		 * "generations mode" is active). */
		if (ip < (unsigned long) __entry_handlers_start ||
				ip >= (unsigned long) __entry_handlers_end) {
			/* Should not happen, error in binco. */
			pr_info("%d [%s]: ERROR: exc_recovery_point received in kernel mode\n",
					current->pid, current->comm);
		}
		return;
	}
	if (!(TASK_IS_BINCO(current) && cpu_has(CPU_FEAT_ISET_V6))) {
		S_SIG(regs, SIGBUS, exc_recovery_point_num, BUS_OBJERR);
		SDBGPRINT("SIGBUS. exc_recovery_point");
	}
}

static notrace void __cpuidle return_from_cpuidle(void) { }

void __cpuidle handle_wtrap(struct pt_regs *regs)
{
	e2k_cr0_hi_t cr0_hi = regs->crs.cr0_hi;

	if (is_from_C3_wait_trap(regs)) {
		/* Instruction prefetch is disabled, re-enable it. */
		u64 mmu_cr = READ_MMU_CR() | _MMU_CR_IPD_MASK;
		WRITE_MMU_CR(__mmu_reg(mmu_cr));

		/* NMIs from local exceptions are disabled, re-enable them. */
		WRITE_DDBCR_REG(current->thread.C3.ddbcr);
		WRITE_DIBCR_REG(current->thread.C3.dibcr);
		WRITE_DDMCR_REG(current->thread.C3.ddmcr);
		WRITE_DIMCR_REG(current->thread.C3.dimcr);
	}

	AS(cr0_hi).ip = (unsigned long) return_from_cpuidle >> 3;
	regs->crs.cr0_hi = cr0_hi;
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

#ifdef CONFIG_MCST
	if (unlikely(show_woken_time) > 1) {
		per_cpu(prev_intr_clock, smp_processor_id()) =
				__this_cpu_read(last_intr_clock);
		per_cpu(last_intr_clock, smp_processor_id()) =
			getns64timeofday();
	}
#endif

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

	if (*interrupt[vector]) {
		(*interrupt[vector])(regs);
	} else {
		do_IRQ(regs, vector);
	}
	return IRQ_HANDLED;
}

noinline notrace void do_nm_interrupt(struct pt_regs *regs)
{
	nmi_enter();
	do_nmi(regs);
	nmi_exit();
}

static void do_division(struct pt_regs *regs)
{
	die_if_kernel("division trap in kernel mode", regs, 0);

	S_SIG(regs, SIGFPE, exc_div_num, FPE_INTDIV);
	SDBGPRINT("SIGFPE. Division by zero or overflow");
}

/*
 * IP for fp exection lay in TIRs
 */ 
static long get_fp_ip(struct trap_pt_regs *trap)
{
	e2k_tir_t *TIRs = trap->TIRs;
	e2k_tir_hi_t	tir_hi;
	e2k_tir_lo_t	tir_lo;
	int nr_TIRs = trap->nr_TIRs;
	int i;

	for (i = nr_TIRs; i >= 0; i --) {
		tir_hi = TIRs[i].TIR_hi;
                /* do_fp exection - 35 BIT */
                if (!(tir_hi.TIR_hi_exc & (1L<<35))) {
                    continue;
                }
		tir_lo = TIRs[i].TIR_lo;
                return tir_lo.TIR_lo_ip;
	}
        printk(" get_fp_ip not find IP\n");
	print_all_TIRs(trap->TIRs, trap->nr_TIRs);
        return 0;
}    

static void do_fp(struct pt_regs *regs)
{
	void __user *addr = (void __user *) get_fp_ip(regs->trap);
	int code = 0;
	unsigned int FPSR;
	unsigned int PFPFR;

	die_if_kernel("fp trap in kernel mode", regs, 0);

	FPSR = NATIVE_NV_READ_FPSR_REG_VALUE();
	PFPFR = NATIVE_NV_READ_PFPFR_REG_VALUE();

	if( FPSR & fp_es ) {
		if (FPSR & fp_pe)
			code = FPE_FLTRES;
		else if (FPSR & fp_ue)
			code = FPE_FLTUND;
		else if (FPSR & fp_oe)
			code = FPE_FLTOVF;
		else if (FPSR & fp_ze)
			code = FPE_FLTDIV;
		else if (FPSR & fp_de)
			code = FPE_FLTUND;
		else if (FPSR & fp_ie)
			code = FPE_FLTINV;
	} else {
		if (PFPFR & fp_pe)
			code = FPE_FLTRES;
		else if (PFPFR & fp_de)
			code = FPE_FLTUND;
		else if (PFPFR & fp_oe)
			code = FPE_FLTOVF;
		else if (PFPFR & fp_ie)
			code = FPE_FLTINV;
		else if (PFPFR & fp_ze)
			code = FPE_FLTDIV;
		else if (PFPFR & fp_ue)
			code = FPE_FLTUND;
	}

	force_sig_fault(SIGFPE, code, addr, 0);
	SDBGPRINT("SIGFPE. Floating point error");
}

static void do_mem_lock(struct pt_regs *regs)
{
	if (TASK_IS_BINCO(current)) {
		struct trap_pt_regs *trap = regs->trap;

		DebugML("started\n");
		DbgTC("call do_trap_cellar\n");
		if (!trap->tc_called) {
			trap->nr_page_fault_exc = exc_mem_lock_num;
			do_trap_cellar(regs, 1);
			do_trap_cellar(regs, 0);
			trap->tc_called = 1;
		}
		DbgTC("after do_trap_cellar\n");
		DbgTC("user_mode(regs) %d signal_pending(current) %d\n",
				user_mode(regs), signal_pending(current));
	} else {
		DebugML("do_mem_lock: send SIGBUS\n");
		S_SIG(regs, SIGBUS, exc_mem_lock_num, BUS_OBJERR);
		SDBGPRINT_WITH_STACK("SIGBUS. Memory lock signaled");
	}
}

static notrace void do_mem_lock_as(struct pt_regs *regs)
{
	nmi_enter();
#ifndef CONFIG_IGNORE_MEM_LOCK_AS
	if (TASK_IS_BINCO(current) && user_mode(regs)) {
		DebugML("started\n");
		S_SIG(regs, SIGBUS, exc_mem_lock_as_num, BUS_OBJERR);
		SDBGPRINT("SIGBUS. Memory lock AS signaled");
	}
#endif
	nmi_exit();
}

static void do_mem_error(struct pt_regs *regs)
{
	struct trap_pt_regs *trap = regs->trap;
	int trapno = 0;
	e2k_tir_hi_t tir_hi;
	e2k_tir_lo_t tir_lo;
	char *s;

	tir_lo.TIR_lo_reg = trap->TIR_lo;
	tir_hi.TIR_hi_reg = trap->TIR_hi;

	switch (tir_hi.TIR_hi_exc & exc_mem_error_mask) {
	case exc_mem_error_ICACHE_mask:
		trapno = exc_mem_error_ICACHE_num;
		s = "ICACHE";
		break;
	case exc_mem_error_L1_02_mask:
		trapno = exc_mem_error_L1_02_num;
		s = "L1 chanel 0, 2";
		break;
	case exc_mem_error_L1_35_mask:
		trapno = exc_mem_error_L1_35_num;
		s = "L1 chanel 3, 5";
		break;
	case exc_mem_error_L2_mask:
		trapno = exc_mem_error_L2_num;
		s = "L2";
		break;
	case exc_mem_error_MAU_mask:
		trapno = exc_mem_error_MAU_num;
		s = "MAU";
		break;
	case exc_mem_error_out_cpu_mask:
		trapno = exc_mem_error_out_cpu_num;
		s = "out cpu";
		break;
	default:
		s = "unknown";
		break;
	}

	if (likely(!sig_on_mem_err)) {
		panic("EXCEPTION: exc_mem_error TIR_hi.exc 0x%016llx (%s) TIR_lo.ip "
			"0x%016llx on cpu %d\n",
			tir_hi.TIR_hi_exc, s, tir_lo.TIR_lo_ip,
			raw_smp_processor_id());
	} else {
		S_SIG(regs, SIGUSR2, trapno, SI_KERNEL);
		SDBGPRINT("SIGUSR2. exc_mem_error");
	}
}

static void do_data_error(struct pt_regs *regs)
{
	/*
	 * 38 bit of TIRs was reused since iset v6, in iset v2 it's
	 * exc_mem_error, in iset v3, iset v4 and iset v5 it's unused.
	 */
	if (machine.native_iset_ver <= E2K_ISET_V2)
		return do_mem_error(regs);
	else if (machine.native_iset_ver < E2K_ISET_V6)
		BUG();

	S_SIG(regs, SIGBUS, exc_data_error_num, BUS_OBJERR);
	SDBGPRINT_WITH_STACK("SIGBUS. data_error");
}

__noreturn static void do_unknown_exc(struct pt_regs *regs)
{
	panic("EXCEPTION: Unknown e2k exception!!!\n");
}

/*
 * pseudo IRQ to emulate SysRq on guest kernel
 */
void native_sysrq_showstate_interrupt(struct pt_regs *regs)
{
	ack_pic_irq();
	/* dump stacks uses NMI to interrupt other CPUs and dump current */
	/* process state running on the CPU */
	raw_all_irq_enable();

	/* vcpu state is unavailable on native guest */
	show_state_filter(0);

	dump_stack();

	HYPERVISOR_vcpu_show_state_completion();
}

