/*
 * Copyright (C) 2001 MCST
 */


/**************************** DEBUG DEFINES *****************************/

#define	DEBUG_TRAP_CELLAR	0	/* DEBUG_TRAP_CELLAR */
#define DbgTC(...)		DebugPrint(DEBUG_TRAP_CELLAR ,##__VA_ARGS__)

#define	DEBUG_IRQ_MODE		0	/* interrupts */
#define DebugIRQ(...)		DebugPrint(DEBUG_IRQ_MODE ,##__VA_ARGS__)

/**************************** END of DEBUG DEFINES ***********************/

#include <linux/debug_locks.h>
#include <linux/init.h>
#include <linux/kdebug.h>
#include <linux/perf_event.h>
#include <linux/types.h>
#include <linux/ptrace.h>
#include <linux/ring_buffer.h>

#include <linux/unistd.h>
#include <linux/vmalloc.h>
#include <asm/cacheflush.h>
#include <asm/e2k_api.h>
#include <asm/processor.h>
#include <asm/cpu_regs_access.h>
#include <asm/regs_state.h>
#include <asm/process.h>
#include <asm/ptrace.h>
#include <asm/current.h>
#include <asm/traps.h>
#include <asm/delay.h>
#include <asm/sge.h>
#include <asm/uaccess.h>
#include <asm/console.h>

#ifdef CONFIG_USE_AAU
#include <asm/aau_context.h>
#endif

#ifdef CONFIG_RECOVERY
#include <asm/cnt_point.h>
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

#undef	DEBUG_PF_MODE
#undef	DebugPF
#define	DEBUG_PF_MODE		0	/* Page fault */
#define DebugPF(...)		DebugPrint(DEBUG_PF_MODE ,##__VA_ARGS__)

#undef	DEBUG_US_EXPAND
#undef	DebugUS
#define	DEBUG_US_EXPAND		0
#define DebugUS(...)		DebugPrint(DEBUG_US_EXPAND ,##__VA_ARGS__)

#undef	DEBUG_MEM_LOCK
#undef	DebugML
#define	DEBUG_MEM_LOCK		0
#define DebugML(...)		DebugPrint(DEBUG_MEM_LOCK ,##__VA_ARGS__)

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
static void do_data_debug(struct pt_regs *regs);
static void do_data_page(struct pt_regs *regs);
static void do_interrupt(struct pt_regs *regs);
static void do_nm_interrupt(struct pt_regs *regs);
static void do_division(struct pt_regs *regs);
static void do_fp(struct pt_regs *regs);
static void do_mem_lock(struct pt_regs *regs);
static void do_mem_lock_as(struct pt_regs *regs);
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
/*26*/	(exceptions)(do_unknown_exc),
/*27*/	(exceptions)(do_unknown_exc),
/*28*/	(exceptions)(do_data_debug),
/*29*/	(exceptions)(do_data_page),
/*30*/	(exceptions)(do_unknown_exc),
/*31*/	(exceptions)(do_recovery_point),
/*32*/	(exceptions)(do_interrupt),
/*33*/	(exceptions)(do_nm_interrupt),
/*34*/	(exceptions)(do_division),
/*35*/	(exceptions)(do_fp),
/*36*/	(exceptions)(do_mem_lock),
/*37*/	(exceptions)(do_mem_lock_as),
/*38*/	(exceptions)(do_mem_error),
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
/*26*/	"exc_unknown_exc",
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
/*38*/	"exc_mem_error",
/*39*/	"exc_mem_error",
/*40*/	"exc_mem_error",
/*41*/	"exc_mem_error",
/*42*/	"exc_mem_error",
/*43*/	"exc_mem_error"
};

#undef  GET_IP
#define GET_IP	( AS(regs->crs.cr0_hi).ip << E2K_ALIGN_INS )

#define	GDB_BREAKPOINT_STUB	0x0dc0c08004000001UL

extern void print_mmap(struct task_struct *task);

int debug_signal = 0;
static int __init sigdebug_setup(char *str)
{
	debug_signal = 1;
	return 1;
}
__setup("sigdebug", sigdebug_setup);

static inline void
do_trap_init(void)
{
	/* Enable system calls for user's processes. */
	unsigned int linux_osem = 0;

	/* Enable deprecated generic ttable2 syscall entry. */
	linux_osem = 1 << LINUX_SYSCALL_TRAPNUM_OLD;

	/* Enable ttable1 syscall entry - 32-bit syscalls only */
	linux_osem |= 1 << LINUX_SYSCALL32_TRAPNUM;
	/* Enable ttable3 syscall entry - 64-bit syscalls only */
	linux_osem |= 1 << LINUX_SYSCALL64_TRAPNUM;

	/* Enable fast syscalls entries. */
	linux_osem |= 1 << LINUX_FAST_SYSCALL32_TRAPNUM;
	linux_osem |= 1 << LINUX_FAST_SYSCALL64_TRAPNUM;
	linux_osem |= 1 << LINUX_FAST_SYSCALL128_TRAPNUM;

#ifdef CONFIG_PROTECTED_MODE
	linux_osem |= (1 << PMODE_NEW_SYSCALL_TRAPNUM);
#endif /* CONFIG_PROTECTED_MODE */

	E2K_SET_SREG(osem, linux_osem);
}

#ifdef	CONFIG_RECOVERY
# ifdef	CONFIG_TIME_TO_RESTART
long	time_to_restart_kernel = (CONFIG_TIME_TO_RESTART * HZ);
# else
long	time_to_restart_kernel = 0;
# endif	/* CONFIG_TIME_TO_RESTART */

static	unsigned long kernel_restart_last_jiffies = 0UL;
extern	int e2k_kernel_started;

void
trap_recovery(void)
{
	do_trap_init();
}
#endif	/* CONFIG_RECOVERY */

void __init_recv
trap_init(void)
{
	do_trap_init();
}

void show_registers(struct pt_regs *regs)
{
	e2k_psr_t psr;
	
	printk("---------------------------- "
	       "CPU Registers values:"
	       " ----------------------------\n");
	
	printk("CR0.lo pf = 0x%016lx\n\n", AW(regs->crs.cr0_lo));
	
	printk("CR0.hi = 0x%016lx:\n"
	       " ip %016lx\n\n", AW(regs->crs.cr0_hi), GET_IP);
	AS_WORD(psr) = AS_STRUCT(regs->crs.cr1_lo).psr;
	printk("CR1.lo = 0x%016lx:\n"
		" tr  = 0x%04x, wfx  = 0x%04x, wpsz     = 0x%04x,\n"
		" wbs = 0x%04x, cuir = 0x%04x, pm       = 0x%04x,\n"
		" ie  = 0x%04x, sge  = 0x%04x, lw       = 0x%04x,\n"
		" uie = 0x%04x, nmie = 0x%04x, unmie    = 0x%04x.\n\n",
		AW(regs->crs.cr1_lo),
		(u16)AS(regs->crs.cr1_lo).tr,
		(u16)AS(regs->crs.cr1_lo).wfx,
		(u16)AS(regs->crs.cr1_lo).wpsz,
		(u16)AS(regs->crs.cr1_lo).wbs,
		(u16)AS(regs->crs.cr1_lo).cuir,
		(u16)AS(psr).pm,(u16)AS(psr).ie,
		(u16)AS(psr).sge,(u16)AS(psr).lw,
		(u16)AS(psr).uie,(u16)AS(psr).nmie,
		(u16)AS(psr).unmie);

	printk("CR1.hi = 0x%016lx:\n"
	       " br  = 0x%08x, ussz = 0x%08x\n\n",
	       AW(regs->crs.cr1_hi), (u32)AS(regs->crs.cr1_hi).br,
	       (u32)AS(regs->crs.cr1_hi).ussz);

	printk("PSP.base  = 0x%016lx, PSP.ind    = 0x%08x, PSP.size  = 0x%08x\n",
		(u64)AS(regs->stacks.psp_lo).base,
		(u32)AS(regs->stacks.psp_hi).ind,
		(u32)AS(regs->stacks.psp_hi).size);
	printk("PCSP.base = 0x%016lx, PCSP.ind   = 0x%08x, PCSP.size = 0x%08x\n",
		(u64)AS(regs->stacks.pcsp_lo).base,
		(u32)AS(regs->stacks.pcsp_hi).ind,
		(u32)AS(regs->stacks.pcsp_hi).size);
        printk("USD.lo = 0x%016lx;   USD.hi = 0x%16lx\n",
                AS_WORD(regs->stacks.usd_lo), AS_WORD(regs->stacks.usd_hi));
	printk("USD.base  = 0x%016lx, USD.curptr = 0x%08x, USD.size  = 0x%08x\n",
		(u64)AS(regs->stacks.usd_lo).base,
		(u32)(regs->stacks.usd_hi._USD_hi_curptr),
		(u32)AS(regs->stacks.usd_hi).size);
	printk("SBR       = 0x%08lx\n", regs->stacks.sbr);
	printk("-----------------------------------------"
	       "---------------------------------------\n");
}


#if 0
void print_TIRj(unsigned long TIR_hi, unsigned long TIR_lo)
{
	int nr_inrpt, nr_TIRs;
	nr_TIRs = GET_NR_TIRS(TIR_hi);
		
	printk("\n nr_TIRs = %d, TIR_hi = 0x%lx, TIR_lo = 0x%lx \n",
		nr_TIRs, TIR_hi, TIR_lo);
	TIR_hi &= 0x1FFFFFFFFF;
	nr_inrpt = 0;
	while (TIR_hi != 0) {
		if ((TIR_hi & 0x1) != 0) {
			printk(" exception = %s \n",exc_tbl_name[nr_inrpt]);
		}
		TIR_hi >>= 1;
		nr_inrpt++;
	}
}
#endif

extern int  print_kernel_threads;

void  start_dump_print(void)
{
#if defined(CONFIG_SERIAL_PRINTK)
	use_boot_printk_all = 1;
#endif
	oops_in_progress = 1;
	print_kernel_threads = 1;
	flush_TLB_all();
	ftrace_dump(DUMP_ALL);
	console_verbose();
}

void  stop_dump_print(void)
{
#if defined(CONFIG_SERIAL_PRINTK)
	use_boot_printk_all = 0;
#endif
	oops_in_progress = 0;
	console_silent();
}

atomic_t cpus_finished = ATOMIC_INIT(0);

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

extern void start_emergency_dump(void);

#ifdef	CONFIG_DUMP_ALL_STACKS
static void do_coredump_in_future(void)
{
# ifdef CONFIG_SMP
	unsigned long flags;
	int count = 0;

start:
	if(!raw_spin_trylock_irqsave(&print_lock, flags)) {
		__delay(100);
		if (count++ < 2) {
			goto start;
		}
		raw_spin_lock_init(&print_lock);
		raw_spin_lock_irqsave(&print_lock, flags);
	}
# endif /* CONFIG_SMP */

	print_stack(current);

	if (my_cpu_is_main) {
		show_state();
		flush_printk_buffer();
	}

# ifdef CONFIG_SMP
	raw_spin_unlock_irqrestore(&print_lock, flags);
# endif
	atomic_inc(&cpus_finished);
}

__noreturn static void coredump_in_future(void)
{
# ifdef CONFIG_SMP
	my_cpu_is_main = (atomic_inc_return(&one_finished) == 1);
# endif
	if (my_cpu_in_dump) {
		/*
		 * recursive dump of stacks, so now needs call core dump
		 * of all memory through boot
		 */
		start_emergency_dump();
# ifdef CONFIG_SMP
		vprint_lock.lock = 0; /* unlocked */
# endif
	}
	my_cpu_in_dump = 1;
	start_dump_print();
	do_coredump_in_future();
	while (1) {
		if (IS_MACHINE_SIM) {
			if (atomic_read(&cpus_finished) == num_online_cpus()) {
				start_emergency_dump();
			}
		}
		barrier();
	}
}
#endif	/* CONFIG_DUMP_ALL_STACKS */

static inline int
check_getsp_operation(struct trap_pt_regs *regs)
{
	instr_hs_t hs;
	instr_alsf2_t als0;
	instr_alesf2_t ales0;
	instr_syl_t *user_sp;
	instr_semisyl_t *user_semisp;
	e2k_addr_t trap_ip;
	tir_hi_struct_t tir_hi;
	tir_lo_struct_t tir_lo;

	tir_lo.TIR_lo_reg = regs->TIR_lo;
	trap_ip = tir_lo.TIR_lo_ip;
	tir_hi.TIR_hi_reg = regs->TIR_hi;

	DebugUS("started for IP 0x%lx, TIR_hi_al 0x%x\n",
		trap_ip, tir_hi.TIR_hi_al);
	if (!(tir_hi.TIR_hi_al & ALS0_mask)) {
		DebugUS("exeption is not for ALS0\n");
		return 0;
	}
	user_sp = &E2K_GET_INSTR_HS(trap_ip);
	__get_user(AS_WORD(hs), user_sp);
	if (!(AS_STRUCT(hs).al & ALS0_mask)) {
		DebugUS("command has not AL0 Syllable: 0x%08x\n", AW(hs));
		return 0;
	}
	user_sp = &E2K_GET_INSTR_ALS0(trap_ip, (AS_STRUCT(hs).s));
	__get_user(AS_WORD(als0), user_sp);
	DebugUS("ALS0 syllable 0x%08x get from addr 0x%p\n", AW(als0), user_sp);
	if (AS_STRUCT(als0).cop == DRTOAP_ALS_COP &&
		AS_STRUCT(als0).opce == USD_ALS_OPCE &&
		!(AS_STRUCT(hs).ale & ALS0_mask)) {
		DebugUS("detected GETSAP operation: ALS0.cop 0x%02x opce 0x%02x\n",
			AS_STRUCT(als0).cop, AS_STRUCT(als0).opce);
		return 1;
	} else if (!(AS_STRUCT(hs).ale & ALS0_mask)) {
		DebugUS("command has not ALU0 extention syllable, so can not be GETSP\n");
		return 0;
	} else if (AS_STRUCT(als0).opce != USD_ALS_OPCE) {
		DebugUS("command ALU0.opce 0x%x is not USD, so it can not be GETSP\n",
				AS(als0).opce);
		return 0;
	}
	user_semisp = &E2K_GET_INSTR_ALES0(trap_ip, AS_STRUCT(hs).mdl);
	__get_user(AS_WORD(ales0), user_semisp);
	DebugUS("ALES0 syllable 0x%04x get from addr 0x%p\n",
			AS_WORD(ales0), user_semisp);
	if (AS_STRUCT(ales0).opc2 != EXT_ALES_OPC2) {
		DebugUS("ALES0 opcode #2 0x%02x is not EXT, so it is not GETSP\n",
				AS_STRUCT(ales0).opc2);
		return 0;
	} else if (AS(als0).cop == GETSP_ALS_COP) {
		DebugUS("detected GETSP operation: ALS0.cop 0x%02x\n",
				AS(als0).cop);
		return 1;
	}
	DebugUS("could not detect SP operation\n");
	return 0;
}

static inline u64 TIR0_clear_false_exceptions(u64 TIR_hi, int nr_TIRs)
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
				DbgTC("ignore precise traps in TIR0 0x%lx\n",
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

#define HANDLE_TIR_EXCEPTION(regs, exc_num, func) \
do { \
	read_ticks(start_tick); \
 \
	(func)(regs); \
 \
	add_info_interrupt(exc_num, start_tick); \
	INCREASE_TRAP_NUM(trap_times); \
} while (0)

static __always_inline void handle_nm_exceptions(struct pt_regs *regs, u64 nmi)
{
	/*
	 * Handle NMIs from TIR0
	 */
	if (nmi & exc_instr_debug_mask)
		HANDLE_TIR_EXCEPTION(regs, exc_instr_debug_num, do_instr_debug);

	/*
	 * Handle NMIs from TIR1
	 */
	if (nmi & exc_data_debug_mask)
		HANDLE_TIR_EXCEPTION(regs, exc_data_debug_num, do_data_debug);

	/*
	 * Handle NMIs from the last TIR
	 */
	if (nmi & exc_nm_interrupt_mask)
		HANDLE_TIR_EXCEPTION(regs, exc_nm_interrupt_num,
				     do_nm_interrupt);
	if (nmi & exc_mem_lock_as_mask)
		HANDLE_TIR_EXCEPTION(regs, exc_mem_lock_as_num, do_mem_lock_as);
}

/**
 * parse_TIR_registers - call handlers for all arrived exceptions
 * @regs: saved context
 * @exceptions: mask of all arrived exceptions
 */
__section(.entry_handlers)
notrace void parse_TIR_registers(struct pt_regs *regs, u64 exceptions)
{
	struct trap_pt_regs *trap = regs->trap;
	register unsigned long	TIR_hi, TIR_lo;
	register unsigned long	nr_TIRs = trap->nr_TIRs;
	register unsigned int	nr_intrpt;
	e2k_tir_t		*TIRs = trap->TIRs;
#ifdef	CONFIG_PROFILING
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
				   (AW(TIRs[1].hi) & exc_data_page_mask) &&
				    !in_atomic() &&
			     likely(!(current->thread.flags & E_MMU_NESTED_OP));
#ifdef CONFIG_DUMP_ALL_STACKS
	bool core_dump = unlikely(nr_TIRs == 0 &&
				  AS(TIRs[0].hi).exc == 0 &&
				  AS(TIRs[0].hi).aa == 0);
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

	AW(TIRs[0].hi) = TIR0_clear_false_exceptions(AW(TIRs[0].hi), nr_TIRs);


	/*
	 * 1) Handle NMIs
	 */

	if (unlikely(nmi))
		handle_nm_exceptions(regs, nmi);


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
	SWITCH_IRQ_TO_UPSR(false);
	trace_hardirqs_off();


	/*
	 * 3) Handle external interrupts before enabling interrupts
	 */

	if (exceptions & exc_interrupt_mask)
		HANDLE_TIR_EXCEPTION(regs, exc_interrupt_num, do_interrupt);


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
		 * AAU fault must be handled with open interrupts
		 */
		aa_field = AS(TIRs[0].hi).aa;
		if (aa_field)
			do_aau_fault(aa_field, regs);
	}
#endif


	/*
	 * 5) Handle all other exceptions
	 */

#pragma loop count (2)
	do {
		TIR_hi = AW(TIRs[nr_TIRs].hi);
		TIR_lo = AW(TIRs[nr_TIRs].lo);

		trap->TIR_hi = TIR_hi;
		trap->TIR_lo = TIR_lo;

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
			if ((1UL << nr_intrpt) & (non_maskable_exc_mask |
						  exc_interrupt_mask))
				continue;

			HANDLE_TIR_EXCEPTION(regs, nr_intrpt,
					     *exc_tbl[nr_intrpt]);
		}
	} while (nr_TIRs-- > 0);

#ifdef	CONFIG_DUMP_ALL_STACKS
	if (unlikely(core_dump))
	    	coredump_in_future();
#endif	/* CONFIG_DUMP_ALL_STACKS */
}

DEFINE_RAW_SPINLOCK(die_lock);

static __cold void die(const char *str, struct pt_regs *regs, long err)
{
	console_verbose();
	raw_spin_lock_irq(&die_lock);
	pr_alert("die %s: %lx\n", str, err);
	print_stack(current);
	show_registers(regs);
	raw_spin_unlock_irq(&die_lock);
	do_exit(SIGSEGV);	
}

static inline void die_if_kernel(const char *str, struct pt_regs *regs,
				 long err)
{
	/* Check SBR. This check can be wrong only in one case: when
	 * we get an exc_array_bounds upon entering system call, but
	 * it is OK. This way fast system calls code is also detected
	 * as user mode (as it should). */
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
	print_stack_frames(current, 1, 0);
}
EXPORT_SYMBOL(dump_stack);

static void do_illegal_opcode(struct pt_regs *regs)
{
	u64 *instr = (u64 *) GET_IP;
#ifdef	CONFIG_KPROBES
	int kprobed = 0;
#endif	/* CONFIG_KPROBES */
#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	thread_info_t *thread_info = current_thread_info();
	sys_e2k_print_kernel_times(current, thread_info->times,
		thread_info->times_num, thread_info->times_index);
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */
#ifdef CONFIG_KPROBES
	switch (*instr) {
	case KPROBE_BREAK_1:
		notify_die(DIE_BREAKPOINT, "break", regs, 0,
					exc_illegal_opcode_num, SIGTRAP);
		kprobed = 1;
		break;
	case KPROBE_BREAK_2:
		notify_die(DIE_SSTEP, "sstep", regs, 0,
					exc_illegal_opcode_num, SIGTRAP);
		kprobed = 1;
		break;
	}
	if (kprobed)
		return;
#endif /* CONFIG_KPROBES */

	die_if_kernel("illegal_opcode trap in kernel mode", regs, 0);
	die_if_init("illegal_opcode trap in init process", regs, SIGILL);
	if (*instr == GDB_BREAKPOINT_STUB)
	{
		S_SIG(regs, SIGTRAP, exc_illegal_opcode_num, TRAP_BRKPT);
		CHK_DEBUGGER(0, SIGTRAP, SIGTRAP, 0xF, regs, )
	} else {
		S_SIG(regs, SIGILL, exc_illegal_opcode_num, ILL_ILLOPC);
		SDBGPRINT("SIGILL. illegal_opcode");
		CHK_DEBUGGER(0, SIGILL, SIGILL, 0xF, regs, )
	}
}

static void do_priv_action(struct pt_regs *regs)
{
	die_if_kernel("priv_action trap in kernel mode", regs, 0);
	S_SIG(regs, SIGILL, exc_priv_action_num, ILL_PRVOPC);
	SDBGPRINT("SIGILL. priv_action");

}

static void do_fp_disabled(struct pt_regs *regs)
{
	die_if_kernel("fp_disabled trap in kernel mode", regs, 0);
	S_SIG(regs, SIGILL, exc_fp_disabled_num, ILL_COPROC);
	SDBGPRINT("SIGILL. fp_disabled");
}

static void do_fp_stack_u(struct pt_regs *regs)
{
	die_if_kernel("fp_stack_u trap in kernel mode", regs, 0);
	S_SIG(regs, SIGFPE, exc_fp_stack_u_num, FPE_FLTINV);
	SDBGPRINT("SIGFPE. fp_stack_u");
}

extern void _t_entry, _t_entry_end;
static void *syscall_entry_begin = &_t_entry + 0x800;
static void *syscall_entry_end = &_t_entry_end;
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
	SDBGPRINT("SIGILL. diag_ct_cond");
}

static void do_diag_instr_addr(struct pt_regs *regs)
{
	die_if_kernel("diag_instr_addr trap in kernel mode", regs, 0);

	S_SIG(regs, SIGILL, exc_diag_instr_addr_num, ILL_ILLADR);
	SDBGPRINT("SIGILL. diag_instr_addr");
}

static void do_illegal_instr_addr(struct pt_regs *regs)
{
	die_if_kernel("illegal_insr_addr trap in kernel mode", regs, 0);

#ifdef	DEBUG_TRAPS
	printk("do_illegal_instr_addr: regs->ctpr1 %lx\n",
		AS_WORD(regs->ctpr1));
	printk("regs->CR0.hi ip 0x%lx\n",
		(long)AS_STRUCT(regs->crs.cr0_hi).ip << E2K_ALIGN_INS);
	print_stack(current);
	print_mmap(current);
#endif	/* DEBUG_TRAPS */
	S_SIG(regs, SIGILL, exc_illegal_instr_addr_num, SEGV_MAPERR);
	SDBGPRINT("SIGILL. illegal_instr_addr");
}

static notrace void do_instr_debug(struct pt_regs *regs)
{
	nmi_enter();

	inc_irq_stat(__nmi_count);

#ifdef CONFIG_PERF_EVENTS
	if (perf_instr_overflow_handle(regs))
		goto out;
#endif

	die_if_kernel("instr_debug trap in kernel mode", regs, 0);
	die_if_init("instr_debug trap in init process", regs, SIGTRAP);
	S_SIG(regs, SIGTRAP, exc_instr_debug_num, TRAP_HWBKPT);

#if 0	/* #24785 Customer asks us to avoid this annoying message */
	SDBGPRINT("SIGTRAP. Stop on breakpoint");
#endif	/* #24785 */

	CHK_DEBUGGER(8, SIGTRAP, SIGTRAP, 0xF, regs, )

#ifdef CONFIG_PERF_EVENTS
out:
#endif
	nmi_exit();
}

static void do_window_bounds(struct pt_regs *regs)
{
	die_if_kernel("window_bounds trap in kernel mode", regs, 0);
	S_SIG(regs, SIGSEGV, exc_window_bounds_num, SEGV_BOUNDS);
	SDBGPRINT("SIGSEGV. window_bounds");
}

static void do_user_stack_bounds(struct pt_regs *regs)
{
	die_if_kernel("user_stack_bounds trap in kernel mode", regs, 0);
	print_stack(current);
	S_SIG(regs, SIGSEGV, exc_user_stack_bounds_num, SEGV_BOUNDS);
	SDBGPRINT("SIGSEGV. user_stack_bounds");
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
	SDBGPRINT("SIGILL. diag_cond");
}

static void do_diag_operand(struct pt_regs *regs)
{
	/* Some history... */
	regs->trap->TIR_lo &= 0x0000ffffffffffff;

	DbgTC("start\n");
	DbgTC("regs->cr0: IP 0x%lx\n", GET_IP);
	die_if_kernel("diag_operand trap in kernel mode", regs, 0);
	die_if_init("diag_operand trap in init process", regs, 0);

	S_SIG(regs, SIGILL, exc_diag_operand_num, ILL_ILLOPN);
	SDBGPRINT("SIGILL. diag_operand");

	DbgTC("finish");
}

static void do_illegal_operand(struct pt_regs *regs)
{
	die_if_kernel("illegal_operand trap in kernel mode", regs, 0);
	die_if_init("illegal_operand trap in init process", regs, 0);

	S_SIG(regs, SIGILL, exc_illegal_operand_num, ILL_ILLOPN);
	SDBGPRINT("SIGILL. illegal_operand");
}

static void do_array_bounds(struct pt_regs *regs)
{
#ifndef CONFIG_ALLOC_MAX_STACK
	struct trap_pt_regs *trap = regs->trap;

	if (user_mode(regs) && check_getsp_operation(trap) &&
			regs->stacks.usd_lo.USD_lo_base < TASK_SIZE) {
		expand_user_data_stack(regs, current, false);
		return;
	}
#endif
	die_if_kernel("array_bounds trap in kernel mode\n", regs, 0);
	die_if_init("array_bounds trap in init process", regs, 0);
	S_SIG(regs, SIGSEGV, exc_array_bounds_num, SEGV_BOUNDS);
	SDBGPRINT("SIGSEGV. array_bounds");
}

static void do_access_rights(struct pt_regs *regs)
{
	die_if_kernel("access_rights trap in kernel mode", regs, 0);

	S_SIG(regs, SIGSEGV, exc_access_rights_num, SEGV_ACCERR);
	SDBGPRINT("SIGSEGV. access_rights");
}

static void do_addr_not_aligned(struct pt_regs *regs)
{
	die_if_kernel("addr_not_aligned trap in kernel mode", regs, 0);

	S_SIG(regs, SIGBUS, exc_addr_not_aligned_num, BUS_ADRALN);
	SDBGPRINT("SIGBUS. addr_not_aligned");
}

static inline void
instr_page_fault(struct pt_regs *regs, tc_fault_type_t ftype,
		const int async_instr)
{
	struct trap_pt_regs *trap = regs->trap;
	e2k_addr_t address;
	tc_cond_t  condition;
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
		tir_lo_struct_t tir_lo;
		tir_lo.TIR_lo_reg = trap->TIR_lo;
		address = tir_lo.TIR_lo_ip;
	} else {
		address = AS_STRUCT(regs->ctpr2).ta_base;
	}
	AW(condition) = 0;
	AS(condition).store = 0;
	AS(condition).spec = 0;
	AS(condition).fault_type = AW(ftype);
	ret = do_page_fault(regs, address, &condition, 1);
	if (ret <= 0)
		return;

	if (!async_instr && ((address & PAGE_MASK) !=
			((address + E2K_INSTR_MAX_SIZE - 1) & PAGE_MASK))) {
		instr_hs_t hs;
		instr_syl_t *user_hsp;
		int instr_size;

		user_hsp = &E2K_GET_INSTR_HS(address);
		while (unlikely(__get_user(AS_WORD(hs), user_hsp)))
			do_page_fault(regs, (e2k_addr_t) user_hsp,
					&condition, 1);
		instr_size = E2K_GET_INSTR_SIZE(hs);
		if ((address & PAGE_MASK) != ((address + instr_size - 1) &
								PAGE_MASK)) {
			address = PAGE_ALIGN_UP(address + instr_size);
			DebugPF("instruction on pages "
				"bounds: will start handle_mm_fault()"
				"for next page 0x%lx\n", address);
			(void) do_page_fault(regs, address, &condition, 1);
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

#if __LCC__ >= 120
				while (unlikely(__get_user(AW(fapb),
						fapb_addr)))
#else
				while (unlikely(__get_user(fapb, fapb_addr)))
#endif
					do_page_fault(regs,
							(e2k_addr_t) fapb_addr,
							&condition, 1);
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
			(void) do_page_fault(regs, address, &condition, 1);
		}
	}
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

static void notrace do_last_wish(struct pt_regs *regs)
{
	die_if_kernel("last_wish in kernel mode", regs, 0);

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
	SDBGPRINT("SIGBUS. Address base is not aligned");
}

static notrace void do_data_debug(struct pt_regs *regs)
{
	nmi_enter();

	inc_irq_stat(__nmi_count);

#ifdef CONFIG_PERF_EVENTS
	if (perf_data_overflow_handle(regs))
		goto out;
#endif

	if (!current_thread_info()->usr_pfault_jump)
		die_if_kernel("data_debug trap in kernel mode", regs, 0);
	die_if_init("data_debug trap in init process", regs, SIGTRAP);

	S_SIG(regs, SIGTRAP, exc_data_debug_num, TRAP_HWBKPT);

#if 0	/* #24785 Customer asks us to avoid this annoying message */
	SDBGPRINT("SIGTRAP. Stop on watchpoint");
#endif	/* #24785 */

	CHK_DEBUGGER(28, SIGTRAP, SIGTRAP, 0xF, regs, )

#ifdef CONFIG_PERF_EVENTS
out:
#endif
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
	/* only for e2s/e8c/e1c+ and next */
	if (machine.iset_ver < E2K_ISET_V3)
		return do_unknown_exc(regs);

	if (!user_mode(regs)) {
		/* Should not happen, error in binco */
		pr_info("%d [%s]: ERROR: exc_recovery_point received in kernel mode\n",
			current->pid, current->comm);
		return;
	}
	S_SIG(regs, SIGBUS, exc_recovery_point_num, BUS_OBJERR);
	SDBGPRINT("SIGBUS. do_recovery_point_exc");
}

static void do_interrupt(struct pt_regs *regs)
{
	int vector = machine.get_irq_vector();
	thread_info_t *thread_info = current_thread_info();

#ifdef CONFIG_MCST
	if (unlikely(show_woken_time) > 1) {
		per_cpu(prev_intr_clock, smp_processor_id()) =
				__get_cpu_var(last_intr_clock);
		per_cpu(last_intr_clock, smp_processor_id()) =
			getns64timeofday();
	}
#endif
	if (unlikely(thread_info->wtrap_jump_addr)) {
		if (thread_info->wtrap_jump_addr != PG_JMP) {
			AS_STRUCT(regs->crs.cr0_hi).ip =
				(thread_info->wtrap_jump_addr >> 3);
		}
		thread_info->wtrap_jump_addr = 0UL;
	}

	DebugIRQ("CPU #%d will start 0x%pS on vector %02x "
			"(IRQ %d)\n", smp_processor_id(),
			interrupt[vector], vector,
			__raw_get_cpu_var(vector_irq)[vector]);

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

#ifdef	CONFIG_RECOVERY
	if (unlikely(IS_BOOT_STRAP_CPU() && time_to_restart_kernel != 0)) {
		long rest_jiffies;
		rest_jiffies = time_to_restart_kernel -
				(jiffies - kernel_restart_last_jiffies);
		if (rest_jiffies <= 0) {
			if (e2k_kernel_started) {
				DebugIRQ("time to restart "
					"system: jiffies 0x%lx last restart "
					"jiffies 0x%lx interval 0x%lx\n",
					jiffies, kernel_restart_last_jiffies,
					time_to_restart_kernel);
				kernel_restart_last_jiffies = jiffies;
				if (!cnt_points_created)
					(void) create_control_point(1);
				else if (recreate_cnt_points)
					(void) create_control_point(1);
				else
					emergency_restart_system();
			} else {
				kernel_restart_last_jiffies = jiffies;
			}
		} else if (rest_jiffies > time_to_restart_kernel &&
				kernel_restart_last_jiffies != 0) {
			panic("do_interrupt() bad jiffies 0x%lx < "
				"last restart jiffies 0x%lx\n",
				jiffies, kernel_restart_last_jiffies);
		}
	}
#endif	/* CONFIG_RECOVERY */
}

static noinline notrace void do_nm_interrupt(struct pt_regs *regs)
{
	do_nmi(regs);
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
	tir_hi_struct_t	tir_hi;
	tir_lo_struct_t	tir_lo;
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
	siginfo_t info;
	unsigned int FPSR;
	unsigned int PFPFR;

	die_if_kernel("fp trap in kernel mode", regs, 0);

	info.si_signo = SIGFPE;
	info.si_errno = SI_EXC;
	info.si_addr = (void __user *) get_fp_ip(regs->trap);
	info.si_trapno = 0;
	info.si_code = __SI_FAULT;

	FPSR = E2K_GET_SREG_NV(fpsr);
	PFPFR = E2K_GET_SREG_NV(pfpfr);
	
	if( FPSR & fp_es ) {
		if( FPSR & fp_pe ) 	info.si_code = FPE_FLTRES;
		else if( FPSR & fp_ue ) info.si_code = FPE_FLTUND;
		else if( FPSR & fp_oe ) info.si_code = FPE_FLTOVF;
		else if( FPSR & fp_ze ) info.si_code = FPE_FLTDIV;
		else if( FPSR & fp_de ) info.si_code = FPE_FLTUND;
		else if( FPSR & fp_ie ) info.si_code = FPE_FLTINV;
	} else { 
                if ( PFPFR & fp_pe )     info.si_code = FPE_FLTRES;
		else if( PFPFR & fp_de ) info.si_code = FPE_FLTUND;
		else if( PFPFR & fp_oe ) info.si_code = FPE_FLTOVF;
		else if( PFPFR & fp_ie ) info.si_code = FPE_FLTINV;
		else if( PFPFR & fp_ze ) info.si_code = FPE_FLTDIV;
		else if( PFPFR & fp_ue ) info.si_code = FPE_FLTUND;
        }
	
	force_sig_info(SIGFPE, &info, current);
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
		SDBGPRINT("SIGBUS. Memory lock signaled");
	}
}

static notrace void do_mem_lock_as(struct pt_regs *regs)
{
	nmi_enter();
	inc_irq_stat(__nmi_count);
	nmi_exit();

#ifndef CONFIG_IGNORE_MEM_LOCK_AS
	if (TASK_IS_BINCO(current) && user_mode(regs)) {
		DebugML("started\n");
		S_SIG(regs, SIGBUS, exc_mem_lock_as_num, BUS_OBJERR);
		SDBGPRINT("SIGBUS. Memory lock AS signaled");
	}
#endif
}

__noreturn static void do_mem_error(struct pt_regs *regs)
{
	struct trap_pt_regs *trap = regs->trap;
	tir_hi_struct_t tir_hi;
	tir_lo_struct_t tir_lo;
	char *s;

	tir_lo.TIR_lo_reg = trap->TIR_lo;
	tir_hi.TIR_hi_reg = trap->TIR_hi;

	switch (tir_hi.TIR_hi_exc & exc_mem_error_mask) {
	case exc_mem_error_ICACHE_mask:
		s = "ICACHE";
		break;
	case exc_mem_error_L1_02_mask:
		s = "L1 chanel 0, 2";
		break;
	case exc_mem_error_L1_35_mask:
		s = "L1 chanel 3, 5";
		break;
	case exc_mem_error_L2_mask:
		s = "L2";
		break;
	case exc_mem_error_MAU_mask:
		s = "MAU";
		break;
	case exc_mem_error_out_cpu_mask:
		s = "out cpu";
		break;
	default:
		s = "unknown";
		break;
	}

	panic("EXCEPTION: exc_mem_error TIR_hi.exc 0x%016lx (%s) TIR_lo.ip "
		"0x%016lx on cpu %d\n",
		tir_hi.TIR_hi_exc, s, tir_lo.TIR_lo_ip,
		raw_smp_processor_id());
}

__noreturn static void do_unknown_exc(struct pt_regs *regs)
{
	panic("EXCEPTION: Unknown e2k exception!!!\n");
}

