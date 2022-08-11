/* linux/arch/e2k/kernel/ttable.c, v 1.1 05/28/2001.
 * 
 * Copyright (C) 2001 MCST
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

#define DEBUG_CTX_MODE	0 /* setcontext/swapcontext */
#if DEBUG_CTX_MODE
#define DebugCTX(...)	DebugPrint(DEBUG_CTX_MODE, ##__VA_ARGS__)
#else
#define DebugCTX(...)
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
#include <linux/tracehook.h>
#include <linux/utsname.h>
#include <linux/sysctl.h>
#include <linux/uio.h>
#include <linux/futex.h>


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

#ifdef CONFIG_USE_AAU
#include <asm/aau_regs.h>
#include <asm/aau_context.h>
#endif

#ifdef CONFIG_PROTECTED_MODE
#include <asm/3p.h>
#include <linux/futex.h>
#endif /* CONFIG_PROTECTED_MODE */

#include <asm/kvm/runstate.h>
#include <asm/kvm/switch.h>

#include <asm/regs_state.h>

#ifdef	CONFIG_COMPAT
#include <linux/compat.h>
#endif

#include "ttable-inline.h"

#undef	DEBUG_PV_UST_MODE
#undef	DebugUST
#define	DEBUG_PV_UST_MODE	0	/* guest user stacks debug mode */
#define	DebugUST(fmt, args...)						\
({									\
	if (debug_guest_ust)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_PV_SYSCALL_MODE
#define	DEBUG_PV_SYSCALL_MODE	0	/* syscall injection debugging */

#if	DEBUG_PV_UST_MODE || DEBUG_PV_SYSCALL_MODE
bool debug_guest_ust = false;
#else
#define	debug_guest_ust	false
#endif	/* DEBUG_PV_UST_MODE || DEBUG_PV_SYSCALL_MODE */

#define	is_kernel_thread(task)	((task)->mm == NULL || (task)->mm == &init_mm)

#define SAVE_PSYSCALL_ARGS(regs, a1, a2, a3, a4, a5, a6, a7, tags)	\
({									\
	(regs)->args[1] = (a1);						\
	(regs)->args[2] = (a2);						\
	(regs)->args[3] = (a3);						\
	(regs)->args[4] = (a4);						\
	(regs)->args[5] = (a5);						\
	(regs)->args[6] = (a6);						\
	(regs)->args[7] = (a7);						\
	(regs)->tags = (tags);						\
	(regs)->kernel_entry = 10;					\
})

#define	SAVE_SYSCALL_ARGS(regs, a1, a2, a3, a4, a5, a6)			\
({									\
	(regs)->args[1] = (a1);						\
	(regs)->args[2] = (a2);						\
	(regs)->args[3] = (a3);						\
	(regs)->args[4] = (a4);						\
	(regs)->args[5] = (a5);						\
	(regs)->args[6] = (a6);						\
})
#define	RESTORE_SYSCALL_ARGS(regs, num, a1, a2, a3, a4, a5, a6)		\
({									\
	(num) = (regs)->sys_num;					\
	(a1) = (regs)->args[1];						\
	(a2) = (regs)->args[2];						\
	(a3) = (regs)->args[3];						\
	(a4) = (regs)->args[4];						\
	(a5) = (regs)->args[5];						\
	(a6) = (regs)->args[6];						\
})
static inline void save_syscall_args_prot(struct pt_regs *regs,
		u64 a1, u64 a2, u64 a3, u64 a4, u64 a5, u64 a6,
		u64 a7, u64 a8, u64 a9, u64 a10, u64 a11, u64 a12, u64 tags)
{
	regs->args[1] = a1;
	regs->args[2] = a2;
	regs->args[3] = a3;
	regs->args[4] = a4;
	regs->args[5] = a5;
	regs->args[6] = a6;
	regs->args[7] = a7;
	regs->args[8] = a8;
	regs->args[9] = a9;
	regs->args[10] = a10;
	regs->args[11] = a11;
	regs->args[12] = a12;
	regs->tags = tags;
}
#define	RESTORE_SYSCALL_RVAL(regs, rval)				\
({									\
	(rval) = (regs)->sys_rval;					\
})
#define	RESTORE_PSYSCALL_RVAL(regs, rval, rval1, rval2)			\
({									\
	(rval) = (regs)->sys_rval;					\
	(rval1) = (regs)->rval1;					\
	(rval2) = (regs)->rval2;					\
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
 * Plus we can have a signal.
 */
#define	MAX_HW_INTR	6


#ifdef	CONFIG_DEBUG_PT_REGS
#define	DO_NEW_CHECK_PT_REGS_ADDR(prev_regs, regs, usd_lo_reg)		\
{									\
									\
	register struct pt_regs *new_regs;				\
	register e2k_addr_t	delta_sp;				\
	register e2k_usd_lo_t	usd_lo_cur;				\
									\
	usd_lo_cur = NATIVE_NV_READ_USD_LO_REG();			\
	delta_sp = usd_lo_cur.USD_lo_base - usd_lo_reg.USD_lo_base;	\
	new_regs = (pt_regs_t *)(((e2k_addr_t) prev_regs) + delta_sp);	\
	if (regs != new_regs) {						\
		pr_alert("ttable_entry() calculated pt_regs structure 0x%px is not the same as from thread_info structure 0x%px\n", \
			new_regs, regs);				\
		dump_stack();						\
	}								\
}

/*
 * pt_regs structure is placed as local data of the
 * trap handler (or system call handler) function
 * into the kernel local data stack
 * Calculate placement of pt_regs structure, it should be
 * same as from thread_info structure
 */
#define	NEW_CHECK_PT_REGS_ADDR(prev_regs, regs, usd_lo_reg)	\
		DO_NEW_CHECK_PT_REGS_ADDR(prev_regs, regs, usd_lo_reg)
#else
#define	NEW_CHECK_PT_REGS_ADDR(prev_regs, regs, usd_lo_reg)
#endif

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
#endif	/* CONFIG_CPU_ISET < 5 */


#ifdef CONFIG_SERIAL_PRINTK
/*
 * Use global variables to prevent using data stack
 */
static char hex_numbers_for_debug[16] = {'0', '1', '2', '3', '4', '5', '6',
			'7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
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

static __interrupt notrace void dump_u32_no_stack(u32 num)
{
	int i;
	int cpu_id;
	char *_u32_char;

	cpu_id = raw_smp_processor_id();

	_u32_char = u64_char[cpu_id];
	_u32_char[8] = 0;

	for (i = 0; i < 8; i++) {
		_u32_char[7 - i] = hex_numbers_for_debug[num % 16];
		num = num / 16;
	}
	dump_puts(_u32_char);
}

static arch_spinlock_t dump_lock = __ARCH_SPIN_LOCK_UNLOCKED;
static __interrupt notrace void dump_debug_info_no_stack(void)
{
	u64 usd_lo_base;
	e2k_cr0_hi_t cr0_hi;
	u64 ip;
	u32 ussz;
	e2k_mem_crs_t *frame;
	e2k_pcsp_lo_t pcsp_lo;
	e2k_pcsp_hi_t pcsp_hi;
	u64 cr_ind;
	u64 cr_base;
	int flags;
	struct thread_info *ti = READ_CURRENT_REG();

	dump_puts("BUG: kernel data stack overflow\n");

	raw_all_irq_save(flags);
	arch_spin_lock(&dump_lock);

	usd_lo_base = NATIVE_NV_READ_USD_LO_REG().USD_lo_base;
	cr0_hi = NATIVE_NV_READ_CR0_HI_REG();
	ip = AS_STRUCT(cr0_hi).ip << 3;

	/*
	 * Print IP ASAP before flushc/flushr instructions
	 */
	dump_puts("last IP: 0x");
	dump_u64_no_stack(ip);

	dump_puts("\nUSD base   = 0x");
	dump_u64_no_stack(usd_lo_base);

	dump_puts("\n    bottom = 0x");
	dump_u64_no_stack((u64)thread_info_task(ti)->stack);

	COPY_STACKS_TO_MEMORY();

	pcsp_hi = NATIVE_NV_READ_PCSP_HI_REG();
	pcsp_lo = NATIVE_NV_READ_PCSP_LO_REG();
	cr_ind = AS_STRUCT(pcsp_hi).ind;
	cr_base = AS_STRUCT(pcsp_lo).base;

	dump_puts("\nchain stack:                  USD size\n      0x");
	dump_u64_no_stack(ip);
	ussz = NATIVE_NV_READ_CR1_HI_REG().CR1_hi_ussz << 4;
	dump_puts("      ");
	dump_u32_no_stack(ussz);

	frame = ((e2k_mem_crs_t *)(cr_base + cr_ind)) - 1;
	while (frame != (e2k_mem_crs_t *)cr_base) {
		dump_puts("\n      0x");
		ip = frame->cr0_hi.CR0_hi_ip << 3;
		dump_u64_no_stack(ip);
		ussz = frame->cr1_hi.CR1_hi_ussz << 4;
		dump_puts("      ");
		dump_u32_no_stack(ussz);
		frame--;
	}
	dump_puts("\n");

	arch_spin_unlock(&dump_lock);
	raw_all_irq_restore(flags);
}
#else
static inline void dump_debug_info_no_stack(void) {}
#endif

__noreturn __interrupt notrace
void kernel_data_stack_overflow(void)
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
		per_cpu(reserve_hw_stacks, cpu) =
				__alloc_thread_stack_node(cpu_to_node(cpu));
	}

	return 0;
}
core_initcall(reserve_hw_stacks_init);

static __always_inline void switch_to_reserve_stacks(void)
{
	unsigned long base;
	e2k_pcsp_lo_t pcsp_lo;
	e2k_pcsp_hi_t pcsp_hi;
	e2k_psp_lo_t psp_lo;
	e2k_psp_hi_t psp_hi;
	e2k_usd_lo_t usd_lo;
	e2k_usd_hi_t usd_hi;
	e2k_sbr_t sbr;

	base = (unsigned long) raw_cpu_read(reserve_hw_stacks);

	AW(pcsp_lo) = 0;
	AS(pcsp_lo).base = base + KERNEL_PC_STACK_OFFSET;
	AW(pcsp_hi) = 0;
	AS(pcsp_hi).size = KERNEL_PC_STACK_SIZE;
	AW(psp_lo) = 0;
	AS(psp_lo).base = base + KERNEL_P_STACK_OFFSET;
	AW(psp_hi) = 0;
	AS(psp_hi).size = KERNEL_P_STACK_SIZE;
	AW(usd_lo) = 0;
	AS(usd_lo).base = base + KERNEL_C_STACK_OFFSET + KERNEL_C_STACK_SIZE -
							 K_DATA_GAP_SIZE;
	AW(usd_hi) = 0;
	AS(usd_hi).size = KERNEL_C_STACK_SIZE;
	AW(sbr) = 0;
	AS(sbr).base = base + KERNEL_C_STACK_OFFSET + KERNEL_C_STACK_SIZE;

	NATIVE_NV_WRITE_PCSP_REG(pcsp_hi, pcsp_lo);
	NATIVE_NV_WRITE_PSP_REG(psp_hi, psp_lo);
	NATIVE_NV_WRITE_USBR_USD_REG_VALUE(AW(sbr), AW(usd_hi), AW(usd_lo));
}

/* noinline is needed to make sure we use the reserved data stack */
notrace noinline __cold __noreturn
static void kernel_hw_stack_fatal_error(struct pt_regs *regs,
		u64 exceptions, u64 kstack_pf_addr)
{
	NATIVE_WRITE_PSR_IRQ_BARRIER(AW(E2K_KERNEL_PSR_ENABLED));
	raw_local_irq_enable();

	bust_spinlocks(1);

	if (kstack_pf_addr) {
		print_address_tlb(kstack_pf_addr);
		print_address_page_tables(kstack_pf_addr, true);

		pr_emerg("BUG: page fault on kernel stack at 0x%llx\n",
				kstack_pf_addr);
	}

	if (exceptions & exc_chain_stack_bounds_mask) {
		e2k_pcsp_hi_t pcsp_hi = regs->stacks.pcsp_hi;
		AS(pcsp_hi).ind -= PCSHTP_SIGN_EXTEND(regs->stacks.pcshtp);
		pr_emerg("BUG: chain stack overflow: pcsp.lo 0x%llx pcsp.hi 0x%llx pcshtp 0x%x\n",
			 AW(regs->stacks.pcsp_lo), AW(pcsp_hi),
			 regs->stacks.pcshtp);
	}

	if (exceptions & exc_proc_stack_bounds_mask) {
		e2k_psp_hi_t psp_hi = regs->stacks.psp_hi;

		AS(psp_hi).ind -= GET_PSHTP_MEM_INDEX(regs->stacks.pshtp);
		pr_emerg("BUG: procedure stack overflow: base 0x%llx ind 0x%x "
			"size 0x%x\n                               pshtp 0x%llx\n",
			regs->stacks.psp_lo.PSP_lo_base,
			psp_hi.PSP_hi_ind, psp_hi.PSP_hi_size,
			GET_PSHTP_MEM_INDEX(regs->stacks.pshtp));
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

#ifndef CONFIG_CPU_HAS_FILL_INSTRUCTION

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

noinline notrace
static u64 cf_fill_call(int nr)
{
	if (nr > 0) {
		u64 ret;

		ret = cf_fill_call(nr - 1);
		if (ret == -1ULL)
			ret = NATIVE_READ_PCSHTP_REG_SVALUE();

		return ret;
	}

	NATIVE_FLUSHC;

	return -1ULL;
}

static int init_cf_fill_depth(void)
{
	unsigned long flags;
	u64 cf_fill_depth;

	raw_all_irq_save(flags);
	cf_fill_depth = cf_fill_call(E2K_MAXCR_q / 2);
	raw_all_irq_restore(flags);

	cf_max_fill_return = cf_fill_depth + 32;

	pr_info("CF FILL depth: %d quadro registers\n",
			cf_max_fill_return / 16);

	return 0;
}
pure_initcall(init_cf_fill_depth);
#endif	/* !CONFIG_CPU_HAS_FILL_INSTRUCTION */

/*
 * Do work marked by TIF_NOTIFY_RESUME
 */
void do_notify_resume(struct pt_regs *regs)
{
#ifdef ARCH_RT_DELAYS_SIGNAL_SEND
	if (unlikely(current->forced_info.si_signo)) {
		force_sig_info(&current->forced_info);
		current->forced_info.si_signo = 0;
	}
#endif

	tracehook_notify_resume(regs);

	rseq_handle_notify_resume(NULL, regs);
}

/*
 * Trap occurred on user or kernel function but on user's stacks
 * So, it needs to switch to kernel stacks
 */
void notrace __irq_entry
user_trap_handler(struct pt_regs *regs, thread_info_t *thread_info)
{
	struct trap_pt_regs	*trap;
#if defined(CONFIG_KERNEL_TIMES_ACCOUNT) || defined(CONFIG_E2K_PROFILING)
	register e2k_clock_t	clock = NATIVE_READ_CLKR_REG_VALUE();
	register e2k_clock_t	clock1;
	register e2k_clock_t	start_tick;
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */
#ifdef CONFIG_USE_AAU
	e2k_aau_t		*aau_regs;
	e2k_aasr_t		aasr;
#endif /* CONFIG_USE_AAU */
#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	register trap_times_t	*trap_times;
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */
	u64 exceptions;
	int save_sbbp = current->ptrace || debug_trap;

	trap = pt_regs_to_trap_regs(regs);
	trap->flags = 0;
	regs->trap = trap;
	regs->kernel_entry = 0;

#ifdef CONFIG_CLI_CHECK_TIME
	start_tick = NATIVE_READ_CLKR_REG_VALUE();
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
	aasr = native_read_aasr_reg();
	SWITCH_GUEST_AAU_AASR(&aasr, aau_regs, test_ts_flag(TS_HOST_AT_VCPU_MODE));
#endif /* CONFIG_USE_AAU */

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
	trap_times = &(current_thread_info()->
			times[current_thread_info()->
					times_index].of.trap);
	current_thread_info()->
		times[current_thread_info()->
			times_index].type = TRAP_TT;
	INCR_KERNEL_TIMES_COUNT(current_thread_info());
	trap_times->start = clock;
	trap_times->ctpr1 = NATIVE_NV_READ_CR1_LO_REG_VALUE();
	trap_times->ctpr2 = NATIVE_NV_READ_CR0_HI_REG_VALUE();
	trap_times->pshtp = NATIVE_NV_READ_PSHTP_REG();
	trap_times->psp_ind = NATIVE_NV_READ_PSP_HI_REG().PSP_hi_ind;
	E2K_SAVE_CLOCK_REG(trap_times->pt_regs_set);
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */

	AW(regs->flags) = 0;
	init_guest_traps_handling(regs, true	/* user mode trap */);

#ifdef CONFIG_USE_AAU
	/*
	 * Put some distance between reading AASR (above) and using it here
	 * since reading of AAU registers is slow.
	 *
	 * This is placed before saving trap cellar since it is done using
	 * 'mmurr' instruction which requires AAU to be stopped.
	 *
	 * Do this before saving %sbbp as it uses 'alc' and thus zeroes %aaldm.
	 */
	NATIVE_SAVE_AAU_MASK_REGS(aau_regs, aasr);
#endif

	/*
	 * %sbbp LIFO stack is unfreezed by writing %TIR register,
	 * so it must be read before TIRs.
	 */
	if (unlikely(save_sbbp || ts_host_at_vcpu_mode())) {
		trap->sbbp = __builtin_alloca(sizeof(*trap->sbbp) *
					      SBBP_ENTRIES_NUM);
		SAVE_SBBP(trap->sbbp);
	} else {
		trap->sbbp = NULL;
	}

	/*
	 * Now we can store all needed trap context into the
	 * current pt_regs structure
	 */

	read_ticks(clock1);
	exceptions = SAVE_TIRS(trap->TIRs, trap->nr_TIRs, false);
	info_save_tir_reg(clock1);

	if (exceptions & have_tc_exc_mask) {
		NATIVE_SAVE_TRAP_CELLAR(regs, trap);
	} else {
		trap->tc_count = 0;
	}

	read_ticks(clock1);
	/*
	 * Here (in SAVE_STACK_REGS) hardware bug #29263 is being worked
	 * around with 'flushc' instruction, so NO function calls must
	 * happen and IRQs must not be enabled (even NMIs) until now.
	 */
	NATIVE_SAVE_STACK_REGS(regs, current_thread_info(), true, true);
	info_save_stack_reg(clock1);

#ifdef CONFIG_USE_AAU
	/* It's important to save AAD before all call operations. */
	if (unlikely(AS(aasr).iab))
		NATIVE_SAVE_AADS(aau_regs);

	/*
	 * If AAU fault happened read aalda/aaldi/aafstr here,
	 * before some call zeroes them.
	 */
	if (unlikely(trap->TIRs[0].TIR_hi.TIR_hi_aa))
		aau_regs->aafstr = native_read_aafstr_reg_value();

	/*
	 * Function calls are allowed from this point on,
	 * mark it with a compiler barrier.
	 */
	barrier();

	/* Since iset v6 %aaldi must be saved too */
	if (machine.native_iset_ver >= E2K_ISET_V6 &&
	    unlikely(AAU_STOPPED(aasr)))
		NATIVE_SAVE_AALDIS(aau_regs->aaldi);
#endif

	/* No atomic/DAM operations are allowed before this point.
	 * Note that we cannot do this before saving AAU. */
	if (cpu_has(CPU_HWBUG_L1I_STOPS_WORKING))
		E2K_DISP_CTPRS();

	/* un-freeze the TIR's LIFO. Tracing can issue a call
	 * here so we cannot do it earlier. */
	if (trace_tir_ip_trace_enabled()) {
		int i;
		for (i = 1; i <= TIR_TRACE_PARTS; i++)
			trace_tir_ip_trace(i);
	}
	UNFREEZE_TIRs();

	/* Restore some host context if trap is on guest.
	 * This uses function calls so cannot be called earlier. */
	trap_guest_exit(current_thread_info(), regs, trap, 0);

	info_save_mmu_reg(clock1);

	if (unlikely(is_chain_stack_bounds(current_thread_info(), regs)))
		(trap->TIRs[0].TIR_hi.TIR_hi_exc) |=
				exc_chain_stack_bounds_mask;
	if (unlikely(is_proc_stack_bounds(current_thread_info(), regs)))
		(trap->TIRs[0].TIR_hi.TIR_hi_exc) |=
				exc_proc_stack_bounds_mask;

#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	if (unlikely(TASK_IS_BINCO(current))) {
		u64 rpr_lo = NATIVE_READ_RPR_LO_REG_VALUE();
		u64 cr0_hi = AW(regs->crs.cr0_hi);

		machine.get_and_invalidate_MLT_context(&trap->mlt_state);

		/* Check if this was a trap in generations mode. */
		if (rpr_lo && (cpu_has(CPU_FEAT_ISET_V3) || trap->mlt_state.num) &&
				cr0_hi >= current_thread_info()->rp_start &&
				cr0_hi < current_thread_info()->rp_end)
			trap->flags |= TRAP_RP_FLAG;
	} else {
		trap->mlt_state.num = 0;
	}
#endif

	/* Update run state info, if trap occured on guest kernel */
	SET_RUNSTATE_IN_USER_TRAP();

	BUILD_BUG_ON(sizeof(enum ctx_state) != sizeof(trap->prev_state));
	trap->prev_state = exception_enter();

	CHECK_PT_REGS_LOOP(current_thread_info()->pt_regs);
	CHECK_PT_REGS_CHAIN(regs,
		NATIVE_NV_READ_USD_LO_REG().USD_lo_base,
		current->stack + KERNEL_C_STACK_SIZE);

#ifdef CONFIG_USE_AAU
	if (aau_working(aau_regs))
		machine.get_aau_context(aau_regs);
#endif
#ifdef CONFIG_CLI_CHECK_TIME
	tt0_prolog_ticks(E2K_GET_DSREG(clkr) - start_tick);
#endif

	/*
	 * %pshtp/%pcshtp cannot be negative after entering kernel
	 */
	if (WARN_ON_ONCE((AW(regs->stacks.pshtp) & (1ULL << E2K_WD_SIZE)) ||
			 (regs->stacks.pcshtp & (1ULL << E2K_PCSHTP_MSB)))) {
		local_irq_enable();
		NATIVE_WRITE_PSR_IRQ_BARRIER(AW(E2K_KERNEL_PSR_ENABLED));
		do_exit(SIGKILL);
	}

	/*
	 * This will enable interrupts
	 */
	parse_TIR_registers(regs, exceptions);
	trace_hardirqs_on();

	/* Guest trap handling can be scheduled and migrate to other VCPU */
	/* see comments at arch/e2k/include/asm/process.h */
	/* So: */
	/* 1) host VCPU thread was changed and */
	/* 2) need update thread info and */
	/* 3) regs satructures pointers */
	UPDATE_VCPU_THREAD_CONTEXT(NULL, &thread_info, &regs, NULL, NULL);

	finish_user_trap_handler(regs, FROM_USER_TRAP);
}

/*
 * Trap occured on kernel function and on kernel's stacks
 * So it does not need to switch to kernel stacks
 */
void notrace __irq_entry
kernel_trap_handler(struct pt_regs *regs, thread_info_t *thread_info)
{
	struct trap_pt_regs *trap;
	e2k_usd_lo_t usd_lo = regs->stacks.usd_lo;
	e2k_psp_hi_t psp_hi;
	e2k_pcsp_hi_t pcsp_hi;
#if defined(CONFIG_KERNEL_TIMES_ACCOUNT) || defined(CONFIG_E2K_PROFILING)
	register e2k_clock_t	clock = NATIVE_READ_CLKR_REG_VALUE();
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */
	e2k_cr0_hi_t cr0_hi;
#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	register trap_times_t	*trap_times;
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */
	e2k_upsr_t		upsr;
	u64 exceptions, nmi, hw_overflow, kstack_pf_addr;
	int save_sbbp = current->ptrace || debug_trap;
#if	defined(CONFIG_VIRTUALIZATION) && !defined(CONFIG_KVM_GUEST_KERNEL)
	int			to_save_runstate;
#endif	/* CONFIG_VIRTUALIZATION && ! CONFIG_KVM_GUEST_KERNEL */
	int hardirqs_enabled = trace_hardirqs_enabled(current);
#ifdef CONFIG_DEBUG_PT_REGS
	e2k_usd_lo_t usd_lo_prev;
#endif
#ifdef CONFIG_CLI_CHECK_TIME
	register long start_tick = NATIVE_READ_CLKR_REG_VALUE();
#endif

	/* No atomic/DAM operations are allowed before this point.
	 * Note that we cannot do this before saving AAU. */
	if (cpu_has(CPU_HWBUG_L1I_STOPS_WORKING))
		E2K_DISP_CTPRS();

	trap = pt_regs_to_trap_regs(regs);
	trap->flags = 0;
	regs->trap = trap;

#ifdef CONFIG_DEBUG_PT_REGS
	usd_lo_prev = NATIVE_NV_READ_USD_LO_REG();
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
	regs->next = current_thread_info()->pt_regs;
	current_thread_info()->pt_regs = regs;
#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	trap_times = &(current_thread_info()->
				times[current_thread_info()->
						times_index].of.trap);
	current_thread_info()->
		times[current_thread_info()->
			times_index].type = TRAP_TT;
	INCR_KERNEL_TIMES_COUNT(current_thread_info());
	trap_times->start = clock;
	trap_times->ctpr1 = NATIVE_NV_READ_CR1_LO_REG_VALUE();
	trap_times->ctpr2 = NATIVE_NV_READ_CR0_HI_REG_VALUE();
	trap_times->pshtp = NATIVE_NV_READ_PSHTP_REG();
	trap_times->psp_ind = NATIVE_NV_READ_PSP_HI_REG().PSP_hi_ind;
	E2K_SAVE_CLOCK_REG(trap_times->pt_regs_set);
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */

	AW(regs->flags) = 0;
	init_guest_traps_handling(regs, false	/* user mode trap */);

	/*
	 * %sbbp LIFO stack is unfreezed by writing %TIR register,
	 * so it must be read before TIRs.
	 */
	if (unlikely(save_sbbp)) {
		trap->sbbp = __builtin_alloca(sizeof(*trap->sbbp) *
					      SBBP_ENTRIES_NUM);
		SAVE_SBBP(trap->sbbp);
	} else {
		trap->sbbp = NULL;
	}

	/*
	 * Now we can store all needed trap context into the
	 * current pt_regs structure
	 */
        read_ticks(clock);
	exceptions = SAVE_TIRS(trap->TIRs, trap->nr_TIRs, false);
	nmi = exceptions & non_maskable_exc_mask;
	hw_overflow = unlikely(exceptions & (exc_chain_stack_bounds_mask |
					     exc_proc_stack_bounds_mask));
        info_save_tir_reg(clock);

	/* Update run state info, if trap occured on guest kernel */
	SET_RUNSTATE_IN_KERNEL_TRAP(to_save_runstate);

	if (exceptions & have_tc_exc_mask) {
		kstack_pf_addr = NATIVE_SAVE_TRAP_CELLAR(regs, trap);
	} else {
		trap->tc_count = 0;
		kstack_pf_addr = 0;
	}
	read_ticks(clock);
	NATIVE_SAVE_STACK_REGS(regs, current_thread_info(), false,
			       likely(!hw_overflow && !kstack_pf_addr));
        info_save_stack_reg(clock);

	/* un-freeze the TIR's LIFO. Tracing can issue a call
	 * here so we cannot do it earlier. */
	if (trace_tir_ip_trace_enabled()) {
		int i;
		for (i = 1; i <= TIR_TRACE_PARTS; i++)
			trace_tir_ip_trace(i);
	}
	UNFREEZE_TIRs();

	cr0_hi = regs->crs.cr0_hi;
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

	CHECK_PT_REGS_LOOP(current_thread_info()->pt_regs);
	CHECK_PT_REGS_CHAIN(regs,
		NATIVE_NV_READ_USD_LO_REG().USD_lo_base,
		current->stack + KERNEL_C_STACK_SIZE);

	if (unlikely(hw_overflow || kstack_pf_addr)) {
		/* Assume that no function calls has been done until this
		 * point, otherwise printed stack might be corrupted. */
		switch_to_reserve_stacks();
		kernel_hw_stack_fatal_error(regs, exceptions, kstack_pf_addr);
	}

	if (is_kernel_data_stack_bounds(true /* trap on kernel */, usd_lo))
		kernel_data_stack_overflow();

#ifdef CONFIG_CLI_CHECK_TIME
	tt0_prolog_ticks(E2K_GET_DSREG(clkr) - start_tick);
#endif

	/*
	 * This will enable non-maskable interrupts if (!nmi)
	 */
	parse_TIR_registers(regs, exceptions);

	/* Guest trap handling can be scheduled and migrate to other VCPU */
	/* see comments at arch/e2k/include/asm/process.h */
	/* So: */
	/* 1) host VCPU thread was changed and */
	/* 2) need update thread info and */
	/* 3) regs satructures pointers */
	UPDATE_VCPU_THREAD_CONTEXT(NULL, &thread_info, &regs, NULL, NULL);

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
	if (unlikely(need_resched() && preempt_count() == 0) &&
			(!nmi || (exceptions & exc_interrupt_mask))
#ifdef CONFIG_PREEMPT_LAZY
			|| (preempt_count() == 0 &&
			current_thread_info()->preempt_lazy_count == 0
			&& test_thread_flag(TIF_NEED_RESCHED_LAZY))
#endif
		) {
		unsigned long flags;
		raw_all_irq_save(flags);
		/* Check again under closed interrupts to avoid races */
		if (likely(need_resched() && !host_is_at_HV_GM_mode()))
			preempt_schedule_irq();
		else
			raw_all_irq_restore(flags);
	}
#endif

	/*
	 * Return control from UPSR register to PSR, if UPSR interrupts
	 * control is used. DONE operation restores PSR state at trap
	 * point and recovers interrupts control
	 *
	 * This also disables all interrupts including NMIs.
	 */
	if (hardirqs_enabled) {
		raw_all_irq_disable();
		trace_hardirqs_on();
	}
	RETURN_TO_KERNEL_UPSR(upsr);

	/*
	 * Dequeue current pt_regs structure and previous
	 * regs will be now actuale
	 */

	CHECK_PT_REGS_CHAIN(regs,
		NATIVE_NV_READ_USD_LO_REG().USD_lo_base,
		current->stack + KERNEL_C_STACK_SIZE);
	current_thread_info()->pt_regs = regs->next;
	regs->next = NULL;
	CHECK_PT_REGS_LOOP(current_thread_info()->pt_regs);

#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	trap_times->psp_hi_to_done = NATIVE_NV_READ_PSP_HI_REG();
	trap_times->pshtp_to_done = NATIVE_NV_READ_PSHTP_REG();
	trap_times->pcsp_hi_to_done = NATIVE_NV_READ_PCSP_HI_REG();
	trap_times->ctpr1_to_done = AS_WORD(regs->ctpr1);
	trap_times->ctpr2_to_done = AS_WORD(regs->ctpr2);
	trap_times->ctpr3_to_done = AS_WORD(regs->ctpr3);
	E2K_SAVE_CLOCK_REG(trap_times->end);
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */

	/* Update run state info, if trap occured on guest kernel */
	SET_RUNSTATE_OUT_KERNEL_TRAP(to_save_runstate);

	if (unlikely(AW(cr0_hi) != AW(regs->crs.cr0_hi)))
		NATIVE_NV_NOIRQ_WRITE_CR0_HI_REG(regs->crs.cr0_hi);
	if (unlikely(cpu_has(CPU_HWBUG_SS) &&
		     test_ts_flag(TS_SINGLESTEP_KERNEL))) {
		/*
		 * Hardware can lose singlestep flag on interrupt if it
		 * arrives earlier, so we must always manually reset it.
		 */
		e2k_cr1_lo_t cr1_lo = READ_CR1_LO_REG();
		AS(cr1_lo).ss = 1;
		WRITE_CR1_LO_REG(cr1_lo);
	}

	NATIVE_RESTORE_COMMON_REGS(regs);
	E2K_DONE();
}


/***********************************************************************/

#ifdef CONFIG_PROTECTED_MODE
#include <linux/net.h>

int handle_futex_death(u32 __user *uaddr, struct task_struct *curr,
		       bool pi, bool pending_op);

extern const system_call_func sys_protcall_table[]; /* defined in systable.c */

static int count_descriptors(long __user *prot_array,
				const int prot_array_size);

static long do_protected_syscall(unsigned long sys_num, const long arg1,
		const long arg2, const long arg3, const long arg4,
		const long arg5, const long arg6, const long arg7);

notrace __section(".entry.text")
static inline void get_ipc_mask(long call, long *mask_type, long *mask_align,
					int *fields)
{
	/* According to sys_ipc () these are SEMTIMEDOP and (MSGRCV |
	 * (1 << 16))' (see below on why MSGRCV is not useful in PM) calls that
	 * make use of FIFTH argument. Both of them interpret it as a long. Thus
	 * all other calls may be considered as 4-argument ones. Some of them
	 * are likely to accept even less than 4 arguments, but here I stupidly
	 * rely on the fact that all invocations of `INLINE_SYSCALL_CALL (ipc)'
	 * in glibc are passed to either 5 or 6 arguments including CALL.  */

	switch (call) {
	case MSGRCV:
		/*
		 * Converting of parameters, which comtain pointers,
		 * implemented in do_protected_syscall
		 */
		*mask_type = 0xd5;
		*mask_align = 0xf5;
		*fields = 4;
		break;
	case (MSGRCV | (1 << 16)):
		/* Instead it's much more handy to pass MSGP as PTR (aka FOURTH)
		 * and MSGTYP as FIFTH. `1 << 16' makes it clear to `sys_ipc ()'
		 * that this way of passing arguments is used.  */
	case SEMTIMEDOP:
		*mask_type = 0x3d5;
		*mask_align = 0x3f5;
		*fields = 5;
		break;
	case SHMAT:
		/* SHMAT is special because it interprets the THIRD argument as
		 * a pointer to which AP should be stored in PM. TODO: this will
		 * require additional efforts in our PM handler.  */
		*mask_type = 0xf5;
		*mask_align = 0xfd;
		*fields = 4;
		break;
	case SEMGET:
		*mask_type = 0x15;
		*mask_align = 0x15;
		*fields = 3;
		break;
	case SHMGET:
		*mask_type = 0x55;
		*mask_align = 0x55;
		*fields = 4;
		break;
	case MSGGET:
		*mask_type = 0x5;
		*mask_align = 0x5;
		*fields = 2;
		break;
	default:
		*mask_type = 0xd5;
		*mask_align = 0xf5;
		*fields = 4;
	}
}

notrace __section(".entry.text")
static inline void get_futex_mask(long call, long *mask_type, long *mask_align,
				int *fields)
{
	long cmd = call & FUTEX_CMD_MASK;

	switch (cmd) {
	case FUTEX_UNLOCK_PI:
		/* On glibc side this command is used both with 2 and 4
		 * arguments. I guess that the last two arguments are just
		 * ignored in the latter case. Consider it to be a 2-argument
		 * one here to be on the safe side.  */
	case FUTEX_WAKE:
		/* This command is invoked with 3 arguments on glibc side. For
		 * 2 and 3-argument futex commands the array parameter is not
		 * used. */
		*mask_type = 0x0;
		*mask_align = 0x0;
		*fields = 0;
		break;
	case FUTEX_WAIT:
#if 0
		/* Does the 4-argument variant of FUTEX_WAKE employed in glibc
		 * make any sense? According to do_futex () on the Kernel side
		 * it does not because the 4-th parameter isn't used in any
		 * way.  */
	case FUTEX_WAKE:
#endif /* 0  */
	case FUTEX_LOCK_PI:
	case FUTEX_TRYLOCK_PI:
		/* For 4 argument futex commands the only TIMEOUT field is
		 * passed in array as a pointer.  */
		*mask_type = 0x3;
		*mask_align = 0x2;
		*fields = 1;
		break;

	case FUTEX_WAIT_BITSET:
		/* On glibc side this command is invoked both with 5 and 6
		 * arguments with TIMEOUT being a pointer. I doubt if 5
		 * arguments are enough for all invocations of this command
		 * in fact because the last VAL3 argument seems to be meaningful
		 * and is passed to futex_wake () when handling this request in
		 * do_futex (). Therefore, here it's treated as 6-argument
		 * one. */
		*mask_type = 0x1f;
		*mask_align = 0x1f;
		*fields = 3;
		break;
	default:
		/* Stupidly treat all other requests as 6-argument ones taking
		 * VAL2 instead of TIMEOUT for now.  */
		*mask_type = 0x1d;
		*mask_align = 0x1f;
		*fields = 3;
	}
}


/*
 * Fetch a PM robust-list pointer. Bit 0 signals PI futexes:
 */
static inline int
fetch_pm_robust_entry(long __user **entry, long __user *head, unsigned int *pi)
{
	long addr;
	if (convert_array(head, &addr, 16, 1, 1, 0x3, 0x3)) {
		long tmp[2];
		if (copy_from_user_with_tags(tmp, head, 16) == 0) {
			long lo, hi;
			int ltag, htag;
			NATIVE_LOAD_VAL_AND_TAGD(tmp, lo, ltag);
			NATIVE_LOAD_VAL_AND_TAGD(&tmp[1], hi, htag);

			printk(KERN_DEBUG "Fetch pm_robust_entry failed with AP == <%x> 0x%lx : <%x> 0x%lx\n",
				ltag, tmp[0], htag, tmp[1]);
		}

		return -EFAULT;
	}

	*entry = (long __user *) (addr & ~1);
	*pi = (unsigned int) addr & 1;

	return 0;
}

static void __user *pm_futex_uaddr(long __user *entry, long futex_offset)
{
	compat_uptr_t base = (long) entry;
	void __user *uaddr = (void __user *) (base + futex_offset);

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
	long __user *head = task_thread_info(curr)->pm_robust_list;
	long __user *entry, *next_entry, *pending;
	unsigned int limit = ROBUST_LIST_LIMIT, pi, pip;
	unsigned int uninitialized_var(next_pi);
	long futex_offset;
	int rc;

	if (!futex_cmpxchg_enabled)
		return;

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
	 * rid of this limiation when (sub)structures containing no APs are
	 * converted.
	 */
	if (get_user(futex_offset, (long *) &head[2])) {
		DbgSCP_ALERT("failed to read from 0x%lx !!!\n",
			     (uintptr_t) &head[2]);
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

__section(".entry.text")
SYS_RET_TYPE notrace ttable_entry10_C(long sys_num,
		long arg1, long arg2, long arg3, long arg4,
		long arg5, long arg6, struct pt_regs *regs)
{
#define ARG_TAG(i)	((tags >> (4*(i))) & 0xF)
#define NOT_PTR(i)	(((tags >> (4*(i))) & 0xFFUL) != ETAGAPQ)
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
		DbgSCP_ALERT(#i " " #j " Not a pointer is not allowed.\n"); \
	} \
} while (0)

#define GET_STR(str, i, j)                                              \
do { \
	if (likely(!NOT_PTR(i) && !NULL_PTR(i))) {                      \
		str = e2k_ptr_str(arg##i, arg##j, GET_SBR_HI());        \
		if (!str)                                               \
			DbgSCP(#i ":" #j " is not a null-terminated string"); \
	} else {                                                        \
		str = 0;                                                \
		DbgSCP_ALERT(#i ":" #j " is NULL or not a valid pointer"); \
		break;                                                  \
	} \
} while (0)

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

	register long rval1 = 0; /* numerical return value  or */
	register long rval2 = 0; /* both rval1 & rval2  */
	int return_desk = 0;
	int rv1_tag = E2K_NUMERIC_ETAG;
	int rv2_tag = E2K_NUMERIC_ETAG;
#ifdef CONFIG_E2K_PROFILING
	register long start_tick = NATIVE_READ_CLKR_REG_VALUE();
	register long clock1;
#endif
	char *str, *str2, *str3;
	e2k_addr_t base;
	unsigned long ptr, ptr2, ptr3;
	unsigned int size;
	long mask_type, mask_align;
	int fields;

#ifdef CONFIG_DEBUG_PT_REGS  
	/*
	 * pt_regs structure is placed as local data of the
	 * trap handler (or system call handler) function
	 * into the kernel local data stack
	 */
	usd_lo_prev = NATIVE_NV_READ_USD_LO_REG();
#endif

	init_pt_regs_for_syscall(regs);
	/* now we have 2 proc_sys_call entry*/
	regs->flags.protected_entry10 = 1;
	regs->return_desk = 0;
	SAVE_STACK_REGS(regs, current_thread_info(), true, false);
	regs->sys_num = sys_num;
	SAVE_PSYSCALL_ARGS(regs, arg1, arg2, arg3, arg4,
			arg5, arg6, arg7, tags);
#ifdef CONFIG_E2K_PROFILING
	read_ticks(clock1);
	info_save_stack_reg(clock1);
#endif
	current_thread_info()->pt_regs = regs;
	WRITE_PSR_IRQ_BARRIER(AW(E2K_KERNEL_PSR_ENABLED));

	DbgSCP("_NR_ %ld start. current %px pid %d tags=0x%x\n",
			sys_num, current, current->pid, tags);

	local_irq_enable();

	/* Trace syscall enter */
	if (unlikely(current_thread_info()->flags & _TIF_WORK_SYSCALL_TRACE)) {
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
	case __NR_read:
	case __NR_write:
	case __NR_getdents:
	case __NR_getdents64:
		DbgSCP("__NR_%ld protected: fd = %d, buf = 0x%lx : 0x%lx, "
			"count = 0x%lx", sys_num, (int) arg1, arg2, arg3, arg4);
		GET_PTR(ptr, size, 2, 3, arg4, 0);
		if (!size && arg4)
			break;

		if (sys_num == __NR_read)
			rval = sys_read(arg1, (char *) ptr, (size_t) arg4);
		else if (sys_num == __NR_write)
			rval = sys_write(arg1, (char *) ptr, (size_t) arg4);
		else if (sys_num == __NR_getdents)
			rval = sys_getdents((unsigned int) arg1,
				      (struct linux_dirent *) ptr,
				      (unsigned int) arg4);
		else
		  rval = sys_getdents64((unsigned int) arg1,
					(struct linux_dirent64 *) ptr,
					(unsigned int) arg4);
		DbgSCP("  rval = %ld\n", rval);
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
	case __NR_waitid:
		DbgSCP("waitid(): idtype = %ld, id = %ld, options = 0x%lx, "
		       "infop = 0x%lx : 0x%lx, rusage = 0x%lx : 0x%lx",
		       arg1, arg2, arg3, arg4, arg5, arg6, arg7);

		GET_PTR(ptr, size, 4, 5, sizeof(siginfo_t), 1);
		if (!size)
			break;

		GET_PTR(ptr2, size, 6, 7, sizeof(struct rusage), 1);
		if (!size)
			break;

		rval = sys_waitid((int) arg1, (pid_t) arg2,
					(struct siginfo *) ptr,
					(int) arg3, (struct rusage *) ptr2);
		DbgSCP(" rval = %ld\n", rval);
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
	case __NR_pipe2:
		DbgSCP("pipe(0x%lx : 0x%lx\n) ", arg2, arg3);
		GET_PTR(ptr, size, 2, 3, 2 * sizeof (u32), 0);
		if (!size)
			break;

		if (sys_num == __NR_pipe)
			rval = sys_pipe((int *) ptr);
		else
			rval = sys_pipe2((int *) ptr, (int) arg4);

		DbgSCP("  rval = %ld\n", rval);
		break;
	case __NR_times:
		DbgSCP("times(): buf = 0x%lx : 0x%lx, ", arg2, arg3);

		GET_PTR(ptr, size, 2, 3, sizeof(struct tms), 1);
		if (!size)
			break;

		rval = sys_times((struct tms *) ptr);
		DbgSCP("rval = %ld\n",rval);
		break;
	case __NR_utime:
		DbgSCP("utime(): filename = 0x%lx : 0x%lx, times = 0x%lx : 0x%lx",
		       arg2, arg3, arg4, arg5);
		GET_STR(str, 2, 3);
		if (!str)
			break;

		GET_PTR(ptr, size, 4, 5, sizeof(struct utimbuf), 1);
		if (!size)
			break;

		rval = sys_utime(str, (struct utimbuf *) ptr);
		DbgSCP("rval = %ld\n", rval);
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
	case __NR_prlimit64:
		GET_PTR(ptr, size, 4, 5, sizeof(struct rlimit64), 1);
		if (!size)
			break;

		GET_PTR(ptr2, size, 6, 7, sizeof(struct rlimit64), 1);
		if (!size)
			break;

		rval = sys_prlimit64((pid_t) arg1, (int) arg2,
				      (struct rlimit64 *)ptr,
				      (struct rlimit64 *) ptr2);

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
		unsigned int enable = 0;

		DbgSCP("mmap(): start = %ld, len = %ld, prot = 0x%lx "
				"flags = 0x%lx, fd = 0x%lx, off = %ld",
				arg1, arg2, arg3, arg4, arg5, arg6);
		return_desk = 1;
		rval1 = rval2 = 0;
		rv1_tag = rv2_tag = 0;
		if ((unsigned long) arg2 > 0xFFFFFFFF) {
			rval = -E2BIG;
			break;
		}
		base = sys_mmap((unsigned long) arg1, (unsigned long) arg2,
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
	case __NR_lstat:
		DbgSCP("stat(): filename = (0x%lx : 0x%lx, "
			"statbuf = 0x%lx : 0x%lx, ", arg2, arg3, arg4, arg5);

		GET_STR(str, 2, 3);
		if (!str)
			break;

		GET_PTR(ptr, size, 4, 5, sizeof(struct stat), 0);
		if (!size)
			break;

		if (sys_num == __NR_stat)
			rval = sys_newstat(str, (struct stat *) ptr);
		else
			rval = sys_newlstat(str, (struct stat *) ptr);

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

		if (sys_num == __NR_getitimer) {
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
		/* sys_ipc - last parameter  may be pointer or long -
		 * it depends on the first parameter.
		 * 6 parameters are passed through array.
		 * maska is the first element of array. */
		GET_PTR(ptr, size, 2, 3, 0, 0);

		/* Let the CALL parameter be passed separately, i.e. not in
		 * array. FIRST, SECOND, THIRD, PTR and FIFTH will be passed
		 * in array.  */
		get_ipc_mask(arg1, &mask_type, &mask_align, &fields);
		if (fields == 0)
			break;

		if ((rval = convert_array((long *) ptr, args, size, fields, 1,
					  mask_type, mask_align))) {
			DbgSCP(" Bad array for _ipc\n");
			break;
		}
		DbgSCP("ipc(): call:%d first:%d second:%lld third:%lld\n"
				"ptr:%px fifth:%lld\n", (u32) arg1,
				(int) args[0], (u64) args[1], (u64) args[2],
				(void *) (u64) args[3], (u64) args[4]);
		rval = sys_ipc((u32) arg1, (int) args[0], (u64) args[1],
				(u64) args[2], (void *) (u64) args[3],
				(u64) args[4]);
		DbgSC("rval = %ld\n", rval);
		break;
	case __NR_clone: {
		unsigned long args_ptr;
		unsigned int args_size, tls = 0, tls_size;
		struct kernel_clone_args cargs;

		DbgSCP("clone(0x%lx, 0x%01lx, 0x%016lx, 0x%lx, 0x%lx)\n",
			arg1, arg2, arg3, arg4, arg5);

		/* Read TLS and TID parameters passed indirectly through
		 * an array at (arg4:arg5).
		 *
		 * User may choose to not pass additional arguments
		 * (tls, tid) at all for historical and compatibility
		 * reasons, so we do not fail if (arg4,arg5) pointer
		 * is bad. */
		GET_PTR(args_ptr, args_size, 4, 5, 3 * 16, 0);
		if (args_size != 0
		    && convert_array((long *) args_ptr, args, args_size,
				     1, 3, 0x3, 0x3) == 0) {
			/* Looks like a good pointer. Flags will later
			 * show whether these arguments are any good.
			 *
			 * The first argument is parent_tidptr and
			 * the second one is child_tidptr. The third
			 * argument (tls) requires special handling. */
			if (arg1 & CLONE_SETTLS) {
				int tls_lo_tag, tls_hi_tag;
				u64 tls_lo, tls_hi;

				/* Copy TLS argument with tags. */
				TRY_USR_PFAULT {
					NATIVE_LOAD_TAGGED_QWORD_AND_TAGS(
						((u64 *) args_ptr) + 4,
						tls_lo, tls_hi,
						tls_lo_tag, tls_hi_tag);
				} CATCH_USR_PFAULT {
					rval = -EFAULT;
					break;
				} END_USR_PFAULT

				/* Check that the pointer is good. */
				tls = e2k_ptr_ptr(tls_lo, tls_hi, 4);
				tls_size = e2k_ptr_size(tls_lo, tls_hi, 4);
				if (((tls_hi_tag << 4) | tls_lo_tag) != ETAGAPQ
						|| tls_size < sizeof(int)) {
					DbgSCP(" Bad TLS pointer: size=%d, tag=%d\n",
						tls_size,
						(tls_hi_tag << 4) | tls_lo_tag);
					break;
				}
			}
		} else {
			if (unlikely(arg1 & (CLONE_SETTLS | CLONE_CHILD_SETTID |
					     CLONE_PARENT_SETTID |
					     CLONE_CHILD_CLEARTID))) {
				DbgSCP("Bad tid or tls argument\n");
				break;
			}
		}

		/* Get stack parameters */
		GET_PTR(ptr, size, 2, 3, 0, true);
		size = e2k_ptr_curptr(arg2, arg3);
		/*
		 * Multithreading support - change all SAP to AP in globals
		 * to guarantee correct access to memory
		 */
		if (arg1 & CLONE_VM)
			mark_all_global_sp(regs, current->pid);

		DbgSCP("calling sys_clone(0x%lx, 0x%lx)size=0x%x\n",
					arg1, ptr, size);

		cargs.flags	  = (arg1 & ~CSIGNAL);
		cargs.pidfd	  = (int __user *) args[0];
		cargs.child_tid	  = (int __user *) args[1];
		cargs.parent_tid  = (int __user *) args[0];
		cargs.exit_signal = (arg1 & CSIGNAL);
		cargs.stack	  = ptr - size;
		cargs.stack_size  = size;
		cargs.tls	  = tls;

		/* passing size of desk to _do_fork */
		rval = _do_fork(&cargs);

		DbgSCP("rval = %ld, sys_num = %ld\n", rval, sys_num);
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

		GET_PTR(ptr, size, 2, 3, sizeof(struct __kernel_timex), 0);
		if (!size)
			break;

		rval = sys_adjtimex((struct __kernel_timex *) ptr);
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
		DbgSCP("init_module(): umod:%px, len:0x%lx, uargs:%px\n",
				(void*) ptr, arg1, str);

		rval = sys_init_module((void *) ptr, (u64) arg1, str);
		DbgSC("rval = %ld\n", rval);
		break;
	case __NR_sysfs:
		/* arg2 may be pnt or long (depend on arg1) */
		DbgSCP("system call %ld arg1=%ld (arg{2,3} = 0x%lx : 0x%lx),"
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

		GET_PTR(ptr, size, 2, 3, sizeof(struct __kernel_timespec), 0);
		if (!size)
			break;

		rval = sys_sched_rr_get_interval((pid_t) arg1,
				(struct __kernel_timespec *) ptr);
		DbgSCP("rval = %ld\n",rval);
		break;
	case __NR_nanosleep:
		DbgSCP("nanosleep(): req = 0x%lx : 0x%lx,"
				"rem = 0x%lx :  0x%lx ",
				arg2, arg3, arg4, arg5);

		GET_PTR(ptr, size, 2, 3, sizeof(struct __kernel_timespec), 0);
		if (!size)
			break;

		GET_PTR(ptr2, size, 4, 5, sizeof(struct __kernel_timespec), 1);
		if (!size)
			break;

		rval = sys_nanosleep((struct __kernel_timespec *) ptr,
				(struct __kernel_timespec *) ptr2);
		DbgSCP("rval = %ld\n",rval);
		break;
	case __NR_mremap:
		DbgSCP("mremap(): void * = 0x%lx, : 0x%lx "
				"o_sz = 0x%lx, n_sz =  0x%lx, flags = 0x%lx",
				arg2, arg3, arg4, arg5, arg6);

		GET_PTR(ptr, size, 2, 3, arg4, 0);
		if (!size)
			break;

		base = sys_mremap((unsigned long) ptr,
				  (unsigned long) arg4, (unsigned long) arg5,
				  (unsigned long) arg6,
				  /* MREMAP_FIXED is not supported in PM,
				   * therefore pass an invalid value for
				   * new_address.  */
				  0);
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
	case __NR_ppoll:
		DbgSCP("ppoll(): fds = 0x%lx : 0x%lx, "
				"nfds = 0x%lx, tmo_p = 0x%lx : 0x%lx, "
				"sigmask = 0x%lx : 0x%lx",
				 arg2, arg3, arg1, arg4, arg5, arg6, arg7);

		GET_PTR(ptr, size, 2, 3, arg1 * sizeof(struct pollfd), 0);
		if (!size)
			break;

		GET_PTR(ptr2, size, 4, 5, sizeof(struct __kernel_timespec), 1);
		if (!size)
			break;

		GET_PTR(ptr3, size, 6, 7, sizeof(sigset_t), 1);
		if (!size)
			break;

		rval = sys_ppoll((struct pollfd *) ptr,
				 arg1,
				 (struct __kernel_timespec *) ptr2,
				 (const sigset_t *) ptr3,
				 sizeof(sigset_t));
		DbgSCP("rval = %ld\n", rval);
		break;
	case __NR_rt_sigaction: {
		GET_PTR(ptr, size, 2, 3, sizeof(prot_sigaction_old_t), 1);
		if (!size)
			break;

		GET_PTR(ptr2, size, 4, 5, sizeof(prot_sigaction_old_t), 1);
		if (!size)
			break;

		rval = protected_sys_rt_sigaction((int)arg1,
				(const void *)ptr, (void *)ptr2, (size_t) arg6);
		DbgSCP("compat_protected_sys_rt_sigaction() "
			"rval = %ld\n", rval);
		break;
	}
	case __NR_rt_sigaction_ex: {
		GET_PTR(ptr, size, 2, 3, sizeof(prot_sigaction_t), 1);
		if (!size)
			break;

		GET_PTR(ptr2, size, 4, 5, sizeof(prot_sigaction_t), 1);
		if (!size)
			break;

		rval = protected_sys_rt_sigaction_ex((int)arg1,
				(const void *)ptr, (void *)ptr2, (size_t) arg6);
		DbgSCP("protected_sys_rt_sigaction() rval = %ld\n", rval);
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
				"sigsetsize %ld\n", arg2, arg3, arg4, arg5,
				arg6, arg7, arg1);

		GET_PTR(ptr, size, 2, 3, arg1, 0);
		if (!size)
			break;

		GET_PTR(ptr2, size, 4, 5, sizeof(siginfo_t), 1);
		if (!size)
			break;

		GET_PTR(ptr3, size, 6, 7, sizeof(struct __kernel_timespec), 1);
		if (!size)
			break;

		rval = sys_rt_sigtimedwait((const sigset_t *) ptr,
				(siginfo_t *) ptr2,
				(const struct __kernel_timespec *) ptr3,
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
		DbgSCP("rval = %ld\n", rval);
		break;
	case __NR_rt_sigqueueinfo:
		GET_PTR(ptr, size, 4, 5, sizeof(siginfo_t), 1);
		rval = sys_rt_sigqueueinfo((pid_t) arg1, (int) arg2,
					   (siginfo_t *) ptr);
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
		DbgSCP("longjmp2 finish regs %px rval %ld\n",
				regs, rval);
		break;
	case __NR_futex:
		/* To ease access to FUTEX_OP let the first three UADDR,
		 * FUTEX_OP and VAL arguments be passed on registers. This way,
		 * the array passed on %qr6 may contain three fields at maximum:
		 * TIMEOUT (VAL2), UADDR2 and VAL3.  */
		get_futex_mask(arg4, &mask_type, &mask_align, &fields);
		/* Don't bother about converting array if it's not required by
		 * the command under consideration.  */
		if (fields != 0) {
			GET_PTR(ptr, size, 6, 7, 0, 0);
			if (!size)
				break;

			/* Strip all protected mode stuff from the passed
			 * parameters. */
			rval = convert_array((long *) ptr, args, size, fields,
					     1, mask_type, mask_align);
			if (rval) {
				DbgSCP(" Bad array for sys_futex (0x%x): rval == %d\n",
				       (int) arg4, (int) rval);
				break;
			}
			DbgSCP("sys_futex extended args: 0x%lx 0x%lx %d\n",
			       args[0], args[1], (int) args[2]);
		}

		/* Extract UADDR out of AP.  */
		GET_PTR(ptr, size, 2, 3, sizeof(int), 0);
		if (!size)
			break;

		DbgSCP("sys_futex primary args: 0x%lx %d %d\n",
		       ptr, (int) arg4, (int) arg5);

		rval = sys_futex((u32 *) ptr, (int) arg4, (int) arg5,
				(struct __kernel_timespec __user *) args[0],
				(u32 __user *) args[1], (int) args[2]);
		DbgSC("rval = %ld\n", rval);
		break;
	case __NR_set_robust_list:
	{
		unsigned long head;
		if (!futex_cmpxchg_enabled) {
			rval = -ENOSYS;
			break;
		}

		/* On glibc side `sizeof (struct robust_list_head) == 0x30'.  */
		if (unlikely(arg4 != 0x30)) {
			/* -EINVAL will be returned by default. */
			break;
		}

		GET_PTR(head, size, 2, 3, 0x30, 0);
		if (!size)
			break;

		current_thread_info()->pm_robust_list = (long __user *) head;
		rval = 0;
		break;
	}
	case __NR_sched_setaffinity:
		DbgSCP("sched_setaffinity(): pid %ld, len %ld, "
				"ptr 0x%lx : 0x%lx", arg1, arg2, arg4, arg5);
		GET_PTR(ptr, size, 4, 5, arg2, 0);
		if (!size)
			break;

		rval = sys_sched_setaffinity(arg1, arg2,
				(unsigned long __user *) ptr);
		DbgSCP(" rval = %ld\n", rval);
		break;
	case __NR_sched_getaffinity:
		DbgSCP("sched_getaffinity(): pid %ld, len %ld, "
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
				"0x%lx : 0x%lx, 0x%lx\n", arg2, arg3,
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
		DbgSCP("syscall %ld: clock_id = 0x%lx, timespec = "
				"0x%lx : 0x%lx, ", sys_num, arg1, arg2, arg3);

		GET_PTR(ptr, size, 2, 3, sizeof(struct __kernel_timespec),
			/* clock_getres is the only among these syscalls which
			 * may be invoked with `struct __kernel_timespec *tp ==
			 * NULL '.
			 */
			(sys_num == __NR_clock_getres ? 1 : 0));
		if (!size)
			break;

		switch (sys_num) {
		case __NR_clock_settime:
			rval = sys_clock_settime((clockid_t) arg1,
					(const struct __kernel_timespec
					__user *) ptr);
			break;
		case __NR_clock_gettime:
			rval = sys_clock_gettime((clockid_t) arg1,
					(struct __kernel_timespec __user *)
					ptr);
			break;
		case __NR_clock_getres:
			rval = sys_clock_getres((clockid_t) arg1,
					(struct __kernel_timespec __user *)
					ptr);
			break;
		}
		DbgSCP("rval = %ld\n",rval);
		break;
	case __NR_timer_create:
		GET_PTR(ptr, size, 2, 3, sizeof(struct sigevent), 0);
		if (!size)
			break;

		GET_PTR(ptr2, size, 4, 5, sizeof(timer_t), 0);
		if (!size)
			break;

		rval = sys_timer_create((clockid_t) arg1,
					(struct sigevent __user *) ptr,
					(timer_t __user *) ptr2);
		break;
	case __NR_clock_nanosleep:
		DbgSCP("sys_clock_nanosleep(): clock_id %ld, flags %ld, "
				"req = 0x%lx : 0x%lx, rem = 0x%lx : 0x%lx\n",
				arg1, arg2, arg4, arg5, arg6, arg7);

		GET_PTR(ptr2, size, 4, 5, sizeof(struct __kernel_timespec), 0);
		if (!size)
			break;

		GET_PTR(ptr3, size, 6, 7, sizeof(struct __kernel_timespec), 1);
		if (!size)
			break;

		rval = sys_clock_nanosleep((clockid_t) arg1, (int) arg2,
				(const struct __kernel_timespec __user *) ptr2,
				(struct __kernel_timespec __user *) ptr3);
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
	case __NR_olduselib:
	case __NR_newuselib:
	case __NR__sysctl:
	case __NR_socketcall:
	case __NR_readv:
	case __NR_writev:
	case __NR_preadv:
	case __NR_preadv2:
	case __NR_pwritev:
	case __NR_pwritev2:
	case __NR_select:
	case __NR__newselect:
	case __NR_pselect6:
	case __NR_execve:
		/* E2K ABI uses only 8 registers for parameter passing
		 * so sys_name and tags are packed into one parameter
		 */
		rval = ((unsigned long)(tags) << 32) | (sys_num & 0xffffffff);
		rval = do_protected_syscall((unsigned long)rval, arg1, arg2,
					arg3, arg4, arg5, arg6, arg7);
		break;
	case __NR_P_get_mem:
	case __NR_get_mem:
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
	case __NR_free_mem:
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
		DbgSCP("system call %ld (arg{2,3} = 0x%lx : 0x%lx)",
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
		DbgSCP("system call %ld (arg{2,3} = 0x%lx : 0x%lx), (arg{4,5} = "
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
		DbgSCP("Unimplemented yet system call %ld\n", sys_num);
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
		DbgSCP("rt_tgsigqueueinfo(): tgid = %ld, pid = %ld, sig = %ld, "
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
		DbgSCP("openat(): dfd = %ld, filename = 0x%lx : 0x%lx, "
				"flags = %lx, mode = %lx, ",
				arg1, arg2, arg3, arg4, arg5);

		GET_STR(str, 2, 3);
		if (!str)
			break;

		rval = sys_openat(arg1, str, arg4, arg5);
		DbgSCP("rval = %ld\n", rval);
		break;
	case __NR_mkdirat:
		DbgSCP("mkdirat(): dfd = %ld, pathname = 0x%lx : 0x%lx, "
				"mode = %lx, ", arg1, arg2, arg3, arg4);

		GET_STR(str, 2, 3);
		if (!str)
			break;

		rval = sys_mkdirat(arg1, str, arg4);
		DbgSCP("rval = %ld\n", rval);
		break;
	case __NR_mknodat:
		DbgSCP("mknodat(): dfd = %ld, filename = 0x%lx : 0x%lx, "
				"mode = %lx, dev = %ld, ",
				arg1, arg2, arg3, arg4, arg5);
		GET_STR(str, 2, 3);
		if (!str)
			break;

		rval = sys_mknodat(arg1, str, arg4, arg5);
		DbgSCP("rval = %ld\n", rval);
		break;
	case __NR_fchownat:
		DbgSCP("fchownat(): dfd = %ld, filename = 0x%lx : 0x%lx, "
				"user = %ld, group = %ld, flag = %lx, ",
				arg1, arg2, arg3, arg4, arg5, arg6);
		GET_STR(str, 2, 3);
		if (!str)
			break;

		rval = sys_fchownat(arg1, str, arg4, arg5, arg6);
		DbgSCP("rval = %ld\n", rval);
		break;
	case __NR_unlinkat:
		DbgSCP("unlinkat(): dfd = %ld, pathname = 0x%lx : 0x%lx, "
				"flag = %lx, ", arg1, arg2, arg3, arg4);
		GET_STR(str, 2, 3);
		if (!str)
			break;

		rval = sys_unlinkat(arg1, str, arg4);
		DbgSCP("rval = %ld\n", rval);
		break;
	case __NR_renameat:
		DbgSCP("renameat(): olddfd = %ld, oldname = 0x%lx : 0x%lx, "
				"newdfd = %ld, newname = 0x%lx : 0x%lx, ",
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
		DbgSCP("linkat(): olddfd = %ld, oldname = 0x%lx : 0x%lx, "
			"newdfd = %ld, flags = %lx, newname = 0x%lx : 0x%lx, ",
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
				"newdfd = %ld, newname = 0x%lx : 0x%lx, ",
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
		DbgSCP("readlinkat(): dfd = %ld, pathname = 0x%lx : 0x%lx, "
				"buf = 0x%lx : 0x%lx, bufsiz = %ld, ",
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
		DbgSCP("fchmodat(): dfd = %ld, filename = 0x%lx : 0x%lx, "
				"mode = %lx, ", arg1, arg2, arg3, arg4);
		GET_STR(str, 2, 3);
		if (!str)
			break;

		rval = sys_fchmodat(arg1, str, arg4);
		DbgSCP("rval = %ld\n", rval);
		break;
	case __NR_faccessat:
		DbgSCP("faccessat(): dfd = %ld, filename = 0x%lx : 0x%lx, "
				"mode = %lx, ", arg1, arg2, arg3, arg4);
		GET_STR(str, 2, 3);
		if (!str)
			break;

		rval = sys_faccessat(arg1, str, arg4);
		DbgSCP("rval = %ld\n", rval);
		break;
	case __NR_dup3:
		DbgSCP("dup3(): oldfd= %ld, newfd = %ld : flags=0x%lx\n "
				, arg1, arg2, arg3);
		rval = sys_dup3(arg1, arg2, arg3);
		DbgSCP("rval = %ld\n", rval);
		break;
	case __NR_inotify_init1:
		rval = sys_inotify_init1(arg1);
		DbgSCP("rval = %ld\n", rval);
		break;
	case __NR_epoll_create1:
		DbgSCP("sys_epoll_create1(): flags=0x%lx\n ", arg1);
		rval = sys_epoll_create1(arg1);
		DbgSCP("rval = %ld\n", rval);
		break;
	case __NR_newfstatat:
		DbgSCP("sys_fstatat64(): dfd=0x%lx filename=0x%lx: 0x%lx"
					" statbuf=0x%lx: 0x%lx,flags=0x%lx\n",
			arg1, arg2, arg3, arg4, arg5, arg6);
		GET_STR(str, 2, 3);
		if (!str)
			break;
		GET_PTR(ptr, size, 4, 5, sizeof(struct stat), 0);
		if (!ptr)
			break;
		rval = sys_newfstatat((int) arg1, str, (struct stat *) ptr,
				      (int) arg6);
		DbgSCP("rval = %ld\n", rval);
		break;
	case __NR_futimesat:
		DbgSCP("sys_futimesat(): dfd=0x%lx filename=0x%lx: 0x%lx"
					" statbuf=0x%lx: 0x%lx,flags=0x%lx\n",
			arg1, arg2, arg3, arg4, arg5, arg6);
		GET_STR(str, 2, 3);
		if (!str)
			break;
		GET_PTR(ptr, size, 4, 5, 2 * sizeof(struct timeval), 1);
		if (!ptr)
			break;
		rval = sys_futimesat((int) arg1, str, (struct timeval *) ptr);
		DbgSCP("rval = %ld\n", rval);
		break;
	case __NR_setcontext:
		DbgSCP("sys_setcontext(): ucp=0x%lx:0x%lx, sigsetsize=%ld\n",
				arg2, arg3, arg4);

		GET_PTR(ptr, size, 2, 3, sizeof(struct ucontext_prot), 0);
		if (!size)
			break;

		rval = protected_sys_setcontext((struct ucontext_prot *) ptr,
						arg4);
		DbgSCP("rval = %ld\n", rval);
		break;
	case __NR_makecontext:
		DbgSCP("sys_makecontext(): ucp=0x%lx:0x%lx, func %lx,"
		       " args_size %lx, args %lx:%lx, sigsetsize=%ld\n",
				arg2, arg3, arg4, arg5, arg6, arg7, arg1);

		GET_PTR(ptr, size, 2, 3, sizeof(struct ucontext_prot), 0);
		if (!size)
			break;

		GET_PTR(ptr2, size, 6, 7, 16, 1);
		if (!size)
			ptr2 = 0;

		rval = protected_sys_makecontext(
				(struct ucontext_prot *) ptr,
				(void (*)(void)) arg4, arg5,
				(void *) ptr2, arg1);
		DbgSCP("rval = %ld\n", rval);
		break;
	case __NR_swapcontext:
		DbgSCP("sys_swapcontext(): oucp=0x%lx:0x%lx, ucp %lx:%lx, sigsetsize=%ld\n",
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
		DbgSCP("rval = %ld\n", rval);
		break;
	case __NR_freecontext:
		DbgSCP("sys_freecontext(): ucp=0x%lx:0x%lx\n",
				arg2, arg3);

		GET_PTR(ptr, size, 2, 3, sizeof(struct ucontext_prot), 0);
		if (!size)
			break;

		rval = protected_sys_freecontext(
				(struct ucontext_prot *) ptr);
		DbgSCP("rval = %ld\n", rval);
		break;
	case __NR_set_backtrace:
		GET_PTR(ptr, size, 2, 3, arg4 * 8, 1);
		if ((arg4 * 8) && !size)
			break;
		rval = sys_set_backtrace((unsigned long *) ptr,
					  arg4, arg5, arg6);
		break;
	case __NR_access_hw_stacks:
		DbgSCP("access_hw_stacks(): mode = 0x%lx, "
				"buf_size = 0x%lx, "
				"frame_ptr = 0x%lx : 0x%lx, "
				"buf = 0x%lx : 0x%lx, "
				"real_size = 0x%lx : 0x%lx, ",
				arg1 >> 32, arg1 & 0xffffffffUL,
				arg2, arg3, arg4, arg5, arg6, arg7);

		GET_PTR(ptr, size, 2, 3, sizeof(unsigned long long), 1);
		if (!size)
			break;

		GET_PTR(ptr2, size, 4, 5, arg1 & 0xffffffffUL, 1);
		/* Take into account that BUF_SIZE provided by the user may
		   be zero in which case it's quite OK to get for BUF `size
		   == 0' (note that `GET_PTR ()' will return `size == 0' also
		   for `buf == NULL' in such a case).  */
		if ((arg1 & 0xffffffffUL) && !size)
			break;

		GET_PTR(ptr3, size, 6, 7, sizeof(u64), 1);
		if (!size)
			break;

		rval = sys_access_hw_stacks(arg1 >> 32,
					    (unsigned long long *) ptr,
					    (char __user *) ptr2,
					    arg1 & 0xffffffffUL,
					    (void __user *) ptr3);
		DbgSCP("rval = %ld\n", rval);
		break;
	case __NR_ioctl:
		/* The exact size of `char *argp' AP required by this or that
		 * request is obviously unknown here. For now stupidly require
		 * AP to be at least one byte long if it's not NULL, but at the
		 * same time allow for NULL. The rationale is that some `ioctl
		 * ()' requests requiring no `argp' should accept NULL, however,
		 * there is no point in passing a zero sized non-NULL buffer to
		 * `ioctl ()'.  */
		GET_PTR(ptr, size, 4, 5, 1, 1);
		rval = sys_ioctl((unsigned int) arg1, (unsigned int) arg2,
				  (unsigned long) ptr);
		break;
	case __NR_fcntl:
		GET_PTR_OR_NUMBER(ptr, size, 4, 5, 0, 1);
		rval = sys_fcntl((unsigned int) arg1, (unsigned int) arg2,
				  (unsigned long) ptr);
		break;
	case __NR_fallocate:
		DbgSCP("fallocate(arg1=%d, arg2=%d, arg3=0x%lx, arg4=0x%lx)\n",
		       (int) arg1, (int) arg2, (off_t) arg3, (off_t) arg4);
		rval = sys_fallocate((int) arg1, (int) arg2, (off_t) arg3,
				      (off_t) arg4);
		break;
	case __NR_getresuid:
		GET_PTR(ptr, size, 2, 3, sizeof(uid_t), 0);
		if (!size) {
			rval = -EFAULT;
			break;
		}

		GET_PTR(ptr2, size, 4, 5, sizeof(uid_t), 0);
		if (!size) {
			rval = -EFAULT;
			break;
		}

		GET_PTR(ptr3, size, 6, 7, sizeof(uid_t), 0);
		if (!size) {
			rval = -EFAULT;
			break;
		}

		rval = sys_getresuid((uid_t *) ptr, (uid_t *) ptr2,
				      (uid_t *) ptr3);
		break;
	case __NR_getresgid:
		GET_PTR(ptr, size, 2, 3, sizeof(gid_t), 0);
		if (!size) {
			rval = -EFAULT;
			break;
		}

		GET_PTR(ptr2, size, 4, 5, sizeof(gid_t), 0);
		if (!size) {
			rval = -EFAULT;
			break;
		}

		GET_PTR(ptr3, size, 6, 7, sizeof(gid_t), 0);
		if (!size) {
			rval = -EFAULT;
			break;
		}

		rval = sys_getresgid((gid_t *) ptr, (gid_t *) ptr2,
				       (gid_t *) ptr3);
		break;
	case __NR_mount:
		GET_PTR(ptr, size, 2, 3, 0, 0);
		rval = convert_array((long *) ptr, args, 80, 5, 1,
					0x37f, 0x3ff);
		if (rval) {
			DbgSCP(" Bad array for sys_mount\n");
			break;
		}
		rval = sys_mount((char *) args[0], (char *) args[1],
				(char *) args[2], (unsigned long) args[3],
				(char *) args[4]);
		break;
	default:
		if ((u64) sys_num >= NR_syscalls) {
			rval = -ENOSYS;
			break;
		}
		DbgSCP("system call %ld (0x%lx, 0x%lx, 0x%lx, 0x%lx)  ",
				sys_num, arg1, arg2, arg3, arg4);
		rval = (*sys_protcall_table[sys_num])(arg1, arg2, arg3, arg4,
				arg5, arg6);
		DbgSCP(" rval = %ld\n", rval);
		break;
	}

	SAVE_PSYSCALL_RVAL(regs, rval, rval1, rval2,
			   rv1_tag, rv2_tag, return_desk);

	/* Trace syscall exit */
	if (unlikely(current_thread_info()->flags & _TIF_WORK_SYSCALL_TRACE)) {
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

	NEW_CHECK_PT_REGS_ADDR(prev_regs, regs, usd_lo_prev);

	finish_syscall(regs, FROM_SYSCALL_PROT_10, true);
}


static inline
unsigned long e2k_dscr_ptr_size(long low, long hiw, long min_size,
				unsigned int *ptr_size, u64 sbr_hi,
				u16 sys_num, u8 argnum, u8 *fatal)
{
	/* NB> 'min_size' may be negative; this is why it has 'long' type */
	e2k_ptr_t ptr;

	AW(ptr).lo = low;
	AW(ptr).hi = hiw;
	*ptr_size = AS(ptr).size - AS(ptr).curptr;

	if (*ptr_size < min_size) {
#define ERR_DESCRIPTOR_SIZE "System call #%d arg #%d: Pointer is too small: %d < %ld\n"
		DbgSCP_ALERT(ERR_DESCRIPTOR_SIZE,
			     sys_num, argnum, *ptr_size, min_size);
		*ptr_size = 0;
		*fatal = 1;
		return 0;
	}
	return E2K_PTR_PTR(ptr, sbr_hi);
}

#define MASK_PROT_ARG_LONG		0
#define MASK_PROT_ARG_DSCR		1
#define MASK_PROT_ARG_LONG_OR_DSCR	2
#define MASK_PROT_ARG_STRING		3
#define MASK_PROT_ARG_INT		4
#define MASK_PROT_ARG_FPTR		5
#define MASK_PROT_ARG_NOARG		0xf
#define ADJUST_SIZE_MASK	1

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
 * descr_lo/hi - protected argument couple;
 * min_size - minimum allowed argument-descriptor size (if known);
 * sbr_hi   - stack base pointer (hi);
 * fatal    - signal to let caller know that this argument is wrong, and
 *                    it would be unsafe to proceed with the system call.
 */
static inline
unsigned long get_protected_ARG(u16 sys_num, u64 tag, u32 mask, u8 a_num,
			     unsigned long descr_lo, unsigned long descr_hi,
			     long min_size, u64 sbr_hi, u8 *fatal)
{
#define ERR_BAD_ARG_TAG \
	"System call #%u/%s: unexpected tag (0x%x) in arg #%d.\n"
#define ERR_MISSED_ARG_TAG \
	"\t\tArg #%d is missed or uninitialized.\n"
#define ERR_NONPTR_NOT_ALLOWED \
	"System call #%u/%s: not a pointer is not allowed in arg #%d.\n"
#define ERR_NOT_A_STRING \
	"System call #%u/%s: not a null-terminated string in arg #%d.\n"
#define ERR_UNEXPECTED_DSCR \
	"System call #%u/%s: unexpected descriptor in arg #%d.\n"
	u8 msk = (mask >> (a_num * 4)) & 0xf;
	unsigned long ptr; /* the result */
	unsigned int size;
	u64 tag_lo = tag & 0xf;

	if ((tag == ETAGDWQ) || (msk == MASK_PROT_ARG_NOARG))
		return 0L; /* arg was not passed or irrelevant */
	else if ((msk == MASK_PROT_ARG_INT) ||
		/* The check below does the following:
		 * - in the current ABI syscall argument takes 4 words (16 bytes);
		 * - if syscall argument is of type 'int' (not 'long'), then
		 *   only lowest word (word #0) gets filled by compiler while
		 *   other 3 words contain trash (the contents of previous call);
		 * - if tag of the lowest word is numeric tag (i.e. '0'), then
		 *   this argument is definitely of type 'int' and
		 * - we may remove trash in the word #1 to make it simpler.
		 */
		(tag_lo && !(tag_lo & 0x3))) { /* numerical tag in lower word */
		/* this is 'int' argument */
		tag_lo &= 0x3;
		tag = tag_lo;
		descr_lo = (int) descr_lo; /* removing trash in higher word */
	}

#if DEBUG_SYSCALLP_CHECK
	if ((tag != ETAGDWQ)
		&& (tag_lo != ETAGNUM)
		&& (tag != ETAGAPQ)
		&& (tag != ETAGPLD)
		&& (tag != ETAGPLQ)) {
		DbgSCP_ERR(ERR_BAD_ARG_TAG,
			sys_num, sys_call_ID_to_name[sys_num], (u8)tag, a_num);
		if (((tag == ETAGDWD)
			&& ((msk == MASK_PROT_ARG_LONG) || (msk == MASK_PROT_ARG_INT)))
			|| ((tag == ETAGDWS) && (msk == MASK_PROT_ARG_INT)))
			DbgSCP_ERR(ERR_MISSED_ARG_TAG, a_num);
		DbgSCP("%s: tag=0x%llx tag_lo=0x%llx msk=0x%x a_num=%d\n",
		       __func__, tag, tag_lo, (int)msk, a_num);
		PM_EXCEPTION_IF_ORTH_MODE(SIGILL, ILL_ILLOPN, -EINVAL);
		*fatal = 1;
	}
#endif /* DEBUG_SYSCALLP_CHECK */

	if ((tag == ETAGPLD) || (tag == ETAGPLQ)) {
		e2k_pl_lo_t pl_lo;

		AW(pl_lo) = descr_lo;
		return pl_lo.PL_lo_target;
	}

	/* First, we check if the argument is non-pointer: */
	if (tag != ETAGAPQ) {
		unsigned long ret = (tag == ETAGDWQ) ? 0 : descr_lo;

		if (unlikely(!null_prot_ptr(tag_lo, descr_lo) &&
				(msk == MASK_PROT_ARG_DSCR ||
				 msk == MASK_PROT_ARG_STRING))) {
			if (!PM_SYSCALL_WARN_ONLY)
				*fatal = 1;
			DbgSCP_ALERT(ERR_NONPTR_NOT_ALLOWED,
				sys_num, sys_call_ID_to_name[sys_num], a_num);
			PM_EXCEPTION_IF_ORTH_MODE(SIGILL, ILL_ILLOPN, -EINVAL);
		}

		return ret;
	}

	/* Finally, this is descriptor; getting pointer from it: */
	ptr = e2k_dscr_ptr_size(descr_lo, descr_hi, min_size, &size,
				sbr_hi, sys_num, a_num, fatal);

	/* Second, we check if the argument is string: */
	if (msk == MASK_PROT_ARG_STRING) {
		if (e2k_ptr_str_check((char __user *) ptr, size)) {
			if (!PM_SYSCALL_WARN_ONLY)
				*fatal = 1;
			DbgSCP_ALERT(ERR_NOT_A_STRING,
				sys_num, sys_call_ID_to_name[sys_num], a_num);
		}
	} else {
		/* Eventually, we check if this is proper pointer: */
		if (unlikely(sys_num && msk != MASK_PROT_ARG_DSCR &&
				msk != MASK_PROT_ARG_LONG_OR_DSCR)) {
			if (!PM_SYSCALL_WARN_ONLY)
				*fatal = 1;
			DbgSCP_ALERT(ERR_UNEXPECTED_DSCR, sys_num,
					sys_call_ID_to_name[sys_num], a_num);
			PM_EXCEPTION_IF_ORTH_MODE(SIGILL, ILL_ILLOPN, -EINVAL);
		}
	}

	return ptr;
}

#define RW_BUFSIZE_WARN \
	"Syscall #%u/%s: Count exceeds the descriptor (arg #%d) size: %d > %d\n"
#define RW_COUNT_TRUNCATED "Count truncated down to the descriptor size (%d)\n"

static inline
int check_arg_descr_size(int sys_num, int arg_num, int neg_size,
			 struct pt_regs *regs, int adjust_bufsize,
			 long *arg3, long *arg5, long *arg7)
/* In case of negative size in syscall argument mask,
 * calculate effective argument size and update args3-7
 */
{
	int size, descr_size, index;

	if (neg_size >= 0) {
		pr_alert("FATAL: bad 'neg_size' (%d) at %s:%d !!!\n",
			 neg_size, __FILE__, __LINE__);
		return neg_size; /* nothing to do with this */
	}

	index = -neg_size*2 - 1;
	size = regs->args[index];
	if (!adjust_bufsize)
		return size;

	descr_size = e2k_ptr_size(regs->args[arg_num * 2 - 1],
				  regs->args[arg_num * 2], 0);

	if (likely(descr_size >= size))
		return size;

	/* Requested size appeared bigger than descriptor size.
	 * Adjusting the requested size value:
	 */
	DbgSCP_WARN(RW_BUFSIZE_WARN,
		    (u32)sys_num, sys_call_ID_to_name[sys_num], arg_num,
		    size, descr_size);
	if (PM_SYSCALL_WARN_ONLY && adjust_bufsize)
		DbgSCP_WARN(RW_COUNT_TRUNCATED, descr_size);
	size = descr_size;

	if (!PM_SYSCALL_WARN_ONLY) {
		e2k_ptr_lo_t descr_lo;
		e2k_ptr_hi_t descr_hi;
		void *addr;

		descr_lo.word = regs->args[arg_num * 2 - 1];
		descr_hi.word = regs->args[arg_num * 2];
		addr = (void *)(descr_lo.fields.ap.base + descr_hi.fields.size);
		force_sig_bnderr(addr, (void *)descr_lo.fields.ap.base, addr);
	}

	if (adjust_bufsize)
		switch (index) {
		case 3:
			*arg3 = size;
			break;
		case 5:
			*arg5 = size;
			break;
		case 7:
			*arg7 = size;
			break;
		default:
			pr_alert("FATAL: bad 'index' (%d) at %s:%d !!!\n",
				index, __FILE__, __LINE__);
			break;
		}

	return size;
}


__section(".entry.text")
SYS_RET_TYPE notrace ttable_entry8_C(u64 sys_num, u64 tags, long arg1,
		long arg2, long arg3, long arg4, struct pt_regs *regs)
{
#ifdef CONFIG_DEBUG_PT_REGS
	e2k_usd_lo_t usd_lo_prev;
	struct pt_regs *prev_regs = regs;
#endif
	long rval = -EINVAL;
	long arg5 = regs->args[5], arg6 = regs->args[6], arg7 = regs->args[7],
	     arg8 = regs->args[8], arg9 = regs->args[9], arg10 = regs->args[10],
	     arg11 = regs->args[11], arg12 = regs->args[12];
	unsigned long a1, a2, a3, a4, a5, a6;
	protected_system_call_func sys_call;
	unsigned long ti_flags = current_thread_info()->flags;
	u32 mask;
	int size1, size2, size3, size4;
	u16 size5, size6;
	u64 sbr_hi = GET_SBR_HI();
	u8 wrong_arg = 0; /* signal that an argument detected wrong */
#ifdef CONFIG_E2K_PROFILING
	register long start_tick = NATIVE_READ_CLKR_REG_VALUE();
	register long clock1;
#endif

#ifdef CONFIG_DEBUG_PT_REGS
	/*
	 * pt_regs structure is placed as local data of the
	 * trap handler (or system call handler) function
	 * into the kernel local data stack
	 */
	usd_lo_prev = NATIVE_NV_READ_USD_LO_REG();
#endif
	init_pt_regs_for_syscall(regs);
	SAVE_STACK_REGS(regs, current_thread_info(), true, false);
	regs->sys_num = sys_num;
	regs->return_desk = 0;

	/* Important: this must be before the first call
	 * but after saving %wd register.
	 */
	if (cpu_has(CPU_HWBUG_VIRT_PSIZE_INTERCEPTION)) {
		e2k_wd_t wd = READ_WD_REG();
		wd.psize = 0x40;
		WRITE_WD_REG(wd);
	}
	DbgSCP("\nsys_num = %lld: tags = 0x%llx, arg1 = 0x%lx, arg2 = 0x%lx, arg3 = 0x%lx, arg4 = 0x%lx\n"
		"\targ5 = 0x%lx, arg6 = 0x%lx, arg7 = 0x%lx, arg8 = 0x%lx, arg9 = 0x%lx, arg10 = 0x%lx\n",
		sys_num, tags, arg1, arg2, arg3, arg4,
		arg5, arg6, arg7, arg8, arg9, arg10);

#ifdef CONFIG_E2K_PROFILING
	read_ticks(clock1);
	info_save_stack_reg(clock1);
#endif
	if (sys_num >= NR_syscalls) {
		sys_call = (protected_system_call_func) sys_ni_syscall;
		mask = size1 = size2 = 0;
	} else {
		sys_call = sys_call_table_entry8[sys_num];
#if DEBUG_SYSCALLP_CHECK
#define SYSCALL_NOT_AVAILABLE_IN_PM \
"!!! System call #%lld (%s) is not available in the protected mode !!!\n"
		if (sys_call == (protected_system_call_func)sys_ni_syscall)
			DbgSCP_ALERT(SYSCALL_NOT_AVAILABLE_IN_PM, sys_num,
						sys_call_ID_to_name[sys_num]);
#endif
		mask = sys_protcall_args[sys_num].mask;
		size1 = sys_protcall_args[sys_num].size1;
		size2 = sys_protcall_args[sys_num].size2;
	}

	current_thread_info()->pt_regs = regs;
	WRITE_PSR_IRQ_BARRIER(AW(E2K_KERNEL_PSR_ENABLED));

	DbgSCP("_NR_ %lld/%s start: mask=0x%x current %px pid %d\n", sys_num,
		(sys_num < NR_syscalls) ? sys_call_ID_to_name[sys_num] : "sys_ni_syscall",
		mask, current, current->pid);

	/* All other arguments have been saved in assembler already */
	regs->args[1] = arg1;
	regs->args[2] = arg2;
	regs->args[3] = arg3;
	regs->args[4] = arg4;
	regs->tags = tags;

	if (likely(sys_num < NR_syscalls)) {

		if (size1 < 0)
			size1 = check_arg_descr_size(sys_num, 1, size1, regs,
						     mask & ADJUST_SIZE_MASK,
						     &arg3, &arg5, &arg7);
		size3 = sys_protcall_args[sys_num].size3;
		if (size3 < 0)
			size3 = check_arg_descr_size(sys_num, 3, size3, regs,
						     mask & ADJUST_SIZE_MASK,
						     &arg3, &arg5, &arg7);
		size4 = sys_protcall_args[sys_num].size4;
		/* So far we don't have negative size in the 4th row.
		 * To be added in the future if needed:
		if (size4 < 0)
			size4 = regs->args[-size4];
		 */
		size5 = sys_protcall_args[sys_num].size5;
		/* So far we don't have negative size in the 5th row.
		 * To be added in the future if needed:
		if (size5 < 0)
			size5 = regs->args[-size5];
		 */
		if (size2 < 0)
			size2 = check_arg_descr_size(sys_num, 2, size2, regs,
						     mask & ADJUST_SIZE_MASK,
						     &arg3, &arg5, &arg7);
		size6 = sys_protcall_args[sys_num].size6;
		/* So far we don't have negative size in the 6th row.
		 * To be added in the future if needed:
		if (size6 < 0)
			size6 = regs->args[-size6];
		 */

		a1 = get_protected_ARG(sys_num, (tags >> 8) & 0xffUL, mask, 1,
			       arg1, arg2, size1, sbr_hi, &wrong_arg);
		a2 = get_protected_ARG(sys_num, (tags >> 16) & 0xffUL, mask, 2,
			       arg3, arg4, size2, sbr_hi, &wrong_arg);
		a3 = get_protected_ARG(sys_num, (tags >> 24) & 0xffUL, mask, 3,
			       arg5, arg6, size3, sbr_hi, &wrong_arg);
		a4 = get_protected_ARG(sys_num, (tags >> 32) & 0xffUL, mask, 4,
			       arg7, arg8, size4, sbr_hi, &wrong_arg);
		a5 = get_protected_ARG(sys_num, (tags >> 40) & 0xffUL, mask, 5,
			       arg9, arg10, size5, sbr_hi, &wrong_arg);
		a6 = get_protected_ARG(sys_num, (tags >> 48) & 0xffUL, mask, 6,
			       arg11, arg12, size6, sbr_hi, &wrong_arg);

	} /* (sys_num < NR_syscalls) */

	DbgSCP("system call %lld (0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx)\n",
			sys_num, a1, a2, a3, a4, a5, a6);
	if (likely(!(ti_flags & _TIF_WORK_SYSCALL_TRACE) && !wrong_arg)) {
		/* Fast path */
		rval = sys_call(a1, a2, a3, a4, a5, a6, regs);
		SAVE_SYSCALL_RVAL(regs, rval);
	} else if (likely(!wrong_arg)) {
		/* Trace syscall enter */
		SAVE_SYSCALL_ARGS(regs, a1, a2, a3, a4, a5, a6);
		syscall_trace_entry(regs);
		/* Update args, since tracer could have changed them */
		RESTORE_SYSCALL_ARGS(regs, sys_num, a1, a2, a3, a4, a5, a6);

		save_syscall_args_prot(regs, arg1, arg2, arg3, arg4, arg5, arg6,
				arg7, arg8, arg9, arg10, arg11, arg12, tags);
		rval = sys_call(a1, a2, a3, a4, a5, a6, regs);
		SAVE_SYSCALL_RVAL(regs, rval);

		/* Trace syscall exit */
		SAVE_SYSCALL_ARGS(regs, a1, a2, a3, a4, a5, a6);
		syscall_trace_leave(regs);
		/* Update rval, since tracer could have changed it */
		RESTORE_SYSCALL_RVAL(regs, rval);

		/* For syscall restart */
		SAVE_SYSCALL_ARGS(regs, arg1, arg2, arg3, arg4, arg5, arg6);
	} else /* (unlikely(wrong_arg)) */ {
		rval = -EFAULT;
		SAVE_SYSCALL_RVAL(regs, rval);
	}
	DbgSCP("syscall %lld : rval = 0x%lx / %ld\n", sys_num, rval, rval);

	/* It works only under CONFIG_FTRACE flag */
	add_info_syscall(sys_num, start_tick);

	/* We may skip assigning 'args' here because
	 * it is used only in the switch above.
	 * args = (long *) ((((unsigned long) regs) + sizeof(struct pt_regs)
	 *		+ 0xfUL) & (~0xfUL));
	 */

	NEW_CHECK_PT_REGS_ADDR(prev_regs, regs, usd_lo_prev);

	finish_syscall(regs, FROM_SYSCALL_PROT_8, true);
}

/*
 * this is a copy of sys_socketcall (net/socket.c)
 *
 * The type of structure  depend on first parameter
 */
notrace __section(".entry.text")
static void get_socketcall_mask(long call, long *mask_type, long *mask_align,
				int *fields)
{

	switch(call)
	{
		case SYS_SOCKET:
			*mask_type = 0x15;
			*mask_align = 0x15;
			*fields = 3;
			/* err = sys_socket(a[0], a[1], a[2]); */
			break;
		case SYS_BIND:
			*mask_type = 0x1d;
			*mask_align = 0x1f;
			*fields = 3;
			/* err = sys_bind(a[0],
				(struct sockaddr __user *) a[1], a[2]); */
			break;
		case SYS_CONNECT:
			*mask_type = 0x1d;
			*mask_align = 0x1f;
			*fields = 3;
			/* err = sys_connect(a[0],
				(struct sockaddr __user *) a[1], a[2]); */
			break;
		case SYS_LISTEN:
			*mask_type = 0x5;
			*mask_align = 0x5;
			*fields = 2;
			/* err = sys_listen(a[0], a[1]); */
			break;
		case SYS_ACCEPT:
			*mask_type = 0x3d;
			*mask_align = 0x3f;
			*fields = 3;
			/* err = sys_accept(a[0],
			(struct sockaddr __user *) a[1], (int __user*) a[2]);*/
			break;
		case SYS_GETSOCKNAME:
			*mask_type = 0x3d;
			*mask_align = 0x3f;
			*fields = 3;
			/* err = sys_getsockname(a[0],
			(struct sockaddr __user*) a[1], (int __user *) a[2]);*/
			break;
		case SYS_GETPEERNAME:
			*mask_type = 0x3d;
			*mask_align = 0x3f;
			*fields = 3;
			/*err = sys_getpeername(a[0],
			(struct sockaddr __user *) a[1], (int __user *)a[2]);*/
			break;
		case SYS_SOCKETPAIR:
			*mask_type = 0xd5;
			*mask_align = 0xf5;
			*fields = 4;
			/*err = sys_socketpair(a[0], a[1], a[2],
						(int __user *)a[3]);*/
			break;
		case SYS_SEND:
			*mask_type = 0x5d;
			*mask_align = 0x5f;
			*fields = 4;
			/* err = sys_send(a[0], (void __user *) a[1], a[2],
								a[3]); */
			break;
		case SYS_SENDTO:
			*mask_type = 0x75d;
			*mask_align = 0x7df;
			*fields = 6;
			/* err = sys_sendto(a[0], (void __user *) a[1], a[2],
			 a[3], (struct sockaddr __user *) a[4], a[5]); */
			break;
		case SYS_RECV:
			*mask_type = 0x5d;
			*mask_align = 0x5f;
			*fields = 4;
			/* err = sys_recv(a[0], (void __user *) a[1],
						a[2], a[3]); */
			break;
		case SYS_RECVFROM:
			*mask_type = 0xf5d;
			*mask_align = 0xfdf;
			*fields = 6;
			/* err = sys_recvfrom(a[0], (void __user *) a[1], a[2],
					a[3], (struct sockaddr __user *) a[4],
					(int __user *) a[5]); */
			break;
		case SYS_SHUTDOWN:
			*mask_type = 0x5;
			*mask_align = 0x5;
			*fields = 2;
			/* err = sys_shutdown(a[0], a[1]); */
			break;
		case SYS_SETSOCKOPT:
			*mask_type = 0x1d5;
			*mask_align = 0x1f5;
			*fields = 5;
			/* err = sys_setsockopt(a[0], a[1], a[2],
					(char __user *)a[3], a[4]); */
			break;
		case SYS_GETSOCKOPT:
			*mask_type = 0x3d5;
			*mask_align = 0x3f5;
			*fields = 5;
			/* err = sys_getsockopt(a[0], a[1], a[2],
				(char __user *) a[3], (int __user *)a[4]); */
			break;
		case SYS_SENDMSG:
			*mask_type = 0x1d;
			*mask_align = 0x1f;
			*fields = 3;
			/* err = sys_sendmsg(a[0],
					(struct msghdr __user *) a[1], a[2]);*/
			break;
		case SYS_RECVMSG:
			*mask_type = 0x1d;
			*mask_align = 0x1f;
			*fields = 3;
			/* err = sys_recvmsg(a[0],
				(struct msghdr __user *) a[1], a[2]); */
			break;
		default:
			*mask_type = 0x0;
			*mask_align = 0x0;
			*fields = 0;
			break;
	}
}

notrace __section(".entry.text")
static long check_select_fs(e2k_ptr_t *fds_p, fd_set *fds[3])
{
	volatile int res = 0;
	int i;

	/* Now we'll touch user addresses. Let's do it carefuly */
	TRY_USR_PFAULT {
		for (i = 0; i < 3; i++, fds_p++) {
			if (AWP(fds_p).lo == 0
			    && AWP(fds_p).hi == 0
			    && (NATIVE_LOAD_TAGD(&AWP(fds_p).hi) == 0)
			    && (NATIVE_LOAD_TAGD(&AWP(fds_p).lo) == 0)) {
				fds[i] = (fd_set *) 0;
				continue;
			}

			if ((NATIVE_LOAD_TAGD(&AWP(fds_p).hi) != E2K_AP_HI_ETAG) ||
			    (NATIVE_LOAD_TAGD(&AWP(fds_p).lo) != E2K_AP_LO_ETAG)) {
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
			fds[i] = (fd_set *)E2K_PTR_PTR(fds_p[i], GET_SBR_HI());
		}
	} CATCH_USR_PFAULT {
		res = -EINVAL;
	} END_USR_PFAULT

	return res;
}

#define get_user_space(x)	arch_compat_alloc_user_space(x)

notrace __section(".entry.text")
static long do_protected_syscall(unsigned long sys_num, const long arg1,
		const long arg2, const long arg3, const long arg4,
		const long arg5, const long arg6, const long arg7)
{
	long rval = -EINVAL;
	unsigned long ptr, ptr2;
	unsigned int size;
	char *str;
	long mask_type, mask_align;
	int fields;
	unsigned long tags = sys_num >> 32;

	sys_num = sys_num & 0xffffffff;
	DbgSCP("protected call %ld: 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx",
			sys_num, arg1, arg2, arg3, arg4, arg5);

	switch (sys_num) {
	case __NR_olduselib: {
		kmdd_t kmdd;
		umdd_old_t *umdd;

		if (IS_CPU_ISET_V6())
			return -ENOSYS;

		GET_STR(str, 2, 3);
		if (!str)
			break;

		GET_PTR(ptr, size, 4, 5, MDD_OLD_PROT_SIZE, 0);
		if (!size)
			break;

		if (current->thread.flags & E2K_FLAG_3P_ELF32)
			rval = sys_load_cu_elf32_3P(str, &kmdd);
		else
			rval = sys_load_cu_elf64_3P(str, &kmdd);

		if (rval) {
			DbgSCP("failed, could not load\n");
			break;
		}

		umdd = (umdd_old_t *) ptr;

		rval |= PUT_USER_AP(&umdd->mdd_got, kmdd.got_addr,
				    kmdd.got_len, 0, RW_ENABLE);
		if (kmdd.init_got_point)
			rval |= PUT_USER_PL_V2(&umdd->mdd_init_got,
						kmdd.init_got_point);
		else
			rval |= put_user(0L, &umdd->mdd_init_got.word);

		if (kmdd.entry_point)
			rval |= PUT_USER_PL_V2(&umdd->mdd_start,
						kmdd.entry_point);
		else
			rval |= put_user(0L, &umdd->mdd_start.word);

		if (kmdd.init_point)
			rval |= PUT_USER_PL_V2(&umdd->mdd_init,
						kmdd.init_point);
		else
			rval |= put_user(0L, &umdd->mdd_init.word);

		if (kmdd.fini_point)
			rval |= PUT_USER_PL_V2(&umdd->mdd_fini,
						kmdd.fini_point);
		else
			rval |= put_user(0L, &umdd->mdd_fini.word);
		break;
	}
	case __NR_newuselib: {
		kmdd_t kmdd;
		umdd_t *umdd;

		GET_STR(str, 2, 3);
		if (!str)
			break;

		GET_PTR(ptr, size, 4, 5, MDD_PROT_SIZE, 0);
		if (!size)
			break;

		if (current->thread.flags & E2K_FLAG_3P_ELF32)
			rval = sys_load_cu_elf32_3P(str, &kmdd);
		else
			rval = sys_load_cu_elf64_3P(str, &kmdd);

		if (rval) {
			DbgSCP("failed, could not load\n");
			break;
		}
		BUG_ON(kmdd.cui == 0);

		umdd = (umdd_t *) ptr;

		rval |= PUT_USER_AP(&umdd->mdd_got, kmdd.got_addr,
				    kmdd.got_len, 0, RW_ENABLE);

		if (kmdd.init_got_point) {
			rval |= PUT_USER_PL(&umdd->mdd_init_got,
						kmdd.init_got_point,
						kmdd.cui);
		} else {
			rval |= put_user(0L, &umdd->mdd_init_got.PLLO_value);
			rval |= put_user(0L, &umdd->mdd_init_got.PLHI_value);
		}

		break;
	}
	case __NR__sysctl: {
		struct __sysctl_args *new_arg;

		GET_PTR(ptr, size, 2, 3, 0, 0);
		new_arg = get_user_space(sizeof(struct __sysctl_args));
		if ((rval = convert_array((long *) ptr, (long *)new_arg, size,
					  6, 1, 0x3f3, 0x3ff))) {
			DbgSCP(" Bad array for sys_sysctl\n");
			return -EINVAL;
		}

		rval = sys_sysctl(new_arg);
		break;
	}
	case __NR_socketcall: {
		long *args;
		get_socketcall_mask(arg1, &mask_type, &mask_align, &fields);

		if (fields == 0) {
			DbgSCP("Bad socketcall number %ld\n", arg1);
			return -EINVAL;
		}

		/* `convert_array ()' below will determine if AP.size is large
		 * enough for this request. */
		GET_PTR(ptr, size, 2, 3, 0, 0);
		if (!ptr) {
			DbgSCP("NULL pointer passed to socketcall (%d)",
								(int) arg1);
			return -EFAULT;
		}

		/*
		 * Need an additional conversions of arguments
		 * for syscalls recvmsg/sendmsg
		 */
		if ((arg1 == SYS_SENDMSG) || (arg1 == SYS_RECVMSG)) {
#define MASK_MSGHDR_TYPE     0x773  /* type mask for struct msghdr */
#define MASK_MSGHDR_ALIGN    0x17ff /* alignment mask for msghdr structure */
#define SIZE_MSGHDR          96     /* size of struct msghdr in user space */
#define MASK_IOVEC_TYPE      0x7    /* mask for converting of struct iovec */
#define MASK_IOVEC_ALIGN     0xf    /* alignment mask for struct iovec */
#define SIZE_IOVEC           32     /* size of struct iovec in user space */

			/*
			 * Structures user_msghdr and iovec contain pointers
			 * inside, therefore they need to be additionally
			 * converted with saving results in these structures
			 */
			struct user_msghdr *converted_msghdr;
			struct iovec *converted_iovec;

			/*
			 * Allocate space on user stack for additional
			 * structures for saving of converted parameters
			 */
			args = get_user_space((fields * 8) +
				sizeof(struct user_msghdr) +
				sizeof(struct iovec));
			/* Convert args array for socketcall from ptr */
			rval = convert_array((long *) ptr, args, size,
						fields, 1, mask_type,
						mask_align);

			if (rval) {
				DbgSCP(" Bad array for socketcall (%ld)", arg1);
				DbgSCP(" size=%d\n", size);
				return -EINVAL;
			}

			/* Convert struct msghdr from args[1] */
			converted_msghdr = (struct user_msghdr *) (args
						+ (fields * 8));
			rval = convert_array((long *) args[1],
					(long *) converted_msghdr,
					SIZE_MSGHDR, 7, 1, MASK_MSGHDR_TYPE,
					MASK_MSGHDR_ALIGN);

			if (rval) {
				DbgSCP("Bad user_msghdr in args[1]\n");
				return -EINVAL;
			}

			/* Convert struct iovec from msghdr->msg_iov */
			converted_iovec = (struct iovec *) (converted_msghdr +
						sizeof(struct user_msghdr));
			rval = convert_array((long *) converted_msghdr->msg_iov,
					(long *) converted_iovec,
					SIZE_IOVEC, 2, 1, MASK_IOVEC_TYPE,
					MASK_IOVEC_ALIGN);

			if (rval) {
				DbgSCP("Bad struct iovec in msghdr\n");
				return -EINVAL;
			}

			/* Assign args[1] to pointers to converted structures */
			args[1] = (long) converted_msghdr;
			converted_msghdr->msg_iov = converted_iovec;
		/* Other socketcalls */
		} else {
			/* Allocate space on user stack for args array */
			args = get_user_space(fields * 8);
			/* Convert args array for socketcall from ptr */
			rval = convert_array((long *) ptr, args, size,
						fields, 1, mask_type,
						mask_align);

			if (rval) {
				DbgSCP(" Bad array for socketcall (%ld)", arg1);
				DbgSCP(" size=%d\n", size);
				return -EINVAL;
			}
		}

		/*
		 * Call socketcall handler function with passing of
		 * arguments to it
		 */
		rval = sys_socketcall((int) arg1, (unsigned long *) args);
		DbgSCP("socketcall (%d) returned %ld\n", (int) arg1, rval);
		break;
	}
	case __NR_ipc: {
		long *args;
		get_ipc_mask(arg1, &mask_type, &mask_align, &fields);

		if (fields == 0) {
			DbgSCP("Bad syscall_ipc number %ld\n", arg1);
			return -EINVAL;
		}

		/*
		 * `convert_array ()' below will determine if AP.size is large
		 * enough for this request.
		 */
		GET_PTR(ptr, size, 2, 3, 0, 0);
		if (!ptr) {
			DbgSCP("NULL pointer passed to syscall_ipc (%d)",
								(int) arg1);
			return -EFAULT;
		}

		/*
		 * Syscalls semctl need an additional converting of arguments
		 * after getting the arg array
		 */
		switch (arg1) {
		case SEMCTL: {
#define MASK_SEMUN_PTR_TYPE  0x3 /* mask for union semun with pointer */
#define MASK_SEMUN_PTR_ALIGN 0x3 /* alignment mask for union semun with ptr */
#define SIZE_SEMUN_PTR       16  /* size of union semun with ptr */
#define MASK_SEMUN_INT_TYPE  0x0 /* mask for union semun with int */
#define MASK_SEMUN_INT_ALIGN 0x3 /* alignment mask for union semun with int */
#define SIZE_SEMUN_INT       16  /* size of union semun with int */

			/*
			 * Union semun (5-th parameter) contains pointers
			 * inside, therefore they need to be additionally
			 * converted with saving results in these union
			 */
			union semun *converted_semun;

			/*
			 * Allocate space on user stack for additional
			 * structures for saving of converted parameters
			 */
			args = get_user_space((fields * 8) +
					sizeof(union semun));
			/* Convert args array for syscall_ipc from ptr */
			rval = convert_array((long *) ptr, args, size,
						fields, 1, mask_type,
						mask_align);
			if (rval) {
				DbgSCP(" Bad args array for syscall_ipc ");
				DbgSCP("(%ld), size=%d\n", arg1, size);
				return -EINVAL;
			}

			/* Convert union semun from args[3] */
			converted_semun = (union semun *) (args + (fields * 8));

			/* Fields of union semun depend on cmd parameter */
			switch (args[2]) {
			/* Pointer in union semun required */
			case IPC_STAT:
			case IPC_SET:
			case IPC_INFO:
			case GETALL:
			case SETALL:
				if (!args[3])
					return -EINVAL;
				rval = convert_array((long *) args[3],
					(long *) converted_semun,
					SIZE_SEMUN_PTR, 1, 1,
					MASK_SEMUN_PTR_TYPE,
					MASK_SEMUN_PTR_ALIGN);
				if (rval) {
					DbgSCP(" Bad semun parameter");
					DbgSCP(" for semctl\n");
					return -EINVAL;
				}
				/*
				 * Assign args[3] to pointer to
				 * converted union
				 */
				args[3] = (long) converted_semun;
				break;
			/* Int value in union semun required */
			case SETVAL:
				rval = convert_array((long *) args[3],
					(long *) converted_semun,
					SIZE_SEMUN_INT, 1, 1,
					MASK_SEMUN_INT_TYPE,
					MASK_SEMUN_INT_ALIGN);
				if (rval) {
					DbgSCP(" Bad semun parameter");
					DbgSCP(" for semctl\n");
					return -EINVAL;
				}
				/*
				 * Assign args[3] to pointer to
				 * converted union
				 */
				args[3] = (long) converted_semun;
				break;
			/* No union semun as argument */
			default:
				break;
			}
			break;
		}
		case MSGRCV: {
#define MASK_MSG_BUF_PTR_TYPE   0x7 /* type mask for struct msg_buf */
#define MASK_MSG_BUF_PTR_ALIGN  0x7 /* alignment mask for struct msg_buf */
#define SIZE_MSG_BUF_PTR        32  /* size of struct msg_buf with pointer */
			/*
			 * Struct new_msg_buf (ipc_kludge) contains pointer
			 * inside, therefore it needs to be additionally
			 * converted with saving results in these struct
			 */
			struct ipc_kludge *converted_new_msg_buf;

			/*
			 * Allocate space on user stack for additional
			 * structures for saving of converted parameters
			 */
			args = get_user_space((fields * 8) +
						sizeof(struct ipc_kludge));
			/* Convert args array for syscall_ipc from ptr */
			rval = convert_array((long *) ptr, args, size,
						fields, 1, mask_type,
						mask_align);
			if (rval) {
				DbgSCP(" Bad args array for syscall_ipc ");
				DbgSCP("(%ld), size=%d\n", arg1, size);
				return -EINVAL;
			}

			/* Convert struct new_msg_buf from args[3] */
			converted_new_msg_buf = (struct ipc_kludge *)
							(args + (fields * 8));

			rval = convert_array((long *) args[3],
					(long *) converted_new_msg_buf,
					SIZE_MSG_BUF_PTR, 2, 1,
					MASK_MSG_BUF_PTR_TYPE,
					MASK_MSG_BUF_PTR_ALIGN);
			if (rval) {
				DbgSCP(" Bad msg_buf parameter");
				DbgSCP(" for msgrcv\n");
				return -EINVAL;
			}

			/*
			 * Assign args[3] to pointer to converted new_msg_buf
			 */
			args[3] = (long) converted_new_msg_buf;
			break;
		}
		/* No additional converting of parameters for other syscalls */
		default:
			/* Allocate space on user stack for args array */
			args = get_user_space(fields * 8);
			/* Convert args array for syscall_ipc from ptr */
			rval = convert_array((long *) ptr, args, size,
						fields, 1, mask_type,
						mask_align);
			if (rval) {
				DbgSCP(" Bad args array for syscall_ipc ");
				DbgSCP("(%ld) size=%d\n", arg1, size);
				return -EINVAL;
			}
			break;
		}

		/*
		 * Call syscall_ipc handler function with passing of
		 * arguments to it
		 */

		DbgSCP("ipc(): call:%d first:%d second:%d third:%ld\n"
				"ptr:%px fifth:0x%px\n", (u32) arg1,
				(int) args[0], (int) args[1], args[2],
				(void *) args[3], (void *) args[4]);
		rval = sys_ipc((u32) arg1, (int) args[0], (u64) args[1],
				(u64) args[2], (void *) args[3],
				(u64) args[4]);
		DbgSCP("syscall_ipc (%d) returned %ld\n", (int) arg1, rval);
		break;
	}
	case __NR_readv:
	case __NR_writev:
	case __NR_preadv:
	case __NR_pwritev:
	case __NR_preadv2:
	case __NR_pwritev2: {
		/*
		 * sys_readv(unsigned long fd, const struct iovec __user *vec,
		 *		unsigned long nr_segs)
		 * struct iovec {
		 *	 void __user *iov_base;
		 *	 __kernel_size_t iov_len;
		 * };
		 */
		const int nr_segs = (int) arg4;
		long *new_arg;

		if (((unsigned int) nr_segs) > UIO_MAXIOV) {
			DbgSCP("Bad nr_segs(%d)\n", nr_segs);
			return -EINVAL;
		}

		/* One could use 0 in place `32 * nr_segs' here as the size
		 * will be checked below in `convert_array ()'.  */
		GET_PTR(ptr, size, 2, 3, 32 * nr_segs, 0);
		if (!size)
			return -EINVAL;

		new_arg = get_user_space(nr_segs * 2 * 8);
		rval = convert_array((long *) ptr, new_arg, size,
							2, nr_segs, 0x7, 0xf);
		if (rval) {
			DbgSCP(" Bad array for sys_sysctl\n");
			return rval;
		}
		if (sys_num == __NR_readv || sys_num == __NR_writev) {
			rval = (*sys_protcall_table[sys_num])(arg1,
					(long) new_arg, nr_segs, 0, 0, 0);
		} else if (sys_num == __NR_preadv || sys_num == __NR_pwritev) {
			rval = (*sys_protcall_table[sys_num])(arg1,
				(unsigned long) new_arg, nr_segs, arg5,
				arg6, 0);
		} else {
			/* sys_num == __NR_preadv2 || sys_num==__NR_pwritev2*/
			rval = (*sys_protcall_table[sys_num])(arg1,
						(unsigned long) new_arg,
						nr_segs, arg5, arg6, arg7);
		}
		DbgSCP(" rval = %ld new_arg=%px\n", rval, new_arg);
		break;
	}
	case __NR_select:
	case __NR__newselect: {
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
	case __NR_pselect6: {
		fd_set *fds[3] = {NULL, NULL, NULL};
		unsigned long ptr3;
		long *buf;

		GET_PTR(ptr, size, 2, 3, 3 * sizeof(e2k_ptr_t), 0);
		if (!size)
			return -EINVAL;

		GET_PTR(ptr2, size, 4, 5, sizeof(struct __kernel_timespec), 1);
		if (!size)
			return -EINVAL;

		GET_PTR(ptr3, size, 6, 7, 2 * 16, 0);
		if (!size)
			return -EINVAL;

		buf = get_user_space(2 * 8);
		/* Extract a pointer to `sigset_t' and its length into `buf[]'.
		   0x1 mask matches one pointer and one long field.  */
		rval = convert_array((long *) ptr3, buf, 2 * 16, 2, 1,
					0x7, 0x7);
		if (rval) {
			DbgSCP("Bad 4th argument for pselect6\n");
			return rval;
		}

		rval = check_select_fs((e2k_ptr_t *) ptr, fds);
		if (rval)
			return -EINVAL;

		rval = sys_pselect6((int) arg1, fds[0], fds[1], fds[2],
				    (struct __kernel_timespec *) ptr2,  buf);
		break;
	}
	case __NR_execve: {
		long filename;
		long *buf;
		long *argv;
		long *envp;
		unsigned int size2;
		int argc, envc = 0;

		/* Path to executable */
		GET_PTR(filename, size, 2, 3, 0, 0);
		if (!size)
			return -EINVAL;

		/* argv */
		GET_PTR(ptr, size, 4, 5, 0, 0);
		if (!size)
			return -EINVAL;

		/* envp */
		GET_PTR(ptr2, size2, 6, 7, 0, 1);
		/*
		 * Note in the release 5.00 of the Linux man-pages:
		 *	The use of a third argument to the main function
		 *	is not specified in POSIX.1; according to POSIX.1,
		 *	the environment should be accessed via the external
		 *	variable environ(7).
		 */

		/* Count real number of entries in argv */
		argc = count_descriptors((long *) ptr, size);
		if (argc < 0)
			return -EINVAL;

		/* Count real number of entries in envc */
		if (size2) {
			envc = count_descriptors((long *) ptr2, size2);
			if (envc < 0)
				return -EINVAL;
		}

		/*
		 * Allocate space on user stack for converting of
		 * descriptors in argv and envp to ints
		 */
		buf = get_user_space((argc + envc + 2) << 3);
		argv = buf;
		envp = &buf[argc + 1];

		/*
		 * Convert descriptors in argv to ints.
		 * For statically-linked executables missing argv is allowed,
		 * therefore kernel doesn't return error in this case.
		 * For dynamically-linked executables missing argv is not
		 * allowed, because at least argv[0] is required by ldso for
		 * loading of executable. Protected ldso must check argv.
		 */
		if (argc) {
			rval = convert_array((long *) ptr, argv,
					argc << 4, 1, argc, 0x3, 0x3);
			if (rval) {
				DbgSCP(" Bad argv array for execve\n");
				return rval;
			}
		}
		/* The array argv must be terminated by zero */
		argv[argc] = 0;

		/*
		 * Convert descriptors in envp to ints
		 * envc can be zero without problems
		 */
		if (envc) {
			rval = convert_array((long *) ptr2, envp,
					envc << 4, 1, envc, 0x3, 0x3);
			if (rval) {
				DbgSCP(" Bad envp array for execve\n");
				return rval;
			}
		}
		/* The array envp must be terminated by zero */
		envp[envc] = 0;

		rval = e2k_sys_execve((char *) filename, (char **) argv,
				      (char **) envp);

		DbgSCP(" rval = %ld filename=%s argv=%px envp=%px\n",
		       rval, (char *) filename, argv, envp);
		break;
	}
	default:
		WARN_ON(1);
	}

	DbgSCP("do_protected_syscall(%ld): rval = %ld\n", sys_num, rval);
	return rval;
}

/*
 * Count the number of descriptors in array, which is terminated by NULL
 * (For counting of elements in argv and envp arrays)
 */
notrace __section(".entry.text")
static int count_descriptors(long __user *prot_array, const int prot_array_size)
{
	int i;
	long tmp[2];

	if (prot_array == NULL)
		return 0;

	/* Ensure that protected array is aligned and sized properly */
	if (!IS_ALIGNED((u64) prot_array, 16))
		return -EINVAL;

	/* Read each entry */
	for (i = 0; 8 * i + 16 <= prot_array_size; i += 2) {
		long hi, lo;
		int htag, ltag;

		if (copy_from_user_with_tags(tmp, &prot_array[i], 16))
			return -EFAULT;

		NATIVE_LOAD_VAL_AND_TAGD(tmp, lo, ltag);
		NATIVE_LOAD_VAL_AND_TAGD(&tmp[1], hi, htag);

		/* If zero is met, it is the end of array*/
		if (lo == 0 && hi == 0 && ltag == 0 && htag == 0)
			return i >> 1;
	}

	return -EINVAL;
}

#endif /* CONFIG_PROTECTED_MODE */

#ifdef CONFIG_KERNEL_TIMES_ACCOUNT
static inline void syscall_enter_kernel_times_account(struct pt_regs *regs)
{
	e2k_clock_t		clock = NATIVE_READ_CLKR_REG_VALUE();
	scall_times_t		*scall_times;
	int			count;

	scall_times = &(current_thread_info()->times[current_thread_info()->
						times_index].of.syscall);
	current_thread_info()->times[current_thread_info()->
					times_index].type = SYSTEM_CALL_TT;
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
	scall_times_t		*scall_times;

	scall_times = &(current_thread_info()->times[current_thread_info()->
						times_index].of.syscall);
	E2K_SAVE_CLOCK_REG(scall_times->restore_thread_state);
	E2K_SAVE_CLOCK_REG(scall_times->scall_done);
	E2K_SAVE_CLOCK_REG(scall_times->check_pt_regs);
}
#else
static inline void syscall_enter_kernel_times_account(struct pt_regs *regs) { }
static inline void syscall_exit_kernel_times_account(struct pt_regs *regs) { }
#endif

__section(".entry.text")
SYS_RET_TYPE notrace handle_sys_call(system_call_func sys_call,
			long arg1, long arg2, long arg3, long arg4,
			long arg5, long arg6, struct pt_regs *regs)
{
	unsigned long ti_flags = current_thread_info()->flags;
	long rval;
	bool ts_host_at_vcpu_mode = ts_host_at_vcpu_mode();

	check_cli();
	info_save_stack_reg(NATIVE_READ_CLKR_REG_VALUE());
	syscall_enter_kernel_times_account(regs);

	SAVE_STACK_REGS(regs, current_thread_info(), true, false);
	init_pt_regs_for_syscall(regs);
	/* Make sure current_pt_regs() works properly by initializing
	 * pt_regs pointer before enabling any interrupts. */
	current_thread_info()->pt_regs = regs;
	WRITE_PSR_IRQ_BARRIER(AW(E2K_KERNEL_PSR_ENABLED));

	SAVE_SYSCALL_ARGS(regs, arg1, arg2, arg3, arg4, arg5, arg6);

	if (guest_syscall_enter(regs, ts_host_at_vcpu_mode)) {
		/* the system call is from guest and syscall is injecting */
		current_thread_info()->pt_regs = NULL;
		guest_syscall_inject(current_thread_info(), regs);
		return (SYS_RET_TYPE)0;
	}

	Dbg1SC(regs->sys_num, "_NR_ %d current %px pid %d name %s\n"
		"handle_sys_call: k_usd: base 0x%llx, size 0x%x, sbr 0x%llx\n"
		"arg1 %lld arg2 0x%llx arg3 0x%llx arg4 0x%llx arg5 0x%llx arg6 0x%llx\n",
		regs->sys_num, current, current->pid, current->comm,
		current_thread_info()->k_usd_lo.USD_lo_base,
		current_thread_info()->k_usd_hi.USD_hi_size,
		current->stack, (u64) arg1, (u64) arg2, (u64) arg3, (u64) arg4,
		(u64) arg5, (u64) arg6);

	if (likely(!(ti_flags & _TIF_WORK_SYSCALL_TRACE))) {
		/* Fast path */
		rval = sys_call((unsigned long) arg1, (unsigned long) arg2,
				(unsigned long) arg3, (unsigned long) arg4,
				(unsigned long) arg5, (unsigned long) arg6);
		SAVE_SYSCALL_RVAL(regs, rval);
	} else {
		/* Trace syscall enter */
		rval = syscall_trace_entry(regs);
		/* Update args, since tracer could have changed them */
		RESTORE_SYSCALL_ARGS(regs, regs->sys_num,
				     arg1, arg2, arg3, arg4, arg5, arg6);

		if (rval != -1)
			rval = sys_call((unsigned long) arg1, (unsigned long) arg2,
					(unsigned long) arg3, (unsigned long) arg4,
					(unsigned long) arg5, (unsigned long) arg6);
		else
			rval = -EPERM;

		SAVE_SYSCALL_RVAL(regs, rval);

		/* Trace syscall exit */
		syscall_trace_leave(regs);
		/* Update rval, since tracer could have changed it */
		RESTORE_SYSCALL_RVAL(regs, rval);
	}

	add_info_syscall(regs->sys_num, clock);
	syscall_exit_kernel_times_account(regs);

	DbgSC("generic_sys_calls:_NR_ %d finish k_stk bottom %lx rval %ld "
		"pid %d nam %s\n",
		regs->sys_num, current->stack, rval, current->pid, current->comm);

	finish_syscall(regs, FROM_SYSCALL_N_PROT, true);
}

__section(".entry.text")
int copy_context_from_signal_stack(struct local_gregs *l_gregs,
		struct pt_regs *regs, struct trap_pt_regs *trap, u64 *sbbp,
		e2k_aau_t *aau_context, struct k_sigaction *ka)
{
	struct signal_stack_context __user *context;
	unsigned long ts_flag;
	int ret;

	context = pop_signal_stack();

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);

	ret = __copy_from_user_with_tags(regs, &context->regs, sizeof(*regs));

	if (regs->trap) {
		ret = ret ?: __copy_from_user_with_tags(trap, &context->trap,
							sizeof(*trap));
		regs->trap = trap;

		if (trap->sbbp) {
			ret = ret ?: __copy_from_user(sbbp, &context->sbbp,
					sizeof(sbbp[0]) * SBBP_ENTRIES_NUM);
			trap->sbbp = sbbp;
		}
	}

	if (regs->aau_context) {
		ret = ret ?: __copy_from_user(aau_context, &context->aau_regs,
					      sizeof(*aau_context));
		regs->aau_context = aau_context;
	}

	if (ka) {
		ret = ret ?: __copy_from_user(ka, &context->sigact,
						sizeof(*ka));
	}

	if (!TASK_IS_BINCO(current)) {
		ret = ret ?: __copy_from_user(l_gregs, &context->l_gregs,
				sizeof(*l_gregs));
	}

	clear_ts_flag(ts_flag);

	return ret ? -EFAULT : 0;
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

	if (current->flags & PF_KTHREAD)
		return 0;

	/*
	 * Restore proper psize for protected mode
	 * TODO Remove this together with TS_FORK and test with longjmp_tc
	 */
	if (TASK_IS_PROTECTED(current)) {
		e2k_wd_t wd;
		unsigned long flags;

		raw_all_irq_save(flags);
		wd = READ_WD_REG();
		wd.psize = regs->wd.psize;
		WRITE_WD_REG(wd);
		raw_all_irq_restore(flags);
	}

	if (TASK_IS_PROTECTED(current)) {
		if (regs->flags.protected_entry10)
			from |= FROM_SYSCALL_PROT_10;
		else
			from |= FROM_SYSCALL_PROT_8;
	} else {
		from |= FROM_SYSCALL_N_PROT;
	}

	ret = ret_from_fork_prepare_hv_stacks(regs);
	if (ret) {
		do_exit(SIGKILL);
	}

	finish_syscall(regs, from, true);
}


__section(".entry.text")
notrace void makecontext_trampoline_switched(void)
{
	long ret = 0;
	struct hw_context *ctx;
	void __user *uc_link = NULL;
	struct pt_regs regs;

	init_pt_regs_for_syscall(&regs);
	regs.sys_num = -1;
	regs.sys_rval = -ENOSYS;
	SAVE_STACK_REGS(&regs, current_thread_info(), true, false);
	current_thread_info()->pt_regs = &regs;
	raw_all_irq_enable();

	/*
	 * Call switch_hw_contexts if needed
	 */
	ctx = current_thread_info()->this_hw_context;
	if (!ctx) {
		DebugCTX("Could not find current context\n");
		do_exit(SIGKILL);
	}

	/*
	 * Read uc_link from user
	 */
	if (ctx->ptr_format == CTX_32_BIT) {
		u32 ucontext_32;

		if (get_user(ucontext_32, (u32 *) ctx->p_uc_link)) {
			ret = -EFAULT;
			goto exit;
		}
		uc_link = (struct ucontext_32 *) (u64) ucontext_32;
	} else if (ctx->ptr_format == CTX_64_BIT) {
		u64 ucontext_64;

		if (get_user(ucontext_64, (u64 *) ctx->p_uc_link)) {
			ret = -EFAULT;
			goto exit;
		}
		uc_link = (struct ucontext *) ucontext_64;
	} else {
		/* CTX_128_BIT */
		e2k_ptr_t ptr;
		u64 lo_val, hi_val;
		u8 lo_tag, hi_tag;
		u8 tag;
		u32 size;

		TRY_USR_PFAULT {
			NATIVE_LOAD_TAGGED_QWORD_AND_TAGS(ctx->p_uc_link,
					lo_val, hi_val, lo_tag, hi_tag);
		} CATCH_USR_PFAULT {
			ret = -EFAULT;
			goto exit;
		} END_USR_PFAULT
		AW(ptr).lo = lo_val;
		AW(ptr).hi = hi_val;
		size = AS(ptr).size - AS(ptr).curptr;
		tag = (hi_tag << 4) | lo_tag;

		/*
		 * Check that the pointer is good.
		 * We must be able to access uc_mcontext.sbr field.
		 */
		if (!size)
			/* NULL pointer, just return */
			goto exit;
		if (tag != ETAGAPQ || size <
				offsetof(struct ucontext_prot,
						uc_mcontext.usd_lo)) {
			ret = -EFAULT;
			goto exit;
		}

		uc_link = (struct ucontext_prot *) E2K_PTR_PTR(ptr, GET_SBR_HI());
	}

	DebugCTX("ctx %lx, uc_link=%lx\n", ctx, uc_link);

	if (uc_link) {
		/*
		 * Call this before swapcontext() to make sure
		 * that u_pcshtp != 0 for user_hw_stacks_copy_full()
		 */
		/* this case has not yet been accounted for */
		BUG_ON(guest_syscall_from_user(current_thread_info()));
		host_user_hw_stacks_prepare(&regs.stacks, &regs,
				MAKECONTEXT_SIZE, FROM_MAKECONTEXT, false);

		/*
		 * Note that this will drop reference from
		 * current_thread_info()->this_hw_context,
		 * but the reference from makecontext() still
		 * holds (until user calls freecontext()).
		 */
		ret = swapcontext(uc_link, ctx->ptr_format);
		if (!ret) {
			enum restore_caller from = FROM_MAKECONTEXT;

			if (TASK_IS_PROTECTED(current))
				from |= FROM_SYSCALL_PROT_8;
			else
				from |= FROM_SYSCALL_N_PROT;

			regs.sys_rval = 0;
			regs.return_desk = 0;
			finish_syscall(&regs, from, true);
		}

		DebugCTX("swapcontext failed with %ld\n", ret);
	}

exit:
	if (test_thread_flag(TIF_NOHZ))
		user_exit();

	/* Convert to user codes */
	ret = -ret;

	DebugCTX("calling do_exit with %ld\n", ret);
	do_exit((ret & 0xff) << 8);
}


__section(".entry.text")
notrace long do_sigreturn(void)
{
	struct thread_info *ti = current_thread_info();
	struct pt_regs regs;
	struct trap_pt_regs saved_trap, *trap;
	u64 sbbp[SBBP_ENTRIES_NUM];
	struct k_sigaction ka;
	e2k_aau_t aau_context;
	struct local_gregs l_gregs;
	e2k_stacks_t cur_stacks;
	e2k_usd_lo_t usd_lo;
	e2k_usd_hi_t usd_hi;
	rt_sigframe_t __user *frame;

	COPY_U_HW_STACKS_FROM_TI(&cur_stacks, ti);
	raw_all_irq_enable();

#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	E2K_SAVE_CLOCK_REG(clock);
	{
		register int count;

		GET_DECR_KERNEL_TIMES_COUNT(ti, count);
		scall_times = &(ti->times[count].of.syscall);
		scall_times->do_signal_done = clock;
	}
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */

	/* Always make any pending restarted system call return -EINTR.
	 * Otherwise we might restart the wrong system call. */
	current->restart_block.fn = do_no_restart_syscall;

	if (copy_context_from_signal_stack(&l_gregs, &regs, &saved_trap,
					   sbbp, &aau_context, &ka)) {
		user_exit();
		do_exit(SIGKILL);
	}

	/* Preserve current p[c]shtp as they indicate */
	/* how much to FILL when returning */
	preserve_user_hw_stacks_to_copy(&regs.stacks, &cur_stacks);

	/* Restore proper psize as it was when signal was delivered */
	if (regs.wd.WD_psize) {
		restore_wd_register_psize(regs.wd);
	}

	if (from_trap(&regs))
		regs.trap->prev_state = exception_enter();
	else
		user_exit();

	regs.next = NULL;
	/* Make sure 'pt_regs' are ready before enqueuing them */
	barrier();
	ti->pt_regs = &regs;

	frame = (rt_sigframe_t *) current_thread_info()->u_stack.top;

	usd_lo = regs.stacks.usd_lo;
	usd_hi = regs.stacks.usd_hi;
	STORE_USER_REGS_TO_THREAD_INFO(ti, AS(usd_lo).base - AS(usd_hi).size,
			regs.stacks.top,
			regs.stacks.top - AS(usd_lo).base + AS(usd_hi).size);

	if (restore_rt_frame(frame, &ka)) {
		printk("%s%s[%d] bad frame:%px\n",
		       task_pid_nr(current) > 1 ? KERN_INFO : KERN_EMERG,
		       current->comm, current->pid, frame);

		force_sig(SIGSEGV);
	}

	trap = regs.trap;
	if (trap && (3 * trap->curr_cnt) < trap->tc_count &&
			trap->tc_count > 0) {
		trap->from_sigreturn = 1;
		do_trap_cellar(&regs, 0);
	}

	clear_restore_sigmask();

	if (!TASK_IS_BINCO(current))
		restore_local_glob_regs(&l_gregs, true);

	if (!from_syscall(&regs)) {
		BUG_ON(!regs.trap || !regs.aau_context || regs.kernel_entry);

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
		/* fallthrough */
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
		case 10:
			from |= FROM_SYSCALL_PROT_10;
			break;
		default:
			BUG();
		}

		finish_syscall(&regs, from, !restart_needed);
	}
}

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
notrace long return_pv_vcpu_syscall_fork(void)
{
	pv_vcpu_return_from_fork();
	return 0;
}
