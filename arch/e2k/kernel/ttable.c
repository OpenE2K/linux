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
#include <asm/kvm/runstate.h>
#include <asm/kvm/switch.h>
#include <asm/fast_syscalls.h>

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
#endif


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
static __always_inline __interrupt notrace void dump_debug_info_no_stack(void)
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

	NATIVE_FLUSHC;

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
	if (!base)
		panic("Stack overflow, could not switch to reserve stack (stack dump can be corrupted)\n");

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

	/* Must spill the reserved frame before any calls */
	NATIVE_FLUSHC;
}

/* noinline is needed to make sure we use the reserved data stack */
notrace noinline __cold __noreturn
static void kernel_hw_stack_fatal_error(struct pt_regs *regs,
		u64 exceptions, u64 kstack_pf_addr)
{
	NATIVE_WRITE_PSR_IRQ_BARRIER(AW(E2K_KERNEL_PSR_ENABLED));
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

	pr_info("Using software emulation of FILLC instruction, CF FILL depth: %d quadro registers\n",
			cf_max_fill_return / 16);

	return 0;
}
pure_initcall(init_cf_fill_depth);

void e2k_notify_resume(void)
{
#ifdef ARCH_RT_DELAYS_SIGNAL_SEND
	if (unlikely(current->forced_info.si_signo)) {
		force_sig_info(&current->forced_info);
		current->forced_info.si_signo = 0;
	}
#endif
}

/*
 * Do work marked by TIF_NOTIFY_RESUME
 */
void do_notify_resume(struct pt_regs *regs)
{
	e2k_notify_resume();
	tracehook_notify_resume(regs);
	rseq_handle_notify_resume(NULL, regs);
}

/*
 * Trap occurred on user or kernel function but on user's stacks
 * So, it needs to switch to kernel stacks
 */
void notrace __irq_entry
user_trap_handler(struct pt_regs *regs)
{
#if defined(CONFIG_KVM_HOST_MODE)
	struct thread_info *thread_info = current_thread_info();
#endif
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
	 * Do this before saving %sbbp as it uses 'alc' and thus zeroes %aaldm.
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
	if (unlikely(aasr.iab))
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
		if (rpr_lo && cr0_hi >= current_thread_info()->rp_start &&
				cr0_hi < current_thread_info()->rp_end)
			trap->rp = 1;
	} else {
		trap->mlt_state.num = 0;
	}
#endif

	BUILD_BUG_ON(sizeof(enum ctx_state) != sizeof(trap->prev_state));
	trap->prev_state = exception_enter();

	CHECK_PT_REGS_LOOP(current_thread_info()->pt_regs);
	CHECK_PT_REGS_CHAIN(regs,
		NATIVE_NV_READ_USD_LO_REG().USD_lo_base,
		current->stack + KERNEL_C_STACK_SIZE);

#ifdef CONFIG_USE_AAU
	if (aau_working(aasr))
		machine.get_aau_context(aau_regs, aasr);
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

	/* Update run state info, if trap occured on guest kernel */
	SET_RUNSTATE_IN_USER_TRAP();

	/*
	 * This will enable interrupts
	 */
	parse_TIR_registers(regs, exceptions);

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
 * We can only get here if either FILLC or FILLR isn't supported.
 * Otherwise finish_user_trap_handler_switched_stacks is called directly.
 */
void notrace __noreturn
finish_user_trap_handler_sw_fill(void)
{
	struct pt_regs *regs;
	struct trap_pt_regs *trap;
	restore_caller_t from;

	user_hw_stacks_restore__sw_sequel();

	from = current->thread.fill.from;

	regs = current_thread_info()->pt_regs;
	trap = regs->trap;

	finish_user_trap_handler_switched_stacks(regs, trap, from);

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
	e2k_usd_lo_t usd_lo = regs->stacks.usd_lo;
	e2k_psp_hi_t psp_hi;
	e2k_pcsp_hi_t pcsp_hi;
#if defined(CONFIG_KERNEL_TIMES_ACCOUNT) || defined(CONFIG_E2K_PROFILING)
	register e2k_clock_t	clock = NATIVE_READ_CLKR_REG_VALUE();
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */
	e2k_cr0_hi_t cr0_hi;
	e2k_cr1_lo_t cr1_lo;
	e2k_cr1_hi_t cr1_hi;
#ifdef CONFIG_USE_AAU
	e2k_aalda_t *aaldas;
	e2k_aau_t *aau_regs;
	e2k_aasr_t aasr;
#endif
#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	register trap_times_t	*trap_times;
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */
	e2k_upsr_t		upsr;
	u64 exceptions, nmi, hw_overflow, kstack_pf_addr;
	int save_sbbp = current->ptrace || debug_trap;
#if	defined(CONFIG_VIRTUALIZATION) && !defined(CONFIG_KVM_GUEST_KERNEL)
	int			to_save_runstate;
#endif	/* CONFIG_VIRTUALIZATION && ! CONFIG_KVM_GUEST_KERNEL */
	int hrdirqs_enabled = lockdep_hardirqs_enabled();
#ifdef CONFIG_DEBUG_PT_REGS
	e2k_usd_lo_t usd_lo_prev;
#endif
#ifdef CONFIG_CLI_CHECK_TIME
	register long start_tick = NATIVE_READ_CLKR_REG_VALUE();
#endif

	trap = pt_regs_to_trap_regs(regs);
	trap->flags = 0;
	regs->trap = trap;

#ifdef CONFIG_DEBUG_PT_REGS
	usd_lo_prev = NATIVE_NV_READ_USD_LO_REG();
#endif

#ifdef CONFIG_USE_AAU
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
	init_guest_traps_handling(regs, false	/* user mode trap */);

#ifdef CONFIG_USE_AAU
	/*
	 * Put some distance between reading AASR (above) and using it here
	 * since reading of AAU registers is slow.
	 *
	 * Do this before saving %sbbp as it uses 'alc' and thus zeroes %aaldm.
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
#endif

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

#ifdef CONFIG_USE_AAU
	/* It's important to save AAD before all call operations. */
	if (unlikely(aasr.iab))
		NATIVE_SAVE_AADS(aau_regs);

	/*
	 * If AAU fault happened read aalda/aaldi/aafstr here,
	 * before some call zeroes them.
	 */
	if (unlikely(trap->TIRs[0].TIR_hi.TIR_hi_aa))
		aau_regs->aafstr = native_read_aafstr_reg_value();
#endif

	/* Even function calls under _false_ predicate will trigger
	 * hardware SPILL of chain stack.  To make sure such a spill
	 * does not mess emergency stack dump, we do this check before
	 * the barrier() below that marks allowed function calls. */
	if (unlikely(hw_overflow || kstack_pf_addr)) {
		switch_to_reserve_stacks();
		kernel_hw_stack_fatal_error(regs, exceptions, kstack_pf_addr);
	}

	/*
	 * Function calls are allowed from this point on,
	 * mark it with a compiler barrier.
	 */
	barrier();

#ifdef CONFIG_USE_AAU
	/* Since iset v6 %aaldi must be saved too */
	if (machine.native_iset_ver >= E2K_ISET_V6 &&
	    unlikely(AAU_STOPPED(aasr)))
		NATIVE_SAVE_AALDIS(aau_regs->aaldi);
#endif

	/* No atomic/DAM operations are allowed before this point.
	 * Note that we cannot do this before saving AAU. */
	if (cpu_has(CPU_HWBUG_L1I_STOPS_WORKING))
		E2K_DISP_CTPRS();

	psp_hi = regs->stacks.psp_hi;
	pcsp_hi = regs->stacks.pcsp_hi;

	/*
	 * We will switch interrupts control from PSR to UPSR
	 * _after_ we have handled all non-masksable exceptions.
	 * This is needed to ensure that a local_irq_save() call
	 * in NMI handler won't enable non-maskable exceptions.
	 */
	SAVE_INIT_KERNEL_IRQ_MASK_REG(false, true, upsr);

	CHECK_PT_REGS_LOOP(current_thread_info()->pt_regs);
	CHECK_PT_REGS_CHAIN(regs,
		NATIVE_NV_READ_USD_LO_REG().USD_lo_base,
		current->stack + KERNEL_C_STACK_SIZE);

#ifdef CONFIG_USE_AAU
	if (aau_working(aasr))
		machine.get_aau_context(aau_regs, aasr);
#endif

	if (is_kernel_data_stack_bounds(true /* trap on kernel */, usd_lo))
		kernel_data_stack_overflow();

#ifdef CONFIG_CLI_CHECK_TIME
	tt0_prolog_ticks(E2K_GET_DSREG(clkr) - start_tick);
#endif

	/* Update run state info, if trap occured on guest kernel */
	SET_RUNSTATE_IN_KERNEL_TRAP(to_save_runstate);

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
		raw_all_irq_restore(flags);
	}
#endif

#ifdef CONFIG_USE_AAU
	if (unlikely(AAU_STOPPED(aasr))) {
		aaldas = __builtin_alloca(AALDAS_REGS_NUM * sizeof(aaldas[0]));
		machine.calculate_aau_aaldis_aaldas(regs, aaldas, aau_regs);
	} else {
		aaldas = NULL;
	}
#endif

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

#ifdef CONFIG_USE_AAU
	NATIVE_CLEAR_APB();
#endif

	cr0_hi = regs->crs.cr0_hi;
	cr1_lo = regs->crs.cr1_lo;
	cr1_hi = regs->crs.cr1_hi;

	/*
	 * Hardware can lose singlestep flag on interrupt if it
	 * arrives earlier, so we must always manually reset it.
	 */
	if (cpu_has(CPU_HWBUG_SS) && test_ts_flag(TS_SINGLESTEP_KERNEL))
		AS(cr1_lo).ss = 1;

	/* Update run state info, if trap occured on guest kernel */
	SET_RUNSTATE_OUT_KERNEL_TRAP(to_save_runstate);

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

	/* MMU registers must be written with not active CLW/AAU */
	uaccess_enable_in_kernel_trap(regs);

	WRITE_CR0_HI_REG(cr0_hi);
	WRITE_CR1_LO_REG(cr1_lo);
	WRITE_CR1_HI_REG(cr1_hi);

#ifdef CONFIG_USE_AAU
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

	/*
	 * There must not be any branches after restoring ctpr register
	 * because of HW bug, so this 'if' is done before restoring %ctpr2
	 * (actually it belongs to set_aau_aaldis_aaldas()).
	 *
	 * RESTORE_COMMON_REGS() must be called before RESTORE_AAU_MASK_REGS()
	 * because of ctpr2 and AAU registers restoring dependencies.
	 */
	if (likely(!AAU_STOPPED(aasr))) {
#endif
		NATIVE_RESTORE_COMMON_REGS(regs);
#ifdef CONFIG_USE_AAU
		NATIVE_RESTORE_AAU_MASK_REGS((e2k_aaldm_t) { .word = 0 },
				(e2k_aaldv_t) { .word = 0 }, aasr);
#endif
		E2K_DONE();
#ifdef CONFIG_USE_AAU
	} else {
		NATIVE_RESTORE_COMMON_REGS(regs);
		native_set_aau_aaldis_aaldas(aaldas, aau_regs);
		NATIVE_RESTORE_AAU_MASK_REGS(aau_regs->aaldm,
				aau_regs->aaldv, aasr);
		E2K_DONE();
	}
#endif
}


/***********************************************************************/

#ifdef CONFIG_PROTECTED_MODE
#include <linux/net.h>

int handle_futex_death(u32 __user *uaddr, struct task_struct *curr,
		       bool pi, bool pending_op);

extern const system_call_func sys_protcall_table[]; /* defined in systable.c */


/*
 * Fetch a PM robust-list pointer. Bit 0 signals PI futexes:
 */
static inline int
fetch_pm_robust_entry(long __user **entry, long __user *head, unsigned int *pi)
{
	e2k_ptr_t descr;
	long addr;
	int tag;

	if (get_user_tagged_16(descr.lo, descr.hi, tag, head)) {
		pr_debug("%s failed with head == 0x%lx\n", __func__, head);
		return -EFAULT;
	}


	if ((descr.lo == 0) && (descr.hi == 0) && (tag == ETAGNPQ)) {
		/* ignoring empty descriptor: */
		addr = 0;
	} else if (tag != ETAGAPQ) {
		goto err_out;
	} else {
		/* replacing descriptor with 64-bit pointer: */
		addr = E2K_PTR_PTR(descr);
	}

	*pi = (unsigned int) addr & 1;
	if (put_user((addr & ~1), (long __user *) entry))
		goto err_out;

	return 0;

err_out:
	pr_debug("%s() failed with AP == <%x> 0x%llx : 0x%llx (head == 0x%lx)\n",
	       __func__, tag, descr.lo,  descr.hi, head);
	return -EFAULT;
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
	struct thread_info *ti = task_thread_info(curr);
	long __user *head = (long __user *)e2k_ptr_ptr(ti->pm_robust_list.lo,
					      ti->pm_robust_list.hi,
					      0);
	long __user *entry, *next_entry, *pending;
	unsigned int limit = ROBUST_LIST_LIMIT, pi, pip;
	unsigned int next_pi = 0;
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
	 * rid of this limitation when (sub)structures containing no APs are
	 * converted.
	 */
	if (get_user(futex_offset, (long __user *) &head[2])) {
		pr_err("FATAL ERROR in %s:%d :\n\t\tError in %s(0x%lx): failed to read from 0x%lx !!!\n",
		       __FILE__, __LINE__,
		       __func__, (uintptr_t) curr, (uintptr_t) &head[2]);
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
static inline
u8 get_size_arg_number(const int sys_num, const u8 argnum)
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
#define MASK_PROT_ARG_NON_EMPTY		0x10 /* Argument must not be 0/NULL */
#define MASK_PROT_ARG_OPTIONAL		0x80
/* Bits of lower syscall mask byte (mask&0xff) : */
#define ADJUST_SIZE_MASK		1
#define NEGATIVE_DESCR_SIZE_MASK	2

static inline
unsigned long e2k_dscr_ptr_size(long low, long hiw, long min_size, int *ptr_size,
				u16 sys_num, u8 argnum, u8 *fatal, u8 lower_byte_mask)
{
	/* NB> 'min_size' may be negative; this is why it has 'long' type */
	e2k_ptr_t ptr;

	ptr.lo = low;
	ptr.hi = hiw;
	*ptr_size = ptr.size - ptr.curptr;

	if (min_size < 0) {
		argnum = get_size_arg_number(sys_num, argnum);
		PROTECTED_MODE_WARNING(PMSCERRMSG_NEGATIVE_SIZE_VALUE,
				sys_num, sys_call_ID_to_name[sys_num], min_size, argnum);
		PM_EXCEPTION_ON_WARNING(SIGABRT, 0, EINVAL);
	} else if (min_size >> 31) {
			argnum = get_size_arg_number(sys_num, argnum);
			PROTECTED_MODE_ALERT(PMSCERRMSG_SC_ARGNUM_VAL_EXCEEDS_DSCR_MAX,
				sys_num, sys_call_ID_to_name[sys_num], min_size, argnum);
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, 0, EINVAL);
			*ptr_size = 0;
			*fatal = 1;
			return 0;
	} else if (unlikely(*ptr_size < 0 && lower_byte_mask && NEGATIVE_DESCR_SIZE_MASK)) {
		PROTECTED_MODE_WARNING(PMSCWARN_NEGATIVE_DSCR_SIZE,
			     sys_num, sys_call_ID_to_name[sys_num], *ptr_size, argnum);
		if (unlikely(!arch_init_pm_sc_debug_mode(PM_SC_DBG_MODE_NO_ERR_MESSAGES))
			&& arch_init_pm_sc_debug_mode(PM_SC_DBG_WARNINGS))
				protected_mode_message(0, PMSCWARN_DSCR_COMPONENTS,
						       low, (hiw >> 32), (hiw & 0xffffffff));
		PM_EXCEPTION_ON_WARNING(SIGABRT, 0, EINVAL);
		*ptr_size = 0;
		if (unlikely(arch_init_pm_sc_debug_mode(PM_SC_DBG_WARNINGS_AS_ERRORS))) {
			*fatal = 1;
			return 0;
		}
	} else if (*ptr_size < min_size) {
			PROTECTED_MODE_ALERT(PMSCERRMSG_SC_ARG_SIZE_TOO_LITTLE,
			     sys_num, sys_call_ID_to_name[sys_num], *ptr_size, min_size, argnum);
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, 0, EINVAL);
			*ptr_size = 0;
			*fatal = 1;
			return 0;
	}
	return E2K_PTR_PTR(ptr);
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
static unsigned long get_protected_ARG(u64 sys_num, u32 tag, const u64 mask, u32 a_num,
			     unsigned long protarg_lo, unsigned long protarg_hi,
			     long min_size, u8 *fatal, struct pt_regs *regs)
{
	u8 msk = (mask >> (a_num * 8)) & 0xff;
	u8 msk_type = msk & 0xf;
	unsigned long ptr; /* the result */
	int size;
	u32 tag_lo = tag & 0xf;
	u32 optional_arg = msk & MASK_PROT_ARG_OPTIONAL;
	char arg[4] = "#0";

	if (msk_type == MASK_PROT_ARG_NOARG) {
		return 0L; /* this is not effective syscall arg */
	} else if (tag == ETAGDWQ) {
		if (!optional_arg) {
			arg[1] = '0' + a_num; /* string # of the argument: "#1" .. "#6" */
			PROTECTED_MODE_WARNING(PMSCERRMSG_SC_WRONG_ARG_VALUE_LX_TAG,
				sys_call_ID_to_name[regs->sys_num], arg, protarg_lo, tag);
			if (IF_PM_DBG_MODE(PM_SC_DBG_ISSUE_WARNINGS))
				protected_mode_message(0, PMSCERRMSG_SC_ARG_MISSED_OR_UNINIT,
						       a_num);
			PM_EXCEPTION_ON_WARNING(SIGABRT, 0, EINVAL);
		}
		return 0L; /* arg was not passed or irrelevant */
	}

	if (msk_type == MASK_PROT_ARG_LONG_OR_DSCR) {
		msk_type = (tag == ETAGAPQ) ? MASK_PROT_ARG_DSCR : MASK_PROT_ARG_LONG;
	} else if (unlikely(msk_type == MASK_PROT_ARG_INT_OR_DSCR)) {
		msk_type = (tag == ETAGAPQ) ? MASK_PROT_ARG_DSCR : MASK_PROT_ARG_INT;
	} else if (unlikely(msk_type == MASK_PROT_ARG_LONG_OR_STRING
				|| msk_type == MASK_PROT_ARG_INT_OR_STRING)) {
		if (tag == ETAGAPQ)
			msk_type = MASK_PROT_ARG_STRING;
		else
			msk_type = (msk_type == MASK_PROT_ARG_LONG_OR_STRING) ?
						MASK_PROT_ARG_LONG : MASK_PROT_ARG_INT;
	}

	if (!optional_arg && !protarg_lo && msk & MASK_PROT_ARG_NON_EMPTY) {
		arg[1] = '0' + a_num; /* string # of the argument: "#1" .. "#6" */
		PROTECTED_MODE_ALERT(PMSCERRMSG_SC_ARG_VAL_UNSUPPORTED,
				     sys_call_ID_to_name[regs->sys_num], arg, 0);
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, 0, EINVAL);
		*fatal = 1;
	}

	if (((msk_type == MASK_PROT_ARG_INT)
		&& (tag != ETAGDWQ) && (tag != ETAGPLD) && (tag != ETAGPLQ))
		/* The check below does the following:
		 * - in the current ABI syscall argument takes 4 words (16 bytes);
		 * - if syscall argument is of type 'int' (not 'long'), then
		 *   only lowest word (word #0) gets filled by compiler while
		 *   other 3 words may contain trash (contents of previous call);
		 * - if tag of the lowest word is numeric one (i.e. '0'), then
		 *   this argument is definitely of type 'int' and
		 * - we can zero the word #1 to make next checks simpler.
		 */
		|| (tag_lo && !(tag_lo & 0x3))) { /* numerical tag in lower word */
		/* this is 'int' argument */
		tag_lo &= 0x3;
		tag = tag_lo;
		protarg_lo = (int) protarg_lo; /* removing trash in higher word */
	}

#if DEBUG_SYSCALLP_CHECK
	if (optional_arg && ((tag_lo == ETAGDWD) || (tag_lo == ETAGDWS))) {
		return 0L; /* optional arg was not passed or irrelevant */
	} else if ((tag != ETAGDWQ)
		&& (tag_lo != ETAGNUM)
		&& (tag != ETAGAPQ)
		&& (tag != ETAGPLD)
		&& (tag != ETAGPLQ)) {
		PROTECTED_MODE_ALERT(PMSCERRMSG_UNEXP_ARG_TAG_ID,
			sys_num, sys_call_ID_to_name[sys_num], (u8)tag, a_num);
		if (((tag == ETAGDWD)
				&& ((msk_type == MASK_PROT_ARG_LONG)
					|| (msk_type == MASK_PROT_ARG_INT)))
				|| ((tag == ETAGDWS) && (msk_type == MASK_PROT_ARG_INT)))
			protected_mode_message(0,
					PMSCERRMSG_SC_ARG_MISSED_OR_UNINIT,
					a_num);
		DbgSCP("%s: tag=0x%x tag_lo=0x%x msk=0x%x a_num=%d\n",
		       __func__, tag, tag_lo, (int)msk, a_num);
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, 0, EINVAL);
		*fatal = 1;
		return 0L; /* uninitialized or missed arg must me zeroed */
	}
#endif /* DEBUG_SYSCALLP_CHECK */

	if ((tag == ETAGPLD) || (tag == ETAGPLQ)) {
		e2k_pl_lo_t pl_lo;

		if (msk_type != MASK_PROT_ARG_FPTR) {
			PROTECTED_MODE_ALERT(PMSCERRMSG_SC_NOT_FUNC_PTR_IN_ARG,
					     sys_num, sys_call_ID_to_name[sys_num], tag, a_num);
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, 0, EINVAL);
			*fatal = 1;
		} else {
			AW(pl_lo) = protarg_lo;
			return pl_lo.target;
		}
	}

	/* First, we check if the argument is non-pointer: */
	if (tag != ETAGAPQ) {
		unsigned long ret = (tag == ETAGDWQ) ? 0 : protarg_lo;

		if (unlikely(!null_prot_ptr(tag_lo, protarg_lo) &&
				(msk_type == MASK_PROT_ARG_DSCR ||
				 msk_type == MASK_PROT_ARG_STRING))) {
			if (PM_SYSCALL_WARN_ONLY == 0)
				*fatal = 1;
			DbgSCP("%s: tag=0x%x tag_lo=0x%x msk=0x%x protarg_lo=0x%lx\n",
			       __func__, tag, tag_lo, (int)msk, protarg_lo);
			PROTECTED_MODE_ALERT(PMSCERRMSG_NOT_DESCR_IN_SC_ARG,
				sys_num, sys_call_ID_to_name[sys_num], a_num);
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, 0, EINVAL);
		}

		return ret;
	}

	/* Finally, this is descriptor; getting pointer from it: */
	ptr = e2k_dscr_ptr_size(protarg_lo, protarg_hi, min_size, &size,
				sys_num, a_num, fatal, mask & 0xff);

	/* Second, we check if the argument is string: */
	if (msk_type == MASK_PROT_ARG_STRING) {
		if (e2k_ptr_str_check((char __user *) ptr, size)) {
			if (PM_SYSCALL_WARN_ONLY == 0)
				*fatal = 1;
			PROTECTED_MODE_ALERT(PMSCERRMSG_NOT_STRING_IN_SC_ARG,
				sys_num, sys_call_ID_to_name[sys_num], a_num);
		}
	} else {
		/* Eventually, we check if this is proper pointer: */
		if (unlikely(sys_num && msk_type != MASK_PROT_ARG_DSCR)) {
			if (PM_SYSCALL_WARN_ONLY == 0)
				*fatal = 1;
			PROTECTED_MODE_ALERT(PMSCERRMSG_UNEXPECTED_DESCR_IN_SC_ARG,
				sys_num, sys_call_ID_to_name[sys_num], a_num);
		}
	}
	if (*fatal)
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, 0, EINVAL);

	return ptr;
}

static inline
int check_arg_descr_size(int sys_num, int arg_num, int neg_size,
			 struct pt_regs *regs, int adjust_bufsize,
			 long *arg3, long *arg5, long *arg7)
/* In case of negative size in syscall argument mask,
 * calculate effective argument size and update args3-7
 * If ((neg_size < 0) && adjust_bufsize) :
 *	if calculated descriptor size exceeds the defined max value,
 *	decrease corresponding argument count down to the given max size.
 */
{
	int size, descr_size, index;

	if (((regs->tags >> (arg_num * 8)) & 0xff) != ETAGAPQ)
		adjust_bufsize = 0; /* this is not descriptor */

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
	PROTECTED_MODE_ALERT(PMSCERRMSG_COUNT_EXCEEDS_DESCR_SIZE,
			     (u32)sys_num, sys_call_ID_to_name[sys_num],
			     size, descr_size, arg_num);
	if (PM_SYSCALL_WARN_ONLY && adjust_bufsize)
		protected_mode_message(0, PMSCERRMSG_SC_ARG_COUNT_TRUNCATED,
				       descr_size);
	else
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, 0, EINVAL);
	size = descr_size;

	if (PM_SYSCALL_WARN_ONLY == 0) {
		e2k_ptr_lo_t lo;
		e2k_ptr_hi_t hi;

		PROTECTED_MODE_WARNING(PMSCERRMSG_EXECUTION_TERMINATED,
				       current->pid, current->comm, EINVAL);
		lo.word = regs->args[arg_num * 2 - 1];
		hi.word = regs->args[arg_num * 2];
		force_sig_bnderr((void __user *)(lo.base + hi.curptr),
				(void __user *)lo.base,
				(void __user *)(lo.base + hi.size));
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


#if 0
#define SC_MASK_ARRAY_2PRINT 999
static inline
void print_prot_syscall_arg_masks(int sys_num)
{
	int i;

	if (!IF_PM_DBG_MODE(PM_SC_DBG_ISSUE_WARNINGS) || sys_num != SC_MASK_ARRAY_2PRINT)
		return;
	pr_info("\n\n##### prot_syscall_arg_masks[%d]: #####\n", NR_syscalls);
	for (i = 0; i <= NR_syscalls; i++) {
		if (sys_call_table_entry8[i] == (protected_system_call_func)sys_ni_syscall) {
			pr_info("NR#%d\t[%s]\t\t >>>sys_ni_syscall<<<\n",
				i, sys_call_ID_to_name[i]);
			continue;
		}
		if (prot_syscall_arg_masks[i].size1 || prot_syscall_arg_masks[i].size2 ||
		    prot_syscall_arg_masks[i].size3 || prot_syscall_arg_masks[i].size4 ||
		    prot_syscall_arg_masks[i].size5 || prot_syscall_arg_masks[i].size6)
			pr_info("NR#%d\t[%s]\t0x%llx\t [%d:%d:%d:%d:%d:%d]\n",
				i, sys_call_ID_to_name[i], prot_syscall_arg_masks[i].mask,
				prot_syscall_arg_masks[i].size1,
				prot_syscall_arg_masks[i].size2,
				prot_syscall_arg_masks[i].size3,
				prot_syscall_arg_masks[i].size4,
				prot_syscall_arg_masks[i].size5,
				prot_syscall_arg_masks[i].size6);
		else
			pr_info("NR#%d\t[%s]\t0x%llx\n",
				i, sys_call_ID_to_name[i], prot_syscall_arg_masks[i].mask);
	}
}
#else
#define print_prot_syscall_arg_masks(...)
#endif

static inline
void report_unsupported_prot_syscall(int sys_num)
{
	PROTECTED_MODE_ALERT(PMSCERRMSG_SC_NOT_AVAILABLE_IN_PM,
			     sys_num, SYSCALL_NAME(sys_num));
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
		       unsigned long arg, int mask, int tag, int arg_num, struct pt_regs *regs)
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
	u64 mask;
	int size1, size2, size3, size4;
	u16 size5, size6;
	u8 wrong_arg = 0; /* signal that an argument detected wrong */
#ifdef CONFIG_E2K_PROFILING
	register long start_tick = NATIVE_READ_CLKR_REG_VALUE();
	register long clock1;
#endif

	if (sys_num >= NR_syscalls) {
		sys_call = (protected_system_call_func) sys_ni_syscall;
		mask = size1 = size2 = 0;
	} else {
		sys_call = sys_call_table_entry8[sys_num];
		mask = prot_syscall_arg_masks[sys_num].mask;
		if (!mask)
			mask = prot_syscall_arg_masks[NR_syscalls].mask;
		size1 = prot_syscall_arg_masks[sys_num].size1;
		size2 = prot_syscall_arg_masks[sys_num].size2;
	}

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

#ifdef CONFIG_E2K_PROFILING
	read_ticks(clock1);
	info_save_stack_reg(clock1);
#endif

	/* Must be done before opening interrupts: we want kernel to
	 * always have proper pt_regs, even in kernel trap handler. */
	current_thread_info()->pt_regs = regs;
	WRITE_PSR_IRQ_BARRIER(AW(E2K_KERNEL_PSR_ENABLED));

	if (arch_init_pm_sc_debug_mode(PM_SC_DBG_MODE_DEBUG)) {
		/* Checking if there is a descriptor in args: */
		if ((((tags >> 8) & 0xff) == ETAGAPQ) || /* arg1-2 */
			(((tags >> 16) & 0xff) == ETAGAPQ)) /* arg3-4 */
			pr_info("\nsys_num = %lld: arg1 = 0x%lx, arg2 = 0x%.8x.%.8x, arg3 = 0x%lx, arg4 = 0x%.8x.%.8x\n",
				sys_num, arg1, (u32)(arg2 >> 32), (u32)arg2,
				arg3, (u32)(arg4 >> 32), (u32)arg4);
		else
			pr_info("\nsys_num = %lld: arg1 = 0x%lx, arg2 = 0x%lx, arg3 = 0x%lx, arg4 = 0x%lx\n",
				sys_num, arg1, arg2, arg3, arg4);
		if ((((tags >> 24) & 0xff) == ETAGAPQ) || /* arg5-6 */
			(((tags >> 32) & 0xff) == ETAGAPQ)) /* arg7-8 */
			pr_info("tags = 0x%llx, arg5 = 0x%lx, arg6 = 0x%.8x.%.8x, arg7 = 0x%lx, arg8 = 0x%.8x.%.8x\n",
				tags, arg5, (u32)(arg6 >> 32), (u32)arg6, arg7,
				(u32)(arg8 >> 32), (u32)arg8);
		else
			pr_info("tags = 0x%llx, arg5 = 0x%lx, arg6 = 0x%lx, arg7 = 0x%lx, arg8 = 0x%lx\n",
				tags, arg5, arg6, arg7, arg8);
		if (((tags >> 40) & 0xff) == ETAGAPQ) /* arg9-10 */
			pr_info("\targ9 = 0x%lx, arg10 = 0x%.8x.%.8x\n", arg9,
				(u32)(arg10 >> 32), (u32)arg10);
		else
			pr_info("\targ9 = 0x%lx, arg10 = 0x%lx\n", arg9, arg10);

		pr_info("_NR_ %lld/%s start: mask=0x%llx current %px pid %d\n",
			sys_num, SYSCALL_NAME(sys_num), mask, current, current->pid);
	}

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
		size3 = prot_syscall_arg_masks[sys_num].size3;
		if (size3 < 0)
			size3 = check_arg_descr_size(sys_num, 3, size3, regs,
						     mask & ADJUST_SIZE_MASK,
						     &arg3, &arg5, &arg7);
		size4 = prot_syscall_arg_masks[sys_num].size4;
		/* So far we don't have negative size in the 4th row.
		 * To be added in the future if needed:
		if (size4 < 0)
			size4 = regs->args[-size4];
		 */
		size5 = prot_syscall_arg_masks[sys_num].size5;
		/* So far we don't have negative size in the 5th row.
		 * To be added in the future if needed:
		if (size5 < 0)
			size5 = regs->args[-size5];
		 */
		if (size2 < 0)
			size2 = check_arg_descr_size(sys_num, 2, size2, regs,
						     mask & ADJUST_SIZE_MASK,
						     &arg3, &arg5, &arg7);
		size6 = prot_syscall_arg_masks[sys_num].size6;
		/* So far we don't have negative size in the 6th row.
		 * To be added in the future if needed:
		if (size6 < 0)
			size6 = regs->args[-size6];
		 */

		a1 = get_protected_ARG(sys_num, (tags >> 8) & 0xffUL, mask, 1,
			       arg1, arg2, size1, &wrong_arg, regs);
		a2 = get_protected_ARG(sys_num, (tags >> 16) & 0xffUL, mask, 2,
			       arg3, arg4, size2, &wrong_arg, regs);
		a3 = get_protected_ARG(sys_num, (tags >> 24) & 0xffUL, mask, 3,
			       arg5, arg6, size3, &wrong_arg, regs);
		a4 = get_protected_ARG(sys_num, (tags >> 32) & 0xffUL, mask, 4,
			       arg7, arg8, size4, &wrong_arg, regs);
		a5 = get_protected_ARG(sys_num, (tags >> 40) & 0xffUL, mask, 5,
			       arg9, arg10, size5, &wrong_arg, regs);
		a6 = get_protected_ARG(sys_num, (tags >> 48) & 0xffUL, mask, 6,
			       arg11, arg12, size6, &wrong_arg, regs);
	} else { /* (sys_num >= NR_syscalls) */
		a1 = 0;
		a2 = 0;
		a3 = 0;
		a4 = 0;
		a5 = 0;
		a6 = 0;
	}

#if DEBUG_1SYSCALL
	Dbg1SC(sys_num, "system call %lld (0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx)\n",
			sys_num, a1, a2, a3, a4, a5, a6);
#else
	if (arch_init_pm_sc_debug_mode(PM_SC_DBG_MODE_COMPLEX_WRAPPERS) &&
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
		DbgSCPanon("system call %lld (%s)\n", sys_num, msg);
	} else {
		DbgSCPanon("system call %lld (0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx)\n",
			   sys_num, a1, a2, a3, a4, a5, a6);
	}
#endif

	if (unlikely(sys_call == (protected_system_call_func)sys_ni_syscall)) {
		report_unsupported_prot_syscall(sys_num);
		rval = -ENOSYS;
		SAVE_SYSCALL_RVAL(regs, rval);
		goto out;
	} else if (likely(!(ti_flags & _TIF_WORK_SYSCALL_TRACE) && !wrong_arg)) {
		/* Fast path */
		rval = sys_call(a1, a2, a3, a4, a5, a6, regs);
		SAVE_SYSCALL_RVAL(regs, rval);
	} else if (likely(!wrong_arg)) {
		/* Trace syscall enter */
		syscall_trace_entry(regs);

		/* Update system call number, since tracer could have changed it */
		if (regs->kernel_entry == 8) {
			if ((unsigned) regs->sys_num < NR_syscalls) {
				sys_call = sys_call_table_entry8[regs->sys_num];
			} else {
				sys_call = (protected_system_call_func) sys_ni_syscall;
			}
		} else {
			BUG();
		}

		rval = sys_call(a1, a2, a3, a4, a5, a6, regs);
		SAVE_SYSCALL_RVAL(regs, rval);

		/* Trace syscall exit */
		syscall_trace_leave(regs);
		/* Update rval, since tracer could have changed it */
		RESTORE_SYSCALL_RVAL(regs, rval);

	} else /* (unlikely(wrong_arg)) */ {
		rval = -EFAULT;
		SAVE_SYSCALL_RVAL(regs, rval);
	}

#if DEBUG_1SYSCALL
	Dbg1SC(sys_num, "syscall %lld : rval = 0x%lx / %ld\n", sys_num, rval, rval);
#else
	DbgSCP("syscall %lld : rval = 0x%lx / %ld\n", sys_num, rval, rval);
#endif
	/* It works only under CONFIG_FTRACE flag */
	add_info_syscall(sys_num, start_tick);

	/* We may skip assigning 'args' here because
	 * it is used only in the switch above.
	 * args = (long *) ((((unsigned long) regs) + sizeof(struct pt_regs)
	 *		+ 0xfUL) & (~0xfUL));
	 */
out:
	NEW_CHECK_PT_REGS_ADDR(prev_regs, regs, usd_lo_prev);

	finish_syscall(regs, FROM_SYSCALL_PROT_8, true);
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
	bool guest_enter, ts_host_at_vcpu_mode = ts_host_at_vcpu_mode();

	check_cli();
	info_save_stack_reg(NATIVE_READ_CLKR_REG_VALUE());
	syscall_enter_kernel_times_account(regs);

	SAVE_STACK_REGS(regs, current_thread_info(), true, false);
	init_pt_regs_for_syscall(regs);
	/* Switch back to host page tables under closed interrupts
	 * (before we can be rescheduled from an interrupt). */
	guest_enter = guest_syscall_enter(regs, ts_host_at_vcpu_mode);
	/* Make sure current_pt_regs() works properly by initializing
	 * pt_regs pointer before enabling any interrupts. */
	current_thread_info()->pt_regs = regs;
	WRITE_PSR_IRQ_BARRIER(AW(E2K_KERNEL_PSR_ENABLED));

	SAVE_SYSCALL_ARGS(regs, arg1, arg2, arg3, arg4, arg5, arg6);

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
		RESTORE_SYSCALL_ARGS(regs, regs->sys_num,
				     arg1, arg2, arg3, arg4, arg5, arg6);

		/* Update system call number, since tracer could have changed it */
		if (regs->kernel_entry == 1 || regs->kernel_entry == 3) {
			if ((unsigned) regs->sys_num < NR_syscalls) {
				sys_call = (regs->kernel_entry == 3)
						? sys_call_table[regs->sys_num]
						: sys_call_table_32[regs->sys_num];
			} else {
				sys_call = (system_call_func) sys_ni_syscall;
			}
		} else {
			BUG();
		}

		if (rval != -1 && regs->sys_num != -1) {
			rval = sys_call((unsigned long) arg1, (unsigned long) arg2,
					(unsigned long) arg3, (unsigned long) arg4,
					(unsigned long) arg5, (unsigned long) arg6);
			SAVE_SYSCALL_RVAL(regs, rval);
		}

		/* Trace syscall exit */
		syscall_trace_leave(regs);
		/* Update rval, since tracer could have changed it */
		RESTORE_SYSCALL_RVAL(regs, rval);
		Dbg1SC(regs->sys_num, "\t\t_NR_ %d rval = %ld / 0x%lx\n",
		       regs->sys_num, rval, rval);
	}

	add_info_syscall(regs->sys_num, clock);
	syscall_exit_kernel_times_account(regs);

	DbgSC("generic_sys_calls:_NR_ %d finish k_stk bottom %lx rval %ld "
		"pid %d nam %s\n",
		regs->sys_num, current->stack, rval, current->pid, current->comm);

	finish_syscall(regs, FROM_SYSCALL_N_PROT, true);
}

/*
 * We can only get here if either FILLC or FILLR isn't supported.
 * Otherwise finish_syscall_switched_stacks is called directly.
 */
void notrace __noreturn
finish_syscall_sw_fill(void)
{
	struct pt_regs *regs = current_thread_info()->pt_regs;
	restore_caller_t from = current->thread.fill.from;
	bool return_to_user = current->thread.fill.return_to_user;
	bool ts_host_at_vcpu_mode = current->thread.fill.ts_host_at_vcpu_mode;

	user_hw_stacks_restore__sw_sequel();

	finish_syscall_switched_stacks(regs, from, return_to_user, ts_host_at_vcpu_mode);

	unreachable();
}

int copy_context_from_signal_stack(struct local_gregs *l_gregs,
		struct pt_regs *regs, struct trap_pt_regs *trap, u64 *sbbp,
		e2k_aau_t *aau_context, struct k_sigaction *ka)
{
	struct signal_stack_context __user *context;
	unsigned long ts_flag;
	int ret;

	context = pop_signal_stack();
	WARN_ON(context == NULL);

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);

	ret = __copy_from_priv_user_with_tags(regs, &context->regs, sizeof(*regs));

	if (likely(trap && regs->trap)) {
		ret = ret ?: __copy_from_priv_user_with_tags(trap, &context->trap,
								sizeof(*trap));
		regs->trap = trap;

		if (likely(sbbp && trap->sbbp)) {
			ret = ret ?: __copy_from_priv_user(sbbp, &context->sbbp,
					sizeof(sbbp[0]) * SBBP_ENTRIES_NUM);
			trap->sbbp = sbbp;
		}
	}

#ifdef CONFIG_USE_AAU
	if (likely(aau_context && regs->aau_context)) {
		ret = ret ?: __copy_from_priv_user(aau_context, &context->aau_regs,
						   sizeof(*aau_context));
		regs->aau_context = aau_context;
	}
#endif

	if (ka) {
		ret = ret ?: __copy_from_priv_user(ka, &context->sigact,
							sizeof(*ka));
	}

	if (likely(l_gregs && !TASK_IS_BINCO(current))) {
		ret = ret ?: __copy_from_priv_user(l_gregs, &context->l_gregs,
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
	e2k_mem_crs_t __user *u_cframe;

	BUG_ON(regs->stacks.pcshtp != SZ_OF_CR);

	k_crs = (e2k_mem_crs_t *) current_thread_info()->k_pcsp_lo.base;
	u_cframe = (void __user *) (regs->stacks.pcsp_lo.base +
				    regs->stacks.pcsp_hi.ind);

	return copy_user_to_current_hw_stack(k_crs, u_cframe - 1,
					     sizeof(*k_crs), regs, true);
}

__section(".entry.text")
notrace long do_sigreturn(void)
{
	struct pt_regs regs;
	struct pt_regs *cur_regs = current_pt_regs();
	unsigned long cur_ti_flags = current_thread_info()->flags;
	struct trap_pt_regs saved_trap, *trap;
	u64 sbbp[SBBP_ENTRIES_NUM];
	struct k_sigaction ka;
	e2k_aau_t aau_context;
	struct local_gregs l_gregs;
	e2k_usd_lo_t usd_lo;
	e2k_usd_hi_t usd_hi;
	rt_sigframe_t __user *frame;

	/* Always make any pending restarted system call return -EINTR.
	 * Otherwise we might restart the wrong system call. */
	current->restart_block.fn = do_no_restart_syscall;

	if (copy_context_from_signal_stack(&l_gregs, &regs, &saved_trap,
					   sbbp, &aau_context, &ka)) {
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

	frame = (rt_sigframe_t __user *) current_thread_info()->u_stack.top;

	usd_lo = regs.stacks.usd_lo;
	usd_hi = regs.stacks.usd_hi;
	update_u_stack_limits(AS(usd_lo).base - AS(usd_hi).size, regs.stacks.top);

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

	regs->args[1] = flags;

	return ret;
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

u64 finish_user_trap_handler_sw_fill_wsz __read_mostly = 0;
u64 finish_syscall_sw_fill_wsz __read_mostly = 0;
u64 return_to_injected_syscall_sw_fill_wsz __read_mostly = 0;

static int initialize_sw_fill_window_size(void)
{
	if (cpu_has(CPU_FEAT_FILLC) && cpu_has(CPU_FEAT_FILLR))
		return 0;

	finish_user_trap_handler_sw_fill_wsz = (u64)FINISH_USER_TRAP_HANDLER_SW_FILL_SIZE;
	finish_syscall_sw_fill_wsz = (u64)FINISH_SYSCALL_SW_FILL_SIZE;
	return_to_injected_syscall_sw_fill_wsz = (u64)RETURN_TO_INJECTED_SYSCALL_SW_FILL_SIZE;

	return 0;
}
arch_initcall(initialize_sw_fill_window_size);
