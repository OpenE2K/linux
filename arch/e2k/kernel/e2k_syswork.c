/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * This file contains various syswork to run them from user.
 */

#include <linux/compat.h>
#include <linux/delay.h>
#include <linux/ftrace.h>
#include <linux/ratelimit.h>
#include <linux/stat.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/kmsg_dump.h>
#include <linux/sem.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/syscalls.h>
#include <linux/console.h>
#include <linux/sched/mm.h>
#include <linux/sched/debug.h>
#include <linux/panic_notifier.h>
#include <linux/pci.h>

#include <asm/gregs.h>
#include <asm/e2k_syswork.h>
#include <asm/e2k_debug.h>
#include <asm/unistd.h>
#include <asm/ptrace.h>
#include <asm/regs_state.h>
#include <asm/e2k.h>
#include <asm/process.h>
#include <asm/copy-hw-stacks.h>
#include <asm/processor.h>
#include <asm/traps.h>
#include <asm/mmu_context.h>
#include <linux/uaccess.h>
#include <asm/bootinfo.h>
#include <asm/p2v/boot_init.h>
#include <asm/boot_recovery.h>
#include <asm/nmi.h>
#include <asm/cacheflush.h>
#include <asm/simul.h>
#include <asm/syscalls.h>


#define DEBUG_ACCVM		0
#define DebugACCVM(...)	DebugPrint(DEBUG_ACCVM, ##__VA_ARGS__)

#define	DEBUG_E2K_SYS_WORK	0
#define DbgESW(...)		DebugPrint(DEBUG_E2K_SYS_WORK, ##__VA_ARGS__)

#define	DEBUG_GETCONTEXT	0
#define DebugGC(...)		DebugPrint(DEBUG_GETCONTEXT, ##__VA_ARGS__)

#undef	DebugCM
#undef	DEBUG_CORE_MODE
#define	DEBUG_CORE_MODE		0
#define DebugCM(...)		DebugPrint(DEBUG_CORE_MODE, ##__VA_ARGS__)

extern int task_statm(struct mm_struct *, int *, int *, int *, int *);

int jtag_stop_var;
EXPORT_SYMBOL(jtag_stop_var);

void	*kernel_symtab;
long	kernel_symtab_size;
void	*kernel_strtab;
long	kernel_strtab_size;
#ifdef E2K_DEBUG_CPU_REGS
int zero_debug = 0; /* to panic in places where lcc not allows to use printk */
EXPORT_SYMBOL(zero_debug);
#endif

int debug_userstack = 0;
static int __init userstack_setup(char *str)
{
	debug_userstack = 1;
	return 1;
}
__setup("debug_userstack", userstack_setup);

#ifdef CONFIG_DATA_STACK_WINDOW
int debug_datastack = 0;
static int __init datastack_setup(char *str)
{
	debug_datastack = 1;
	return 1;
}
__setup("debug_datastack", datastack_setup);
#endif


#ifdef CONFIG_E2K_PROFILING
disable_interrupt_t disable_interrupt[NR_CPUS];
EXPORT_SYMBOL(disable_interrupt);
char *system_info_name[] = {
	"disabled interrupts ",
	"storing stack_register",
	"storing TIR",
	"storing all registers",
	"storing debug registers",
	"storing aau registers",
	"restoring of stack_registers",
	"restoring all registers",
	"restoring debug registers",
	"restoring aau registers",
	"cpu_idle",
	"spin_lock",
	"mutex_lock",
	"hard_irq",
	"switch",
	"soft_irq",
	"preempt_count",
};

system_info_t system_info[NR_CPUS];
EXPORT_SYMBOL(system_info);
int enable_collect_interrupt_ticks = 0;
EXPORT_SYMBOL(enable_collect_interrupt_ticks);

long TIME = 0;
long TIME1 = 0;

static void clear_interrupt_info(void)
{
	memset(&system_info[0], 0, sizeof(system_info));
	memset(&disable_interrupt[0], 0, sizeof(disable_interrupt));

	TIME = READ_CLKR_REG();
	enable_collect_interrupt_ticks = 1;
}

static void print_interrupt_info(void)
{
	int i, j;
	time_info_t *pnt;
	long freq;
	int print_ip = 0;	/* !!!! tmp */

	enable_collect_interrupt_ticks = 0;
	freq = cpu_data[0].proc_freq / 1000000;

	pr_info("\t\t  ==============PROFILE  INFO=(%ld(ticks) /%ld(mks)/) ==============\n",
		TIME1 - TIME, (TIME1 - TIME) / freq);

	for_each_possible_cpu(j) {
		pr_info("\t\t\t CPU%d\n", j);
		pnt = (time_info_t *) & system_info[j].max_disabled_interrupt;
		for (i = 0; i < sizeof(system_info_name) / sizeof(void *); i++) {
			pr_info("  %30s  max time=%10ld   average=%10ld number=%10ld\n",
				system_info_name[i], pnt->max_time / freq,
				pnt->full_time / freq /
				((pnt->number == 0) ? 1 : pnt->number),
				pnt->number);
			if (print_ip) {
				pr_info(" time=%10lx ", pnt->max_begin_time);
				pr_info("\t\t\t %pS", pnt->max_beg_ip);
				pr_info(" (%pS) ---\n", pnt->max_beg_parent_ip);
				pr_info("\t\t\t\t %pS", pnt->max_end_ip);
				pr_info("( %pS)\n", pnt->max_end_parent_ip);
			}
			pnt++;
		}
		pr_info("\n\t\t\t\t system calls\n");
		for (i = 0; i < NR_syscalls; i++) {
			if (disable_interrupt[j].syscall[i]) {
				pr_info("  %30pS ", sys_call_table[i]);
				pr_info("average=%5ld   number=%10ld \n",
					disable_interrupt[j].syscall_time[i] / freq /
					((disable_interrupt[j].syscall[i] == 0) ? 1 :
					 disable_interrupt[j].syscall[i]),
					disable_interrupt[j].syscall[i]);
			}
		}

		pr_info("\t\t\t\t interrupts\n");
		for (i = 0; i < exc_max_num; i++) {
			if (disable_interrupt[j].interrupts[i]) {
				pr_info("  %30s max time=%5ld average=%5ld   number=%10ld\n",
					exc_tbl_name[i],
					disable_interrupt[j].max_interrupts_time[i] / freq,
					disable_interrupt[j].interrupts_time[i] / freq /
					((disable_interrupt[j].interrupts[i] == 0) ? 1 :
					 disable_interrupt[j].interrupts[i]),
					disable_interrupt[j].interrupts[i]);
			}

		}
		pr_info("\n\t\t\t\t DO_IRQ\n");
		for (i = 0; i < NR_VECTORS; i++) {
			if (disable_interrupt[j].do_irq[i]) {
				pr_info("  %5d max time=%5ld average=%5ld   number=%10ld\n",
					i, disable_interrupt[j].max_do_irq_time[i] / freq,
					disable_interrupt[j].do_irq_time[i] / freq /
					((disable_interrupt[j].do_irq[i] == 0) ? 1 :
					 disable_interrupt[j].do_irq[i]),
					disable_interrupt[j].do_irq[i]);
			}
		}

	}

};

static void stop_interrupt_info(void)
{
	TIME1 = READ_CLKR_REG();
	enable_collect_interrupt_ticks = 0;

	pr_info(" start =%lx stop_interrupt_info =%lx  begin_time(max_disabled_interrupt 0) =%lx\n"
		" end_time =%lx  max_time =%lx begin_time(max_disabled_interrupt 1) =%lx\n"
		" end_time =%lx  max_time =%lx\n",
		TIME, TIME1, system_info[0].max_disabled_interrupt.begin_time,
		system_info[0].max_disabled_interrupt.begin_time
		+ system_info[0].max_disabled_interrupt.max_time,
		system_info[0].max_disabled_interrupt.max_time,
		system_info[1].max_disabled_interrupt.begin_time,
		system_info[1].max_disabled_interrupt.begin_time
		+ system_info[1].max_disabled_interrupt.max_time,
		system_info[1].max_disabled_interrupt.max_time);
};

#else /* !CONFIG_E2K_PROFILING */
static void print_interrupt_info(void) {};

static void clear_interrupt_info(void) {};

static void stop_interrupt_info(void) {};
#endif /* CONFIG_E2K_PROFILING */

/* Preallocate psp and data stack cache for the boot CPU so that
 * it can print full stacks from other CPUs as early as possible
 * (at boot time sysrq is handled by the boot CPU). */
static char psp_stack_cache[SIZE_PSP_STACK];
#ifdef CONFIG_DATA_STACK_WINDOW
static char k_data_stack_cache[SIZE_DATA_STACK];
#endif

static __initdata char chain_stack_cache[NR_CPUS][SIZE_CHAIN_STACK];


/* Initially 'chain_stack_cache' array is used but later
 * it is discarded together with .init.data and replaced
 * with kmalloc()'ed memory (see print_stack_init()). */
__refdata struct stack_regs stack_regs_cache[NR_CPUS] = {
	[0].psp_stack_cache = psp_stack_cache,
#ifdef CONFIG_DATA_STACK_WINDOW
	[0].k_data_stack_cache = k_data_stack_cache,
#endif
	[0].chain_stack_cache = chain_stack_cache[0],
};

__init __no_sanitize_address void setup_stack_print(void)
{
	int i;

	for (i = 0; i < NR_CPUS; i++)
		stack_regs_cache[i].chain_stack_cache = chain_stack_cache[i];
}

/* Returns number of *not* copied bytes */
static int careful_tagged_copy(void *dst, void *src, unsigned long sz)
{
	SET_USR_PFAULT("$recovery_memcpy_fault", false);
	size_t copied = fast_tagged_memory_copy_in_user((void __force __user *)dst,
							(void __force __user *)src,
							sz, NULL, 0);
	RESTORE_USR_PFAULT(false);
	return sz - copied;
}

#ifdef CONFIG_SMP
static int get_cpu_regs_nmi(int cpu, struct task_struct *task,
			    struct stack_regs *const regs);
#endif

#ifdef CONFIG_DATA_STACK_WINDOW
__always_inline /* for %cr1.ussz calculations below */
static void copy_k_data_stack_regs(const struct pt_regs *limit_regs,
				   struct stack_regs *regs)
{
	struct pt_regs *pt_regs;
	int i;

	if (!regs->show_k_data_stack)
		return;

	if (!limit_regs || kernel_mode(limit_regs)) {
		e2k_usd_t usd;
		e2k_addr_t sbr;

		if (!limit_regs) {
			usd = native_read_USD_reg();
			sbr = native_read_SBR_reg().base;
		} else {
			usd = limit_regs->stacks.usd;
			sbr = limit_regs->stacks.top;
		}
		regs->base_k_data_stack = (void *)(USD_P(usd) ? sbr + USD_PPTR(usd) :
								USD_PTR(usd));
		/* We found the current data stack frame, but
		 * of interest is our parent's frame. Move up. */
		if (!limit_regs) {
			regs->base_k_data_stack += (cpu_has(CPU_FEAT_V7_CPU_REGS)) ?
					read_USFS_reg() + get_cr1_ussz(read_CR1_reg()) :
					get_cr1_ussz(regs->crs.cr1) - USD_IND(usd);
		}

		regs->real_k_data_stack_addr = regs->base_k_data_stack;
		regs->size_k_data_stack = sbr - (unsigned long)regs->base_k_data_stack;
	} else {
		regs->base_k_data_stack = NULL;
	}

	pt_regs = find_host_regs(current_thread_info()->pt_regs);

	for (i = 0; i < MAX_PT_REGS_SHOWN; i++) {
		if (!pt_regs)
			break;

		regs->pt_regs[i].valid = 1;
		regs->pt_regs[i].addr = (unsigned long) pt_regs;
		pt_regs = find_host_regs(pt_regs->next);
	}
}
#else
static void copy_k_data_stack_regs(const struct pt_regs *limit_regs,
				   struct stack_regs *regs)
{
}
#endif

void fill_trap_stack_regs(const pt_regs_t *trap_pt_regs,
			  printed_trap_regs_t *regs_trap)
{
	regs_trap->frame = PCSP_PTR(trap_pt_regs->stacks.pcsp);
	regs_trap->ctpr1 = trap_pt_regs->ctpr1;
	regs_trap->ctpr2 = trap_pt_regs->ctpr2;
	regs_trap->ctpr3 = trap_pt_regs->ctpr3;
	regs_trap->lsr = trap_pt_regs->lsr;
	regs_trap->ilcr = trap_pt_regs->ilcr;
	if (machine.native_iset_ver >= E2K_ISET_V5) {
		regs_trap->lsr1 = trap_pt_regs->lsr1;
		regs_trap->ilcr1 = trap_pt_regs->ilcr1;
	}
	if (trap_pt_regs->trap) {
		memcpy(regs_trap->sbbp, trap_pt_regs->trap->sbbp,
		       sizeof(regs_trap->sbbp));
	} else {
		memset(regs_trap->sbbp, 0, sizeof(regs_trap->sbbp));
	}
	regs_trap->valid = 1;
}

static void copy_trap_stack_regs(const struct pt_regs *limit_regs,
				 struct stack_regs *regs)
{
	struct pt_regs *trap_pt_regs;
	int i;

	if (!regs->show_trap_regs)
		return;

	trap_pt_regs = find_trap_host_regs(current_thread_info()->pt_regs);

	while (trap_pt_regs && limit_regs &&
	       (PCSP_PTR(trap_pt_regs->stacks.pcsp) >
			PCSP_PTR(limit_regs->stacks.pcsp))) {
		trap_pt_regs = find_trap_host_regs(trap_pt_regs->next);
	}
	for (i = 0; i < MAX_USER_TRAPS; i++) {
		if (!trap_pt_regs)
			break;

		fill_trap_stack_regs(trap_pt_regs, &regs->trap[i]);

		trap_pt_regs = find_trap_host_regs(trap_pt_regs->next);
	}
}

/* Returns number of *not* copied bytes */
static unsigned long copy_user_hardware_stack(void *dst, void __priv *src, unsigned long sz)
{
	unsigned long n;
	int ret;

	if (on_reserve_stack()) {
		/* We are currently on reserve stacks which means
		 * that this function is trying to access kernel's stacks */
		return careful_tagged_copy(dst, (void __force *) src, sz);
	}

	n = (unsigned long) src + sz - round_down((unsigned long) src + sz, PAGE_SIZE);
	if (n == 0)
		n = PAGE_SIZE;
	n = min(n, sz);

	src = src + sz - n;
	dst = dst + sz - n;

	while (sz > 0) {
		/* Trying to handle page fault for user hardware stack
		 * might lead to accessing swap which is not a good idea
		 * if we want to reliably print stack */
		pagefault_disable();
		ret = copy_e2k_stack_from_user(dst, src, n, NULL);
		pagefault_enable();

		if (ret)
			return sz;

		sz -= n;
		n = min(sz, PAGE_SIZE);
		src -= n;
		dst -= n;
	}

	WARN_ON(sz);

	return 0;
}

static void copy_proc_stack_regs(const struct pt_regs *limit_regs,
				 struct stack_regs *regs)
{
	const struct pt_regs *pt_regs;
	void *dst, *src;
	u64 sz;

	BUG_ON(!raw_all_irqs_disabled());

	if (!regs->psp_stack_cache) {
		regs->base_psp_stack = NULL;
		return;
	}

	if (limit_regs && on_reserve_stack()) {
		/* Hardware stack overflow happened. First we copy
		 * SPILLed to reserve stacks part of kernel stacks. */
		src = (void *) PSP_BASE(read_PSP_reg());
		if (limit_regs) {
			sz = PSHTP_MEM_INDEX(limit_regs->stacks.pshtp);
			regs->orig_base_psp_stack_k = PSP_PTR(limit_regs->stacks.psp) - sz;
		} else {
			sz = min_t(u64, PSP_IND(regs->psp),  SIZE_PSP_STACK);
			regs->orig_base_psp_stack_k = (u64) src;
		}
	} else if (limit_regs && PSP_BASE(limit_regs->stacks.psp) < PAGE_OFFSET) {
		/* Trying to get user stacks through NMI. First we
		 * copy SPILLed to kernel part of user stacks. */
		sz = PSHTP_MEM_INDEX(limit_regs->stacks.pshtp);
		src = (void *) PSP_BASE(current_thread_info()->k_psp);
		regs->orig_base_psp_stack_k = (u64) src;
	} else {
		/* Trying to get all stacks; start with kernel. */
		sz = min_t(u64, PSP_IND(regs->psp), SIZE_PSP_STACK);
		src = (void *) PSP_BASE(regs->psp);
		regs->orig_base_psp_stack_k = (u64) src;
	}
	dst = regs->psp_stack_cache + SIZE_PSP_STACK - sz;

	if (careful_tagged_copy(dst, src, sz)) {
		pr_alert("WARNING current procedure stack not available at %px\n", src);
		/* We can still print chain stack */
		regs->base_psp_stack = NULL;
		return;
	}

	regs->base_psp_stack = dst;
	regs->size_psp_stack = sz;

	if (on_reserve_stack()) {
		pt_regs = limit_regs;
		regs->user_size_psp_stack = 0;
	} else {
		pt_regs = current_pt_regs();
		if (pt_regs && !user_mode(pt_regs))
			pt_regs = NULL;
		regs->user_size_psp_stack = (pt_regs) ? PSHTP_MEM_INDEX(pt_regs->stacks.pshtp) : 0;
	}
	if (pt_regs) {
		unsigned long copied;
		void __priv *u_src = (void __priv *) PSP_BASE(pt_regs->stacks.psp);
		sz = PSP_IND(pt_regs->stacks.psp) - PSHTP_MEM_INDEX(pt_regs->stacks.pshtp);
		if (sz > regs->base_psp_stack - regs->psp_stack_cache) {
			s64 delta = sz - (u64) (regs->base_psp_stack - regs->psp_stack_cache);
			sz -= delta;
			u_src += delta;
		}
		dst = regs->base_psp_stack - sz;

		copied = sz - copy_user_hardware_stack(dst, u_src, sz);
		if (copied != sz)
			memmove(regs->base_psp_stack - copied, dst, copied);

		regs->orig_base_psp_stack_u = (unsigned long) u_src + sz - copied;
		if (copied) {
			regs->base_psp_stack -= copied;
			regs->size_psp_stack += copied;
			regs->orig_base_psp_stack_k -= copied;
			regs->user_size_psp_stack += (on_reserve_stack()) ? 0 : copied;
		}
	} else {
		regs->orig_base_psp_stack_u = 0;
	}
}

static int copy_chain_stack_regs(const struct pt_regs *limit_regs,
				 struct stack_regs *regs)
{
	const struct pt_regs *pt_regs;
	void *dst, *src;
	u64 sz, free_dst_sz = SIZE_CHAIN_STACK;

	if (!regs->chain_stack_cache) {
		regs->base_chain_stack = NULL;
		return -ENOMEM;
	}

	if (on_reserve_stack()) {
		/* Hardware stack overflow happened. First we copy
		 * SPILLed to reserve stacks part of kernel stacks. */
		src = (void *) PCSP_BASE(read_PCSP_reg());
		if (limit_regs) {
			sz = limit_regs->stacks.pcshtp.ind;
			regs->orig_base_chain_stack_k =
			    PCSP_PTR(limit_regs->stacks.pcsp) - sz;
		} else {
			sz = min(PCSP_IND(regs->pcsp), free_dst_sz);
			regs->orig_base_chain_stack_k = (u64) src;
		}
	} else if (limit_regs &&
			PCSP_BASE(limit_regs->stacks.pcsp) < PAGE_OFFSET) {
		/* Trying to get user stacks through NMI. First we
		 * copy SPILLed to kernel part of user stacks. */
		sz = limit_regs->stacks.pcshtp.ind;
		src = (void *) PCSP_BASE(current_thread_info()->k_pcsp);
		regs->orig_base_chain_stack_k = (u64) src;
	} else {
		/* Trying to get all stacks; start with kernel. */
		sz = min(PCSP_IND(regs->pcsp), free_dst_sz);
		src = (void *) PCSP_BASE(regs->pcsp);
		regs->orig_base_chain_stack_k = (u64) src;
	}
	dst = regs->chain_stack_cache + free_dst_sz - sz;

	if (careful_tagged_copy(dst, src, sz)) {
		pr_alert("WARNING current chain stack not available at %px\n", src);
		regs->base_chain_stack = NULL;
		return -EFAULT;
	}

	regs->base_chain_stack = dst;
	regs->size_chain_stack = sz;

	if (on_reserve_stack()) {
		pt_regs = limit_regs;
		regs->user_size_chain_stack = 0;
	} else {
		pt_regs = current_pt_regs();
		if (!pt_regs || !user_mode(pt_regs)) {
			pt_regs = NULL;
			regs->user_size_chain_stack = 0;
		} else {
			regs->user_size_chain_stack = pt_regs->stacks.pcshtp.ind;
			if (limit_regs &&
			    PCSP_BASE(limit_regs->stacks.pcsp) < PAGE_OFFSET) {
				regs->user_size_chain_stack += SZ_OF_CR;
			}
		}
	}

	if (pt_regs) {
		unsigned long copied;
		void __priv *u_src = (void __priv *) PCSP_BASE(pt_regs->stacks.pcsp);
		sz = PCSP_IND(pt_regs->stacks.pcsp) - pt_regs->stacks.pcshtp.ind;
		if (sz > regs->base_chain_stack - regs->chain_stack_cache) {
			s64 delta = sz - (u64) (regs->base_chain_stack - regs->chain_stack_cache);
			sz -= delta;
			u_src += delta;
		}
		dst = regs->base_chain_stack - sz;

		copied = sz - copy_user_hardware_stack(dst, u_src, sz);
		if (copied != sz)
			memmove(regs->base_chain_stack - copied, dst, copied);

		regs->orig_base_chain_stack_u = (unsigned long) u_src + sz - copied;
		if (copied) {
			regs->base_chain_stack -= copied;
			regs->size_chain_stack += copied;
			regs->orig_base_chain_stack_k -= copied;
			regs->user_size_chain_stack += (on_reserve_stack()) ? 0 : copied;
		}
	} else {
		regs->orig_base_chain_stack_u = 0;
	}

	return 0;
}

/*
 * Copy full or last part of a process stack to a buffer.
 * Is inlined to make sure that the return will not flush stack.
 *
 * Must be called with maskable interrupts disabled because
 * stack registers are protected by IRQ-disable.
 */
noinline void copy_stack_regs(struct task_struct *task, const struct pt_regs *limit_regs,
			      struct stack_regs *regs)
{
	struct sw_regs *sw_regs;
	int i;
	void *dst, *src;
	u64 sz;

	if (unlikely(!raw_irqs_disabled()))
		pr_info("copy_stack_regs called with enabled interrupts!\n");

	regs->valid = 0;
	regs->gregs_valid = 0;
	regs->ignore_banner = false;
	for (i = 0; i < MAX_USER_TRAPS; i++)
		regs->trap[i].valid = 0;
#ifdef CONFIG_DATA_STACK_WINDOW
	for (i = 0; i < MAX_PT_REGS_SHOWN; i++)
		regs->pt_regs[i].valid = 0;
#endif

	if (task == current) {
		unsigned long flags;

		raw_all_irq_save(flags);
		COPY_STACKS_TO_MEMORY();

		if (limit_regs) {
			regs->pcsp = limit_regs->stacks.pcsp;
			regs->psp = limit_regs->stacks.psp;
			regs->crs = limit_regs->crs;
		} else {
			e2k_mem_crs_t *frame;
			e2k_pcshtp_t pcshtp;
			e2k_pshtp_t pshtp;

			ATOMIC_READ_PC_STACK_REGS(regs->pcsp, AW(pcshtp));
			regs->pcsp = incr_pcsp_ind(regs->pcsp, pcshtp.ind);
			ATOMIC_READ_P_STACK_REGS(regs->psp, AW(pshtp));
			regs->psp = incr_psp_ind(regs->psp, PSHTP_MEM_INDEX(pshtp));

			frame = (e2k_mem_crs_t *) PCSP_PTR(regs->pcsp);
			regs->crs = *(frame - 1);
			regs->pcsp = decr_pcsp_ind(regs->pcsp, SZ_OF_CR);
			regs->psp = decr_psp_ind(regs->psp,
						 native_read_CR1_reg().wbs * EXT_4_NR_SZ);
		}

		get_all_user_glob_regs(&regs->gregs);
		regs->gregs_valid = 1;

		copy_trap_stack_regs(limit_regs, regs);

		copy_k_data_stack_regs(limit_regs, regs);

		copy_proc_stack_regs(limit_regs, regs);

		if (!copy_chain_stack_regs(limit_regs, regs)) {
			regs->task = current;
			regs->valid = 1;
		}

		raw_all_irq_restore(flags);

		return;
	}

#ifdef CONFIG_SMP
	while (task_curr(task)) {
		/* get regs using NMI */
		if (-ESRCH == get_cpu_regs_nmi(task_cpu(task), task, regs))
			continue;
		if (regs->valid)
			return;

		/* Still no luck, fall back to sw_regs */
		pr_alert(" * * * * * * * * * ATTENTION * * * * * * * * *\n"
			 "Could not get %s[%d] stack using NMI,\n"
			 "used sw_regs instead. The stack is unreliable!\n"
			 " * * * * * * * * * * * * * * * * * * * * * * *\n",
			 task->comm, task_pid_nr(task));

		break;
	}
#endif

	sw_regs = &task->thread.sw_regs;

	regs->crs = sw_regs->crs;
	regs->pcsp = sw_regs->pcsp;
	regs->psp = sw_regs->psp;
#ifdef CONFIG_DATA_STACK_WINDOW
	regs->base_k_data_stack = NULL;
#endif

	/*
	 * We are here. This means that NMI failed and we will be
	 * printing stack using sw_regs. Copy another task's
	 * registers accessing them directly at physical address.
	 */

	/*
	 * Copy a part (or all) of the chain stack.
	 * If it fails then leave regs->valid set to 0.
	 */
	regs->base_chain_stack = (void *) regs->chain_stack_cache;
	if (!regs->base_chain_stack)
		goto out;

	regs->size_chain_stack = min_t(u64, PCSP_IND(regs->pcsp), SIZE_CHAIN_STACK);

	sz = regs->size_chain_stack;
	dst = regs->base_chain_stack;
	src = (void *)(PCSP_PTR(regs->pcsp) - sz);
	if (unlikely(((long)dst & 0x7) || ((long)src & 0x7) ||
		     ((long)sz & 0x7) || (u64) src < PAGE_OFFSET)) {
		pr_alert("Bad chain registers: src %lx, dst %lx, sz %llx\n",
			 src, dst, sz);
		goto out;
	}

	regs->orig_base_chain_stack_k = (u64) src;
	regs->orig_base_chain_stack_u = 0;

	/* Do the copy */
	if (careful_tagged_copy(dst, src, sz)) {
		pr_alert("WARNING chain stack not available at %px\n", src);
		goto out;
	}

	/* Copy a part (or all) of the procedure stack.
	 * Do _not_ set regs->valid to 0 if it fails
	 * (we can still print stack albeit without register windows) */
	regs->base_psp_stack = (void *) regs->psp_stack_cache;
	if (!regs->base_psp_stack)
		goto finish_copying_psp_stack;

	regs->size_psp_stack = min_t(u64, PSP_IND(regs->psp), SIZE_PSP_STACK);

	sz = regs->size_psp_stack;
	dst = regs->base_psp_stack;
	src = (void *)(PSP_PTR(regs->psp) - sz);
	if (unlikely(((long)dst & 0x7) || ((long)src & 0x7) ||
		     ((long)sz & 0x7) || (u64) src < PAGE_OFFSET)) {
		pr_alert("Bad psp registers: src %lx, dst %lx, sz %llx\n",
			 src, dst, sz);
		/* We can still print chain stack */
		regs->base_psp_stack = NULL;
		goto finish_copying_psp_stack;
	}

	regs->orig_base_psp_stack_k = (u64) src;
	regs->orig_base_psp_stack_u = 0;

	if (careful_tagged_copy(dst, src, sz)) {
		pr_alert("WARNING procedure stack not available at %px\n", src);
		/* We can still print chain stack */
		regs->base_psp_stack = NULL;
		goto finish_copying_psp_stack;
	}
finish_copying_psp_stack:

	regs->task = task;
	regs->valid = 1;

out:
	return;
}


#ifdef CONFIG_SMP
struct nmi_copy_stack_args {
	struct task_struct *task;
	struct stack_regs *regs;
	int ret;
};

static void nmi_copy_current_stack_regs(void *arg)
{
	struct nmi_copy_stack_args *args = arg;

	if (args->task && args->task != current) {
		/*
		 * Race: needed task is no longer running
		 */
		args->ret = -ESRCH;
		return;
	}

	copy_stack_regs(current, find_host_regs(current_thread_info()->pt_regs), args->regs);
}

static int get_cpu_regs_nmi(int cpu, struct task_struct *task,
			    struct stack_regs *const regs)
{
	struct nmi_copy_stack_args args;
	int attempt;

	/* get regs using NMI, try several times
	 * waiting for a total of 30 seconds. */
	regs->valid = 0;

	/* Paravirt guest does not use nmi IPI to dump stacks */
	if (paravirt_enabled() && !IS_HV_GM())
		return 0;

	args.task = task;
	args.regs = regs;
	args.ret = 0;
	for (attempt = 0; attempt < 3; attempt++) {
		nmi_call_function_single(cpu, nmi_copy_current_stack_regs,
					 &args, 1, 10000);
		if (args.ret)
			return args.ret;

		if (regs->valid) {
			if (task && regs->task != task)
				return -ESRCH;

			break;
		}
	}

	return 0;
}
#endif /* CONFIG_SMP */


#ifdef CONFIG_CLI_CHECK_TIME
cli_info_t	cli_info[2];
tt0_info_t	tt0_info[2];
int		cli_info_needed = 0;

void start_cli_info(void)
{
	pr_info("start_cli_info: clock %ld\n", READ_CLKR_REG());
	memset(cli_info, 0, sizeof(cli_info));
	cli_info_needed = 1;
}

void tt0_prolog_ticks(long ticks)
{
	if (cli_info_needed && Max_tt0_prolog < ticks) {
		Max_tt0_prolog = ticks;
	}
}

static void print_cli_info(void)
{

	pr_info("print_cli_info: for CPU 0\n");
	pr_info("Max_tt0_prolog %ld\n", tt0_info[0].max_tt0_prolog);
	pr_info("max_cli %ld max_cli_ip 0x%lx max_cli_cl %ld end_cl %ld\n",
		cli_info[0].max_cli,
		cli_info[0].max_cli_ip,
		cli_info[0].max_cli_cl,
		cli_info[0].max_cli_cl + cli_info[0].max_cli);

	pr_info("max_gcli %ld max_gcli_ip 0x%lx max_gcli_cl %ld\n\n",
		cli_info[0].max_gcli,
		cli_info[0].max_gcli_ip, cli_info[0].max_gcli_cl);
	if (num_online_cpus() == 1)
		return;

	pr_info("print_cli_info: for CPU 1\n");
	pr_info("Max_tt0_prolog %ld\n", tt0_info[1].max_tt0_prolog);
	pr_info("max_cli %ld max_cli_ip 0x%lx max_cli_cl %ld end_cl %ld\n",
		cli_info[1].max_cli,
		cli_info[1].max_cli_ip,
		cli_info[1].max_cli_cl,
		cli_info[1].max_cli_cl + cli_info[1].max_cli);

	pr_info("max_gcli %ld max_gcli_ip 0x%lx max_gcli_cl %ld\n",
		cli_info[1].max_gcli,
		cli_info[1].max_gcli_ip, cli_info[1].max_gcli_cl);
}
#else // CONFIG_CLI_CHECK_TIME
static void print_cli_info(void) { }
#endif

/*
 * print_reg_window - print local registers from psp stack
 * @window_base - pointer to the window in psp stack
 * @window_size - size of the window in psp stack (in quadro registers)
 * @fx - do print extensions?
  */
static void print_reg_window(u64 window_base, int window_size,
			     int fx, e2k_cr1_t cr1)
{
	int qreg, dreg, dreg_ind;
	u64 *rw = (u64 *)window_base;
	u64 qreg_lo, qreg_hi, ext_lo, ext_hi;
	u8 tag_lo, tag_hi, tag_ext_lo, tag_ext_hi;
	char brX0_name[6], brX1_name[6];
	u64 rbs, rsz, rcur;

	rbs = cr1.rbs;
	rsz = cr1.rsz;
	rcur = cr1.rcur;

	for (qreg = window_size - 1; qreg >= 0; qreg--) {
		dreg_ind = qreg * (EXT_4_NR_SZ / sizeof(*rw));

		load_value_and_tagd(&rw[dreg_ind + 0], &qreg_lo, &tag_lo);
		if (machine.native_iset_ver < E2K_ISET_V5) {
			load_value_and_tagd(&rw[dreg_ind + 1], &qreg_hi, &tag_hi);
			if (fx) {
				ext_lo = rw[dreg_ind + 2];
				ext_hi = rw[dreg_ind + 3];
			}
		} else {
			load_value_and_tagd(&rw[dreg_ind + 2], &qreg_hi, &tag_hi);
			if (fx) {
				load_value_and_tagd(&rw[dreg_ind + 1],
						    &ext_lo, &tag_ext_lo);
				load_value_and_tagd(&rw[dreg_ind + 3],
						    &ext_hi, &tag_ext_hi);
			}
		}

		dreg = qreg * 2;

		/* Calculate %br[] register number */
		if (qreg >= rbs && qreg <= (rbs + rsz) && rsz >= rcur) {
			int qbr, brX0, brX1;

			qbr = (qreg - rbs) + ((rsz + 1) - rcur);

			while (qbr > rsz)
				qbr -= rsz + 1;

			brX0 = 2 * qbr;
			brX1 = 2 * qbr + 1;

			snprintf(brX0_name, 7, "%sb%d/", (brX0 < 10) ? "  " :
					((brX0 < 100) ? " " : ""), brX0);
			snprintf(brX1_name, 7, "%sb%d/", (brX0 < 10) ? "  " :
					((brX0 < 100) ? " " : ""), brX1);
		} else {
			memset(brX0_name, ' ', 5);
			memset(brX1_name, ' ', 5);
			brX0_name[5] = 0;
			brX1_name[5] = 0;
		}

		if (fx) {
			if (machine.native_iset_ver < E2K_ISET_V5) {
				pr_alert("     %sr%-3d: %hhx 0x%016llx %04hx %sr%-3d: %hhx 0x%016llx %04hx\n",
					 brX0_name, dreg, tag_lo, qreg_lo,
					 (u16) ext_lo, brX1_name, dreg + 1, tag_hi,
					 qreg_hi, (u16) ext_hi);
			} else {
				pr_alert("     %sr%-3d: %hhx 0x%016llx   ext: %hhx %016llx\n",
					 brX1_name, dreg + 1, tag_hi, qreg_hi,
					 tag_ext_hi, ext_hi);
				pr_alert("     %sr%-3d: %hhx 0x%016llx   ext: %hhx %016llx\n",
					 brX0_name, dreg, tag_lo, qreg_lo,
					 tag_ext_lo, ext_lo);
			}
		} else {
			pr_alert("     %sr%-3d: %hhx 0x%016llx    %sr%-3d: %hhx 0x%016llx\n",
				 brX0_name, dreg, tag_lo, qreg_lo, brX1_name,
				 dreg + 1, tag_hi, qreg_hi);
		}
	}
}

static inline void print_predicates(u64 pf, e2k_cr1_t cr1)
{
	u64 i, values = 0, tags = 0;

	for (i = 0; i < 32; i++) {
		values |= (pf & (1ULL << 2 * i)) >> i;
		tags |= (pf & (1ULL << (2 * i + 1))) >> (i + 1);
	}
	pr_alert("      predicates[31:0] %08x   ptags[31:0] %08x   psz %d   pcur %d\n",
		 (u32) values, (u32) tags, cr1.psz, cr1.pcur);
}

u64 print_all_TIRs(const e2k_tir_t *TIRs, u64 nr_TIRs)
{
	e2k_tir_t tir;
	u64 all_interrupts = 0;
	int i;

	pr_alert("TIR all registers:\n");
	for (i = nr_TIRs; i >= 0; i--) {
		tir = TIRs[i];

		all_interrupts |= HI(tir);

		pr_alert("TIR.hi[%d]: 0x%016llx : exc 0x%011llx al 0x%x aa 0x%x #%d\n",
			 i, tir.hi, tir.exc, tir.al, tir.aa, tir.j);

		if (tir.exc) {
			u64 exc = tir.exc;
			int nr_intrpt;

			pr_alert("  ");
			for (nr_intrpt = __ffs64(exc); exc != 0;
					exc &= ~(1UL << nr_intrpt),
					nr_intrpt = __ffs64(exc))
				pr_cont(" %s", exc_tbl_name[nr_intrpt]);
			pr_cont("\n");
		}

		pr_alert("TIR.lo[%d]: 0x%016llx : IP 0x%012llx\n",
			 i, tir.lo, tir.ip);
	}

	return all_interrupts & (exc_all_mask | aau_exc_mask);
}

void print_tc_record(const trap_cellar_t *tcellar, int num)
{
	tc_fault_type_t ftype;
	mmu_tc_dst_t	dst;
	tc_opcode_t	opcode;
	u64		data;
	u8		data_tag;

	AW(dst) = tcellar->condition.dst;
	AW(opcode) = tcellar->condition.opcode;
	AW(ftype) = tcellar->condition.fault_type;

	load_value_and_tagd(&tcellar->data, &data, &data_tag);
	/* FIXME: data has tag, but E2K_LOAD_TAGGED_DWORD() is privileged */
	/* action? guest will be trapped */
	if (!paravirt_enabled())
		load_value_and_tagd(&tcellar->data, &data, &data_tag);
	else {
		data = tcellar->data;
		data_tag = 0;
	}
	pr_info("   record #%d: address 0x%016llx data 0x%016llx tag 0x%x\n"
		"              condition 0x%016llx:\n"
		"                 dst 0x%05x: address 0x%04x, vl %d, vr %d\n"
		"                 opcode 0x%03x: fmt 0x%02x, npsp 0x%x\n"
		"                 store 0x%x, s_f  0x%x, mas 0x%x\n"
		"                 root  0x%x, scal 0x%x, sru 0x%x\n"
		"                 chan  0x%x, spec 0x%x, pm  0x%x\n"
		"                 fault_type 0x%x:\n"
		"                    addr_prot_page = %d\n"
		"                    intl_res_bits = %d MLT_trap     = %d\n"
		"                    ph_pr_page    = %d global_sp    = %d\n"
		"                    io_page       = %d isys_page    = %d\n"
		"                    prot_page     = %d priv_page    = %d\n"
		"                    illegal_page  = %d nwrite_page  = %d\n"
		"                    page_miss     = %d ph_bound     = %d\n"
		"                 miss_lvl 0x%x, num_align 0x%x, empt    0x%x\n"
		"                 clw      0x%x, rcv       0x%x  dst_rcv 0x%x\n",
		num,
		(u64) tcellar->address, data, data_tag,
		(u64) AW(tcellar->condition),
		(u32) AW(dst), (u32) dst.address, (u32) dst.vl, (u32) dst.vr,
		(u32) AW(opcode), (u32) opcode.fmt, (u32) opcode.npsp,
		(u32) tcellar->condition.store,
		(u32) tcellar->condition.s_f,
		(u32) tcellar->condition.mas,
		(u32) tcellar->condition.root,
		(u32) tcellar->condition.scal,
		(u32) tcellar->condition.sru,
		(u32) tcellar->condition.chan,
		(u32) tcellar->condition.spec,
		(u32) tcellar->condition.pm,
		(u32) tcellar->condition.fault_type,
		(u32) ftype.addr_prot_page,
		(u32) ftype.intl_res_bits,	(u32) ftype.exc_mem_lock,
		(u32) ftype.ph_pr_page,		(u32) ftype.global_sp,
		(u32) ftype.io_page,		(u32) ftype.isys_page,
		(u32) ftype.prot_page,		(u32) ftype.priv_page,
		(u32) ftype.illegal_page,	(u32) ftype.nwrite_page,
		(u32) ftype.page_miss,		(u32) ftype.ph_bound,
		(u32) tcellar->condition.miss_lvl,
		(u32) tcellar->condition.num_align,
		(u32) tcellar->condition.empt,
		(u32) tcellar->condition.clw,
		(u32) tcellar->condition.rcv,
		(u32) tcellar->condition.dst_rcv);
}

void print_all_TC(const trap_cellar_t *TC, int TC_count)
{
	int i;

	if (!TC_count)
		return;

	pr_info("TRAP CELLAR all %d records:\n", TC_count / 3);
	for (i = 0; i < TC_count / 3; i++)
		print_tc_record(&TC[i], i);
}

static void print_SBBP_pt_regs(const struct trap_pt_regs *trap)
{
	int i;

	for (i = 0; i < SBBP_ENTRIES_NUM; i += 4) {
		pr_alert("sbbp%-2d  0x%-12llx 0x%-12llx 0x%-12llx 0x%-12llx\n",
			 i, trap->sbbp[i + 0], trap->sbbp[i + 1],
			 trap->sbbp[i + 2], trap->sbbp[i + 3]);
	}

}

/*
 * Print pt_regs
 */
void print_pt_regs(const pt_regs_t *regs)
{
	const e2k_mem_crs_t crs = regs->crs;
	const e2k_upsr_t upsr = current_thread_info()->upsr;

	if (!regs)
		return;

	pr_info("	PT_REGS value:\n");


	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		pr_info("usd: base 0x%llx, ind 0x%llx size 0x%llx, lo:hi 0x%llx : 0x%llx. usincr: %lld(0x%llx)\n",
			USD_BASE(regs->stacks.usd), USD_IND(regs->stacks.usd),
			USD_SIZE(regs->stacks.usd),
			regs->stacks.usd.lo, regs->stacks.usd.hi,
			native_read_USINCR_reg().incr, AW(native_read_USINCR_reg()));
	} else {
		pr_info("usd: base 0x%llx, size 0x%llx, p %d, sbr: 0x%llx\n",
			USD_PTR(regs->stacks.usd), USD_IND(regs->stacks.usd),
			USD_P(regs->stacks.usd), regs->stacks.top);
	}
	pr_info("psp: base %llx, ind %llx, size %llx. lo:hi 0x%llx : ox%llx. PSHTP: 0x%d\n",
		PSP_BASE(regs->stacks.psp), PSP_IND(regs->stacks.psp), PSP_SIZE(regs->stacks.psp),
		regs->stacks.psp.lo, regs->stacks.psp.hi,
		PSHTP_MEM_INDEX(regs->stacks.pshtp));
	pr_info("pcsp: base %llx, ind %llx, size %llx. lo:hi 0x%llx : 0x%llx. PCSHTP 0x%d\n",
		PCSP_BASE(regs->stacks.pcsp), PCSP_IND(regs->stacks.pcsp),
		PCSP_SIZE(regs->stacks.pcsp), regs->stacks.pcsp.lo, regs->stacks.pcsp.hi,
		AW(regs->stacks.pcshtp));

	pr_info("cr0.lo: pf 0x%llx, cr0.hi: ip 0x%llx\n",
		crs.cr0.pf, get_cr0_ip(crs.cr0));
	pr_info("cr1.lo: unmie %d, nmie %d, uie %d, lw %d, sge %d, ie %d, pm %d\n"
		"        cuir 0x%x, wbs 0x%x, wpsz 0x%x, wfx %d, ss %d, ein %d\n",
		crs.cr1.unmie, crs.cr1.nmie, crs.cr1.uie, crs.cr1.lw, crs.cr1.sge,
		crs.cr1.ie, crs.cr1.pm, crs.cr1.cuir, crs.cr1.wbs, crs.cr1.wpsz,
		crs.cr1.wfx, crs.cr1.ss, crs.cr1.ein);
	pr_info("cr1.hi: ussz 0x%llx, wdbl %d\n"
		"        rbs 0x%x, rsz 0x%x, rcur 0x%x, psz 0x%x, pcur 0x%x\n",
		get_cr1_ussz(crs.cr1), crs.cr1.wdbl, crs.cr1.rbs, crs.cr1.rsz,
		crs.cr1.rcur, crs.cr1.psz, crs.cr1.pcur);
	pr_info("WD: base 0x%x, size 0x%x, psize 0x%x, fx %d, dbl %d\n",
		regs->wd.base, regs->wd.size, regs->wd.psize, regs->wd.fx,
		regs->wd.dbl);
	if (from_syscall(regs)) {
		pr_info("regs->kernel_entry: %d, syscall #%d\n",
			regs->kernel_entry, regs->sys_num);
	} else {
		const struct trap_pt_regs *trap = regs->trap;
		u64 exceptions;

		pr_info("ctpr1: base 0x%llx, tag 0x%llx, opc 0x%llx, ipd 0x%llx\n",
			regs->ctpr1.ta_base, ctpr_ta_tag(regs->ctpr1),
			ctpr_opc(regs->ctpr1), ctpr_ipd(regs->ctpr1));
		pr_info("ctpr2: base 0x%llx, tag 0x%llx, opc 0x%llx, prefetch 0x%llx\n",
			regs->ctpr2.ta_base, ctpr_ta_tag(regs->ctpr2),
			ctpr_opc(regs->ctpr2), ctpr_ipd(regs->ctpr2));
		pr_info("ctpr3: base 0x%llx, tag 0x%llx, opc 0x%llx, prefetch 0x%llx\n",
			regs->ctpr3.ta_base, ctpr_ta_tag(regs->ctpr3),
			ctpr_opc(regs->ctpr3), ctpr_ipd(regs->ctpr3));
		pr_info("regs->trap: 0x%px\n", regs->trap);
		pr_info("AAU context at 0x%px\n", regs->aau_context);

		exceptions = print_all_TIRs(trap->TIRs, trap->nr_TIRs);
		if (regs->trap) {
			print_SBBP_pt_regs(trap);
		}
		print_all_TC(trap->tcellar, trap->tc_count);
		if (exceptions & exc_data_debug_mask) {
			pr_info("ddbar0 0x%llx, ddbar1 0x%llx, ddbar2 0x%llx, ddbar3 0x%llx\n",
				READ_DDBAR0_REG_VALUE(), READ_DDBAR1_REG_VALUE(),
				READ_DDBAR2_REG_VALUE(), READ_DDBAR3_REG_VALUE());
			if (cpu_has(CPU_FEAT_ISET_V7)) {
				pr_info("ddbcr 0x%llx, ddmcr 0x%llx, ddmcr1 0x%llx, ddbsr 0x%llx\n",
					READ_DDBCR_REG_VALUE(), READ_DDMCR_REG_VALUE(),
					READ_DDMCR1_REG_VALUE(), READ_DDBSR_REG_VALUE());
				pr_info("ddmar0 0x%llx, ddmar1 0x%llx, ddmar2 0x%llx, ddmar3 0x%llx\n",
					READ_DDMAR0_REG_VALUE(), READ_DDMAR1_REG_VALUE(),
					READ_DDMAR2_REG_VALUE(), READ_DDMAR3_REG_VALUE());
			} else {
				pr_info("ddbcr 0x%llx, ddmcr 0x%llx, ddbsr 0x%llx\n",
					READ_DDBCR_REG_VALUE(), READ_DDMCR_REG_VALUE(),
					READ_DDBSR_REG_VALUE());
				pr_info("ddmar0 0x%llx, ddmar1 0x%llx\n",
					READ_DDMAR0_REG_VALUE(), READ_DDMAR1_REG_VALUE());
			}
		}
		if (exceptions & exc_instr_debug_mask) {
			pr_info("dibar0 0x%llx, dibar1 0x%llx, dibar2 0x%llx, dibar3 0x%llx\n",
				read_DIBAR0_reg_value(), read_DIBAR1_reg_value(),
				read_DIBAR2_reg_value(), read_DIBAR3_reg_value());
			if (cpu_has(CPU_FEAT_ISET_V7) && !cpu_has(CPU_HWBUG_DIMCR1)) {
				pr_info("dibcr 0x%x, dimcr 0x%llx, dimcr1 0x%llx, dibsr 0x%x\n",
					AW(read_DIBCR_reg()), AW(read_DIMCR_reg()),
					AW(read_DIMCR1_reg()), AW(read_DIBSR_reg()));
				pr_info("dimar0 0x%llx, dimar1 0x%llx, dimar2 0x%llx, dimar3 0x%llx\n",
					read_DIMAR0_reg_value(), read_DIMAR1_reg_value(),
					read_DIMAR2_reg_value(), read_DIMAR3_reg_value());
			} else {
				pr_info("dibcr 0x%x, dimcr 0x%llx, dibsr 0x%x\n",
					AW(read_DIBCR_reg()), AW(read_DIMCR_reg()),
					AW(read_DIBSR_reg()));
				pr_info("dimar0 0x%llx, dimar1 0x%llx\n",
					read_DIMAR0_reg_value(), read_DIMAR1_reg_value());
			}
		}
	}
	pr_info("UPSR: 0x%x : fe %d\n", AW(upsr), upsr.fe);
}

void notrace arch_trigger_cpumask_backtrace(const cpumask_t *mask,
					    bool exclude_self)
{
#ifdef CONFIG_SMP
	struct stack_regs *stack_regs;
	int cpu, this_cpu;
#endif
	unsigned long flags;

	/* stack_regs_cache[] is protected by IRQ-disable
	 * (we assume that NMI handlers will not call print_stack() and
	 * do not disable NMIs here as they are used by copy_stack_regs()) */
	raw_local_irq_save(flags);

	if (!exclude_self)
		print_stack_frames(current, NULL, 0);

#ifdef CONFIG_SMP
	this_cpu = raw_smp_processor_id();
	stack_regs = &stack_regs_cache[this_cpu];

	for_each_cpu(cpu, mask) {
		if (cpu == this_cpu)
			continue;

		/* Always show trap regs for user threads and
		 * skip by default fo kernel threads to make
		 * panic's stacks more robust. */
		stack_regs->show_trap_regs = debug_trap || !(current->flags & PF_KTHREAD);
		stack_regs->show_user_regs = debug_userstack;
# ifdef CONFIG_DATA_STACK_WINDOW
		stack_regs->show_k_data_stack = debug_datastack;
# endif
		get_cpu_regs_nmi(cpu, NULL, stack_regs);
		if (stack_regs->valid == 0) {
			pr_alert("WARNING could not get stack from CPU #%d, stack will not be printed\n",
				 cpu);
			continue;
		}

		pr_alert("NMI backtrace for cpu %d\n", cpu);
		print_chain_stack(stack_regs, 0);
	}
#endif
	raw_local_irq_restore(flags);
}

UACCESS_FN_DEFINE2(copy_crs_fn, e2k_mem_crs_t *, dst, const e2k_mem_crs_t *, src)
{
	e2k_cr0_t cr0;
	e2k_cr1_t cr1;

	if (IS_USER_ADDR(src)) {
		const e2k_mem_crs_t __user *u_src = (const e2k_mem_crs_t __user __force *) src;
		USER_LD(HI(cr0), &HI(u_src->cr0));
		USER_LD(LO(cr0), &LO(u_src->cr0));
		USER_LD(LO(cr1), &LO(u_src->cr1));
		USER_LD(HI(cr1), &HI(u_src->cr1));
	} else {
		cr0 = src->cr0;
		cr1 = src->cr1;
	}

	if (IS_USER_ADDR(dst)) {
		e2k_mem_crs_t __user *u_dst = (e2k_mem_crs_t __user __force *) dst;
		USER_ST(LO(cr0), &LO(u_dst->cr0));
		USER_ST(HI(cr0), &HI(u_dst->cr0));
		USER_ST(LO(cr1), &LO(u_dst->cr1));
		USER_ST(HI(cr1), &HI(u_dst->cr1));
	} else {
		dst->cr0 = cr0;
		dst->cr1 = cr1;
	}

	return 0;
}

notrace
static int get_chain_frame(e2k_mem_crs_t *dst, const e2k_mem_crs_t *src,
			   bool user, struct task_struct *p)
{
	if (p != current || user) {
		unsigned long ts_flag;
		int ret;

		ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
		/*
		 * Can be under closed interrupts here. If unhandled
		 * page fault happens we just bail out, otherwise we
		 * would have to SPILL chain stack again.
		 */
		ret = ____UACCESS_FN_CALL(copy_crs_fn, dst, src);
		clear_ts_flag(ts_flag);

		return ret;
	}

	if (WARN_ON_ONCE(IS_USER_ADDR(src)))
		return -EFAULT;

	*dst = *src;

	return 0;
}

static int put_chain_frame(unsigned long real_frame_addr, const e2k_mem_crs_t *crs)
{
	if (real_frame_addr >= PAGE_OFFSET) {
		unsigned long flags;

		raw_all_irq_save(flags);
		NATIVE_FLUSHC;
		*(e2k_mem_crs_t *) real_frame_addr = *crs;
		raw_all_irq_restore(flags);
	} else {
		if (copy_to_priv((void __priv *) real_frame_addr,
				crs, sizeof(*crs)))
			return -EFAULT;
	}

	return 0;
}

notrace
int ____parse_chain_stack(bool user, struct task_struct *p,
		parse_chain_fn_t func, void *arg, unsigned long delta_user,
		unsigned long top, unsigned long bottom)
{
	e2k_mem_crs_t *frame;
	int ret;

	for (frame = ((e2k_mem_crs_t *) top) - 1;
			(unsigned long) frame >= bottom; frame--) {
		e2k_mem_crs_t copied_frame;

		ret = get_chain_frame(&copied_frame, frame, user, p);
		if (unlikely(ret))
			return ret;

		ret = func(&copied_frame, (unsigned long) frame,
				(unsigned long) frame + delta_user,
				put_chain_frame, arg);
		if (ret)
			return ret;
	}

	return 0;
}

notrace noinline
static int __parse_chain_stack(bool user, struct task_struct *p,
				   parse_chain_fn_t func, void *arg)
{
	unsigned long irq_flags;
	u64 pcs_base, pcs_ind;
	u64 actual_base;
	int ret;

	if (p == current) {
		e2k_pcsp_t pcsp;

		raw_all_irq_save(irq_flags);
		/* `flushc` also ensures that data in memory
		 * is correct even if later there is a FILL. */
		NATIVE_FLUSHC;
		pcsp = native_read_PCSP_reg();
		raw_all_irq_restore(irq_flags);

		pcs_base = PCSP_BASE(pcsp);
		pcs_ind = PCSP_IND(pcsp);

		if (user) {
			struct pt_regs *regs = current_pt_regs();
			unsigned long spilled_to_kernel, delta_user, user_size;

			if (WARN_ON(!regs))
				return -EINVAL;

			/*
			 * In this case part of the user's stack was
			 * spilled into kernel so go over it first,
			 * then check user's stack.
			 *
			 * First pass: part of user stack spilled to kernel.
			 */
			spilled_to_kernel = regs->stacks.pcshtp.ind;
			if (spilled_to_kernel < 0)
				spilled_to_kernel = 0;

			/*
			 * The last user frame is not accounted for in %pcshtp
			 */
			user_size = spilled_to_kernel + SZ_OF_CR;

			/*
			 * The very last frame does not have any useful information
			 */
			if (PCSP_IND(regs->stacks.pcsp) == spilled_to_kernel) {
				user_size -= SZ_OF_CR;
				pcs_base += SZ_OF_CR;
			}

			delta_user = PCSP_PTR(regs->stacks.pcsp) - spilled_to_kernel -
					PCSP_BASE(current_thread_info()->k_pcsp);
			ret = do_parse_chain_stack(user, p, func, arg,
					delta_user, pcs_base + user_size, pcs_base);
			if (ret)
				return ret;

			/*
			 * Second pass: stack in user
			 */
			pcsp = regs->stacks.pcsp;
			pcs_base = PCSP_BASE(pcsp);
			pcs_ind = PCSP_IND(pcsp) - spilled_to_kernel;
		} else {
			/* First parse softirq if we are handling one */
			if (on_softirq_stack()) {
				ret = do_parse_chain_stack(user, p, func, arg,
						0, pcs_base + pcs_ind, pcs_base);
				if (ret)
					return ret;

				pcs_base = PCSP_BASE(current->thread.before_softirq.pcsp);
				pcs_ind = PCSP_IND(current->thread.before_softirq.pcsp);
			}

			if (CURRENT_PS_BASE() || CURRENT_PCS_BASE()) {
				struct pt_regs *regs = current_pt_regs();
				unsigned long spilled_to_kernel;

				/* 'regs' can be zero when kernel thread tries to
				 * execve() user binary or after deactivate_mm() in
				 * execve, in which case we assume there is only
				 * the minimum of (SZ_OF_CR + crs) user frames left
				 * in kernel stack. */
				if (regs) {
					spilled_to_kernel = regs->stacks.pcshtp.ind;
				} else {
					spilled_to_kernel = min_t(u64, pcs_ind, SZ_OF_CR);
				}

				if (WARN_ON_ONCE(spilled_to_kernel > pcs_ind))
					return -EINVAL;

				/*
				 * Skip part of user's stack that was spilled to kernel
				 */
				pcs_base += spilled_to_kernel;
				pcs_ind -= spilled_to_kernel;
			}
		}

		actual_base = (pcs_base >= PAGE_OFFSET) ? pcs_base :
						(unsigned long) CURRENT_PCS_BASE();
	} else {
		pcs_base = PCSP_BASE(p->thread.sw_regs.pcsp);
		pcs_ind = PCSP_IND(p->thread.sw_regs.pcsp);

		actual_base = pcs_base;
	}

	/* The very last frame does not have any useful information */
	actual_base += SZ_OF_CR;
	return do_parse_chain_stack(user, p, func, arg, 0,
			pcs_base + pcs_ind, actual_base);
}

/**
 * parse_chain_stack - parse chain stack backwards starting from the last frame
 * @user: which stack to parse (true for user and false for kernel)
 * @p: process to parse
 * @func: function to call
 * @arg: function argument
 *
 * Will stop parsing when either condition is met:
 *  - bottom of chain stack is reached;
 *  - @func returned non-zero value.
 *
 * See comment before parse_chain_fn_t for other arguments explanation.
 *
 * IMPORTANT: if @func wants to modify frame contents it must flush
 * chain stack if PCF_FLUSH_NEEDED is set.
 */
notrace noinline long parse_chain_stack(bool user, struct task_struct *p,
					parse_chain_fn_t func, void *arg)
{
	int ret;

	if (!p)
		p = current;

	/*
	 * Too much hassle to support when no one needs this
	 */
	if (p != current && user)
		return -ENOTSUPP;

	if (p != current) {
		if (!try_get_task_stack(p))
			return -ESRCH;
	}

	ret = __parse_chain_stack(user, p, func, arg);

	if (p != current)
		put_task_stack(p);

	return ret;
}


#ifdef CONFIG_USR_CONTROL_INTERRUPTS
static notrace int correct_psr_register(e2k_mem_crs_t *frame, unsigned long real_frame_addr,
		unsigned long corrected_frame_addr, chain_write_fn_t write_frame, void *arg)
{
	u64 maska = (u64) arg1;
	u64 cr_ip = get_cr0_ip(frame->cr0);

	if (IS_USER_ADDR(cr_ip)) {
		frame->cr1.psr = maska;

		int ret = write_frame(real_frame_addr, frame);
		if (ret)
			return -1;
	}
	return 0;
}
#endif /* CONFIG_USR_CONTROL_INTERRUPTS */

static int get_addr_name(u64 addr, char *buf, size_t len,
			 unsigned long *start_addr_p, struct mm_struct *mm)
{
	struct vm_area_struct *vma;
	int ret = 0;
	bool locked;

	if (!mm)
		return -ENOENT;

	/*
	 * This function is used when everything goes south
	 * so do not try too hard to lock mmap_lock
	 */
	locked = mmap_read_trylock(mm);

	vma = find_vma(mm, addr);
	if (!vma || vma->vm_start > addr || !vma->vm_file) {
		ret = -ENOENT;
		goto out_unlock;
	}

	/* seq_buf_path() locks init_fs.seq which is normally
	 * locked with enabled interrupts, so we cannot reliably
	 * call it if we are in interrupt */
	if (!in_irq()) {
		struct seq_buf s;

		seq_buf_init(&s, buf, len);
		seq_buf_path(&s, &vma->vm_file->f_path, "\n");

		if (seq_buf_used(&s) < len)
			buf[seq_buf_used(&s)] = 0;
		else
			buf[len - 1] = 0;
	} else {
		buf[0] = 0;
	}

	/* Assume that load_base == vm_start */
	if (start_addr_p)
		*start_addr_p = vma->vm_start;

out_unlock:
	if (locked)
		mmap_read_unlock(mm);

	return ret;
}


static DEFINE_RAW_SPINLOCK(print_stack_lock);

/**
 * print_stack_frames - print task's stack to console
 * @task: which task's stack to print?
 * @pt_regs: skip stack on top of this pt_regs structure
 * @show_reg_window: print local registers?
 */
noinline void
print_stack_frames(struct task_struct *task, const struct pt_regs *pt_regs,
		   int show_reg_window)
{
	unsigned long flags;
	int cpu;
	bool used;
	struct stack_regs *stack_regs;

	if (!task)
		task = current;

	if (test_and_set_bit(PRINT_FUNCY_STACK_WORKS_BIT, &task->thread.flags)) {
		pr_alert("  %d: print_stack: works already on pid %d\n",
				task_pid_nr(current), task_pid_nr(task));
		if (task != current)
			return;
	}

	/* if this is guest, stop tracing in host to avoid buffer overwrite */
	if (task == current)
		host_ftrace_stop();

	/*
	 * stack_regs_cache[] is protected by IRQ-disable
	 * (we assume that NMI handlers will not call dump_stack() and
	 * do not disable NMIs here as they are used by copy_stack_regs())
	 */
	raw_local_irq_save(flags);

	if (task == current) {
		pr_alert("%s", linux_banner);
	}

	cpu = raw_smp_processor_id();
	stack_regs = &stack_regs_cache[cpu];

	used = xchg(&stack_regs->used, 1);
	if (used) {
		pr_alert("  %d: print stack: works already on cpu %d\n",
				task_pid_nr(current), cpu);
	} else {
		/* Always show trap regs for user threads and
		 * skip by default fo kernel threads to make
		 * panic's stacks more robust. */
		stack_regs->show_trap_regs = debug_trap || !(current->flags & PF_KTHREAD);
		stack_regs->show_user_regs = debug_userstack;
#ifdef CONFIG_DATA_STACK_WINDOW
		stack_regs->show_k_data_stack = debug_datastack;
#endif
		copy_stack_regs(task, pt_regs, stack_regs);

		/* All checks of stacks validity are
		 * performed in print_chain_stack() */

		print_chain_stack(stack_regs, show_reg_window);
	}

	/* if task is host of guest VM or VCPU, then print guest stacks */
	print_guest_stack(task, stack_regs, show_reg_window);

	stack_regs->used = 0;

	raw_local_irq_restore(flags);

	clear_bit(PRINT_FUNCY_STACK_WORKS_BIT, &task->thread.flags);
}

static void print_ip(u64 addr, u64 cr_base, u64 cr_ind,
		     struct task_struct *task, u64 orig_base, bool *is_guest)
{
	unsigned long start_addr;
	char buf[64];
	int traced = 0;

	if (*is_guest) {
		pr_alert("  0x%-12llx   <guest>\n", addr);
	} else if (IS_USER_ADDR(addr)) {
		if (!get_addr_name(addr, buf, sizeof(buf), &start_addr, task->mm)) {
			pr_alert("  0x%-12llx   %s (@0x%lx)\n", addr, buf, start_addr);
		} else {
			pr_alert("  0x%-12llx   <anonymous>\n", addr);
		}
	} else {
#ifdef CONFIG_FUNCTION_GRAPH_TRACER
		if (task->ret_stack) {
			int index;
			for (index = 0; index <= task->curr_ret_stack; index++)
				if (task->ret_stack[index].fp == orig_base + cr_ind) {
					addr = task->ret_stack[index].ret;
					traced = 1;
					break;
				}
		}
#endif
		pr_alert("  0x%-12llx   %pS%s", addr, (void *)addr,
			 (traced) ? " (traced)" : "");
	}

	if (addr >= (unsigned long) __entry_handlers_hcalls_start &&
	    addr < (unsigned long) __entry_handlers_hcalls_end) {
		/* This is a hypercall, so frames below belong to guest
		 * and their translation cannot be trusted. */
		*is_guest = true;
	}
}

/* This function allocates memory necessary to print
 * procedure stack registers from other CPUs */
static int __init print_stack_init(void)
{
	int cpu;

	for (cpu = 0; cpu < NR_CPUS; cpu++)
		stack_regs_cache[cpu].chain_stack_cache = NULL;

	for_each_possible_cpu(cpu) {
		stack_regs_cache[cpu].chain_stack_cache =
				kmalloc(SIZE_CHAIN_STACK, GFP_KERNEL);
		BUG_ON(stack_regs_cache[cpu].chain_stack_cache == NULL);

		if (cpu == 0)
			continue;

		stack_regs_cache[cpu].psp_stack_cache = kmalloc(SIZE_PSP_STACK,
								GFP_KERNEL);
		if (stack_regs_cache[cpu].psp_stack_cache == NULL) {
			pr_info("WARNING print_stack_init: no memory, printing running tasks\n"
				" register stacks from CPU #%d will not be done\n", cpu);
			continue;
		}
#ifdef CONFIG_DATA_STACK_WINDOW
		stack_regs_cache[cpu].k_data_stack_cache =
				kmalloc(SIZE_DATA_STACK, GFP_KERNEL);
		if (stack_regs_cache[cpu].k_data_stack_cache == NULL) {
			pr_info("WARNING print_stack_init: no memory, printing running tasks\n"
				" kernel data stacks from CPU #%d will not be done\n", cpu);
			continue;
		}
#endif
	}

	return 0;
}
/* Initialize printing stacks from other CPUs before initializing those CPUs */
early_initcall(print_stack_init);

int print_window_regs = 0;
static int __init print_window_regs_setup(char *str)
{
	print_window_regs = 1;
	return 1;
}
__setup("print_window_regs", print_window_regs_setup);

int debug_protected_mode = 0;
static int __init init_debug_protected_mode(void)
{
	if (cpu_has(CPU_FEAT_ISET_V7))
		return 0;

	debug_protected_mode = read_CORE_MODE_reg().no_stack_prot;
	DebugCM(" init debug_protected_mode =%d\n", debug_protected_mode);
	return 0;
}
early_initcall(init_debug_protected_mode);

static void nmi_set_no_stack_prot(void *arg)
{
	if (cpu_has(CPU_FEAT_ISET_V7))
		return;

	e2k_core_mode_t core_mode = read_CORE_MODE_reg();
	core_mode.no_stack_prot = !!arg;
	write_CORE_MODE_reg(core_mode);

	DebugCM(" debug_protected_mode =%d cpu=%d\n", debug_protected_mode,
		raw_smp_processor_id());
}

void set_protected_mode_flags(void)
{
	on_each_cpu(nmi_set_no_stack_prot,
		    (void *)(long)debug_protected_mode, 1);
}

/* bug 115090: always set %core_mode.no_stack_prot */
static int initialize_no_stack_prot(void)
{
	if (cpu_has(CPU_FEAT_ISET_V7))
		return 0;

	debug_protected_mode = 1;
	set_protected_mode_flags();

	return 0;
}
arch_initcall(initialize_no_stack_prot);

#ifdef CONFIG_DATA_STACK_WINDOW
static void print_k_data_stack(struct stack_regs *regs, int *pt_regs_num,
			       unsigned long base, u64 size)
{
	unsigned long delta = regs->real_k_data_stack_addr -
			regs->base_k_data_stack;
	bool pt_regs_valid = regs->pt_regs[*pt_regs_num].valid;
	unsigned long pt_regs_addr = regs->pt_regs[*pt_regs_num].addr;
	unsigned long addr;
	bool show_pt_regs;

	if (!size)
		return;

	if (pt_regs_valid && pt_regs_addr >= (unsigned long) base + delta &&
	    pt_regs_addr < (unsigned long) base + delta + size) {
		show_pt_regs = 1;
		(*pt_regs_num)++;
	} else {
		show_pt_regs = 0;
	}

	pr_info("    DATA STACK from %lx to %llx\n", base + delta,
		base + delta + size);
	for (addr = base; addr < base + size; addr += 16) {
		u8 tag;
		e2k_qreg_t value;
		bool is_pt_regs_addr = show_pt_regs
				&& (addr + delta) >= pt_regs_addr
				&& (addr + delta) < (pt_regs_addr +
							sizeof(struct pt_regs));

		load_qvalue_and_tagq((void *) addr, &value, &tag, 8);
		pr_info("      %lx (%s+0x%-3lx): %x %016llx    %x %016llx\n",
			addr + delta, (is_pt_regs_addr) ? "pt_regs" : "",
			(is_pt_regs_addr) ? (addr + delta - pt_regs_addr) :
			(addr - base), tag & 0xf, value.lo, tag >> 4, value.hi);
	}
}
#endif


/*
 * Must be called with disabled interrupts
 */
void print_chain_stack(struct stack_regs *regs, int show_reg_window)
{
	unsigned long flags;
	bool disable_nmis;
	struct task_struct *task = regs->task;
	u32 attempt, locked = 0;
	u64 new_chain_base = (u64) regs->base_chain_stack;
	u64 orig_chain_base, orig_psp_base;
	s64 cr_ind = regs->size_chain_stack;
	s64 kernel_size_chain_stack = regs->size_chain_stack -
				      regs->user_size_chain_stack;
	e2k_mem_crs_t crs = regs->crs;
	u64 new_psp_base = (u64) regs->base_psp_stack;
	s64 psp_ind = regs->size_psp_stack;
	s64 kernel_size_psp_stack = regs->size_psp_stack -
				    regs->user_size_psp_stack;
	stack_frame_t cur_frame;
	bool ignore_ip = false;
	int trap_num = 0;
#ifdef CONFIG_DATA_STACK_WINDOW
	e2k_cr1_t prev_cr1;
	bool show_k_data_stack = !!regs->base_k_data_stack;
	int pt_regs_num = 0;
	void *base_k_data_stack = regs->base_k_data_stack;
	u64 size_k_data_stack = regs->size_k_data_stack;
#endif
	int last_user_windows = 2;
	int i;
	int timeout = is_prototype() ? 150000 : 30000;
	bool is_guest = false;

	if (!regs->valid) {
		pr_alert(" BUG print_chain_stack pid=%d valid=0\n",
				(task) ? task_pid_nr(task) : -1);
		return;
	}
	if (!regs->base_chain_stack) {
		pr_alert(" BUG could not get task %s (%d) stack registers, stack will not be printed\n",
				task->comm, task_pid_nr(task));
		return;
	}

	if (unlikely(!raw_irqs_disabled()))
		pr_alert("WARNING: print_chain_stack called with enabled interrupts\n");

	/* If task is current, disable NMIs so that interrupts handlers
	 * will not spill our stacks.*/
	disable_nmis = (task == current);
	if (disable_nmis)
		raw_all_irq_save(flags);

	/* sparse cannot follow locking here */
#ifndef __CHECKER__
	/* Try locking the spinlock (with 30 seconds timeout) */
	attempt = 0;
	do {
		if (raw_spin_trylock(&print_stack_lock)) {
			locked = 1;
			break;
		}

		/* Wait for 0.001 second. */
		if (disable_nmis)
			raw_all_irq_restore(flags);
		udelay(1000);
		if (disable_nmis)
			raw_all_irq_save(flags);
	} while (attempt++ < timeout);
#endif

	if (disable_nmis) {
		COPY_STACKS_TO_MEMORY();
	}

	debug_userstack |= (print_window_regs && debug_guest_regs(task));

	if (!regs->ignore_banner) {
#ifdef CONFIG_SMP
		pr_alert("PROCESS: %s, PID: %d, %s: %d, __state: %c %s (0x%x), flags: 0x%x (%s)\n",
			task->comm, task_pid_nr(task),
			get_cpu_type_name(),
			task_cpu(task), task_state_to_char(task),
			task_curr(task) ? "oncpu" : "",
			task->__state, task->flags,
			(task->flags & PF_KTHREAD) ? "Kernel" : "User");
#else /* CONFIG_SMP */
		pr_alert("PROCESS: %s, PID: %d, %s: %d, __state: %c %s (0x%x), flags: 0x%x (%s)\n",
			task->comm, task->pid,
			get_cpu_type_name(),
			task_cpu(task), task_state_to_char(task),
			"",
			task->__state, task->flags,
			(task->flags & PF_KTHREAD) ? "Kernel" : "User");
#endif /* CONFIG_SMP */
	}

	if (!regs->base_psp_stack) {
		pr_alert(" WARNING could not get task %s (%d) procedure stack "
			"registers, register windows will not be printed\n",
			task->comm, task_pid_nr(task));
		show_reg_window = 0;
	} else {
		show_reg_window = show_reg_window && (task == current ||
				print_window_regs || task_curr(task) ||
				debug_guest_regs(task));
	}

	/* Print header */
	if (show_reg_window) {
		pr_alert("  PSP:  base 0x%016llx ind 0x%llx size 0x%llx\n",
				PSP_BASE(regs->psp), PSP_IND(regs->psp),
				PSP_SIZE(regs->psp));
		pr_alert("  PCSP: base 0x%016llx ind 0x%llx size 0x%llx\n",
				PCSP_BASE(regs->pcsp), PCSP_IND(regs->pcsp),
				PCSP_SIZE(regs->pcsp));
		pr_alert("  ---------------------------------------------------------------------\n");
		pr_alert("      IP (hex)     PROCEDURE/FILE(@ Library load address)\n");
		pr_alert("  ---------------------------------------------------------------------\n");
	}

	for (;;) {
		struct thread_info *ti = task_thread_info(task);
		bool kthread = true;

		if (GET_PCS_BASE(&ti->u_hw_stack))
			kthread = false;

		if (kernel_size_chain_stack > 0) {
			orig_chain_base = regs->orig_base_chain_stack_k;
			kernel_size_chain_stack -= SZ_OF_CR;
		} else {
			orig_chain_base = regs->orig_base_chain_stack_u;
		}
		print_ip(get_cr0_ip(crs.cr0), new_chain_base, cr_ind,
			 task, orig_chain_base, &is_guest);

		if (show_reg_window) {
			psp_ind -= crs.cr1.wbs * EXT_4_NR_SZ;

			if (regs->show_trap_regs && trap_num < MAX_USER_TRAPS &&
			    regs->trap[trap_num].valid &&
			    regs->trap[trap_num].frame ==
					orig_chain_base + cr_ind) {
				if (machine.native_iset_ver >= E2K_ISET_V6) {
					pr_alert("      ctpr1 %llx:%llx ctpr2 %llx:%llx ctpr3 %llx:%llx\n",
						 HI(regs->trap[trap_num].ctpr1),
						 LO(regs->trap[trap_num].ctpr1),
						 HI(regs->trap[trap_num].ctpr2),
						 LO(regs->trap[trap_num].ctpr2),
						 HI(regs->trap[trap_num].ctpr3),
						 LO(regs->trap[trap_num].ctpr3));
					pr_alert("      lsr %llx ilcr %llx lsr1 %llx ilcr1 %llx\n",
						 regs->trap[trap_num].lsr,
						 regs->trap[trap_num].ilcr,
						 regs->trap[trap_num].lsr1,
						 regs->trap[trap_num].ilcr1);
				} else if (machine.native_iset_ver == E2K_ISET_V5) {
					pr_alert("      ctpr1 %llx ctpr2 %llx ctpr3 %llx\n",
						 LO(regs->trap[trap_num].ctpr1),
						 LO(regs->trap[trap_num].ctpr2),
						 LO(regs->trap[trap_num].ctpr3));
					pr_alert("      lsr %llx ilcr %llx lsr1 %llx ilcr1 %llx\n",
						 regs->trap[trap_num].lsr,
						 regs->trap[trap_num].ilcr,
						 regs->trap[trap_num].lsr1,
						 regs->trap[trap_num].ilcr1);
				} else {
					pr_alert("      ctpr1 %llx ctpr2 %llx ctpr3 %llx\n",
						 LO(regs->trap[trap_num].ctpr1),
						 LO(regs->trap[trap_num].ctpr2),
						 LO(regs->trap[trap_num].ctpr3));
					pr_alert("      lsr %llx ilcr %llx\n",
						 regs->trap[trap_num].lsr,
						 regs->trap[trap_num].ilcr);
				}
				for (i = 0; i < SBBP_ENTRIES_NUM; i += 4) {
					pr_alert("      sbbp%-2d  0x%-12llx 0x%-12llx 0x%-12llx 0x%-12llx\n",
						 i, regs->trap[trap_num].sbbp[i],
						 regs->trap[trap_num].sbbp[i + 1],
						 regs->trap[trap_num].sbbp[i + 2],
						 regs->trap[trap_num].sbbp[i + 3]);
				}
				++trap_num;
			}
			cur_frame = get_task_stack_frame_type_IP(task,
					crs.cr0, crs.cr1, ignore_ip);
			if (cur_frame != user_frame_type ||
			    regs->show_user_regs || last_user_windows) {
				/* Show a couple of last user windows - usually
				 * there is something useful there */
				if ((cur_frame == user_frame_type) && last_user_windows) {
					--last_user_windows;
				}
				if (kernel_size_psp_stack > 0) {
					orig_psp_base = regs->orig_base_psp_stack_k;
					kernel_size_psp_stack -= crs.cr1.wbs * EXT_4_NR_SZ;
				} else {
					orig_psp_base = regs->orig_base_psp_stack_u;
				}

				pr_alert("    PCSP: 0x%llx,  PSP: 0x%llx/0x%x\n",
					 orig_chain_base + cr_ind,
					 orig_psp_base + psp_ind,
					 crs.cr1.wbs * EXT_4_NR_SZ);

				print_predicates(crs.cr0.pf, crs.cr1);

				if (likely(psp_ind >= 0)) {
					print_reg_window(new_psp_base + psp_ind,
							 crs.cr1.wbs,
							 crs.cr1.wfx, crs.cr1);
				} else if (psp_ind < 0 && cr_ind > 0 &&
					   /* Avoid false warnings for deep recursion */
					   regs->size_psp_stack <=
						ARRAY_SIZE(psp_stack_cache) - 2 * MAX_SRF_SIZE) {
					pr_alert("! Invalid Register Window index (psp.ind) 0x%llx\n",
						 psp_ind);
				}
			}
		}
#ifdef CONFIG_DATA_STACK_WINDOW
		if (show_k_data_stack &&
		    call_from_kernel_mode(crs.cr0, crs.cr1)) {
			u64 k_window_size;
			s64 cur_chain_index;

			/* To find data stack window size we have to
			 * read cr1.hi from current *and* previous frames */
			cur_chain_index = cr_ind;
			do {
				cur_chain_index -= SZ_OF_CR;
				if (cur_chain_index < 0)
					/* This is a thread created with clone
					 * and we have reached the last kernel
					 * frame. */
					break;

				get_kernel_cr1(&prev_cr1, new_chain_base,
					       cur_chain_index);
			} while (!prev_cr1.pm);

			if (cur_chain_index < 0) {
				k_window_size = size_k_data_stack;
			} else {
				k_window_size = cpu_has(CPU_FEAT_V7_CPU_REGS) ?
						get_cr1_ussz(crs.cr1) :
						(get_cr1_ussz(prev_cr1) - get_cr1_ussz(crs.cr1));
				if (k_window_size > size_k_data_stack) {
					/* The stack is suspiciously large */
					k_window_size = size_k_data_stack;
					pr_alert("    This is the last frame or it was not copied fully\n"
						 "The stack is suspiciously large (0x%llx)\n",
						 k_window_size);
					show_k_data_stack = 0;
				}
			}
			print_k_data_stack(regs, &pt_regs_num, (unsigned long)
					   base_k_data_stack, k_window_size);
			base_k_data_stack += k_window_size;
			size_k_data_stack -= k_window_size;
			if (!size_k_data_stack)
				show_k_data_stack = 0;
		}
#endif

		if (cr_ind < SZ_OF_CR)
			break;

		cr_ind -= SZ_OF_CR;

		/*
		 * Last frame is bogus (from execve or clone), skip it.
		 *
		 * For kernel threads there is one more reserved frame
		 * (for start_thread())
		 */
		if ((cr_ind == 0 || cr_ind == SZ_OF_CR && kthread) && (task == current ||
				regs->size_chain_stack < SIZE_CHAIN_STACK))
			break;

		crs = *(e2k_mem_crs_t *) (new_chain_base + cr_ind);
	}

	if (cr_ind < 0)
		pr_alert("INVALID cr_ind SHOULD BE 0\n");

	if (show_reg_window && regs->show_user_regs && regs->gregs_valid) {
		int i;

		pr_alert("  Global registers: bgr.cur = %d, bgr.val = 0x%x\n",
			 regs->gregs.bgr.cur, regs->gregs.bgr.val);
		for (i = 0; i < 32; i += 2) {
			u64 val_lo, val_hi;
			u8 tag_lo, tag_hi;

			load_value_and_tagd(&regs->gregs.g[i + 0].base,
					    &val_lo, &tag_lo);
			load_value_and_tagd(&regs->gregs.g[i + 1].base,
					    &val_hi, &tag_hi);

			if (machine.native_iset_ver < E2K_ISET_V5) {
				pr_alert("       g%-3d: %hhx %016llx %04hx      g%-3d: %hhx %016llx %04hx\n",
					 i, tag_lo, val_lo, (u16) regs->gregs.g[i].ext,
					 i + 1, tag_hi, val_hi, (u16) regs->gregs.g[i + 1].ext);
			} else {
				u64 ext_lo_val, ext_hi_val;
				u8 ext_lo_tag, ext_hi_tag;

				load_value_and_tagd(&regs->gregs.g[i + 0].ext,
						    &ext_lo_val, &ext_lo_tag);
				load_value_and_tagd(&regs->gregs.g[i + 1].ext,
						    &ext_hi_val, &ext_hi_tag);

				pr_alert("       g%-3d: %hhx %016llx   ext: %hhx %016llx\n",
					 i, tag_lo, val_lo, ext_lo_tag, ext_lo_val);
				pr_alert("       g%-3d: %hhx %016llx   ext: %hhx %016llx\n",
					 i + 1, tag_hi, val_hi, ext_hi_tag, ext_hi_val);
			}
		}
	}

	/* sparse cannot follow locking here */
#ifndef __CHECKER__
	if (locked)
		raw_spin_unlock(&print_stack_lock);
	if (disable_nmis)
		raw_all_irq_restore(flags);
#endif
}

static int sim_panic(struct notifier_block *this, unsigned long ev, void *ptr)
{
	if (NATIVE_IS_MACHINE_SIM) {
		kmsg_dump(KMSG_DUMP_PANIC);
		bust_spinlocks(0);
		debug_locks_off();
		console_flush_on_panic(CONSOLE_REPLAY_ALL);
		E2K_LMS_HALT_ERROR(100);
	}
	return 0;
}

static struct notifier_block sim_panic_block = {
	.notifier_call = sim_panic,
};

static int __init sim_panic_init(void)
{
	atomic_notifier_chain_register(&panic_notifier_list, &sim_panic_block);
	return 0;
}
early_initcall(sim_panic_init);

void show_stack(struct task_struct *task, unsigned long *sp, const char *loglvl)
{
	print_stack_frames(task, NULL, 1);
}

static long get_addr_prot(long addr)
{
	struct task_struct *tsk;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	long pgprot;

	tsk = current;
	mm = tsk->mm;
	mmap_read_lock(mm);
	vma = find_vma(mm, addr);
	if (vma == NULL) {
		pgprot = pmd_virt_offset(addr);
		goto end;
	}
	pgprot = pgprot_val(vma->vm_page_prot);

end:	mmap_read_unlock(mm);
	if (vma != NULL)
		print_vma_and_ptes(vma, addr);
	else
		print_kernel_address_ptes(addr);
	return pgprot;
}

#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
static void sys_e2k_print_syscall_times(scall_times_t *times)
{
	e2k_clock_t clock_time, func_time;
	int syscall_num = times->syscall_num;

	pr_info("   System call # %d execution time info:\n", syscall_num);
	clock_time = CALCULATE_CLOCK_TIME(times->start, times->end);
	pr_info("      total execution time \t\t\t\t% 8ld\n", clock_time);
	func_time = CALCULATE_CLOCK_TIME(times->scall_switch,
					 times->scall_done);
	pr_info("      execution time without syscall function \t\t% 8ld\n",
		clock_time - func_time);
	clock_time = CALCULATE_CLOCK_TIME(times->start, times->pt_regs_set);
	pr_info("      pt_regs structure calculation \t\t\t% 8ld\n", clock_time);
	clock_time = CALCULATE_CLOCK_TIME(times->pt_regs_set,
					  times->save_stack_regs);
	pr_info("      stacks registers saving \t\t\t\t% 8ld\n", clock_time);
	clock_time = CALCULATE_CLOCK_TIME(times->save_stack_regs,
					  times->save_sys_regs);
	pr_info("      system registers saving \t\t\t\t% 8ld\n", clock_time);
	clock_time = CALCULATE_CLOCK_TIME(times->save_sys_regs,
					  times->save_stacks_state);
	pr_info("      stacks state saving \t\t\t\t% 8ld\n", clock_time);
	clock_time = CALCULATE_CLOCK_TIME(times->save_stacks_state,
					  times->save_thread_state);
	pr_info("      thread info state saving \t\t\t\t% 8ld\n", clock_time);
	clock_time = CALCULATE_CLOCK_TIME(times->save_thread_state,
					  times->scall_switch);
	pr_info("      time after all savings and before sys func. \t% 8ld\n",
		clock_time);
	pr_info("      syscall function execution time \t\t\t% 8ld\n",
		func_time);
	if (syscall_num == __NR_exit || syscall_num == __NR_execve)
		return;
	clock_time = CALCULATE_CLOCK_TIME(times->scall_done,
					  times->restore_thread_state);
	pr_info("      thread info state restoring \t\t\t% 8ld\n", clock_time);
	clock_time = CALCULATE_CLOCK_TIME(times->restore_thread_state,
					  times->check_pt_regs);
	pr_info("      pt_regs structure checking \t\t\t% 8ld\n", clock_time);
	if (times->signals_num != 0) {
		clock_time = CALCULATE_CLOCK_TIME(times->check_pt_regs,
						  times->do_signal_start);
		pr_info("      time between checking and start signal handling \t% 8ld\n",
			clock_time);
		clock_time = CALCULATE_CLOCK_TIME(times->do_signal_start,
						  times->do_signal_done);
		pr_info("      signal handling time \t\t\t\t% 8ld\n",
			clock_time);
		clock_time = CALCULATE_CLOCK_TIME(times->do_signal_done,
						  times->restore_start);
		pr_info("      time between signal handling and start restoring \t% 8ld\n",
			clock_time);
	} else {
		clock_time = CALCULATE_CLOCK_TIME(times->check_pt_regs,
						  times->restore_start);
		pr_info("      time after checking and before start restoring \t% 8ld\n",
			clock_time);
	}
	clock_time = CALCULATE_CLOCK_TIME(times->restore_start,
					  times->restore_user_regs);
	pr_info("      time of user registers restoring \t\t% 8ld\n",
		clock_time);
	clock_time = CALCULATE_CLOCK_TIME(times->restore_user_regs, times->end);
	pr_info("      time after restoring and before return \t\t% 8ld\n",
		clock_time);
	pr_info("      after sys call PSP.ind 0x%lx + PSHTP 0x%lx\n",
		times->psp_ind, GET_PSHTP_MEM_INDEX(times->pshtp));
	pr_info("      before done:   PSP.ind 0x%lx + PSHTP 0x%lx\n",
		times->psp_ind_to_done, GET_PSHTP_MEM_INDEX(times->pshtp_to_done));
}

static void sys_e2k_print_trap_times(trap_times_t *times)
{
	e2k_clock_t clock_time;
	int tir;

	pr_info("   Trap info start clock 0x%016lx end clock 0x%016lx\n",
		times->start, times->end);
	clock_time = CALCULATE_CLOCK_TIME(times->start, times->end);
	pr_info("      total execution time \t\t\t\t% 8ld\n", clock_time);
	clock_time = CALCULATE_CLOCK_TIME(times->start, times->pt_regs_set);
	pr_info("      pt_regs structure calculation \t\t\t% 8ld\n", clock_time);
	tir = times->nr_TIRs;
	pr_info("      TIRs number %d\n", tir);
	for (; tir >= 0; tir--) {
		pr_info("         TIR[%02d].hi 0x%016lx .lo 0x%016lx\n",
			tir, HI(times->TIRs[tir]), LO(times->TIRs[tir]));
	}
	pr_info("      Total handled trap number %d\n", times->trap_num);
	pr_info("         Procedure stack bounds %s handled: PSP.ind 0x%lx size 0x%lx (PSP.ind 0x%lx + PSHTP 0x%lx)\n",
		(times->ps_bounds) ? "WAS" : "was NOT",
		times->psp.ind, times->psp.size,
		times->psp_ind, GET_PSHTP_MEM_INDEX(times->pshtp));
	pr_info("         Chain procedure stack bounds %s handled: PCSP.ind 0x%lx size 0x%lx\n",
		(times->pcs_bounds) ? "WAS" : "was NOT",
		times->pcsp.ind, times->pcsp.size);
	pr_info("         PSP to done ind 0x%lx size 0x%lx PSHTP 0x%lx\n",
		times->psp_to_done.ind, times->psp_to_done.size,
		GET_PSHTP_MEM_INDEX(times->pshtp_to_done));
	pr_info("         PCSP to done ind 0x%lx size 0x%lx\n",
		times->pcsp_to_done.ind, times->pcsp_to_done.size);
	pr_info("         CTPRs saved   1 : 0x%016lx 2 : 0x%016lx 3 : 0x%016lx\n",
		times->ctpr1, times->ctpr2, times->ctpr3);
	pr_info("         CTPRs to done 1 : 0x%016lx 2 : 0x%016lx 3 : 0x%016lx\n",
		times->ctpr1_to_done, times->ctpr2_to_done, times->ctpr3_to_done);
}

void sys_e2k_print_kernel_times(struct task_struct *task, kernel_times_t *times,
				long times_num, int times_index)
{
	kernel_times_t *cur_times;
	times_type_t type;
	int count;
	int times_count;
	int cur_index;
	unsigned long flags;

	raw_local_irq_save(flags);
	if (times_num >= MAX_KERNEL_TIMES_NUM) {
		times_count = MAX_KERNEL_TIMES_NUM;
		cur_index = times_index;
	} else {
		times_count = times_num;
		cur_index = times_index - times_num;
		if (cur_index < 0)
			cur_index += MAX_KERNEL_TIMES_NUM;
	}
	pr_info("Kernel execution time info, process %d (\"%s\"), records # %d, total events %ld\n",
		task_pid_nr(task), task->comm == NULL ? "NULL" : task->comm,
		times_count, times_num);
	for (count = 0; count < times_count; count++) {
		cur_times = &times[cur_index];
		type = cur_times->type;
		switch (type) {
		case SYSTEM_CALL_TT:
			sys_e2k_print_syscall_times(&cur_times->of.syscall);
			break;
		case TRAP_TT:
			sys_e2k_print_trap_times(&cur_times->of.trap);
			break;
		default:
			pr_info("Unknown kernel times structure type\n");
		}
		cur_index++;
		if (cur_index >= MAX_KERNEL_TIMES_NUM)
			cur_index = 0;
	}
	raw_local_irq_restore(flags);
}
#endif /* CONFIG_KERNEL_TIMES_ACCOUNT */


struct get_cr_args {
	long __user *cr_storage;
	long num;
};

static int __get_cr(e2k_mem_crs_t *frame, unsigned long real_frame_addr,
		unsigned long corrected_frame_addr, chain_write_fn_t write_frame, void *arg)
{
	struct get_cr_args *args = (struct get_cr_args *) arg;

	if (args->num) {
		args->num--;
		return 0;
	}

	if (copy_to_user(args->cr_storage, frame, sizeof(e2k_mem_crs_t))) {
		DebugGC("Unhandled page fault\n");
		return -EFAULT;
	}

	return 1;
}

/*
 * libunwind support.
 * num - user section number in user Procedure Chain stack;
 * cr_storage - storage to put cr0.lo, cr0.hi, cr1.lo, cr1.hi.
 */
static long get_cr(long num, long __user *cr_storage)
{
	struct get_cr_args args;
	long ret;

	DebugGC("get_cr num:0x%lx cr_storage:%px\n", num, cr_storage);

	args.cr_storage = cr_storage;
	args.num = num;

	ret = parse_chain_stack(true, NULL, __get_cr, &args);
	if (IS_ERR_VALUE(ret))
		return ret;

	return 0;
}

static inline void copy_chain_frame_from_user(e2k_mem_crs_t *to,
					   e2k_mem_crs_t *from, u8 cr_mask)
{
	/* Only allowed fields replaced */
	if (cr_mask & 0x1) {
		to->cr0.pf = from->cr0.pf;
	}
	if (cr_mask & 0x2) {
		to->cr0.hi = from->cr0.hi;
	}
	if (cr_mask & 0x4) {
		if (machine.native_iset_ver < E2K_ISET_V6)
			to->cr1.ic = from->cr1.ic;
		to->cr1.ss = from->cr1.ss;
	}
	if (cr_mask & 0x8) {
		to->cr1.wdbl = from->cr1.wdbl;
		to->cr1.br = from->cr1.br;
	}
}

struct copy_chain_args {
	unsigned long buf;
	bool buf_is_user;
	unsigned long start;
	unsigned long end;
	u32 usd_free;
};

static u8 calculate_cr_mask(unsigned long start, unsigned long end,
			    unsigned long corrected_frame_addr)
{
	u8 cr_mask = 0;

	if (range_includes(start, end - start, corrected_frame_addr, 8))
		cr_mask |= 0x1;
	if (range_includes(start, end - start, corrected_frame_addr + 8, 8))
		cr_mask |= 0x2;
	if (range_includes(start, end - start, corrected_frame_addr + 16, 8))
		cr_mask |= 0x4;
	if (range_includes(start, end - start, corrected_frame_addr + 24, 8))
		cr_mask |= 0x8;

	return cr_mask;
}

static int __read_current_chain_stack(e2k_mem_crs_t *frame, unsigned long real_frame_addr,
		unsigned long corrected_frame_addr, chain_write_fn_t write_frame, void *arg)
{
	struct copy_chain_args *args = (struct copy_chain_args *) arg;
	unsigned long start = args->start, end = args->end;
	e2k_mem_crs_t read_frame;

	BUG_ON(frame->cr1.pm);
	if (corrected_frame_addr < start) {
		return 1;
	}
	if (corrected_frame_addr >= end) {
		if (args->usd_free != -1U) {
			/* We prepare chain stack for v6 app */
			/* frame size can't be >= 2**32 for v6 app */
			BUG_ON(frame->cr1.ussz_hi);
			args->usd_free += (frame->cr1.ussz_lo << 4);
		}
		return 0;
	}
	DebugACCVM("Reading frame 0x%lx to 0x%lx (pm %d, wbs 0x%x)\n",
		   corrected_frame_addr, (unsigned long) args->buf,
		   frame->cr1.pm, frame->cr1.wbs);

	args->buf -= SZ_OF_CR;

	memset(&read_frame, 0, SZ_OF_CR);

	/* Not all fields publish to user */
	read_frame.cr0.pf = frame->cr0.pf;
	copy_cr0_ip(read_frame.cr0, frame->cr0);
	read_frame.cr1.ss = frame->cr1.ss;
	read_frame.cr1.wbs = frame->cr1.wbs;
	read_frame.cr1.ic = frame->cr1.ic;
	read_frame.cr1.br = frame->cr1.br;
	read_frame.cr1.wdbl = frame->cr1.wdbl;
	if (args->usd_free != -1U) {
		/* We prepare chain stack for v6 app */
		/* frame size can't be >= 2**32 for v6 app */
		read_frame.cr1.ussz_lo = (args->usd_free >> 4);
		args->usd_free += (frame->cr1.ussz_lo << 4);
		if (cpu_has(CPU_FEAT_V7_CPU_REGS))
			read_frame.cr1.ussz_hi = 0;
	} else {
		read_frame.cr1 = set_cr1_ussz(read_frame.cr1, get_cr1_ussz(frame->cr1));
	}
	/* Always mark kernel's service frames as privileged even
	 * if they actually are not; useful for JITs to distinguish
	 * frames with actual user data. */
	read_frame.cr1.pm = is_trampoline(get_cr0_ip(frame->cr0));

	if (args->buf_is_user) {
		if (copy_to_user((void __user *) args->buf, &read_frame, SZ_OF_CR))
			return -EFAULT;
	} else {
		memcpy((void *) args->buf, &read_frame, SZ_OF_CR);
	}

	return 0;
}

static int __write_current_chain_stack(e2k_mem_crs_t *frame, unsigned long real_frame_addr,
		unsigned long corrected_frame_addr, chain_write_fn_t write_frame, void *arg)
{
	struct copy_chain_args *args = (struct copy_chain_args *) arg;
	unsigned long start = args->start, end = args->end;
	e2k_mem_crs_t user_frame;
	size_t size, offset;
	u8 cr_mask;
	int ret;

	if (corrected_frame_addr + SZ_OF_CR <= start)
		return 1;

	if (corrected_frame_addr >= end || frame->cr1.pm) {
		return 0;
	}

	DebugACCVM("Writing frame 0x%lx to 0x%lx (pm %d, wbs 0x%x)\n",
		   (unsigned long) args->buf, corrected_frame_addr,
		   frame->cr1.pm, frame->cr1.wbs);

	if (start <= corrected_frame_addr && end >= corrected_frame_addr + SZ_OF_CR) {
		cr_mask = 0xf;
		size = 32;
		offset = 0;
	} else {
		cr_mask = calculate_cr_mask(start, end, corrected_frame_addr);
		size = hweight8(cr_mask) * 8;
		offset = (ffs((u32) cr_mask) - 1) * 8;
	}

	args->buf -= size;

	if (args->buf_is_user) {
		if (__copy_from_user((void *) &user_frame + offset,
				(void __user *) args->buf, size))
			return -EFAULT;
	} else {
		memcpy((void *) &user_frame + offset, (void *) args->buf, size);
	}

	copy_chain_frame_from_user(frame, &user_frame, cr_mask);

	ret = write_frame(real_frame_addr, frame);
	if (ret)
		return -EFAULT;

	return 0;
}

static long read_current_chain_stack(void __user *buf,
				     unsigned long src,
				     unsigned long size,
				     int v6_app)
{
	struct copy_chain_args args;
	long ret;

	if (!IS_ALIGNED(src, SZ_OF_CR) || !IS_ALIGNED(size, SZ_OF_CR)) {
		DebugACCVM("src or size is not aligned\n");
		return -EINVAL;
	}

	args.buf = (unsigned long) buf + size;
	args.buf_is_user = true;
	args.start = src;
	args.end = src + size;
	args.usd_free = v6_app ? (USD_IND(current_pt_regs()->stacks.usd) & 0xffffffff) : -1U;

	ret = parse_chain_stack(true, NULL, __read_current_chain_stack, &args);
	if (IS_ERR_VALUE(ret))
		return ret;

	if (src == (unsigned long) GET_PCS_BASE(&current_thread_info()->u_hw_stack)) {
		e2k_mem_crs_t crs;
		memset(&crs, 0, sizeof(crs));
		crs.cr1.pm = 1;
		if (copy_to_user(buf, &crs, SZ_OF_CR))
			return -EFAULT;
	}

	return 0;
}

long write_current_chain_stack(unsigned long dst, unsigned long buf,
		bool buf_is_user, unsigned long size)
{
	struct copy_chain_args args;
	long ret;

	if (!IS_ALIGNED(dst, 8) || !IS_ALIGNED(size, 8)) {
		DebugACCVM("dst or size is not aligned\n");
		return -EINVAL;
	}
	args.buf = buf + size;
	args.buf_is_user = buf_is_user;
	args.start = dst;
	args.end = dst + size;

	ret = parse_chain_stack(true, NULL, __write_current_chain_stack, &args);
	if (IS_ERR_VALUE(ret))
		return ret;

	return 0;
}

struct copy_proc_args {
	unsigned long buf;
	bool buf_is_user;
	void __priv *p_stack;
	s64 size;
	s64 spilled_size;
	unsigned long ps_frame_top;
	int write;
};

static int __copy_current_proc_stack(e2k_mem_crs_t *frame, unsigned long real_frame_addr,
		unsigned long corrected_frame_addr, chain_write_fn_t write_frame, void *arg)
{
	struct copy_proc_args *args = (struct copy_proc_args *) arg;
	unsigned long ps_frame_top = args->ps_frame_top;
	void __priv *p_stack = args->p_stack;
	unsigned long buf = args->buf;
	bool buf_is_user = args->buf_is_user;
	s64 spilled_size = args->spilled_size, size = args->size;
	unsigned long ps_frame_size, copy_bottom, copy_top, len;
	int ret;

	if ((s64) size <= 0)
		return 1;

	WARN_ON(frame->cr1.pm);

	ps_frame_size = frame->cr1.wbs * EXT_4_NR_SZ;

	DebugACCVM("Considering frame under 0x%lx (pm %d), frame size 0x%lx, size 0x%llx\n",
		   ps_frame_top, frame->cr1.pm, ps_frame_size, size);

	if (corrected_frame_addr == (unsigned long) CURRENT_PCS_BASE() + SZ_OF_CR) {
		/* We have reached the end of stack, do the copy */
		ps_frame_top -= ps_frame_size;
	} else {
		if (ps_frame_top > (unsigned long) p_stack) {
			/* Continue batching frames... */
			goto next_frame;
		}
		/* Reached the end of requested area, do the copy */
	}

	copy_top = (unsigned long) p_stack + size;
	copy_bottom = max3(ps_frame_top, (unsigned long) p_stack,
			   (unsigned long) CURRENT_PS_BASE());
	if (copy_top <= copy_bottom) {
		/* Have not reached requested frame yet */
		goto next_frame;
	}

	len = copy_top - copy_bottom;
	if (!args->write) {
		DebugACCVM("Reading 0x%lx bytes from 0x%lx to 0x%llx\n",
			   len, p_stack + size - len, buf + size - len);

		if (spilled_size) {
			s64 copy_size = min((s64) len, spilled_size);

			if (buf_is_user) {
				ret = copy_to_user((void __user *) buf + size - copy_size,
					(void *) PSP_BASE(current_thread_info()->k_psp) +
					 spilled_size - copy_size, copy_size);
				if (ret)
					return ret;
			} else {
				memcpy((void *) buf + size - copy_size,
					(void __force *) PSP_BASE(current_thread_info()->k_psp) +
						 spilled_size - copy_size,
					copy_size);
			}

			args->spilled_size -= copy_size;
			len -= copy_size;
			size -= copy_size;
		}

		if (buf_is_user) {
			if (copy_priv_to_user_tagged((void __user *) buf + size - len,
					p_stack + size - len, len))
				return -EFAULT;
		} else {
			if (copy_from_priv_tagged((void *) buf + size - len,
					p_stack + size - len, len))
				return -EFAULT;
		}
	} else {
		/* Writing user frames to stack */
		DebugACCVM("Writing 0x%lx bytes from 0x%llx to 0x%lx\n",
			   len, buf + size - len, p_stack + size - len);
		if (spilled_size) {
			s64 copy_size = min((s64) len, spilled_size);

			if (buf_is_user) {
				ret = copy_user_to_current_hw_stack((void *)
						PSP_BASE(current_thread_info()->k_psp) +
								spilled_size - copy_size,
						(void __user *) buf + size - copy_size,
						copy_size, NULL, false);
				if (ret)
					return ret;
			} else {
				copy_to_current_hw_stack((void *)
						PSP_BASE(current_thread_info()->k_psp) +
								spilled_size - copy_size,
						(void *) buf + size - copy_size,
						copy_size, false);
			}

			args->spilled_size -= copy_size;
			len -= copy_size;
			size -= copy_size;
		}

		if (buf_is_user) {
			if (copy_user_to_priv_tagged(p_stack + size - len,
					(void __user *) buf + size - len, len))
				return -EFAULT;
		} else {
			if (copy_to_priv_tagged(p_stack + size - len,
					(void *) buf + size - len, len))
				return -EFAULT;
		}
	}

	args->size = size - len;

next_frame:
	args->ps_frame_top -= ps_frame_size;

	return 0;
}


long copy_current_proc_stack(unsigned long buf, bool buf_is_user, void __priv *p_stack,
			     unsigned long size, int write, unsigned long ps_used_top)
{
	struct copy_proc_args args;
	unsigned long ps_spilled_size;
	long ret;

	raw_all_irq_disable();
	/* Dump procedure stack frames to memory */
	if (!write)
		COPY_STACKS_TO_MEMORY();
	raw_all_irq_enable();

	args.buf = buf;
	args.buf_is_user = buf_is_user;
	args.p_stack = p_stack;
	args.size = size;
	args.ps_frame_top = ps_used_top;
	args.write = write;

	ps_spilled_size = PSHTP_MEM_INDEX(current_pt_regs()->stacks.pshtp);
	if (ps_used_top - ps_spilled_size < (unsigned long) p_stack + size) {
		args.spilled_size = (unsigned long) p_stack + size -
				    (ps_used_top - ps_spilled_size);
	} else {
		args.spilled_size = 0;
	}

	ret = parse_chain_stack(true, NULL, __copy_current_proc_stack, &args);
	if (IS_ERR_VALUE(ret))
		return ret;

	return 0;
}

#define modes_to_get_frame_ptr	(		\
	(1 << E2K_READ_CHAIN_STACK) |		\
	(1 << E2K_READ_PROCEDURE_STACK) |	\
	(1 << E2K_READ_CHAIN_STACK_EX) |	\
	(1 << E2K_READ_CHAIN_STACK_NATIVE) |	\
	(1 << E2K_READ_PROCEDURE_STACK_EX) |	\
	(1 << E2K_WRITE_PROCEDURE_STACK_EX) |	\
	(1 << E2K_WRITE_CHAIN_STACK_EX) |	\
	(1 << E2K_GET_CHAIN_STACK_OFFSET)	\
)

#define mode_to_get_frame_ptr(_mode)	((1 << (_mode)) & modes_to_get_frame_ptr)

static long do_access_hw_stacks(unsigned long mode,
				unsigned long long __user *frame_ptr,
				char __user *buf, unsigned long buf_size,
				void __user *real_size, int compat)
{
	struct pt_regs *regs = current_pt_regs();
	unsigned long pcs_base, pcs_used_top, ps_base, ps_used_top;
	unsigned long long frame;
	long ret;
	int v6_app = 0;

	/* Filter out illegal requests immediately. */
	if ((unsigned int) mode >= E2K_SYS_ACCESS_HW_STACKS_MAX) {
		return -EINVAL;
	}
	if (mode_to_get_frame_ptr(mode) && get_user(frame, frame_ptr)) {
		return -EFAULT;
	}

	/*
	 * Calculate stack frame addresses
	 */
	pcs_base = (unsigned long) CURRENT_PCS_BASE();
	ps_base = (unsigned long) CURRENT_PS_BASE();

	pcs_used_top = PCSP_PTR(regs->stacks.pcsp);
	ps_used_top = PSP_PTR(regs->stacks.psp);

	if (mode == E2K_GET_CHAIN_STACK_OFFSET) {
		unsigned long delta, offset;

		/*
		 * IMPORTANT: frame should *not* include pcshtp value,
		 * because then it might point outside of chain stack
		 * window (when setjmp is executing outside of allocated
		 * chain stack window and the next SPILL will cause
		 * a stack overflow exception).
		 */
		if (find_in_old_u_pcs_list(frame, &delta))
			return -ESRCH;

		offset = frame + delta - (u64)pcs_base;

		return put_user(offset, (u64 __user *) real_size);
	}

	if (real_size && (mode == E2K_READ_CHAIN_STACK ||
			  mode == E2K_READ_PROCEDURE_STACK)) {
		unsigned long used_size;

		if (mode == E2K_READ_CHAIN_STACK) {
			used_size = frame - pcs_base;
		} else { /* mode == E2K_READ_PROCEDURE_STACK */
			used_size = frame - ps_base;
		}
		if (compat) {
			ret = put_user(used_size, (u32 __user *) real_size);
		} else {
			ret = put_user(used_size, (u64 __user *) real_size);
		}
		if (ret)
			return -EFAULT;
	}

	switch (mode) {
	case E2K_GET_CHAIN_STACK_SIZE:
		/*
		 * To start unwinding procedure stack obtained by
		 * E2K_READ_PROC_STACK_EX from its top, the user
		 * needs one extra chain stack frame containing
		 * `%cr's related the top function.
		 */
		ret = put_user(pcs_used_top - pcs_base + SZ_OF_CR, (u64 __user *) real_size);
		break;
	case E2K_GET_PROCEDURE_STACK_SIZE:
		ret = put_user(ps_used_top - ps_base, (u64 __user *) real_size);
		break;
	case E2K_READ_CHAIN_STACK:
		/* Old scheme that E2K_READ_CHAIN_STACK used required
		 * manually reading %psp/%pcsp in user and decoding it.
		 * When porting applications to v7 it will be easier to
		 * switch to *_EX versions */
		if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
			return -EPERM;
		}
	case E2K_READ_CHAIN_STACK_EX:
		if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
			v6_app = 1;
		}
	case E2K_READ_CHAIN_STACK_NATIVE:
		if (!access_ok(buf, buf_size))
			return -EFAULT;

		if (mode == E2K_READ_CHAIN_STACK) {
			if (frame < pcs_base || frame > pcs_used_top) {
				return -EAGAIN;
			}
			if (frame - pcs_base > buf_size) {
				return -ENOMEM;
			}
			ret = read_current_chain_stack(buf, pcs_base, frame - pcs_base, v6_app);
		} else { /* mode == E2K_READ_CHAIN_STACK_EX or E2K_READ_CHAIN_STACK_NATIVE */
			if ((pcs_used_top + SZ_OF_CR) - (pcs_base + frame) < buf_size) {
				return -EINVAL;
			}
			ret = read_current_chain_stack(buf, pcs_base + frame, buf_size, v6_app);
		}
		break;
	case E2K_READ_PROCEDURE_STACK:
		/* See comment in E2K_READ_CHAIN_STACK */
		if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
			return -EPERM;
		}
	case E2K_READ_PROCEDURE_STACK_EX:
		if (!access_ok(buf, buf_size))
			return -EFAULT;

#if DEBUG_ACCVM
		dump_stack();
#endif

		if (mode == E2K_READ_PROCEDURE_STACK) {
			if (frame < ps_base || frame > ps_used_top)
				return -EAGAIN;

			if (frame - ps_base > buf_size)
				return -ENOMEM;

			ret = copy_current_proc_stack((unsigned long) buf, true,
					(void __priv *)ps_base,
					frame - ps_base, false, ps_used_top);
		} else { /* mode == E2K_READ_PROCEDURE_STACK_EX */
			if (ps_used_top < (ps_base + frame) + buf_size)
				return -EINVAL;

			ret = copy_current_proc_stack((unsigned long) buf, true,
					(void __priv *)(ps_base + frame),
					buf_size, false, ps_used_top);
		}
		break;
	case E2K_WRITE_CHAIN_STACK_EX:
		if (!access_ok(buf, buf_size))
			return -EFAULT;

		if ((pcs_used_top + SZ_OF_CR) - (pcs_base + frame) < buf_size)
			return -EINVAL;

		ret = write_current_chain_stack(pcs_base + frame,
				(unsigned long) buf, true, buf_size);
		break;
	case E2K_WRITE_PROCEDURE_STACK:
	case E2K_WRITE_PROCEDURE_STACK_EX:
		if (!access_ok(buf, buf_size))
			return -EFAULT;

		if (mode == E2K_WRITE_PROCEDURE_STACK) {
			if (buf_size > ps_used_top - ps_base)
				return -EINVAL;

			ret = copy_current_proc_stack((unsigned long) buf,
					true, (void __priv *)ps_base,
					buf_size, true, ps_used_top);
		} else { /* mode == E2K_WRITE_PROCEDURE_STACK_EX */
			if (ps_used_top < (ps_base + frame) + buf_size)
				return -EINVAL;

			ret = copy_current_proc_stack((unsigned long) buf,
					true, (void __priv *)(ps_base + frame),
					buf_size, true, ps_used_top);
		}
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

SYSCALL_DEFINE5(access_hw_stacks, unsigned long, mode,
		unsigned long long __user *, frame_ptr, char __user *, buf,
		unsigned long, buf_size, void __user *, real_size)
{
	return do_access_hw_stacks(mode, frame_ptr, buf, buf_size,
				   real_size, false);
}

COMPAT_SYSCALL_DEFINE5(access_hw_stacks, unsigned long, mode,
		unsigned long long __user *, frame_ptr, char __user *, buf,
		unsigned long, buf_size, void __user *, real_size)
{
	return do_access_hw_stacks(mode, frame_ptr, buf, buf_size,
				   real_size, true);
}

/*
 * sys_e2k_syswork() is to run different system work from user
 */
asmlinkage long
sys_e2k_syswork(long syswork, long arg2, long arg3, long arg4, long arg5)
{

	long rval = 0;

	if (syswork == FAST_RETURN) /* Using to estimate time needed for entering to OS */
		return rval;

	if (!capable(CAP_SYS_ADMIN))
		goto user_syswork;

	switch (syswork) {
	case PRINT_STACK:
		dump_stack();
		break;
	case GET_ADDR_PROT:
		rval = get_addr_prot(arg2);
		break;
	case PRINT_TASKS:
		/*
		 * Force stacks dump kernel thread to run as soon as we yield:
		 * to do core dump all stacks
		 */
                show_state();
		break;
	case PRINT_REGS:
		DbgESW("PRINT_PT_REGS\n");
		print_cpu_regs((char *) arg2);
		break;
	case START_CLI_INFO:
		#ifdef CONFIG_CLI_CHECK_TIME
			start_cli_info();
		#endif
		rval = 0;
		break;
	case PRINT_CLI_INFO:
		print_cli_info();
		rval = 0;
		break;
	case PRINT_INTERRUPT_INFO:
		print_interrupt_info();
		rval = 0;
		break;
	case CLEAR_INTERRUPT_INFO:
		clear_interrupt_info();
		rval = 0;
		break;
	case STOP_INTERRUPT_INFO:
		stop_interrupt_info();
		rval = 0;
		break;
	case USER_CONTROL_INTERRUPT:
#ifndef CONFIG_USR_CONTROL_INTERRUPTS
		pr_info("The kernel was compiled w/o CONFIG_USR_CONTROL_INTERRUPTS\n");
#else /* CONFIG_USR_CONTROL_INTERRUPTS */
		{
			unsigned long psr;
			arg2 = !!arg2;
			current_thread_info()->flags &= ~_TIF_USR_CONTROL_INTERRUPTS;
			current_thread_info()->flags |= arg2 << TIF_USR_CONTROL_INTERRUPTS;
			if (arg2) {
				psr = (PSR_UIE | PSR_UNMIE | PSR_NMIE | PSR_IE | PSR_SGE);
			} else {
				psr = (PSR_NMIE | PSR_IE | PSR_SGE);
			}
			parse_chain_stack(true, current, correct_psr_register, (void *) psr);
		}
#endif /* CONFIG_USR_CONTROL_INTERRUPTS */
		break;
	default:
		rval = -1;
		goto user_syswork;
	}
	return rval;

user_syswork:
	switch (syswork) {
	case GET_CONTEXT:
		rval = get_cr((long)arg2, (long __user *)arg3);
		break;
	case FLUSH_CMD_CACHES:
		/* Snooping is done by hardware since V3 */
		rval = -EPERM;
		break;
	default:
		rval = ENOSYS;
		break;
	}
	return rval;
}


void nmi_set_hardware_data_breakpoint(struct data_breakpoint_params *params)
{
	set_hardware_data_breakpoint((unsigned long) params->address,
				     params->size, params->write, params->read,
				     params->stop, params->cp_num, 1);
}

/* Special versions of printk() and panic() to use inside of body_of_entry2.c
 * and ttable_entry10_C()i and other functions with disabled data stack.
 *
 * We cannot use functions with variable number of arguments in functions with
 * __interrupt attribute. The attribute makes compiler put all local variables
 * in registers and do not use stack, but these functions pass their parameters
 * through stack and thus conflict with the attribute. So we deceive the
 * compiler: put functions that use stack inside of functions that do not
 * use it. */
notrace void __printk_fixed_args(char *fmt,
				 u64 a1, u64 a2, u64 a3, u64 a4, u64 a5, u64 a6, u64 a7)
{
	printk(fmt, a1, a2, a3, a4, a5, a6, a7);
}

__noreturn notrace void __panic_fixed_args(char *fmt,
					   u64 a1, u64 a2, u64 a3, u64 a4, u64 a5, u64 a6, u64 a7)
{
	panic(fmt, a1, a2, a3, a4, a5, a6, a7);
}

#ifdef CONFIG_TRACING
notrace void ____trace_bprintk_fixed_args(unsigned long ip,
		char *fmt, u64 a1, u64 a2, u64 a3, u64 a4, u64 a5, u64 a6)
{
	__trace_bprintk(ip, fmt, a1, a2, a3, a4, a5, a6);
}
#endif
