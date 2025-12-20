/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Kernel suspend and recovery.
 */

#include <asm/cacheflush.h>
#include <asm/smp.h>
#include <asm/regs_state.h>
#include <asm/p2v/boot_head.h>
#include <asm/boot_recovery.h>
#include <asm/boot_flags.h>
#include <asm/debug_print.h>
#include <asm/time.h>
#include <asm/traps.h>
#include <asm/boot_profiling.h>

#include <asm-l/setup.h>

#include <linux/pci.h>

#include "../../../drivers/pci/pci.h"


#undef	DebugR
#define	DEBUG_RECOVERY_MODE	0	/* system recovery */
#define DebugR(...)		DebugPrint(DEBUG_RECOVERY_MODE ,##__VA_ARGS__)


struct task_struct	*task_to_recover;
struct aligned_task	task_to_restart[NR_CPUS];


/*
 * Recovery the first processor.
 */ 
void recover_kernel(void)
{
	DebugR("recover_kernel() started\n");

	/*
	 * Mark the boot cpu "online" so that it can call console drivers in
	 * printk() and can access its per-cpu storage.
	 */
	init_cpu_online(cpumask_of(smp_processor_id()));

	kernel_trap_mask_init();

	/*
	 * Init spinlocks, taken on S3 entering
	 */
	raw_spin_lock_init(&pci_config_lock);
	raw_spin_lock_init(&pci_lock);

	/*
	 * Recover softreset state. Only after spinlocks init!
	 */
	l_recover_reset_state();

#ifdef CONFIG_BOOT_TRACE
	BOOT_TRACEPOINT("Recovery trace finished");
	stop_boot_trace();
#endif

	/*
	 * Return to caller function to switch to interrupted task on all CPUs
	 */
	DebugR("completed recovery and returns to switch to interrupted tasks\n");
}

static void str_adjust_bootblock(void)
{
	set_bootblock_flags(bootblock_phys,
		RECOVERY_BB_FLAG | NO_READ_IMAGE_BB_FLAG);
}

static noinline void do_restart_system(void (*restart_func)(void *), void *arg)
{
	task_to_recover = current;
	NATIVE_SAVE_TASK_REGS_TO_SWITCH(current);

	str_adjust_bootblock();

#if 0
	/* S3 emulation through softreset */
	extern void e2k_restart(char *cmd);
	e2k_restart(NULL);
#else
	restart_func(arg);
#endif

	/*
	 * Never should be here
	 */
	BUG();
}

void restart_system(void (*restart_func)(void *), void *arg)
{
	void (*volatile restart)(void (*)(void *), void *) = do_restart_system;

	DebugR("System restart started on cpu %d\n", raw_smp_processor_id());

	BUG_ON(num_online_cpus() != 1);
	BUG_ON(preempt_count());

	/*
	 * Use pointer instead of call or LCC will remove all code after
	 * do_restart_system() because of noret attribute of BUG() in
	 * do_restart_system()
	 */
	restart(restart_func, arg);

	/*
	 * kernel returns here after recovery.
	 */
	DebugR("System restart finished on cpu %d\n", raw_smp_processor_id());
}
