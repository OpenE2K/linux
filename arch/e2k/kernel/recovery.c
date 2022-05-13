/*
 * arch/e2k/kernel/recovery.c
 *
 * Kernel suspend and recovery.
 *
 * Copyright (C) 2016 Pavel V. Panteleev (panteleev_p@mcst.ru)
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


#undef	DebugR
#define	DEBUG_RECOVERY_MODE	0	/* system recovery */
#define DebugR(...)		DebugPrint(DEBUG_RECOVERY_MODE ,##__VA_ARGS__)


static DEFINE_RAW_SPINLOCK(restart_lock);

#ifdef CONFIG_SMP
static unsigned int	max_cpus_to_recover = NR_CPUS;
#endif	/* CONFIG_SMP */
struct task_struct	*task_to_recover;

struct aligned_task	task_to_restart[NR_CPUS];


#ifdef CONFIG_SMP
/* Called by boot processor to recover the rest. */
static void
smp_recovery(void)
{
	unsigned int i;
	unsigned int j = 1;

	/* Get other processors into their bootup holding patterns. */
	for (i = 0; i < NR_CPUS; i++) {
		if (num_online_cpus() >= max_cpus_to_recover)
			break;
		if (cpu_possible(i) && !cpu_online(i)) {
			cpu_recover(i);
			j++;
		}
	}

	pr_warn("Recover up %u CPUs\n", j);

	smp_cpus_recovery_done(max_cpus_to_recover);
}
#endif

/*
 * Recovery the first processor.
 * Same as function start_kernel() only to recover kernel state,
 * timers, BUS controllers, IO controllers, drivers, etc...
 */ 
void
recover_kernel(void)
{
	DebugR("started\n");

	/*
	 * Interrupts should be still disabled. Do necessary setups,
	 * interrupts will be enabled after switching to interrupted
	 * tasks on all CPUs
	 */

	/*
	 * Mark the boot cpu "online" so that it can call console drivers in
	 * printk() and can access its per-cpu storage.
	 */
#ifdef CONFIG_SMP
	smp_prepare_boot_cpu_to_recover();
#else
	init_cpu_online(cpumask_of(smp_processor_id()));
#endif

	kernel_trap_mask_init();

#ifdef	CONFIG_SMP
	/*
	 * Recover SMP mode and other CPUs
	 */
	DebugR("will start smp_prepare_cpus_to_recover()\n");
	smp_prepare_cpus_to_recover(max_cpus_to_recover);
#endif	/* CONFIG_SMP */

#ifdef CONFIG_SMP
	DebugR("will start smp_recovery()\n");
	smp_recovery();
	DebugR("completed SMP recovery\n");
#endif

	/*
	 * Return to caller function to switch
	 * to interrupted task on all CPUs
	 */
	DebugR("completed recovery and returns to "
		"switch to interrupted tasks\n");
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

	local_write_back_cache_all();

	restart_func(arg);

	/*
	 * Never should be here
	 */
	BUG();
}

int restart_system(void (*restart_func)(void *), void *arg)
{
	void (*volatile restart)(void (*)(void *), void *) = do_restart_system;
	unsigned long flags;

	DebugR("System restart started on cpu %d\n", raw_smp_processor_id());

	if (num_online_cpus() != 1) {
		DebugR("Not only one cpu is online\n");
		return -EBUSY;
	}

	if (!raw_spin_trylock_irqsave(&restart_lock, flags)) {
		DebugR("Restart system already in progress\n");
		return -EBUSY;
	}

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

	raw_spin_unlock_irqrestore(&restart_lock, flags);

	return 0;
}
