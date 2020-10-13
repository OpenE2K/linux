/*
 *  $Id: recovery.c,v 1.9 2008/09/18 14:28:31 atic Exp $
 *
 * Architecture-specific recovery
 *
 * Copyright 2001-2003 Salavat S. Guiliazov (atic@mcst.ru)
 *
 */

#include <linux/init.h>
#include <linux/sched.h>

#include <asm/system.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/head.h>
#include <asm/boot_head.h>
#include <asm/cnt_point.h>
#include <asm/cpu_regs_access.h>
#include <asm/mmu_regs.h>
#include <asm/machdep.h>
#include <asm/process.h>
#include <asm/bootinfo.h>
#ifdef	CONFIG_STATE_SAVE
#include <asm/state_save.h>
#endif	/* CONFIG_STATE_SAVE */
#include <asm/e2k_debug.h>

#undef	DEBUG_RECOVERY_MODE
#undef	DebugR
#define	DEBUG_RECOVERY_MODE	0	/* system recovery */
#define DebugR(...)		DebugPrint(DEBUG_RECOVERY_MODE ,##__VA_ARGS__)

extern void	time_recovery(void);

unsigned int	max_cpus_to_recover = NR_CPUS;

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

	printk("Recover up %u CPUs\n", j);

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

	trap_recovery();	/* to enable System Calls for users */
	recovery_IRQ();
	time_recovery();

#ifdef	CONFIG_STATE_SAVE
	e2k_load_state();
#endif	/* CONFIG_STATE_SAVE */

#ifdef	CONFIG_SMP
	/*
	 * Recover SMP mode and other CPUs
	 */
	DebugR("will start smp_prepare_cpus_to_recover()\n");
	smp_prepare_cpus_to_recover(max_cpus_to_recover);
#endif	/* CONFIG_SMP */

#if (CONFIG_CNT_POINTS_NUM != 1)
	switch_control_points();
#endif /* CONFIG_CNT_POINTS_NUM != 1 */

#if (CONFIG_CNT_POINTS_NUM < 2)
	if (dump_analyze_opt)
		init_dump_analyze_mode();
#endif	/* CONFIG_CNT_POINTS_NUM < 2 */

#ifdef CONFIG_SMP
	DebugR("will start smp_recovery()\n");
	smp_recovery();
	DebugR("completed SMP recovery\n");
#endif

	/*
	 * Return to caller function to switch
	 * to interrupted task on all CPUs
	 */

	system_state = SYSTEM_RUNNING;
	DebugR("completed recovery and returns to "
		"switch to interrupted tasks\n");
}
