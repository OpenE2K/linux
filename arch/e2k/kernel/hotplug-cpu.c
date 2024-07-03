/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/cpu.h>
#include <linux/delay.h>
#include <linux/irq.h>
#include <linux/sched/hotplug.h>

#include <asm/cpu.h>
#include <asm/e2k.h>
#include <asm/pic.h>
#include <asm/smp.h>

#include <asm-l/io_pic.h>

void arch_cpu_idle_dead(void)
{
	unsigned int cpu = raw_smp_processor_id();
	unsigned int cpuid = hard_smp_processor_id();

	/* Make sure idle task is using init_mm */
	idle_task_exit();

	/* Flush cache since this CPU might be powered down (e.g. S3) */
	local_write_back_cache_all();

	/* Tell __cpu_die() that this CPU is now safe to dispose of */
	(void)cpu_report_death();

	/* Unplug cpu and wait for a plug */
	wait_for_startup(cpuid, true);
	WARN_ON_ONCE(!physid_isset(cpuid, phys_cpu_present_map));

	/* If we return, we re-enter start_secondary */
	start_secondary_resume(cpuid, cpu);
}

/* A cpu has been removed from cpu_online_mask.  Reset irq affinities. */
static void fixup_irqs(void)
{
	irq_migrate_all_off_this_cpu();
	fixup_irqs_pic();
}

/*
 * __cpu_disable runs on the processor to be shutdown.
 */
int __cpu_disable(void)
{
	unsigned int cpu = smp_processor_id();

	lock_vector_lock();
	set_cpu_online(cpu, false);
	numa_remove_cpu(cpu);
	unlock_vector_lock();

	fixup_irqs();

	return 0;
}

void __cpu_die(unsigned int cpu)
{
	if (!cpu_wait_death(cpu, 5)) {
		pr_err("CPU %u didn't die...\n", cpu);
		return;
	}

	pr_info("CPU %u is now offline\n", cpu);
}
