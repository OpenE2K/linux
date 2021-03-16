#include <linux/cpu.h>
#include <linux/delay.h>
#include <linux/irq.h>
#include <linux/sched/hotplug.h>

#include <asm/cpu.h>
#include <asm/debug_print.h>
#include <asm/e2k.h>
#include <asm/hw_irq.h>
#include <asm/mmu_regs.h>
#include <asm/nmi.h>
#include <asm/pic.h>
#include <asm/sic_regs.h>
#include <asm/smp.h>
#include <asm/topology.h>


void arch_cpu_idle_dead(void)
{
	unsigned int cpu = raw_smp_processor_id();
	unsigned int cpuid = hard_smp_processor_id();

	/* Make sure idle task is using init_mm */
	idle_task_exit();

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
	unsigned int irq, vector;
	struct irq_desc *desc;
	struct irq_data *data;
	struct irq_chip *chip;

	irq_migrate_all_off_this_cpu();

	if (cpu_has_epic())
		return;

	/*
	 * We can remove mdelay() and then send spuriuous interrupts to
	 * new cpu targets for all the irqs that were handled previously by
	 * this cpu. While it works, I have seen spurious interrupt messages
	 * (nothing wrong but still...).
	 *
	 * So for now, retain mdelay(1) and check the IRR and then send those
	 * interrupts to new targets as this cpu is already offlined...
	 */
	mdelay(1);

	for (vector = FIRST_EXTERNAL_VECTOR; vector < NR_VECTORS; vector++) {
		unsigned int irr;

		if (__this_cpu_read(vector_irq[vector]) < 0)
			continue;

		irr = apic_read(APIC_IRR + (vector / 32 * 0x10));
		if (irr  & (1 << (vector % 32))) {
			irq = __this_cpu_read(vector_irq[vector]);

			desc = irq_to_desc(irq);
			data = irq_desc_get_irq_data(desc);
			chip = irq_data_get_irq_chip(data);
			raw_spin_lock(&desc->lock);
			if (chip->irq_retrigger)
				chip->irq_retrigger(data);
			raw_spin_unlock(&desc->lock);
		}
		__this_cpu_write(vector_irq[vector], -1);
	}
}

/*
 * __cpu_disable runs on the processor to be shutdown.
 */
int __cpu_disable(void)
{
	lock_vector_lock();
	set_cpu_online(raw_smp_processor_id(), false);
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
