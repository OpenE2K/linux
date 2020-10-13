
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/irq.h>
#include <linux/signal.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <linux/kernel_stat.h>
#include <linux/proc_fs.h>
#include <linux/random.h>
#include <linux/seq_file.h>
#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/hardirq.h>
#include <linux/ftrace.h>
#include <linux/percpu.h>
#include <linux/delay.h>

#include <asm/e2k_api.h>

#include <asm/machdep.h>
#include <asm/irq.h>
#include <asm/apic.h>
#include <asm/pgalloc.h>
#include <asm/uaccess.h>
#include <asm/e2k_syswork.h>
#include <asm/console.h>
#ifdef	CONFIG_RECOVERY
#include <asm/cnt_point.h>
#endif	/* CONFIG_RECOVERY */

#undef	DEBUG_IRQ_MODE
#undef	DebugIRQ
#define	DEBUG_IRQ_MODE		0	/* interrupts */
#define DebugIRQ(...)		DebugPrint(DEBUG_IRQ_MODE ,##__VA_ARGS__)


void __init init_IRQ(void)
{
	DebugIRQ("init_IRQ entered.\n");

	machine.init_IRQ(0);

	DebugIRQ("init_IRQ exited.\n");
}

#ifdef	CONFIG_RECOVERY
void
recovery_IRQ(void)
{
	DebugIRQ("recovery_IRQ entered.\n");

	machine.init_IRQ(1);

	DebugIRQ("recovery_IRQ exited.\n");
}
#endif	/* CONFIG_RECOVERY */

#ifdef CONFIG_HOTPLUG_CPU
/* A cpu has been removed from cpu_online_mask.  Reset irq affinities. */
void fixup_irqs(void)
{
	unsigned int irq, vector;
	static int warned;
	struct irq_desc *desc;
	struct irq_data *data;
	struct irq_chip *chip;

	for_each_irq_desc(irq, desc) {
		int break_affinity = 0;
		int set_affinity = 1;
		const struct cpumask *affinity;

		if (!desc)
			continue;

		/* interrupt's are disabled at this point */
		raw_spin_lock(&desc->lock);

		data = irq_desc_get_irq_data(desc);
		affinity = data->affinity;
		if (!irq_has_action(irq) || irqd_is_per_cpu(data) ||
		    cpumask_subset(affinity, cpu_online_mask)) {
			raw_spin_unlock(&desc->lock);
			continue;
		}

		/*
		 * Complete the irq move. This cpu is going down and for
		 * non intr-remapping case, we can't wait till this interrupt
		 * arrives at this cpu before completing the irq move.
		 */
		irq_force_complete_move(irq);

		if (cpumask_any_and(affinity, cpu_online_mask) >= nr_cpu_ids) {
			break_affinity = 1;
			affinity = cpu_online_mask;
		}

		chip = irq_data_get_irq_chip(data);
		if (!irqd_can_move_in_process_context(data) && chip->irq_mask)
			chip->irq_mask(data);

		if (chip->irq_set_affinity)
			chip->irq_set_affinity(data, affinity, true);
		else if (!(warned++))
			set_affinity = 0;

		/*
		 * We unmask if the irq was not marked masked by the
		 * core code. That respects the lazy irq disable
		 * behaviour.
		 */
		if (!irqd_can_move_in_process_context(data) &&
		    !irqd_irq_masked(data) && chip->irq_unmask)
			chip->irq_unmask(data);

		raw_spin_unlock(&desc->lock);

		if (break_affinity && set_affinity)
			pr_notice("Broke affinity for irq %i\n", irq);
		else if (!set_affinity)
			pr_notice("Cannot set affinity for irq %i\n", irq);
	}

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
#endif /* CONFIG_HOTPLUG_CPU */
