/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */
#include <linux/bug.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/kernel_stat.h>
#include <linux/export.h>
#include <linux/percpu.h>
#include <linux/types.h>
#include <linux/cpu.h>
#include <linux/irq.h>
#include <linux/irq_work.h>
#include <linux/irqdomain.h>
#include <linux/of_irq.h>
#include "pic.h"

int irq_move_cleanup_vector;

enum ipi_msg_type {
	IPI_RESCHEDULE,
	IPI_CALL_FUNC,
	IPI_IRQ_WORK,
	IPI_IRQ_MOVE_CLEANUP,
	NR_IPI,
	/* NMI is special and not included in NR_IPI */
	IPI_NMI = NR_IPI, /* NMI Non-maskable interrupt */
	MAX_IPI,
};


static const char *ipi_types[MAX_IPI] = {
	[IPI_RESCHEDULE]	= "RES Rescheduling interrupts",
	[IPI_CALL_FUNC]		= "CAL Function single call interrupts",
	[IPI_IRQ_WORK]		= "IWI IRQ work interrupts",
	[IPI_IRQ_MOVE_CLEANUP]	= "IMI IRQ move cleanup interrupts",
	[IPI_NMI]		= "NMI Non-maskable interrupts"
};

static int ipi_irq_base __read_mostly;
static int nr_ipi __read_mostly = NR_IPI;
static struct irq_desc *ipi_desc[MAX_IPI] __read_mostly;


static int smp_cross_call(const struct cpumask *target, unsigned int ipinr)
{
	return __ipi_send_mask(ipi_desc[ipinr], target);
}

int pic_send_nmi(const struct cpumask *target)
{
	return smp_cross_call(target, IPI_NMI);
}

int pic_send_cleanup_vector(const struct cpumask *target)
{
	return smp_cross_call(target, IPI_IRQ_MOVE_CLEANUP);
}
#ifdef CONFIG_IRQ_WORK
void arch_irq_work_raise(void)
{
	smp_cross_call(cpumask_of(smp_processor_id()), IPI_IRQ_WORK);
}
#endif

void arch_send_call_function_ipi_mask(const struct cpumask *mask)
{
	smp_cross_call(mask, IPI_CALL_FUNC);
}

void arch_send_call_function_single_ipi(int cpu)
{
	smp_cross_call(cpumask_of(cpu), IPI_CALL_FUNC);
}

void smp_send_reschedule(int cpu)
{
	smp_cross_call(cpumask_of(cpu), IPI_RESCHEDULE);
}


void irq_force_complete_move(struct irq_desc *desc)
{
	BUG();
}


/*
 * Main handler for inter-processor interrupts
 */
static void do_handle_IPI(int ipinr)
{
	unsigned int cpu = smp_processor_id();

	switch (ipinr) {
	case IPI_RESCHEDULE:
		scheduler_ipi();
		break;
	case IPI_CALL_FUNC:
		generic_smp_call_function_interrupt();
		break;
#ifdef CONFIG_IRQ_WORK
	case IPI_IRQ_WORK:
		irq_work_run();
		break;
#endif
	case IPI_IRQ_MOVE_CLEANUP:
		smp_irq_move_cleanup_interrupt();
		break;
	default:
		pr_crit("CPU%u: Unknown IPI message 0x%x\n", cpu, ipinr);
		break;
	}
}

static irqreturn_t ipi_handler(int irq, void *data)
{
	do_handle_IPI(irq - ipi_irq_base);
	return IRQ_HANDLED;
}

static int pic_smp_dying_cpu(unsigned int cpu)
{
	int i;
	if (WARN_ON_ONCE(!ipi_irq_base))
		return -EINVAL;
	for (i = 0; i < nr_ipi; i++)
		disable_percpu_irq(ipi_irq_base + i);
	return 0;
}

static int pic_smp_starting_cpu(unsigned int cpu)
{
	int i;
	if (WARN_ON_ONCE(!ipi_irq_base))
		return -EINVAL;
	for (i = 0; i < nr_ipi; i++)
		enable_percpu_irq(ipi_irq_base + i, 0);
	return 0;
}

static void __init set_smp_ipi_range(struct device_node *np, int ipi_base, int n)
{
	int i, ret;

	WARN_ON(n < MAX_IPI);
	nr_ipi = min(n, MAX_IPI);

	for (i = 0; i < nr_ipi; i++) {
		int ret = request_percpu_irq(ipi_base + i, ipi_handler,
					 ipi_types[i], &cpu_to_picid);
		if (WARN(ret, "%pOF: %d %d", np, ipi_base + i, ret))
			return;
		ipi_desc[i] = irq_to_desc(ipi_base + i);
	}

	ipi_irq_base = ipi_base;

	ret = cpuhp_setup_state(CPUHP_AP_IRQ_E2K_SMP_STARTING,
				  "irq/smp:starting",
				  pic_smp_starting_cpu, pic_smp_dying_cpu);

	if (WARN(ret < 0, "%pOF: Failed to setup hotplug state: %d\n", np, ret))
		return;
}

int __init pic_init_smp(struct irq_domain *dmn, struct device_node *np)
{
	int i, n, ret, irq;
	n = irq_alloc_descs(-1, 1, MAX_IPI, of_node_to_nid(np));
	if (WARN(n <= 0, "%pOF: %d", np, n))
		return n;

	for (i = 0; i < NR_IPI; i++) {
		struct of_phandle_args oirq;
		ret = of_property_match_string(np, "interrupt-names", ipi_types[i]);
		if (WARN(ret < 0, "%pOF: %d", np, ret))
			return irq;

		ret = of_irq_parse_one(np, ret, &oirq);
		if (WARN(ret, "%pOF: %d", np, ret))
			return ret;

		if (WARN_ON(oirq.args_count != 2))
			return -ERANGE;

		irq = oirq.args[0];
		ret = irq_domain_associate(dmn, n + i, irq);
		if (WARN(ret, "%pOF: %d", np, ret))
			return ret;
	}

	ret = irq_domain_associate(dmn, n + IPI_NMI, NMI_VECTOR);
	if (WARN(ret, "%pOF: %d", np, ret))
		return ret;

	set_smp_ipi_range(np, n, MAX_IPI);
	irq_move_cleanup_vector =
			ipi_desc[IPI_IRQ_MOVE_CLEANUP]->irq_data.hwirq;
	return 0;
}
