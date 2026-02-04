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
	IPI_ERROR_INTERRUPTS,
	IPI_SPURIOUS_INTERRUPTS,
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
	[IPI_ERROR_INTERRUPTS]	= "ERR Error interrupts",
	[IPI_SPURIOUS_INTERRUPTS] = "SPU Spurious interrupts",
	[IPI_NMI]		= "NMI Non-maskable interrupts"
};

static int ipi_irq_base __ro_after_init;
static const int nr_ipi = NR_IPI;
static struct irq_desc *ipi_desc[MAX_IPI] __ro_after_init;


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

static void (*pic_smp_error_interrupt)(void);
static void (*pic_smp_spurious_interrupt)(void);

void l_kstat_incr_nmi(void)
{
	kstat_incr_irq_this_cpu(ipi_desc[IPI_NMI]->irq_data.hwirq);
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
	case IPI_ERROR_INTERRUPTS:
		pic_smp_error_interrupt();
		break;
	case IPI_SPURIOUS_INTERRUPTS:
		pic_smp_spurious_interrupt();
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
	int ret;

	ipi_irq_base = ipi_base;

	ret = cpuhp_setup_state(CPUHP_AP_IRQ_E2K_SMP_STARTING, "irq/smp:starting",
				pic_smp_starting_cpu, pic_smp_dying_cpu);

	if (WARN(ret < 0, "%pOF: Failed to setup hotplug state: %d\n", np, ret))
		return;
}

static int of_interrupt_name_to_hwirq(struct device_node *np, const char *name)
{
	struct of_phandle_args oirq;
	int ret;

	ret = of_property_match_string(np, "interrupt-names", name);
	if (WARN(ret < 0, "%pOF: %d", np, ret))
		return ret;

	ret = of_irq_parse_one(np, ret, &oirq);
	if (WARN(ret, "%pOF: %d", np, ret))
		return ret;

	if (WARN_ON(oirq.args_count != 2))
		return -ERANGE;

	return oirq.args[0];
}

int __init pic_init_smp(struct irq_domain *dmn,
		struct device_node *np, struct pic_params *p)
{
	int ret;

	pic_smp_error_interrupt = p->pic_smp_error_interrupt;
	pic_smp_spurious_interrupt = p->pic_smp_spurious_interrupt;

	int ipi_base = irq_alloc_descs(-1, 1, MAX_IPI, of_node_to_nid(np));
	if (WARN(ipi_base <= 0, "%pOF: %d", np, ipi_base))
		return ipi_base;

	for (int ipi = 0; ipi < MAX_IPI; ipi++) {
		/* NMI vector is fixed so does not appear in device tree list */
		int hwirq = (ipi == IPI_NMI) ? NMI_VECTOR
					     : of_interrupt_name_to_hwirq(np, ipi_types[ipi]);
		if (hwirq < 0)
			continue;

		int swirq = ipi_base + ipi;

		ret = irq_domain_associate(dmn, swirq, hwirq);
		if (WARN(ret, "%pOF: %d", np, ret))
			return ret;

		ret = request_percpu_irq(swirq, ipi_handler, ipi_types[ipi], &cpu_to_picid);
		if (WARN(ret, "%pOF: %d %d", np, swirq, ret))
			return ret;
		ipi_desc[ipi] = irq_to_desc(swirq);
	}

	set_smp_ipi_range(np, ipi_base, MAX_IPI);

	irq_move_cleanup_vector = ipi_desc[IPI_IRQ_MOVE_CLEANUP]->irq_data.hwirq;
	p->error_interrupts_vector = (ipi_desc[IPI_ERROR_INTERRUPTS])
			? ipi_desc[IPI_ERROR_INTERRUPTS]->irq_data.hwirq
			: -1;
	p->spurious_interrupts_vector = (ipi_desc[IPI_SPURIOUS_INTERRUPTS])
			? ipi_desc[IPI_SPURIOUS_INTERRUPTS]->irq_data.hwirq
			: -1;
	return 0;
}
