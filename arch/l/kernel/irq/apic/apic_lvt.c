#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/init.h>
#include <linux/irqchip.h>
#include <linux/irqdomain.h>
#include <asm/hw_irq.h>
#include <asm/pic.h>

#include <asm/trace/irq_vectors.h>

#include "apicdef.h"
#include "apic-msidef.h"
#include "apic.h"
#include "../pic.h"

static int irq_domain_translate_threecell(struct irq_domain *d,
				 struct irq_fwspec *fwspec,
				 unsigned *out_vector,
				 unsigned long *out_hwirq,
				 unsigned *out_type)
{
	if (WARN_ON(fwspec->param_count != 3 || !is_of_node(fwspec->fwnode)))
		return -EINVAL;
	*out_vector = fwspec->param[0];
	*out_hwirq = fwspec->param[1];
	*out_type = fwspec->param[2] & IRQ_TYPE_SENSE_MASK;
	return 0;
}

static void lvt_apic_irq_enable(struct irq_data *d)
{
	/*
	 * Everthing is done in lvt_irq_setup().
	 * We cannot call it here because of warning
	 *  in smp_call_function_single()
	 */
}

static void lvt_apic_irq_disable(struct irq_data *d)
{
	/*
	 * Everthing is done in lvt_irq_setup().
	 * We cannot call it here because of warning
	 *  in smp_call_function_single()
	 */
}

static struct irq_chip lvt_apic_chip = {
	.name			= "LVT-APIC",
	.irq_ack		= irq_chip_ack_parent,
	.irq_enable		= lvt_apic_irq_enable,
	.irq_disable		= lvt_apic_irq_disable,
	.flags			= IRQCHIP_SKIP_SET_WAKE
};

struct lvt_data {
	struct msi_msg msg;
	unsigned reg;
	struct irq_data *irqd;
};

static void lvt_enable(void *info)
{
	unsigned v;
	unsigned apic_id = read_apic_id();
	struct lvt_data *l = info;
	ioapic_msi_msg_data_t *d = (ioapic_msi_msg_data_t *)&l->msg.data;

	irq_chip_enable_parent(l->irqd);
	v = APIC_LVT_LEVEL_TRIGGER | APIC_DM_FIXED |
			d->vector |
			SET_XAPIC_DEST_FIELD(apic_id);
	apic_write(l->reg, v);
}

static void lvt_disable(void *info)
{
	struct lvt_data *l = info;
	apic_write(l->reg, apic_read(l->reg) | APIC_LVT_MASKED);
	irq_chip_disable_parent(l->irqd);
}

static const int lvt_regs[] = {
	APIC_LVTERR,
	APIC_LVT1,
	APIC_LVT2,
	APIC_LVT3,
	APIC_LVT4
};

static int lvt_irq_setup(struct irq_domain *dmn, struct irq_data *irqd,
				smp_call_func_t func)
{
	int ret;
	struct lvt_data l = { .irqd = irqd };
	irq_hw_number_t pin = irqd_to_hwirq(irqd);
	int node = irq_data_get_node(irqd);
	int cpu = cpumask_first(cpumask_of_node(node));

	/* Let the parent dmn compose the MSI message */
	ret = irq_chip_compose_msi_msg(irqd, &l.msg);
	if (WARN_ON(ret))
		return ret;

	if (WARN_ON(pin >= ARRAY_SIZE(lvt_regs)))
		return -EINVAL;
	l.reg = lvt_regs[pin];
	ret = smp_call_function_single(cpu, func, &l, true);
	if (WARN(ret, "cpu%d call failed:%d", cpu, ret))
		return ret;
	return 0;
}

static int lvt_irq_domain_translate(struct irq_domain *dmn,
				    struct irq_fwspec *fwspec,
				    unsigned long *hwirq,
				    unsigned *type)
{
	unsigned vector;
	return irq_domain_translate_threecell(dmn, fwspec, &vector, hwirq, type);
}

static int lvt_irqdomain_alloc(struct irq_domain *dmn, unsigned virq,
		       unsigned nr_irqs, void *arg)
{
	struct irq_fwspec *fwspec = arg;
	struct irq_data *d, *irqd = irq_domain_get_irq_data(dmn, virq);
	int ret;
	unsigned vector;
	irq_hw_number_t pin;
	unsigned type;

	if (!irqd)
		return -EINVAL;

	ret = irq_domain_translate_threecell(dmn, fwspec, &vector, &pin, &type);
	if (ret)
		return ret;
	irq_set_handler_locked(irqd, handle_edge_irq);

	ret = irq_domain_set_hwirq_and_chip(dmn, virq, pin,
					    &lvt_apic_chip, NULL);
	if (ret)
		return ret;
	d = irq_domain_get_irq_data(dmn->parent, virq);
	BUG_ON(!d);
	/* assign vector to parent domain */
	d->hwirq = vector;

	ret = irq_domain_alloc_irqs_parent(dmn, virq, nr_irqs, arg);
	if (ret)
		return ret;

	return lvt_irq_setup(dmn, irqd, lvt_enable);
}

static void lvt_irqdomain_free(struct irq_domain *dmn, unsigned int virq,
		       unsigned int nr_irqs)
{
	struct irq_data *irqd;
	BUG_ON(nr_irqs != 1);
	irqd = irq_domain_get_irq_data(dmn, virq);
	if (WARN_ON(!irqd))
		return;
	lvt_irq_setup(dmn, irqd, lvt_disable);
	irq_domain_free_irqs_top(dmn, virq, nr_irqs);
}


const struct irq_domain_ops lvt_apic_irqdomain_ops = {
	.translate	= lvt_irq_domain_translate,
	.alloc		= lvt_irqdomain_alloc,
	.free		= lvt_irqdomain_free,
};

static int __init
lvt_apic_init(struct device_node *np, struct device_node *parent)
{
	int ret;
	struct irq_domain *dmn;
	struct fwnode_handle *fn = of_node_to_fwnode(np);

	dmn = irq_domain_create_linear(fn, ARRAY_SIZE(lvt_regs),
				&lvt_apic_irqdomain_ops,
				NULL);
	if (!dmn) {
		ret = -ENOMEM;
		goto err;
	}

	dmn->parent = irq_find_host(parent);
	BUG_ON(!dmn->parent);
err:
	return ret;
}

IRQCHIP_DECLARE(apic, "mcst,apic-lvt", lvt_apic_init);
