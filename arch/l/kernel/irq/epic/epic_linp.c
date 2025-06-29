#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/init.h>
#include <linux/irqchip.h>
#include <linux/irqdomain.h>
#include <asm/hw_irq.h>
#include <asm/pic.h>
#include <asm/sic_regs.h>
#include <asm/sic_regs_access.h>

#include <asm/trace/irq_vectors.h>


#include "../pic.h"
#include "epic.h"
#include "io_epic_regs.h"

/*
* Interrupts for e2c3 & e16c:
* - PREPIC error interrupt
* - LINP0 - emergency interrupt from HC
* - LINP1 - IOMMU interrupt
* - LINP2 - Uncore interrupt
* - LINP3 - IPCC interrupt
* - LINP4 - non-emergency interrupt from HC
* - LINP5 - Power Control (PCS) interrupt
*/

static const int linp_regs[] = {
	SIC_prepic_linp0,
	SIC_prepic_linp0 + 1 * 4,
	SIC_prepic_linp0 + 2 * 4,
	SIC_prepic_linp0 + 3 * 4,
	SIC_prepic_linp0 + 4 * 4,
	SIC_prepic_linp0 + 5 * 4,
	SIC_prepic_linp0 + 6 * 4,
	SIC_prepic_linp0 + 7 * 4,
	SIC_prepic_linp0 + 8 * 4,
	SIC_prepic_linp0 + 9 * 4,
	SIC_prepic_linp0 + 10 * 4,
	SIC_prepic_linp0 + 11 * 4,
	SIC_prepic_linp0 + 12 * 4,
	SIC_prepic_linp0 + 13 * 4,
	SIC_prepic_linp0 + 14 * 4,
	SIC_prepic_linp0 + 15 * 4,
	SIC_prepic_linp0 + 16 * 4,
	SIC_prepic_linp0 + 17 * 4,
	SIC_prepic_linp0 + 18 * 4,
	SIC_prepic_linp0 + 19 * 4,
	SIC_prepic_linp0 + 20 * 4,
	SIC_prepic_linp0 + 21 * 4,
	SIC_prepic_linp0 + 22 * 4,
	SIC_prepic_linp0 + 23 * 4,
	SIC_prepic_linp0 + 24 * 4,
	SIC_prepic_linp0 + 25 * 4,
	SIC_prepic_linp0 + 26 * 4,
	SIC_prepic_linp0 + 27 * 4,
	SIC_prepic_linp0 + 28 * 4,
	SIC_prepic_linp0 + 29 * 4,
	SIC_prepic_linp0 + 30 * 4,
	SIC_prepic_linp0 + 31 * 4,
	SIC_prepic_err_int,
};


/* Accessing PREPIC registers */
unsigned int early_prepic_node_read_w(int node, unsigned int reg)
{
	return early_sic_read_node_nbsr_reg(node, reg);
}

void early_prepic_node_write_w(int node, unsigned int reg, unsigned int v)
{
	early_sic_write_node_nbsr_reg(node, reg, v);
}

/* FIXME Use early_sic_read in guest to avoid mas 0x13 reads/writes in guest */
unsigned int prepic_node_read_w(int node, unsigned int reg)
{
	if (paravirt_enabled())
		return early_prepic_node_read_w(node, reg);
	else
		return sic_read_node_nbsr_reg(node, reg);
}

void prepic_node_write_w(int node, unsigned int reg, unsigned int v)
{
	if (paravirt_enabled())
		early_prepic_node_write_w(node, reg, v);
	else
		sic_write_node_nbsr_reg(node, reg, v);
}

static int irq_domain_translate_threecell(struct irq_domain *d,
				 struct irq_fwspec *fwspec,
				 unsigned *out_vector,
				 unsigned long *out_hwirq,
				 unsigned *out_type)
{
	if (WARN(fwspec->param_count != 3, "wrong args number:%d\n", fwspec->param_count))
		return -EINVAL;
	if (WARN_ON(!is_of_node(fwspec->fwnode)))
		return -EINVAL;
	*out_vector = fwspec->param[0];
	*out_hwirq = fwspec->param[1];
	*out_type = fwspec->param[2] & IRQ_TYPE_SENSE_MASK;
	return 0;
}

static void linp_epic_irq_enable(struct irq_data *irqd)
{
	int ret;
	struct msi_msg msg;
	union prepic_linpn reg = {};
	irq_hw_number_t pin = irqd_to_hwirq(irqd);
	int node = irq_data_get_node(irqd);
	int cpu = cpumask_first(cpumask_of_node(node));

	union IO_EPIC_MSG_DATA *data = (void *)&msg.data;

	/* Let the parent dmn compose the MSI message */
	ret = irq_chip_compose_msi_msg(irqd, &msg);
	if (WARN_ON(ret))
		return;

	if (WARN_ON(pin >= ARRAY_SIZE(linp_regs)))
		return;

	cpu = cpu_to_full_cepic_id(cpu);

	reg.dst = cpu;
	reg.vect = data->vector;
	prepic_node_write_w(node, linp_regs[pin], reg.raw);

	irq_chip_enable_parent(irqd);
}

static void linp_epic_irq_disable(struct irq_data *irqd)
{
	union prepic_linpn reg = {};
	int node = irq_data_get_node(irqd);
	irq_hw_number_t pin = irqd_to_hwirq(irqd);

	reg.mask = 1;
	prepic_node_write_w(node, linp_regs[pin], reg.raw);

	irq_chip_disable_parent(irqd);
}

static struct irq_chip linp_epic_chip = {
	.name			= "LINP-EPIC",
	.irq_ack		= irq_chip_ack_parent,
	.irq_enable		= linp_epic_irq_enable,
	.irq_disable		= linp_epic_irq_disable,
	.flags			= IRQCHIP_SKIP_SET_WAKE
};

static int linp_irq_domain_translate(struct irq_domain *dmn,
				    struct irq_fwspec *fwspec,
				    unsigned long *hwirq,
				    unsigned *type)
{
	unsigned vector;
	return irq_domain_translate_threecell(dmn, fwspec, &vector, hwirq, type);
}

static int linp_irqdomain_alloc(struct irq_domain *dmn, unsigned virq,
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
					    &linp_epic_chip, NULL);
	if (ret)
		return ret;
	d = irq_domain_get_irq_data(dmn->parent, virq);
	BUG_ON(!d);
	/* assign vector to parent domain */
	d->hwirq = vector;

	ret = irq_domain_alloc_irqs_parent(dmn, virq, nr_irqs, arg);
	if (ret)
		return ret;

	return ret;
}

static void linp_irqdomain_free(struct irq_domain *dmn, unsigned int virq,
		       unsigned int nr_irqs)
{
	struct irq_data *irqd;
	BUG_ON(nr_irqs != 1);
	irqd = irq_domain_get_irq_data(dmn, virq);
	if (WARN_ON(!irqd))
		return;
	irq_domain_free_irqs_top(dmn, virq, nr_irqs);
}


const struct irq_domain_ops linp_epic_irqdomain_ops = {
	.translate	= linp_irq_domain_translate,
	.alloc		= linp_irqdomain_alloc,
	.free		= linp_irqdomain_free,
};

static int __init
linp_epic_init(struct device_node *np, struct device_node *parent)
{
	int ret;
	struct irq_domain *dmn;
	struct fwnode_handle *fn = of_node_to_fwnode(np);

	dmn = irq_domain_create_linear(fn, ARRAY_SIZE(linp_regs),
				&linp_epic_irqdomain_ops,
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

IRQCHIP_DECLARE(epic, "mcst,epic-linp", linp_epic_init);
