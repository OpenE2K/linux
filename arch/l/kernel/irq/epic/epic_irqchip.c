#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/irqchip.h>
#include <linux/cpuhotplug.h>
#include <asm/sic_regs.h>
#include <asm/sic_regs_access.h>
#include <asm/pic.h>

#include "../pic.h"
#include "epic.h"
#include "io_epic_regs.h"



static int epic_dying_cpu(unsigned int cpu)
{
	union cepic_ctrl reg_ctrl;
	unsigned long flags;

	local_irq_save(flags);

	/* Disable CEPIC */
	reg_ctrl.raw = epic_read_w(CEPIC_CTRL);
	reg_ctrl.soft_en = 0;
	epic_write_w(CEPIC_CTRL, reg_ctrl.raw);

	local_irq_restore(flags);
	return 0;
}

static int epic_starting_cpu(unsigned int cpu)
{
	union cepic_ctrl reg_ctrl;
	unsigned long flags;

	local_irq_save(flags);

	/* Enable CEPIC */
	reg_ctrl.raw = epic_read_w(CEPIC_CTRL);
	reg_ctrl.soft_en = 1;
	epic_write_w(CEPIC_CTRL, reg_ctrl.raw);

	local_irq_restore(flags);
	return 0;
}

int __init epic_init(struct device_node *np)
{
	int ret;

	ret = cpuhp_setup_state(CPUHP_AP_IRQ_E2K_EPIC_STARTING,
			"epic/:starting",
			epic_starting_cpu, epic_dying_cpu);

	if (WARN(ret < 0, "%pOF: Failed to setup hotplug state: %d\n", np, ret))
		return ret;

	return 0;

}

/* struct irq_chip callbacks */

static int epic_retrigger_irq(struct irq_data *irqd)
{
	struct pic_chip_data *picd = pic_chip_data(irqd);

	lock_vector_lock();
	epic_send_IPI(picd->cpu, picd->vector);
	unlock_vector_lock();

	return 1;
}

static void epic_ack_irq(struct irq_data *irqd)
{
	irq_move_irq(irqd);
	ack_epic_irq();
}

static void epic_ack_edge(struct irq_data *irqd)
{
	irq_complete_move(irqd_cfg(irqd));
	epic_ack_irq(irqd);
}

static inline void get_io_epic_msi(int node, u32 *lo, u32 *hi)
{
	if (node < 0)
		node = 0;
	/* FIXME SIC reads with mas 0x13 aren't supported by hypervisor */
	if (paravirt_enabled()) {
		*lo = early_sic_read_node_nbsr_reg(node, SIC_rt_msi);
		*hi = early_sic_read_node_nbsr_reg(node, SIC_rt_msi_h);
	} else {
		*lo = sic_read_node_nbsr_reg(node, SIC_rt_msi);
		*hi = sic_read_node_nbsr_reg(node, SIC_rt_msi_h);
	}
}

static void epic_msi_compose_msg(struct irq_data *irqd,
				       struct msi_msg *msg)
{
	struct irq_cfg *cfg = irqd_cfg(irqd);
	struct pic_chip_data *picd = pic_chip_data(irqd);
	union IO_EPIC_MSG_ADDR_LOW lo;
	union IO_EPIC_MSG_DATA data;
	u32 hi = 0;

	memset(msg, 0, sizeof(*msg));
	lo.raw = 0;
	BUG_ON(!cpu_has_epic());
	get_io_epic_msi(irq_data_get_node(irqd), &lo.raw, &hi);

	lo.dst = cepic_id_short_to_full(cfg->dest_apicid);

	data.raw = 0;
	data.vector = cfg->vector;

	msg->data = data.raw;
	msg->address_lo = lo.raw;
	msg->address_hi = hi;

	WARN_ON_ONCE(cfg->dest_apicid > 0x3FF);
}

static bool epic_check_sys_vect(unsigned v)
{
	BUG_ON(v > 0x3FF);
	return v < FIRST_EXTERNAL_VECTOR + 1 && v >= FIRST_EPIC_SYSTEM_VECTOR;
}

static void epic_irq_enable(struct irq_data *d)
{
	unsigned vector = irqd_to_hwirq(d);
	int node = irq_data_get_node(d);
	int cpu = irq_is_percpu_devid(d->irq) ?
				smp_processor_id() :
				cpumask_first(cpumask_of_node(node));

	if (!vector && !WARN_ON(epic_check_sys_vect(vector)))
		return;
	WARN_ON(!IS_ERR_OR_NULL(per_cpu(vector_irq, cpu)[vector]));

	per_cpu(vector_irq, cpu)[vector] = irq_data_to_desc(d);
	return;
}

static void epic_irq_disable(struct irq_data *d)
{
	unsigned vector = irqd_to_hwirq(d);
	int node = irq_data_get_node(d);
	int cpu = irq_is_percpu_devid(d->irq) ?
				smp_processor_id() :
				cpumask_first(cpumask_of_node(node));

	if (!vector && !WARN_ON(epic_check_sys_vect(vector)))
		return;
	WARN_ON(IS_ERR_OR_NULL(per_cpu(vector_irq, cpu)[vector]));

	per_cpu(vector_irq, cpu)[vector] = __setup_vector_irq(vector);
}

static void epic_ipi_send_single(struct irq_data *d, unsigned int cpu)
{

	epic_send_IPI(cpu, irqd_to_hwirq(d));
}

struct irq_chip epic_controller = {
	.name			= "EPIC",
	.irq_ack		= epic_ack_edge,
	.irq_set_affinity	= pic_set_affinity,
	.irq_compose_msi_msg	= epic_msi_compose_msg,
	.irq_retrigger		= epic_retrigger_irq,

	.irq_enable		= epic_irq_enable,
	.irq_disable		= epic_irq_disable,
	.ipi_send_single	= epic_ipi_send_single,
};
