/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

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


/* Write 0 to CEPIC_ESR before reading it */
void epic_smp_error_interrupt(void)
{
	union cepic_esr reg;

	epic_write_w(CEPIC_ESR, 0);
	reg.raw = epic_read_w(CEPIC_ESR);

	pr_err("EPIC error on CPU%d: 0x%x", smp_processor_id(), reg.raw);

	if (reg.rq_addr_err)
		pr_cont(" : Illegal regsiter address");

	if (reg.rq_virt_err)
		pr_cont(" : Illegal virt request (virt disabled)");

	if (reg.rq_cop_err)
		pr_cont(" : Illegal opcode");

	if (reg.ms_gstid_err)
		pr_cont(" : Illegal guest id");

	if (reg.ms_virt_err)
		pr_cont(" : Illegal virt message (virt disabled)");

	if (reg.ms_err)
		pr_cont(" : Illegal message");

	if (reg.ms_icr_err)
		pr_cont(" : Illegal write to CEPIC_ICR");

	pr_cont("\n");
}

void epic_smp_spurious_interrupt(void)
{
	pr_info("Spurious EPIC interrupt on CPU#%d\n", smp_processor_id());
}


static int spurious_interrupts_vector;
static int error_interrupts_vector;

static int epic_starting_cpu(unsigned int cpu)
{
	unsigned long flags;
	union cepic_ctrl reg_ctrl;
	union cepic_svr reg_svr = {};
	union cepic_esr2 reg_esr2 = {};
	union cepic_cpr reg_cpr = {};
	unsigned int value;

	local_irq_save(flags);

	/*
	 * CPR may contain too high priority after kexec which calls
	 * nmi_call_function before jump.
	 */
	reg_cpr.raw = epic_read_w(CEPIC_CPR);
	reg_cpr.cpr = 0;
	epic_write_w(CEPIC_CPR, reg_cpr.raw);

	/*
	* After a crash, we no longer service the interrupts and a pending
	* interrupt from previous kernel might still have IRR bit set.
	*/

	/* handle PNMIRR */
	epic_read_w(CEPIC_PNMIRR);
	epic_write_w(CEPIC_PNMIRR, CEPIC_PNMIRR_BIT_MASK);

	 /* handle PMIRR */
	reg_svr.raw = epic_read_w(CEPIC_SVR);
	while ((value = epic_get_vector()) != reg_svr.vect)
		ack_epic_irq();

	/* Set up spurious IRQ vector */
	if (spurious_interrupts_vector >= 0) {
		reg_svr.vect = spurious_interrupts_vector;
		epic_write_w(CEPIC_SVR, reg_svr.raw);
	}

	/* Set up Error Status Register */
	if (error_interrupts_vector >= 0) {
		reg_esr2.vect = error_interrupts_vector;
		epic_write_w(CEPIC_ESR2, reg_esr2.raw);
	}

	/* Enable CEPIC */
	reg_ctrl.raw = epic_read_w(CEPIC_CTRL);
	reg_ctrl.soft_en = 1;
	epic_write_w(CEPIC_CTRL, reg_ctrl.raw);

	/*
	 * CIR/PMIRR might have some old interrupts from kexec or suspend
	 */
	int acked = 0;
	while (((union cepic_cir) { .raw = epic_read_w(CEPIC_CIR) }).stat) {
		union cepic_vect_inta vect_inta = {
			.raw = epic_read_w(CEPIC_VECT_INTA),
		};
		union cepic_eoi eoi = {
			.rcpr = vect_inta.cpr,
		};
		epic_write_w(CEPIC_EOI, eoi.raw);

		acked++;
		if (acked > 1024) {
			pr_err("CEPIC pending interrupts after %d EOI\n", acked);
			break;
		}
	}

	local_irq_restore(flags);
	return 0;
}

int __init epic_init(struct device_node *np, struct pic_params *p)
{
	int ret;

	spurious_interrupts_vector = p->spurious_interrupts_vector;
	error_interrupts_vector = p->error_interrupts_vector;

	/*
	 * Don't disable EPIC soft_en on cpu dying: we need ipc sending in cpuhp_report_idle_dead()
	 */
	ret = cpuhp_setup_state(CPUHP_AP_IRQ_E2K_PIC_STARTING,
			"epic/:starting",
			epic_starting_cpu, NULL);

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

static void epic_chip_eoi(struct irq_data *irqd)
{
	ack_epic_irq();
}

static void epic_compose_msi_msg(struct irq_data *irqd,
				       struct msi_msg *msg)
{
	int node = irq_data_get_node(irqd);
	struct irq_cfg *cfg = irqd_cfg(irqd);
	union IO_EPIC_MSG_ADDR_LOW *lo = (void *)&msg->address_lo;
	union IO_EPIC_MSG_DATA *d = (void *)&msg->data;

	BUG_ON(!cpu_has_epic());
	memset(msg, 0, sizeof(*msg));

	/*set address for compatibility with old devtrees */
	get_io_pic_msi(node, &msg->address_lo, &msg->address_hi);

	lo->dst = cepic_id_short_to_full(cfg->dest_apicid);
	d->vector = cfg->vector;

	WARN_ON_ONCE(cfg->dest_apicid > 0x3FF);
}

static bool epic_check_sys_vect(unsigned v)
{
	BUG_ON(v > 0x3FF);
	return v < FIRST_EXTERNAL_VECTOR + 1 || v >= FIRST_EPIC_SYSTEM_VECTOR;
}

static void epic_irq_enable(struct irq_data *d)
{
	int cpu;
	unsigned vector = irqd_to_hwirq(d);
	int node = irq_data_get_node(d);
	int percpu = irq_is_percpu_devid(d->irq);
	if (!percpu && WARN_ON(node < 0))
		return;

	if (!percpu && WARN_ON(!node_online(node)))
		return;
	if (!percpu && cpumask_weight(cpumask_of_node(node)) < 1)
		return;

	cpu = percpu ?
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

	per_cpu(vector_irq, cpu)[vector] = VECTOR_UNUSED;
}

static void epic_ipi_send_single(struct irq_data *d, unsigned int cpu)
{

	epic_send_IPI(cpu, irqd_to_hwirq(d));
}

struct irq_chip epic_controller = {
	.name			= "EPIC",
	.irq_ack		= epic_ack_edge,
	.irq_eoi                = epic_chip_eoi,
	.irq_set_affinity	= pic_set_affinity,
	.irq_compose_msi_msg	= epic_compose_msi_msg,
	.irq_retrigger		= epic_retrigger_irq,
	.irq_enable		= epic_irq_enable,
	.irq_disable		= epic_irq_disable,
	.ipi_send_single	= epic_ipi_send_single,
};
