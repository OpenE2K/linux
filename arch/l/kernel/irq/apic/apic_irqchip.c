/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/irqchip.h>
#include <linux/cpuhotplug.h>
#include <asm/pci.h>
#include <asm/pic.h>

#include "apic.h"
#include "apic_local.h"
#include "apic-msidef.h"
#include "../pic.h"

static int spurious_interrupts_vector;
static int error_interrupts_vector;
/*
 * This interrupt should never happen with our APIC/SMP architecture
 */
void apic_smp_error_interrupt(void)
{
	u32 v;
	u32 i = 0;
	static const char * const error_interrupt_reason[] = {
		"Send CS error",		/* APIC Error Bit 0 */
		"Receive CS error",		/* APIC Error Bit 1 */
		"Send accept error",		/* APIC Error Bit 2 */
		"Receive accept error",		/* APIC Error Bit 3 */
		"Redirectable IPI",		/* APIC Error Bit 4 */
		"Send illegal vector",		/* APIC Error Bit 5 */
		"Received illegal vector",	/* APIC Error Bit 6 */
		"Illegal register address",	/* APIC Error Bit 7 */
	};

	/* First tickle the hardware, only then report what went on. -- REW */
	apic_write(APIC_ESR, 0);
	v = apic_read(APIC_ESR);

	apic_printk(APIC_DEBUG, KERN_DEBUG "APIC error on CPU%d: %02x",
		    smp_processor_id(), v);

	v = v & 0xff;
	while (v) {
		if (v & 0x1)
			apic_printk(APIC_DEBUG, KERN_CONT " : %s", error_interrupt_reason[i]);
		i++;
		v >>= 1;
	}

	apic_printk(APIC_DEBUG, KERN_CONT "\n");
}

/*
 * This interrupt should _never_ happen with our APIC/SMP architecture
 */
void apic_smp_spurious_interrupt(void)
{
	u32 v;

	/*
	 * Check if this really is a spurious interrupt and ACK it
	 * if it is a vectored one.  Just in case...
	 * Spurious interrupts should not be ACKed.
	 */
	v = apic_read(APIC_ISR + ((spurious_interrupts_vector & ~0x1f) >> 1));

	/* see sw-dev-man vol 3, chapter 7.4.13.5 */
	pr_info("spurious APIC interrupt on CPU#%d %x, should never happen.\n",
			v, smp_processor_id());
}

#ifdef CONFIG_SMP
static int apic_retrigger_irq(struct irq_data *irqd)
{
	struct pic_chip_data *picd = pic_chip_data(irqd);
	lock_vector_lock();
	default_send_IPI_single_phys(picd->cpu, picd->vector);
	unlock_vector_lock();

	return 1;
}
#else
# define apic_retrigger_irq NULL
#endif

static void apic_ack_irq(struct irq_data *irqd)
{
	irq_move_irq(irqd);
	ack_APIC_irq();
}

static void apic_ack_edge(struct irq_data *irqd)
{
	irq_complete_move(irqd_cfg(irqd));
	apic_ack_irq(irqd);
}

static void apic_chip_eoi(struct irq_data *irqd)
{
	ack_APIC_irq();
}

static void apic_compose_msi_msg(struct irq_data *irqd,
				       struct msi_msg *msg)
{
	int node = irq_data_get_node(irqd);
	struct irq_cfg *cfg = irqd_cfg(irqd);
	ioapic_msi_msg_addr_lo_t *lo = (void *)&msg->address_lo;
	ioapic_msi_msg_data_t *d = (void *)&msg->data;

	memset(msg, 0, sizeof(*msg));

	/*set address for compatibility with old devtrees */
	get_io_pic_msi(node, &msg->address_lo, &msg->address_hi);

	lo->dest_mode_logical = false;
	lo->destid_0_7 = cfg->dest_apicid & 0xFF;

	d->delivery_mode = APIC_DELIVERY_MODE_FIXED;
	d->vector = cfg->vector;

	WARN_ON_ONCE(cfg->dest_apicid > 0xFF);
}

static bool apic_check_sys_vect(unsigned v)
{
	BUG_ON(v > 0xff);
	return v < FIRST_EXTERNAL_VECTOR && v > FIRST_SYSTEM_VECTOR;
}

static void apic_irq_enable(struct irq_data *d)
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

	if (!vector && !WARN_ON(apic_check_sys_vect(vector)))
		return;

	WARN_ON(!IS_ERR_OR_NULL(per_cpu(vector_irq, cpu)[vector]));

	per_cpu(vector_irq, cpu)[vector] = irq_data_to_desc(d);
	return;
}

static void apic_irq_disable(struct irq_data *d)
{
	unsigned vector = irqd_to_hwirq(d);
	int node = irq_data_get_node(d);
	int cpu = irq_is_percpu_devid(d->irq) ?
				smp_processor_id() :
				cpumask_first(cpumask_of_node(node));

	if (!vector && !WARN_ON(apic_check_sys_vect(vector)))
		return;
	WARN_ON(IS_ERR_OR_NULL(per_cpu(vector_irq, cpu)[vector]));

	per_cpu(vector_irq, cpu)[vector] = VECTOR_UNUSED;
}

#ifdef CONFIG_SMP
static void apic_ipi_send_single(struct irq_data *d, unsigned int cpu)
{
	default_send_IPI_single_phys(cpu, irqd_to_hwirq(d));
}
#else
# define apic_ipi_send_single NULL
#endif

struct irq_chip lapic_controller = {
	.name			= "APIC",
	.irq_ack		= apic_ack_edge,
	.irq_eoi		= apic_chip_eoi,
	.irq_set_affinity	= pic_set_affinity,
	.irq_compose_msi_msg	= apic_compose_msi_msg,
	.irq_retrigger		= apic_retrigger_irq,

	.irq_enable		= apic_irq_enable,
	.irq_disable		= apic_irq_disable,
	.ipi_send_single	= apic_ipi_send_single,
};




static int apic_dying_cpu(unsigned int cpu)
{
	unsigned int value;
	unsigned long flags;

	local_irq_save(flags);

	/* Disable CEPIC */
	value = apic_read(APIC_SPIV);
	value &= ~APIC_SPIV_APIC_ENABLED;
	apic_write(APIC_SPIV, value);

	local_irq_restore(flags);
	return 0;
}

static int apic_starting_cpu(unsigned int cpu)
{
#ifdef CONFIG_MCST
	unsigned int value, acked = 0;
#else
	unsigned int value, acked;
#endif
	unsigned long flags;
	local_irq_save(flags);

	/*
	* If this comes from kexec/kcrash the APIC might be enabled in
	* SPIV. Soft disable it before doing further initialization.
	*/
	value = apic_read(APIC_SPIV);
	value &= ~APIC_SPIV_APIC_ENABLED;
	apic_write(APIC_SPIV, value);

	/*
	* After a crash, we no longer service the interrupts and a pending
	* interrupt from previous kernel might still have ISR bit set.
	*/
	for (int i = APIC_ISR_NR - 1; i >= 0; i--) {
		value = apic_read(APIC_ISR + i*0x10);
		if (!value)
			continue;
		for (int j = 31; j >= 0; j--) {
			if (value & (1<<j)) {
				ack_APIC_irq();
				acked++;
			}
		}
	}

	do {
		value = 0;
		for (int i = APIC_ISR_NR - 1; i >= 0; i--) {
			if ((value = apic_read(APIC_IRR + i*0x10)))
				break;
		}
		if (value) {
			apic_get_vector();
			ack_APIC_irq();
			acked++;
		}
	} while (value && acked <= 256);

	if (acked > 256)
		pr_err("LAPIC pending interrupts after %d EOI\n", acked);

	/*
	 * Set Task Priority to 'accept all'. We never change this
	 * later on.
	 */
	value = apic_read(APIC_TASKPRI);
	value &= ~APIC_TPRI_MASK;
	apic_write(APIC_TASKPRI, value);

	/*
	 * Now that we are all set up, enable the APIC
	 */
	value = apic_read(APIC_SPIV);
	value &= ~APIC_VECTOR_MASK;
	/*
	 * Enable APIC
	 */
	value |= APIC_SPIV_APIC_ENABLED;

	apic_write(APIC_SPIV, value);

	local_irq_restore(flags);
	return 0;
}

int __init apic_init(struct device_node *np, struct pic_params *p)
{
	int ret;

	spurious_interrupts_vector = p->spurious_interrupts_vector;
	error_interrupts_vector = p->error_interrupts_vector;

	ret = cpuhp_setup_state(CPUHP_AP_IRQ_E2K_PIC_STARTING,
			"apic/:starting",
			apic_starting_cpu, apic_dying_cpu);

	if (WARN(ret < 0, "%pOF: Failed to setup hotplug state: %d\n", np, ret))
		return ret;

	return 0;

}
