#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/irqchip.h>
#include <asm/pci.h>

#include "apic.h"
#include "apic_local.h"
#include "apic-msidef.h"
#include "../pic.h"


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

#define MSI_LO_ADDRESS			0x48
#define MSI_HI_ADDRESS			0x4c

static void get_io_apic_msi(int node, u32 *lo, u32 *hi)
{
	if (node < 0)
		node = 0;
	/* Read from i2c-spi controller */
	conf_inl(0, 1,  CONFIG_CMD(1, PCI_DEVFN(2, 1), MSI_LO_ADDRESS), lo);
	conf_inl(0, 1,  CONFIG_CMD(1, PCI_DEVFN(2, 1), MSI_HI_ADDRESS),	hi);
}

static void apic_msi_compose_msg(struct irq_data *irqd,
				       struct msi_msg *msg)
{
	struct irq_cfg *cfg = irqd_cfg(irqd);
	struct pic_chip_data *picd = pic_chip_data(irqd);
	ioapic_msi_msg_addr_lo_t *lo = (ioapic_msi_msg_addr_lo_t *)&msg->address_lo;
	ioapic_msi_msg_data_t *d = (ioapic_msi_msg_data_t *)&msg->data;
	memset(msg, 0, sizeof(*msg));
	get_io_apic_msi(irq_data_get_node(irqd),
			&msg->address_lo, &msg->address_hi);

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
	unsigned vector = irqd_to_hwirq(d);
	int node = irq_data_get_node(d);
	int cpu = irq_is_percpu_devid(d->irq) ?
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

	per_cpu(vector_irq, cpu)[vector] = __setup_vector_irq(vector);
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
	.irq_set_affinity	= pic_set_affinity,
	.irq_compose_msi_msg	= apic_msi_compose_msg,
	.irq_retrigger		= apic_retrigger_irq,

	.irq_enable		= apic_irq_enable,
	.irq_disable		= apic_irq_disable,
	.ipi_send_single	= apic_ipi_send_single,
};
