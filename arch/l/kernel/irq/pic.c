/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/kernel.h>
#include <linux/cpu.h>

#include <asm/pic.h>

#include "pic.h"
#include "apic/apic.h"
#include "epic/epic.h"

/*
 * Map cpu index to physical APIC ID
 */
DEFINE_EARLY_PER_CPU_READ_MOSTLY(u16, cpu_to_picid, BAD_APICID);


/*
 * Bitmask of physically existing CPUs:
 */
physid_mask_t phys_cpu_present_map;

DEFINE_PER_CPU(long long, next_rt_intr) = 0;
DEFINE_PER_CPU(long long, must_do_timer) = 0;


/* Processor that is doing the boot up */
unsigned int boot_cpu_physical_apicid = -1U;
EXPORT_SYMBOL_GPL(boot_cpu_physical_apicid);


/* Have we found an MP table */
int smp_found_config;


unsigned int read_pic_id(void)
{
	if (cpu_has_epic())
		return read_epic_id();
	else
		return read_apic_id();
}

int pic_get_vector(void)
{
	if (cpu_has_epic())
		return epic_get_vector();
	else
		return apic_get_vector();
}

void ack_pic_irq(void)
{
	if (cpu_has_epic())
		ack_epic_irq();
	else
		ack_APIC_irq();
}

void __init pic_processor_info(int picid, int picver, unsigned int freq)
{
	int cpu;
	if (cpu_has_epic())
		cpu = epic_processor_info(picid, picver, freq);
	else
		cpu = generic_processor_info(picid, picver);
	early_map_cpu_to_node(cpu, early_cpu_to_node(cpu));
}

bool read_pic_bsp(void)
{
	if (cpu_has_epic())
		return read_epic_bsp();
	else
		return !!BootStrap(apic_read(APIC_BSP));
}

u32 apic_default_calc_apicid(unsigned int cpu)
{
	return per_cpu(cpu_to_picid, cpu);
}

#ifdef CONFIG_SMP
bool pic_check_vector_to_be_cleaned(unsigned vector)
{
	if (cpu_has_epic())
		return epic_check_vector_to_be_cleaned(vector);
	else
		return apic_check_vector_to_be_cleaned(vector);
}
#endif

int pic_get_vector_by_name(struct device_node *np,
		char *path, char *name, int *vec)
{
	int ret;
	u32 v;

	if (!np)
		np = of_find_node_by_path(path);
	else
		of_node_get(np);
	if (!np)
		return -ENODEV;
	ret = name ? of_property_match_string(np, "interrupt-names", name) : 0;
	if (ret < 0)
		goto out;

	ret = of_property_read_u32_index(np, "interrupts", ret * 2, &v);
	if (ret)
		goto out;
	*vec = v;
out:
	of_node_put(np);
	return ret;
}

void fixup_irqs_pic(void)
{
	unsigned int vector;

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

		irr = cpu_has_epic() ? get_irr_epic(vector) : get_irr_apic(vector);
		if (irr  & (1 << (vector % 32))) {
			struct irq_desc *desc = __this_cpu_read(vector_irq[vector]);
			struct irq_data *data = irq_desc_get_irq_data(desc);
			struct irq_chip *chip = irq_data_get_irq_chip(data);

			raw_spin_lock(&desc->lock);
			if (chip->irq_retrigger)
				chip->irq_retrigger(data);
			raw_spin_unlock(&desc->lock);
		}
	}
}
