/*
 * Copyright (C) 2012 MCST Evgeny Kravtsunov <kravtsunov_e@mcst.ru>
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/acpi.h>
#include <linux/cpu.h>
#include <linux/sched.h>

#include <acpi/processor.h>
#include <asm/acpi.h>

/*
 * Initialize bm_flags based on the CPU cache properties
 * On SMP it depends on cache configuration
 * - When cache is not shared among all CPUs, we flush cache
 *   before entering C3.
 * - When cache is shared among all CPUs, we use bm_check
 *   mechanism as in UP case
 *
 * This routine is called only after all the CPUs are online
 */
void acpi_processor_power_init_bm_check(struct acpi_processor_flags *flags,
					unsigned int cpu)
{
	return;
}
EXPORT_SYMBOL(acpi_processor_power_init_bm_check);

int acpi_processor_ffh_cstate_probe(unsigned int cpu,
		struct acpi_processor_cx *cx, struct acpi_power_register *reg)
{
	return 0;
}
EXPORT_SYMBOL_GPL(acpi_processor_ffh_cstate_probe);

void acpi_processor_ffh_cstate_enter(struct acpi_processor_cx *cx)
{
	return;
}
EXPORT_SYMBOL_GPL(acpi_processor_ffh_cstate_enter);

static int __init ffh_cstate_init(void)
{
	return 0;
}

static void __exit ffh_cstate_exit(void)
{
}

arch_initcall(ffh_cstate_init);
__exitcall(ffh_cstate_exit);
