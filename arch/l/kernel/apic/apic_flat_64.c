/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 *
 * Flat APIC subarch code.
 */

#include <linux/errno.h>
#include <linux/threads.h>
#include <linux/cpumask.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/ctype.h>
#include <linux/hardirq.h>
#include <linux/export.h>
#include <asm/smp.h>
#include <asm/apic.h>
#include <asm-l/ipi.h>

#include <linux/acpi.h>

static struct apic apic_physflat;

struct apic __read_mostly *apic = &apic_physflat;
EXPORT_SYMBOL_GPL(apic);


static notrace_on_host unsigned int flat_get_apic_id(unsigned long x)
{
	unsigned int id;

	id = (((x)>>24) & 0xFFu);

	return id;
}

static unsigned int read_xapic_id(void)
{
	unsigned int id;

	id = flat_get_apic_id(apic_read(APIC_ID));
	return id;
}

static int flat_apic_id_registered(void)
{
	return physid_isset(read_xapic_id(), phys_cpu_present_map);
}

/*
 * Physflat mode is used when there are more than 8 CPUs on a system.
 * We cannot use logical delivery in this case because the mask
 * overflows, so use physical mode.
 */
static int physflat_acpi_madt_oem_check(char *oem_id, char *oem_table_id)
{
#ifdef CONFIG_ACPI
	/*
	 * Quirk: some machines can only use physical APIC mode regardless of how many processors
	 * are present.
	 */
	if (acpi_gbl_FADT.header.revision >= FADT2_REVISION_ID &&
		(acpi_gbl_FADT.flags & ACPI_FADT_APIC_PHYSICAL)) {
		printk(KERN_DEBUG "system APIC only can use physical flat");
		return 1;
	}

	if (!strncmp(oem_id, "IBM", 3) && !strncmp(oem_table_id, "EXA", 3)) {
		printk(KERN_DEBUG "IBM Summit detected, will use apic physical");
		return 1;
	}
#endif

	return 0;
}

static void physflat_send_IPI_mask(const struct cpumask *cpumask, int vector)
{
	default_send_IPI_mask_sequence_phys(cpumask, vector);
}

static void physflat_send_IPI_mask_allbutself(const struct cpumask *cpumask,
					      int vector)
{
	default_send_IPI_mask_allbutself_phys(cpumask, vector);
}

static void physflat_send_IPI_allbutself(int vector)
{
	default_send_IPI_mask_allbutself_phys(cpu_online_mask, vector);
}

static void physflat_send_IPI_all(int vector)
{
	physflat_send_IPI_mask(cpu_online_mask, vector);
}

static int physflat_probe(void)
{
	/*
	 * On e90s and e2k machines flat logical addresation is
	 * not supported (bug #35585, bug #57594) so use physflat.
	 *
	 * IMPORTANT! There is another bug on some APICs: if
	 * interrupts arrive on non-boot CPU we might lose them.
	 * Physical addressation by default delivers all interrupts
	 * to the boot CPU, but logical flat addressation requires
	 * an explicit workaround. (bugs #46675, #48128)
	 */
	return 1;
}

static struct apic apic_physflat =  {

	.name				= "physical flat",
	.probe				= physflat_probe,
	.acpi_madt_oem_check		= physflat_acpi_madt_oem_check,
	.apic_id_registered		= flat_apic_id_registered,

	.irq_delivery_mode		= dest_Fixed,
	.irq_dest_mode			= 0, /* physical */

	.target_cpus			= online_target_cpus,
	.dest_logical			= 0,
	.check_apicid_used		= default_check_apicid_used,

	.vector_allocation_domain	= default_vector_allocation_domain,

	.ioapic_phys_id_map		= default_ioapic_phys_id_map,
	.apicid_to_cpu_present		= physid_set_mask_of_physid,
	.check_phys_apicid_present	= default_check_phys_apicid_present,

	.get_apic_id			= flat_get_apic_id,
	.apic_id_mask			= 0xFFu << 24,

	.cpu_mask_to_apicid_and		= default_cpu_mask_to_apicid_and,

	.send_IPI_mask			= physflat_send_IPI_mask,
	.send_IPI_mask_allbutself	= physflat_send_IPI_mask_allbutself,
	.send_IPI_allbutself		= physflat_send_IPI_allbutself,
	.send_IPI_all			= physflat_send_IPI_all,
	.send_IPI_self			= apic_send_IPI_self,

	.read				= native_apic_mem_read,
	.write				= native_apic_mem_write,
	.eoi_write			= native_apic_mem_write,
	.icr_read			= native_apic_icr_read,
	.icr_write			= native_apic_icr_write,
	.wait_icr_idle			= native_apic_wait_icr_idle,
	.safe_wait_icr_idle		= native_safe_apic_wait_icr_idle,
};
apic_driver(apic_physflat);
