/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/perf_event.h>

#include <asm/pic.h>

#include "apic_local.h"

#define ERROR_APIC_VECTOR	0xfe

int nr_ioapics;
int apic_verbosity __ro_after_init;

unsigned long mp_lapic_addr;

void native_apic_wait_icr_idle(void)
{
	while (apic_read(APIC_ICR) & APIC_ICR_BUSY)
		cpu_relax();
}

u32 native_safe_apic_wait_icr_idle(void)
{
	u32 send_status;
	int timeout;

	timeout = 0;
	do {
		send_status = apic_read(APIC_ICR) & APIC_ICR_BUSY;
		if (!send_status)
			break;
		inc_irq_stat(icr_read_retry_count);
		udelay(100);
	} while (timeout++ < 1000);

	return send_status;
}

void native_apic_icr_write(u32 low, u32 id)
{
	unsigned long flags;

	local_irq_save(flags);
	apic_write(APIC_ICR2, SET_XAPIC_DEST_FIELD(id));
	apic_write(APIC_ICR, low);
	local_irq_restore(flags);
}

u64 native_apic_icr_read(void)
{
	u32 icr1, icr2;

	icr2 = apic_read(APIC_ICR2);
	icr1 = apic_read(APIC_ICR);

	return icr1 | ((u64)icr2 << 32);
}


int apic_get_vector(void)
{
	int vector;

	vector = apic_read(APIC_VECT);

	return APIC_VECT_VECTOR(vector);
}

#ifdef CONFIG_SMP
bool apic_check_vector_to_be_cleaned(unsigned vector)
{
	unsigned int irr;
	/*
	* Paranoia: Check if the vector that needs to be cleaned
	* up is registered at the APICs IRR. If so, then this is
	* not the best time to clean it up. Clean it up in the
	* next attempt by sending another IRQ_MOVE_CLEANUP_VECTOR
	* to this CPU. IRQ_MOVE_CLEANUP_VECTOR is the lowest
	* priority external vector, so on return from this
	* interrupt the device interrupt will happen first.
	*/
	irr = apic_read(APIC_IRR + (vector / 32 * 0x10));
	if (irr & (1U << (vector % 32))) {
		default_send_IPI_self(irq_move_cleanup_vector);
		return true;
	}
	return false;
}
#endif

int __init generic_processor_info(int apicid, int version)
{
	int cpu, max = nr_cpu_ids;
	static unsigned int num_processors;
	static unsigned disabled_cpus;
	bool boot_cpu_detected = physid_isset(boot_cpu_physical_apicid,
				phys_cpu_present_map);

	/*
	 * If boot cpu has not been detected yet, then only allow upto
	 * nr_cpu_ids - 1 processors and keep one slot free for boot cpu
	 */
	if (!boot_cpu_detected && num_processors >= nr_cpu_ids - 1 &&
	    apicid != boot_cpu_physical_apicid) {
		int thiscpu = max + disabled_cpus - 1;

		pr_warn(
			"ACPI: NR_CPUS/possible_cpus limit of %i almost"
			" reached. Keeping one slot for boot cpu."
			"  Processor %d/0x%x ignored.\n", max, thiscpu, apicid);

		disabled_cpus++;
		return -ENODEV;
	}

	if (num_processors >= nr_cpu_ids) {
		int thiscpu = max + disabled_cpus;

		pr_warn(
			"ACPI: NR_CPUS/possible_cpus limit of %i reached."
			"  Processor %d/0x%x ignored.\n", max, thiscpu, apicid);

		disabled_cpus++;
		return -EINVAL;
	}

	num_processors++;

	if (apicid == boot_cpu_physical_apicid) {
		/* Logical cpuid 0 is reserved for BSP. */
		cpu = 0;
		cpuid_to_picid[0] = apicid;
	} else {
		cpu = allocate_logical_cpuid(apicid);
	}

	/*
	 * Validate version
	 */
	if (version == 0x0) {
		pr_warn("BIOS bug: APIC version is 0 for CPU %d/0x%x, fixing up to 0x10\n",
			   cpu, apicid);
	}

	physid_set(apicid, phys_cpu_present_map);

	early_per_cpu(cpu_to_picid, cpu) = apicid;

	set_cpu_possible(cpu, true);
	set_cpu_present(cpu, true);

	return cpu;
}

static int __init apic_set_verbosity(char *arg)
{
	if (!arg)  {
		return 0;
	}

	if (strcmp("debug", arg) == 0) {
		apic_verbosity = APIC_DEBUG;
	} else if (strcmp("verbose", arg) == 0) {
		apic_verbosity = APIC_VERBOSE;
	} else {
		pr_warn("APIC Verbosity level %s not recognised use apic=verbose or apic=debug\n",
					arg);
		return -EINVAL;
	}
	return 0;
}
early_param("apic", apic_set_verbosity);

/*
 * Get the maximum number of local vector table entries
 */
int lapic_get_maxlvt(void)
{
	return GET_APIC_MAXLVT(apic_read(APIC_LVR));
}

/*
 * Shutdown the local APIC.
 *
 * This is called, when a CPU is disabled and before rebooting, so the state of
 * the local APIC has no dangling leftovers. Also used to cleanout any BIOS
 * leftovers during boot.
 */
static void clear_local_APIC(void)
{
	int maxlvt;
	u32 v;

	maxlvt = lapic_get_maxlvt();
	/*
	 * Masking an LVT entry can trigger a local APIC error
	 * if the vector is zero. Mask LVTERR first to prevent this.
	 */
	if (maxlvt >= 3) {
		v = ERROR_APIC_VECTOR; /* any non-zero vector will do */
		apic_write(APIC_LVTERR, v | APIC_LVT_MASKED);
	}
	/*
	 * Careful: we have to set masks only first to deassert
	 * any level-triggered sources.
	 */
	v = apic_read(APIC_LVTT);
	apic_write(APIC_LVTT, v | APIC_LVT_MASKED);
	v = apic_read(APIC_LVT0);
	apic_write(APIC_LVT0, v | APIC_LVT_MASKED);
	v = apic_read(APIC_LVT1);
	apic_write(APIC_LVT1, v | APIC_LVT_MASKED);
	if (maxlvt >= 4) {
		v = apic_read(APIC_LVTPC);
		apic_write(APIC_LVTPC, v | APIC_LVT_MASKED);
	}

	/*
	 * Clean APIC state for other OSs:
	 */
	apic_write(APIC_LVTT, APIC_LVT_MASKED);
	apic_write(APIC_LVT0, APIC_LVT_MASKED);
	apic_write(APIC_LVT1, APIC_LVT_MASKED);
	if (maxlvt >= 3)
		apic_write(APIC_LVTERR, APIC_LVT_MASKED);
	if (maxlvt >= 4)
		apic_write(APIC_LVTPC, APIC_LVT_MASKED);

	if (maxlvt > 3) {
		/* Clear ESR due to Pentium errata 3AP and 11AP */
		apic_write(APIC_ESR, 0);
	}
	apic_read(APIC_ESR);
}

/*
 * Clear and disable the local APIC
 */
void disable_local_APIC(void)
{
	unsigned int value;

	clear_local_APIC();

	/*
	 * Disable APIC (implies clearing of registers for 82489DX!).
	 */
	value = apic_read(APIC_SPIV);
	value &= ~APIC_SPIV_APIC_ENABLED;
	apic_write(APIC_SPIV, value);
}

unsigned int get_irr_apic(unsigned int vector)
{
	return apic_read(APIC_IRR + vector / 32 * 0x10);
}
