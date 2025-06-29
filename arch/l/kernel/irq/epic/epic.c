#include <linux/kernel.h>
#include <linux/cpu.h>

#include "epic.h"


/* Enable CEPIC debugging from kernel cmdline */
bool epic_debug = false;

bool epic_bgi_mode;

/*
 * EPIC Masked interrupt handling starts with reading CEPIC_VECT_INTA.
 * Value read from CEPIC_VECT_INTA also contains Core Priority bits,
 * which have to be saved to be written to CEPIC_EOI later
 */
int epic_get_vector(void)
{
	union cepic_vect_inta reg;

	reg.raw = epic_read_w(CEPIC_VECT_INTA);

	set_current_epic_core_priority(reg.cpr);

	return reg.vect;
}

/* Core priority is read from CEPIC_VECT_INTA in native_do_interrupt */
void ack_epic_irq(void)
{
	union cepic_eoi reg;

	reg.raw = 0;
	reg.rcpr = get_current_epic_core_priority();
	epic_write_w(CEPIC_EOI, reg.raw);
}

#ifdef CONFIG_SMP
bool epic_check_vector_to_be_cleaned(unsigned vector)
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
	irr = epic_read_w(CEPIC_PMIRR + vector / 32 * 0x4);
	if (irr & (1U << (vector % 32))) {
		epic_send_IPI_self(irq_move_cleanup_vector);
		return true;
	}
	return false;
}
#endif
/*
 * E2K depends on the "hard" cpu number to determine NUMA node,
 * so we must exclude the influence of the order in which all
 * processors get here.
 */
int epic_processor_info(int epicid, int version, unsigned int cepic_freq)
{
	unsigned int bsp_id = read_epic_id();
	bool boot_cpu_detected = physid_isset(bsp_id, phys_cpu_present_map);
	int cpu;
	static unsigned int epic_num_processors;

	boot_cpu_physical_apicid = bsp_id;

	/*
	 * If boot cpu has not been detected yet, then only allow upto
	 * nr_cpu_ids - 1 processors and keep one slot free for boot cpu
	 */
	if (!boot_cpu_detected && epic_num_processors >= nr_cpu_ids - 1 &&
	    epicid != bsp_id) {
		pr_warn("NR_CPUS=%d limit was reached", nr_cpu_ids);
		pr_warn("Ignoring CPU#%d to keep a slot for boot CPU", epicid);
		return -EEXIST;
	}

	if (epic_num_processors >= nr_cpu_ids) {
		pr_warn("NR_CPUS=%d limit was reached", nr_cpu_ids);
		pr_warn("Ignoring CPU#%d", epicid);
		return -EOVERFLOW;
	}

	epic_num_processors++;

	if (epicid == boot_cpu_physical_apicid) {
		/* Logical cpuid 0 is reserved for BSP. */
		cpu = 0;
		cpuid_to_picid[0] = epicid;
	} else {
		cpu = allocate_logical_cpuid(epicid);
	}

	if (epicid >= MAX_PHYSID_NUM)
		panic("EPIC id from MP table exceeds %d\n", MAX_PHYSID_NUM);

	physid_set(epicid, phys_cpu_present_map);

	early_per_cpu(cpu_to_picid, cpu) = epicid;

	set_cpu_possible(cpu, true);
	set_cpu_present(cpu, true);

	return cpu;
}

static int __init epic_set_bgi_mode(char *arg)
{
	epic_bgi_mode = true;
	return 0;
}
early_param("epic_bgi_mode", epic_set_bgi_mode);
