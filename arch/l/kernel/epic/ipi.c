/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/delay.h>
#include <linux/kernel_stat.h>

#include <asm/epic.h>

/*
 * The following functions deal with sending EPIC IPIs between CPUs
 * We use 'broadcast', CPU->CPU IPIs and self-IPIs too
 */
void epic_wait_icr_idle(void)
{
	union cepic_icr reg;

	reg.raw = epic_read_d(CEPIC_ICR);
	while (reg.bits.stat) {
		cpu_relax();
		reg.raw = epic_read_d(CEPIC_ICR);
	}
}

static unsigned int epic_safe_wait_icr_idle(void)
{
	union cepic_icr reg;
	int timeout;

	timeout = 0;
	do {
		reg.raw = epic_read_d(CEPIC_ICR);
		if (!reg.bits.stat)
			break;
		inc_irq_stat(icr_read_retry_count);
		udelay(100);
	} while (timeout++ < 1000);

	return reg.bits.stat;
}

/*
 * Send an IPI to another CPU. Destination is specified in CEPIC_ICR2
 */
void epic_send_IPI(unsigned int dest_cpu, int vector)
{
	union cepic_icr reg;

	/*
	 * Wait if other IPI is currently being delivered
	 */
	if (unlikely(vector == NMI_VECTOR)) {
		if (epic_safe_wait_icr_idle())
			pr_err("ERROR : CEPIC : ICR safe 1 sec wait failed\n");
	} else {
		epic_wait_icr_idle();
	}

	/*
	 * Set destination in CEPIC_ICR2
	 */
	reg.raw = 0;
	reg.bits.dst = cpu_to_full_cepic_id(dest_cpu);

	reg.bits.dst_sh = CEPIC_ICR_DST_FULL;

	if (vector != NMI_VECTOR) {
		reg.bits.dlvm = CEPIC_ICR_DLVM_FIXED_IPI;
		reg.bits.vect = vector;
	} else {
		reg.bits.dlvm = CEPIC_ICR_DLVM_NMI;
	}

	/*
	 * Send the IPI by writing to CEPIC_ICR
	 */
	epic_write_d(CEPIC_ICR, reg.raw);
}

void epic_send_IPI_mask(const struct cpumask *mask, int vector)
{
	unsigned long query_cpu;
	unsigned long flags;

	local_irq_save(flags);
	for_each_cpu(query_cpu, mask) {
		epic_send_IPI(query_cpu, vector);
	}
	local_irq_restore(flags);
}

void epic_send_IPI_mask_allbutself(const struct cpumask *mask, int vector)
{
	unsigned int this_cpu = smp_processor_id();
	unsigned long query_cpu;
	unsigned long flags;

	local_irq_save(flags);
	for_each_cpu(query_cpu, mask) {
		if (query_cpu == this_cpu)
			continue;
		epic_send_IPI(query_cpu, vector);
	}
	local_irq_restore(flags);
}

static inline void epic_send_IPI_shortcut(unsigned int shortcut, int vector)
{
	union cepic_icr reg;

	epic_wait_icr_idle();

	reg.raw = 0;
	reg.bits.dst_sh = shortcut;

	if (vector != NMI_VECTOR) {
		reg.bits.dlvm = CEPIC_ICR_DLVM_FIXED_IPI;
		reg.bits.vect = vector;
	} else {
		reg.bits.dlvm = CEPIC_ICR_DLVM_NMI;
	}

	epic_write_d(CEPIC_ICR, reg.raw);
}

void epic_send_IPI_self(int vector)
{
	epic_send_IPI_shortcut(CEPIC_ICR_DST_SELF, vector);
}
