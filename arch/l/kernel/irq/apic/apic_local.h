/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/jump_label.h>
#include "../pic.h"
#include "apic.h"

static inline unsigned int __prepare_ICR(unsigned int shortcut, int vector,
					 unsigned int dest)
{
	unsigned int icr = shortcut | dest;

	switch (vector) {
	default:
		icr |= APIC_DM_FIXED | vector;
		break;
	case NMI_VECTOR:
		icr |= APIC_DM_NMI;
		break;
	}
	return icr;
}

void __default_send_IPI_shortcut(unsigned int shortcut, int vector);

/*
 * This is used to send an IPI with no shorthand notation (the destination is
 * specified in bits 56 to 63 of the ICR).
 */
void __default_send_IPI_dest_field(unsigned int mask, int vector, unsigned int dest);

void default_send_IPI_single(int cpu, int vector);
void default_send_IPI_single_phys(int cpu, int vector);
void default_send_IPI_mask_sequence_phys(const struct cpumask *mask, int vector);
void default_send_IPI_mask_allbutself_phys(const struct cpumask *mask, int vector);
void default_send_IPI_allbutself(int vector);
void default_send_IPI_all(int vector);
void default_send_IPI_self(int vector);
