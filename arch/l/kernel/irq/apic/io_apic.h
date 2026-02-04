/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _ASM_L_IO_APIC_H
#define _ASM_L_IO_APIC_H

#include <linux/types.h>
#include "apicdef.h"
/*
 * Intel IO-APIC support for SMP and UP systems.
 *
 * Copyright (C) 1997, 1998, 1999, 2000 Ingo Molnar
 */

/*
 * The structure of the IO-APIC:
 */
union IO_APIC_reg_00 {
	u32	raw;
	struct {
		u32	__reserved_2	: 14,
			LTS		:  1,
			delivery_type	:  1,
			__reserved_1	:  8,
			ID		:  8;
	} __attribute__ ((packed)) bits;
};

union IO_APIC_reg_01 {
	u32	raw;
	struct {
		u32	version		:  8,
			__reserved_2	:  7,
			PRQ		:  1,
			entries		:  8,
			__reserved_1	:  8;
	} __attribute__ ((packed)) bits;
};

union IO_APIC_reg_02 {
	u32	raw;
	struct {
		u32	__reserved_2	: 24,
			arbitration	:  4,
			__reserved_1	:  4;
	} __attribute__ ((packed)) bits;
};

union IO_APIC_reg_03 {
	u32	raw;
	struct {
		u32	boot_DT		:  1,
			__reserved_1	: 31;
	} __attribute__ ((packed)) bits;
};

struct IO_APIC_route_entry {
	union {
		struct {
			u64	vector			:  8,
				delivery_mode		:  3,
				dest_mode_logical	:  1,
				delivery_status		:  1,
				active_low		:  1,
				irr			:  1,
				is_level		:  1,
				masked			:  1,
				reserved_0		: 15,
				reserved_1		: 24,
				destid_0_7		:  8;
		};
		struct {
			u64	ir_shared_0		:  8,
				ir_zero			:  3,
				ir_index_15		:  1,
				ir_shared_1		:  5,
				ir_reserved_0		: 31,
				ir_format		:  1,
				ir_index_0_14		: 15;
		};
		struct {
			u64	w1			: 32,
				w2			: 32;
		};
	};
} __attribute__ ((packed));


#endif /* _ASM_L_IO_APIC_H */
