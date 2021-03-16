#ifndef __ASM_IO_APIC_REGS_H
#define __ASM_IO_APIC_REGS_H

#include <asm/types.h>
#include <asm/apicdef.h>


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
		u32	ID		:  8,
			__reserved_1	:  8,
			delivery_type	:  1,
			LTS		:  1,
			__reserved_2	: 14;
	} __attribute__ ((packed)) bits;
};

union IO_APIC_reg_01 {
	u32	raw;
	struct {
		u32	__reserved_1	:  8,
			entries		:  8,
			PRQ		:  1,
			__reserved_2	:  7,
			version		:  8;
	} __attribute__ ((packed)) bits;
};

union IO_APIC_reg_02 {
	u32	raw;
	struct {
		u32	__reserved_1	:  4,
			arbitration	:  4,
			__reserved_2	: 24;
	} __attribute__ ((packed)) bits;
};

union IO_APIC_reg_03 {
	u32	raw;
	struct {
		u32	__reserved_1	: 31,
			boot_DT		:  1;
	} __attribute__ ((packed)) bits;
};

struct IO_APIC_route_entry {
	__u32	__reserved_2	: 15,
		mask		:  1,	/* 0: enabled, 1: disabled */
		trigger		:  1,	/* 0: edge, 1: level */
		irr		:  1,
		polarity	:  1,
		delivery_status	:  1,
		dest_mode	:  1,	/* 0: physical, 1: logical */
		delivery_mode	:  3,	/* 000: FIXED
					 * 001: lowest prio
					 * 111: ExtINT
					 */
		vector		:  8;

	__u32	dest		:  8,
		__reserved_3	: 24;
} __attribute__ ((packed));

struct IR_IO_APIC_route_entry {
	__u64	index		: 15,
		format		: 1,
		reserved	: 31,
		mask		: 1,
		trigger		: 1,
		irr		: 1,
		polarity	: 1,
		delivery_status : 1,
		index2		: 1,
		zero		: 3,
		vector		: 8;
} __attribute__ ((packed));

#endif	/* __ASM_IO_APIC_REGS_H */
