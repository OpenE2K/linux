#ifndef __ASM_IO_APIC_REGS_H
#define __ASM_IO_APIC_REGS_H

#include <asm/types.h>


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
	__u32	vector		:  8,
		delivery_mode	:  3,	/* 000: FIXED
					 * 001: lowest prio
					 * 111: ExtINT
					 */
		dest_mode	:  1,	/* 0: physical, 1: logical */
		delivery_status	:  1,
		polarity	:  1,
		irr		:  1,
		trigger		:  1,	/* 0: edge, 1: level */
		mask		:  1,	/* 0: enabled, 1: disabled */
		__reserved_2	: 15;

	__u32	__reserved_3	: 24,
		dest		:  8;
} __attribute__ ((packed));

struct IR_IO_APIC_route_entry {
	__u64	vector		: 8,
		zero		: 3,
		index2		: 1,
		delivery_status : 1,
		polarity	: 1,
		irr		: 1,
		trigger		: 1,
		mask		: 1,
		reserved	: 31,
		format		: 1,
		index		: 15;
} __attribute__ ((packed));

#endif	/* __ASM_IO_APIC_REGS_H */
