/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _BASE_REGS_TYPES_H_
#define _BASE_REGS_TYPES_H_

#include <asm/types.h>

/* E2K physical address definitions */

/* E2K physical address size (bits number) */
#define	MAX_PA_SIZE	CONFIG_E2K_PA_BITS
/* The number of the most significant bit of E2K physical address */
#define	MAX_PA_MSB	(MAX_PA_SIZE - 1)
#define	MAX_PA_MASK	((1UL << MAX_PA_SIZE) - 1)
#define	MAX_PM_SIZE	(1UL << MAX_PA_SIZE)

/* E2K virtual address definitions */
#define	E2K_VA_SIZE	48	/* E2K Virtual address size */
						/* (bits number) */
#define	E2K_VA_MSB	(E2K_VA_SIZE - 1)	/* The number of the most */
						/* significant bit of E2K */
						/* virtual address */
#define	E2K_VA_MASK	((1UL << E2K_VA_SIZE) - 1)
#define E2K_VA_END	(1UL << E2K_VA_SIZE)
#define	E2K_VA_PAGE_MASK	(E2K_VA_MASK & PAGE_MASK)



typedef struct {
	u32 word;
} e2k_reg_t;

typedef struct {
	u64 word;
} e2k_dreg_t;

typedef struct {
	u64 lo;
	u64 hi;
} e2k_qreg_t;

#define E2K_V7_AP_RW_MASK (0x3ull << 60)

#define AW(x)	((x).word)
#define AWP(xp)	((xp)->word)
#define TOS(reg_type, val) ((reg_type) { .word = val })
#define LO(reg)	((reg).lo)
#define HI(reg) ((reg).hi)



/* For v7 and more */

#define AP_SIZE_ALIGN_0		(1LL << 27)
#define AP_SIZE_ALIGN_4		(1LL << 29)
#define AP_SIZE_ALIGN_8		(1LL << 33)
#define AP_SIZE_ALIGN_12	(1LL << 37)
#define AP_SIZE_ALIGN_PAGE	AP_SIZE_ALIGN_12
#define AP_SIZE_ALIGN_16	(1LL << 41)
#define AP_SIZE_ALIGN_20	(1LL << 45)
#define AP_SIZE_ALIGN_24	(1LL << 48)

static __always_inline int ap_alignment(unsigned long size)
{
	if (size <= AP_SIZE_ALIGN_0) {
		return 0;
	} else if (size <= AP_SIZE_ALIGN_4) {
		return 4;
	} else if (size <= AP_SIZE_ALIGN_8) {
		return 8;
	} else if (size <= AP_SIZE_ALIGN_12) {
		return 12;
	} else if (size <= AP_SIZE_ALIGN_16) {
		return 16;
	} else if (size <= AP_SIZE_ALIGN_20) {
		return 20;
	} else {
		return 24;
	}
}

static __always_inline unsigned long ap_align_mask(unsigned long size)
{
	if (size <= AP_SIZE_ALIGN_0) {
		return 0;
	} else if (size <= AP_SIZE_ALIGN_4) {
		return (1 << 4) - 1;
	} else if (size <= AP_SIZE_ALIGN_8) {
		return (1 << 8) - 1;
	} else if (size <= AP_SIZE_ALIGN_12) {
		return (1 << 12) - 1;
	} else if (size <= AP_SIZE_ALIGN_16) {
		return (1 << 16) - 1;
	} else if (size <= AP_SIZE_ALIGN_20) {
		return (1 << 20) - 1;
	} else {
		return (1 << 24) - 1;
	}
}

#endif /* _BASE_REGS_TYPES_H_ */

