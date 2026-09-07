/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef F_PLL_H
#define F_PLL_H

#include <asm/sic_regs.h>
#include <asm/sic_regs_access.h>

#define EFUSE_START_ADDR    0x0
#define EFUSE_END_ADDR	    0xff
#define EFUSE_RAM_ADDR_OFFSET 0x0
#define EFUSE_RAM_DATA_OFFSET 0x4

#define OD_MASK		    0x7ff
#define OD_OFFSET           5

#define NR_MASK		    0xfff
#define NR_OFFSET	    7

#define NF_MASK_LO	    0x1f
#define NF_MASK_HI	    0x7f
#define NF_OFFSET_LO	    16
#define NF_OFFSET_HI	    0

#define EFUSE_DATA_SIZE	    21

#define F_REF		100
#define MAX_F_PLL	2000
#define MIN_F_PLL	600
#define DEFAULT_F_PLL	2000

#define e2c3_get_od(data) (OD_MASK & (data >> OD_OFFSET))
#define e2c3_get_nr(data) (NR_MASK & (data >> NR_OFFSET))

typedef union {
	struct {
		uint32_t data:21;
		uint32_t broadcast:1;
		uint32_t addr:7;
		uint32_t parity:1;
		uint32_t disable:1;
		uint32_t sign:1;
	};
	u32 word;
} efuse_data_t;
#endif /* F_PLL_H */
