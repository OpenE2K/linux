/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 MCST
 */
#ifndef __E2K_CPUFREQ_H__
#define __E2K_CPUFREQ_H__

#define M_BFS 3
#define N_BFS 16
#define MAX_STATES (M_BFS*N_BFS)
#define F_REF				100

 /* default pll_clkr, pll_clkod, pll_clkf */
#define DEF_PLL_CLKR_V6			0x0
#define DEF_PLL_CLKOD_V6		0x0
#define DEF_PLL_CLKF_V6			0x2800000000
#define DEF_PLL_CLKR_E8V7		0x0
#define DEF_PLL_CLKOD_E8V7		0x0
#define DEF_PLL_CLKF_E8V7		0x2800000000

#define EFUSE_START_ADDR		0x0
#define EFUSE_END_ADDR_V6		0xff
#define EFUSE_END_ADDR_E8V7		0x1fff

#define V5_PCS_MODE_3			0x3
#define V5_PCS_MODE_7			0x7
/* V6, V7 one step takes ~2600 ns */
#define DIVF_STEPS_LENGTH_NS(divF) ((divF) * 2600)
/* V5 one step takes ~250 ns */
#define DIVF_STEPS_LENGTH_NS_V5(divF) ((divF) * 250)
#define THROTTLING_NODE_BITMASK(f) (1U << (f))

/* E12C/E16C/E2C3 Power Control System (PCS) cpufreq registers:
 * PMC base = 0x1000, FREQ_CORE_0_MON base = 0x200, FUSE base = 0xcc0
 * E8V7 Power Control System (PCS) cpufreq registers:
 * PMC base = 0x1000, FREQ_CORE_0_MON base = 0x400, FUSE base = 0xcc0
 * */
#define PMC_FREQ_CORE_0_MON_SHIFT		0x0
#define PMC_FREQ_CORE_0_CTRL_SHIFT		0x4
#define PMC_FREQ_CORE_N_MON_SHIFT(n)		(PMC_FREQ_CORE_0_MON_SHIFT +  n * 16)
#define PMC_FREQ_CORE_N_CTRL_SHIFT(n)		(PMC_FREQ_CORE_0_CTRL_SHIFT +  n * 16)

#define EFUSE_RAM_ADDR_SHIFT          0x0
#define EFUSE_RAM_DATA_SHIFT          0x4

typedef union {
	struct {
		u32 data		:21;
		u32 broadcast		:1;
		u32 addr		:7;
		u32 parity		:1;
		u32 disable		:1;
		u32 val			:1;
	} v6;
	struct {
		u32 empty		:5;
		u32 pll_clkod		:11;
		u32 pll_clkf_lo		:5;
		u32 empty2		:11;
	} v6_addr_46;
	struct {
		u32 pll_clkf_med_lo	:21;
		u32 empty		:11;
	} v6_addr_47;
	struct {
		u32 pll_clkf_med_hi	:21;
		u32 empty		:11;
	} v6_addr_48;
	struct {
		u32 pll_clkf_hi		:7;
		u32 pll_clkr		:12;
		u32 empty		:13;
	} v6_addr_49;
	struct {
		u32 data		:20;
		u32 part_num		:4;
		u32 addr		:5;
		u32 parity		:1;
		u32 disable		:1;
		u32 val			:1;
	} v7;
	struct {
		u32 empty		:16;
		u32 pll_clkod_lo	:4;
		u32 empty2		:12;
	} e8v7_partnum5;
	struct {
		u32 pll_clkod_hi	:7;
		u32 pll_clkf_lo		:13;
		u32 empty		:12;
	} e8v7_partnum6;
	struct {
		u32 pll_clkf_med_lo	:20;
		u32 empty		:12;
	} e8v7_partnum7;
	struct {
		u32 pll_clkf_med_hi	:20;
		u32 empty		:12;
	} e8v7_partnum8;
	struct {
		u32 pll_clkf_hi		:1;
		u32 pll_clkr		:12;
		u32 empty		:19;
	} e8v7_partnum9;
	u32 word;
} efuse_data_t;


/* V6 fuse */
#define V6_ADDR_45				(1 << 5)
#define V6_ADDR_46				(1 << 6)
#define V6_ADDR_47				(1 << 7)
#define V6_ADDR_48				(1 << 8)

/* V7 fuse */
#define PLL_BFS_CORE_ADDR_V7			0x0f
#define PART_NUM_5				(1 << 5)
#define PART_NUM_6				(1 << 6)
#define PART_NUM_7				(1 << 7)
#define PART_NUM_8				(1 << 8)
#define PART_NUM_9				(1 << 9)

/* E8C2 Power Control System (PCS) freq registers:
 * PCS_CTRL0 base = 0xbc0 */
#define SIC_pcs_ctrl0_shift		0x0
#define SIC_pcs_ctrl1_shift		0x4
#define SIC_pcs_ctrl3_shift		0xc

#if 0
/* PCS_CTRL1 fields: */
typedef union {
	struct {
		u32 pcs_mode	: 4;
		u32 n_fprogr	: 6;
		u32 n_fmin	: 6;
		u32 n_fminmc	: 6;
		u32 n		: 6;
		u32 rsv		: 4;
	};
	u32 word;
} pcs_ctrl1_t;

/* PCS_CTRL3 fields: */
typedef union {
	struct {
		u32 n_fpin	    : 6;
		u32 rsv1	    : 2;
		u32 bfs_freq	    : 4;
		u32 pll_bw	    : 3;
		u32 rsv2	    : 1;
		u32 pll_mode	    : 3;
		u32 rsv3	    : 1;
		u32 iol_bitrate	    : 3;
		u32 rsv4	    : 1;
		u32 ipl_bitrate	    : 3;
		u32 rsv5	    : 1;
		u32 l_equaliz	    : 1;
		u32 l_preemph	    : 1;
		u32 bfs_adj_dsbl    : 1;
		u32 rsv6	    : 1;
	};
	u32 word;
} pcs_ctrl3_t;
#endif

typedef union {
	struct {
		u8 enable		:1;
		u8 rsv			:3;
		u8 nodemask		:4;
	};
	u8 byte;
} throttling_data_t;

#endif
