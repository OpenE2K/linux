/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * HW_CHECK kernel module for e2k platforms
 * e8c, e8c2, e16c, e2c3, e12c, e8v7
 */

#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/err.h>
#include <linux/platform_device.h>
#include <linux/node.h>
#include <linux/cpu.h>
#include <linux/mod_devicetable.h>
#include <linux/hwmon-sysfs.h>
#include <linux/hwmon.h>
#include <linux/thermal.h>
#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/workqueue.h>
#include <linux/completion.h>
#include "hw_check.h"

#ifdef CONFIG_E2K
static int CalcFreq(int base, int div)
{
	int divF;
	int bfs_M;
	int bfs_N;

	if (div >= 0x30) {
		divF = 0x2F;
	} else {
		divF = div;
	}
	bfs_M = (1 << ((divF & 0x30) >> 4));
	bfs_N = (divF & 0xF) + 0x10;

	return base * 16 / bfs_M / bfs_N;
}

static int CalcTemp(int T_data)
{
	int Temp;
	int T_sign = (T_data >> 8) & 0x1;

	if (T_sign == 1) {
		Temp = (0x1FF) | (T_data & 0x1FF);
	} else {
		Temp = T_data & 0x1FF;
	}

	return Temp;
}

static unsigned int get_mpll_freq_e8v7(void __iomem *fuse_base, enum mode_for_get_pll mode)
{
	uint64_t DEF_PLL_CLKF_E8V7;
	int PLL_BFS_ADDR_V7;

	if (mode) {
		DEF_PLL_CLKF_E8V7	= DEF_PLL_UNCORE_CLKF_E8V7;
		PLL_BFS_ADDR_V7		= PLL_BFS_UNCORE_ADDR_V7;
	} else {
		DEF_PLL_CLKF_E8V7	= DEF_PLL_CORE_CLKF_E8V7;
		PLL_BFS_ADDR_V7		= PLL_BFS_CORE_ADDR_V7;
	}
	efuse_data_t efuse_data;
	unsigned int addr;
	unsigned int f_pll;
	uint32_t pll_clkr = DEF_PLL_CLKR_E8V7;
	union {
		struct {
			u32 lo		: 4;
			u32 hi		: 7;
			u32 empty	: 21;
		};
		u32 reg;
	} pll_clkod = {
		.reg = DEF_PLL_CLKOD_E8V7
	};
	uint16_t flags = 0;
	union {
		struct {
			u64 lo		: 13;
			u64 med_lo	: 20;
			u64 med_hi	: 20;
			u64 hi		: 1;
			u64	empty	: 10;
		};
		u64 reg;
	} pll_clkf = {
		.reg = DEF_PLL_CLKF_E8V7
	};

	for (addr = EFUSE_START_ADDR; addr < EFUSE_END_ADDR_E8V7; addr++) {
		writel(addr, fuse_base + EFUSE_RAM_ADDR_SHIFT);
		efuse_data.word = readl(fuse_base + EFUSE_RAM_DATA_SHIFT);
		if (efuse_data.v7.val && !efuse_data.v7.disable &&
				efuse_data.v7.addr == PLL_BFS_ADDR_V7) {
			switch (efuse_data.v7.part_num) {
			case PARTNUM_5:
				pll_clkod.lo = efuse_data.e8v7_partnum5.pll_clkod_lo;
				flags |= PARTNUM_5_FLAG;
				break;
			case PARTNUM_6:
				pll_clkod.hi = efuse_data.e8v7_partnum6.pll_clkod_hi;
				pll_clkf.lo = efuse_data.e8v7_partnum6.pll_clkf_lo;
				flags |= PARTNUM_6_FLAG;
				break;
			case PARTNUM_7:
				pll_clkf.med_lo = efuse_data.e8v7_partnum7.pll_clkf_med_lo;
				flags |= PARTNUM_7_FLAG;
				break;
			case PARTNUM_8:
				pll_clkf.med_hi = efuse_data.e8v7_partnum8.pll_clkf_med_hi;
				flags |= PARTNUM_8_FLAG;
				break;
			case PARTNUM_9:
				pll_clkf.hi = efuse_data.e8v7_partnum9.pll_clkf_hi;
				pll_clkr = efuse_data.e8v7_partnum9.pll_clkr;
				flags |= PARTNUM_9_FLAG;
				break;
			}
		}
		if (flags == (PARTNUM_5_FLAG | PARTNUM_6_FLAG |
				PARTNUM_7_FLAG | PARTNUM_8_FLAG | PARTNUM_9_FLAG))
			break;
	}

	if (pll_clkr == 0 && pll_clkod.reg == 0 && pll_clkf.reg == 0) {
		pll_clkr = DEF_PLL_CLKR_E8V7;
		pll_clkod.reg = DEF_PLL_CLKOD_E8V7;
		pll_clkf.reg = DEF_PLL_CLKF_E8V7;
	}

	f_pll = F_REF * pll_clkf.reg / ((1ULL << 33) * (pll_clkr + 1) * (pll_clkod.reg + 1));

	return f_pll;
}

static unsigned int get_core_mpll_freq(void __iomem *fuse_base)
{
	efuse_data_t efuse_data;
	unsigned int addr;
	unsigned int f_pll;
	uint32_t pll_clkr, pll_clkod;
	uint16_t flags = 0;
	union {
		struct {
			u64 lo		: 13;
			u64 med_lo	: 21;
			u64 med_hi	: 21;
			u64 hi		: 7;
			u64	empty	: 2;
		};
		u64 reg;
	} pll_clkf;

	for (addr = EFUSE_START_ADDR; addr < EFUSE_END_ADDR; addr++) {
		writel(addr, fuse_base + EFUSE_RAM_ADDR_SHIFT);
		efuse_data.word = readl(fuse_base + EFUSE_RAM_DATA_SHIFT);
		if (efuse_data.string_from_efuse.val &&
				!efuse_data.string_from_efuse.disable &&
					efuse_data.string_from_efuse.broadcast) {
			switch (efuse_data.string_from_efuse.addr) {
			case ADDR_FIRST_CORE_SUB_BLOCK:
				pll_clkod = efuse_data.first_sub_block.pll_clkod;
				pll_clkf.lo = efuse_data.first_sub_block.pll_clkf_lo;
				flags |= FIRST_SUB_BLOCK;
				break;
			case ADDR_SECOND_CORE_SUB_BLOCK:
				pll_clkf.med_lo = efuse_data.second_sub_block.pll_clkf_med_lo;
				flags |= SECOND_SUB_BLOCK;
				break;
			case ADDR_THIRD_CORE_SUB_BLOCK:
				pll_clkf.med_hi = efuse_data.third_sub_block.pll_clkf_med_hi;
				flags |= THIRD_SUB_BLOCK;
				break;
			case ADDR_FOURTH_CORE_SUB_BLOCK:
				pll_clkf.hi = efuse_data.fourth_sub_block.pll_clkf_hi;
				pll_clkr = efuse_data.fourth_sub_block.pll_clkr;
				flags |= FOURTH_SUB_BLOCK;
				break;
			}
		}
		if (flags == (FIRST_SUB_BLOCK | SECOND_SUB_BLOCK |
				THIRD_SUB_BLOCK | FOURTH_SUB_BLOCK))
			break;
	}

	if ((flags != (FIRST_SUB_BLOCK | SECOND_SUB_BLOCK |
			THIRD_SUB_BLOCK | FOURTH_SUB_BLOCK)) ||
				(pll_clkr == 0 && pll_clkod == 0 && pll_clkf.reg == 0))
		f_pll = CORE_MPLL_FREQ;
	else
		f_pll = F_REF * pll_clkf.reg / ((1ULL << 33) * (pll_clkr + 1) * (pll_clkod + 1));

	return f_pll;
}

static unsigned int get_uncore_mpll_freq(void __iomem *fuse_base)
{
	efuse_data_t efuse_data;
	unsigned int addr;
	unsigned int f_pll;
	uint32_t pll_clkr, pll_clkod;
	uint16_t flags = 0;
	union {
		struct {
			u64 lo		: 13;
			u64 med_lo	: 21;
			u64 med_hi	: 21;
			u64 hi		: 7;
			u64	empty	: 2;
		};
		u64 reg;
	} pll_clkf;

	for (addr = EFUSE_START_ADDR; addr < EFUSE_END_ADDR; addr++) {
		writel(addr, fuse_base + EFUSE_RAM_ADDR_SHIFT);
		efuse_data.word = readl(fuse_base + EFUSE_RAM_DATA_SHIFT);
		if (efuse_data.string_from_efuse.val &&
				!efuse_data.string_from_efuse.disable &&
					efuse_data.string_from_efuse.broadcast) {
			switch (efuse_data.string_from_efuse.addr) {
			case ADDR_FIRST_UNCORE_SUB_BLOCK:
				pll_clkod = efuse_data.first_sub_block.pll_clkod;
				pll_clkf.lo = efuse_data.first_sub_block.pll_clkf_lo;
				flags |= FIRST_SUB_BLOCK;
				break;
			case ADDR_SECOND_UNCORE_SUB_BLOCK:
				pll_clkf.med_lo = efuse_data.second_sub_block.pll_clkf_med_lo;
				flags |= SECOND_SUB_BLOCK;
				break;
			case ADDR_THIRD_UNCORE_SUB_BLOCK:
				pll_clkf.med_hi = efuse_data.third_sub_block.pll_clkf_med_hi;
				flags |= THIRD_SUB_BLOCK;
				break;
			case ADDR_FOURTH_UNCORE_SUB_BLOCK:
				pll_clkf.hi = efuse_data.fourth_sub_block.pll_clkf_hi;
				pll_clkr = efuse_data.fourth_sub_block.pll_clkr;
				flags |= FOURTH_SUB_BLOCK;
				break;
			}
		}
		if (flags == (FIRST_SUB_BLOCK | SECOND_SUB_BLOCK |
				THIRD_SUB_BLOCK | FOURTH_SUB_BLOCK))
			break;
	}

	if ((flags != (FIRST_SUB_BLOCK | SECOND_SUB_BLOCK |
			THIRD_SUB_BLOCK | FOURTH_SUB_BLOCK)) ||
				(pll_clkr == 0 && pll_clkod == 0 && pll_clkf.reg == 0))
		f_pll = UNCORE_MPLL_FREQ;
	else
		f_pll = F_REF * pll_clkf.reg / ((1ULL << 33) * (pll_clkr + 1) * (pll_clkod + 1));

	return f_pll;
}

int e8v7_block[E8V7_size] = {0, 1, 2, 3, 4, 5, 6, 7, 32, 33, 34, 35, 36};
static struct cpu_data_e8v7 read_cpu_data_e8v7(struct hwmon_data *hwmon)
{
	struct cpu_data_e8v7 a;
	int i;
	int block_addr_shift;
	int rr_data;
	int block_is_graphic;
	int graphic_num;
	int ctrl_data;
	int pmc_freq_data;
	enum mode_for_get_pll mode;

	for (i = 0; i < E8V7_size; i++) {
		block_addr_shift = 0x10 * e8v7_block[i];
		graphic_num = e8v7_block[i] - 33;
		if (e8v7_block[i] < 16) {
			mode = CORE;
			a.base_freq[i] = get_mpll_freq_e8v7(hwmon->base[4], mode);
			block_is_graphic = 0;
			block_addr_shift += 0x400;
		} else if (e8v7_block[i] < 32) {
			a.base_freq[i] = 0;
			block_is_graphic = 0;
		} else if (e8v7_block[i] == 32) {
			mode = UNCORE;
			a.base_freq[i] = get_mpll_freq_e8v7(hwmon->base[4], mode);
			block_is_graphic = 0;
			block_addr_shift += 0x180;
		} else if (e8v7_block[i] < 37) {
			mode = CORE;
			a.base_freq[i] = get_mpll_freq_e8v7(hwmon->base[4], mode);
			block_is_graphic = 1;
			block_addr_shift += 0x1B0;
		} else {
			a.base_freq[i] = 0;
			block_is_graphic = 0;
		}
		rr_data = readl(hwmon->base[3] + block_addr_shift);
		a.mon_divF_curr[i] = rr_data & DIVF_CURR_MASK;
		a.mon_divF_lim_lo[i] = (rr_data & DIVF_LIM_LO_MASK) >>
							DIVF_LIM_LO_SHIFT;
		a.mon_divF_lim_hi[i] = (rr_data & DIVF_LIM_HI_MASK) >>
							DIVF_LIM_HI_SHIFT;
		a.mon_bfs_bypass[i] = (rr_data & BFS_BYPASS_MASK) >>
							BFS_BYPASS_SHIFT;
		a.mon_freq_curr[i] = CalcFreq(a.base_freq[i],
						a.mon_divF_curr[i]);
		a.mon_freq_lim_hi[i] = CalcFreq(a.base_freq[i],
						a.mon_divF_lim_hi[i]);
		a.mon_freq_lim_lo[i] = CalcFreq(a.base_freq[i],
						a.mon_divF_lim_lo[i]);

		ctrl_data = readl(hwmon->base[3] + block_addr_shift + 0x4);

		if (block_is_graphic == 1) {
			a.graph_ctrl_bfs_bypass[i] = (ctrl_data &
				BFS_BYPASS_MASK) >> BFS_BYPASS_SHIFT;
			a.graph_ctrl_en[i] = (ctrl_data & CTRL_EN_MASK);
		}
		a.ctrl_bfs_bypass[i] = (ctrl_data & BFS_BYPASS_MASK) >> BFS_BYPASS_SHIFT;
		a.ctrl_en[i] = (ctrl_data & CTRL_EN_MASK);
		pmc_freq_data = readl(hwmon->base[3] + 0x300);
		a.pmc_freq_cfg_alter_disable[i] = (pmc_freq_data & CFG_ALTER_MASK)
						>> CFG_ALTER_SHIFT;
	}

	return a;
}

static ssize_t show_cpu_data_e8v7(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct hwmon_data *hwmon = dev_get_drvdata(dev);
	struct cpu_data_e8v7 b = read_cpu_data_e8v7(hwmon);
	int j = 0;
	int i;
	int graphic_num;
	int block_is_graphic;
	int graph_ctrl_freq_bypassed;
	char block_name[30];
	char *GRAPHIC_NAME[] = {"MGA", "GPU", "ENCODERs", "DECODERs"};
	int block_is_core;
	int block_is_uncore;

	for (i = 0; i < E8V7_size; i++) {
		graphic_num = e8v7_block[i] - 33;
		if (e8v7_block[i] < 16) {
			block_is_core = 1;
			block_is_uncore = 0;
			block_is_graphic = 0;
			sprintf(block_name, "CORE_%d", e8v7_block[i]);
		} else if (e8v7_block[i] < 32) {
			block_is_core = 0;
			block_is_uncore = 0;
			block_is_graphic = 0;
			sprintf(block_name, "reserved");
		} else if (e8v7_block[i] == 32) {
			block_is_core = 0;
			block_is_uncore = 1;
			block_is_graphic = 0;
			sprintf(block_name, "OCI");
		} else if (e8v7_block[i] < 37) {
			block_is_core = 0;
			block_is_uncore = 0;
			block_is_graphic = 1;
			sprintf(block_name, "%s", GRAPHIC_NAME[graphic_num]);
		} else {
			block_is_core = 0;
			block_is_uncore = 0;
			block_is_graphic = 0;
			sprintf(block_name, "reserved");
		}
		j += sprintf(buf + j, "NODE_%d: Checking block %s\n", hwmon->node, block_name);
		if (b.mon_bfs_bypass[i]) {
			if (block_is_graphic == 1) {
				j += sprintf(buf + j, " - presence of a controlled frequency ");
				j += sprintf(buf + j, "divider: simple divider 1/%d or 1/%d\n",
							1, 1);
			} else {
				j += sprintf(buf + j, " - presence of a controlled frequency ");
				j += sprintf(buf + j, "divider: absent (BFS bypass)\n");
				j += sprintf(buf + j, " - current frequency: %d MHz (BFS bypass)\n",
										b.base_freq[i]);
				j += sprintf(buf + j, " - hardware allowed frequency range:");
				j += sprintf(buf + j, " absent (BFS bypass)\n");
			}
		} else {
			j += sprintf(buf + j, " - presence of a controlled frequency divider:");
			j += sprintf(buf + j, " standard (BFS bypass)\n");
			j += sprintf(buf + j, " - current frequency: %d MHz (divF=0x%x)\n",
						b.mon_freq_curr[i], b.mon_divF_curr[i]);
			j += sprintf(buf + j, " - hardware allowed frequency range:");
			j += sprintf(buf + j, " from %d MHz to %d MHz (0x%x>=divF>=0x%x)\n",
						b.mon_freq_lim_hi[i], b.mon_freq_lim_lo[i],
						b.mon_divF_lim_hi[i], b.mon_divF_lim_lo[i]);
		}

		if (block_is_graphic) {
			if (b.graph_ctrl_bfs_bypass[i]) {
				graph_ctrl_freq_bypassed = b.base_freq[i];
				j += sprintf(buf + j, " - current frequency: %d MHz\n",
							graph_ctrl_freq_bypassed);
			}
		}
	}

	return sprintf(buf, "%s", buf);
}

static int e2c3_block[E2C3_size] = {0, 1, 32, 33, 34, 35, 36};
static struct cpu_data read_cpu_data(struct hwmon_data *hwmon)
{
	struct cpu_data a;
	int i;
	int block_addr_shift;
	int rr_data;
	int block_is_graphic;
	int graphic_num;
	int ctrl_data;
	int graph_data;
	int pmc_freq_data;
	int pmc_freq_gra_float_T_lo[E2C3_size];
	int pmc_freq_gra_float_T_hi[E2C3_size];
	int core_data;
	int pmc_freq_core_float_T_lo[E2C3_size];
	int pmc_freq_core_float_T_hi[E2C3_size];
	int ocn_data;
	int pmc_freq_ocn_float_T_lo[E2C3_size];
	int pmc_freq_ocn_float_T_hi[E2C3_size];

	for (i = 0; i < E2C3_size; i++) {
		block_addr_shift = 0x10 * e2c3_block[i];
		graphic_num = e2c3_block[i] - 33;
		if (e2c3_block[i] < 16) {
			a.base_freq[i] = get_core_mpll_freq(hwmon->base[5]);
			block_is_graphic = 0;
		} else if (e2c3_block[i] < 32) {
			a.base_freq[i] = 0;
			block_is_graphic = 0;
		} else if (e2c3_block[i] == 32) {
			a.base_freq[i] = get_uncore_mpll_freq(hwmon->base[5]);
			block_is_graphic = 0;
		} else if (e2c3_block[i] < 37) {
			a.base_freq[i] = get_core_mpll_freq(hwmon->base[5]);
			block_is_graphic = 1;
		} else {
			a.base_freq[i] = 0;
			block_is_graphic = 0;
		}
		rr_data = readl(hwmon->base[3] + 0x200 + block_addr_shift);
		a.mon_divF_curr[i] = rr_data & DIVF_CURR_MASK;
		a.mon_divF_lim_lo[i] = (rr_data & DIVF_LIM_LO_MASK) >>
							DIVF_LIM_LO_SHIFT;
		a.mon_divF_lim_hi[i] = (rr_data & DIVF_LIM_HI_MASK) >>
							DIVF_LIM_HI_SHIFT;
		a.mon_bfs_bypass[i] = (rr_data & BFS_BYPASS_MASK) >>
							BFS_BYPASS_SHIFT;
		a.mon_freq_curr[i] = CalcFreq(a.base_freq[i],
						a.mon_divF_curr[i]);
		a.mon_freq_lim_hi[i] = CalcFreq(a.base_freq[i],
						a.mon_divF_lim_hi[i]);
		a.mon_freq_lim_lo[i] = CalcFreq(a.base_freq[i],
						a.mon_divF_lim_lo[i]);

		ctrl_data = readl(hwmon->base[3] + 0x204 + block_addr_shift);

		if (block_is_graphic == 1) {
			a.graph_ctrl_bfs_bypass[i] = (ctrl_data &
				BFS_BYPASS_MASK) >> BFS_BYPASS_SHIFT;
			a.graph_ctrl_en[i] = (ctrl_data & CTRL_EN_MASK);
			a.graph_ctrl_clk_mux[i] = (ctrl_data & CTRL_CLK_MASK)
							>> CTRL_CLK_SHIFT;
			a.graph_ctrl_mode[i] = (ctrl_data & CTRL_MODE_MASK)
							>> CTRL_MODE_SHIFT;
			graph_data = readl(hwmon->base[3] + 0x600 + (0x4 * graphic_num));
			pmc_freq_gra_float_T_lo[i] = graph_data & FLOAT_LO_MASK;
			pmc_freq_gra_float_T_hi[i] = (graph_data & FLOAT_HI_MASK)
							>> FLOAT_HI_SHIFT;
			a.pmc_freq_gra_float_T_lo_dec[i] = CalcTemp(pmc_freq_gra_float_T_lo[i]);
			a.pmc_freq_gra_float_T_hi_dec[i] = CalcTemp(pmc_freq_gra_float_T_hi[i]);
		}
		a.ctrl_bfs_bypass[i] = (ctrl_data & BFS_BYPASS_MASK) >> BFS_BYPASS_SHIFT;
		a.ctrl_en[i] = (ctrl_data & CTRL_EN_MASK);
		a.ctrl_mode[i] = (ctrl_data & CTRL_MODE_MASK) >> CTRL_MODE_SHIFT;
		core_data = readl(hwmon->base[3] + 0x110);
		pmc_freq_core_float_T_lo[i] = core_data & FLOAT_LO_MASK;
		pmc_freq_core_float_T_hi[i] = (core_data & FLOAT_HI_MASK)
						>> FLOAT_HI_SHIFT;
		a.pmc_freq_core_float_T_lo_dec[i] = CalcTemp(pmc_freq_core_float_T_lo[i]);
		a.pmc_freq_core_float_T_hi_dec[i] = CalcTemp(pmc_freq_core_float_T_hi[i]);
		pmc_freq_data = readl(hwmon->base[3] + 0x100);
		a.pmc_freq_cfg_alter_disable[i] = (pmc_freq_data & CFG_ALTER_MASK)
						>> CFG_ALTER_SHIFT;
		ocn_data = readl(hwmon->base[3] + 0x114);
		pmc_freq_ocn_float_T_lo[i] = ocn_data & FLOAT_LO_MASK;
		pmc_freq_ocn_float_T_hi[i] = (ocn_data & FLOAT_HI_MASK)
						>> FLOAT_HI_SHIFT;
		a.pmc_freq_ocn_float_T_lo_dec[i] = CalcTemp(pmc_freq_ocn_float_T_lo[i]);
		a.pmc_freq_ocn_float_T_hi_dec[i] = CalcTemp(pmc_freq_ocn_float_T_hi[i]);
	}

	return a;
}

static ssize_t show_cpu_data(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct hwmon_data *hwmon = dev_get_drvdata(dev);
	struct cpu_data b = read_cpu_data(hwmon);
	int j = 0;
	int i;
	int graphic_num;
	int block_is_graphic;
	int graph_ctrl_freq_bypassed;
	char block_name[20];
	char *GRAPHIC_NAME[] = {"MGA", "GPU", "ENCODERs", "DECODERs"};
	int GRAPHIC_DIV_0[4] = {3, 3, 4, 4};
	int GRAPHIC_DIV_1[4] = {2, 2, 3, 3};
	int simple_div[2];
	int block_is_core;
	int block_is_uncore;

	for (i = 0; i < E2C3_size; i++) {
		graphic_num = e2c3_block[i] - 33;
		if (e2c3_block[i] < 16) {
			block_is_core = 1;
			block_is_uncore = 0;
			block_is_graphic = 0;
			sprintf(block_name, "CORE_%d", e2c3_block[i]);
			simple_div[0] = 1;
			simple_div[1] = 1;
		} else if (e2c3_block[i] < 32) {
			block_is_core = 0;
			block_is_uncore = 0;
			block_is_graphic = 0;
			sprintf(block_name, "reserved");
			simple_div[0] = 1;
			simple_div[1] = 1;
		} else if (e2c3_block[i] == 32) {
			block_is_core = 0;
			block_is_uncore = 1;
			block_is_graphic = 0;
			sprintf(block_name, "OCI");
			simple_div[0] = 1;
			simple_div[1] = 1;
		} else if (e2c3_block[i] < 37) {
			block_is_core = 0;
			block_is_uncore = 0;
			block_is_graphic = 1;
			sprintf(block_name, "%s", GRAPHIC_NAME[graphic_num]);
			simple_div[0] = GRAPHIC_DIV_0[graphic_num];
			simple_div[1] = GRAPHIC_DIV_1[graphic_num];
		} else {
			block_is_core = 0;
			block_is_uncore = 0;
			block_is_graphic = 0;
			sprintf(block_name, "reserved");
			simple_div[0] = 1;
			simple_div[1] = 1;
		}
		j += sprintf(buf + j, "NODE_%d: Checking block %s\n", hwmon->node, block_name);
		if (b.mon_bfs_bypass[i]) {
			if (block_is_graphic == 1) {
				j += sprintf(buf + j, " - presence of a controlled frequency ");
				j += sprintf(buf + j, "divider: simple divider 1/%d or 1/%d\n",
							simple_div[0], simple_div[1]);
			} else {
				j += sprintf(buf + j, " - presence of a controlled frequency ");
				j += sprintf(buf + j, "divider: absent (BFS bypass)\n");
				j += sprintf(buf + j, " - current frequency: %d MHz (BFS bypass)\n",
										b.base_freq[i]);
				j += sprintf(buf + j, " - hardware allowed frequency range:");
				j += sprintf(buf + j, " absent (BFS bypass)\n");
			}
		} else {
			j += sprintf(buf + j, " - presence of a controlled frequency divider:");
			j += sprintf(buf + j, " standard (BFS bypass)\n");
			j += sprintf(buf + j, " - current frequency: %d MHz (divF=0x%x)\n",
						b.mon_freq_curr[i], b.mon_divF_curr[i]);
			j += sprintf(buf + j, " - hardware allowed frequency range:");
			j += sprintf(buf + j, " from %d MHz to %d MHz (0x%x>=divF>=0x%x)\n",
						b.mon_freq_lim_hi[i], b.mon_freq_lim_lo[i],
						b.mon_divF_lim_hi[i], b.mon_divF_lim_lo[i]);
		}

		if (block_is_graphic) {
			if (b.graph_ctrl_bfs_bypass[i]) {
				graph_ctrl_freq_bypassed = b.base_freq[i];
				graph_ctrl_freq_bypassed /= simple_div[b.graph_ctrl_clk_mux[i]];
				j += sprintf(buf + j, " - current frequency: %d MHz",
							graph_ctrl_freq_bypassed);
				j += sprintf(buf + j, " (clk_mux=%d, simple_divider=1/%d",
							b.graph_ctrl_clk_mux[i],
							simple_div[b.graph_ctrl_clk_mux[i]]);
			} else {
				if ((!b.pmc_freq_cfg_alter_disable[i]) && (b.graph_ctrl_en[i])) {
					if ((b.graph_ctrl_mode[i] == 4) ||
								(b.graph_ctrl_mode[i] == 5)) {
						j += sprintf(buf + j, " - thermal control window");
						j += sprintf(buf + j, " with floating divider:");
						j += sprintf(buf + j, " T_lo = %d, T_hi = %d\n",
								b.pmc_freq_gra_float_T_lo_dec[i],
								b.pmc_freq_gra_float_T_hi_dec[i]);
					}
				}
			}
		} else {
			if ((!b.pmc_freq_cfg_alter_disable[i]) && (b.ctrl_en[i])) {
				if ((b.ctrl_mode[i] == 4) || (b.ctrl_mode[i] == 5)) {
					if (block_is_core) {
						j += sprintf(buf + j, " - thermal control window");
						j += sprintf(buf + j, " with floating divider:");
						j += sprintf(buf + j, " T_lo = %d, T_hi = %d\n",
								b.pmc_freq_core_float_T_lo_dec[i],
								b.pmc_freq_core_float_T_hi_dec[i]);
					} else if (block_is_uncore) {
						j += sprintf(buf + j, " - thermal control window");
						j += sprintf(buf + j, " with floating divider:");
						j += sprintf(buf + j, " T_lo = %d, T_hi = %d\n",
								b.pmc_freq_ocn_float_T_lo_dec[i],
								b.pmc_freq_ocn_float_T_hi_dec[i]);
					  }
				}
			}
		}
	}

	return sprintf(buf, "%s", buf);
}

static u32 read_reg(bool *present)
{
	struct pci_dev *dev;
	u32 value = 0;
	*present = true;

	dev = pci_get_device(PCI_VIRT_BRIDGE_VENDOR_ID,
				PCI_VIRT_BRIDGE_DEVICE_ID, NULL);
	if (!dev) {
		*present = false;
		return value;
	}
	pci_read_config_dword(dev, 0x70, &value);
	pci_dev_put(dev);

	/* To read needed info I use this shift and mask,
	   just like it's done in the script  */
	value = (value >> 16) & 0xffff;
	return value;

}

static int prev_str_err_mode[IPCC_LINKS] = {-1, -1, -1};

static int read_wlcc_data(struct link_data *data, struct hwmon_data *hwmon)
{
	struct link_data *a = data;
	struct pci_dev *dev;
	static void __iomem *base_addr;
	int iol_pls = 0;
	int wlcc_err_val = 0;

	if (IS_MACHINE_E16C || IS_MACHINE_E12C ||
			IS_MACHINE_E2C3) {
		dev = pci_get_device(PCI_VIRT_BRIDGE_VENDOR_ID,
					PCI_VIRT_BRIDGE_DEVICE_ID, NULL);
		if (!dev)
			return -ENODEV;

		base_addr = pci_iomap(dev, 0, PCI_IOL_SIZE);
		if (!base_addr) {
			pci_release_regions(dev);
			return -EFAULT;
		}

		/* iol_bitrate[22:20] from PCS_CTRL3 reg (v5) moved
		 * to pin_wlcc_speed_presets[18:16] PMC_SYS_MON_0 reg (v6)
		 * */
		a->io_mpll = (readl(hwmon->base[3] + PMC_SYS_MON_0_SHIFT)
				& PIN_WLCC_SPEED_PRESETS_MASK) >> PIN_WLCC_SPEED_PRESETS_SHIFT;
		a->wlcc_rate = (readl(base_addr + IOL_PLM_CTLR_SHIFT_PCI)
							& WLCC_RATE_MASK) >> WLCC_RATE_SHIFT;
		iol_pls = readl(base_addr + IOL_PLS_CTLR_SHIFT_PCI);
		wlcc_err_val = readl(base_addr + IOL_DLL_STSR_SHIFT_PCI);
		pci_iounmap(dev, base_addr);
		pci_dev_put(dev);
	}

	if (IS_MACHINE_E8C || IS_MACHINE_E8C2) {
		a->io_mpll = (readl(hwmon->base[4])
					& MPLL_MASK) >> MPLL_SHIFT;
		a->ip_mpll = (readl(hwmon->base[4])
				& MPLL_LINK_MASK) >> MPLL_LINK_SHIFT;
		a->wlcc_rate = (readl(hwmon->base[3] + IOL_PLM_CTLR_SHIFT)
					& WLCC_RATE_MASK) >> WLCC_RATE_SHIFT;
		iol_pls = readl(hwmon->base[3] + IOL_PLS_CTLR_SHIFT);
		wlcc_err_val = readl(hwmon->base[3] + IOL_DLL_STSR_SHIFT);
	}

	a->wlcc_active = (iol_pls & WLCC_ACTIVE_MASK) >>
			WLCC_ACTIVE_SHIFT;
	a->wlcc_state = (iol_pls & WLCC_STATE_MASK) >>
			WLCC_STATE_SHIFT;
	a->wlcc_width = (iol_pls & WLCC_WIDTH_MASK) >>
			WLCC_WIDTH_SHIFT;
	a->wlcc_cnt = wlcc_err_val & ERR_CNT_MASK;
	a->wlcc_ov = (wlcc_err_val & ERR_OV_MASK) >>
					 ERR_OV_SHIFT;
	a->wlcc_md = (wlcc_err_val & ERR_MD_MASK) >>
					 ERR_MD_SHIFT;

	return 0;
}

static int read_kpi_data(struct link_data *data, struct hwmon_data *hwmon)
{
	struct link_data *a = data;
	struct pci_dev *dev;
	static void __iomem *base_addr;
	int kpi_err_val;
	u32 pls_ctrl;

	a->iol = (readl(hwmon->base[0] + RT_LCFG0_SHIFT) &
					IOL_MASK) >> IOL_SHIFT;
	if (a->iol == 1) {
		dev = pci_get_device(PCI_VIRT_BRIDGE_VENDOR_ID,
					PCI_VIRT_BRIDGE_DEVICE_ID, NULL);
		if (!dev)
			return -ENODEV;
		base_addr = pci_iomap(dev, 0, PCI_KPI_SIZE);
		if (!base_addr) {
			pci_release_regions(dev);
			return -EFAULT;
		}

		a->kpi_rate = (readl(base_addr + 0x8) & WLCC_RATE_MASK) >>
							 WLCC_RATE_SHIFT;
		pls_ctrl = readl(base_addr + 0x4);
		a->kpi_active = ((pls_ctrl) &	WLCC_ACTIVE_MASK) >>
						 WLCC_ACTIVE_SHIFT;
		a->kpi_state = ((pls_ctrl) & WLCC_STATE_MASK) >>
						WLCC_STATE_SHIFT;
		a->kpi_width = ((pls_ctrl) & WLCC_WIDTH_MASK) >>
						WLCC_WIDTH_SHIFT;
		kpi_err_val = readl(base_addr + 0xC);
		a->kpi_cnt = kpi_err_val & ERR_CNT_MASK;
		a->kpi_ov = (kpi_err_val & ERR_OV_MASK) >>
							ERR_OV_SHIFT;
		a->kpi_md = (kpi_err_val & ERR_MD_MASK) >>
							 ERR_MD_SHIFT;
		pci_iounmap(dev, base_addr);
		pci_dev_put(dev);
	}

	return 0;
}

static void read_ipcc_data(struct link_data *data, struct hwmon_data *hwmon)
{
	static void __iomem *base;
	struct link_data *a = data;
	int curr_LCFG;
	int str_shift = 3; /*This shift is used to read from str regs*/
	int lanes = 1;
	int rt_lcfg_val;
	int ipcc_csr[IPCC_LINKS];
	int ipcc_str[IPCC_LINKS];
	struct pci_dev *dev;
	u32 ref_clk_div2_en;
	u32 clk_div2_en_val;
	u32 rx_rate;
	u32 rx_rate_val;
	u32 mplla_multiplier_and_clk_mplla;
	u32 mplla_val;
	u32 mplla_mult_val;
	u32 mplla_div2_val;
	int bitrate, bitrate_mean = 0, lnum = 0;
	int b, i, j;
	bool present;

	a->multilink = ((readl(hwmon->base[0] + ST_P_SHIFT)) >>
				 MULTILINK_SHIFT) & MULTILINK_MASK;
	a->mlc = (readl(hwmon->base[0] + ST_P_SHIFT) >>
				 MLC_SHIFT) & MLC_MASK;
	a->st_p = readl(hwmon->base[0] + ST_P_SHIFT);

	/*Depending on the number of ipcc link, reading from definite regs */
	for (i = 0; i < IPCC_LINKS; i++) {
		switch (i) {
		case 0:
			curr_LCFG = RT_LCFG1_SHIFT;
			break;
		case 1:
			curr_LCFG = RT_LCFG2_SHIFT;
			break;
		case 2:
			curr_LCFG = RT_LCFG3_SHIFT;
			break;
		default:
			curr_LCFG = 0;
			break;
		}
		rt_lcfg_val = readl(hwmon->base[0] + curr_LCFG);

		a->vp[i] = rt_lcfg_val & RT_LCFG_VP_MASK;
		a->pn[i] = (rt_lcfg_val >>
				RT_LCFG_PN_SHIFT)&RT_LCFG_PN_MASK;
		if (IS_MACHINE_E16C || IS_MACHINE_E12C ||
				IS_MACHINE_E2C3)
			base = hwmon->base[2];
		else
			base = hwmon->base[3];
		ipcc_str[i] = readl(base + ipcc_ctrls_off[i+str_shift].offset);
		a->str_val[i] = ipcc_str[i];
		ipcc_csr[i] = readl(base + ipcc_ctrls_off[i].offset);
		a->csr_reg[i] = ipcc_csr[i];
		a->str_reg[i] = ipcc_ctrls[i+str_shift].offset;
		a->active[i] = (ipcc_csr[i] & ACTIVE_MASK) >> ACTIVE_SHIFT;
		a->width[i] = (ipcc_csr[i] & WIDTH_MASK) >> WIDTH_SHIFT;
		a->state[i] = (ipcc_csr[i] & STATE_MASK) >> STATE_SHIFT;
		a->cnt_err[i] = (ipcc_str[i] & CNT_MASK);
		a->err_mode[i] = (ipcc_str[i] & ERR_MODE_MASK) >> ERR_MODE_SHIFT;

		/* The IPCC_STR register bits [31:30] are responsible for err_mode and
		 * if the value of the previous reading is different, then write 1 to bit [29]
		 * to reset the cnt_err counter [28:0].*/

		if (prev_str_err_mode[i] >=  0 && prev_str_err_mode[i] != a->err_mode[i]) {
			writel(a->str_val[i] | OVER_CNT_MASK,
				base + ipcc_ctrls_off[i+str_shift].offset);
		}
		prev_str_err_mode[i] = a->err_mode[i];

		if (IS_MACHINE_E16C || IS_MACHINE_E12C ||
				IS_MACHINE_E2C3) {
			/*Depening on bitrate link*/
			switch (i) {
			case 0:
				b = 0;
				break;
			case 1:
				b = 4;
				break;
			case 2:
				b = 8;
				break;
			default:
				b = 0;
				break;
			}

			dev = pci_get_device(PCI_VIRT_BRIDGE_VENDOR_ID,
						PCI_VIRT_BRIDGE_DEVICE_ID, NULL);
			if (!dev) {
				pr_err("PCI Virtual Bridge not presented\n");
				return;
			}
			for (j = 0; j < lanes; j++) {
				lnum++;
				/* All magical numbers were got from engineer scripts */
				mplla_multiplier_and_clk_mplla = ((0x80 << 24)|
						(ipcc_rate_ctrls[b+j].offset << 16)|
								 SUP_DIG_MPLLA_ASIC_IN_0);

				pci_write_config_dword(dev, 0x6c,
							mplla_multiplier_and_clk_mplla);
				mplla_val = read_reg(&present);
				if (!present) {
					pr_err("PCI Virtual Bridge not presented\n");
					pci_dev_put(dev);
					return;
				}

				mplla_mult_val = (mplla_val >> MPLLA_SHIFT) & MPLLA_MASK;
				mplla_div2_val = (mplla_val >> MPLLA_DIV2_SHIFT) &
									MPLLA_DIV2_MASK;

				ref_clk_div2_en = ((0x80 << 24)|
						(ipcc_rate_ctrls[b+j].offset << 16)|
									SUP_DIG_ASIC_IN);
				pci_write_config_dword(dev, 0x6c, ref_clk_div2_en);
				clk_div2_en_val = read_reg(&present);
				if (!present) {
					pr_err("PCI Virtual Bridge not presented\n");
					pci_dev_put(dev);
					return;
				}
				clk_div2_en_val = (clk_div2_en_val >> CLK_DIV2_EN_SHIFT) &
									CLK_DIV2_EN_MASK;

				rx_rate = ((0x80 << 24) | (ipcc_rate_ctrls[b+j].offset << 16) |
								LANEN_DIG_ASIC_RX_ASIC_IN_0);

				pci_write_config_dword(dev, 0x6c, rx_rate);
				rx_rate_val = read_reg(&present);
				if (!present) {
					pr_err("PCI Virtual Bridge not presented\n");
					pci_dev_put(dev);
					return;
				}
				rx_rate_val = (rx_rate_val >> RX_RATE_SHIFT) & RX_RATE_MASK;

				bitrate = 2 * 100 * (mplla_mult_val & 0x7f);

				if (((mplla_mult_val >> 7) & 1) == 1) {
					bitrate = bitrate*2;
				}

				if (rx_rate_val == 0) {
					bitrate = bitrate*2;
				}

				if (rx_rate_val == 2) {
					bitrate = bitrate/2;
				}

				if (clk_div2_en_val == 1) {
					bitrate = bitrate/2;
				}

				if (mplla_div2_val == 1) {
					bitrate = bitrate/2;
				}
				bitrate_mean += bitrate;
			}
			bitrate_mean /= lnum;
			a->link_bitrate[i] = bitrate_mean;
			bitrate_mean = 0;
			lnum = 0;
			pci_dev_put(dev);
		}
	}
}

static struct link_data read_link_data(struct hwmon_data *hwmon)
{
	struct link_data a;
	int ret;

	ret = read_wlcc_data(&a, hwmon);
	if (ret < 0) {
		a.wlcc_state = ret;
	}

	ret = read_kpi_data(&a, hwmon);
	if (ret < 0) {
		a.kpi_state = ret;
	}

	if (!IS_MACHINE_E2C3) {
		read_ipcc_data(&a, hwmon);
	}

	return a;
}

static void convert_mbit2gbit(char *buf, int mbit_link_bitrate)
{
	int mod, j = 0;

	j += sprintf(buf, "%d", mbit_link_bitrate / 1000);
	mod = mbit_link_bitrate % 1000;
	if (mod && !(mod % 100)) {
		j += sprintf(buf + j, ".%d", mod / 100);
	} else if (mod && !(mod % 10)) {
		j += sprintf(buf + j, ".%02d", mod / 10);
	} else if (mod) {
		j += sprintf(buf + j, ".%03d", mod);
	}
}

static int get_kpi_information(struct link_data *data, char *buf,
					struct hwmon_data *hwmon, int j)
{
	struct link_data *b = data;

	j += sprintf(buf + j, "NODE%d-kpi2: ",
				hwmon->node);
	if (b->kpi_rate == 1) {
		j += sprintf(buf + j, "full rate, ");
	} else {
		j += sprintf(buf + j, "half rate, ");
	}

	switch (b->kpi_state) {
	case POWEROFF_STATE:
		j += sprintf(buf + j, "state(%d): Poweroff",
					b->kpi_state);
		break;
	case DISABLE_STATE:
		j += sprintf(buf + j, "state(%d): Disable",
					 b->kpi_state);
		break;
	case SLEEP_STATE:
		j += sprintf(buf + j, "state(%d): Sleep",
					 b->kpi_state);
		break;
	case LINKUP_STATE:
		j += sprintf(buf + j, "state(%d): Work ",
					 b->kpi_state);
		j += sprintf(buf + j, "width=0x%x",
					b->kpi_width);
		if (b->kpi_width != FULL_WIDTH) {
			j += sprintf(buf + j, "WARNING (not full wlcc width)");
		}
		break;
	}

	j += sprintf(buf + j, " err_mode=0x%x ", b->kpi_md);
	if (b->kpi_state == LINKUP_STATE) {
		switch (b->kpi_md) {
		case 0:
			j += sprintf(buf + j, "- ERROR\n");
			break;
		case 1:
			j += sprintf(buf + j, "- WARNING ");
			break;
		case 2:
			j += sprintf(buf + j, "- OK ");
			break;
		}
	}

	if ((b->kpi_state == LINKUP_STATE) && (b->kpi_md != 0)) {
		j += sprintf(buf + j, "err_ov=0x%x ", b->kpi_ov);
		if (b->kpi_ov != 0) {
			j += sprintf(buf + j, "- overflown (!!!)");
		}

		j += sprintf(buf + j, "err_cnt=0x%x ", b->kpi_cnt);
		if (b->kpi_cnt == CNT_LIMIT) {
			j += sprintf(buf + j, "- too much errors (!!!)\n");
		} else if (b->kpi_cnt != 0) {
			j += sprintf(buf + j, "- found some errors (!!!)\n");
		} else {
			j += sprintf(buf + j, "- OK\n");
		}
	} else {
		j += sprintf(buf + j, "\n");
	}

	return j;
}

static int get_wlcc_information(struct link_data *data, char *buf,
					struct hwmon_data *hwmon, int j)
{
	struct link_data *b = data;
	char *wlcc_half_rate_v6[] = {"2.5", "3", "2.5", "3", "1.25", "1.5", "2", "4"};
	char *wlcc_full_rate_v6[] = {"5", "6", "5", "6", "2.5", "3", "4", "8"};
	char *wlcc_half_rate[] = {"1.25", "1.5", "2.5", "3", "1", "2", "2.25", "2.75"};
	char *wlcc_full_rate[] = {"2.5", "3", "5", "6", "2", "4", "4.5", "5.5"};

	j += sprintf(buf + j, "NODE%d-wlcc: ", hwmon->node);
	if (b->wlcc_rate == 1) {
		if (IS_MACHINE_E16C || IS_MACHINE_E12C ||
				IS_MACHINE_E2C3) {
			j += sprintf(buf + j, "%s Gbit/s (mpll=0x%x full rate), ",
						wlcc_full_rate_v6[b->io_mpll], b->io_mpll);
		} else {
			j += sprintf(buf + j, "%s Gbit/s (mpll=0x%x full rate), ",
						wlcc_full_rate[b->io_mpll], b->io_mpll);
		}
	} else {
		if (IS_MACHINE_E16C || IS_MACHINE_E12C ||
				IS_MACHINE_E2C3) {
			j += sprintf(buf + j, "%s Gbit/s (mpll=0x%x half rate), ",
						 wlcc_half_rate_v6[b->io_mpll], b->io_mpll);
		} else {
			j += sprintf(buf + j, "%s Gbit/s (mpll=0x%x half rate), ",
						 wlcc_half_rate[b->io_mpll], b->io_mpll);
		}
	}

	switch (b->wlcc_active) {
	case LINK_NOT_ACTIVE:
		j += sprintf(buf + j, "wlcc not active(%d), ",
				 b->wlcc_active);
		break;
	case LINK_ACTIVE:
		j += sprintf(buf + j, "wlcc is active(%d), ",
				 b->wlcc_active);
		break;
	}

	switch (b->wlcc_state) {
	case POWEROFF_STATE:
		j += sprintf(buf + j, "state(%d): Poweroff",
					b->wlcc_state);
		break;
	case DISABLE_STATE:
		j += sprintf(buf + j, "state(%d): Disable",
					 b->wlcc_state);
		break;
	case SLEEP_STATE:
		j += sprintf(buf + j, "state(%d): Sleep",
					 b->wlcc_state);
		break;
	case LINKUP_STATE:
		j += sprintf(buf + j, "state(%d): Work ",
					 b->wlcc_state);
		j += sprintf(buf + j, "width=0x%x", b->wlcc_width);
		if (b->wlcc_width != FULL_WIDTH) {
			j += sprintf(buf + j,
				"WARNING (not full wlcc width)");
		}
		break;
	}

	j += sprintf(buf + j, " err_mode=0x%x ", b->wlcc_md);
	if (b->wlcc_state == LINKUP_STATE) {
		switch (b->wlcc_md) {
		case 0:
			j += sprintf(buf + j, "- ERROR\n");
			break;
		case 1:
			j += sprintf(buf + j, "- WARNING ");
			break;
		case 2:
			j += sprintf(buf + j, "- OK ");
			break;
		}
	}
	if ((b->wlcc_state == LINKUP_STATE) && (b->wlcc_md != 0)) {
		j += sprintf(buf + j, "err_ov=0x%x ", b->wlcc_ov);
		if (b->wlcc_ov != 0) {
			j += sprintf(buf + j, "- overflown (!!!)");
		}

		j += sprintf(buf + j, "err_cnt=0x%x ", b->wlcc_cnt);
		if (b->wlcc_cnt == CNT_LIMIT) {
			j += sprintf(buf + j, "- too much errors (!!!)\n");
		} else if (b->wlcc_cnt != 0) {
			j += sprintf(buf + j, "- found some errors (!!!)\n");
		} else {
			j += sprintf(buf + j, "- OK\n");
		}
	} else {
		j += sprintf(buf + j, "\n");
	}

	return j;
}

static int get_ipcc_information(struct link_data *data, char *buf,
					struct hwmon_data *hwmon, int j)
{
	struct link_data *b = data;
	char *ip_rate[] = {"2.5", "3", "4", "4.5", "5", "5.5", "6", "6.25"};
	int i;
	char gbit_link_bitrate[10];
	char letter;

	for (i = 0; i < IPCC_LINKS; i++) {
		switch (ipcc_ctrls[i].offset) {
		case IPCC_CSR1:
			letter = 'A';
			break;
		case IPCC_CSR2:
			letter = 'B';
			break;
		case IPCC_CSR3:
			letter = 'C';
			break;
		default:
			letter = '?';
			break;
		}

		j += sprintf(buf + j, "NODE%d-ipcc-%c-csr(0x%x) width=0x%x, ",
					 hwmon->node, letter, ipcc_ctrls[i].offset, b->width[i]);
		if (IS_MACHINE_E8C || IS_MACHINE_E8C2) {
			j += sprintf(buf + j, "%s Gbit/s(mpll=0x%x), ",
						ip_rate[b->ip_mpll], b->ip_mpll);
		} else if (IS_MACHINE_E16C ||
						IS_MACHINE_E12C ||
							IS_MACHINE_E2C3) {
			convert_mbit2gbit(gbit_link_bitrate, b->link_bitrate[i]);
			j += sprintf(buf + j, "%s Gbit/s, ", gbit_link_bitrate);
		}
		if (b->width[i] != FULL_WIDTH) {
			j += sprintf(buf + j,
					"WARNING (not full width), ");
		}

		switch (b->active[i]) {
		case LINK_NOT_ACTIVE:
			j += sprintf(buf + j, "link not active(%d), ",
						 b->active[i]);
			break;
		case LINK_ACTIVE:
			j += sprintf(buf + j, "link is active(%d), ",
						 b->active[i]);
			break;
		}

		switch (b->state[i]) {
		case POWEROFF_STATE:
			j += sprintf(buf + j, "state(%d): Poweroff",
						b->state[i]);
			break;
		case DISABLE_STATE:
			j += sprintf(buf + j, "state(%d): Disable",
						 b->state[i]);
			break;
		case SLEEP_STATE:
			j += sprintf(buf + j, "state(%d): Sleep",
						 b->state[i]);
			break;
		case LINKUP_STATE:
			j += sprintf(buf + j, "state(%d): Work",
						 b->state[i]);
			break;
		case SERVICE_STATE:
			j += sprintf(buf + j, "state(%d): Service",
						 b->state[i]);
			break;
		case REINIT_STATE:
			j += sprintf(buf + j, "state(%d): Reinit",
						 b->state[i]);
			break;
		}

		if (b->vp[i] == 1) {
			j += sprintf(buf + j,
				", connected with NODE_%d\n", b->pn[i]);
		}

		else {
			j += sprintf(buf + j,
				", without connection\n");
		}

		if (!IS_MACHINE_E16C) {
			if ((b->multilink != 0) || (b->mlc != 0)) {
				j += sprintf(buf + j,
					"ERROR!!! Multilink is not supported for this ");
				j += sprintf(buf + j,
					"CPU, but mlp=0x%x and mlc=0x%x  (ST_P=0x%x)\n",
					b->multilink, b->mlc, b->st_p);
			}
		}

		else if ((b->multilink == 0) && (b->mlc == 1)) {
			j += sprintf(buf + j,
				"ERROR!!! Multilink is not connected on motherboard");
			j += sprintf(buf + j,
				", but enabled by software (ST_P=0x%x)\n", b->st_p);
		}

		else if ((b->multilink == 1) && (b->mlc == 0)) {
			j += sprintf(buf + j,
				"(multilink is disabled by software)\n");
		}

		else if ((b->multilink == 1) && (b->mlc == 1)) {
			j += sprintf(buf + j,
				"(multilink is enabled)\n");
		}
		if (b->state[i] == LINKUP_STATE) {
			switch (b->err_mode[i]) {
			case IPCC_STR_MODE_LERR:
				j += sprintf(buf + j,
					"NODE%d-ipcc-%c-str(0x%x) err_mode=%d - WARNING(0x%x)\n",
						hwmon->node, letter, b->str_reg[i],
						b->err_mode[i], b->str_val[i]);
				j += sprintf(buf + j,
					"amount of errors in cnt_err -  %d\n", b->cnt_err[i]);
				break;
			case IPCC_STR_MODE_RTRY:
				j += sprintf(buf + j,
					"NODE%d-ipcc-%c-str(0x%x) err_mode=%d - OK(0x%x)\n",
						hwmon->node, letter, b->str_reg[i],
						b->err_mode[i], b->str_val[i]);
				j += sprintf(buf + j,
					"amount of errors in cnt_err -  %d\n", b->cnt_err[i]);

				break;
			default:
				j += sprintf(buf + j,
					"NODE%d-ipcc-%c-str(0x%x) err_mode=%d - ERROR(0x%x)\n",
						hwmon->node, letter,  b->str_reg[i],
						b->err_mode[i], b->str_val[i]);
			}
		} else {
			j += sprintf(buf + j,
				"NODE%d-ipcc-%c-str(0x%x) err_mode=%d - OFF(0x%x - CSR)\n",
						hwmon->node, letter,  b->str_reg[i],
						b->err_mode[i], b->csr_reg[i]);
		}
	}

	return j;
}

static ssize_t show_link_data(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct hwmon_data *hwmon = dev_get_drvdata(dev);
	struct link_data b = read_link_data(hwmon);
	int j = 0;

	/* KPI INFORMATION */
	if (b.iol) {
		j = get_kpi_information(&b, buf, hwmon, j);
	}

	/* WLCC INFORMATION */
	if (b.wlcc_state >= 0) {
		j = get_wlcc_information(&b, buf, hwmon, j);
	}

	/* IPCC INFORMATION */
	if (!IS_MACHINE_E2C3) {
		j = get_ipcc_information(&b, buf, hwmon, j);
	}

	return sprintf(buf, "%s", buf);
}

static int get_mem_channels(void)
{
	int mem_channels = 0;
	int cpu_type = machine.native_id;

	switch (cpu_type) {
	case MACHINE_ID_E16C:
		mem_channels = 8;
		break;
	case MACHINE_ID_E12C:
		mem_channels = 2;
		break;
	case MACHINE_ID_E2C3:
		mem_channels = 2;
		break;
	case MACHINE_ID_E8C2:
		mem_channels = 4;
		break;
	case MACHINE_ID_E8C:
		mem_channels = 4;
		break;
	case MACHINE_ID_E8V7:
		mem_channels = 2;
		break;
	}

	return mem_channels;
}

static struct mem_data read_mem(struct hwmon_data *hwmon)
{
	struct mem_data a;
	int val;
	int num_link[MEM_LINKS] = {0, 1, 2, 3, 4, 5, 6, 7};
	int i;
	int mem_channels = get_mem_channels();

	/* Reading information from MC in case of e8v7 */
	if (IS_MACHINE_E8V7) {
		for (i = 0; i < mem_channels; i++) {
			writel(num_link[i], hwmon->base[1] + mc_ctrls_off[4].offset);
			val = readl(hwmon->base[1] + mc_ctrls_off[5].offset);
			a.mem_mode[i] = val & MC_ENABLE_MASK;
			a.mem_secnt[i] = (val >> MC_SECNT_SHIFT) &
							 MC_SECNT_MASK;
			a.mem_uecnt[i] = (val >> MC_UECNT_SHIFT_E8V7) &
							MC_UECNT_MASK_E8V7;
			a.mem_dmode[i] = (val >> MC_DMODE_SHIFT) &
							MC_DMODE_MASK;
			a.mem_reg_val[i] = val;
			a.mem_ctl_val[i] = readl(hwmon->base[1] + MC_CTL_SHIFT);
			a.mem_ctl_mcen[i] = readl(hwmon->base[1] + MC_CTL_SHIFT) & MC_CTL_MCEN_MASK;
			a.mem_status_val[i] = readl(hwmon->base[1] + MC_STATUS_SHIFT);
			a.mem_rst_done[i] = (readl(hwmon->base[1] + MC_STATUS_SHIFT)
							>> MC_ST_RST_DONE_SHIFT)
								& MC_ST_RST_DONE_MASK;
			a.mem_reg[i] = mc_ctrls[5].offset;
			a.mem_hmu_mcen = (readl(hwmon->base[2]) >> OCN_MIL_SHIFT)
						& OCN_MIL_MASK;
		}
	}

	/* Reading information from MC in case of e12c, e16c, e2c3 */
	if (IS_MACHINE_E16C || IS_MACHINE_E12C ||
				IS_MACHINE_E2C3) {
		for (i = 0; i < mem_channels; i++) {
			writel(num_link[i], hwmon->base[1] + mc_ctrls_off[4].offset);
			val = readl(hwmon->base[1] + mc_ctrls_off[5].offset);
			a.mem_mode[i] = val & MC_ENABLE_MASK;
			a.mem_secnt[i] = (val >> MC_SECNT_SHIFT) &
							 MC_SECNT_MASK;
			a.mem_uecnt[i] = (val >> MC_UECNT_SHIFT) &
							MC_UECNT_MASK;
			a.mem_dmode[i] = (val >> MC_DMODE_SHIFT) &
							MC_DMODE_MASK;
			a.mem_reg_val[i] = val;
			a.mem_ctl_val[i] = readl(hwmon->base[1] + MC_CTL_SHIFT);
			a.mem_ctl_mcen[i] = readl(hwmon->base[1] + MC_CTL_SHIFT) & MC_CTL_MCEN_MASK;
			a.mem_status_val[i] = readl(hwmon->base[1] + MC_STATUS_SHIFT);
			a.mem_rst_done[i] = (readl(hwmon->base[1] + MC_STATUS_SHIFT)
							>> MC_ST_RST_DONE_SHIFT)
								& MC_ST_RST_DONE_MASK;
			a.mem_reg[i] = mc_ctrls[5].offset;
			a.mem_hmu_mcen = (readl(hwmon->base[4]) >> HMU_MCEN_SHIFT)
						& HMU_MCEN_MASK;
		}
	}

	/* Reading information from MC in case of e8c, e8c2 */
	else if (IS_MACHINE_E8C || IS_MACHINE_E8C2) {
		for (i = 0; i < mem_channels; i++) {
			val = readl(hwmon->base[2] + mc_ctrls_off[i].offset);
			a.mem_mode[i] = val & MC_ENABLE_MASK;
			a.mem_secnt[i] = (val >> MC_SECNT_SHIFT)
							& MC_SECNT_MASK;
			a.mem_uecnt[i] = (val >> MC_UECNT_SHIFT)
							& MC_UECNT_MASK;
			a.mem_dmode[i] = (val >> MC_DMODE_SHIFT)
							& MC_DMODE_MASK;
			a.mem_reg_val[i] = val;
			a.mem_ctl_val[i] = readl(hwmon->base[2] + mc_ctls_off[i].offset);
			a.mem_ctl_mcen[i] = readl(hwmon->base[2] + mc_ctls_off[i].offset)
						& MC_CTL_MCEN_MASK;
			a.mem_status_val[i] = readl(hwmon->base[2] + MC_STATUS_SHIFT);
			a.mem_rst_done[i] = (readl(hwmon->base[2] + MC_STATUS_SHIFT)
						>> MC_ST_RST_DONE_SHIFT) & MC_ST_RST_DONE_MASK;
			a.mem_reg[i] = mc_ctrls[i].offset;
		}
	}

	return a;
}

static ssize_t show_mem_data(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	struct hwmon_data *hwmon = dev_get_drvdata(dev);
	struct mem_data b = read_mem(hwmon);
	int j = 0;
	int i;
	int mem_channels = get_mem_channels();
	int mc_enabled;

	for (i = 0; i < mem_channels; i++) {
		j += sprintf(buf + j,
			"NODE-%d_MC%d_ECC(0x%x): mem_mode=%d, secnt=0x%x, uecnt=0x%x, dmode=0x%x\n",
						hwmon->node, i, b.mem_reg[i],
						b.mem_mode[i], b.mem_secnt[i],
						b.mem_uecnt[i], b.mem_dmode[i]);
		if ((b.mem_ctl_mcen[i] != 1) && (IS_MACHINE_E8C ||
					 IS_MACHINE_E8C2)) {
			j += sprintf(buf + j,
				"warning!!! MC%d IS DISABLED, MCEN IS OFF\n", i);
		}
		mc_enabled = (b.mem_hmu_mcen >> i) & HMU_ENABLE;
		if ((mc_enabled == 0) &&
			(IS_MACHINE_E16C || IS_MACHINE_E2C3 ||
					IS_MACHINE_E12C)) {
			j += sprintf(buf + j,
				"warning!!! MC%d IS DISABLED, HMU_MIC_MCEN IS OFF\n", i);
		}

		if ((mc_enabled == 0) &&
				IS_MACHINE_E8V7) {
			j += sprintf(buf + j,
				"warning!!! MC%d IS DISABLED, OCN_MIL_MCEN IS OFF\n", i);
		}


		if (b.mem_mode[i] != 1) {
			j += sprintf(buf + j,
				"Warning!!! ECC control is disabled\n");
		}

		if (b.mem_dmode[i] != 0) {
			j += sprintf(buf + j,
				"Warning!!! ECC debug mode is set\n");
		}

		if (b.mem_uecnt[i] != 0) {
			j += sprintf(buf + j,
				"Warning!!! ECC multi-error counter (uecnt = 0x%x)\n",
							b.mem_uecnt[i]);
		}

		if (b.mem_secnt[i] != 0) {
			j += sprintf(buf + j,
				"Warning!!! ECC single-error counter (secnt = 0x%x)\n",
							b.mem_secnt[i]);
		}

		if (b.mem_ctl_mcen[i] != 1) {
			j += sprintf(buf + j,
				"Warning!!! controller is disabled (MC_CTL = 0x%x)\n",
							b.mem_ctl_val[i]);
		}
		if (IS_MACHINE_E16C || IS_MACHINE_E12C ||
				IS_MACHINE_E2C3 || IS_MACHINE_E8V7) {
			if (b.mem_rst_done[i] == 0) {
				j += sprintf(buf + j,
					"Warning!!! status rst_done = 0x%x (MC_STATUS = 0x%x)\n",
							b.mem_rst_done[i],
							b.mem_status_val[i]);
			}
		}
	}

	return sprintf(buf, "%s", buf);
}

static struct mem_data read_mem_rate(struct hwmon_data *hwmon)
{
	struct mem_data a;
	int i;
	int num_link[MEM_LINKS] = {0, 1, 2, 3, 4, 5, 6, 7};
	int mc_freq;
	int mc_ddr_rate;
	long long int mc_mon_ctr0;
	int mc_mon_ctr_ext;
	long long int mc_mnt0;
	int ref = 125;
	long int pwr_mgr1;
	long int pwr_mgr2;
	int mc_rst;
	int mc_outena;
	int mc_clkr;
	int mc_clkf;
	int mc_clkod;
	int mc_lock;
	int mem_channels = get_mem_channels();

	if (IS_MACHINE_E2C3 || IS_MACHINE_E12C ||
			IS_MACHINE_E16C || IS_MACHINE_E8V7) {
		writel(0xF, hwmon->base[1]);
		writel(0xFFFF000F, hwmon->base[1] + MC_MON_CTL_SHIFT);
		writel(0xFFFF0000, hwmon->base[1] + MC_MON_CTL_SHIFT);
		mdelay(MC_MON_DELAY_MS);
		writel(0xF, hwmon->base[1]);
		writel(0x0000000C, hwmon->base[1] + MC_MON_CTL_SHIFT);
		writel(0x0, hwmon->base[1]);

		for (i = 0; i < mem_channels; i++) {
			writel(num_link[i], hwmon->base[1]);
			mc_mon_ctr0 = readl(hwmon->base[1] + MC_MON_CTR0_SHIFT);
			mc_mon_ctr_ext = readl(hwmon->base[1] + MC_MON_CTRext_SHIFT);

			mc_mnt0 = mc_mon_ctr_ext & MC_MNT0_MASK;
			mc_mnt0 = (mc_mnt0 << MC_MNT0_SHIFT) + mc_mon_ctr0;

			mc_freq = mc_mnt0/10/1000000;
			mc_ddr_rate = mc_freq * 2 * 2;
			a.mem_freq[i] = mc_freq;
			a.mem_ddr_rate[i] = mc_ddr_rate;
			a.mem_ctl_val[i] = readl(hwmon->base[1] + MC_CTL_SHIFT);
			a.mem_ctl_mcen[i] = readl(hwmon->base[1] + MC_CTL_SHIFT) & MC_CTL_MCEN_MASK;
			}
		if (IS_MACHINE_E8V7) {
			a.mem_hmu_mcen = (readl(hwmon->base[2]) >> OCN_MIL_SHIFT)
				& OCN_MIL_MASK;
		} else {
			a.mem_hmu_mcen = (readl(hwmon->base[4]) >> HMU_MCEN_SHIFT)
				& HMU_MCEN_MASK;
		}
	} else if (IS_MACHINE_E8C || IS_MACHINE_E8C2) {
		/* Here I get memory freq from mgr1 */
		pwr_mgr1 = readl(hwmon->base[1]);
		mc_rst = pwr_mgr1 & RST_MASK;
		mc_outena = (pwr_mgr1 & OUTENA_MASK) >> OUTENA_SHIFT;
		mc_clkr = (pwr_mgr1 & CLKR_MASK) >> CLKR_SHIFT;
		mc_clkf = (pwr_mgr1 & CLKF_MASK) >> CLKF_SHIFT;
		mc_clkod = (pwr_mgr1 & CLKOD_MASK) >> CLKOD_SHIFT;
		mc_lock = (pwr_mgr1 & LOCK_MASK) >> LOCK_SHIFT;
		a.mem_freq_e8c_mgr1 = ref / (mc_clkr + 1) * (mc_clkf + 1) /
						(mc_clkod + 1);
		a.mem_ddr_e8c_mgr1 = 4 * ref / (mc_clkr + 1) * (mc_clkf + 1) /
						(mc_clkod + 1);

		/* Here I do th same thing but from mgr2 */
		pwr_mgr2 = readl(hwmon->base[1] + PWR_MGR2_SHIFT);
		mc_rst = pwr_mgr2 & RST_MASK;
		mc_outena = (pwr_mgr2 & OUTENA_MASK) >> OUTENA_SHIFT;
		mc_clkr = (pwr_mgr2 & CLKR_MASK) >> CLKR_SHIFT;
		mc_clkf = (pwr_mgr2 & CLKF_MASK) >> CLKF_SHIFT;
		mc_clkod = (pwr_mgr2 & CLKOD_MASK) >> CLKOD_SHIFT;
		mc_lock = (pwr_mgr2 & LOCK_MASK) >> LOCK_SHIFT;
		a.mem_freq_e8c_mgr2 = ref / (mc_clkr + 1) * (mc_clkf + 1) /
						(mc_clkod + 1);
		a.mem_ddr_e8c_mgr2 = 4 * ref / (mc_clkr + 1) *
						(mc_clkf + 1) / (mc_clkod + 1);
	}

	return a;
}

static struct mem_data save[MAX_NODES];
static struct mem_data new[MAX_NODES];
static void thread_func(struct work_struct *work)
{
	struct th_info *th_info_var = container_of(work, struct th_info, work);

	if (!th_info_var) {
		pr_err("THREAD FUNCTION: th_info_var is empty!\n");
		return;
	}

	struct hwmon_data *hwmon = container_of(th_info_var, struct hwmon_data, th_info_var);

	if (th_info_var->mode == 0)
		save[th_info_var->node] = read_mem_rate(hwmon);
	else
		new[th_info_var->node] = read_mem_rate(hwmon);

	complete(&th_info_var->rate_done);
}


static ssize_t show_mem_rate(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	struct hwmon_data *hwmon = dev_get_drvdata(dev);
	struct th_info *th_info_var = &hwmon->th_info_var;

	mutex_lock(&th_info_var->mutex_measure);

	wait_for_completion(&th_info_var->rate_done);

	th_info_var->mode = 1;

	int ret = queue_work_on(1, hwmon->wq, &th_info_var->work);
	if (!ret) {
		mutex_unlock(&th_info_var->mutex_measure);
		return -EAGAIN;
	}
	wait_for_completion(&th_info_var->rate_done);

	struct mem_data b = new[hwmon->node];
	int j = 0;
	int curr_ch;
	int mc_enabled;
	int mem_channels = get_mem_channels();

	for (curr_ch = 0; curr_ch < mem_channels; curr_ch++) {
		mc_enabled = ((b.mem_hmu_mcen >> curr_ch) & HMU_ENABLE);
		if (mc_enabled == 0) {
			if (!IS_MACHINE_E8V7)
				j += sprintf(buf + j,
					"WARNING!!! NODE_%d: MC_%d: controller is disabled (MIC_HMU_MCEN=%d)\n",
						hwmon->node, curr_ch, b.mem_hmu_mcen);
			else
				j += sprintf(buf + j,
					"WARNING!!! NODE_%d: MC_%d: controller is disabled (OCN_MIL_MCEN=%d)\n",
						hwmon->node, curr_ch, b.mem_hmu_mcen);
		} else {
			j += sprintf(buf + j,
				"NODE_%d: MC_%d: DDR4: %d (MC_freq %d MHz) likely!\n",
						hwmon->node, curr_ch, b.mem_ddr_rate[curr_ch],
									b.mem_freq[curr_ch]);
		}
	}
	complete(&th_info_var->rate_done);
	mutex_unlock(&th_info_var->mutex_measure);
	return sprintf(buf, "%s", buf);
}

static ssize_t show_mem_rate_saved(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	struct hwmon_data *hwmon = dev_get_drvdata(dev);
	int j = 0;
	int curr_ch;
	int mc_enabled;
	int mem_channels = get_mem_channels();

	for (curr_ch = 0; curr_ch < mem_channels; curr_ch++) {
		mc_enabled = ((save[hwmon->node].mem_hmu_mcen >> curr_ch) & HMU_ENABLE);
		if (mc_enabled == 0) {
			if (!IS_MACHINE_E8V7)
				j += sprintf(buf + j,
					"WARNING!!! NODE_%d: MC_%d: controller is disabled (MIC_HMU_MCEN=%d)\n",
						hwmon->node, curr_ch,
							save[hwmon->node].mem_hmu_mcen);
			else
				j += sprintf(buf + j,
					"WARNING!!! NODE_%d: MC_%d: controller is disabled (OCN_MIL_MCEN=%d)\n",
						hwmon->node, curr_ch,
							save[hwmon->node].mem_hmu_mcen);
		} else {
			j += sprintf(buf + j,
				"NODE_%d: MC_%d: DDR4: %d (MC_freq %d MHz) likely!\n",
					hwmon->node, curr_ch,
						save[hwmon->node].mem_ddr_rate[curr_ch],
							save[hwmon->node].mem_freq[curr_ch]);
		}
	}

	return sprintf(buf, "%s", buf);
}

static ssize_t show_mem_rate_e8c(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	struct hwmon_data *hwmon = dev_get_drvdata(dev);
	struct mem_data b = read_mem_rate(hwmon);
	int mem_channels = get_mem_channels();
	int i;
	int j = 0;

	for (i = 0; i < mem_channels; i++) {
		if ((i == 0) || (i == 1)) {
			j += sprintf(buf + j,
				"NODE_%d: MC_%d: DDR4: %d (MC_freq %d MHz): MGR1\n",
					hwmon->node, i, b.mem_ddr_e8c_mgr1,
							b.mem_freq_e8c_mgr1);
		} else if ((i == 2) || (i == 3)) {
			j += sprintf(buf + j,
				"NODE_%d: MC_%d: DDR4: %d (MC_freq %d MHz): MGR2\n",
					hwmon->node, i, b.mem_ddr_e8c_mgr2,
							b.mem_freq_e8c_mgr2);
		}
	}

	return sprintf(buf, "%s", buf);
}

static struct pins_data read_pins(struct hwmon_data *hwmon)
{
	int node = hwmon->node;
	struct pins_data a;
	int pmc_inform = 0;
	int rt_lcfg_val;
	int curr_LCFG = 0;

	switch (node) {
	case 0:
		curr_LCFG = RT_LCFG0_SHIFT;
		break;
	case 1:
		curr_LCFG = RT_LCFG1_SHIFT;
		break;
	case 2:
		curr_LCFG = RT_LCFG2_SHIFT;
		break;
	case 3:
		curr_LCFG = RT_LCFG3_SHIFT;
		break;
	default:
		curr_LCFG = 0;
		break;
	}

	rt_lcfg_val = readl(hwmon->base[0] + curr_LCFG);
	a.vp = rt_lcfg_val & RT_LCFG_VP_MASK;
	a.pn = (rt_lcfg_val >> RT_LCFG_PN_SHIFT) & RT_LCFG_PN_MASK;
	if (IS_MACHINE_E16C || IS_MACHINE_E12C ||
			IS_MACHINE_E2C3) {
		pmc_inform = readl(hwmon->base[3]);
		a.sys_mon_0 = readl(hwmon->base[3] + PMC_SYS_MON_0_SHIFT);
		a.sys_mon_1 = readl(hwmon->base[3] + PMC_SYS_MON_1_SHIFT);
	}
	if (IS_MACHINE_E8V7) {
		pmc_inform = readl(hwmon->base[3]);
		a.sys_mon_0 = readl(hwmon->base[3] + PMC_SYS_MON_0_SHIFT_E8V7);
		a.sys_mon_1 = readl(hwmon->base[3] + PMC_SYS_MON_1_SHIFT_E8V7);
	}
	a.pmc_info = pmc_inform;

	return a;
}

static ssize_t show_pins(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	struct hwmon_data *hwmon = dev_get_drvdata(dev);
	struct pins_data b = read_pins(hwmon);
	int i;
	char *machine_model = NULL;
	int cpu_type = machine.native_id;
	int pin;
	int id_model = b.pmc_info & PMC_MODEL_MASK;
	int id_version = (b.pmc_info & PMC_VERSION_MASK) >> PMC_VERSION_SHIFT;
	int j;

	switch (cpu_type) {
	case MACHINE_ID_E16C:
		machine_model = "Elbrus-16C";
		break;
	case MACHINE_ID_E12C:
		machine_model = "Elbrus-12C";
		break;
	case MACHINE_ID_E2C3:
		machine_model = "Elbrus-E2C3";
		break;
	case MACHINE_ID_E8V7:
		machine_model = "Elbrus-E8V7";
		break;
	}

	j = sprintf(buf, "Identificator PMC: 0x%x\n", b.pmc_info);
	j += sprintf(buf + j,
		" - cpu model: %s (0x%x)\n", machine_model, id_model);
	j += sprintf(buf + j,
		" - cpu version: %x\n", id_version);
	j += sprintf(buf + j,
		"NODE_%d: Register PMC_SYS_MON_0=0x%x\n",
				hwmon->node, b.sys_mon_0);

	/* Here depending on cpu type, I'm printing config of pins */
	if (!IS_MACHINE_E8V7) {
		for (i = 0; i < 8; i++) {
			pin = (b.sys_mon_0 >> pins_ctrls[i].shift) &
							pins_ctrls[i].mask;
			j += sprintf(buf + j, " - %s=0x%x",
						pins_ctrls[i].name, pin);
			if ((i == 0 || i == 1 || i == 2 || i == 4) &&  (pin == 1)) {
				j += sprintf(buf + j, " (warning!!!)");
			}
			j += sprintf(buf + j, "\n");
		}
	}

	if (IS_MACHINE_E12C) {
		for (i = 8; i < 10; i++) {
			pin = (b.sys_mon_0 >> pins_ctrls[i].shift) &
							pins_ctrls[i].mask;
			j += sprintf(buf + j, " - %s=0x%x",
						pins_ctrls[i].name, pin);
		}
	}

	if (IS_MACHINE_E16C) {
		for (i = 9; i < 13; i++) {
			pin = (b.sys_mon_0 >> pins_ctrls[i].shift) &
							pins_ctrls[i].mask;
			j += sprintf(buf + j, " - %s=0x%x",
					pins_ctrls[i].name, pin);
			if ((i == 11 || i == 12) && (pin == 1)) {
				j += sprintf(buf + j, " (warning!!!)");
			}
		j += sprintf(buf + j, "\n");
		}
	}

	if (IS_MACHINE_E2C3) {
		pin = (b.sys_mon_0 >> pins_ctrls[PIN_CORE_ENABLE_NUM].shift) &
					pins_ctrls[PIN_CORE_ENABLE_NUM].mask;
		j += sprintf(buf + j, " - %s=0x%x",
				pins_ctrls[PIN_CORE_ENABLE_NUM].name, pin);
		if (pin == 1) {
			j += sprintf(buf + j, " (warning!!!)");
		}
		j += sprintf(buf + j, "\n");
	}

	if (IS_MACHINE_E8V7) {
		for (i = 44; i < 46; i++) {
			pin = (b.sys_mon_0 >> pins_ctrls[i].shift) &
							pins_ctrls[i].mask;
			j += sprintf(buf + j, " - %s=0x%x",
					pins_ctrls[i].name, pin);
		j += sprintf(buf + j, "\n");
		}
	}

	j += sprintf(buf + j,
			"NODE_%d: Register PMC_SYS_MON_1=0x%x\n",
					hwmon->node, b.sys_mon_1);
	if (!IS_MACHINE_E8V7) {
		for (i = 14; i < 23; i++) {
			pin = (b.sys_mon_1 >> pins_ctrls[i].shift) &
							 pins_ctrls[i].mask;
			j += sprintf(buf + j, " - %s=0x%x",
					pins_ctrls[i].name, pin);

			if ((i != 20 && i != 21 && i != 22) && (pin == 1)) {
				j += sprintf(buf + j, " (warning!!!)");
			}
			j += sprintf(buf + j, "\n");
		}
	}

	if (IS_MACHINE_E8V7) {
		pin = (b.sys_mon_1 >> pins_ctrls[PIN_FREQ_MODE_NUM].shift) &
					pins_ctrls[PIN_FREQ_MODE_NUM].mask;
		j += sprintf(buf + j, " - %s=0x%x",
				pins_ctrls[PIN_FREQ_MODE_NUM].name, pin);
		if (pin == 1) {
			j += sprintf(buf + j, " (warning!!!)");
		}
		j += sprintf(buf + j, "\n");
		pin = (b.sys_mon_1 >> pins_ctrls[MACHINE_GEN_ALERT_NUM].shift) &
					pins_ctrls[MACHINE_GEN_ALERT_NUM].mask;
		j += sprintf(buf + j, " - %s=0x%x",
				pins_ctrls[MACHINE_GEN_ALERT_NUM].name, pin);
		if (pin == 1) {
			j += sprintf(buf + j, " (warning!!!)");
		}
		j += sprintf(buf + j, "\n");

		for (i = 17; i < 20; i++) {
			pin = (b.sys_mon_1 >> pins_ctrls[i].shift) &
							pins_ctrls[i].mask;
			j += sprintf(buf + j, " - %s=0x%x",
					pins_ctrls[i].name, pin);
			if (pin == 1) {
				j += sprintf(buf + j, " (warning!!!)");
			}
			j += sprintf(buf + j, "\n");
		}

		pin = (b.sys_mon_1 >> pins_ctrls[PIN_EFUSE_MODE_NUM].shift) &
					pins_ctrls[PIN_EFUSE_MODE_NUM].mask;
		j += sprintf(buf + j, " - %s=0x%x",
				pins_ctrls[PIN_EFUSE_MODE_NUM].name, pin);
		j += sprintf(buf + j, "\n");
	}

	if (IS_MACHINE_E12C) {
		for (i = 23; i < 28; i++) {
			pin = (b.sys_mon_1 >> pins_ctrls[i].shift) &
							pins_ctrls[i].mask;
			j += sprintf(buf + j, " - %s=0x%x",
					pins_ctrls[i].name, pin);
			if ((i != 27) && (pin == 1)) {
				j += sprintf(buf + j, " (warning!!!)");
			}
			j += sprintf(buf + j, "\n");
		}
	}

	if (IS_MACHINE_E16C) {
		for (i = 28; i < 42; i++) {
			pin = (b.sys_mon_1 >> pins_ctrls[i].shift) &
					pins_ctrls[i].mask;
			j += sprintf(buf + j, " - %s=0x%x",
						pins_ctrls[i].name, pin);
			if ((i != 38 && i != 39 && i != 40 && i != 41)
								&& (pin == 1)) {
				j += sprintf(buf + j, " (warning!!!)");
			}
			j += sprintf(buf + j, "\n");
		}
	}

	if (IS_MACHINE_E2C3) {
		for (i = 41; i < 44; i++) {
			pin = (b.sys_mon_1 >> pins_ctrls[i].shift) &
							pins_ctrls[i].mask;
			j += sprintf(buf + j,
				" - %s=0x%x", pins_ctrls[i].name, pin);

			if ((i != 41) && (pin == 1)) {
				j += sprintf(buf + j, " (warning!!!)");
			}
			j += sprintf(buf + j, "\n");
		}
	}

	if (IS_MACHINE_E8V7) {
		for (i = 46; i < 51; i++) {
			pin = (b.sys_mon_1 >> pins_ctrls[i].shift) &
							pins_ctrls[i].mask;
			j += sprintf(buf + j,
				" - %s=0x%x", pins_ctrls[i].name, pin);
			if (pin == 1) {
				j += sprintf(buf + j, " (warning!!!)");
			}
			j += sprintf(buf + j, "\n");
		}

		for (i = 51; i < 59; i++) {
			pin = (b.sys_mon_1 >> pins_ctrls[i].shift) &
							pins_ctrls[i].mask;
			j += sprintf(buf + j,
				" - %s=0x%x", pins_ctrls[i].name, pin);
			j += sprintf(buf + j, "\n");
		}
	}

	return sprintf(buf, "%s", buf);
}

static struct bist_data read_bist_e8v7(int node)
{
	struct bist_data a;
	struct pci_dev *dev;
	static void __iomem *base_addr;
	/* GPU_BIST READ */
	dev = pci_get_device(PCI_VIRT_BRIDGE_VENDOR_ID,
				PCI_VIRT_3DGPU_DEVICE_ID, NULL);
	if (dev) {
		a.GPU_present = true;
		pci_read_config_dword(dev, 0x50, &a.GPU0_E8V7.word);
		pci_read_config_dword(dev, 0x54, &a.GPU1_E8V7.word);
		pci_dev_put(dev);
	} else {
		a.GPU_present = false;
	}
	/* VXD_BIST READ */
	dev = pci_get_device(PCI_VIRT_BRIDGE_VENDOR_ID,
				PCI_VIRT_DEC_DEVICE_ID, NULL);
	if (dev) {
		a.VXD_present = true;
		pci_read_config_dword(dev, 0x50, &a.VXD_E8V7.word);
		pci_dev_put(dev);
	} else {
		a.VXD_present = false;
	}
	/* MGA2_BIST READ (READING FROM BAR0) */
	dev = pci_get_device(PCI_VIRT_BRIDGE_VENDOR_ID,
			PCI_VIRT_MGA27_DEVICE_ID, NULL);
	if (dev) {
		a.MGA_present = true;
		base_addr = pci_iomap(dev, 0, PCI_BIST_SIZE);
		if (!base_addr) {
			pci_release_regions(dev);
			a.MGA_present = false;
		} else {
			a.MGA_E8V7.word = readl(base_addr + 0x3F8);
			pci_iounmap(dev, base_addr);
		}
		pci_dev_put(dev);
	} else {
		a.MGA_present = false;
	}
	return a;
}

static ssize_t show_bist_info_e8v7(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	struct hwmon_data *hwmon = dev_get_drvdata(dev);
	struct bist_data a = read_bist_e8v7(hwmon->node);
	int i;
	int j = 0;
	int GPU0_BIST_bits[MAX_GPU0_E8V7] = {a.GPU0_E8V7.hi_mmu_slave_cache_u_mem_3,
			a.GPU0_E8V7.hi_mmu_slave_cache_u_mem_2,
			a.GPU0_E8V7.hi_mmu_slave_cache_u_mem_1,
			a.GPU0_E8V7.hi_mmu_slave_cache_u_mem_0, a.GPU0_E8V7.pe_color_src_3,
			a.GPU0_E8V7.tx_LodAddressRam_3, a.GPU0_E8V7.tx_fast_cache_3,
			a.GPU0_E8V7.LFIFO_3, a.GPU0_E8V7.us_dirbank_cache_3,
			a.GPU0_E8V7.pixel_input_buffer_3, a.GPU0_E8V7.a0_ram_3,
			a.GPU0_E8V7.context_ram_3, a.GPU0_E8V7.temporary_register_3,
			a.GPU0_E8V7.pe_color_src_2, a.GPU0_E8V7.tx_LodAddressRam_2,
			a.GPU0_E8V7.tx_fast_cache_2, a.GPU0_E8V7.LFIFO_2,
			a.GPU0_E8V7.us_dirbank_cache_2, a.GPU0_E8V7.pixel_input_buffer_2,
			a.GPU0_E8V7.a0_ram_2, a.GPU0_E8V7.context_ram_2,
			a.GPU0_E8V7.temporary_register_2, a.GPU0_E8V7.pe_color_src_1,
			a.GPU0_E8V7.tx_LodAddressRam_1, a.GPU0_E8V7.tx_fast_cache_1,
			a.GPU0_E8V7.LFIFO_1, a.GPU0_E8V7.us_dirbank_cache_1,
			a.GPU0_E8V7.pixel_input_buffer_1, a.GPU0_E8V7.a0_ram_1,
			a.GPU0_E8V7.context_ram_1, a.GPU0_E8V7.temporary_register_1,
			a.GPU0_E8V7.pe_color_src_0};
	char GPU0_BIST_name[MAX_GPU0_E8V7][WORD_SIZE_E8V7] = {"hi_mmu_slave_cache_u_mem_3",
				"hi_mmu_slave_cache_u_mem_2", "hi_mmu_slave_cache_u_mem_1",
				"hi_mmu_slave_cache_u_mem_0", "pe_color_src_3",
				"tx_LodAddressRam_3", "tx_fast_cache_3", "LFIFO_3",
				"us_dirbank_cache_3", "pixel_input_buffer_3", "a0_ram_3",
				"context_ram_3", "temporary_register_3", "pe_color_src_2",
				"tx_LodAddressRam_2",	"tx_fast_cache_2", "LFIFO_2",
				"us_dirbank_cache_2", "pixel_input_buffer_2", "a0_ram_2",
				"context_ram_2", "temporary_register_2", "pe_color_src_1",
				"tx_LodAddressRam_1", "tx_fast_cache_1", "LFIFO_1",
				"us_dirbank_cache_1", "pixel_input_buffer_1", "a0_ram_1",
				"context_ram_1", "temporary_register_1",
				"pe_color_src_0"};

	int GPU1_BIST_bits[MAX_GPU1_E8V7] = {a.GPU1_E8V7.tx_LodAddressRam_0,
			a.GPU1_E8V7.tx_fast_cache_0, a.GPU1_E8V7.LFIFO_0,
			a.GPU1_E8V7.us_dirbank_cache_0, a.GPU1_E8V7.pixel_input_buffer_0,
			a.GPU1_E8V7.a0_ram_0, a.GPU1_E8V7.context_ram_0,
			a.GPU1_E8V7.temporary_register_0};
	char GPU1_BIST_name[MAX_GPU1_E8V7][WORD_SIZE_E8V7] = {"tx_LodAddressRam_0",
				"tx_fast_cache_0", "LFIFO_0", "us_dirbank_cache_0",
				"pixel_input_buffer_0", "a0_ram_0", "context_ram_0",
				"temporary_register_0"};

	int VXD_BIST_bits[MAX_VXD_E8V7] = {a.VXD_E8V7.prefetch_cache_3,
			a.VXD_E8V7.emd_ctrl_frame_cdf_3, a.VXD_E8V7.mvd_above0_ambc0_3,
			a.VXD_E8V7.pred_ambc_3, a.VXD_E8V7.ref_bwd_ref_fwd_3,
			a.VXD_E8V7.filter_above_bs_data_2, a.VXD_E8V7.filter_above_df_data_2,
			a.VXD_E8V7.sao_filter_shared_ram_2, a.VXD_E8V7.dec_400_ch_lu_ts_0,
			a.VXD_E8V7.sca_row_0, a.VXD_E8V7.cache_data_0, a.VXD_E8V7.reorder_row_0,
			a.VXD_E8V7.stile_row_0, a.VXD_E8V7.shaper_0};
	char VXD_BIST_name[MAX_VXD_E8V7][WORD_SIZE_E8V7] = {"prefetch_cache_3",
				"emd_ctrl_frame_cdf_3", "mvd_above0_ambc0_3", "pred_ambc_3",
				"ref_bwd_ref_fwd_3", "filter_above_bs_data_2",
				"filter_above_df_data_2", "sao_filter_shared_ram_2",
				"dec400_ch_lu_ts_0", "sca_row_0", "cache_data_0", "reorder_row_0",
				"stile_row_0", "shaper_0"};

	int MGA_BIST_bits[MAX_MGA_E8V7] = {a.MGA_E8V7.bist_0, a.MGA_E8V7.bist_1, a.MGA_E8V7.bist_2,
			a.MGA_E8V7.bist_3, a.MGA_E8V7.bist_4, a.MGA_E8V7.bist_5, a.MGA.bist_6,};
	char MGA_BIST_name[MAX_MGA_E8V7][WORD_SIZE_E8V7] = {"bist_0", "bist_1", "bist_2", "bist_3",
				"bist_4", "bist_5", "bist_6"};

	/*Checking GPU_BIST*/
	if (a.GPU_present) {
		j += sprintf(buf + j, "GPU_BIST:\n");
		for (i = 0; i < MAX_GPU0_E8V7; i++) {
			if (GPU0_BIST_bits[i]) {
				j += sprintf(buf + j, "%s=%d -- ERROR in memory\n",
							GPU0_BIST_name[i], GPU0_BIST_bits[i]);
			} else {
				j += sprintf(buf + j, "%s=%d\n",
							GPU0_BIST_name[i], GPU0_BIST_bits[i]);
			}
		}
		for (i = 0; i < MAX_GPU1_E8V7; i++) {
			if (GPU1_BIST_bits[i]) {
				j += sprintf(buf + j, "%s=%d -- ERROR in memory\n",
							GPU1_BIST_name[i], GPU1_BIST_bits[i]);
			} else {
				j += sprintf(buf + j, "%s=%d\n",
							GPU1_BIST_name[i], GPU1_BIST_bits[i]);
			}
		}
	} else {
		j += sprintf(buf + j, "Warning!!! GPU is disabled\n");
	}

	/*Checking VXD_BIST*/
	if (a.VXD_present) {
		j += sprintf(buf + j, "\nVXD_BIST:\n");
		for (i = 0; i < MAX_VXD_E8V7; i++) {
			if (VXD_BIST_bits[i]) {
				j += sprintf(buf + j, "%s=%d -- ERROR in memory\n",
							VXD_BIST_name[i], VXD_BIST_bits[i]);
			} else {
				j += sprintf(buf + j, "%s=%d\n",
							VXD_BIST_name[i], VXD_BIST_bits[i]);
			}
		}
	} else {
		j += sprintf(buf + j, "Warning!!! VXD is disabled\n");
	}

	/*Checking MGA27_BIST*/
	if (a.MGA_present) {
		j += sprintf(buf + j, "\nMGA2.7_BIST:\n");
		for (i = 0; i < MAX_MGA_E8V7; i++) {
			if (MGA_BIST_bits[i]) {
				j += sprintf(buf + j, "%s=%d -- ERROR in memory\n",
							MGA_BIST_name[i], MGA_BIST_bits[i]);
			} else {
				j += sprintf(buf + j, "%s=%d\n",
							MGA_BIST_name[i], MGA_BIST_bits[i]);
			}
		}
	} else {
		j += sprintf(buf + j, "Warning!!! MGA2.7 is disabled\n");
	}
	return sprintf(buf, "%s", buf);
}

static struct bist_data read_bist(int node)
{
	struct bist_data a;
	struct pci_dev *dev;
	static void __iomem *base_addr;
	/* GPU_BIST READ */
	dev = pci_get_device(PCI_VIRT_BRIDGE_VENDOR_ID,
				PCI_VIRT_GX6650_DEVICE_ID, NULL);
	if (dev) {
		a.GPU_present = true;
		pci_read_config_dword(dev, 0x40, &a.GPU.word);
		pci_dev_put(dev);
	} else {
		a.GPU_present = false;
	}
	/* VXE_BIST READ */
	dev = pci_get_device(PCI_VIRT_BRIDGE_VENDOR_ID,
				PCI_VIRT_E5810_DEVICE_ID, NULL);
	if (dev) {
		a.VXE_present = true;
		pci_read_config_dword(dev, 0x40, &a.VXE.word);
		pci_dev_put(dev);
	} else {
		a.VXE_present = false;
	}
	/* VXD_BIST READ */
	dev = pci_get_device(PCI_VIRT_BRIDGE_VENDOR_ID,
				PCI_VIRT_D5520_DEVICE_ID, NULL);
	if (dev) {
		a.VXD_present = true;
		pci_read_config_dword(dev, 0x40, &a.VXD.word);
		pci_dev_put(dev);
	} else {
		a.VXD_present = false;
	}
	/* MGA2_BIST READ (READING FROM BAR0) */
	dev = pci_get_device(PCI_VIRT_BRIDGE_VENDOR_ID,
			PCI_VIRT_MGA25_DEVICE_ID, NULL);
	if (dev) {
		a.MGA_present = true;
		base_addr = pci_iomap(dev, 0, PCI_BIST_SIZE);
		if (!base_addr) {
			pci_release_regions(dev);
			a.MGA_present = false;
		} else {
			a.MGA.word = readl(base_addr + 0x3F8);
			pci_iounmap(dev, base_addr);
		}
		pci_dev_put(dev);
	} else {
		a.MGA_present = false;
	}
	return a;
}

static ssize_t show_bist_info(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	struct hwmon_data *hwmon = dev_get_drvdata(dev);
	struct bist_data a = read_bist(hwmon->node);
	int i;
	int j = 0;
	int GPU_BIST_bits[MAX_GPU] = {a.GPU.SLC2, a.GPU.TA_UVS, a.GPU.tornado, a.GPU.texas_ph0,
			  a.GPU.raterisation_ph0, a.GPU.USC0_dustA_ph0, a.GPU.USC1_dustA_ph0,
			  a.GPU.USC0_dustB_ph0, a.GPU.USC1_dustB_ph0, a.GPU.texas_ph1,
			  a.GPU.raterisation_ph1, a.GPU.USC0_dustA_ph1, a.GPU.USC1_dustA_ph1};
	char GPU_BIST_name[MAX_GPU][WORD_SIZE] = {"SLC2", "TA_UVS", "tornado", "texas_ph0",
				"raterisation_ph0", "USC0_dustA_ph0", "USC1_dustA_ph0",
				"USC0_dustB_ph0", "USC1_dustB_ph0", "texas_ph1",
				"raterisation_ph1", "USC0_dustA_ph1", "USC1_dustA_ph1"};
	int VXE_BIST_bits[MAX_VXE] = {a.VXE.front_end_p0, a.VXE.cache_p0, a.VXE.back_end_p0,
				a.VXE.front_end_p1, a.VXE.cache_p1, a.VXE.back_end_p1,
				a.VXE.front_end_p2, a.VXE.cache_p2, a.VXE.back_end_p2,
				a.VXE.sys_if};
	char VXE_BIST_name[MAX_VXE][WORD_SIZE] = {"front_end_p0", "cache_p0", "back_end_p0",
				"front_end_p1", "cache_p1", "back_end_p1",
				"front_end_p2", "cache_p2", "back_end_p2", "sys_if"};
	int VXD_BIST_bits[MAX_VXD] = {a.VXD.mmu_cache, a.VXD.mtx_core_ram,
			a.VXD.pipe1, a.VXD.pipe2, a.VXD.pipe3};
	char VXD_BIST_name[MAX_VXD][WORD_SIZE] = {"mmu_cache", "mtx_core_ram", "pipe1",
							 "pipe2", "pipe3"};
	int MGA_BIST_bits[MAX_MGA] = {a.MGA.bist_0, a.MGA.bist_1, a.MGA.bist_2,
				a.MGA.bist_3, a.MGA.bist_4, a.MGA.bist_5,
				a.MGA.bist_6, a.MGA.bist_7, a.MGA.bist_8,
				a.MGA.bist_9};
	char MGA_BIST_name[MAX_MGA][WORD_SIZE] = {"bist_0", "bist_1", "bist_2", "bist_3", "bist_4",
				 "bist_5", "bist_6", "bist_7", "bist_8", "bist_9"};

	/*Checking GPU_BIST*/
	if (a.GPU_present) {
		j += sprintf(buf + j, "GPU_BIST:\n");
		for (i = 0; i < MAX_GPU; i++) {
			if (GPU_BIST_bits[i]) {
				j += sprintf(buf + j, "%s=%d -- ERROR in memory\n",
							GPU_BIST_name[i], GPU_BIST_bits[i]);
			} else {
				j += sprintf(buf + j, "%s=%d\n",
							GPU_BIST_name[i], GPU_BIST_bits[i]);
			}
		}
	} else {
		j += sprintf(buf + j, "Warning!!! GPU is disabled\n");
	}

	/*Checking VXE_BIST*/
	if (a.VXE_present) {
		j += sprintf(buf + j, "\nVXE_BIST:\n");
		for (i = 0; i < MAX_VXE; i++) {
			if (VXE_BIST_bits[i]) {
				j += sprintf(buf + j, "%s=%d -- ERROR in memory\n",
							VXE_BIST_name[i], VXE_BIST_bits[i]);
			} else {
				j += sprintf(buf + j, "%s=%d\n",
							VXE_BIST_name[i], VXE_BIST_bits[i]);
			}
		}
	} else {
		j += sprintf(buf + j, "Warning!!! VXE is disabled\n");
	}

	/*Checking VXD_BIST*/
	if (a.VXD_present) {
		j += sprintf(buf + j, "\nVXD_BIST:\n");
		for (i = 0; i < MAX_VXD; i++) {
			if (VXD_BIST_bits[i]) {
				j += sprintf(buf + j, "%s=%d -- ERROR in memory\n",
							VXD_BIST_name[i], VXD_BIST_bits[i]);
			} else {
				j += sprintf(buf + j, "%s=%d\n",
							VXD_BIST_name[i], VXD_BIST_bits[i]);
			}
		}
	} else {
		j += sprintf(buf + j, "Warning!!! VXD is disabled\n");
	}

	/*Checking MGA25_BIST*/
	if (a.MGA_present) {
		j += sprintf(buf + j, "\nMGA2.5_BIST:\n");
		for (i = 0; i < MAX_MGA; i++) {
			if (MGA_BIST_bits[i]) {
				j += sprintf(buf + j, "%s=%d -- ERROR in memory\n",
							MGA_BIST_name[i], MGA_BIST_bits[i]);
			} else {
				j += sprintf(buf + j, "%s=%d\n",
							MGA_BIST_name[i], MGA_BIST_bits[i]);
			}
		}
	} else {
		j += sprintf(buf + j, "Warning!!! MGA2.5 is disabled\n");
	}
	return sprintf(buf, "%s", buf);
}
#endif /* CONFIG_E2K */

static ssize_t show_node(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	struct hwmon_data *hwmon = dev_get_drvdata(dev);
	return sprintf(buf, "NODE_%d\n", hwmon->node);
}

#ifdef CONFIG_E90S

#define CC0_MC_ECC(node) (NODE_PFREG_AREA_BASE(node) | (1 << 25) | (0 << 8))
#define CC1_MC_ECC(node) (CC0_MC_ECC(node) | (1 << 26))

__u64 pf_reg_read(int node, int nr)
{
	u64 base = CC0_MC_ECC(node);
	if (nr)
		base = CC1_MC_ECC(node);
	return __raw_readq((void *)base);
}

typedef union {
	struct {
		u32 McPllLock		: 1;
		u32 McPllReset		: 1;
		u32 McPllNbw		: 2;
		u32 McPllGated		: 1;
		u32 Reserved_2		: 2;
		u32 McPllNf		: 13;
		u32 Reserved_1		: 2;
		u32 McPllNr		: 6;
		u32 McPllNod		: 4;
};
	u32 word;
} mc_freq_sparc_t;

typedef union {
	struct {
		u64 unused		: 60;
		u32 ECC_DMODE		: 1;
		u32 ECC_CINT		: 1;
		u32 ECC_CORR		: 1;
		u32 ECC_DET		: 1;
};
	u64 word;
} pf_mc_ecc_r2000_t;

typedef union {
	struct {
		u32 unused		: 28;
		u32 ECC_DMODE		: 1;
		u32 ECC_CINT		: 1;
		u32 ECC_CORR		: 1;
		u32 ECC_DET		: 1;
};
	u32 word;
} pf_mc_ecc_r1000_t;

static ssize_t show_mem_info_sparc(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct hwmon_data *hwmon = dev_get_drvdata(dev);
	pf_mc_ecc_r1000_t mc_ecc_r1000;
	pf_mc_ecc_r2000_t cc0_mc_ecc_r2000;
	pf_mc_ecc_r2000_t cc1_mc_ecc_r2000;
	int j = 0;
	int ecc_mode;
	int regval;
	int cecnt;
	int uecnt;
	switch (e90s_get_cpu_type()) {
	case E90S_CPU_R1000:
		mc_ecc_r1000.word = readl(hwmon->base[0]);
		sprintf(buf, "NODE-%d DMODE=0x%x CINT=0x%x CORR=0x%X DET=0x%x\n",
				hwmon->node, mc_ecc_r1000.ECC_DMODE, mc_ecc_r1000.ECC_CINT,
				mc_ecc_r1000.ECC_CORR, mc_ecc_r1000.ECC_DET);
		break;
	case E90S_CPU_R2000:
		cc0_mc_ecc_r2000.word = pf_reg_read(hwmon->node, 0);
		cc1_mc_ecc_r2000.word = pf_reg_read(hwmon->node, 1);
		j += sprintf(buf + j, "NODE-%d CC-0 DMODE=0x%x CINT=0x%x CORR=0x%X DET=0x%x\n",
				hwmon->node, cc0_mc_ecc_r2000.ECC_DMODE, cc0_mc_ecc_r2000.ECC_CINT,
				cc0_mc_ecc_r2000.ECC_CORR, cc0_mc_ecc_r2000.ECC_DET);
		j += sprintf(buf + j, "NODE-%d CC-1 DMODE=0x%x CINT=0x%x CORR=0x%X DET=0x%x\n",
				hwmon->node, cc1_mc_ecc_r2000.ECC_DMODE, cc1_mc_ecc_r2000.ECC_CINT,
				cc1_mc_ecc_r2000.ECC_CORR, cc1_mc_ecc_r2000.ECC_DET);
		break;
	case E90S_CPU_R2000P:
		nbsr_writel(MC_ECCCFG0, MC_DDR_PHY_REGISTER_ADDRESS, 0);
		ecc_mode = nbsr_readl(MC_REGISTER_DATA, 0) & ECC_MODE_MASK;
		nbsr_writel(MC_ECCSTAT, MC_DDR_PHY_REGISTER_ADDRESS, 0);
		regval = nbsr_readl(MC_REGISTER_DATA, 0);
		cecnt = (regval & ECC_STAT_CECNT_MASK) >> ECC_STAT_CECNT_SHIFT;
		uecnt = (regval & ECC_STAT_UECNT_MASK) >> ECC_STAT_UECNT_SHIFT;
		j += sprintf(buf + j, "NODE-%d ECC_MODE=0x%x CECNT=0x%x UECNT=0x%x\n",
						hwmon->node, ecc_mode, cecnt, uecnt);
		break;
	}
	return sprintf(buf, "%s", buf);
}


static int read_mem_rate_sparc(struct hwmon_data *hwmon)
{
	int node = hwmon->node;
	int Nf;
	int Nod;
	int Nr;
	int Fmc;
	mc_freq_sparc_t mc_freq_reg;
	switch (e90s_get_cpu_type()) {
	case E90S_CPU_R1000:
		/* There is no register with pll parameters */
		Fmc = 250;
		break;
	case E90S_CPU_R2000:
		mc_freq_reg.word = readl(hwmon->base[1] + MC_FREQ_SPARC_SHIFT);
		Nf = mc_freq_reg.McPllNf + 1;
		Nod = mc_freq_reg.McPllNod + 1;
		Nr = mc_freq_reg.McPllNr + 1;
		Fmc = (100 * Nf) / (Nod * Nr);
		break;
	case E90S_CPU_R2000P:
		/* Soon counting from PMC will be added */
		break;
	}
	return Fmc;
}

static ssize_t show_mem_rate_sparc(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct hwmon_data *hwmon = dev_get_drvdata(dev);
	int Fmc = read_mem_rate_sparc(hwmon);
	int j = 0;
	if (e90s_get_cpu_type() == E90S_CPU_R1000)
		j += sprintf(buf + j, "For R1000 frequency is just printed, not from register:\n");
	j += sprintf(buf + j, "MC_freq = %d MHz\n", Fmc);
	return sprintf(buf, "%s", buf);
}

static struct link_data read_link_info_sparc(struct hwmon_data *hwmon)
{
	int node = hwmon->node;
	struct link_data a;
	int str_shift = 3;
	int ipcc_csr;
	int ipcc_str;
	int i;
	int wlcc_err_val;
	int iol_pls;
	for (i = 0; i < IPCC_LINKS; i++) {
		ipcc_csr = readl(hwmon->base[1] + ipcc_sparc_ctrls_off[i].offset);
		ipcc_str = readl(hwmon->base[1] + ipcc_sparc_ctrls_off[i+str_shift].offset);
		a.csr_reg[i] = ipcc_csr;
		a.str_reg[i] = ipcc_sparc_ctrls[i+str_shift].offset;
		a.active[i] = (ipcc_csr & ACTIVE_MASK) >> ACTIVE_SHIFT;
		a.width[i] = (ipcc_csr & WIDTH_MASK) >> WIDTH_SHIFT;
		a.state[i] = (ipcc_csr & STATE_MASK) >> STATE_SHIFT;
		a.str_val[i] = ipcc_str;
		a.cnt_err[i] = (ipcc_str & CNT_MASK);
		a.err_mode[i] = (ipcc_str & ERR_MODE_MASK) >> ERR_MODE_SHIFT;
	}
	a.wlcc_rate = (readl(hwmon->base[2] + IOL_PLM_CTLR_SHIFT_SPARC) & WLCC_RATE_MASK) >>
					 WLCC_RATE_SHIFT;
	iol_pls = readl(hwmon->base[2]);
	a.wlcc_active = (iol_pls & WLCC_ACTIVE_MASK) >> WLCC_ACTIVE_SHIFT;
	a.wlcc_state = (iol_pls & WLCC_STATE_MASK) >> WLCC_STATE_SHIFT;
	a.wlcc_width = (iol_pls & WLCC_WIDTH_MASK) >> WLCC_WIDTH_SHIFT;
	a.iol = (readl(hwmon->base[0] + RT_LCFG0_SHIFT) & IOL_MASK) >> IOL_SHIFT;
	wlcc_err_val = readl(hwmon->base[2] + IOL_DLL_STSR);
	a.wlcc_cnt = wlcc_err_val & ERR_CNT_MASK;
	a.wlcc_ov = (wlcc_err_val & ERR_OV_MASK) >> ERR_OV_SHIFT;
	a.wlcc_md = (wlcc_err_val & ERR_MD_MASK) >> ERR_MD_SHIFT;
	return a;
}

static int get_wlcc_information_sparc(struct link_data *data, char *buf,
					struct hwmon_data *hwmon, int j)
{
	struct link_data *b = data;

	j += sprintf(buf + j, "NODE%d-wlcc: ", hwmon->node);

	switch (b->wlcc_active) {
	case LINK_NOT_ACTIVE:
		j += sprintf(buf + j, "wlcc not active(%d), ",
				 b->wlcc_active);
		break;
	case LINK_ACTIVE:
		j += sprintf(buf + j, "wlcc is active(%d), ",
				 b->wlcc_active);
		break;
	}

	switch (b->wlcc_state) {
	case POWEROFF_STATE:
		j += sprintf(buf + j, "state(%d): Poweroff",
					b->wlcc_state);
		break;
	case DISABLE_STATE:
		j += sprintf(buf + j, "state(%d): Disable",
					 b->wlcc_state);
		break;
	case SLEEP_STATE:
		j += sprintf(buf + j, "state(%d): Sleep",
					 b->wlcc_state);
		break;
	case LINKUP_STATE:
		j += sprintf(buf + j, "state(%d): Work ",
					 b->wlcc_state);
		j += sprintf(buf + j, "width=0x%x", b->wlcc_width);
		if (b->wlcc_width != FULL_WIDTH)
			j += sprintf(buf + j, "WARNING (not full wlcc width)");
		break;
	}

	j += sprintf(buf + j, " err_mode=0x%x ", b->wlcc_md);

	if (b->wlcc_state == LINKUP_STATE) {
		switch (b->wlcc_md) {
		case 0:
			j += sprintf(buf + j, "- ERROR\n");
			break;
		case 1:
			j += sprintf(buf + j, "- WARNING ");
			break;
		case 2:
			j += sprintf(buf + j, "- OK ");
			break;
		}
	}

	if ((b->wlcc_state == LINKUP_STATE) && (b->wlcc_md != 0)) {
		j += sprintf(buf + j, "err_ov=0x%x ", b->wlcc_ov);
		if (b->wlcc_ov != 0)
			j += sprintf(buf + j, "- overflown (!!!)");

		j += sprintf(buf + j, "err_cnt=0x%x ", b->wlcc_cnt);

		if (b->wlcc_cnt == CNT_LIMIT)
			j += sprintf(buf + j, "- too much errors (!!!)\n");
		else if (b->wlcc_cnt != 0)
			j += sprintf(buf + j, "- found some errors (!!!)\n");
		else
			j += sprintf(buf + j, "- OK\n");

	} else {
		j += sprintf(buf + j, "\n");
	}

	return j;
}

static int get_ipcc_information_sparc(struct link_data *data, char *buf,
					struct hwmon_data *hwmon, int j)
{
	struct link_data *b = data;
	char letter;
	int i;

	for (i = 0; i < IPCC_LINKS; i++) {
		switch (ipcc_sparc_ctrls[i].offset) {
		case IPCC_CSR1_SPARC:
			letter = 'A';
			break;
		case IPCC_CSR2_SPARC:
			letter = 'B';
			break;
		case IPCC_CSR3_SPARC:
			letter = 'C';
			break;
		}
		j += sprintf(buf + j, "NODE%d-ipcc-%c-csr(0x%x) width=0x%x, ",
				 hwmon->node, letter, ipcc_sparc_ctrls[i].offset, b->width[i]);
		if (b->width[i] != FULL_WIDTH)
			j += sprintf(buf + j, "WARNING (not full width), ");

		switch (b->active[i]) {
		case LINK_NOT_ACTIVE:
			j += sprintf(buf + j, "link not active(%d), ", b->active[i]);
			break;
		case LINK_ACTIVE:
			j += sprintf(buf + j, "link is active(%d), ", b->active[i]);
			break;
		}

		switch (b->state[i]) {
		case POWEROFF_STATE:
			j += sprintf(buf + j, "state(%d): Poweroff\n", b->state[i]);
			break;
		case DISABLE_STATE:
			j += sprintf(buf + j, "state(%d): Disable\n", b->state[i]);
			break;
		case SLEEP_STATE:
			j += sprintf(buf + j, "state(%d): Sleep\n", b->state[i]);
			break;
		case LINKUP_STATE:
			j += sprintf(buf + j, "state(%d): Work\n", b->state[i]);
			break;
		case SERVICE_STATE:
			j += sprintf(buf + j, "state(%d): Service\n", b->state[i]);
			break;
		case REINIT_STATE:
			j += sprintf(buf + j, "state(%d): Reinit\n", b->state[i]);
			break;
		}


		if (b->state[i] == LINKUP_STATE) {
			switch (b->err_mode[i]) {
			case IPCC_STR_MODE_LERR:
				j += sprintf(buf + j,
					"NODE%d-ipcc-%c-str(0x%x) err_mode=%d - WARNING(0x%x)\n",
						hwmon->node, letter, b->str_reg[i],
						b->err_mode[i], b->str_val[i]);
				j += sprintf(buf + j,
					"amount of errors in cnt_err -  %d\n", b->cnt_err[i]);
				break;
			case IPCC_STR_MODE_RTRY:
				j += sprintf(buf + j,
					"NODE%d-ipcc-%c-str(0x%x) err_mode=%d - OK(0x%x)\n",
						hwmon->node, letter, b->str_reg[i],
						b->err_mode[i], b->str_val[i]);
				j += sprintf(buf + j,
					"amount of errors in cnt_err -  %d\n", b->cnt_err[i]);

				break;
			default:
				j += sprintf(buf + j,
					"NODE%d-ipcc-%c-str(0x%x) err_mode=%d - ERROR(0x%x)\n",
						hwmon->node, letter,  b->str_reg[i],
						b->err_mode[i], b->str_val[i]);
			}
		} else {
			j += sprintf(buf + j,
				"NODE%d-ipcc-%c-str(0x%x) err_mode=%d - OFF(0x%x - CSR)\n",
						hwmon->node, letter,  b->str_reg[i],
						b->err_mode[i], b->csr_reg[i]);
		}
	}

	return j;
}

static ssize_t show_link_info_sparc(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct hwmon_data *hwmon = dev_get_drvdata(dev);
	struct link_data b = read_link_info_sparc(hwmon);
	int j = 0;

	/* WLCC INFORMATION */
	j = get_wlcc_information_sparc(&b, buf, hwmon, j);

	/*IPCC INFORMATION*/
	j = get_ipcc_information_sparc(&b, buf, hwmon, j);

	return sprintf(buf, "%s", buf);
}

#endif /* CONFIG_E90S */

#define MAX_NAME  18
static int num_attrs = 0;

struct hwmon_device_attribute {
	struct sensor_device_attribute s_attrs;
	char name[MAX_NAME];
};

static struct attribute_group hwmon_group = {
	.attrs = NULL,
};

static const struct attribute_group *hwmon_groups[] = {
	&hwmon_group,
	NULL,
};

static struct hwmon_device_attribute *hwmon_attrs;

static int create_info_device_attr(struct device *dev)
{
	int num_files = 0;
#ifdef CONFIG_E2K
	int cpu_type = machine.native_id;
#endif

#ifdef CONFIG_E2K
	switch (cpu_type) {
	case MACHINE_ID_E16C:
		num_files = 6;
		break;
	case MACHINE_ID_E12C:
		num_files = 6;
		break;
	case MACHINE_ID_E2C3:
		num_files = 8;
		break;
	case MACHINE_ID_E8C:
		num_files = 4;
		break;
	case MACHINE_ID_E8C2:
		num_files = 4;
		break;
	case MACHINE_ID_E8V7:
		num_files = 7;
		break;
	}
#endif

#ifdef CONFIG_E90S
	switch (e90s_get_cpu_type()) {
	case E90S_CPU_R1000:
		num_files = 4;
		break;
	case E90S_CPU_R2000:
		num_files = 4;
		break;
	case E90S_CPU_R2000P:
		num_files = 2;
		break;
	}
#endif

	hwmon_attrs = devm_kzalloc(dev,
			(num_files)*sizeof(struct hwmon_device_attribute),
								GFP_KERNEL);
	if (!hwmon_attrs) {
		return -ENOMEM;
	}

	struct hwmon_device_attribute *pattr;

#ifdef CONFIG_E2K
	if (!IS_MACHINE_E8V7) {
		pattr = hwmon_attrs + num_attrs;
		snprintf(pattr->name, MAX_NAME, "link_info");
		pattr->s_attrs.dev_attr.attr.name = pattr->name;
		pattr->s_attrs.dev_attr.attr.mode = 0444;
		pattr->s_attrs.dev_attr.show = show_link_data;
		pattr->s_attrs.dev_attr.store = NULL;
		sysfs_attr_init(&pattr->s_attrs.dev_attr.attr);
		num_attrs++;
	}

	pattr = hwmon_attrs + num_attrs;
	snprintf(pattr->name, MAX_NAME, "mem_info");
	pattr->s_attrs.dev_attr.attr.name = pattr->name;
	pattr->s_attrs.dev_attr.attr.mode = 0444;
	pattr->s_attrs.dev_attr.show = show_mem_data;
	pattr->s_attrs.dev_attr.store = NULL;
	sysfs_attr_init(&pattr->s_attrs.dev_attr.attr);
	num_attrs++;

	if (IS_MACHINE_E2C3) {
		pattr = hwmon_attrs + num_attrs;
		snprintf(pattr->name, MAX_NAME, "cpu_info");
		pattr->s_attrs.dev_attr.attr.name = pattr->name;
		pattr->s_attrs.dev_attr.attr.mode = 0444;
		pattr->s_attrs.dev_attr.show = show_cpu_data;
		pattr->s_attrs.dev_attr.store = NULL;
		sysfs_attr_init(&pattr->s_attrs.dev_attr.attr);
		num_attrs++;

		pattr = hwmon_attrs + num_attrs;
		snprintf(pattr->name, MAX_NAME, "bist_info");
		pattr->s_attrs.dev_attr.attr.name = pattr->name;
		pattr->s_attrs.dev_attr.attr.mode = 0444;
		pattr->s_attrs.dev_attr.show = show_bist_info;
		pattr->s_attrs.dev_attr.store = NULL;
		sysfs_attr_init(&pattr->s_attrs.dev_attr.attr);
		num_attrs++;
	}

	if (IS_MACHINE_E8V7) {
		pattr = hwmon_attrs + num_attrs;
		snprintf(pattr->name, MAX_NAME, "cpu_info");
		pattr->s_attrs.dev_attr.attr.name = pattr->name;
		pattr->s_attrs.dev_attr.attr.mode = 0444;
		pattr->s_attrs.dev_attr.show = show_cpu_data_e8v7;
		pattr->s_attrs.dev_attr.store = NULL;
		sysfs_attr_init(&pattr->s_attrs.dev_attr.attr);
		num_attrs++;

		pattr = hwmon_attrs + num_attrs;
		snprintf(pattr->name, MAX_NAME, "bist_info");
		pattr->s_attrs.dev_attr.attr.name = pattr->name;
		pattr->s_attrs.dev_attr.attr.mode = 0444;
		pattr->s_attrs.dev_attr.show = show_bist_info_e8v7;
		pattr->s_attrs.dev_attr.store = NULL;
		sysfs_attr_init(&pattr->s_attrs.dev_attr.attr);
		num_attrs++;
	}

	if (IS_MACHINE_E8C || IS_MACHINE_E8C2) {
		pattr = hwmon_attrs + num_attrs;
		snprintf(pattr->name, MAX_NAME, "mem_rate");
		pattr->s_attrs.dev_attr.attr.name = pattr->name;
		pattr->s_attrs.dev_attr.attr.mode = 0444;
		pattr->s_attrs.dev_attr.show = show_mem_rate_e8c;
		pattr->s_attrs.dev_attr.store = NULL;
		sysfs_attr_init(&pattr->s_attrs.dev_attr.attr);
		num_attrs++;
	}

	if (IS_MACHINE_E16C || IS_MACHINE_E12C ||
				IS_MACHINE_E2C3 || IS_MACHINE_E8V7) {
		pattr = hwmon_attrs + num_attrs;
		snprintf(pattr->name, MAX_NAME, "config_pins");
		pattr->s_attrs.dev_attr.attr.name = pattr->name;
		pattr->s_attrs.dev_attr.attr.mode = 0444;
		pattr->s_attrs.dev_attr.show = show_pins;
		pattr->s_attrs.dev_attr.store = NULL;
		sysfs_attr_init(&pattr->s_attrs.dev_attr.attr);
		num_attrs++;

		pattr = hwmon_attrs + num_attrs;
		snprintf(pattr->name, MAX_NAME, "mem_rate_measure");
		pattr->s_attrs.dev_attr.attr.name = pattr->name;
		pattr->s_attrs.dev_attr.attr.mode = 0444;
		pattr->s_attrs.dev_attr.show = show_mem_rate;
		pattr->s_attrs.dev_attr.store = NULL;
		sysfs_attr_init(&pattr->s_attrs.dev_attr.attr);
		num_attrs++;

		pattr = hwmon_attrs + num_attrs;
		snprintf(pattr->name, MAX_NAME, "mem_rate");
		pattr->s_attrs.dev_attr.attr.name = pattr->name;
		pattr->s_attrs.dev_attr.attr.mode = 0444;
		pattr->s_attrs.dev_attr.show = show_mem_rate_saved;
		pattr->s_attrs.dev_attr.store = NULL;
		sysfs_attr_init(&pattr->s_attrs.dev_attr.attr);
		num_attrs++;
	}
#endif /* CONFIG_E2K */

#ifdef CONFIG_E90S
	if (e90s_get_cpu_type() != E90S_CPU_R2000P) {
		pattr = hwmon_attrs + num_attrs;
		snprintf(pattr->name, MAX_NAME, "mem_rate_sparc");
		pattr->s_attrs.dev_attr.attr.name = pattr->name;
		pattr->s_attrs.dev_attr.attr.mode = 0444;
		pattr->s_attrs.dev_attr.show = show_mem_rate_sparc;
		pattr->s_attrs.dev_attr.store = NULL;
		sysfs_attr_init(&pattr->s_attrs.dev_attr.attr);
		num_attrs++;

		pattr = hwmon_attrs + num_attrs;
		snprintf(pattr->name, MAX_NAME, "link_info_sparc");
		pattr->s_attrs.dev_attr.attr.name = pattr->name;
		pattr->s_attrs.dev_attr.attr.mode = 0444;
		pattr->s_attrs.dev_attr.show = show_link_info_sparc;
		pattr->s_attrs.dev_attr.store = NULL;
		sysfs_attr_init(&pattr->s_attrs.dev_attr.attr);
		num_attrs++;
	}

	pattr = hwmon_attrs + num_attrs;
	snprintf(pattr->name, MAX_NAME, "mem_info_sparc");
	pattr->s_attrs.dev_attr.attr.name = pattr->name;
	pattr->s_attrs.dev_attr.attr.mode = 0444;
	pattr->s_attrs.dev_attr.show = show_mem_info_sparc;
	pattr->s_attrs.dev_attr.store = NULL;
	sysfs_attr_init(&pattr->s_attrs.dev_attr.attr);
	num_attrs++;
#endif /* CONFIG_E90S */
	pattr = hwmon_attrs + num_attrs;
	snprintf(pattr->name, MAX_NAME, "curr_node");
	pattr->s_attrs.dev_attr.attr.name = pattr->name;
	pattr->s_attrs.dev_attr.attr.mode = 0444;
	pattr->s_attrs.dev_attr.show = show_node;
	pattr->s_attrs.dev_attr.store = NULL;
	sysfs_attr_init(&pattr->s_attrs.dev_attr.attr);
	num_attrs++;

	return 0;
}

static struct attribute **attrs;
static int create_hwmon_group(struct device *dev)
{

	int i;
	attrs = devm_kzalloc(dev, (num_attrs + 1) * sizeof(struct attribute *),
							GFP_KERNEL);
	if (!attrs) {
		return -ENOMEM;
	}

	for (i = 0; i < num_attrs; i++) {
		*(attrs + i) = &((hwmon_attrs + i)->s_attrs.dev_attr.attr);
	}
	hwmon_group.attrs = attrs;

	return 0;
}

#define MAX_NODE 4

static struct hwmon_data *p_hwmon[MAX_NODE];

static int hwmon_probe(struct platform_device *pdev)
{
	int base_num = SPARC_BASE_NUM;
	struct device *dev = &pdev->dev;
	void __iomem *base;
	struct resource *r;
	int node;
#ifdef CONFIG_E2K
	base_num = E2K_BASE_NUM;
	if (IS_MACHINE_E2C3)
		base_num = E2C3_BASE_NUM;
#endif
	struct hwmon_data *hwmon = devm_kzalloc(&pdev->dev, sizeof(*hwmon), GFP_KERNEL);
	dev_set_drvdata(dev, hwmon);

	if (!hwmon)
		return -ENOMEM;
	struct device *hwmon_dev;
	int ret;

#ifdef CONFIG_E2K
	if (!(IS_MACHINE_E8C || IS_MACHINE_E8C2 ||
			IS_MACHINE_E12C || IS_MACHINE_E16C ||
			IS_MACHINE_E2C3 || IS_MACHINE_E8V7))
		return -ENODEV;
#endif
	for (int i = 0; i < base_num; ++i) {
		r = platform_get_resource(pdev, IORESOURCE_MEM, i);
		if (!r) {
			dev_err(dev, "failed to get mem resource %d\n", i);
			return -ENOMEM;
		}
		base = devm_ioremap(dev, r->start, resource_size(r));
		if (IS_ERR(base)) {
			dev_err(dev, "failed to map resource %d\n", i);
			return PTR_ERR(base);
		}
		hwmon->base[i] = base;
	}
	node = dev_to_node(&pdev->dev);

	if (node == -1)
		node++;
	if (node == 0) {
		ret = create_info_device_attr(dev);
		if (ret)
			return -ENOMEM;
		ret = create_hwmon_group(dev);
		if (ret)
			return -ENOMEM;
	}

	hwmon->pdev = pdev;
	hwmon->node = node;
	hwmon_dev = hwmon_device_register_with_groups(&pdev->dev,
								KBUILD_MODNAME,
								hwmon,
								hwmon_groups);
	if (IS_ERR(hwmon_dev))
		return PTR_ERR(hwmon_dev);

	hwmon->hdev = hwmon_dev;
	p_hwmon[node] = hwmon;

#ifdef CONFIG_E2K
	if (IS_MACHINE_E2C3 || IS_MACHINE_E12C ||
			IS_MACHINE_E16C || IS_MACHINE_E8V7) {
		struct workqueue_struct *wq = create_singlethread_workqueue("mem_rate_measure");

		if (!wq)
			return -EINVAL;

		struct th_info *th_info_var = &hwmon->th_info_var;

		hwmon->wq = wq;
		th_info_var->node = node;
		th_info_var->mode = 0;
		mutex_init(&th_info_var->mutex_measure);
		init_completion(&th_info_var->rate_done);
		INIT_WORK(&th_info_var->work, thread_func);
		queue_work_on(1, wq, &th_info_var->work);
	}
#endif
	return 0;
}


static int hwmon_remove(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct hwmon_data *hwmon = dev_get_drvdata(dev);
	int node = hwmon->th_info_var.node;

#ifdef CONFIG_E2K
	if (IS_MACHINE_E2C3 || IS_MACHINE_E12C ||
			IS_MACHINE_E16C || IS_MACHINE_E8V7) {
		wait_for_completion(&hwmon->th_info_var.rate_done);
		destroy_workqueue(hwmon->wq);
	}
#endif
	if (node == -1)
		node++;
	hwmon_device_unregister(hwmon->hdev);
	return 0;
}

static const struct of_device_id hw_check_of_match[] = {
	{ .compatible = "mcst,hw_check", },
	{}
};

/* MODULE_DEVICE_TABLE(of, hw_check_of_match);
 * Disable autoloading
 */

static struct platform_driver hw_check_driver = {
	.driver = {
		.name = "hw_check",
		.of_match_table = hw_check_of_match,
	},
	.probe = hwmon_probe,
	.remove = hwmon_remove,
};
module_platform_driver(hw_check_driver);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("MCST");
MODULE_DESCRIPTION("Engineer scripts driver");
