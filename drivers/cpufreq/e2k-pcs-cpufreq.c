/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/err.h>
#include <linux/cpufreq.h>
#include <linux/topology.h>
#include <asm/pci.h>
#include "e2k-pcs-cpufreq.h"

/*
 * cpufreq driver is disabled on guest as it is host's responsibility to adjust
 * CPU frequency.
 */
#define PCS_CPUFREQ_SUPPORTED() \
		((IS_MACHINE_E2C3 || IS_MACHINE_E12C || IS_MACHINE_E16C || \
		IS_MACHINE_E8C2 || IS_MACHINE_E48C || IS_MACHINE_E8V7) && \
		!IS_HV_GM() && !IS_ENABLED(CONFIG_KVM_GUEST_KERNEL) && \
		!IS_ENABLED(CONFIG_E2K_SIMULATOR) && !is_prototype())
/*
 * module param throttling:
 * bit [0]: responsible for enabling throttling
 * bits [7-4]: nodes 3-0
 */
static char throttling = -1;
module_param(throttling, byte, 0444);
MODULE_PARM_DESC(throttling, KBUILD_MODNAME " cpufreq throttling");

struct pcs_freq_data {
	void __iomem *base;
	int div_max;
	int div_min;
	struct cpufreq_frequency_table *table;
};

#ifdef DEBUG
static void print_pmc_freq_core_mon(freq_core_mon_t *mon)
{
	printk(KERN_DEBUG "freq_core_mon:\n"
	       "\tdivF_curr     %d\n"
	       "\tdivF_target   %d\n"
	       "\tdivF_limit_hi %d\n"
	       "\tdivF_limit_lo %d\n"
	       "\tdivF_init     %d\n"
	       "\tbfs_bypass    %d\n",
	       mon->divF_curr,
	       mon->divF_target,
	       mon->divF_limit_hi,
	       mon->divF_limit_lo, mon->divF_init, mon->bfs_bypass);
}

static void print_efuse_data(efuse_data_t *efuse_data)
{
	printk(KERN_DEBUG "efuse_data:\n"
	       "\tval       %d\n"
	       "\tdisable   %d\n"
	       "\tparity    %d\n"
	       "\taddr      0x%x\n"
	       "\tbroadcast %d\n"
	       "\tdata      0x%x\n",
	       efuse_data->v6.val,
	       efuse_data->v6.disable,
	       efuse_data->v6.parity,
	       efuse_data->v6.addr, efuse_data->v6.broadcast, efuse_data->v6.data);
}

static void print_efuse_data_v7(efuse_data_t *efuse_data)
{
	printk(KERN_DEBUG "efuse_data:\n"
	       "\tval       %d\n"
	       "\tdisable   %d\n"
	       "\tparity    %d\n"
	       "\taddr      0x%x\n"
	       "\tpart_num  0x%x\n"
	       "\tdata      0x%x\n",
	       efuse_data->v7.val,
	       efuse_data->v7.disable,
	       efuse_data->v7.parity,
	       efuse_data->v7.addr, efuse_data->v7.part_num, efuse_data->v7.data);
}
#endif

static inline bool check_bfs_bypass(struct pcs_freq_data *data)
{
	pcs_ctrl3_t ctrl;

	ctrl.word = readl(data->base + SIC_pcs_ctrl3);

	return (ctrl.bfs_freq == 8);
}

static inline int get_pcs_mode_e8c2(struct pcs_freq_data *data)
{
	pcs_ctrl1_t ctrl;

	ctrl.word = readl(data->base + SIC_pcs_ctrl1);

	return ctrl.pcs_mode;
}

static inline void set_pcs_mode(throttling_data_t *throttling_data,
				struct pcs_freq_data *data)
{
	pcs_ctrl1_t ctrl;

	ctrl.word = readl(data->base + SIC_pcs_ctrl1);
	ctrl.pcs_mode = throttling_data->enable ? V5_PCS_MODE_7 : V5_PCS_MODE_3;
	writel(ctrl.word, data->base + SIC_pcs_ctrl1);
}

static void throttling_handle(struct pcs_freq_data *data, int node)
{
	throttling_data_t throttling_data;
	throttling_data.byte = throttling;

	if (throttling_data.nodemask & THROTTLING_NODE_BITMASK(node))
		set_pcs_mode(&throttling_data, data);
	else if (!throttling_data.nodemask)
		set_pcs_mode(&throttling_data, data);
}

static unsigned int get_f_pll_v6(void __iomem *fuse_base)
{
	efuse_data_t efuse_data;
	unsigned int addr;
	unsigned int f_pll;
	uint32_t pll_clkr, pll_clkod;
	uint16_t flags;
	union {
		struct {
			u64 lo     : 13;
			u64 med_lo : 21;
			u64 med_hi : 21;
			u64 hi     : 7;
			u64 empty  : 2;
		};
		u64 reg;
	} pll_clkf;

	for (addr = EFUSE_START_ADDR; addr < EFUSE_END_ADDR_V6; addr++) {
		writel(addr, fuse_base + EFUSE_RAM_ADDR);
		efuse_data.word = readl(fuse_base + EFUSE_RAM_DATA);
#ifdef DEBUG
		print_efuse_data(&efuse_data);
#endif
		/* PLL core abonent addr only 0x45-0x48,
		 * but the documentation may indicate other addr
		 * that should be ignored
		 */
		if (efuse_data.v6.val && !efuse_data.v6.disable
		    && efuse_data.v6.broadcast) {
			switch (efuse_data.v6.addr) {
			case 0x45:
				pll_clkod = efuse_data.v6_addr_46.pll_clkod;
				pll_clkf.lo = efuse_data.v6_addr_46.pll_clkf_lo;
				flags |= V6_ADDR_45;
				break;
			case 0x46:
				pll_clkf.med_lo = efuse_data.v6_addr_47.pll_clkf_med_lo;
				flags |= V6_ADDR_46;
				break;
			case 0x47:
				pll_clkf.med_hi = efuse_data.v6_addr_48.pll_clkf_med_hi;
				flags |= V6_ADDR_47;
				break;
			case 0x48:
				pll_clkf.hi = efuse_data.v6_addr_49.pll_clkf_hi;

				pll_clkr = efuse_data.v6_addr_49.pll_clkr;
				flags |= V6_ADDR_48;
				break;
			}
		}
		if (flags == (V6_ADDR_45 | V6_ADDR_46 | V6_ADDR_47 | V6_ADDR_48))
			break;
	}

	if ((flags != (V6_ADDR_45 | V6_ADDR_46 | V6_ADDR_47 | V6_ADDR_48)) ||
	    (pll_clkr == 0 && pll_clkod == 0 && pll_clkf.reg == 0)) {
		pll_clkr = DEF_PLL_CLKR_V6;
		pll_clkod = DEF_PLL_CLKOD_V6;
		pll_clkf.reg = DEF_PLL_CLKF_V6;
	}

	f_pll = F_REF * pll_clkf.reg / ((1ULL << 33) * (pll_clkr + 1) * (pll_clkod + 1));

	return f_pll;
}

static unsigned int get_f_pll_e8v7(void __iomem *fuse_base)
{
	efuse_data_t efuse_data;
	unsigned int addr;
	unsigned int f_pll;
	uint32_t pll_clkr = DEF_PLL_CLKR_E8V7;
	union {
		struct {
			u32 lo    : 4;
			u32 hi    : 7;
			u32 empty : 21;
		};
		u32 reg;
	} pll_clkod = {
		.reg = DEF_PLL_CLKOD_E8V7
	};
	union {
		struct {
			u64 lo     : 13;
			u64 med_lo : 20;
			u64 med_hi : 20;
			u64 hi     : 1;
			u64 empty  : 10;
		};
		u64 reg;
	} pll_clkf = {
		.reg = DEF_PLL_CLKF_E8V7
	};
	uint16_t flags = 0;

	for (addr = EFUSE_START_ADDR; addr < EFUSE_END_ADDR_E8V7; addr++) {
		writel(addr, fuse_base + EFUSE_RAM_ADDR);
		efuse_data.word = readl(fuse_base + EFUSE_RAM_DATA);
#ifdef DEBUG
		print_efuse_data_v7(&efuse_data);
#endif
		if (efuse_data.v7.val && !efuse_data.v7.disable
		    && (efuse_data.v7.addr == PLL_BFS_CORE_ADDR_V7)) {
			switch (efuse_data.v7.part_num) {
			case 5:
				/* pll_clkod[3:0] */
				pll_clkod.lo = efuse_data.e8v7_partnum5.pll_clkod_lo;
				flags |= PART_NUM_5;
				break;
			case 6:
				/* pll_clkod[10:4] */
				pll_clkod.hi = efuse_data.e8v7_partnum6.pll_clkod_hi;
				/* pll_clkf[12:0] */
				pll_clkf.lo = efuse_data.e8v7_partnum6.pll_clkf_lo;
				flags |= PART_NUM_6;
				break;
			case 7:
				/* pll_clkf[32:13] */
				pll_clkf.med_lo = efuse_data.e8v7_partnum7.pll_clkf_med_lo;
				flags |= PART_NUM_7;
				break;
			case 8:
				/* pll_clkf[52:33] */
				pll_clkf.med_hi = efuse_data.e8v7_partnum8.pll_clkf_med_hi;
				flags |= PART_NUM_8;
				break;
			case 9:
				/* pll_clkf[52] */
				pll_clkf.hi = efuse_data.e8v7_partnum9.pll_clkf_hi;

				/* pll_clkr[11:00] */
				pll_clkr = efuse_data.e8v7_partnum9.pll_clkr;
				flags |= PART_NUM_9;
				break;
			}
		}
		if (flags == (PART_NUM_5 | PART_NUM_6 | PART_NUM_7 |
			      PART_NUM_8 | PART_NUM_9))
			break;
	}

	if (pll_clkr == 0 && pll_clkod.reg == 0 && pll_clkf.reg == 0) {
		pll_clkr = DEF_PLL_CLKR_E8V7;
		pll_clkod.reg = DEF_PLL_CLKOD_E8V7;
		pll_clkf.reg = DEF_PLL_CLKF_E8V7;
	}

	f_pll = (F_REF * pll_clkf.reg / (1ULL << 33)) / ((pll_clkr + 1) * (pll_clkod.reg + 1));

	return f_pll;
}

static unsigned int get_f_pll_e48c(void __iomem *fuse_base)
{
	efuse_data_t efuse_data;
	unsigned int addr, addr_end = EFUSE_END_ADDR_E48C;
	unsigned int addr_offset = 1;
	unsigned int f_pll;
	uint16_t pll_clkod = DEF_PLL_CLKOD_E48C;
	uint16_t flags = 0;
	union {
		struct {
			u32 lo    : 3;
			u32 hi    : 3;
			u32 empty : 26;
		};
		u32 reg;
	} pll_clkr = {
		.reg = DEF_PLL_CLKR_E48C
	};
	union {
		struct {
			u32 lo    : 12;
			u32 hi    : 1;
			u32 empty : 19;
		};
		u32 reg;
	} pll_clkf = {
		.reg = DEF_PLL_CLKF_E48C
	};

	/*
	 * bugzilla #166393 addr_end = 0xff for e48c.rev0
	 * rm #32944 addr_offset = 0x4 for e48c.rev0
	 */
	if (cpu_has(CPU_FEAT_E48C_MAKET)) {
		addr_end = EFUSE_END_ADDR_E48C_REV0;
		addr_offset = 4;
	}

	for (addr = EFUSE_START_ADDR; addr < addr_end; addr += addr_offset) {
		writel(addr, fuse_base + EFUSE_RAM_ADDR);
		efuse_data.word = readl(fuse_base + EFUSE_RAM_DATA);
#ifdef DEBUG
		print_efuse_data_v7(&efuse_data);
#endif
		if (efuse_data.v7.val && !efuse_data.v7.disable
				&& (efuse_data.v7.addr == PLL_BFS_CORE_ADDR_V7)) {
			switch (efuse_data.v7.part_num) {
			case 5:
				if (cpu_has(CPU_FEAT_E48C_MAKET)) {
					/* pll_clkr[2:0] */
					pll_clkr.lo = efuse_data.e48c_rev0_partnum5.pll_clkr_lo;

					/* pll_clkf[12:0] */
					pll_clkf.reg = efuse_data.e48c_rev0_partnum5.pll_clkf;

					/* pll_clkod[3:0] */
					pll_clkod = efuse_data.e48c_rev0_partnum5.pll_clkod;
				} else {
					/* pll_clkf[11:0] */
					pll_clkf.lo = efuse_data.e48c_partnum5.pll_clkf_lo;

					/* pll_clkod[3:0] */
					pll_clkod = efuse_data.e48c_partnum5.pll_clkod;
				}
				flags |= PART_NUM_5;
				break;
			case 6:
				if (cpu_has(CPU_FEAT_E48C_MAKET)) {
					/* pll_clkr[5:3] */
					pll_clkr.hi = efuse_data.e48c_rev0_partnum6.pll_clkr_hi;
				} else {
					/* pll_clkf[12] */
					pll_clkf.hi = efuse_data.e48c_partnum6.pll_clkf_hi;

					/* pll_clkr[5:0] */
					pll_clkr.reg = efuse_data.e48c_partnum6.pll_clkr;
				}
				flags |= PART_NUM_6;
				break;
			}
		}
		if (flags == (PART_NUM_5 | PART_NUM_6))
			break;
	}

	if (pll_clkr.reg == 0 && pll_clkod == 0 && pll_clkf.reg == 0) {
		pll_clkr.reg = DEF_PLL_CLKR_E48C;
		pll_clkod = DEF_PLL_CLKOD_E48C;
		pll_clkf.reg = DEF_PLL_CLKF_E48C;
	}

	f_pll = F_REF * (pll_clkf.reg + 1) / ((pll_clkr.reg + 1) * (pll_clkod + 1));

	if (cpu_has(CPU_FEAT_E48C_MAKET) && f_pll > DEF_F_PLL_E48C_REV0)
		f_pll = DEF_F_PLL_E48C_REV0;

	return f_pll;
}

#define GET_FREQ(div, pll) (16000*pll/(1 << div/16)/(div%16 + 16)) /* Khz */

static int pcs_l_create_freq_table(struct platform_device *pdev,
				   struct pcs_freq_data *data, int divFmin,
				   int divFmax, int node)
{
	struct device *dev = &pdev->dev;
	struct device_node *np = pdev->dev.of_node;
	struct device_node *pmc_freq_np;
	struct platform_device *pmc_freq_pdev;
	struct resource *res;
	void __iomem *fuse_base;
	unsigned int divF;
	unsigned int divFi = 0;
	unsigned int f_pll;

	pmc_freq_np = of_parse_phandle(np, "mcst,freq-nodes", node);
	if (!pmc_freq_np) {
		dev_err(dev, "failed parse phandle mcst,freq-nodes\n");
		return -ENODEV;
	}
	pmc_freq_pdev = of_find_device_by_node(pmc_freq_np);
	if (!pmc_freq_pdev)
		return -ENODEV;

	of_node_put(pmc_freq_np);

	res = platform_get_resource(pmc_freq_pdev, IORESOURCE_MEM, 1);
	if (!res) {
		dev_err(dev, "failed to get fuse mem resource\n");
		return -ENOMEM;
	}
	fuse_base = ioremap(res->start, resource_size(res));
	if (IS_ERR(fuse_base)) {
		dev_err(dev, "failed to map fuse resource\n");
		return PTR_ERR(fuse_base);
	}

	if (IS_MACHINE_E8V7)
		f_pll = get_f_pll_e8v7(fuse_base);
	else if (IS_MACHINE_E48C)
		f_pll = get_f_pll_e48c(fuse_base);
	else
		f_pll = get_f_pll_v6(fuse_base);

	iounmap(fuse_base);

	data->table = devm_kzalloc(dev, (sizeof(struct cpufreq_frequency_table) *
		 (divFmax - divFmin + 2)), GFP_KERNEL);
	if (!data->table)
		return -ENOMEM;

	for (divF = divFmin; divF < MAX_STATES && divF <= divFmax; divF++) {
		data->table[divFi].frequency = GET_FREQ(divF, f_pll);
		data->table[divFi++].driver_data = divF;
	}

	data->table[divFi].frequency = CPUFREQ_TABLE_END;

	return 0;
}

int get_idx_by_n_sys(int n_sys)
{
	return n_sys - 8;
}

int n_sys[] = {8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
	       20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
int f_base_rev0[] = {900, 1000, 1050, 1100, 1125, 1175, 1200, 1300};
int f_base_rev1[] = {900, 1000, 1100, 1200, 1300, 1400, 1500, 1550};

static int pcs_l_create_freq_table_e8c2(struct platform_device *pdev,
					struct pcs_freq_data *data,
					int divFmin, int divFmax)
{
	struct device *dev = &pdev->dev;
	int i, ii = 0;
	int f_base = 0;
	pcs_ctrl3_t ctrl;

	if (divFmin >= divFmax) {
		pr_err("%s: invalid params", __func__);
		return -EINVAL;
	}

	data->table = devm_kzalloc(dev, (sizeof(struct cpufreq_frequency_table) *
				(ARRAY_SIZE(n_sys) + 1)),
				GFP_KERNEL);
	if (!data->table)
		return -ENOMEM;

	ctrl.word = readl(data->base + SIC_pcs_ctrl3);

	if (!read_IDR_reg().rev)
		f_base = f_base_rev0[ctrl.pll_mode];
	else
		f_base = f_base_rev1[ctrl.pll_mode];

	for (i = 0; i < ARRAY_SIZE(n_sys); i++) {
		int freq = f_base * 16000 / n_sys[i];

		if (n_sys[i] >= divFmin && n_sys[i] <= divFmax) {
			data->table[ii].frequency = freq;
			data->table[ii].driver_data = n_sys[i];
			ii++;
		}
	}

	data->table[ii].frequency = CPUFREQ_TABLE_END;

	return 0;
}


static unsigned int pcs_l_cpufreq_get_e8c2(struct pcs_freq_data *data,
					   unsigned int cpu)
{
	int target_idx = 0;
	pcs_ctrl1_t ctrl;
	struct cpufreq_frequency_table *table = data->table;

	ctrl.word = readl(data->base + SIC_pcs_ctrl1);

	target_idx = get_idx_by_n_sys(ctrl.n) - get_idx_by_n_sys(table[0].driver_data);

	return data->table[target_idx].frequency;
}

static unsigned int _pcs_l_cpufreq_get(struct pcs_freq_data *data, unsigned int cpu)
{
	freq_core_mon_t mon;
	int core = cpu_to_cpuid(cpu) % cpu_max_cores_num();

	mon.word = readl(data->base + PMC_FREQ_CORE_N_MON(core));
	WARN_ON_ONCE(mon.divF_curr < data->div_min || mon.divF_curr > data->div_max);

	return data->table[mon.divF_curr - data->div_min].frequency;
}

static unsigned int pcs_l_cpufreq_get(unsigned int cpu)
{
	int node = cpu_to_node(cpu);
	struct pcs_freq_data **pdata = cpufreq_get_driver_data();
	struct pcs_freq_data *data = pdata[node];

	if (!data)
		return 0;

	if (IS_MACHINE_E8C2)
		return pcs_l_cpufreq_get_e8c2(data, cpu);

	return _pcs_l_cpufreq_get(data, cpu);
}

static int get_pcs_freq_data(struct platform_device *pdev,
			     struct pcs_freq_data *data, int node)
{
	int ret = 0;
	freq_core_mon_t mon;
	boot_info_t *boot_info = &bootblock_virt->info;
	uint8_t progr_divF, divF_min;

	mon.word = readl(data->base + PMC_FREQ_CORE_0_MON);
	progr_divF = boot_info->progr_divf;
	divF_min = progr_divF != 0 ? progr_divF : mon.divF_init;

	if (divF_min > mon.divF_limit_hi || divF_min != mon.divF_curr)
		return -EINVAL;

	data->div_max = mon.divF_limit_hi;
	data->div_min = divF_min;
	ret = pcs_l_create_freq_table(pdev, data, divF_min, mon.divF_limit_hi, node);
	if (ret) {
		pr_err("%s: Failed to create freq table\n", __func__);
		pr_err("%s: mon0 reg value 0x%08x of node %d core 0\n",
			__func__, mon.word, node);

		return ret;
	}

	return ret;
}

static int get_pcs_freq_data_e8c2(struct platform_device *pdev,
				  struct pcs_freq_data *data, int node)
{
	int ret;
	pcs_ctrl1_t ctrl;

	ctrl.word = readl(data->base + SIC_pcs_ctrl1);

	data->div_min = ctrl.n_fmin;
	data->div_max = ctrl.n;
	ret = pcs_l_create_freq_table_e8c2(pdev, data, ctrl.n, ctrl.n_fmin);
	if (ret) {
		pr_err("%s: Failed to create freq table\n", __func__);
		pr_err("%s: ctrl1 reg value 0x%08x of node %d\n",
			__func__, ctrl.word, node);

		return ret;
	}

	return 0;
}

static int init_pcs_freq_data(struct platform_device *pdev,
			      struct pcs_freq_data *data, int node)
{
	int ret = 0;

	if (IS_MACHINE_E8C2)
		ret = get_pcs_freq_data_e8c2(pdev, data, node);
	else
		ret = get_pcs_freq_data(pdev, data, node);

	return ret;
}

static int pcs_l_cpufreq_init(struct cpufreq_policy *policy)
{
	int node = cpu_to_node(policy->cpu);
	struct pcs_freq_data **pdata = cpufreq_get_driver_data();
	struct pcs_freq_data *data = pdata[node];

	if (!data)
		return -ENOMEM;

	unsigned int divf_steps = abs(data->div_max - data->div_min);

	policy->max = data->table[data->div_max].frequency;
	policy->min = data->table[data->div_min].frequency;

	policy->cur = pcs_l_cpufreq_get(policy->cpu);
	policy->freq_table = data->table;

	if (IS_MACHINE_E8C2) {
		cpumask_copy(policy->cpus, topology_core_cpumask(policy->cpu));
		policy->cpuinfo.transition_latency =
					DIVF_STEPS_LENGTH_NS_V5(divf_steps);
	} else {
		cpumask_set_cpu(policy->cpu, policy->cpus);
		policy->cpuinfo.transition_latency =
					DIVF_STEPS_LENGTH_NS(divf_steps);
	}
	policy->fast_switch_possible = true;

	return 0;
}

static int pcs_l_cpufreq_exit(struct cpufreq_policy *policy)
{
	return 0;
}

static struct freq_attr *pcs_l_cpufreq_attr[] = {
	&cpufreq_freq_attr_scaling_available_freqs,
	NULL,
};

static void pcs_l_cpufreq_set_e8c2(struct pcs_freq_data *data,
				   struct cpufreq_policy *policy,
				   unsigned int index)
{
	unsigned int div = policy->freq_table[index].driver_data;
	pcs_ctrl1_t ctrl;

	ctrl.word = readl(data->base + SIC_pcs_ctrl1);
	ctrl.pcs_mode = get_pcs_mode_e8c2(data) < 4 ? V5_PCS_MODE_3 : V5_PCS_MODE_7;
	ctrl.n_fprogr = div;
	writel(ctrl.word, data->base + SIC_pcs_ctrl1);
}

static void pcs_l_cpufreq_set(struct pcs_freq_data *data,
				 struct cpufreq_policy *policy,
				 unsigned int index)
{
	int core = cpu_to_cpuid(policy->cpu) % cpu_max_cores_num();
	unsigned int div = policy->freq_table[index].driver_data;
	freq_core_ctrl_t ctrl;

	ctrl.word = readl(data->base + PMC_FREQ_CORE_N_CTRL(core));
	if (IS_MACHINE_E2C3 || IS_MACHINE_E12C || IS_MACHINE_E16C) {
		if (!ctrl.v6.enable) {
			pr_err("%s: frequency scaling is disabled for core %d\n",
				__func__, core);
			return;
		}
		ctrl.v6.progr_divF = div;
		if (ctrl.v6.rmwen)
			ctrl.v6.rmwen = 0;
	} else {
		if (!ctrl.v7.enable) {
			pr_err("%s: frequency scaling is disabled for core %d\n",
				__func__, core);
			return;
		}
		ctrl.v7.progr_divF = div;
		if (ctrl.v7.rmwen)
			ctrl.v7.rmwen = 0;
	}
	writel(ctrl.word, data->base + PMC_FREQ_CORE_N_CTRL(core));
}

static int pcs_l_cpufreq_target_index(struct cpufreq_policy *policy,
				      unsigned int index)
{
	int node = cpu_to_node(policy->cpu);
	struct pcs_freq_data **pdata = cpufreq_get_driver_data();
	struct pcs_freq_data *data = pdata[node];

	if (IS_MACHINE_E8C2)
		pcs_l_cpufreq_set_e8c2(data, policy, index);
	else
		pcs_l_cpufreq_set(data, policy, index);

	return 0;
}

static unsigned int pcs_l_cpufreq_fast_switch(struct cpufreq_policy *policy,
					      unsigned int target_freq)
{
	int node = cpu_to_node(policy->cpu);
	struct pcs_freq_data **pdata = cpufreq_get_driver_data();
	struct pcs_freq_data *data = pdata[node];
	unsigned int next_freq, index;

	if (policy->cached_target_freq == target_freq)
		index = policy->cached_resolved_idx;
	else
		index = cpufreq_table_find_index_dl(policy, target_freq, false);

	next_freq = policy->freq_table[index].frequency;

	if (IS_MACHINE_E8C2)
		pcs_l_cpufreq_set_e8c2(data, policy, index);
	else
		pcs_l_cpufreq_set(data, policy, index);

	return next_freq;
}

/*
 * pcs_l_cpufreq_cpu_ready will be called after the driver is fully initialized.
 * set the minimum frequency 800 MHz for e2c3.
 */
static void pcs_l_cpufreq_cpu_ready(struct cpufreq_policy *policy)
{
	if (IS_MACHINE_E2C3) {
		unsigned long freq = 800000;
		if (freq_qos_update_request(policy->min_freq_req, freq) < 0)
			pr_err("%s: minimum frequency setting error %lu KHz\n",
				__func__, freq);
	}
}

static struct cpufreq_driver pcs_cpufreq_driver = {
	.init = pcs_l_cpufreq_init,
	.verify = cpufreq_generic_frequency_table_verify,
	.target_index = pcs_l_cpufreq_target_index,
	.fast_switch = pcs_l_cpufreq_fast_switch,
	.exit = pcs_l_cpufreq_exit,
	.get = pcs_l_cpufreq_get,
	.name = "pcs_cpufreq",
	.ready = pcs_l_cpufreq_cpu_ready,
	.attr = pcs_l_cpufreq_attr,
};

static int pcs_cpufreq_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct device_node *np = pdev->dev.of_node;
	struct device_node *pmc_freq_np;
	struct platform_device *pmc_freq_pdev;
	struct resource *res;
	void __iomem *base;
	struct pcs_freq_data **pdata, *data;
	int node;
	int ret;

	if (!PCS_CPUFREQ_SUPPORTED())
		return -ENODEV;

	pdata = devm_kzalloc(dev, sizeof(*pdata) * MAX_NUMNODES, GFP_KERNEL);
	if (!pdata)
		return -ENOMEM;

	for_each_online_node(node) {
		pdata[node] = devm_kzalloc(dev, sizeof(**pdata), GFP_KERNEL);
		data = pdata[node];
		if (!data)
			return -ENOMEM;

		pmc_freq_np = of_parse_phandle(np, "mcst,freq-nodes", node);
		if (!pmc_freq_np) {
			dev_err(dev, "failed parse phandle mcst,freq-nodes\n");
			return -ENODEV;
		}

		pmc_freq_pdev = of_find_device_by_node(pmc_freq_np);
		of_node_put(pmc_freq_np);
		if (!pmc_freq_pdev)
			return -ENODEV;

		res = platform_get_resource(pmc_freq_pdev, IORESOURCE_MEM, 0);
		if (!res) {
			dev_err(dev, "failed to get mem resource\n");
			return -ENOMEM;
		}

		base = devm_ioremap_resource(dev, res);
		if (IS_ERR(base)) {
			dev_err(dev, "failed to map resource\n");
			return PTR_ERR(base);
		}

		data->base = base;

		ret = init_pcs_freq_data(pdev, data, node);
		if (ret) {
			pr_err("%s: failed init pcs freq data\n", __func__);
			pr_err("%s: e2k-pcs-cpufreq not probed\n", __func__);
			return ret;
		}

		if (IS_MACHINE_E8C2) {
			if (check_bfs_bypass(data)) {
				pr_err("%s: CPU pins encode the BFS bypass mode (bfs_freq=8)\n",
					__func__);
				pr_err("%s: so frequency control is not available on the node %d!\n",
					__func__, node);
			}

			if (throttling >= 0)
				throttling_handle(data, node);

			if (get_pcs_mode_e8c2(data) < 4)
				pr_err("%s: throttling is disabled on node %d\n",
					__func__, node);
		}
	}
	pcs_cpufreq_driver.driver_data = pdata;

	ret = cpufreq_register_driver(&pcs_cpufreq_driver);
	if (ret) {
		pr_err("%s: failed to register cpufreq driver %d\n",
			__func__, ret);
	}

	return ret;
}

static int pcs_cpufreq_remove(struct platform_device *pdev)
{
	if (PCS_CPUFREQ_SUPPORTED())
		cpufreq_unregister_driver(&pcs_cpufreq_driver);

	return 0;
}

static const struct of_device_id pcs_cpufreq_of_match[] = {
	{ .compatible = "mcst,cpufreq", },
	{}
};

MODULE_DEVICE_TABLE(of, pcs_cpufreq_of_match);

static struct platform_driver pcs_cpufreq_platdrv = {
	.probe = pcs_cpufreq_probe,
	.remove = pcs_cpufreq_remove,
	.driver = {
		.name = "pcs_cpufreq",
		.of_match_table = pcs_cpufreq_of_match,
	},
};
module_platform_driver(pcs_cpufreq_platdrv);

MODULE_AUTHOR("MCST");
MODULE_DESCRIPTION("E2K CPUFreq Driver");
MODULE_LICENSE("GPL v2");
