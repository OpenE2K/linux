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
#include <asm/sic_regs.h>
#include <asm/sic_regs_access.h>

#define M_BFS 3
#define N_BFS 16
#define MAX_STATES (M_BFS*N_BFS)
#define DEFAULT_F_PLL	2000
#define MAX_F_PLL	2000
#define MIN_F_PLL	600
#define F_REF		100

#define EFUSE_START_ADDR    0x0
#define EFUSE_END_ADDR	    0xff
#define OD_MASK		    0x7ff
#define NF_MASK_LO	    0x1f
#define NF_MASK_HI	    0x7f
#define NR_MASK		    0xfff

#define OD_OFFSET           5
#define NF_OFFSET_LO	    16
#define NF_OFFSET_HI	    0
#define NR_OFFSET	    7

#define EFUSE_DATA_SIZE	    21

#define get_od(data) (OD_MASK & (data >> OD_OFFSET))
#define get_nr(data) (NR_MASK & (data >> NR_OFFSET))

#define V5_PCS_MODE_3 0x3
#define V5_PCS_MODE_7 0x7

/*
 * cpufreq driver is disabled on guest as it is host's responsibility to adjust
 * CPU frequency.
 */
#define PCS_CPUFREQ_SUPPORTED() \
		((IS_MACHINE_E2C3 || IS_MACHINE_E12C || IS_MACHINE_E16C || \
		IS_MACHINE_E8C2 || IS_MACHINE_E48C || IS_MACHINE_E8V7) && \
		!IS_HV_GM() && !IS_ENABLED(CONFIG_KVM_GUEST_KERNEL) && \
		!is_prototype())

/* V6 one step takes ~2600 ns */
#define DIVF_STEPS_LENGTH_NS_V6(divF) ((divF) * 2600)
/* V5 one step takes ~250 ns */
#define DIVF_STEPS_LENGTH_NS_V5(divF) ((divF) * 250)
#define THROTTLING_NODE_BITMASK(f) (1U << (f))

/*
 * module param throttling:
 * bit [0]: responsible for enabling throttling
 * bits [7-4]: nodes 3-0
*/
static char throttling = -1;
module_param(throttling, byte, 0444);
MODULE_PARM_DESC(throttling, KBUILD_MODNAME " cpufreq throttling");

typedef union {
	struct {
		u8 enable:1;
		u8 :3;
		u8 nodemask:4;
	};
	u8 byte;
} throttling_data_t;

static int f_plls[MAX_NUMNODES];

struct pcs_data {
	int div_max;
	int div_min;
	struct cpufreq_frequency_table *table;
};

struct pcs_data *cpufreq_pcs_data[MAX_NUMNODES];

typedef union {
	struct {
		u32 data:21;
		u32 broadcast:1;
		u32 addr:7;
		u32 parity:1;
		u32 disable:1;
		u32 sign:1;
	};
	u32 word;
} efuse_data_t;

static inline bool check_bfs_bypass(int node)
{
	pcs_ctrl3_t ctrl;

	ctrl.word = sic_read_node_nbsr_reg(node, SIC_pcs_ctrl3);

	return (ctrl.bfs_freq == 8);
}

static inline int get_pcs_mode(int node)
{
	pcs_ctrl1_t ctrl;

	ctrl.word = sic_read_node_nbsr_reg(node, SIC_pcs_ctrl1);

	return ctrl.pcs_mode;
}

static inline void set_pcs_mode(throttling_data_t *throttling_data, int node)
{
	pcs_ctrl1_t ctrl;

	ctrl.word = sic_read_node_nbsr_reg(node, SIC_pcs_ctrl1);
	ctrl.pcs_mode = throttling_data->enable ? V5_PCS_MODE_7 : V5_PCS_MODE_3;
	sic_write_node_nbsr_reg(node, SIC_pcs_ctrl1, ctrl.word);
}

static void throttling_handle(int node)
{
	throttling_data_t throttling_data;
	throttling_data.byte = throttling;

	if (throttling_data.nodemask & THROTTLING_NODE_BITMASK(node))
		set_pcs_mode(&throttling_data, node);
	else if (!throttling_data.nodemask)
		set_pcs_mode(&throttling_data, node);
}

static inline int64_t get_nf(uint64_t *data)
{
	int64_t val = 0;
	val += (NF_MASK_LO & (data[0] >> NF_OFFSET_LO));
	val += data[1] << (EFUSE_DATA_SIZE - NF_OFFSET_LO);
	val += data[2] << (EFUSE_DATA_SIZE * 2 - NF_OFFSET_LO);
	val +=
	    ((NF_MASK_HI << NF_OFFSET_HI) & data[3]) << (EFUSE_DATA_SIZE * 3 -
							 NF_OFFSET_LO);

	return val;
}

#define GET_FREQ(div, pll) (16000*pll/(1 << div/16)/(div%16 + 16))	/* Khz */

static struct cpufreq_frequency_table *pcs_l_calc_freq_tables(int node,
	int divFmin, int divFmax)
{
	int divF;
	int divFi = 0;

	struct cpufreq_frequency_table *table = kzalloc((sizeof(struct cpufreq_frequency_table) *
		 (divFmax - divFmin + 2)), GFP_KERNEL);
	if (table == NULL) {
		return NULL;
	}
	for (divF = divFmin; divF < MAX_STATES && divF <= divFmax; divF++) {
		table[divFi].frequency = GET_FREQ(divF, f_plls[node]);
		table[divFi++].driver_data = divF;
	}

	table[divFi].frequency = CPUFREQ_TABLE_END;

	return table;
}

int get_idx_by_n_sys(int n_sys)
{
	return n_sys - 8;
}

int n_sys[] = {8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
	       20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
int f_base_rev0[] = {900, 1000, 1050, 1100, 1125, 1175, 1200, 1300};
int f_base_rev1[] = {900, 1000, 1100, 1200, 1300, 1400, 1500, 1550};

static struct cpufreq_frequency_table *pcs_l_calc_freq_tables_e8c2(int node,
	int divFmin, int divFmax)
{
	struct cpufreq_frequency_table *table;
	int i, ii = 0;
	int f_base = 0;
	pcs_ctrl3_t ctrl;

	if (divFmin >= divFmax) {
		pr_err("%s: invalid params", __func__);
		return NULL;
	}

	table = kzalloc((sizeof(struct cpufreq_frequency_table) *
				(ARRAY_SIZE(n_sys) + 1)),
				GFP_KERNEL);
	if (table == NULL) {
		return NULL;
	}
	ctrl.word = sic_read_node_nbsr_reg(node, SIC_pcs_ctrl3);

	if (!read_IDR_reg().rev)
		f_base = f_base_rev0[ctrl.pll_mode];
	else
		f_base = f_base_rev1[ctrl.pll_mode];

	for (i = 0; i < ARRAY_SIZE(n_sys); i++) {
		int freq = f_base * 16000 / n_sys[i];

		if (n_sys[i] >= divFmin && n_sys[i] <= divFmax) {
			table[ii].frequency = freq;
			table[ii].driver_data = n_sys[i];
			ii++;
		}
	}

	table[ii].frequency = CPUFREQ_TABLE_END;

	return table;
}

#ifdef DEBUG
static void print_pmc_freq_core_mon(freq_core_mon_t *mon)
{
	printk(KERN_DEBUG "freq_core_mon:\n"
	       "\tdivF_curr	%d\n"
	       "\tdivF_target	%d\n"
	       "\tdivF_limit_hi	%d\n"
	       "\tdivF_limit_lo	%d\n"
	       "\tdivF_init	%d\n"
	       "\tbfs_bypass	%d\n",
	       mon->divF_curr,
	       mon->divF_target,
	       mon->divF_limit_hi,
	       mon->divF_limit_lo, mon->divF_init, mon->bfs_bypass);
}

static void print_pmc_freq_core_sleep(freq_core_sleep_t *sleep)
{
	printk(KERN_DEBUG "freq_core_sleep:\n"
	       "\tcmd		%d\n"
	       "\tstatus		%d\n"
	       "\tctrl_enable	%d\n"
	       "\talter_disable	%d\n"
	       "\tbfs_bypass	%d\n"
	       "\tpin_en		%d\n",
	       sleep->cmd,
	       sleep->status,
	       sleep->ctrl_enable,
	       sleep->alter_disable, sleep->bfs_bypass, sleep->pin_en);
}

static void print_efuse_data(efuse_data_t *efuse_data)
{
	printk(KERN_DEBUG "efuse_data:\n"
	       "\tsign	    %d\n"
	       "\tdisable	    %d\n"
	       "\tparity	    %d\n"
	       "\taddr	    0x%x\n"
	       "\tbroadcast    %d\n"
	       "\tdata	    0x%x\n",
	       efuse_data->sign,
	       efuse_data->disable,
	       efuse_data->parity,
	       efuse_data->addr, efuse_data->broadcast, efuse_data->data);
}
#endif

static unsigned int pcs_l_cpufreq_get_e8c2(unsigned int cpu)
{
	int node = cpu_to_node(cpu);
	int target_idx = 0;
	pcs_ctrl1_t ctrl;

	if (cpufreq_pcs_data[node] == NULL) {
		return 0;
	}
	struct cpufreq_frequency_table *table = cpufreq_pcs_data[node]->table;
	ctrl.word = sic_read_node_nbsr_reg(node, SIC_pcs_ctrl1);

	target_idx = get_idx_by_n_sys(ctrl.n) - get_idx_by_n_sys(table[0].driver_data);

	return cpufreq_pcs_data[node]->table[target_idx].frequency;
}

static unsigned int pcs_l_cpufreq_get_v6(unsigned int cpu)
{
	freq_core_mon_t mon;
	int core = cpu_to_cpuid(cpu) % cpu_max_cores_num();
	int node = cpu_to_node(cpu);
	struct pcs_data *pcs_data = cpufreq_pcs_data[node];

	if (pcs_data == NULL) {
		return 0;
	}

	mon.word = sic_read_node_nbsr_reg(node, PMC_FREQ_CORE_N_MON(core));
	WARN_ON_ONCE(mon.divF_curr < pcs_data->div_min || mon.divF_curr > pcs_data->div_max);

	return pcs_data->table[mon.divF_curr - pcs_data->div_min].frequency;
}

static unsigned int pcs_l_cpufreq_get(unsigned int cpu)
{
	if (IS_MACHINE_E8C2)
		return pcs_l_cpufreq_get_e8c2(cpu);

	return pcs_l_cpufreq_get_v6(cpu);
}

static int get_f_pll(int node)
{
	int addr;
	int f_pll = DEFAULT_F_PLL;
	uint64_t data[4];
	int i = 0;

	for (addr = EFUSE_START_ADDR; addr < EFUSE_END_ADDR; addr++) {
		efuse_data_t efuse_data;
#ifdef DEBUG
		print_efuse_data(&efuse_data);
#endif
		sic_write_node_nbsr_reg(node, EFUSE_RAM_ADDR, addr);
		efuse_data.word = sic_read_node_nbsr_reg(node, EFUSE_RAM_DATA);
		if (efuse_data.sign && !efuse_data.disable
		    && efuse_data.broadcast && (efuse_data.addr >= 0x45)
		    && (efuse_data.addr <= 0x48)) {
			data[i++] = efuse_data.data;
		}
	}

	if (i == 4) {
		int64_t nr = get_nr(data[3]);
		int64_t nf = get_nf(data);
		int64_t od = get_od(data[0]);

		int f_pll_calc = F_REF * nf / ((1LL << 33) * (nr + 1) * (od + 1));

		if (f_pll_calc >= MIN_F_PLL && f_pll_calc <= MAX_F_PLL)
			f_pll = f_pll_calc;
	}

	return f_pll;
}

static struct pcs_data *get_pcs_data(int node)
{
	freq_core_mon_t mon;
	struct pcs_data *data;


	mon.word = sic_read_node_nbsr_reg(node, PMC_FREQ_CORE_0_MON);
	if (mon.divF_init >= mon.divF_limit_hi) {
		return NULL;
	}

	data = kzalloc(sizeof(struct pcs_data), GFP_KERNEL);
	if (data == NULL) {
		return NULL;
	}
	data->div_max = mon.divF_limit_hi;
	data->div_min = mon.divF_init;
	data->table = pcs_l_calc_freq_tables(node, mon.divF_init, mon.divF_limit_hi);
	if (data->table == NULL) {
		kfree(data);
		return NULL;
	}
	return data;
}

static struct pcs_data *get_pcs_data_e8c2(int node)
{
	pcs_ctrl1_t ctrl;
	struct pcs_data *data;

	data = kzalloc(sizeof(struct pcs_data), GFP_KERNEL);
	if (data == NULL) {
		return NULL;
	}

	ctrl.word = sic_read_node_nbsr_reg(node, SIC_pcs_ctrl1);

	data->div_min = ctrl.n_fmin;
	data->div_max = ctrl.n;
	data->table = pcs_l_calc_freq_tables_e8c2(node, ctrl.n, ctrl.n_fmin);

	if (data->table == NULL) {
		kfree(data);
		return NULL;
	}

	return data;
}


static int pcs_l_cpufreq_init(struct cpufreq_policy *policy)
{
	int node = cpu_to_node(policy->cpu);
	struct pcs_data *data = cpufreq_pcs_data[node];
	if (data == NULL) {
		return -ENOMEM;
	}
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
					DIVF_STEPS_LENGTH_NS_V6(divf_steps);
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

static void pcs_l_cpufreq_set_e8c2(struct cpufreq_policy *policy,
				      unsigned int index)
{
	int node = cpu_to_node(policy->cpu);
	unsigned int div = policy->freq_table[index].driver_data;
	pcs_ctrl1_t ctrl;

	ctrl.word = sic_read_node_nbsr_reg(node, SIC_pcs_ctrl1);
	ctrl.pcs_mode = get_pcs_mode(node) < 4 ? V5_PCS_MODE_3 : V5_PCS_MODE_7;
	ctrl.n_fprogr = div;
	sic_write_node_nbsr_reg(node, SIC_pcs_ctrl1, ctrl.word);
}

static void pcs_l_cpufreq_set_v6(struct cpufreq_policy *policy,
				      unsigned int index)
{
	int node = cpu_to_node(policy->cpu);
	int core = cpu_to_cpuid(policy->cpu) % cpu_max_cores_num();
	unsigned int div = policy->freq_table[index].driver_data;
	freq_core_ctrl_t ctrl;

	ctrl.word = sic_read_node_nbsr_reg(node, PMC_FREQ_CORE_N_CTRL(core));
	ctrl.progr_divF = div;
	sic_write_node_nbsr_reg(node, PMC_FREQ_CORE_N_CTRL(core), ctrl.word);
}

static int pcs_l_cpufreq_target_index(struct cpufreq_policy *policy,
				      unsigned int index)
{
	if (IS_MACHINE_E8C2)
		pcs_l_cpufreq_set_e8c2(policy, index);
	else
		pcs_l_cpufreq_set_v6(policy, index);

	return 0;
}

static unsigned int pcs_l_cpufreq_fast_switch(struct cpufreq_policy *policy,
                                              unsigned int target_freq)
{
	unsigned int next_freq, index;

	if (policy->cached_target_freq == target_freq)
		index = policy->cached_resolved_idx;
	else
		index = cpufreq_table_find_index_dl(policy, target_freq);

	next_freq = policy->freq_table[index].frequency;

	if (IS_MACHINE_E8C2)
		pcs_l_cpufreq_set_e8c2(policy, index);
	else
		pcs_l_cpufreq_set_v6(policy, index);

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
			pr_err("cpufreq: minimum frequency setting error %lu KHz\n", freq);
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

static int __init pcs_cpufreq_probe(void)
{
	struct pcs_data *data;
	int node;
	int ret = 0;

	if (!PCS_CPUFREQ_SUPPORTED())
		return -ENODEV;

	for_each_online_node(node) {
		if (IS_MACHINE_E8C2) {
			if (check_bfs_bypass(node)) {
				pr_err("cpufreq: CPU pins encode BFS bypass mode (bfs_freq==8), that is why program frequency control is unavailable on node %d!",
					node);
				continue;
			}

			if (throttling >= 0)
				throttling_handle(node);

			if (get_pcs_mode(node) < 4)
				pr_err("cpufreq: throttling is disabled on node %d", node);
			data = get_pcs_data_e8c2(node);
		} else {
			f_plls[node] = get_f_pll(node);
			data = get_pcs_data(node);
		}

		cpufreq_pcs_data[node] = data;
		if (cpufreq_pcs_data[node] == NULL) {
			if (IS_MACHINE_E8C2) {
				pr_err("Wrong cpufreq ctrl1 reg value 0x%08x of node %d\n",
					sic_read_node_nbsr_reg(node,
						SIC_pcs_ctrl1), node);
			} else {
				pr_err("Wrong cpufreq mon0 reg value 0x%08x of node %d core 0\n",
					sic_read_node_nbsr_reg(node,
					    PMC_FREQ_CORE_0_MON), node);
			}
			pr_err("e2k-pcs-cpufreq: not probed\n");

			return -ENODEV;
		}
	}

	ret = cpufreq_register_driver(&pcs_cpufreq_driver);
	if (ret) {
		pr_err("ERROR: %s: %d\n", __func__, ret);
	}

	return ret;
}

static void __exit pcs_cpufreq_remove(void)
{
	if (PCS_CPUFREQ_SUPPORTED())
		cpufreq_unregister_driver(&pcs_cpufreq_driver);
}

MODULE_AUTHOR("MCST");
MODULE_DESCRIPTION("E2K CPUFreq Driver");
MODULE_LICENSE("GPL v2");

module_init(pcs_cpufreq_probe);
module_exit(pcs_cpufreq_remove);
