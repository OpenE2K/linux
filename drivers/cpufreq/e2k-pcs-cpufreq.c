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

#define MAX_NODE 4
#define MAX_CORE 16

static int f_plls[MAX_NODE];

struct pcs_data {
	int div_max;
	int div_min;
	struct cpufreq_frequency_table *table;
};

struct pcs_data *cpufreq_pcs_data[MAX_NODE][MAX_CORE];

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

	struct cpufreq_frequency_table *table = kzalloc(
		(sizeof(struct cpufreq_frequency_table) *
		 (divFmax - divFmin + 2)), GFP_KERNEL);

	for (divF = divFmin; divF < MAX_STATES && divF <= divFmax; divF++) {
		table[divFi].frequency =
		    GET_FREQ(divF, f_plls[node]);
		table[divFi++].driver_data = divF;
	}

	table[divFi].frequency = CPUFREQ_TABLE_END;

	return table;
}

int get_idx_by_n_sys(int n_sys)
{
	return (n_sys < 20) ? n_sys - 10 : (n_sys < 32) ? 9 + (n_sys - 20) / 2 : 14;
}

int n_sys[] = {10, 11, 12, 13, 14, 15, 16, 17, 18, 20, 22, 24, 26, 28, 32};
int f_base_rev0[] = {900, 1000, 1050, 1100, 1125, 1175, 1200, 1300};
int f_base_rev1[] = {900, 1000, 1100, 1200, 1300, 1400, 1500, 1550};

static struct cpufreq_frequency_table *pcs_l_calc_freq_tables_e8c2(int node,
	int divFmin, int divFmax)
{
	struct cpufreq_frequency_table *table;
	int i, ii = 0;
	int f_base = 0;
	e2k_idr_t IDR;
	pcs_ctrl3_t ctrl;

	if (divFmin > divFmax) {
		pr_err("%s: invalid params", __func__);
		return NULL;
	}

	table = kzalloc((sizeof(struct cpufreq_frequency_table) *
				(ARRAY_SIZE(n_sys) + 1)),
				GFP_KERNEL);

	ctrl.word = sic_read_node_nbsr_reg(node, SIC_pcs_ctrl3);

	IDR = read_IDR_reg();

	if (!IDR.IDR_rev)
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
	int core = cpu_to_cpuid(cpu) % cpu_max_cores_num();
	struct cpufreq_frequency_table *table =
	    cpufreq_pcs_data[node][core]->table;
	int target_idx = 0;
	pcs_ctrl1_t ctrl;

	ctrl.word = sic_read_node_nbsr_reg(node, SIC_pcs_ctrl1);

	target_idx = get_idx_by_n_sys(ctrl.n) - get_idx_by_n_sys(table[0].driver_data);

	return cpufreq_pcs_data[node][core]->table[target_idx].frequency;
}

static unsigned int pcs_l_cpufreq_get_e16c(unsigned int cpu)
{
	freq_core_mon_t mon;
	int core = cpu_to_cpuid(cpu) % cpu_max_cores_num();
	int node = cpu_to_node(cpu);
	struct pcs_data *pcs_data = cpufreq_pcs_data[node][core];

	mon.word = sic_read_node_nbsr_reg(node, PMC_FREQ_CORE_N_MON(core));
	WARN_ON_ONCE(mon.divF_curr < pcs_data->div_min || mon.divF_curr > pcs_data->div_max);

	return pcs_data->table[mon.divF_curr - pcs_data->div_min].frequency;
}

static unsigned int pcs_l_cpufreq_get(unsigned int cpu)
{
	if (IS_MACHINE_E8C2)
		return pcs_l_cpufreq_get_e8c2(cpu);

	return pcs_l_cpufreq_get_e16c(cpu);
}

static int pcs_l_cpufreq_setpolicy(struct cpufreq_policy *policy)
{
	/* TODO */
	switch (policy->policy) {
	case CPUFREQ_POLICY_PERFORMANCE:
		break;
	case CPUFREQ_POLICY_POWERSAVE:
		break;
	}

	return 0;
}

static int get_f_pll(int node)
{
	int addr = EFUSE_START_ADDR;
	int f_pll = DEFAULT_F_PLL;
	uint64_t data[4];
	int i = 0;

	for (addr; addr < EFUSE_END_ADDR; addr++) {
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

static struct pcs_data *get_pcs_data(int node, int core)
{
	freq_core_mon_t mon;
	struct pcs_data *data;

	data = kzalloc(sizeof(struct pcs_data), GFP_KERNEL);

	mon.word = sic_read_node_nbsr_reg(node, PMC_FREQ_CORE_N_MON(core));

	data->div_max = mon.divF_limit_hi;
	data->div_min = mon.divF_init;
	data->table = pcs_l_calc_freq_tables(node,
		mon.divF_init, mon.divF_limit_hi);

	return data;
}

static struct pcs_data *get_pcs_data_e8c2(int node)
{
	pcs_ctrl1_t ctrl;
	struct pcs_data *data;

	data = kzalloc(sizeof(struct pcs_data), GFP_KERNEL);

	ctrl.word = sic_read_node_nbsr_reg(node, SIC_pcs_ctrl1);

	data->div_min = ctrl.n_fmin;
	data->div_max = ctrl.n;
	data->table = pcs_l_calc_freq_tables_e8c2(node, ctrl.n, ctrl.n_fmin);

	return data;
}

static int pcs_l_cpufreq_init(struct cpufreq_policy *policy)
{
	int node = cpu_to_node(policy->cpu);
	int core = cpu_to_cpuid(policy->cpu) % cpu_max_cores_num();
	struct pcs_data *data = cpufreq_pcs_data[node][core];

	policy->max = data->table[data->div_max].frequency;
	policy->min = data->table[data->div_min].frequency;

	policy->cur = pcs_l_cpufreq_get(policy->cpu);
	policy->freq_table = data->table;
	policy->cpuinfo.transition_latency = CPUFREQ_ETERNAL;

	cpumask_set_cpu(policy->cpu, policy->cpus);

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

static struct cpufreq_driver pcs_cpufreq_driver = {
	.init = pcs_l_cpufreq_init,
	.verify = cpufreq_generic_frequency_table_verify,
	.setpolicy = pcs_l_cpufreq_setpolicy,
	.exit = pcs_l_cpufreq_exit,
	.get = pcs_l_cpufreq_get,
	.name = "pcs_cpufreq",
	.attr = pcs_l_cpufreq_attr,
};

static int __init pcs_cpufreq_probe(void)
{
	/* cpufreq driver is disabled on guest as it is host's
	 * responsibility to adjust CPU frequency. */
	bool use_cpufreq = !IS_HV_GM() && !IS_ENABLED(CONFIG_KVM_GUEST_KERNEL);

	if ((IS_MACHINE_E2C3 || IS_MACHINE_E12C || IS_MACHINE_E16C ||
		    IS_MACHINE_E8C2) && use_cpufreq && !is_prototype()) {

		int node;
		int core;

		for_each_online_node(node) {
			if (IS_MACHINE_E8C2) {
				struct pcs_data *data;

				if (check_bfs_bypass(node)) {
					pr_err("cpufreq: CPU pins encode BFS bypass mode (bfs_freq==8),"
						" that is why program frequency control is unavailable on node %d!", node);
					continue;
				}

				if (get_pcs_mode(node) < 4)
					pr_err("cpufreq: throttling is disabled on node %d", node);

				data = get_pcs_data_e8c2(node);

				for (core = 0; core < cpu_max_cores_num(); core++)
					cpufreq_pcs_data[node][core] = data;
			} else {
				f_plls[node] = get_f_pll(node);

				for (core = 0; core < cpu_max_cores_num(); core++)
					cpufreq_pcs_data[node][core] = get_pcs_data(node, core);
			}
		}

		if (cpufreq_register_driver(&pcs_cpufreq_driver)) {
			pr_err("ERROR: %s: %d\n", __func__, __LINE__);
		}
	}

	return 0;
}

static void __exit pcs_cpufreq_remove(void)
{
	/* cpufreq driver is disabled on guest as it is host's
	 * responsibility to adjust CPU frequency. */
	bool use_cpufreq = !IS_HV_GM() && !IS_ENABLED(CONFIG_KVM_GUEST_KERNEL);

	if ((IS_MACHINE_E2C3 || IS_MACHINE_E12C || IS_MACHINE_E16C ||
		    IS_MACHINE_E8C2) && use_cpufreq && !is_prototype()) {
		cpufreq_unregister_driver(&pcs_cpufreq_driver);
	}
}

MODULE_AUTHOR("Arseniy.A.Demidov@mcst.ru");
MODULE_DESCRIPTION("E2K CPUFreq Driver");
MODULE_LICENSE("GPL v2");

module_init(pcs_cpufreq_probe);
module_exit(pcs_cpufreq_remove);
