#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/err.h>
#include <linux/cpufreq.h>
#include <linux/topology.h>
#include <asm/sic_regs.h>
#include <asm/sic_regs_access.h>

#define M_BFS 3
#define N_BFS 16
#define MAX_STATES (M_BFS*N_BFS)
#define DEFAULT_F_PLL 2000 /* Mhz */

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

#define GET_OD(data) ((OD_MASK << OD_OFFSET) & data)
#define GET_NR(data) ((NR_MASK << NR_OFFSET) & data)

struct cpufreq_frequency_table pcs_l_freqs[MAX_STATES + 1];

typedef union {
    struct {
	u32 sign	: 1;
	u32 disable	: 1;
	u32 parity	: 1;
	u32 addr	: 7;
	u32 broadcast	: 1;
	u32 data	: 21;
    };
    u32 word;
} efuse_data_t;

static inline int get_nf(uint64_t *data)
{
    uint64_t val = 0;
    val += (((NF_MASK_LO << NF_OFFSET_LO) & data[0]) >> NF_OFFSET_LO);
    val += data[1] << (EFUSE_DATA_SIZE - NF_OFFSET_LO);
    val += data[2] << (EFUSE_DATA_SIZE * 2 - NF_OFFSET_LO);
    val += ((NF_MASK_HI << NF_OFFSET_HI) & data[3]) << (EFUSE_DATA_SIZE * 3 - NF_OFFSET_LO);

    return val;
}

#define GET_FREQ(div, pll) (16000*pll/(1 << div/16)/(div%16 + 16)) /* Khz */

static void pcs_l_calc_freq_tables(int f_pll)
{
    int divF = 0;

    for (divF; divF < MAX_STATES; divF++) {
	pcs_l_freqs[divF].frequency = GET_FREQ(divF, f_pll);
	pcs_l_freqs[divF].driver_data = divF;
    }

    pcs_l_freqs[divF].frequency = CPUFREQ_TABLE_END;
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
    mon->divF_limit_lo,
    mon->divF_init,
    mon->bfs_bypass);
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
    sleep->alter_disable,
    sleep->bfs_bypass,
    sleep->pin_en);
}

static void print_efuse_data(efuse_data_t *efuse_data)
{
    printk(KERN_DEBUG "efuse_data:\n"
    "\tsign	    %d\n"
    "\tdisable	    %d\n"
    "\tparity	    %d\n"
    "\taddr	    %d\n"
    "\tbroadcast    %d\n"
    "\tdata	    %d\n",
    efuse_data->sign,
    efuse_data->disable,
    efuse_data->parity,
    efuse_data->addr,
    efuse_data->broadcast,
    efuse_data->data);
}
#endif

static unsigned int pcs_l_cpufreq_get(unsigned int cpu)
{
    freq_core_mon_t mon;
    int core = cpu_to_cpuid(cpu) % cpu_max_cores_num();
    int node = cpu_to_node(cpu);

    mon.word = sic_read_node_nbsr_reg(node, PMC_FREQ_CORE_N_MON(core));

    return pcs_l_freqs[mon.divF_curr].frequency;
}

static int pcs_l_cpufreq_setpolicy (struct cpufreq_policy *policy)
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

static int pcs_l_cpufreq_verify_policy(struct cpufreq_policy_data *policy)
{
    return cpufreq_frequency_table_verify(policy, pcs_l_freqs);
}

static int get_f_pll(int node)
{
    /* TODO */
    int addr = EFUSE_START_ADDR;
    int f_pll = DEFAULT_F_PLL;
    uint64_t data[4];
    int i = 0;

    for (addr; addr < EFUSE_END_ADDR; addr++) {
	efuse_data_t efuse_data;

	sic_write_node_nbsr_reg(node, EFUSE_RAM_ADDR, addr);
	efuse_data.word =  sic_read_node_nbsr_reg(node, EFUSE_RAM_DATA);

	if (efuse_data.sign && !efuse_data.disable && efuse_data.broadcast &&
		(efuse_data.addr >= 0x46 && efuse_data.addr <= 0x49)) {
	    data[i++] = efuse_data.data;
#ifdef DEBUG
	    print_efuse_data(&efuse_data);
#endif
	}
    }

    if (i == 4) {
	int nr = GET_NR(data[3]);
	int nf = get_nf(data);
	int od = GET_OD(data[0]);

	f_pll = nf/(1LL<<33)*(nr+1)*(od+1);
    }

    return DEFAULT_F_PLL;
}

static int pcs_l_cpufreq_init(struct cpufreq_policy *policy)
{
    freq_core_mon_t mon;
    int core = cpu_to_cpuid(policy->cpu) % cpu_max_cores_num();
    int node = cpu_to_node(policy->cpu);

    mon.word = sic_read_node_nbsr_reg(node, PMC_FREQ_CORE_N_MON(core));

    pcs_l_calc_freq_tables(get_f_pll(node));

    policy->max = pcs_l_freqs[mon.divF_limit_hi].frequency;
    policy->min = pcs_l_freqs[mon.divF_limit_lo].frequency;

    policy->cur = pcs_l_cpufreq_get(policy->cpu);
    policy->freq_table = pcs_l_freqs;
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
    .init	= pcs_l_cpufreq_init,
    .verify	= pcs_l_cpufreq_verify_policy,
    .setpolicy	= pcs_l_cpufreq_setpolicy,
    .exit	= pcs_l_cpufreq_exit,
    .get	= pcs_l_cpufreq_get,
    .name	= "pcs_cpufreq",
    .attr	= pcs_l_cpufreq_attr,
};

static int __init pcs_cpufreq_probe(void)
{
    if (IS_MACHINE_E2C3 || IS_MACHINE_E12C || IS_MACHINE_E16C) {
	if (cpufreq_register_driver(&pcs_cpufreq_driver)) {
	    pr_err("ERROR: %s: %d\n", __FUNCTION__, __LINE__);
	}
    }

    return 0;
}

static void __exit pcs_cpufreq_remove(void)
{
    if (IS_MACHINE_E2C3 || IS_MACHINE_E12C || IS_MACHINE_E16C) {
	cpufreq_unregister_driver(&pcs_cpufreq_driver);
    }
}

MODULE_AUTHOR("Arseniy.A.Demidov@mcst.ru");
MODULE_DESCRIPTION("E2K CPUFreq Driver");
MODULE_LICENSE("GPL v2");

module_init(pcs_cpufreq_probe);
module_exit(pcs_cpufreq_remove);
