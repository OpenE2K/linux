/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/cpufreq.h>
#include <linux/smp.h>
#include <linux/topology.h>
#include <linux/node.h>
#include <linux/cpu.h>
#include <asm/l_pmc.h>
#include <asm/io.h>
#include <asm/sic_regs.h>
#include <asm/e90s.h>

#include "pmc.h"

#define S2_PMC_DEBUG 0
#ifdef S2_PMC_DEBUG
#define DebugPMC(x, ...) do {					\
	pr_err("S2-PMC DEBUG: %s: %d: " x, __func__,		\
				__LINE__, ##__VA_ARGS__);	\
} while (0)
#else
#define DebugPMC(...) (while (0) {})
#endif /* S2_PMC_DEBUG */

struct l_pmc l_pmc[MAX_NUM_PMCS];

/*
 *  Global storage for NBSR_NODE_CFG_INFO, same for all nodes,
 *  initialized in s2_pmc_init
 */
unsigned int bfs_bypass_val;

/**
 * s2_reg_to_addr - convert PMC register name to matching arrdess
 * @reg: PMC register
 * @cpu:
 *
 * S2 (R2000) PMC specific function, converts PMC register to
 * corresponding address which depends on CPU's cluster (CL0 or CL1)
 *
 */
unsigned int s2_reg_to_addr(pmc_reg reg, unsigned int cpu)
{
	switch (reg) {
	case PMC_L_COVFID_STATUS_REG:
		if (cpu_to_cluster(cpu))
			return PMC_L_COVFID_STATUS_REG_CL1;
		else
			return PMC_L_COVFID_STATUS_REG_CL0;
	case PMC_L_P_STATE_CNTRL_REG:
		if (cpu_to_cluster(cpu))
			return PMC_L_P_STATE_CNTRL_REG_CL1;
		else
			return PMC_L_P_STATE_CNTRL_REG_CL0;
	case PMC_L_P_STATE_STATUS_REG:
		if (cpu_to_cluster(cpu))
			return PMC_L_P_STATE_STATUS_REG_CL1;
		else
			return PMC_L_P_STATE_STATUS_REG_CL0;
	case PMC_L_P_STATE_VALUE_0_REG:
		if (cpu_to_cluster(cpu))
			return PMC_L_P_STATE_VALUE_0_REG_CL1;
		else
			return PMC_L_P_STATE_VALUE_0_REG_CL0;
	case PMC_L_P_STATE_VALUE_1_REG:
		if (cpu_to_cluster(cpu))
			return PMC_L_P_STATE_VALUE_1_REG_CL1;
		else
			return PMC_L_P_STATE_VALUE_1_REG_CL0;
	case PMC_L_P_STATE_VALUE_2_REG:
		if (cpu_to_cluster(cpu))
			return PMC_L_P_STATE_VALUE_2_REG_CL1;
		else
			return PMC_L_P_STATE_VALUE_2_REG_CL0;
	case PMC_L_P_STATE_VALUE_3_REG:
		if (cpu_to_cluster(cpu))
			return PMC_L_P_STATE_VALUE_3_REG_CL1;
		else
			return PMC_L_P_STATE_VALUE_3_REG_CL0;
	}
	return 0;
}

unsigned s2_get_freq_mult(int cpu)
{
	unsigned int freq, Fbfs, Mii_inv, Nii;
	unsigned int fid = 0;
	fid =  pmc_reg_readl(PMC_L_P_STATE_VALUE_0_REG, cpu);
	Mii_inv = Mii_inv(fid);
	Nii = Nii(fid);
	Fbfs = Fbfs(BASE_FREQ, bfs_bypass_val & 0xf);
	freq = Fcpu(Fbfs, Mii_inv, Nii);
	return freq;
}

#ifdef CONFIG_CPU_FREQ

/* cpufreq subsystem: */
struct cpufreq_frequency_table pmc_l_freqs[MAX_PSTATES];
/* available frequencies */
struct cpufreq_frequency_table
			pmc_l_available_freqs[MAX_AV_PSTATES];

int pmc_l_cpufreq_init(struct cpufreq_policy *policy)
{
	int result = 0;
	unsigned long cpu_mask;
	unsigned int hb_syscfg_val;
	int i = 0;
	int node = cpu_to_node(policy->cpu);
	void __iomem *pmc_cbase = __pmc_regs(node);
	unsigned int reg_addr;
	/*
	 * Set masks for groups of cpu, that share the same frequency.
	 * Same freqs have cpus situated on the same node cluster,
	 * R2000 cpu has two cluster of 4 cores (8 cores in total) per each node
	 */
	for (i = 0; i < 8; i++) {
		if (1UL << policy->cpu & 0xffUL << (i * 8)) {
			if (policy->cpu & 0x4) {
				cpu_mask = 0xf0UL<<(i*8);
			} else {
				cpu_mask = 0xfUL<<(i*8);
			}
			memcpy(policy->cpus, &cpu_mask, sizeof(cpu_mask));
		}
	}

	hb_syscfg_val = bfs_bypass_val;

	if (bfs_bypass_val & HB_BFS_BYPASS_MASK) {
		/*
		 * WA case.
		 * pmc_l_init_wa_freq_tables() should be here, but...
		 * S2 1st iteration has a bug in bypass mode, so we can`t use it now
		 */
		return -ENODEV;
	} else { /* Normal case. */

		/*
		 * Calculate FIDs - Frequencies table.
		 */
		pmc_l_calc_freq_tables(policy, hb_syscfg_val & 0xf);
	}

	/*
	 * Write FID values to P_State_value_X registers
	 * (NOTE: we do not touch state P0 on init, - use value from boot.
	 * P0 can be updated when using userspace governor.
	 */
	reg_addr = s2_reg_to_addr(PMC_L_P_STATE_VALUE_1_REG, policy->cpu);
	__raw_writel(pmc_l_freqs[PMC_PSTATEVAL_REG1].driver_data,
					pmc_cbase + reg_addr);
	reg_addr = s2_reg_to_addr(PMC_L_P_STATE_VALUE_2_REG, policy->cpu);
	__raw_writel(pmc_l_freqs[PMC_PSTATEVAL_REG2].driver_data,
					pmc_cbase + reg_addr);
	reg_addr = s2_reg_to_addr(PMC_L_P_STATE_VALUE_3_REG, policy->cpu);
	__raw_writel(pmc_l_freqs[PMC_PSTATEVAL_REG3].driver_data,
					pmc_cbase + reg_addr);

	/* Get boot's frequency, that was set up by jumpers */
	policy->cur = pmc_l_freqs[PMC_PSTATEVAL_REG0].frequency;

	if (bfs_bypass_val & HB_BFS_BYPASS_MASK) {
		/*
		 *  The code below should be used for bypass mode,
		 *  but nowdays there is no any R2000 with working bypass
		 */
#if 0
		result = cpufreq_table_validate_and_show(policy, pmc_l_freqs);
		if (result) {
			pr_err("%s: invalid frequency table: %d\n", __func__, result);
		}
		policy->cpuinfo.transition_latency = S2_TRANSITION_LATENCY;
#endif
		return -ENODEV;
	} else {
		/*
		 *  We can't use cpufreq_generic_init on R2000, its only for SMP
		 *  with same frequency on cores, so let's do init explictly
		 */
#if 0
		result = cpufreq_table_validate_and_show(policy, pmc_l_available_freqs);
		if (result) {
			pr_err("%s: invalid frequency table: %d\n", __func__, result);
		}
#endif
		result = cpufreq_frequency_table_cpuinfo(policy, pmc_l_available_freqs);
		if (result) {
			pr_err("%s: invalid frequency table: %d\n", __func__, result);
			return result;
		}
		policy->freq_table = pmc_l_available_freqs;
		policy->cpuinfo.transition_latency = S2_TRANSITION_LATENCY;
	}
	return result;
}
#endif /* CONFIG_CPU_FREQ */
