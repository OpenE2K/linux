/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/cpu.h>
#include <linux/cpufreq.h>
#include <asm/io.h>
#include <linux/pci.h>
#include <linux/platform_data/i2c-l-i2c2.h>
#include <linux/pm_opp.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/regulator/consumer.h>
#include <asm/l_pmc.h>

#include "pmc.h"

#undef DEBUG_PMC
#undef DebugPMC
#define DEBUG_PMC 0
#if DEBUG_PMC
#define DebugPMC(...) pr_debug(##__VA_ARGS__)
#else /* DEBUG_PMC */
#define DebugPMC(...) do {} while (0)
#endif /* DEBUG_PMC */

/* cpufreq subsystem: */
struct cpufreq_frequency_table pmc_l_3d_clkSh_freqs[E1CP_MAX_PSTATES];
struct cpufreq_frequency_table pmc_l_3d_clk1x_freqs[E1CP_MAX_PSTATES];
/* available frequencies */
struct cpufreq_frequency_table
			pmc_l_3d_clk1x_available_freqs[E1CP_MAX_AV_PSTATES];
struct cpufreq_frequency_table
			pmc_l_3d_clkSh_available_freqs[E1CP_MAX_AV_PSTATES];

static struct thermal_cooling_device *cpufreq_cooling_device;


int pmc_l_calc_freq_tables(struct cpufreq_policy *policy,
					unsigned int cfgclksys)
{
	unsigned int Fbfs, Fboot, Fcpu;
	unsigned int boots_fid, fid;
	unsigned int Mii_inv, Nii;
	int idx = 0;
	struct device *cpu_dev;
	struct dev_pm_opp *opp;
	int idx_3d_clk1x = 0;
	int idx_3d_clkSh = 0;

	cpu_dev = get_cpu_device(policy->cpu);

	/* P-state 0 is taken from boot's jumper. */
	Fbfs = Fbfs(BASE_FREQ, cfgclksys);
	boots_fid =  pmc_reg_readl(PMC_L_P_STATE_VALUE_0_REG, policy->cpu);
	Mii_inv = Mii_inv(boots_fid);
	Nii = Nii(boots_fid);
	Fboot = Fcpu(Fbfs, Mii_inv, Nii);

	pmc_l_freqs[PMC_PSTATEVAL_REG0].frequency = Fboot * 1000;
	pmc_l_freqs[PMC_PSTATEVAL_REG0].driver_data = boots_fid;
	pr_debug("set pmc_l_freqs[PMC_PSTATEVAL_REG0]: FID 0x%x FREQ %u Mhz.\n",
		  pmc_l_freqs[PMC_PSTATEVAL_REG0].driver_data,
		  pmc_l_freqs[PMC_PSTATEVAL_REG0].frequency / 1000);

	WARN_ON(Fboot > MAX_FREQ);
	WARN_ON(Fboot < MIN_FREQ);

	for (fid = 0; fid <= 0xff; fid++) {
		Mii_inv = Mii_inv(fid);
		Nii = Nii(fid);


		if (Mii_inv == 0)
			continue;
		if (Nii < 8 || Nii > 32)
			continue;

		Fcpu = Fcpu(Fbfs, Mii_inv, Nii);

		if (dev_pm_opp_get_opp_count(cpu_dev) > 0) {
			opp = dev_pm_opp_find_freq_exact(cpu_dev, Fcpu * 1000000, true);
			if (IS_ERR(opp)) {
				continue;
			}
		}

		if (
		Fcpu <= Fboot && Fcpu >= MIN_FREQ
		&& ((idx > 0 && (Fcpu * 1000) <
			pmc_l_available_freqs[idx-1].frequency) || idx == 0)
		&& idx < MAX_AV_ID) {
			pmc_l_available_freqs[idx].driver_data = fid;
			pmc_l_available_freqs[idx].frequency = Fcpu * 1000;
			DebugPMC("Available freq [%d]: FID %d FREQ %u MHz\n",
				 idx,
				 pmc_l_available_freqs[idx].driver_data,
				 pmc_l_available_freqs[idx].frequency / 1000);
			idx++;
		}

		if (
		Fcpu <= E1CP_MAX_3D_CLK1X_FREQ && Fcpu >= E1CP_MIN_3D_CLK1X_FREQ
		&& ((idx_3d_clk1x > 0 && (Fcpu * 1000) <
			pmc_l_3d_clk1x_available_freqs[idx_3d_clk1x-1].frequency)
		|| idx_3d_clk1x == 0)

		&& idx_3d_clk1x < E1CP_MAX_AV_ID) {
			pmc_l_3d_clk1x_available_freqs[idx_3d_clk1x].driver_data = fid;
			pmc_l_3d_clk1x_available_freqs[idx_3d_clk1x].frequency =
								Fcpu * 1000;
			idx_3d_clk1x++;
		}

		if (
		Fcpu <= E1CP_MAX_3D_CLKSH_FREQ && Fcpu >= E1CP_MIN_3D_CLKSH_FREQ
		&& ((idx_3d_clkSh > 0 && (Fcpu * 1000) <
			pmc_l_3d_clkSh_available_freqs[idx_3d_clkSh-1].frequency)
		|| idx_3d_clkSh == 0)

		&& idx_3d_clkSh < E1CP_MAX_AV_ID) {
			pmc_l_3d_clkSh_available_freqs[idx_3d_clkSh].driver_data = fid;
			pmc_l_3d_clkSh_available_freqs[idx_3d_clkSh].frequency =
								Fcpu * 1000;
			idx_3d_clkSh++;
		}
	}

	pmc_l_available_freqs[idx].driver_data = 0;
	pmc_l_available_freqs[idx].frequency = CPUFREQ_TABLE_END;
	pmc_l_3d_clk1x_available_freqs[idx_3d_clk1x].driver_data = 0;
	pmc_l_3d_clk1x_available_freqs[idx_3d_clk1x].frequency =
							CPUFREQ_TABLE_END;
	pmc_l_3d_clkSh_available_freqs[idx_3d_clkSh].driver_data = 0;
	pmc_l_3d_clkSh_available_freqs[idx_3d_clkSh].frequency =
							CPUFREQ_TABLE_END;

	BUG_ON(idx == 0);

	pmc_l_freqs[PMC_PSTATEVAL_REG1].driver_data =
			pmc_l_available_freqs[idx / 3].driver_data;
	pmc_l_freqs[PMC_PSTATEVAL_REG1].frequency =
			pmc_l_available_freqs[idx / 3].frequency;
	pr_debug("set pmc_l_freqs[PMC_PSTATEVAL_REG1]: [idx %d] FID 0x%x FREQ %u KHz.\n",
		  idx / 3,
		  pmc_l_freqs[PMC_PSTATEVAL_REG1].driver_data,
		  pmc_l_freqs[PMC_PSTATEVAL_REG1].frequency);

	pmc_l_freqs[PMC_PSTATEVAL_REG2].driver_data =
			pmc_l_available_freqs[(idx * 2) / 3].driver_data;
	pmc_l_freqs[PMC_PSTATEVAL_REG2].frequency =
			pmc_l_available_freqs[(idx * 2) / 3].frequency;
	pr_debug("set pmc_l_freqs[PMC_PSTATEVAL_REG2]: [idx %d] FID 0x%x FREQ %u KHz.\n",
		  (idx * 2) / 3,
		  pmc_l_freqs[PMC_PSTATEVAL_REG2].driver_data,
		  pmc_l_freqs[PMC_PSTATEVAL_REG2].frequency);

	pmc_l_freqs[PMC_PSTATEVAL_REG3].driver_data =
			pmc_l_available_freqs[idx - 1].driver_data;
	pmc_l_freqs[PMC_PSTATEVAL_REG3].frequency =
			pmc_l_available_freqs[idx - 1].frequency;
	pr_debug("set pmc_l_freqs[PMC_PSTATEVAL_REG3]: [idx %d] FID 0x%x FREQ %u KHz.\n",
		  idx - 1,
		  pmc_l_freqs[PMC_PSTATEVAL_REG3].driver_data,
		  pmc_l_freqs[PMC_PSTATEVAL_REG3].frequency);

	pmc_l_freqs[MAX_PSTATES - 1].driver_data = 0;
	pmc_l_freqs[MAX_PSTATES - 1].frequency = CPUFREQ_TABLE_END;

	pmc_l_3d_clk1x_freqs[PMC_PSTATEVAL_REG0].driver_data =
			pmc_l_3d_clk1x_available_freqs[0].driver_data;
	pmc_l_3d_clk1x_freqs[PMC_PSTATEVAL_REG0].frequency =
			pmc_l_3d_clk1x_available_freqs[0].frequency;
	pmc_l_3d_clk1x_freqs[PMC_PSTATEVAL_REG1].driver_data =
			pmc_l_3d_clk1x_available_freqs[(idx_3d_clk1x / 3)].driver_data;
	pmc_l_3d_clk1x_freqs[PMC_PSTATEVAL_REG1].frequency =
			pmc_l_3d_clk1x_available_freqs[(idx_3d_clk1x / 3)].frequency;
	pmc_l_3d_clk1x_freqs[PMC_PSTATEVAL_REG2].driver_data =
			pmc_l_3d_clk1x_available_freqs[(idx_3d_clk1x / 3) * 2].driver_data;
	pmc_l_3d_clk1x_freqs[PMC_PSTATEVAL_REG2].frequency =
			pmc_l_3d_clk1x_available_freqs[(idx_3d_clk1x / 3) * 2].frequency;
	pmc_l_3d_clk1x_freqs[PMC_PSTATEVAL_REG3].driver_data =
			pmc_l_3d_clk1x_available_freqs[(idx_3d_clk1x - 1)].driver_data;
	pmc_l_3d_clk1x_freqs[PMC_PSTATEVAL_REG3].frequency =
			pmc_l_3d_clk1x_available_freqs[(idx_3d_clk1x - 1)].frequency;
	pmc_l_3d_clk1x_freqs[E1CP_MAX_PSTATES - 1].driver_data = 0;
	pmc_l_3d_clk1x_freqs[E1CP_MAX_PSTATES - 1].frequency = CPUFREQ_TABLE_END;

	pmc_l_3d_clkSh_freqs[PMC_PSTATEVAL_REG0].driver_data =
			pmc_l_3d_clkSh_available_freqs[0].driver_data;
	pmc_l_3d_clkSh_freqs[PMC_PSTATEVAL_REG0].frequency =
			pmc_l_3d_clkSh_available_freqs[0].frequency;
	pmc_l_3d_clkSh_freqs[PMC_PSTATEVAL_REG1].driver_data =
			pmc_l_3d_clkSh_available_freqs[(idx_3d_clkSh / 3)].driver_data;
	pmc_l_3d_clkSh_freqs[PMC_PSTATEVAL_REG1].frequency =
			pmc_l_3d_clkSh_available_freqs[(idx_3d_clkSh / 3)].frequency;
	pmc_l_3d_clkSh_freqs[PMC_PSTATEVAL_REG2].driver_data =
			pmc_l_3d_clkSh_available_freqs[(idx_3d_clkSh / 3) * 2].driver_data;
	pmc_l_3d_clkSh_freqs[PMC_PSTATEVAL_REG2].frequency =
			pmc_l_3d_clkSh_available_freqs[(idx_3d_clkSh / 3) * 2].frequency;
	pmc_l_3d_clkSh_freqs[PMC_PSTATEVAL_REG3].driver_data =
			pmc_l_3d_clkSh_available_freqs[(idx_3d_clkSh - 1)].driver_data;
	pmc_l_3d_clkSh_freqs[PMC_PSTATEVAL_REG3].frequency =
			pmc_l_3d_clkSh_available_freqs[(idx_3d_clkSh - 1)].frequency;
	pmc_l_3d_clkSh_freqs[E1CP_MAX_PSTATES - 1].driver_data = 0;
	pmc_l_3d_clkSh_freqs[E1CP_MAX_PSTATES - 1].frequency = CPUFREQ_TABLE_END;
	return 0;
}


static int pmc_l_cpufreq_get_state(unsigned int cpu)
{
	unsigned int state = 0;

	state = pmc_reg_readl(PMC_L_P_STATE_CNTRL_REG, cpu);
	DebugPMC("PMC_L_P_STATE_CNTRL_REG=0x%x\n", state);
	state >>= PMC_L_P_STATE_CNTRL_SHIFT;
	state &= PMC_L_P_STATE_CNTRL_MASK;
	DebugPMC("state=0x%x\n", state);

	return state;
}

static void pmc_l_cpufreq_set_state(unsigned int state, unsigned int cpu)
{
	unsigned int st = (state << PMC_L_P_STATE_CNTRL_SHIFT) &
				PMC_L_P_STATE_CNTRL_MASK;
	DebugPMC("state=0x%x st=0x%x\n", state, st);
	pmc_reg_writel(st, PMC_L_P_STATE_CNTRL_REG, cpu);
}
static void pmc_l_cpufreq_update_state_reg(unsigned int state,
				 unsigned int fid, unsigned int cpu)
{
	if (state == PMC_PSTATEVAL_REG0) {
		pmc_reg_writel(fid, PMC_L_P_STATE_VALUE_0_REG, cpu);
	} else if (state == PMC_PSTATEVAL_REG1) {
		pmc_reg_writel(fid, PMC_L_P_STATE_VALUE_1_REG, cpu);
	} else if (state == PMC_PSTATEVAL_REG2) {
		pmc_reg_writel(fid, PMC_L_P_STATE_VALUE_2_REG, cpu);
	} else if (state == PMC_PSTATEVAL_REG3) {
		pmc_reg_writel(fid, PMC_L_P_STATE_VALUE_3_REG, cpu);
	}
}

static unsigned int pmc_l_cpufreq_get(unsigned int cpu)
{
	return pmc_l_freqs[pmc_l_cpufreq_get_state(cpu)].frequency;
}

/**
 * pmc_l_cpufreq_verify_policy - verifies a new CPUFreq policy
 * @policy: new policy
 *
 * Limit must be within low_freq and high_freq, with at least
 * one border included.
 */
static int pmc_l_cpufreq_verify_policy(struct cpufreq_policy_data *policy)
{
	return cpufreq_frequency_table_verify(policy, pmc_l_freqs);
}


/**
 * pmc_l_cpufreq_set_target - set a new CPUFreq policy
 * @policy: new policy
 * @target_freq: new freq
 * @relation:
 *
 * Sets a new CPUFreq policy/freq.
 */
static int pmc_l_cpufreq_set_target(struct cpufreq_policy *policy,
				unsigned int target_freq, unsigned int relation)
{
	int ii = 0;
	unsigned int i;
	unsigned int newstate = 0;
	int ffound = 0;
	struct cpufreq_freqs freqs;
	unsigned long volt = 0;
	struct dev_pm_opp *opp;
	int ret = 0;
	struct device *cpu_dev;
	struct regulator *vout_regulator = (struct regulator *)policy->driver_data;

	/*  Select fequency from pmc_l_available_freqs only when bfs is disabled.
	 *  In other case (bfs) - use only fixed values of FIDs, determined
	 *  in pmc_l_freq table during init.
	 */
	if (bfs_bypass_val & HB_BFS_BYPASS_MASK) { /* use pmc_l_freqs here */
		if (policy->freq_table != pmc_l_freqs) { /* switch tables */

			pr_err("%s: policy->freq_table is supposed to be set properly already. Has bfs_bypass_val changed since it was initialized?\n",
								 __func__);

			/* Use cpufreq_generic_init() here: it allows
			 *	to switch policy's frequency table
			 *	and transition latency at the same time
			 *	using cpufreq interface. We don't care about
			 *	setting all cpus in the policy's mask as we
			 *	check it's presence later with cpu_online()
			 *	anyway */
			cpufreq_generic_init(policy, pmc_l_freqs,
				PMC_TRANSITION_LATENCY);
		}

		newstate = cpufreq_frequency_table_target(policy, target_freq,
				policy->min, policy->max, relation);
		if (newstate < 0)
			return newstate;

		freqs.new = pmc_l_freqs[newstate].frequency;
	} else { /* use pmc_l_available_freqs table here */
		if (policy->freq_table != pmc_l_available_freqs) { /* switch */

			pr_err("%s: policy->freq_table is supposed to be set properly already. Has bfs_bypass_val changed since it was initialized?\n",
								 __func__);

			/* Use cpufreq_generic_init() here: see above */
			cpufreq_generic_init(policy, pmc_l_available_freqs,
				PMC_TRANSITION_LATENCY);
		}

		newstate = cpufreq_frequency_table_target(policy, target_freq,
					policy->min, policy->max, relation);
		if (newstate < 0)
			return newstate;

		freqs.new = pmc_l_available_freqs[newstate].frequency;
	}

	freqs.old = pmc_l_freqs[pmc_l_cpufreq_get_state(policy->cpu)].frequency;

	if (freqs.old == freqs.new)
		return 0;

	/*
	* 0) If bfs - skip 1) and 2) as newstate is valid.
	*/
	if (!(bfs_bypass_val & HB_BFS_BYPASS_MASK)) {

		/*
		* 1) Check if wanted frequency is in pmc_l_freqs: if so select
		*    index of state and update newstate.
		*/

		for (ii = 0; ii < PMC_MAX_STATES; ii++) {
			if (pmc_l_freqs[ii].frequency == freqs.new) {
				newstate = ii;
				ffound = 1;
				break;
			}
		}

		/*
		* 2) If frequency is not presented - userspace governor probably
		*    is used: update pmc_l_freqs table and PStateValueX reg,
		*    update newstate by index of updated entry.
		*/
		if (!ffound) {
			unsigned int fid;
			unsigned int idx;
			unsigned int delta1;
			unsigned int delta2;

			if (freqs.new >
						pmc_l_freqs[PMC_PSTATEVAL_REG0].frequency) {
				idx = PMC_PSTATEVAL_REG0;
			} else if (freqs.new <
						pmc_l_freqs[PMC_PSTATEVAL_REG3].frequency) {
				idx = PMC_PSTATEVAL_REG3;
			} else if (freqs.new <
						pmc_l_freqs[PMC_PSTATEVAL_REG0].frequency &&
						freqs.new >
						pmc_l_freqs[PMC_PSTATEVAL_REG1].frequency) {
				idx = PMC_PSTATEVAL_REG1;
			} else if (freqs.new <
						pmc_l_freqs[PMC_PSTATEVAL_REG2].frequency &&
						freqs.new >
						pmc_l_freqs[PMC_PSTATEVAL_REG3].frequency) {
				idx = PMC_PSTATEVAL_REG2;
			} else {
				delta1 = freqs.new -
				    pmc_l_freqs[PMC_PSTATEVAL_REG2].frequency;
				delta2 =
				    pmc_l_freqs[PMC_PSTATEVAL_REG1].frequency
								  - freqs.new;

				if (delta1 > delta2) {
					idx = PMC_PSTATEVAL_REG1;
				} else {
					idx = PMC_PSTATEVAL_REG2;
				}
			}

			pmc_l_freqs[idx].frequency = freqs.new;
			fid = pmc_l_available_freqs[newstate].driver_data;
			pmc_l_freqs[idx].driver_data = fid;
			newstate = idx;
			pmc_l_cpufreq_update_state_reg(newstate, fid, policy->cpu);

#if 0
			/* TODO: This function is non-exported */
			cpufreq_frequency_table_cpuinfo(policy, pmc_l_freqs);
#endif
		}
	}


	if (vout_regulator) {
		cpu_dev = get_cpu_device(policy->cpu);

		opp = dev_pm_opp_find_freq_exact(
			cpu_dev, freqs.new * 1000, true);

		if (IS_ERR(opp)) {
			opp = NULL;
		} else {
			volt = dev_pm_opp_get_voltage(opp);
			dev_pm_opp_put(opp);
		}
	}

	if ((volt > 0) && (freqs.new > freqs.old)) {
		ret = regulator_set_voltage_tol(
			vout_regulator, volt, 0);
	}

	/* One PMC, many CPUs */
	for_each_cpu(i, policy->cpus) {
		if (!cpu_online(i))
			continue;
		cpufreq_freq_transition_begin(policy, &freqs);
		pmc_l_cpufreq_set_state(newstate, policy->cpu); /* Can't catch a failure */
		cpufreq_freq_transition_end(policy, &freqs, 0); /* here */
	}

	if ((volt > 0) && (freqs.new < freqs.old)) {
		ret = regulator_set_voltage_tol(
			vout_regulator, volt, 0);
	}

	return 0;
}


static struct freq_attr *pmc_l_cpufreq_attr[] = {
	&cpufreq_freq_attr_scaling_available_freqs,
	NULL,
};

struct cpufreq_driver pmc_l_cpufreq_driver = {
	.init		= pmc_l_cpufreq_init,
	.verify		= pmc_l_cpufreq_verify_policy,
	.target		= pmc_l_cpufreq_set_target,
	.get		= pmc_l_cpufreq_get,
	.name		= "pmc_l_cpufreq",
	.attr		= pmc_l_cpufreq_attr,
};

static struct cpufreq_policy *pmc_cpufreq_policy;

int pmc_cpufreq_init(void)
{
	int res = 0;

	res = cpufreq_register_driver(&pmc_l_cpufreq_driver);
	if (res)
		pr_err("PMC: failed to register cpufreq err = %d\n", res);

	pmc_cpufreq_policy = cpufreq_cpu_get(cpumask_first(cpu_online_mask));

	if (!pmc_cpufreq_policy) {
		pr_err("CPUFreq policy not found\n");
		return -EPROBE_DEFER;
	}

	cpufreq_cooling_device = cpufreq_cooling_register(pmc_cpufreq_policy);

	return res;
}

void pmc_cpufreq_exit(void)
{

	cpufreq_cooling_unregister(cpufreq_cooling_device);
	cpufreq_cpu_put(pmc_cpufreq_policy);
	cpufreq_unregister_driver(&pmc_l_cpufreq_driver);

}
