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

#ifdef CONFIG_E90S
#include <asm/e90s.h>
#endif

#include "pmc.h"

#undef DEBUG_PMC
#undef DebugPMC
#define DEBUG_PMC 0
#if DEBUG_PMC
#define DebugPMC(...) pr_debug(##__VA_ARGS__)
#else /* DEBUG_PMC */
#define DebugPMC(...) do {} while (0)
#endif /* DEBUG_PMC */


/*******/
void __iomem *pmc_cbase; /*Global for e1cp*/

#ifndef CONFIG_E90S /* E2K */
struct l_pmc l_pmc[MAX_NUM_PMCS];
#endif

#ifdef CONFIG_E90S
void __iomem *__pmc_regs(int node)
{
	node = node >= 0 ? node : 0;
	return (void *)(BASE_NODE0 +
				(BASE_NODE1 - BASE_NODE0) * node + 0x9000);
}
#else /* E2K */
void __iomem *__pmc_regs(int node)
{
	return pmc_cbase;
}
#endif /* CONFIG_E90S */

#ifdef CONFIG_CPU_FREQ
static int pmc_l_cpufreq_exit(struct cpufreq_policy *policy);

#ifndef CONFIG_E90S /* E2K */
/* cpufreq subsystem: */
struct cpufreq_frequency_table pmc_l_3d_clkSh_freqs[E1CP_MAX_PSTATES];
struct cpufreq_frequency_table pmc_l_3d_clk1x_freqs[E1CP_MAX_PSTATES];
/* available frequencies */
struct cpufreq_frequency_table
			pmc_l_3d_clk1x_available_freqs[E1CP_MAX_AV_PSTATES];
struct cpufreq_frequency_table
			pmc_l_3d_clkSh_available_freqs[E1CP_MAX_AV_PSTATES];
#endif

int pmc_l_calc_freq_tables(struct cpufreq_policy *policy,
					unsigned int cfgclksys)
{
	unsigned int Fbfs, Fboot, Fcpu;
	unsigned int boots_fid, fid;
	unsigned int Mii_inv, Nii;
	int idx = 0;
#ifndef CONFIG_E90S
	struct device *cpu_dev;
	struct dev_pm_opp *opp;
	int idx_3d_clk1x = 0;
	int idx_3d_clkSh = 0;

	cpu_dev = get_cpu_device(policy->cpu);
#endif /* CONFIG_E90S */
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

#ifndef CONFIG_E90S
		if (dev_pm_opp_get_opp_count(cpu_dev) > 0) {
			opp = dev_pm_opp_find_freq_exact(cpu_dev, Fcpu * 1000000, true);
			if (IS_ERR(opp)) {
				continue;
			}
		}
#endif

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

#ifndef CONFIG_E90S /* E1CP GPU */
		if (
		Fcpu <= E1CP_MAX_3D_CLK1X_FREQ && Fcpu >= E1CP_MIN_3D_CLK1X_FREQ
		&& ((idx_3d_clk1x > 0 && (Fcpu * 1000) <
			pmc_l_3d_clk1x_available_freqs[idx_3d_clk1x-1].frequency) || idx_3d_clk1x == 0)
		&& idx_3d_clk1x < E1CP_MAX_AV_ID) {
			pmc_l_3d_clk1x_available_freqs[idx_3d_clk1x].driver_data = fid;
			pmc_l_3d_clk1x_available_freqs[idx_3d_clk1x].frequency =
								Fcpu * 1000;
			idx_3d_clk1x++;
		}

		if (
		Fcpu <= E1CP_MAX_3D_CLKSH_FREQ && Fcpu >= E1CP_MIN_3D_CLKSH_FREQ
		&& ((idx_3d_clkSh > 0 && (Fcpu * 1000) <
			pmc_l_3d_clkSh_available_freqs[idx_3d_clkSh-1].frequency) || idx_3d_clkSh == 0)
		&& idx_3d_clkSh < E1CP_MAX_AV_ID) {
			pmc_l_3d_clkSh_available_freqs[idx_3d_clkSh].driver_data = fid;
			pmc_l_3d_clkSh_available_freqs[idx_3d_clkSh].frequency =
								Fcpu * 1000;
			idx_3d_clkSh++;
		}
#endif /* CONFIG_E90S */
	}

	pmc_l_available_freqs[idx].driver_data = 0;
	pmc_l_available_freqs[idx].frequency = CPUFREQ_TABLE_END;
#ifndef CONFIG_E90S /* E1CP GPU */
	pmc_l_3d_clk1x_available_freqs[idx_3d_clk1x].driver_data = 0;
	pmc_l_3d_clk1x_available_freqs[idx_3d_clk1x].frequency =
							CPUFREQ_TABLE_END;
	pmc_l_3d_clkSh_available_freqs[idx_3d_clkSh].driver_data = 0;
	pmc_l_3d_clkSh_available_freqs[idx_3d_clkSh].frequency =
							CPUFREQ_TABLE_END;
#endif /* CONFIG_E90S */

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

#ifndef CONFIG_E90S /* E1CP GPU */
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
#endif /* CONFIG_E90S */
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


static unsigned int pmc_l_cpufreq_resolve_freq(struct cpufreq_policy *policy,
						unsigned int target_freq)
{
	unsigned int resolved_freq;
	int index;

	index = cpufreq_frequency_table_target(policy, target_freq,
						CPUFREQ_RELATION_L);
	if (index < 0) {
		pr_err("%s: returned frequency index is %d.\n",
					__func__, index);
		return index;
	}

	resolved_freq = policy->freq_table[index].frequency;
	policy->cached_target_freq = resolved_freq;

	return resolved_freq;
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
#ifndef CONFIG_E90S /* E2K */
	unsigned long volt = 0;
	struct dev_pm_opp *opp;
	int ret = 0;
	struct device *cpu_dev;
#endif

	/*  Select fequency from pmc_l_available_freqs only when bfs is disabled.
	 *  In other case (bfs) - use only fixed values of FIDs, determined
	 *  in pmc_l_freq table during init.
	 */
	if (bfs_bypass_val & HB_BFS_BYPASS_MASK) { /* use pmc_l_freqs here */
		if (policy->freq_table != pmc_l_freqs) { /* switch tables */

			pr_err("%s: policy->freq_table is supposed "
				"to be set properly already. Has bfs_bypass_val"
				" changed since it was initialized?\n",
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

		newstate = cpufreq_frequency_table_target(policy,
						target_freq, relation);
		if (newstate < 0)
			return newstate;

		freqs.new = pmc_l_freqs[newstate].frequency;
	} else { /* use pmc_l_available_freqs table here */
		if (policy->freq_table != pmc_l_available_freqs) { /* switch */

			pr_err("%s: policy->freq_table is supposed "
				"to be set properly already. Has bfs_bypass_val"
				" changed since it was initialized?\n",
								 __func__);

			/* Use cpufreq_generic_init() here: see above */
			cpufreq_generic_init(policy, pmc_l_available_freqs,
				PMC_TRANSITION_LATENCY);
		}

		newstate = cpufreq_frequency_table_target(policy,
						target_freq, relation);
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


#ifndef CONFIG_E90S /* E2K */
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
#endif

	/* One PMC, many CPUs */
	for_each_cpu(i, policy->cpus) {
		if (!cpu_online(i))
			continue;
		cpufreq_freq_transition_begin(policy, &freqs);
		pmc_l_cpufreq_set_state(newstate, policy->cpu); /* Can't catch a failure */
		cpufreq_freq_transition_end(policy, &freqs, 0); /* here */
	}

#ifndef CONFIG_E90S /* E2K */
	if ((volt > 0) && (freqs.new < freqs.old)) {
		ret = regulator_set_voltage_tol(
			vout_regulator, volt, 0);
	}
#endif

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
	.resolve_freq	= pmc_l_cpufreq_resolve_freq,
	.exit		= pmc_l_cpufreq_exit,
	.get		= pmc_l_cpufreq_get,
	.name		= "pmc_l_cpufreq",
	.attr		= pmc_l_cpufreq_attr,
};

#endif /* CONFIG_CPU_FREQ */


#ifndef CONFIG_E90S
static int get_pmc_cbase(void)
{
	int result = -ENODEV;
	struct pci_dev *pdev = NULL;
	unsigned long covfid_status;

	struct resource r[] = {
		{
			.flags	= IORESOURCE_MEM,
			.start	= PMC_I2C_REGS_BASE,
			.end	= PMC_I2C_REGS_BASE + 0x20 - 1
		},
	};
	struct l_i2c2_platform_data pmc_i2c = {
		.bus_nr	         = -1,
		.base_freq_hz    = 100 * 1000 * 1000,
		.desired_freq_hz = 100 * 1000,
	};

	pdev = pci_get_device(PCI_VENDOR_ID_MCST_TMP,
				PCI_DEVICE_ID_MCST_HB,
				pdev);
	if (!pdev)
		return result;

	result = pci_enable_device_mem(pdev);

	if (result) {
		pci_dev_put(pdev);
		pr_err("pmc_init:"
				" failed to enable pci mem device\n");
		return result;
	}

	l_pmc[0].cntrl_base = pci_iomap(pdev, E1CP_PMC_BAR, 0);
	l_pmc[0].pdev = pdev;

	pr_err("pmc_init: l_pmc[0]=%p", &l_pmc[0]);
	pr_err("pmc_init: l_pmc[0].cntrl_base=%p\n",
							l_pmc[0].cntrl_base);

	pmc_cbase = l_pmc[0].cntrl_base;

	covfid_status = __raw_readl(pmc_cbase + PMC_L_COVFID_STATUS_REG);
	pr_err("pmc_init: covfid_status_lo = %lx\n",
								covfid_status);

	/* Initialize I2C master */
	r[0].start += pci_resource_start(pdev, E1CP_PMC_BAR);
	r[0].end   += pci_resource_start(pdev, E1CP_PMC_BAR);

	l_pmc[0].i2c_chan  =
		platform_device_register_resndata(&l_pmc[0].pdev->dev,
				"pmc-i2c", PLATFORM_DEVID_AUTO, r,
				ARRAY_SIZE(r),
				&pmc_i2c, sizeof(pmc_i2c));
	if (l_pmc[0].i2c_chan == NULL) {
		pr_err("pmc_init:"
				" failed to initialize pmc_i2c master\n");
	}

	return result;
}
#endif

static int __init pmc_init(void)
{
	int res = 0;
#ifdef CONFIG_E90S
	int node;
	unsigned int node_cfg_info[MAX_NUMNODES] = {0};
#endif

#ifdef CONFIG_E90S
	if (e90s_get_cpu_type() != E90S_CPU_R2000) {
		return 0;
	}
	/* Check configurations of nodes and exit if it differs */
	for_each_online_node(node) {
		node_cfg_info[node] = nbsr_readl(NBSR_NODE_CFG_INFO, node);
		DebugPMC("node=%d cfg = 0x%x\n", node, node_cfg_info[node]);
		if (node > 0 && node_cfg_info[node] != node_cfg_info[0]) {
			DebugPMC("s2_pmc_init error: \
				(node_cfg_info[%d] = 0x%x) !=   \
				(node_cfg_info[0] = 0x%x)",    \
				 node, node_cfg_info[node],   \
				 node_cfg_info[0]);
			WARN_ON(1);
			return -ENODEV;
		}
	}

	bfs_bypass_val = node_cfg_info[0];
#else
	res = get_pmc_cbase();
	if (res) {
		pr_err("PMC: failed to get pmc_cbase err = %d\n", res);
		return res;
	}
#endif

#ifdef CONFIG_CPU_FREQ
	res = cpufreq_register_driver(&pmc_l_cpufreq_driver);
	if (res) {
		pr_err("PMC: failed to register cpufreq err = %d\n", res);
		return res;
	}
#endif
	res = pmc_temp_sensors_init();
	if (res) {
		pr_err("PMC: failed to init temp sensors err = %d\n", res);
		return res;
	}
	res = pmc_hwmon_init();
	if (res) {
		pr_err("PMC: failed to hwmon err = %d\n", res);
		return res;
	}
	return res;
}

#ifdef CONFIG_CPU_FREQ
static int pmc_l_cpufreq_exit(struct cpufreq_policy *policy)
{
#ifndef CONFIG_E90S /* E2K */
	pmc_cbase = NULL;
#endif
	return 0;
}
#endif

static void __exit pmc_exit(void)
{
#ifdef CONFIG_E90S
	if (e90s_get_cpu_type() != E90S_CPU_R2000) {
		return;
	}
#endif
	pmc_hwmon_exit();

#ifdef CONFIG_CPU_FREQ
	pmc_temp_sensors_exit();

	cpufreq_unregister_driver(&pmc_l_cpufreq_driver);

#ifndef CONFIG_E90S /* E2K */
	regulator_put(vout_regulator);
#endif
#endif
#ifndef CONFIG_E90S /* E2K */
	if (l_pmc[0].i2c_chan) {
		platform_device_unregister(l_pmc[0].i2c_chan);
		l_pmc[0].i2c_chan = NULL;
	}

	pci_dev_put(l_pmc[0].pdev);
	l_pmc[0].pdev = NULL;
#endif
}

module_init(pmc_init);
module_exit(pmc_exit);

MODULE_AUTHOR("MCST");
MODULE_DESCRIPTION("PMC driver. For E1C+ and R2000");
MODULE_LICENSE("GPL v2");
MODULE_SOFTDEP("pre: max20730");
