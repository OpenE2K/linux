/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * PMC (Power Management Controller) for e2k (E1CP)
 */

#define pr_fmt(fmt) "%s: " fmt, __func__

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/cpufreq.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/smp.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/cpuidle.h>
#include <linux/io.h>
#include <linux/i2c.h>
#include <linux/cpumask.h>
#include <linux/sysfs.h>
#include <linux/irq.h>
#include <linux/node.h>
#include <linux/cpu.h>
#include <linux/platform_device.h>
#include <linux/pm_opp.h>
#include <linux/regulator/consumer.h>

#ifdef CONFIG_CPU_FREQ

#include <asm/pci.h>
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


unsigned int bfs_bypass_val;
static unsigned int gpu_scale;

/* global cpufreq subsystem: */
struct cpufreq_frequency_table pmc_l_freqs[MAX_PSTATES];
/* global available frequencies */
struct cpufreq_frequency_table
			pmc_l_available_freqs[MAX_AV_PSTATES];

struct regulator *vout_regulator;

static int pmc_l_gpufreq_get_state(void)
{
	unsigned int state = 0;

	state = __raw_readl(pmc_cbase + PMC_L_P_STATE_3D_CNTRL_REG);

	state >>= PMC_L_P_STATE_3D_CNTRL_SHIFT;
	state &= PMC_L_P_STATE_3D_CNTRL_MASK;

	return state;
}

int pmc_l_gpufreq_get_scale(void)
{
	return gpu_scale;
}
EXPORT_SYMBOL(pmc_l_gpufreq_get_scale);

int pmc_l_gpufreq_get_frequency(void)
{
	int state = pmc_l_gpufreq_get_state();
	return pmc_l_3d_clk1x_freqs[state].frequency;
}
EXPORT_SYMBOL(pmc_l_gpufreq_get_frequency);

void pmc_l_gpufreq_set_state(unsigned int state)
{
	unsigned int st;

	st = (state << PMC_L_P_STATE_3D_CNTRL_SHIFT) &
				PMC_L_P_STATE_3D_CNTRL_MASK;

	__raw_writel(st, pmc_cbase + PMC_L_P_STATE_3D_CNTRL_REG);
}

static void pmc_l_gpufreq_update_state_reg(unsigned int state,
						 unsigned int fid_clk1x,
						 unsigned int fid_clkSh,
						 unsigned int target)
{
/* Here we want to write fid to both FID1 and FID2 */
	if (target & PMC_L_TARGET_CLK1X)
		switch (state) {
		case PMC_PSTATEVAL_REG0:
			__raw_writel(fid_clk1x, pmc_cbase +
					PMC_L_P_STATE_3D_VALUE_0_REG);
			break;
		case PMC_PSTATEVAL_REG1:
			__raw_writel(fid_clk1x, pmc_cbase +
					PMC_L_P_STATE_3D_VALUE_1_REG);
			break;
		case PMC_PSTATEVAL_REG2:
			__raw_writel(fid_clk1x, pmc_cbase +
					PMC_L_P_STATE_3D_VALUE_2_REG);
			break;
		case PMC_PSTATEVAL_REG3:
			__raw_writel(fid_clk1x, pmc_cbase +
					PMC_L_P_STATE_3D_VALUE_3_REG);
			break;
		}
	if (target & PMC_L_TARGET_CLKSH)
		switch (state) {
		case PMC_PSTATEVAL_REG0:
			__raw_writel(fid_clkSh, pmc_cbase +
					PMC_L_P_STATE_3D_VALUE_0_REG+1);
			break;
		case PMC_PSTATEVAL_REG1:
			__raw_writel(fid_clkSh, pmc_cbase +
					PMC_L_P_STATE_3D_VALUE_1_REG+1);
			break;
		case PMC_PSTATEVAL_REG2:
			__raw_writel(fid_clkSh, pmc_cbase +
					PMC_L_P_STATE_3D_VALUE_2_REG+1);
			break;
		case PMC_PSTATEVAL_REG3:
			__raw_writel(fid_clkSh, pmc_cbase +
					PMC_L_P_STATE_3D_VALUE_3_REG+1);
			break;
		}
}

static int pmc_l_gpufreq_set_target(unsigned int target_clk1x_freq,
				unsigned int target_clkSh_freq,
				unsigned int relation)
{
	int ii = 0, j;
	unsigned int target_freq, transition_latency;
	unsigned int newstate, clk1x_newstate, clkSh_newstate;
	int ffound, clk1x_ffound, clkSh_ffound;
	struct cpufreq_frequency_table *target_table, *available_freqs;
	struct cpufreq_freqs freqs, clk1x_freqs = {}, clkSh_freqs;
	struct cpufreq_policy policy;

	newstate = 0; clk1x_newstate = 0; clkSh_newstate = 0;
	ffound = 0; clk1x_ffound = 0; clkSh_ffound = 0;
	policy.cpu = 0; /* This value is used only for debug output
	in cpufreq_frequency_table_target(). So it's not so awful
	if we just don't care. */
	policy.min = E1CP_MIN_FREQ * 1000;
	policy.max = E1CP_MAX_FREQ * 1000;

	/* Select fequency from pmc_l_available_freqs only when bfs is disabled.
	*  In other case (bfs) - use only fixed values of FIDs, determined
	*  in pmc_l_3d_freq table during init.
	*/

	for (j = 0; j < 2; j++) {
		if (!j) {
			target_table = pmc_l_3d_clk1x_freqs;
			available_freqs = pmc_l_3d_clk1x_available_freqs;
			target_freq = target_clk1x_freq;
			transition_latency = E1CP_TRANSITION_LATENCY;
		} else {
			target_table = pmc_l_3d_clkSh_freqs;
			available_freqs = pmc_l_3d_clkSh_available_freqs;
			target_freq = target_clkSh_freq;
			transition_latency = E1CP_TRANSITION_LATENCY;
		}

		if (bfs_bypass_val & HB_BFS_BYPASS_MASK) { /* target_table */

			policy.freq_table = target_table;
			policy.cpuinfo.transition_latency = transition_latency;
			newstate = cpufreq_frequency_table_target(&policy,
							target_freq, relation);
			if (newstate < 0)
				return newstate;

			freqs.new = target_table[newstate].frequency;
		} else { /* available_freqs table */

			policy.freq_table = available_freqs;
			policy.cpuinfo.transition_latency = transition_latency;
			newstate = cpufreq_frequency_table_target(&policy,
							target_freq, relation);
			if (newstate < 0)
				return newstate;

			freqs.new = available_freqs[newstate].frequency;
		}

		freqs.old = target_table[pmc_l_gpufreq_get_state()].frequency;

		/*
		* 0) If bfs - skip 1) and 2) as newstate is valid.
		*/
		if (!(bfs_bypass_val & HB_BFS_BYPASS_MASK)) {

			/*
			* 1) Check if wanted frequency is in target_table: if so select
			*    index of state and update newstate.
			*/

			for (ii = 0; ii < PMC_MAX_STATES; ii++) {
				if (target_table[ii].frequency == freqs.new) {
					newstate = ii;
					ffound = 1;
					break;
				}
			}
		}

		if (!j) {
			clk1x_freqs.old = freqs.old;
			clk1x_freqs.new = freqs.new;
			clk1x_ffound = ffound;
			clk1x_newstate = newstate;
		} else {
			clkSh_freqs.old = freqs.old;
			clkSh_freqs.new = freqs.new;
			clkSh_ffound = ffound;
			clkSh_newstate = newstate;
		}
	}

	if (clk1x_freqs.old == clk1x_freqs.new &&
			clkSh_freqs.old == clkSh_freqs.new)
		return 0;

	/*
	* 2) If frequency is not presented - userspace governor probably
	*    is used: update target_table table and PStateValueX reg,
	*    update newstate by index of updated entry.
	*/
	if (!(clk1x_ffound || clkSh_ffound)) {
		unsigned int clk1x_fid;
		unsigned int clkSh_fid;
		unsigned int idx;
		unsigned int delta1;
		unsigned int delta2;

		target_table = pmc_l_3d_clk1x_freqs;
		freqs.new = clk1x_freqs.new;
		freqs.old = clk1x_freqs.old;

		if (freqs.new >
			target_table[PMC_PSTATEVAL_REG0].frequency) {
			    idx = PMC_PSTATEVAL_REG0;
		} else if (freqs.new <
			target_table[PMC_PSTATEVAL_REG3].frequency) {
			    idx = PMC_PSTATEVAL_REG3;
		} else if (freqs.new <
			target_table[PMC_PSTATEVAL_REG0].frequency &&
			freqs.new >
			target_table[PMC_PSTATEVAL_REG1].frequency) {
			    idx = PMC_PSTATEVAL_REG1;
		} else if (freqs.new <
			target_table[PMC_PSTATEVAL_REG2].frequency &&
			freqs.new >
			target_table[PMC_PSTATEVAL_REG3].frequency) {
			    idx = PMC_PSTATEVAL_REG2;
		} else {
			delta1 = freqs.new -
			    target_table[PMC_PSTATEVAL_REG2].frequency;
			delta2 =
			    target_table[PMC_PSTATEVAL_REG1].frequency
							  - freqs.new;

			if (delta1 > delta2) {
				idx = PMC_PSTATEVAL_REG1;
			} else {
				idx = PMC_PSTATEVAL_REG2;
			}
		}

		target_table[idx].frequency = freqs.new;
		clk1x_fid = pmc_l_3d_clk1x_available_freqs[clk1x_newstate].driver_data;
		clkSh_fid = pmc_l_3d_clkSh_available_freqs[clkSh_newstate].driver_data;
		newstate = idx;
		pmc_l_gpufreq_update_state_reg(newstate, clk1x_fid,
			clkSh_fid, PMC_L_TARGET_CLK1X | PMC_L_TARGET_CLKSH);
	} else {
		unsigned int clk1x_fid;
		unsigned int clkSh_fid;
		if (clkSh_ffound) {
			newstate = clkSh_newstate;
			if (!clk1x_ffound)
				clk1x_fid = pmc_l_3d_clk1x_available_freqs[clk1x_newstate].driver_data;
			else
				clk1x_fid = pmc_l_3d_clk1x_freqs[clk1x_newstate].driver_data;
			pmc_l_gpufreq_update_state_reg(newstate, clk1x_fid, 0, PMC_L_TARGET_CLK1X);
		} else {
			newstate = clk1x_newstate;
			clkSh_fid = pmc_l_3d_clkSh_available_freqs[clkSh_newstate].driver_data;
			pmc_l_gpufreq_update_state_reg(newstate, 0, clkSh_fid, PMC_L_TARGET_CLKSH);
		}
	}
	/* should we notify anyone here about this trainsition? */
	pmc_l_gpufreq_set_state(newstate);
	return 0;
}

/* pmc_l_gpufreq_set_scale - set GPU frequency according to @scale
 * @scale - a real number <1 - 64>
 */
int pmc_l_gpufreq_set_scale(unsigned char scale)
{
	unsigned int target_clk1x_freq, target_clkSh_freq;
	gpu_scale = scale;
	/* A convertation from @scale to an actual (approximate)
	 * frequency.
	 */
	target_clk1x_freq = (1000 * E1CP_MIN_3D_CLK1X_FREQ) +
		((E1CP_MAX_3D_CLK1X_FREQ - E1CP_MIN_3D_CLK1X_FREQ) * 1000 * (scale - 1)) / 63;
	target_clkSh_freq = (1000 * E1CP_MIN_3D_CLKSH_FREQ) +
		((E1CP_MAX_3D_CLKSH_FREQ - E1CP_MIN_3D_CLKSH_FREQ) * 1000 * (scale - 1)) / 63;
	return pmc_l_gpufreq_set_target(target_clk1x_freq, target_clkSh_freq,
								 CPUFREQ_RELATION_L);
}
EXPORT_SYMBOL(pmc_l_gpufreq_set_scale);

static int pmc_l_init_wa_freq_tables(void)
{
	pmc_l_freqs[PMC_PSTATEVAL_REG0].driver_data = E1CP_BYPASS_FID_P0;
	pmc_l_freqs[PMC_PSTATEVAL_REG0].frequency = PMC_L_FREQUENCY_1;
	pmc_l_freqs[PMC_PSTATEVAL_REG1].driver_data = E1CP_BYPASS_FID_P1;
	pmc_l_freqs[PMC_PSTATEVAL_REG1].frequency = PMC_L_FREQUENCY_2;
	pmc_l_freqs[PMC_PSTATEVAL_REG2].driver_data = E1CP_BYPASS_FID_P2;
	pmc_l_freqs[PMC_PSTATEVAL_REG2].frequency = PMC_L_FREQUENCY_3;
	pmc_l_freqs[PMC_PSTATEVAL_REG3].driver_data = E1CP_BYPASS_FID_P3;
	pmc_l_freqs[PMC_PSTATEVAL_REG3].frequency = PMC_L_FREQUENCY_4;
	pmc_l_freqs[E1CP_MAX_PSTATES - 1].driver_data = 0;
	pmc_l_freqs[E1CP_MAX_PSTATES - 1].frequency = CPUFREQ_TABLE_END;

	pmc_l_3d_clk1x_freqs[PMC_PSTATEVAL_REG0].driver_data = E1CP_BYPASS_FID_P0;
	pmc_l_3d_clk1x_freqs[PMC_PSTATEVAL_REG0].frequency = PMC_L_FREQUENCY_1;
	pmc_l_3d_clk1x_freqs[PMC_PSTATEVAL_REG1].driver_data = E1CP_BYPASS_FID_P1;
	pmc_l_3d_clk1x_freqs[PMC_PSTATEVAL_REG1].frequency = PMC_L_FREQUENCY_2;
	pmc_l_3d_clk1x_freqs[PMC_PSTATEVAL_REG2].driver_data = E1CP_BYPASS_FID_P2;
	pmc_l_3d_clk1x_freqs[PMC_PSTATEVAL_REG2].frequency = PMC_L_FREQUENCY_3;
	pmc_l_3d_clk1x_freqs[PMC_PSTATEVAL_REG3].driver_data = E1CP_BYPASS_FID_P3;
	pmc_l_3d_clk1x_freqs[PMC_PSTATEVAL_REG3].frequency = PMC_L_FREQUENCY_4;
	pmc_l_3d_clk1x_freqs[E1CP_MAX_PSTATES - 1].driver_data = 0;
	pmc_l_3d_clk1x_freqs[E1CP_MAX_PSTATES - 1].frequency = CPUFREQ_TABLE_END;

	pmc_l_3d_clkSh_freqs[PMC_PSTATEVAL_REG0].driver_data = E1CP_BYPASS_FID_P0;
	pmc_l_3d_clkSh_freqs[PMC_PSTATEVAL_REG0].frequency = PMC_L_FREQUENCY_1;
	pmc_l_3d_clkSh_freqs[PMC_PSTATEVAL_REG1].driver_data = E1CP_BYPASS_FID_P1;
	pmc_l_3d_clkSh_freqs[PMC_PSTATEVAL_REG1].frequency = PMC_L_FREQUENCY_2;
	pmc_l_3d_clkSh_freqs[PMC_PSTATEVAL_REG2].driver_data = E1CP_BYPASS_FID_P2;
	pmc_l_3d_clkSh_freqs[PMC_PSTATEVAL_REG2].frequency = PMC_L_FREQUENCY_3;
	pmc_l_3d_clkSh_freqs[PMC_PSTATEVAL_REG3].driver_data = E1CP_BYPASS_FID_P3;
	pmc_l_3d_clkSh_freqs[PMC_PSTATEVAL_REG3].frequency = PMC_L_FREQUENCY_4;
	pmc_l_3d_clkSh_freqs[E1CP_MAX_PSTATES - 1].driver_data = 0;
	pmc_l_3d_clkSh_freqs[E1CP_MAX_PSTATES - 1].frequency = CPUFREQ_TABLE_END;

	return 0;
}

int pmc_l_cpufreq_init(struct cpufreq_policy *policy)
{
	int result = -ENODEV;
	unsigned int hb_syscfg_val;
	struct device *cpu_dev;
	struct dev_pm_opp *opp;

	/* Dvfs init */
	cpu_dev = get_cpu_device(policy->cpu);

	vout_regulator = regulator_get_exclusive(cpu_dev, "vout");
	if (IS_ERR(vout_regulator)) {
		pr_warn("didn't find vout regulator\n");
		vout_regulator = NULL;
	}

	result = dev_pm_opp_of_add_table(cpu_dev);
	if (result)
		pr_warn("no OPP table for cpu%d\n", policy->cpu);


	/* Initialize P_State_value_X:
	 * 1) Check BFS bypass bit value in host brigde pci config space;
	 * 2) Initialize FID values for both cases
	 *    (0 - normal case, 1 - bypass;
	 *    case is determined by jumper on board).
	 */
	pci_read_config_dword(l_pmc[0].pdev, HB_BFS_PCI_CONF_REG,
							&bfs_bypass_val);
	pr_err("BFS val = 0x%x bypass bit: 0x%x\n",
			bfs_bypass_val, (bfs_bypass_val & HB_BFS_BYPASS_MASK));

	hb_syscfg_val = bfs_bypass_val;
	pr_err("HB SYSCFG val = 0x%x, Frequency is %d MHz\n", hb_syscfg_val,
			((E1CP_BASE_FREQ * ((hb_syscfg_val & 0xf) + 10)) / 2));

	if (bfs_bypass_val & HB_BFS_BYPASS_MASK) {
		/* WA case. */
		pr_err("WA case\n");
		pmc_l_init_wa_freq_tables();
	} else {
		/* Normal case. */
		pr_err("Normal case\n");

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
	__raw_writel(pmc_l_freqs[PMC_PSTATEVAL_REG1].driver_data,
					pmc_cbase + PMC_L_P_STATE_VALUE_1_REG);
	__raw_writel(pmc_l_freqs[PMC_PSTATEVAL_REG2].driver_data,
					pmc_cbase + PMC_L_P_STATE_VALUE_2_REG);
	__raw_writel(pmc_l_freqs[PMC_PSTATEVAL_REG3].driver_data,
					pmc_cbase + PMC_L_P_STATE_VALUE_3_REG);

	/* Also write FID values to P_State_3D_value_X register */
	__raw_writel(pmc_l_3d_clk1x_freqs[PMC_PSTATEVAL_REG0].driver_data,
					pmc_cbase + PMC_L_P_STATE_3D_VALUE_0_REG);
	__raw_writel(pmc_l_3d_clk1x_freqs[PMC_PSTATEVAL_REG1].driver_data,
					pmc_cbase + PMC_L_P_STATE_3D_VALUE_1_REG);
	__raw_writel(pmc_l_3d_clk1x_freqs[PMC_PSTATEVAL_REG2].driver_data,
					pmc_cbase + PMC_L_P_STATE_3D_VALUE_2_REG);
	__raw_writel(pmc_l_3d_clk1x_freqs[PMC_PSTATEVAL_REG3].driver_data,
					pmc_cbase + PMC_L_P_STATE_3D_VALUE_3_REG);

	__raw_writel(pmc_l_3d_clkSh_freqs[PMC_PSTATEVAL_REG0].driver_data,
					pmc_cbase + PMC_L_P_STATE_3D_VALUE_0_REG + 1);
	__raw_writel(pmc_l_3d_clkSh_freqs[PMC_PSTATEVAL_REG1].driver_data,
					pmc_cbase + PMC_L_P_STATE_3D_VALUE_1_REG + 1);
	__raw_writel(pmc_l_3d_clkSh_freqs[PMC_PSTATEVAL_REG2].driver_data,
					pmc_cbase + PMC_L_P_STATE_3D_VALUE_2_REG + 1);
	__raw_writel(pmc_l_3d_clkSh_freqs[PMC_PSTATEVAL_REG3].driver_data,
					pmc_cbase + PMC_L_P_STATE_3D_VALUE_3_REG + 1);

	/* A little trick to save development time */
	pmc_l_gpufreq_set_scale(64);
	gpu_scale = 64;

	/* Get boot's frequency, that was set up by jumpers */
	policy->cur = pmc_l_freqs[PMC_PSTATEVAL_REG0].frequency;

	if (!result) {
		opp = dev_pm_opp_find_freq_exact(
			cpu_dev, policy->cur * 1000, true);

		if (!IS_ERR(opp)) {
			if (vout_regulator) {
				regulator_set_voltage_tol(vout_regulator,
					dev_pm_opp_get_voltage(opp), 0);
			}
			dev_pm_opp_put(opp);
		}
	}

	if (bfs_bypass_val & HB_BFS_BYPASS_MASK)
		cpufreq_generic_init(policy, pmc_l_freqs,
			E1CP_TRANSITION_LATENCY);
	else
		cpufreq_generic_init(policy, pmc_l_available_freqs,
			E1CP_TRANSITION_LATENCY);

	return 0;
}

#endif /* CONFIG_CPU_FREQ */
