/*
 * linux/arch/l/kernel/pmc.c
 *
 * Copyright (C) 2013 Evgeny Kravtsunov <kravtsunov_e@mcst.ru>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * PMC (Power Management Controller) for e90s (Izumrud) and e2k (Processor-2)
 */
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/cpufreq.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/smp.h>
#include <linux/init.h>
#include <linux/cpuidle.h>
#include <linux/io.h>
#include <linux/cpumask.h>

#include <asm/l_pmc.h>

#define PMC_VERSION_MODEL	0 /* Has fixed set of frequencies */
#define PMC_VERSION_REAL	1 /* Boot provides values for
				   * calculating frequencies
				   */

#ifdef	__e2k__
#define HAS_MACHINE_PMC	\
		(bootblock_virt->info.bios.mb_type == MB_TYPE_E1CP_PMC)
#elif defined(CONFIG_E90)
#define HAS_MACHINE_PMC	\
	(bootblock_virt->info.bios.mb_type == MB_TYPE_E90_PMC)
#else
#define HAS_MACHINE_PMC	0
#endif

#ifdef __e2k__
extern bootblock_struct_t	*bootblock_virt;
#else   /* !__e2k__ */
#define bootblock_virt		bootblock
#endif  /* __e2k__ */

struct l_pmc l_pmc;

static void __iomem *pmc_cbase;
static struct cpufreq_frequency_table *pmc_l_freqs;

/* cpuidle subsystem: */
static DEFINE_PER_CPU(struct cpuidle_device, pmc_l_cpuidle_device);

static struct cpuidle_driver pmc_l_idle_driver = {
	.name =		"pmc_l_idle",
	.owner =	THIS_MODULE,
};

/* Interface for entering the sleep state */
static int pmc_l_enter_idle(struct cpuidle_device *dev,
				struct cpuidle_state *state)
{
	ktime_t before, after;

	before = ktime_get();
	if (state == &dev->states[0]) { /* just busy loop */
		while (!need_resched()) {
			default_idle();
		}
	} else if (state == &dev->states[1]) {
		local_irq_enable();
		pmc_l_enter_C1();
	} else if (state == &dev->states[2]) {
		local_irq_enable();
		pmc_l_enter_C3();
	} else if (state == &dev->states[3]) {
		local_irq_enable();
		pmc_l_enter_C6();
	}

	after = ktime_get();
	return ktime_to_ns(ktime_sub(after, before)) >> 10;
}

/* cpufreq subsystem: */
static struct cpufreq_frequency_table pmc_l_freqs_model[] = {
	{ 1,  PMC_L_FREQUENCY_1 },
	{ 2,  PMC_L_FREQUENCY_2 },
	{ 3,  PMC_L_FREQUENCY_3 },
	{ 4,  PMC_L_FREQUENCY_4 },
	{ 0,  CPUFREQ_TABLE_END },
};

static int pmc_l_cpufreq_get_state(void)
{
	unsigned int state = 0;

	state = __raw_readl(pmc_cbase + PMC_L_P_STATE_STATUS_REG);
	state >>= PMC_L_P_STATE_STATUS_SHIFT;
	state &= PMC_L_P_STATE_STATUS_MASK;

	return state;
}

static void pmc_l_cpufreq_set_state(unsigned int state)
{
	unsigned int st;

	st = (state << PMC_L_P_STATE_CNTRL_SHIFT) &
				PMC_L_P_STATE_CNTRL_MASK;

	__raw_writel(st, pmc_cbase + PMC_L_P_STATE_CNTRL_REG);
}

/**
 * pmc_l_cpufreq_verify_policy - verifies a new CPUFreq policy
 * @policy: new policy
 *
 * Limit must be within low_freq and high_freq, with at least
 * one border included.
 */
static int pmc_l_cpufreq_verify_policy(struct cpufreq_policy *policy)
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
	unsigned int i;
	unsigned int newstate = 0;
	struct cpufreq_freqs freqs;

	if (cpufreq_frequency_table_target(policy, pmc_l_freqs,
				target_freq, relation, &newstate))
		return -EINVAL;

	freqs.old = pmc_l_freqs[pmc_l_cpufreq_get_state()].frequency;
	freqs.new = pmc_l_freqs[newstate].frequency;

	if (freqs.old == freqs.new)
		return 0;

	/* One PMC, many CPUs */
	for_each_cpu(i, policy->cpus) {
		if (!cpu_online(i))
			continue;
		freqs.cpu = i;
		cpufreq_notify_transition(&freqs, CPUFREQ_PRECHANGE);
		pmc_l_cpufreq_set_state(newstate);
		cpufreq_notify_transition(&freqs, CPUFREQ_POSTCHANGE);
	}

	return 0;
}

static unsigned int pmc_l_div(unsigned int freq, unsigned char did,
						unsigned char fid) {

	return freq * PMC_L_PRECISION /
		((unsigned int)(((unsigned int)(did) * PMC_L_PRECISION)
								+ fid));
}


static int pmc_l_cpufreq_init(struct cpufreq_policy *policy)
{
	int i;
	int result;
	unsigned char version;
	unsigned long covfid_status;
	unsigned char vid, did, fid;
	unsigned int p_state_val;
	unsigned int freq;

	/* allocate freqs table */
	pmc_cbase = l_pmc.cntrl_base;
	version = l_pmc.version;

	if (version == PMC_VERSION_MODEL) {
		pmc_l_freqs = &pmc_l_freqs_model[0];
	} else if (version == PMC_VERSION_REAL) {
		freq = l_pmc.freq;
		pmc_l_freqs = kmalloc(sizeof(struct cpufreq_frequency_table) *
				(PMC_L_MAX_PSTATES+1), GFP_KERNEL);
		if (!pmc_l_freqs)
			return -ENOMEM;

		/*
		 * 1. initialize pmc_l_freq values using data obtained from
		 *    boot, invalidate zero entries
		 * 2. fill P_State_value_X according to real states
		 */
		for (i = 0; i < PMC_L_MAX_PSTATES; i++) {
			p_state_val = l_pmc.p_state[i];
			vid = (unsigned char)
				((p_state_val & PMC_L_P_STATE_VALUE_VID_MASK) >>
						PMC_L_P_STATE_VALUE_VID_SHIFT);
			did = (unsigned char)
				((p_state_val & PMC_L_P_STATE_VALUE_DID_MASK) >>
						PMC_L_P_STATE_VALUE_DID_SHIFT);
			fid = (unsigned char)
				((p_state_val & PMC_L_P_STATE_VALUE_FID_MASK) >>
						PMC_L_P_STATE_VALUE_FID_SHIFT);

			pmc_l_freqs[i].index = i + 1;
			if (did == 0) {
				/* mark state as invalid */
				pmc_l_freqs[i].frequency =
						CPUFREQ_ENTRY_INVALID;
			} else {
				pmc_l_freqs[i].frequency =
						pmc_l_div(freq, did, fid);
			}
		}
		pmc_l_freqs[PMC_L_MAX_PSTATES].index = 0;
		pmc_l_freqs[PMC_L_MAX_PSTATES].frequency = CPUFREQ_TABLE_END;
	} else {
		return -EINVAL;
	}

	/*
	 * 1. get 4 sets of {VID, {DID, FID}} form l_pmc
	 * 2. write them to P_State_value_X, where X=1,2,3,4
	 */
	__raw_writel(l_pmc.p_state[0], pmc_cbase + PMC_L_P_STATE_VALUE_0_REG);
	__raw_writel(l_pmc.p_state[1], pmc_cbase + PMC_L_P_STATE_VALUE_1_REG);
	__raw_writel(l_pmc.p_state[2], pmc_cbase + PMC_L_P_STATE_VALUE_2_REG);
	__raw_writel(l_pmc.p_state[3], pmc_cbase + PMC_L_P_STATE_VALUE_3_REG);

	/*
	 * 3. get VMAX, VMIN, FMAX from l_pmc (boot to give us)
	 * 4. Write VMAX, VMIN, FMAX to COVFID_status
	 */
	covfid_status = __raw_readq(pmc_cbase + PMC_L_COVFID_STATUS_REG);
	covfid_status |= (l_pmc.vrange & (PMC_L_COVFID_RM_MASK));
	__raw_writeq(covfid_status, pmc_cbase + PMC_L_COVFID_STATUS_REG);

	/*
	 * 5. Disable RM bits: write 1 to RMWEN
	 * 6. Enable PMC: write PMCEN to COVFID_Status
	 */
	covfid_status |= (PMC_L_COVFID_STATUS_PMCEN_VAL |
					PMC_L_COVFID_STATUS_RMWEN_VAL);
	__raw_writeq(covfid_status, pmc_cbase + PMC_L_COVFID_STATUS_REG);

	/* Setup cpufreq subsystem values */
	policy->cpuinfo.transition_latency = 60000; /* 60 uS */
	policy->cur = l_pmc.freq;

	result = cpufreq_frequency_table_cpuinfo(policy, pmc_l_freqs);
	if (result)
		return result;

	cpufreq_frequency_table_get_attr(pmc_l_freqs, policy->cpu);
	return 0;
}

static int pmc_l_cpufreq_exit(struct cpufreq_policy *policy)
{
	unsigned char version;
	unsigned long covfid_status;

	version = l_pmc.version;

	/*
	 * Disable PMC: write ~PMCEN to COVFID_Status
	 */
	covfid_status = __raw_readq(pmc_cbase + PMC_L_COVFID_STATUS_REG);
	covfid_status &= ~(PMC_L_COVFID_STATUS_PMCEN_VAL);
	__raw_writeq(covfid_status, pmc_cbase + PMC_L_COVFID_STATUS_REG);

	cpufreq_frequency_table_put_attr(policy->cpu);

	if (version == PMC_VERSION_REAL) {
		kfree(pmc_l_freqs);
	}
	pmc_l_freqs = NULL;

	return 0;
}

static unsigned int pmc_l_cpufreq_get(unsigned int cpu)
{
	return pmc_l_freqs[pmc_l_cpufreq_get_state()].frequency;
}

static struct freq_attr *pmc_l_cpufreq_attr[] = {
	&cpufreq_freq_attr_scaling_available_freqs,
	NULL,
};

static struct cpufreq_driver pmc_l_cpufreq_driver = {
	.verify		= pmc_l_cpufreq_verify_policy,
	.target		= pmc_l_cpufreq_set_target,
	.init		= pmc_l_cpufreq_init,
	.exit		= pmc_l_cpufreq_exit,
	.get		= pmc_l_cpufreq_get,
	.name		= "pmc_l_cpufreq",
	.owner		= THIS_MODULE,
	.attr		= pmc_l_cpufreq_attr,
};

/* init both cpufreq and cpuidle */
static int __init pmc_l_init(void)
{
	struct cpuidle_device *device;
	int cpu;

	/*
	 * Check if machine has PMC
	 */
	if (!HAS_MACHINE_PMC)
		return 0;

	/* init cpuidle subsystem */
	cpuidle_register_driver(&pmc_l_idle_driver);

	for_each_online_cpu(cpu) {
		device = &per_cpu(pmc_l_cpuidle_device, cpu);
		device->cpu = cpu;
		device->state_count = PMC_L_MAX_IDLE_STATES;

		/* Wait for interrupt state (busy loop) */
		device->states[0].enter = pmc_l_enter_idle;
		device->states[0].exit_latency = 1;
		device->states[0].target_residency = 10000;
		device->states[0].flags = CPUIDLE_FLAG_TIME_VALID;
		strcpy(device->states[0].name, "C0");
		strcpy(device->states[0].desc, "Idle busy loop");

		/* C1: stopping the conveyor */
		device->states[1].enter = pmc_l_enter_idle;
		device->states[1].exit_latency = 10;
		device->states[1].target_residency = 10000;
		device->states[1].flags = CPUIDLE_FLAG_TIME_VALID;
		strcpy(device->states[1].name, "C1");
		strcpy(device->states[1].desc, "Wait trap");

		/* C3: stopping the conveyor + gating clock */
		device->states[2].enter = pmc_l_enter_idle;
		device->states[2].exit_latency = 100;
		device->states[2].target_residency = 10000;
		device->states[2].flags = CPUIDLE_FLAG_TIME_VALID;
		strcpy(device->states[2].name, "C3");
		strcpy(device->states[2].desc, "Gate clock");

		/* C6: deep sleep on retention regs */
		device->states[3].enter = pmc_l_enter_idle;
		device->states[3].exit_latency = 1000;
		device->states[3].target_residency = 10000;
		device->states[3].flags = CPUIDLE_FLAG_TIME_VALID;
		strcpy(device->states[3].name, "C6");
		strcpy(device->states[3].desc, "Deep sleep");

		if (cpuidle_register_device(device)) {
			pr_err("pmc_l_init_cpuidle: "
					"Failed registering cpu = %d\n", cpu);
			return -EIO;
		}
	}

	/* init cpufreq subsystem */
	return cpufreq_register_driver(&pmc_l_cpufreq_driver);
}

static void __exit pmc_l_exit(void)
{
	struct cpuidle_device *device;
	int cpu;

	/*
	 * Check if machine has PMC
	 */
	if (!HAS_MACHINE_PMC)
		return;

	/* exit cpufreq subsystem */
	cpufreq_unregister_driver(&pmc_l_cpufreq_driver);

	/* exit cpuidle subsystem */
	for_each_online_cpu(cpu) {
		device = &per_cpu(pmc_l_cpuidle_device, cpu);
		if (device->enabled) { /* check for cpu hotplug case */
			cpuidle_unregister_device(device);
		}
	}
	cpuidle_unregister_driver(&pmc_l_idle_driver);
}

MODULE_AUTHOR("Evgeny Kravtsunov");
MODULE_DESCRIPTION("PMC driver");
MODULE_LICENSE("GPL");

module_init(pmc_l_init);
module_exit(pmc_l_exit);
