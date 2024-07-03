/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * CPU idle for E2K machines.
 */

#include <linux/cpu.h>
#include <linux/cpuidle.h>
#include <linux/init.h>
#include <linux/sched/idle.h>

#include <asm/sic_regs.h>

static int __cpuidle C1_enter(struct cpuidle_device *dev,
		struct cpuidle_driver *drv, int index)
{
	machine.C1_enter();
	return index;
}

static int __cpuidle C2_enter(struct cpuidle_device *dev,
		struct cpuidle_driver *drv, int index)
{
	unsigned long flags;
	unsigned int node = numa_node_id();
	int core = cpu_to_cpuid(dev->cpu) % cpu_max_cores_num();
	int reg = PMC_FREQ_CORE_N_SLEEP(core);
	freq_core_sleep_t C2 = { .cmd = 2 }, C0 = { .cmd = 0 };

	/* We do not want an NMI to arrive just before
	 * machine.C1_enter() and force us out of C2. */
	raw_all_irq_save(flags);
	sic_write_node_nbsr_reg(node, reg, AW(C2));

	machine.C1_enter();

	sic_write_node_nbsr_reg(node, reg, AW(C0));
	raw_all_irq_restore(flags);

	return index;
}

static int __cpuidle C3_enter(struct cpuidle_device *dev,
		struct cpuidle_driver *drv, int index)
{
	if (WARN_ON_ONCE(!machine.C3_enter))
		return 0;

	machine.C3_enter();
	return index;
}


#define E2K_CPUIDLE_C1_STATE ({ \
	struct cpuidle_state state = { \
		.name = "C1", \
		.desc = "CPU pipeline stop", \
		.exit_latency = 0, \
		.target_residency = 0, \
		.enter = &C1_enter \
	}; \
	state; \
})

/* One step takes ~2.6 us */
#define DIVF_STEPS_LENGTH_US(divF) ((divF) * 26 / 10)
#define E2K_CPUIDLE_C2_STATE(divF) ({ \
	struct cpuidle_state state = { \
		.name = "C2", \
		.desc = "CPU pipeline stop at lower freq", \
		/* Divide by 2 since CPU starts executing immediately \
		 * (although at lower frequency), and enters C2 also \
		 * immediately (although at higher frequency). */ \
		.exit_latency = DIVF_STEPS_LENGTH_US(divF) / 2, \
		.target_residency = 1 + DIVF_STEPS_LENGTH_US(divF) / 2, \
		.enter = &C2_enter \
	}; \
	state; \
})

#define E2K_CPUIDLE_C3_STATE ({ \
	struct cpuidle_state state = { \
		.name = "C3", \
		.desc = "CPU clock off (including L1/L2)", \
		/* Since v6 C3 is entered and exited ~(7 * 2.6) us slower */ \
		.exit_latency = 30 + (cpu_has(CPU_FEAT_ISET_V6) \
				      ? DIVF_STEPS_LENGTH_US(7) \
				      : 0), \
		.target_residency = 100 + (cpu_has(CPU_FEAT_ISET_V6) \
					   ? DIVF_STEPS_LENGTH_US(14) \
					   : 0), \
		.enter = &C3_enter \
	}; \
	state; \
})


static struct cpuidle_driver e2k_idle_driver = {
	.name = "e2k_idle",
	.owner = THIS_MODULE,
};

static int __initdata cpu_divF[NR_CPUS];
static void __init initialize_C2_state(void *unused)
{
	int cpu = smp_processor_id();
	int node = numa_node_id();
	int core = cpu_to_cpuid(cpu) % cpu_max_cores_num();
	freq_core_mon_t C2_mon;
	/* Choose not too deep sleep, otherwise there is no
	 * value in choosing C2 over C3. */
	int new_divF = 0x10;

	C2_mon.word = sic_read_node_nbsr_reg(node, PMC_FREQ_CORE_N_MON(core));
	if (C2_mon.divF_limit_hi < new_divF)
		new_divF = C2_mon.divF_limit_hi;

	cpu_divF[cpu] = new_divF;

	/* Set C2 state to also reduce CPU frequency */
	if (cpu == cpumask_first(cpumask_of_node(node)))
		sic_write_node_nbsr_reg(node, PMC_FREQ_C2, new_divF);
}

/* Force C3 on if it is disabled on current hardware */
static bool force_C3;
static int __init force_C3_setup(char *__unused)
{
	pr_info("C3 idle state enabled from command line\n");
	force_C3 = 1;

	return 1;
}
__setup("force_C3", force_C3_setup);


/* Initialize CPU idle by registering the idle states */
static int __init e2k_idle_init(void)
{
	/* C2/C3 states are disabled on guest as they will
	 * just cause a lot of unnecessary interceptions. */
	bool use_deep_states = !IS_HV_GM() && !IS_ENABLED(CONFIG_KVM_GUEST_KERNEL);

	if (cpu_has(CPU_FEAT_ISET_V6)) {
		int nr = 0;

		/* Enable C1 state */
		if (!idle_nomwait) {
			e2k_idle_driver.states[nr] = E2K_CPUIDLE_C1_STATE;
			nr += 1;
		}

		/* Enable C2 state */
		if (use_deep_states && !idle_nomwait) {
			int cpu, divF_min = INT_MAX, divF_max = 0;

			on_each_cpu(initialize_C2_state, NULL, 1);
			for_each_online_cpu(cpu) {
				divF_min = min(divF_min, cpu_divF[cpu]);
				divF_max = max(divF_max, cpu_divF[cpu]);
			}
			pr_info("Chosen C2 state dividers range 0x%x:0x%x\n",
					divF_min, divF_max);

			if (divF_min) {
				e2k_idle_driver.states[nr] = E2K_CPUIDLE_C2_STATE(
						(divF_min + divF_max) / 2);
				nr += 1;
			} else {
				pr_warn("WARNING: disabling C2 state\n");
			}
		}

		/* Enable C3 state */
		if (use_deep_states && (!cpu_has(CPU_HWBUG_C3) || force_C3)) {
			e2k_idle_driver.states[nr] = E2K_CPUIDLE_C3_STATE;
			nr += 1;
			WARN_ON(nr > 1 && e2k_idle_driver.states[nr - 1].target_residency <=
					  e2k_idle_driver.states[nr - 2].target_residency);
		}
		e2k_idle_driver.state_count = nr;
	} else {
		e2k_idle_driver.states[0] = E2K_CPUIDLE_C1_STATE;
		e2k_idle_driver.state_count = 1;

		if (use_deep_states && (!cpu_has(CPU_HWBUG_C3) || force_C3)) {
			e2k_idle_driver.states[1] = E2K_CPUIDLE_C3_STATE;
			e2k_idle_driver.state_count = 2;
		}
	}
	return cpuidle_register(&e2k_idle_driver, NULL);
}
device_initcall(e2k_idle_init);
