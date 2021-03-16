// SPDX-License-Identifier: GPL-2.0-only
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

#define E2K_CPUIDLE_C2_STATE ({ \
	struct cpuidle_state state = { \
		.name = "C2", \
		.desc = "CPU pipeline stop at lower freq", \
		/* TODO These can be measured only on real hardware */ \
		.exit_latency = 10, \
		.target_residency = 20, \
		.enter = &C2_enter \
	}; \
	state; \
})

#define E2K_CPUIDLE_C3_STATE ({ \
	struct cpuidle_state state = { \
		.name = "C3", \
		.desc = "CPU clock off (including L1/L2)", \
		.exit_latency = 30, \
		.target_residency = 100, \
		.enter = &C3_enter \
	}; \
	state; \
})


static struct cpuidle_driver e2k_idle_driver = {
	.name = "e2k_idle",
	.owner = THIS_MODULE,
};

static void __init initialize_C2_state(void *unused)
{
	int cpu = smp_processor_id();
	int node = numa_node_id();
	int core = cpu_to_cpuid(cpu) % cpu_max_cores_num();
	freq_core_mon_t C2_mon;
	int new_divF = 0x2f;

	C2_mon.word = sic_read_node_nbsr_reg(node, PMC_FREQ_CORE_N_MON(core));
	if (C2_mon.divF_limit_hi < new_divF)
		new_divF = C2_mon.divF_limit_hi;
	pr_info("Chosen C2 divider: 0x%x (hardware limit 0x%x)\n",
			new_divF, C2_mon.divF_limit_hi);

	/* Set C2 state to also reduce CPU frequency */
	if (cpu == cpumask_first(cpumask_of_node(node)))
		sic_write_node_nbsr_reg(node, PMC_FREQ_C2, new_divF);

	put_cpu();
}

/* Initialize CPU idle by registering the idle states */
static int __init e2k_idle_init(void)
{
	if (cpu_has(CPU_FEAT_ISET_V6)) {
		int nr = 0;

		if (!idle_nomwait) {
			e2k_idle_driver.states[nr] = E2K_CPUIDLE_C1_STATE;

			on_each_cpu(initialize_C2_state, NULL, 1);
			e2k_idle_driver.states[nr + 1] = E2K_CPUIDLE_C2_STATE;
			nr += 2;
		}
		/* Old C3 state would just cause interceptions */
		if (!IS_ENABLED(CONFIG_KVM_GUEST_KERNEL)) {
			e2k_idle_driver.states[nr] = E2K_CPUIDLE_C3_STATE;
			nr += 1;
		}
		e2k_idle_driver.state_count = nr;
	} else if (cpu_has(CPU_FEAT_ISET_V3)) {
		e2k_idle_driver.states[0] = E2K_CPUIDLE_C1_STATE;
		e2k_idle_driver.states[1] = E2K_CPUIDLE_C3_STATE;
		e2k_idle_driver.state_count = 2;
	} else {
		e2k_idle_driver.states[0] = E2K_CPUIDLE_C1_STATE;
		e2k_idle_driver.state_count = 1;
	}
	return cpuidle_register(&e2k_idle_driver, NULL);
}
device_initcall(e2k_idle_init);
