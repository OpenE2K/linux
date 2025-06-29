/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/* drivers/cpufreq/cpufreq_pstates.c */

#include <linux/cpufreq.h>
#include <linux/cpu.h>
#include <linux/percpu-defs.h>
#include <linux/slab.h>
#include <linux/tick.h>

#include "cpufreq_governor.h"

#include <asm/l_pmc.h>
#include <asm/e2k.h>

#define CPU_PWR_LIMIT_MAX (5100)
#define CPU_PWR_LIMIT_MIN (2850)
#define MIN_POWER_CONSUMPTION_LIMIT CPU_PWR_LIMIT_MIN /*mWatt*/
#define MAX_POWER_CONSUMPTION_LIMIT CPU_PWR_LIMIT_MAX /*mWatt*/
#define MICRO_FREQUENCY_MIN_SAMPLE_RATE (10000)
#define CPUFREQ_PSTATES_INIT_TEMP 70

struct ps_cpu_state {
	unsigned int temperature;
	unsigned int power;
	struct pstate *pstate;
};

struct ps_policy_dbs_info {
	struct policy_dbs_info policy_dbs;
	struct ps_cpu_state cur_cpu_state;
	struct cpufreq_frequency_table;
};

static inline struct ps_policy_dbs_info
			*to_dbs_info(struct policy_dbs_info *policy_dbs)
{
	return container_of(policy_dbs, struct ps_policy_dbs_info, policy_dbs);
}

struct ps_dbs_tuners {
	unsigned int power_consumption_limit;
	unsigned int temperature;
};

/* These are straight from cpufreq_ondemand.c */
#define DEF_FREQUENCY_UP_THRESHOLD              (80)
#define DEF_SAMPLING_DOWN_FACTOR                (1)


unsigned int init_cpu_pwr_limit = 5100; /* CPU_PWR_LIMIT_MAX */
EXPORT_SYMBOL(init_cpu_pwr_limit);
unsigned int cpu_pwr_limit = 5100; /* CPU_PWR_LIMIT_MAX */
EXPORT_SYMBOL(cpu_pwr_limit);
unsigned int battery_pwr = 2850; /*CPU_PWR_LIMIT_MIN */
EXPORT_SYMBOL(battery_pwr);

int set_cpu_pwr_limit(int new_cpu_pwr_limit)
{
	if ((new_cpu_pwr_limit < CPU_PWR_LIMIT_MIN) ||
			(new_cpu_pwr_limit > CPU_PWR_LIMIT_MAX)) {
		pr_err("set_cpu_pwr_limit: attribue is out of range - "
		"new_cpu_pwr_limit = %d\n", new_cpu_pwr_limit);
		return -1;
	}

	cpu_pwr_limit = new_cpu_pwr_limit;

	return 0;
}

static int init_cpu_pwr_limit_setup(char *str)
{
	int new_cpu_pwr_limit;
	int ints[2];

	str = get_options(str, ARRAY_SIZE(ints), ints);
	new_cpu_pwr_limit = ints[1];

	if (new_cpu_pwr_limit < CPU_PWR_LIMIT_MIN) {
		pr_err("cpu_pwr_limit_setup: "
		"get_options(...) has returned a value <= CPU_PWR_LIMIT_MIN\n");
		return -1;
	}
	if (new_cpu_pwr_limit > CPU_PWR_LIMIT_MAX) {
		pr_err("cpu_pwr_limit_setup: "
		"get_options(...) has retrned a value > CPU_PWR_LIMIT_MAX");
		return -2;
	}

	init_cpu_pwr_limit = new_cpu_pwr_limit;

	return set_cpu_pwr_limit(init_cpu_pwr_limit);
}

static int battery_pwr_setup(char *str)
{
	int new_battery_pwr;
	int ints[2];

	str = get_options(str, ARRAY_SIZE(ints), ints);
	new_battery_pwr = ints[1];

	if (new_battery_pwr <= 0) {
		pr_err("battery_pwr_setup: "
		"get_options(...) has returned a value <= 0\n");
		return -1;
	}
	if (new_battery_pwr > CPU_PWR_LIMIT_MAX) {
		pr_err("battery_pwr_setup: "
		"get_options(...) has retrned a value > CPU_PWR_LIMIT_MAX");
		return -2;
	}

	battery_pwr = new_battery_pwr;

	return 0;
}

__setup("init_cpu_pwr_limit=", init_cpu_pwr_limit_setup);
__setup("battery_pwr=", battery_pwr_setup);

struct pstate {
	unsigned int frequency;
	unsigned int voltage;
};

#define NUMBER_OF_PSTATES 8
struct pstate available_pstates[NUMBER_OF_PSTATES] = {
	{.frequency = 984000, .voltage = 999},
	{.frequency = 914000, .voltage = 999},
	{.frequency = 800000, .voltage = 999},
	{.frequency = 711000, .voltage = 999},
	{.frequency = 512000, .voltage = 999},
	{.frequency = 400000, .voltage = 999},
	{.frequency = 200000, .voltage = 999},
	{.frequency = 0, .voltage = 0}
};
#define P0 (&available_pstates[0])
#define P1 (&available_pstates[1])
#define P2 (&available_pstates[2])
#define P3 (&available_pstates[3])
#define P4 (&available_pstates[4])
#define P5 (&available_pstates[5])
#define P6 (&available_pstates[6])
#define PS_HALT (&available_pstates[7])


#define NUMBER_OF_TEMPS 9
int scaling_temperatures[NUMBER_OF_TEMPS] = {
50, 60, 70, 80, 90, 100, 110, 120, 130
};

#define NUMBER_OF_PWRS 13
int scaling_powers[NUMBER_OF_PWRS] = {
5100, 4850, 4600, 4350, 4100, 3850, 3600, 3350, 3100, 2850, 2600, 2350, 2100
};

struct pstate *pstates[NUMBER_OF_PWRS][NUMBER_OF_TEMPS] = {
	{P0, P0, P0, P0, P0, P0, P0, P5, PS_HALT},
	{P0, P0, P0, P0, P0, P0, P2, PS_HALT, PS_HALT},
	{P0, P0, P0, P0, P0, P0, PS_HALT, PS_HALT, PS_HALT},
	{P0, P0, P0, P0, P0, P6, PS_HALT, PS_HALT, PS_HALT},
	{P0, P0, P0, P0, P4, PS_HALT, PS_HALT, PS_HALT, PS_HALT},
	{P0, P0, P0, P3, PS_HALT, PS_HALT, PS_HALT, PS_HALT, PS_HALT},
	{P0, P0, P1, PS_HALT, PS_HALT, PS_HALT, PS_HALT, PS_HALT, PS_HALT},
	{P0, P0, PS_HALT, PS_HALT, PS_HALT, PS_HALT, PS_HALT, PS_HALT, PS_HALT},
	{P0, P6, PS_HALT, PS_HALT, PS_HALT, PS_HALT, PS_HALT, PS_HALT, PS_HALT},
	{P6, PS_HALT, PS_HALT, PS_HALT, PS_HALT, PS_HALT, PS_HALT, PS_HALT, PS_HALT},
	{PS_HALT, PS_HALT, PS_HALT, PS_HALT, PS_HALT, PS_HALT, PS_HALT, PS_HALT, PS_HALT},
	{PS_HALT, PS_HALT, PS_HALT, PS_HALT, PS_HALT, PS_HALT, PS_HALT, PS_HALT, PS_HALT},
	{PS_HALT, PS_HALT, PS_HALT, PS_HALT, PS_HALT, PS_HALT, PS_HALT, PS_HALT, PS_HALT}
};

unsigned int ps_get_cpu_power(void)
{
	return cpu_pwr_limit;
}

int ps_cpu_power_to_index(unsigned int cpu_power)
{
	int i;
	for (i = 0; i < NUMBER_OF_PWRS; i++) {
		if (scaling_powers[i] <= cpu_power)
			return i;
	}

	pr_alert("cpufreq_pstates.c: ps_cpu_power_to_index() - "
	"can't find appropriate index for cpu_power = %d.\n", cpu_power);
	return -EINVAL;
}

static void update_cpu_state(struct cpufreq_policy *policy,
				struct ps_cpu_state *cpu_state,
				int new_temperature, int new_power)
{
	int new_frequency;
	struct pstate *new_pstate;

	if ((new_temperature < 0) || (new_temperature >= NUMBER_OF_TEMPS)) {
		pr_err("update_cpu_state: atribute is out of limits - "
				"new_temperature = %d\n", new_temperature);
		return;
	}
	if ((new_power < 0) || (new_power >= NUMBER_OF_PWRS)) {
		pr_err("update_cpu_state: atribute is out of limits - "
				"new_power = %d\n", new_power);
		return;
	}

	cpu_state->temperature = new_temperature;
	cpu_state->power = new_power;
	new_pstate = pstates[new_power][new_temperature];
	cpu_state->pstate = new_pstate;
	new_frequency = new_pstate->frequency;
	
	__cpufreq_driver_target(policy, new_frequency , CPUFREQ_RELATION_L);
}

int ps_get_cpu_temperature(void)
{
	int temp = spmc_get_temp_cur0();
	if (temp == SPMC_TEMP_BAD_VALUE)
		pr_alert("cpufreq_pstates.c - "
			"ps_get_cpu_temperature(): spmc_get_temp_cur0() "
			"returned bad value.\n");

	return temp;
}

void ps_check_cpu(struct cpufreq_policy *policy)
{
	int temperature, new_temperature, current_temperature,
		power, new_power, current_power, cpu;

	struct ps_dbs_tuners *ps_tuners;
	struct policy_dbs_info *policy_dbs = policy->governor_data;
	struct ps_policy_dbs_info *ps_policy_dbs;
	struct dbs_data *dbs_data;
	struct ps_cpu_state *current_cpu_state;

	ps_policy_dbs = to_dbs_info(policy_dbs);
	if (!ps_policy_dbs) {
		pr_alert("%s: ps_policy_dbs is NULL!\n", __func__);
		return;
	}
	dbs_data = policy_dbs->dbs_data;
	if (!dbs_data) {
		pr_alert("%s: dbs_data is NULL!\n", __func__);
		return;
	}
	ps_tuners = (struct ps_dbs_tuners *)dbs_data->tuners;
	if (!ps_tuners) {
		pr_alert("%s: ps_tuners is NULL!\n", __func__);
		return;
	}
	current_cpu_state = &ps_policy_dbs->cur_cpu_state;
	if (!current_cpu_state) {
		pr_alert("%s: current_cpu_state is NULL!\n", __func__);
		return;
	}

	cpu = policy->cpu;
	temperature = ps_get_cpu_temperature();
	power = ps_get_cpu_power(); /* Returns cpu_pwr_limit */

	current_temperature = current_cpu_state->temperature;
	new_temperature = current_temperature;
	if (temperature < scaling_temperatures[current_temperature]) {
		if (current_temperature > 0) {
			while (temperature <=
				scaling_temperatures[new_temperature-1]) {
				new_temperature--;
				if (new_temperature <= 0) {
					break;
				}
			}
		}
	} else if (current_temperature < (NUMBER_OF_TEMPS-1)) {
		while (temperature >= scaling_temperatures[new_temperature+1]) {
			new_temperature++;
			if (new_temperature >= NUMBER_OF_TEMPS-1) {
				break;
			}
		}
	}

	current_power = current_cpu_state->power;
	new_power = current_power;
	if (power < scaling_powers[current_power]) {
		if (current_power < (NUMBER_OF_PWRS-1)) {
			while (power < scaling_powers[new_power]) {
				new_power++;
				if (new_power >= NUMBER_OF_PWRS-1) {
					break;
				}
			}
		}
	} else if (current_power > 0) {
		while (power >= scaling_powers[new_power-1]) {
			new_power--;
			if (new_power <= 0) {
				break;
			}
		}
	}

	if ((new_temperature != current_temperature) ||
						(new_power != current_power)) {
		ps_tuners->temperature = scaling_temperatures[new_temperature];
		update_cpu_state(policy, current_cpu_state,
						new_temperature, new_power);
	}
}

static unsigned int ps_dbs_update(struct cpufreq_policy *policy)
{
	struct policy_dbs_info *policy_dbs = policy->governor_data;
	struct dbs_data *dbs_data = policy_dbs->dbs_data;

	/* if (!ps_need_load_eval(&core_pbs_info->cpbs,
				ps_tuners->sampling_rate)) {
		modify_all = false;
		goto max_delay;
	} */

	ps_check_cpu(policy);

	return dbs_data->sampling_rate;

}

/**************** sysfs ******************/

static ssize_t store_power_consumption_limit(struct gov_attr_set *attr_set,
					const char *buf, size_t count)
{
	struct dbs_data *dbs_data = to_dbs_data(attr_set);
	struct ps_dbs_tuners *ps_tuners;
	int input;
	int ret;

	ps_tuners = (struct ps_dbs_tuners *) dbs_data->tuners;
	ret = sscanf(buf, "%u", &input);
	ret = set_cpu_pwr_limit(input);
	if (!ret)
		ps_tuners->power_consumption_limit = input;

	return count;
}

/* For later debug purposes */
/*
static ssize_t store_temperature(struct gov_attr_set *attr_set, const char *buf,
					size_t count)
{
	struct dbs_data *dbs_data = to_dbs_data(attr_set);
	struct ps_dbs_tuners *ps_tuners;
	int input;
	int ret;

	ps_tuners = (struct ps_dbs_tuners *) dbs_data->tuners;
	ret = sscanf(buf, "%d", &input);
	ps_tuners->temperature = input;

	return count;
}
*/

gov_show_one_common(sampling_rate);
gov_show_one(ps, power_consumption_limit);
gov_show_one(ps, temperature);

gov_attr_rw(sampling_rate);
gov_attr_rw(power_consumption_limit);
gov_attr_ro(temperature);

static struct attribute *ps_attributes[] = {
	&sampling_rate.attr,
	&power_consumption_limit.attr,
	&temperature.attr,
	NULL
};


/************** sysfs end ****************/

static struct policy_dbs_info *ps_alloc(void)
{
	struct ps_policy_dbs_info *dbs_info;

	if (!IS_MACHINE_E1CP) {
		pr_alert("PSTATES governor is only supported for E1CP. "
				"Please select another governor.\n");
		return NULL;
	}

	dbs_info = kzalloc(sizeof(*dbs_info), GFP_KERNEL);
	return dbs_info ? &dbs_info->policy_dbs : NULL;
}

static void ps_free(struct policy_dbs_info *policy_dbs)
{
	kfree(to_dbs_info(policy_dbs));
}

static int ps_init(struct dbs_data *dbs_data)
{
	struct ps_dbs_tuners *tuners;
	u64 idle_time;
	int cpu;

	if (!IS_MACHINE_E1CP) {
		pr_alert("PSTATES governor is only supported for E1CP. "
				"Please select another governor.\n");
		return -EINVAL;
	}

	tuners = kzalloc(sizeof(*tuners), GFP_KERNEL);
	if (!tuners) {
		pr_alert("%s: can't allocate memory for tuners!\n",
				__func__);
		return -ENOMEM;
	}

	cpu = get_cpu();
	idle_time = get_cpu_idle_time_us(cpu, NULL);
	put_cpu();

	dbs_data->up_threshold = DEF_FREQUENCY_UP_THRESHOLD;

	dbs_data->sampling_down_factor = DEF_SAMPLING_DOWN_FACTOR;
	dbs_data->ignore_nice_load = 0;

	tuners->power_consumption_limit = ps_get_cpu_power();
	tuners->temperature = CPUFREQ_PSTATES_INIT_TEMP;

	dbs_data->tuners = tuners;

	return 0;
}

static void ps_exit(struct dbs_data *dbs_data)
{
	kfree(dbs_data->tuners);
}

static void ps_start(struct cpufreq_policy *policy)
{
	struct ps_policy_dbs_info *dbs_info =
			to_dbs_info(policy->governor_data);

	dbs_info->cur_cpu_state.pstate = P0;
	dbs_info->cur_cpu_state.temperature = NUMBER_OF_TEMPS - 1;
	dbs_info->cur_cpu_state.power =
		ps_cpu_power_to_index(ps_get_cpu_power());
}

static struct dbs_governor ps_dbs_gov = {
	.gov = CPUFREQ_DBS_GOVERNOR_INITIALIZER("pstates"),
	.kobj_type = { .default_attrs = ps_attributes },
	.gov_dbs_update = ps_dbs_update,
	.alloc = ps_alloc,
	.free = ps_free,
	.init = ps_init,
	.exit = ps_exit,
	.start = ps_start,
};

#define CPU_FREQ_GOV_PSTATES	(&ps_dbs_gov.gov)

static int __init cpufreq_gov_pbs_init(void)
{
	if (!IS_MACHINE_E1CP) {
		pr_warn("PSTATES governor is only supported for E1CP.\n");
		return 0;
	}

	return cpufreq_register_governor(CPU_FREQ_GOV_PSTATES);
}

static void __exit cpufreq_gov_pbs_exit(void)
{
	if (!IS_MACHINE_E1CP)
		return;

	cpufreq_unregister_governor(CPU_FREQ_GOV_PSTATES);
}

MODULE_AUTHOR("MCST");
MODULE_DESCRIPTION("'cpufreq_pstates' - A dynamic cpufreq governor for E1C+");
MODULE_LICENSE("GPL v2");

#ifdef CONFIG_CPU_FREQ_DEFAULT_GOV_PSTATES
struct cpufreq_governor *cpufreq_default_governor(void)
{
	return CPU_FREQ_GOV_PSTATES;
}
#endif

#ifdef CONFIG_CPU_FREQ_DEFAULT_GOV_PSTATES
fs_initcall(cpufreq_gov_pbs_init);
#else
module_init(cpufreq_gov_pbs_init);
#endif
module_exit(cpufreq_gov_pbs_exit);
