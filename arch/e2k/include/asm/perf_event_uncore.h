#ifndef _ASM_E2K_PERF_EVENT_UNCORE_H
#define _ASM_E2K_PERF_EVENT_UNCORE_H

#include <linux/perf_event.h>
#include <asm/sic_regs.h>
#include <linux/nodemask.h>

#define UNCORE_PMU_NAME_LEN	256

#define IPCC_STR_PER_NODE	SIC_IPCC_LINKS_COUNT
#define IOCC_STR_PER_NODE	SIC_IO_LINKS_COUNT
#define SIC_STR_PER_NODE	2

/* We have one control register for one ipcc or iocc counter */
#define NUM_COUNTERS_IPCC	(num_online_nodes() * IPCC_STR_PER_NODE)
#define NUM_COUNTERS_IOCC	(num_online_nodes() * IOCC_STR_PER_NODE)

/* We have one control register for two sic counters */
#define NUM_COUNTERS_SIC	(num_online_nodes() * SIC_STR_PER_NODE)


#define E2K_UNCORE_HAS_IPCC					\
	(IS_MACHINE_E2S || IS_MACHINE_E8C)

#define E2K_UNCORE_HAS_IOCC					\
	(IS_MACHINE_E3S || IS_MACHINE_E2S || IS_MACHINE_ES2 ||	\
		IS_MACHINE_E1CP)

#define E2K_UNCORE_HAS_SIC					\
	(HAS_MACHINE_L_SIC && !IS_MACHINE_E3S && !IS_MACHINE_ES2)

#define E2K_IO_STR_EVENT_MASK	0xE0000000
#define E2K_IO_STR_EVENT_SHIFT	29

#define MAX_COUNTERS	32

struct e2k_uncore {
	char name[UNCORE_PMU_NAME_LEN];
	int num_counters;
	int node;
	int idx_at_node;

	/*
	 * Array of valid event numbers.
	 * Must be terminated with -1
	 */
	int *valid_events;
	struct e2k_uncore_reg_ops *reg_ops;
	struct pmu pmu;
	struct perf_event *events[MAX_COUNTERS];
};

/*
 * We implement this functions to generalize access to
 * monitor registers. (void *) arguments for flexibility.
 */
struct e2k_uncore_reg_ops {
	void (*get_cnt)(struct e2k_uncore *uncore, void *result);
	void (*set_cfg)(struct e2k_uncore *uncore, void *val);
	void (*set_cnt)(struct e2k_uncore *uncore, void *val);
};

struct e2k_uncore_event_desc {
	struct kobj_attribute attr;
	const char *config;
};

#define E2K_UNCORE_EVENT_DESC(_name, _config)			\
{								\
	.attr	= __ATTR(_name, 0444, uncore_event_show, NULL),	\
	.config	= _config,					\
}

static ssize_t uncore_event_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	struct e2k_uncore_event_desc *event =
		container_of(attr, struct e2k_uncore_event_desc, attr);
	return sprintf(buf, "%s", event->config);
}

#endif /* _ASM_E2K_PERF_EVENT_UNCORE_H */
