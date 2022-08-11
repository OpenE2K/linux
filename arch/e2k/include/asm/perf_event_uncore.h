#ifndef _ASM_E2K_PERF_EVENT_UNCORE_H
#define _ASM_E2K_PERF_EVENT_UNCORE_H

#include <linux/perf_event.h>
#include <linux/nodemask.h>

#define UNCORE_PMU_NAME_LEN	32

#define E2K_UNCORE_HAS_IPCC					\
	(IS_MACHINE_E2S || IS_MACHINE_E8C)

#define E2K_UNCORE_HAS_IOCC					\
	(IS_MACHINE_E2S || IS_MACHINE_ES2 || IS_MACHINE_E1CP)

#define E2K_UNCORE_HAS_SIC	(HAS_MACHINE_L_SIC && \
		(IS_MACHINE_E2S || IS_MACHINE_E8C || IS_MACHINE_E8C2))

#define E2K_UNCORE_HAS_SIC_L3	(E2K_UNCORE_HAS_SIC && \
		(IS_MACHINE_E8C || IS_MACHINE_E8C2))

#define E2K_UNCORE_HAS_HMU \
	(IS_MACHINE_E2C3 || IS_MACHINE_E12C || IS_MACHINE_E16C)

#define E2K_UNCORE_HAS_IOMMU \
	(IS_MACHINE_E2C3 || IS_MACHINE_E12C || IS_MACHINE_E16C)

#define E2K_UNCORE_HAS_HC \
	(IS_MACHINE_E2C3 || IS_MACHINE_E12C || IS_MACHINE_E16C)

#define E2K_UNCORE_HAS_MC \
	(IS_MACHINE_E2C3 || IS_MACHINE_E12C || IS_MACHINE_E16C)

#define E2K_UNCORE_HAS_PREPIC \
	(IS_MACHINE_E2C3 || IS_MACHINE_E12C || IS_MACHINE_E16C)

enum {
	E2K_UNCORE_IOCC = 1,
	E2K_UNCORE_IPCC,
	E2K_UNCORE_SIC,
	E2K_UNCORE_HMU,
	E2K_UNCORE_IOMMU,
	E2K_UNCORE_HC,
	E2K_UNCORE_MC,
	E2K_UNCORE_PREPIC
};

extern int __init register_iocc_pmus(void);
extern int __init register_ipcc_pmus(void);
extern int __init register_sic_pmus(void);
extern int __init register_hmu_pmus(void);
extern int __init register_iommu_pmus(void);
extern int __init register_hc_pmus(void);
extern int __init register_mc_pmus(void);
extern int __init register_prepic_pmus(void);

extern int e2k_uncore_event_init(struct perf_event *event);

extern int e2k_uncore_add(struct perf_event *event, int flags);
extern void e2k_uncore_del(struct perf_event *event, int flags);
extern void e2k_uncore_start(struct perf_event *event, int flags);
extern void e2k_uncore_stop(struct perf_event *event, int flags);
extern void e2k_uncore_read(struct perf_event *event);

extern const struct attribute_group e2k_cpumask_attr_group;

struct e2k_uncore_valid_events {
	int first;
	int last;
};

struct e2k_uncore {
	char name[UNCORE_PMU_NAME_LEN];
	int type;
	int num_counters;
	int node;
	int idx_at_node;

	/*
	 * Array of valid event numbers.
	 * Must be terminated with { -1, -1 }
	 */
	struct e2k_uncore_valid_events *valid_events;
	int (*validate_event)(struct e2k_uncore *, struct hw_perf_event *);
	u64 (*get_event)(struct hw_perf_event *);
	int (*add_event)(struct e2k_uncore *, struct perf_event *);

	struct e2k_uncore_reg_ops *reg_ops;
	struct pmu pmu;
	struct perf_event *events[0];
};

/*
 * We implement this functions to generalize access to
 * monitor registers. (void *) arguments for flexibility.
 */
struct e2k_uncore_reg_ops {
	u64 (*get_cnt)(struct e2k_uncore *uncore, struct hw_perf_event *);
	void (*set_cfg)(struct e2k_uncore *uncore,
			struct hw_perf_event *, bool);
	void (*set_cnt)(struct e2k_uncore *uncore, struct hw_perf_event *, u64);
};

struct e2k_uncore_event_desc {
	struct kobj_attribute attr;
	const char *config;
};

extern ssize_t e2k_uncore_event_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf);
#define E2K_UNCORE_EVENT_DESC(_name, _config)			\
{								\
	.attr	= __ATTR(_name, 0444, e2k_uncore_event_show, NULL),	\
	.config	= _config,					\
}

#endif /* _ASM_E2K_PERF_EVENT_UNCORE_H */
