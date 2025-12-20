/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/list.h>
#include <linux/perf_event.h>
#include <linux/nodemask.h>
#include <linux/slab.h>
#include <asm/apic.h>
#include <asm/sic_regs.h>
#include <asm/perf_event_uncore.h>


static struct e2k_uncore *e2k_uncore_ipcc[MAX_NUMNODES][SIC_IPCC_LINKS_COUNT];
static struct e2k_uncore *e2k_uncore_iocc[MAX_NUMNODES][SIC_IO_LINKS_COUNT];
static struct e2k_uncore *e2k_uncore_sic[MAX_NUMNODES];

typedef union {
	struct {
		u64 event	: 9;
		u64 l3_cpu	: 11;
		u64 l3_select_cpu : 1;
		u64 __unused	: 43;
	};
	u64 word;
} sic_config_attr_t;

/* event for MCR: 0xNMM, where N selects a counter
 * and MM selects an event in the counter */
PMU_FORMAT_ATTR(event, "config:0-8");
PMU_FORMAT_ATTR(l3_cpu, "config:9-19");
PMU_FORMAT_ATTR(l3_select_cpu, "config:20");

static struct attribute *e2k_mcm_wo_l3_format_attr[] = {
	&format_attr_event.attr,
	NULL,
};

static struct attribute *e2k_mcm_with_l3_format_attr[] = {
	&format_attr_event.attr,
	&format_attr_l3_cpu.attr,
	&format_attr_l3_select_cpu.attr,
	NULL,
};

static struct attribute *e2k_uncore_format_attr[] = {
	&format_attr_event.attr,
	NULL,
};


static u64 get_ipcc_str_cnt(struct e2k_uncore *uncore,
		struct hw_perf_event *hwc)
{
	e2k_ipcc_str_struct_t reg;
	int node = uncore->node;
	int idx = uncore->idx_at_node;

	reg.E2K_IPCC_STR_reg = sic_get_ipcc_str(node, idx);

	/* see comment in set_ipcc_str_cnt() */
	return reg.E2K_IPCC_STR_ecnt + hwc->last_tag;
}

static void set_ipcc_str_cfg(struct e2k_uncore *uncore,
			     struct hw_perf_event *hwc, bool enable)
{
	e2k_ipcc_str_struct_t reg;
	int node = uncore->node;
	int idx = uncore->idx_at_node;
	sic_config_attr_t config = { .word = hwc->config };
	u64 event = config.event;

	reg.E2K_IPCC_STR_reg = sic_get_ipcc_str(node, idx);

	if (enable)
		reg.E2K_IPCC_STR_ecf = event;
	else
		reg.E2K_IPCC_STR_ecf = 0;

	sic_set_ipcc_str(node, idx, reg.E2K_IPCC_STR_reg);
}

static void set_ipcc_str_cnt(struct e2k_uncore *uncore,
			     struct hw_perf_event *hwc, u64 val)
{
	e2k_ipcc_str_struct_t reg;
	int node = uncore->node;
	int idx = uncore->idx_at_node;

	/* ipcc counter cannot be set, only cleared, so `val'
	 * is saved in memory instead of register */
	hwc->last_tag = val;

	reg.E2K_IPCC_STR_reg = sic_get_ipcc_str(node, idx);

	reg.E2K_IPCC_STR_eco = 1;

	sic_set_ipcc_str(node, idx, reg.E2K_IPCC_STR_reg);
}

static struct e2k_uncore_reg_ops ipcc_reg_ops = {
	.get_cnt = get_ipcc_str_cnt,
	.set_cfg = set_ipcc_str_cfg,
	.set_cnt = set_ipcc_str_cnt,
};

static u64 get_iocc_str_cnt(struct e2k_uncore *uncore,
		struct hw_perf_event *hwc)
{
	e2k_io_str_struct_t reg;
	int node = uncore->node;
	int idx = uncore->idx_at_node;

	reg.E2K_IO_STR_reg = sic_get_io_str(node, idx);

	/* see comment in set_iocc_str_cnt() */
	return reg.E2K_IO_STR_rc + hwc->last_tag;
}

#define E2K_IO_STR_EVENT_MASK	0xE0000000
#define E2K_IO_STR_EVENT_SHIFT	29
static void set_iocc_str_cfg(struct e2k_uncore *uncore,
			     struct hw_perf_event *hwc, bool enable)
{
	e2k_io_str_struct_t reg;
	int node = uncore->node;
	int idx = uncore->idx_at_node;
	sic_config_attr_t config = { .word = hwc->config };
	u64 event = config.event;

	reg.E2K_IO_STR_reg = sic_get_ipcc_str(node, idx);
	reg.E2K_IO_STR_reg &= ~E2K_IO_STR_EVENT_MASK;
	if (enable)
		reg.E2K_IO_STR_reg |= event << E2K_IO_STR_EVENT_SHIFT;

	sic_set_io_str(node, idx, reg.E2K_IO_STR_reg);
}

static void set_iocc_str_cnt(struct e2k_uncore *uncore,
			     struct hw_perf_event *hwc, u64 val)
{
	e2k_io_str_struct_t reg;
	int node = uncore->node;
	int idx = uncore->idx_at_node;

	/* iocc counter cannot be set, only cleared, so `val'
	 * is saved in memory instead of register */
	hwc->last_tag = val;

	reg.E2K_IO_STR_reg = sic_get_io_str(node, idx);
	reg.E2K_IO_STR_rcol = 1;

	sic_set_io_str(node, idx, reg.E2K_IO_STR_reg);
}

static struct e2k_uncore_reg_ops iocc_reg_ops = {
	.get_cnt = get_iocc_str_cnt,
	.set_cfg = set_iocc_str_cfg,
	.set_cnt = set_iocc_str_cnt,
};

enum {
	MCM0 = 0,
	MCM1,
};

static u64 get_sic_str_cnt(struct e2k_uncore *uncore, struct hw_perf_event *hwc)
{
	e2k_sic_mar_lo_t mar_lo = 0;
	e2k_sic_mar_hi_t mar_hi = 0;
	sic_config_attr_t config = { .word = hwc->config };
	u64 val, event = config.event;
	int node = uncore->node;

	switch (event >> 8) {
	case MCM0:
		do {
			mar_hi = sic_read_node_nbsr_reg(node, SIC_sic_mar0_hi);
			mar_lo = sic_read_node_nbsr_reg(node, SIC_sic_mar0_lo);
		} while (mar_hi != sic_read_node_nbsr_reg(node, SIC_sic_mar0_hi));
		break;
	case MCM1:
		do {
			mar_lo = sic_read_node_nbsr_reg(node, SIC_sic_mar1_lo);
			mar_hi = sic_read_node_nbsr_reg(node, SIC_sic_mar1_hi);
		} while (mar_hi != sic_read_node_nbsr_reg(node, SIC_sic_mar1_hi));
		break;
	}

	val = ((u64) mar_hi << 32UL) | (u64) mar_lo;

	pr_debug("hw_event %px: get_cnt %lld\n", hwc, val);

	return val;
}

static void set_sic_str_cfg(struct e2k_uncore *uncore,
		struct hw_perf_event *hwc, bool enable)
{
	e2k_sic_mcr_struct_t mcr_reg;
	int node = uncore->node;
	sic_config_attr_t config = { .word = hwc->config };
	u64 event = config.event;

	mcr_reg.E2K_SIC_MCR_reg = sic_read_node_nbsr_reg(node, SIC_sic_mcr);

	if (E2K_UNCORE_HAS_SIC_L3) {
		u64 cpu = config.l3_cpu;

		if (config.l3_select_cpu && cpu_present(cpu)) {
			AS(mcr_reg).mcnmo = 0;
			AS(mcr_reg).mcn = default_cpu_present_to_apicid(cpu);
		} else {
			AS(mcr_reg).mcnmo = 1;
		}
	}

	switch (event >> 8) {
	case MCM0:
		mcr_reg.E2K_SIC_MCR_v0 = !!enable;
		mcr_reg.E2K_SIC_MCR_es0 = event & 0xff;
		break;
	case MCM1:
		mcr_reg.E2K_SIC_MCR_v1 = !!enable;
		mcr_reg.E2K_SIC_MCR_es1 = event & 0xff;
		break;
	}

	sic_write_node_nbsr_reg(node, SIC_sic_mcr, mcr_reg.E2K_SIC_MCR_reg);

	pr_debug("hw_event %px: set_cfg 0x%x\n", hwc, AW(mcr_reg));
}

static void set_sic_str_cnt(struct e2k_uncore *uncore,
			    struct hw_perf_event *hwc, u64 val)
{
	e2k_sic_mar_lo_t mar_lo;
	e2k_sic_mar_hi_t mar_hi;
	sic_config_attr_t config = { .word = hwc->config };
	u64 event = config.event;
	int node = uncore->node;

	mar_lo = val;
	mar_hi = val >> 32;

	switch (event >> 8) {
	case MCM0:
		sic_write_node_nbsr_reg(node, SIC_sic_mar0_lo, mar_lo);
		sic_write_node_nbsr_reg(node, SIC_sic_mar0_hi, mar_hi);
		break;
	case MCM1:
		sic_write_node_nbsr_reg(node, SIC_sic_mar1_lo, mar_lo);
		sic_write_node_nbsr_reg(node, SIC_sic_mar1_hi, mar_hi);
		break;
	}

	pr_debug("hw_event %px: set_cnt %lld\n", hwc, val);
}

static struct e2k_uncore_reg_ops sic_reg_ops = {
	.get_cnt = get_sic_str_cnt,
	.set_cfg = set_sic_str_cfg,
	.set_cnt = set_sic_str_cnt,
};

static struct e2k_uncore_event_desc ipcc_events[] = {
	E2K_UNCORE_EVENT_DESC(phl_errors,	"event=0x1"),
	E2K_UNCORE_EVENT_DESC(retry_ops,	"event=0x2"),
	{ /*end: all zeroes */ },
};

static struct e2k_uncore_valid_events ipcc_valid_events[] = {
	{ 1, 2 },
	{ -1, -1}
};

static struct attribute *e2k_ipcc_events_attrs[] = {
	&ipcc_events[0].attr.attr,
	&ipcc_events[1].attr.attr,
	NULL,
};

static const struct attribute_group e2k_ipcc_events_group = {
	.name = "events",
	.attrs = e2k_ipcc_events_attrs,
};

static const struct attribute_group e2k_ipcc_format_group = {
	.name = "format",
	.attrs = e2k_uncore_format_attr,
};

static const struct attribute_group *e2k_ipcc_attr_group[] = {
	&e2k_ipcc_events_group,
	&e2k_ipcc_format_group,
	&e2k_cpumask_attr_group,
	NULL,
};

static struct e2k_uncore_event_desc iocc_events[] = {
	E2K_UNCORE_EVENT_DESC(busy,		"event=0x1"),
	E2K_UNCORE_EVENT_DESC(crc_err,		"event=0x2"),
	E2K_UNCORE_EVENT_DESC(time_out,		"event=0x4"),
	E2K_UNCORE_EVENT_DESC(cmn_rc,		"event=0x7"),
	{ /*end: all zeroes */ },
};

static struct e2k_uncore_valid_events iocc_valid_events[] = {
	{ 1, 2 },
	{ 4, 4 },
	{ 7, 7 },
	{ -1, -1}
};


static struct attribute *e2k_iocc_events_attrs[] = {
	&iocc_events[0].attr.attr,
	&iocc_events[1].attr.attr,
	&iocc_events[2].attr.attr,
	NULL,
};

static const struct attribute_group e2k_iocc_events_group = {
	.name = "events",
	.attrs = e2k_iocc_events_attrs,
};

static const struct attribute_group e2k_iocc_format_group = {
	.name = "format",
	.attrs = e2k_uncore_format_attr,
};

static const struct attribute_group *e2k_iocc_attr_group[] = {
	&e2k_iocc_events_group,
	&e2k_iocc_format_group,
	&e2k_cpumask_attr_group,
	NULL,
};

static struct e2k_uncore_event_desc sic_MCM_events[] = {
	E2K_UNCORE_EVENT_DESC(mc_read,			"event=0x0"),
	E2K_UNCORE_EVENT_DESC(mc_write_local,		"event=0x1"),
	E2K_UNCORE_EVENT_DESC(mc_read_local_cores,	"event=0x2"),
	E2K_UNCORE_EVENT_DESC(mc_write,			"event=0x100"),
	E2K_UNCORE_EVENT_DESC(mc_read_local,		"event=0x101"),
	E2K_UNCORE_EVENT_DESC(mc_write_local_cores,	"event=0x102"),
	{ /*end: all zeroes */ },
};

static struct e2k_uncore_valid_events sic_MCM_e4c_valid_events[] = {
	{ 0x0, 0x8 },
	{ 0x100, 0x106 },
	{ -1, -1}
};
static struct e2k_uncore_valid_events sic_MCM_e8c_valid_events[] = {
	{ 0x0, 0x5 },
	{ 0x100, 0x105 },
	{ 0x20, 0x3f },
	{ 0x120, 0x13f },
	{ -1, -1}
};
static struct e2k_uncore_valid_events sic_MCM_e8c2_valid_events[] = {
	{ 0x0, 0x1b },
	{ 0x100, 0x11b },
	{ 0x20, 0x3f },
	{ 0x120, 0x13f },
	{ -1, -1}
};

static struct attribute *e2k_sic_MCM_events_attrs[] = {
	&sic_MCM_events[0].attr.attr,
	&sic_MCM_events[1].attr.attr,
	&sic_MCM_events[2].attr.attr,
	&sic_MCM_events[3].attr.attr,
	&sic_MCM_events[4].attr.attr,
	&sic_MCM_events[5].attr.attr,
	NULL,
};

static const struct attribute_group e2k_sic_MCM_events_group = {
	.name = "events",
	.attrs = e2k_sic_MCM_events_attrs,
};

static struct attribute_group e2k_sic_MCM_format_group = {
	.name = "format",
};

static const struct attribute_group *e2k_sic_MCM_attr_group[] = {
	&e2k_sic_MCM_events_group,
	&e2k_sic_MCM_format_group,
	&e2k_cpumask_attr_group,
	NULL,
};

static int is_l3_config(u64 config)
{
	if (!IS_MACHINE_E8C && !IS_MACHINE_E8C2)
		return 0;

	return (config & 0xff) >= 0x20 && (config & 0xff) <= 0x3f;
}

static u64 sic_get_event(struct hw_perf_event *hwc)
{
	sic_config_attr_t config = { .word = hwc->config };

	return config.event;
}

int __init register_ipcc_pmus()
{
	int node, cnt, counters = 1;

	for_each_online_node(node)
	for (cnt = 0; cnt < SIC_IPCC_LINKS_COUNT; cnt++) {
		struct e2k_uncore *uncore = kzalloc(sizeof(struct e2k_uncore) +
				counters * sizeof(void *), GFP_KERNEL);
		if (!uncore)
			return -ENOMEM;

		uncore->type = E2K_UNCORE_IPCC;

		uncore->pmu.attr_groups	=
			(const struct attribute_group **) e2k_ipcc_attr_group;
		uncore->pmu.task_ctx_nr	= perf_invalid_context;
		uncore->pmu.event_init	= e2k_uncore_event_init;
		uncore->pmu.add		= e2k_uncore_add;
		uncore->pmu.del		= e2k_uncore_del;
		uncore->pmu.start	= e2k_uncore_start;
		uncore->pmu.stop	= e2k_uncore_stop;
		uncore->pmu.read	= e2k_uncore_read;

		uncore->get_event = sic_get_event;

		uncore->reg_ops = &ipcc_reg_ops;
		uncore->num_counters = counters;

		uncore->node = node;
		uncore->idx_at_node = cnt;

		uncore->valid_events = ipcc_valid_events;

		snprintf(uncore->name, UNCORE_PMU_NAME_LEN, "ipcc_%d_%d", node, cnt);

		e2k_uncore_ipcc[node][cnt] = uncore;
		perf_pmu_register(&uncore->pmu, uncore->name, -1);
	}

	return 0;
}

int __init register_iocc_pmus()
{
	int node, cnt, counters = 1;

	for_each_online_node(node)
	for (cnt = 0; cnt < SIC_IO_LINKS_COUNT; cnt++) {
		struct e2k_uncore *uncore = kzalloc(sizeof(struct e2k_uncore) +
				counters * sizeof(void *), GFP_KERNEL);
		if (!uncore)
			return -ENOMEM;

		uncore->type = E2K_UNCORE_IOCC;

		uncore->pmu.attr_groups	=
			(const struct attribute_group **) e2k_iocc_attr_group;
		uncore->pmu.task_ctx_nr	= perf_invalid_context,
		uncore->pmu.event_init	= e2k_uncore_event_init;
		uncore->pmu.add		= e2k_uncore_add;
		uncore->pmu.del		= e2k_uncore_del;
		uncore->pmu.start	= e2k_uncore_start;
		uncore->pmu.stop	= e2k_uncore_stop;
		uncore->pmu.read	= e2k_uncore_read;

		uncore->get_event = sic_get_event;

		uncore->reg_ops = &iocc_reg_ops;
		uncore->num_counters = counters;

		uncore->node = node;
		uncore->idx_at_node = cnt;

		uncore->valid_events = iocc_valid_events;

		snprintf(uncore->name, UNCORE_PMU_NAME_LEN, "iocc_%d_%d", node, cnt);

		e2k_uncore_iocc[node][cnt] = uncore;
		perf_pmu_register(&uncore->pmu, uncore->name, -1);
	}

	return 0;
}


static int sic_validate_event(struct e2k_uncore *uncore,
		struct hw_perf_event *hwc)
{
	sic_config_attr_t config = { .word = hwc->config };

	/*
	 * Check that proper cpu is selected
	 */
	if (E2K_UNCORE_HAS_SIC_L3 && config.l3_select_cpu) {
		u64 cpu = config.l3_cpu, event = config.event;

		if (event < 32) {
			pr_info_ratelimited("uncore_sic: L3 parameters specified for non-L3 event 0x%llx\n",
					event);
			return -EINVAL;
		}
		if (cpu >= nr_cpu_ids || !cpu_present(cpu)) {
			pr_info_ratelimited("uncore_sic: cpu %lld does not exist\n",
					cpu);
			return -EINVAL;
		}
		if (cpu_to_node(cpu) != uncore->node) {
			pr_info_ratelimited("uncore_sic: cpu %lld does not exist on node %d\n",
					cpu, uncore->node);
			return -EINVAL;
		}
	}

	return 0;
}

static int sic_add_event(struct e2k_uncore *uncore, struct perf_event *event)
{
	sic_config_attr_t config = { .word = event->hw.config };
	u64 event_id = config.event;
	int i;

	/* validate against running counters */
	for (i = 0; i < uncore->num_counters; i++) {
		struct perf_event *event2 = READ_ONCE(uncore->events[i]);
		sic_config_attr_t config2;

		if (!event2)
			continue;

		AW(config2) = event2->hw.config;

		/*
		 * Check that there is no conflict with same counter in SIC
		 */
		if ((event_id >> 8) == (config2.event >> 8))
			return -ENOSPC;

		/*
		 * Check that there is no conflict with cpu selection in %MCR
		 */
		if (E2K_UNCORE_HAS_SIC_L3 &&
		    is_l3_config(config.word) && is_l3_config(config2.word) &&
		    (config.l3_select_cpu != config2.l3_select_cpu ||
		     config.l3_cpu != config2.l3_cpu))
			return -ENOSPC;
	}

	/* take the first available slot */
	for (i = 0; i < uncore->num_counters; i++) {
		if (cmpxchg(&uncore->events[i], NULL, event) == NULL) {
			event->hw.idx = i;
			return 0;
		}
	}

	return -ENOSPC;
}

int __init register_sic_pmus()
{
	int i, counters = 2;

	for_each_online_node(i) {
		struct e2k_uncore *uncore = kzalloc(sizeof(struct e2k_uncore) +
				counters * sizeof(void *), GFP_KERNEL);
		if (!uncore)
			return -ENOMEM;

		uncore->type = E2K_UNCORE_SIC;

		uncore->pmu.event_init	= e2k_uncore_event_init,
		uncore->pmu.task_ctx_nr	= perf_invalid_context,
		uncore->pmu.add		= e2k_uncore_add;
		uncore->pmu.del		= e2k_uncore_del;
		uncore->pmu.start		= e2k_uncore_start;
		uncore->pmu.stop		= e2k_uncore_stop;
		uncore->pmu.read		= e2k_uncore_read;

		uncore->get_event = sic_get_event;
		uncore->add_event = sic_add_event;
		uncore->validate_event = sic_validate_event;

		uncore->reg_ops = &sic_reg_ops;
		uncore->num_counters = counters;

		uncore->node = i;

		if (E2K_UNCORE_HAS_SIC_L3)
			e2k_sic_MCM_format_group.attrs = e2k_mcm_with_l3_format_attr;
		else
			e2k_sic_MCM_format_group.attrs = e2k_mcm_wo_l3_format_attr;

		if (IS_MACHINE_E2S)
			uncore->valid_events = sic_MCM_e4c_valid_events;
		else if (IS_MACHINE_E8C)
			uncore->valid_events = sic_MCM_e8c_valid_events;
		else if (IS_MACHINE_E8C2)
			uncore->valid_events = sic_MCM_e8c2_valid_events;
		else
			BUG();

		uncore->pmu.attr_groups = e2k_sic_MCM_attr_group;

		snprintf(uncore->name, UNCORE_PMU_NAME_LEN, "sic_%d_MCM", i);

		e2k_uncore_sic[i] = uncore;
		perf_pmu_register(&uncore->pmu, uncore->name, -1);
	}

	return 0;
}
