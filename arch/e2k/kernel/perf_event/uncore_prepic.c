/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/list.h>
#include <linux/perf_event.h>
#include <linux/nodemask.h>
#include <linux/slab.h>
#include <asm/nbsr_v6_regs.h>
#include <asm/sic_regs.h>
#include <asm/perf_event_uncore.h>

static struct e2k_uncore *e2k_uncore_prepic[MAX_NUMNODES];

typedef union {
	struct {
		u64 event	: 8;
		u64 counter	: 1;
		u64 id		: 16;
		u64 __unused	: 39;
	};
	u64 word;
} prepic_config_attr_t;

PMU_FORMAT_ATTR(event, "config:0-7");
/* 1 bit reserved for software setting of used counter */
PMU_FORMAT_ATTR(id, "config:9-24");

static struct attribute *prepic_mcr_format_attr[] = {
	&format_attr_event.attr,
	&format_attr_id.attr,
	NULL,
};

static struct e2k_uncore_valid_events prepic_mcr_valid_events[] = {
	{ 0, 7 },
	{ -1, -1}
};

static struct attribute_group prepic_mcr_format_group = {
	.name = "format",
	.attrs = prepic_mcr_format_attr,
};

static const struct attribute_group *prepic_mcr_attr_group[] = {
	&prepic_mcr_format_group,
	&e2k_cpumask_attr_group,
	NULL,
};

static u64 get_prepic_str_cnt(struct e2k_uncore *uncore,
			      struct hw_perf_event *hwc)
{
	u32 mar_lo = 0, mar_hi = 0;
	prepic_config_attr_t config = { .word = hwc->config };
	int node = uncore->node;
	u64 val;

	switch (config.counter) {
	case 0:
		do {
			mar_hi = sic_read_node_nbsr_reg(node, PREPIC_MAR0_HI);
			mar_lo = sic_read_node_nbsr_reg(node, PREPIC_MAR0_LO);
		} while (mar_hi != sic_read_node_nbsr_reg(node, PREPIC_MAR0_HI));
		break;
	case 1:
		do {
			mar_hi = sic_read_node_nbsr_reg(node, PREPIC_MAR1_HI);
			mar_lo = sic_read_node_nbsr_reg(node, PREPIC_MAR1_LO);
		} while (mar_hi != sic_read_node_nbsr_reg(node, PREPIC_MAR1_HI));
		break;
	}

	val = ((u64) mar_hi << 32UL) | (u64) mar_lo;

	pr_debug("hw_event %px: get_cnt %lld\n", hwc, val);

	return val;
}

static void modify_mid(int node, prepic_config_attr_t config)
{
	e2k_prepic_mid_t mid;

	AW(mid) = sic_read_node_nbsr_reg(node, PREPIC_MID);
	if (config.counter)
		mid.id1 = config.id;
	else
		mid.id0 = config.id;
	sic_write_node_nbsr_reg(node, PREPIC_MID, AW(mid));
}

static void modify_mcr(int node, prepic_config_attr_t config, bool enable)
{
	e2k_prepic_mcr_t mcr;

	AW(mcr) = sic_read_node_nbsr_reg(node, PREPIC_MCR);
	if (config.counter) {
		mcr.vc1 = !!enable;
		mcr.es1 = config.event;
	} else {
		mcr.vc0 = !!enable;
		mcr.es0 = config.event;
	}
	sic_write_node_nbsr_reg(node, PREPIC_MCR, AW(mcr));

	pr_debug("set_cfg 0x%x\n", AW(mcr));
}

static void set_prepic_str_cfg(struct e2k_uncore *uncore,
			       struct hw_perf_event *hwc, bool enable)
{
	prepic_config_attr_t config = { .word = hwc->config };
	int node = uncore->node;

	if (enable) {
		modify_mid(node, config);
		modify_mcr(node, config, enable);
	} else {
		modify_mcr(node, config, enable);
		modify_mid(node, config);
	}
}

static void set_prepic_str_cnt(struct e2k_uncore *uncore,
			       struct hw_perf_event *hwc, u64 val)
{
	u32 mar_lo, mar_hi;
	prepic_config_attr_t config = { .word = hwc->config };
	int node = uncore->node;

	mar_lo = val;
	mar_hi = val >> 32;

	switch (config.counter) {
	case 0:
		sic_write_node_nbsr_reg(node, PREPIC_MAR0_LO, mar_lo);
		sic_write_node_nbsr_reg(node, PREPIC_MAR0_HI, mar_hi);
		break;
	case 1:
		sic_write_node_nbsr_reg(node, PREPIC_MAR1_LO, mar_lo);
		sic_write_node_nbsr_reg(node, PREPIC_MAR1_HI, mar_hi);
		break;
	}

	pr_debug("hw_event %px: set_cnt %lld\n", hwc, val);
}


static struct e2k_uncore_reg_ops prepic_reg_ops = {
	.get_cnt = get_prepic_str_cnt,
	.set_cfg = set_prepic_str_cfg,
	.set_cnt = set_prepic_str_cnt,
};

static u64 prepic_get_event(struct hw_perf_event *hwc)
{
	prepic_config_attr_t config = { .word = hwc->config };

	return config.event;
}

static int prepic_add_event(struct e2k_uncore *uncore, struct perf_event *event)
{
	prepic_config_attr_t config = { .word = event->hw.config }, config2;
	int i, empty_slot = -1, used_counter = -1;

	/* validate against running counters */
	for (i = 0; i < uncore->num_counters; i++) {
		struct perf_event *event2 = READ_ONCE(uncore->events[i]);

		if (!event2) {
			empty_slot = i;
			continue;
		}

		AW(config2) = event2->hw.config;
		used_counter = config2.counter;
	}

	/* take the first available slot */
	if (empty_slot == -1)
		return -ENOSPC;

	config.counter = !used_counter;
	event->hw.config = AW(config);

	if (cmpxchg(&uncore->events[empty_slot], NULL, event) != NULL)
		return -ENOSPC;

	event->hw.idx = empty_slot;

	return 0;
}

int __init register_prepic_pmus()
{
	int i, counters = 2;

	for_each_online_node(i) {
		struct e2k_uncore *uncore = kzalloc(sizeof(struct e2k_uncore) +
				counters * sizeof(void *), GFP_KERNEL);
		if (!uncore)
			return -ENOMEM;

		uncore->type = E2K_UNCORE_PREPIC;

		uncore->pmu.event_init	= e2k_uncore_event_init;
		uncore->pmu.task_ctx_nr	= perf_invalid_context;
		uncore->pmu.add		= e2k_uncore_add;
		uncore->pmu.del		= e2k_uncore_del;
		uncore->pmu.start	= e2k_uncore_start;
		uncore->pmu.stop	= e2k_uncore_stop;
		uncore->pmu.read	= e2k_uncore_read;

		uncore->get_event = prepic_get_event;
		uncore->add_event = prepic_add_event;

		uncore->reg_ops = &prepic_reg_ops;
		uncore->num_counters = counters;

		uncore->node = i;

		uncore->valid_events = prepic_mcr_valid_events;
		uncore->pmu.attr_groups = prepic_mcr_attr_group;

		snprintf(uncore->name, UNCORE_PMU_NAME_LEN,
				"uncore_prepic_%d", i);

		e2k_uncore_prepic[i] = uncore;
		perf_pmu_register(&uncore->pmu, uncore->name, -1);
	}

	return 0;
}
