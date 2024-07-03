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

static struct e2k_uncore *e2k_uncore_iommu[MAX_NUMNODES];

typedef union {
	struct {
		u64 event	: 8;
		u64 counter	: 1;
		u64 id		: 16;
		u64 iommu_mask	: 7;
		u64 __unused	: 32;
	};
	u64 word;
} iommu_config_attr_t;

PMU_FORMAT_ATTR(event, "config:0-7");
/* 1 bit reserved for software setting of used counter */
PMU_FORMAT_ATTR(id, "config:9-24");
PMU_FORMAT_ATTR(iommu_mask, "config:25-31");

static struct attribute *iommu_mcr_format_attr[] = {
	&format_attr_event.attr,
	&format_attr_id.attr,
	&format_attr_iommu_mask.attr,
	NULL,
};

static struct e2k_uncore_valid_events iommu_mcr_valid_events[] = {
	{ 0x0, 0x19 },
	{ 0x20, 0x21 },
	{ -1, -1}
};

static struct attribute_group iommu_mcr_format_group = {
	.name = "format",
	.attrs = iommu_mcr_format_attr,
};

static const struct attribute_group *iommu_mcr_attr_group[] = {
	&iommu_mcr_format_group,
	&e2k_cpumask_attr_group,
	NULL,
};

static u64 get_iommu_str_cnt(struct e2k_uncore *uncore, struct hw_perf_event *hwc)
{
	u32 mar_lo = 0, mar_hi = 0, mar26_lo = 0, mar26_hi = 0,
	    mar27_lo = 0, mar27_hi = 0, mar28_lo = 0, mar28_hi = 0,
	    mar29_lo = 0, mar29_hi = 0, mar30_lo = 0, mar30_hi = 0,
	    mar31_lo = 0, mar31_hi = 0;
	iommu_config_attr_t config = { .word = hwc->config };
	u64 val, iommu_mask = config.iommu_mask;
	int node = uncore->node;
	bool trace0, trace26, trace27, trace28, trace29, trace30, trace31;

	if (READ_IDR_REG().mdl == IDR_E2C3_MDL) {
		trace0 = !iommu_mask || (iommu_mask & 0x1);
		trace26 = !iommu_mask || (iommu_mask & 0x2);
		trace27 = !iommu_mask || (iommu_mask & 0x4);
		trace28 = !iommu_mask || (iommu_mask & 0x8);
		trace29 = !iommu_mask || (iommu_mask & 0x10);
		trace30 = !iommu_mask || (iommu_mask & 0x20);
		trace31 = !iommu_mask || (iommu_mask & 0x40);
	} else {
		trace0 = true;
		trace26 = trace27 = trace28 = trace29 = trace30 = trace31 = false;
	}

	switch (config.counter) {
	case 0:
		do {
			if (!trace0)
				break;
			mar_hi = sic_read_node_nbsr_reg(node, IOMMU_MAR0_HI);
			mar_lo = sic_read_node_nbsr_reg(node, IOMMU_MAR0_LO);
		} while (mar_hi != sic_read_node_nbsr_reg(node, IOMMU_MAR0_HI));
		do {
			if (!trace26)
				break;
			mar26_hi = sic_read_node_nbsr_reg(node, ED26_IOMMU_MAR0_HI);
			mar26_lo = sic_read_node_nbsr_reg(node, ED26_IOMMU_MAR0_LO);
		} while (mar26_hi != sic_read_node_nbsr_reg(node, ED26_IOMMU_MAR0_HI));
		do {
			if (!trace27)
				break;
			mar27_hi = sic_read_node_nbsr_reg(node, ED27_IOMMU_MAR0_HI);
			mar27_lo = sic_read_node_nbsr_reg(node, ED27_IOMMU_MAR0_LO);
		} while (mar27_hi != sic_read_node_nbsr_reg(node, ED27_IOMMU_MAR0_HI));
		do {
			if (!trace28)
				break;
			mar28_hi = sic_read_node_nbsr_reg(node, ED28_IOMMU_MAR0_HI);
			mar28_lo = sic_read_node_nbsr_reg(node, ED28_IOMMU_MAR0_LO);
		} while (mar28_hi != sic_read_node_nbsr_reg(node, ED28_IOMMU_MAR0_HI));
		do {
			if (!trace29)
				break;
			mar29_hi = sic_read_node_nbsr_reg(node, ED29_IOMMU_MAR0_HI);
			mar29_lo = sic_read_node_nbsr_reg(node, ED29_IOMMU_MAR0_LO);
		} while (mar29_hi != sic_read_node_nbsr_reg(node, ED29_IOMMU_MAR0_HI));
		do {
			if (!trace30)
				break;
			mar30_hi = sic_read_node_nbsr_reg(node, ED30_IOMMU_MAR0_HI);
			mar30_lo = sic_read_node_nbsr_reg(node, ED30_IOMMU_MAR0_LO);
		} while (mar30_hi != sic_read_node_nbsr_reg(node, ED30_IOMMU_MAR0_HI));
		do {
			if (!trace31)
				break;
			mar31_hi = sic_read_node_nbsr_reg(node, ED31_IOMMU_MAR0_HI);
			mar31_lo = sic_read_node_nbsr_reg(node, ED31_IOMMU_MAR0_LO);
		} while (mar31_hi != sic_read_node_nbsr_reg(node, ED31_IOMMU_MAR0_HI));
		break;
	case 1:
		do {
			if (!trace0)
				break;
			mar_hi = sic_read_node_nbsr_reg(node, IOMMU_MAR1_HI);
			mar_lo = sic_read_node_nbsr_reg(node, IOMMU_MAR1_LO);
		} while (mar_hi != sic_read_node_nbsr_reg(node, IOMMU_MAR1_HI));
		do {
			if (!trace26)
				break;
			mar26_hi = sic_read_node_nbsr_reg(node, ED26_IOMMU_MAR1_HI);
			mar26_lo = sic_read_node_nbsr_reg(node, ED26_IOMMU_MAR1_LO);
		} while (mar26_hi != sic_read_node_nbsr_reg(node, ED26_IOMMU_MAR1_HI));
		do {
			if (!trace27)
				break;
			mar27_hi = sic_read_node_nbsr_reg(node, ED27_IOMMU_MAR1_HI);
			mar27_lo = sic_read_node_nbsr_reg(node, ED27_IOMMU_MAR1_LO);
		} while (mar27_hi != sic_read_node_nbsr_reg(node, ED27_IOMMU_MAR1_HI));
		do {
			if (!trace28)
				break;
			mar28_hi = sic_read_node_nbsr_reg(node, ED28_IOMMU_MAR1_HI);
			mar28_lo = sic_read_node_nbsr_reg(node, ED28_IOMMU_MAR1_LO);
		} while (mar28_hi != sic_read_node_nbsr_reg(node, ED28_IOMMU_MAR1_HI));
		do {
			if (!trace29)
				break;
			mar29_hi = sic_read_node_nbsr_reg(node, ED29_IOMMU_MAR1_HI);
			mar29_lo = sic_read_node_nbsr_reg(node, ED29_IOMMU_MAR1_LO);
		} while (mar29_hi != sic_read_node_nbsr_reg(node, ED29_IOMMU_MAR1_HI));
		do {
			if (!trace30)
				break;
			mar30_hi = sic_read_node_nbsr_reg(node, ED30_IOMMU_MAR1_HI);
			mar30_lo = sic_read_node_nbsr_reg(node, ED30_IOMMU_MAR1_LO);
		} while (mar30_hi != sic_read_node_nbsr_reg(node, ED30_IOMMU_MAR1_HI));
		do {
			if (!trace31)
				break;
			mar31_hi = sic_read_node_nbsr_reg(node, ED31_IOMMU_MAR1_HI);
			mar31_lo = sic_read_node_nbsr_reg(node, ED31_IOMMU_MAR1_LO);
		} while (mar31_hi != sic_read_node_nbsr_reg(node, ED31_IOMMU_MAR1_HI));
		break;
	}

	val = 0;

	if (trace0)
		val += ((u64) mar_hi << 32UL) | (u64) mar_lo;
	if (trace26)
		val += ((u64) mar26_hi << 32UL) | (u64) mar26_lo;
	if (trace27)
		val += ((u64) mar27_hi << 32UL) | (u64) mar27_lo;
	if (trace28)
		val += ((u64) mar28_hi << 32UL) | (u64) mar28_lo;
	if (trace29)
		val += ((u64) mar29_hi << 32UL) | (u64) mar29_lo;
	if (trace30)
		val += ((u64) mar30_hi << 32UL) | (u64) mar30_lo;
	if (trace31)
		val += ((u64) mar31_hi << 32UL) | (u64) mar31_lo;

	pr_debug("hw_event %px: get_cnt %lld\n", hwc, val);

	return val;
}

static void modify_mid(int mid_reg, int node, iommu_config_attr_t config)
{
	e2k_iommu_mid_t mid;

	AW(mid) = sic_read_node_nbsr_reg(node, mid_reg);
	if (config.counter)
		mid.id1 = config.id;
	else
		mid.id0 = config.id;
	sic_write_node_nbsr_reg(node, mid_reg, AW(mid));
}

static void modify_mcr(int mcr_reg, int node,
		iommu_config_attr_t config, bool enable)
{
	e2k_iommu_mcr_t mcr;

	AW(mcr) = sic_read_node_nbsr_reg(node, mcr_reg);
	if (config.counter) {
		mcr.v1 = !!enable;
		mcr.es1 = config.event;
	} else {
		mcr.v0 = !!enable;
		mcr.es0 = config.event;
	}
	sic_write_node_nbsr_reg(node, mcr_reg, AW(mcr));

	pr_debug("set_cfg 0x%x\n", AW(mcr));
}

static void modify_mid_mcr(int mid_reg, int mcr_reg, int node,
		iommu_config_attr_t config, bool enable)
{
	if (enable) {
		modify_mid(mid_reg, node, config);
		modify_mcr(mcr_reg, node, config, enable);
	} else {
		modify_mcr(mcr_reg, node, config, enable);
		modify_mid(mid_reg, node, config);
	}
}

static void set_iommu_str_cfg(struct e2k_uncore *uncore,
		struct hw_perf_event *hwc, bool enable)
{
	iommu_config_attr_t config = { .word = hwc->config };
	u64 iommu_mask = config.iommu_mask;
	int node = uncore->node;
	bool trace0, trace26, trace27, trace28, trace29, trace30, trace31;

	if (READ_IDR_REG().mdl == IDR_E2C3_MDL) {
		trace0 = !iommu_mask || (iommu_mask & 0x1);
		trace26 = !iommu_mask || (iommu_mask & 0x2);
		trace27 = !iommu_mask || (iommu_mask & 0x4);
		trace28 = !iommu_mask || (iommu_mask & 0x8);
		trace29 = !iommu_mask || (iommu_mask & 0x10);
		trace30 = !iommu_mask || (iommu_mask & 0x20);
		trace31 = !iommu_mask || (iommu_mask & 0x40);
	} else {
		trace0 = true;
		trace26 = trace27 = trace28 = trace29 = trace30 = trace31 = false;
	}

	if (trace0)
		modify_mid_mcr(IOMMU_MID, IOMMU_MCR, node, config, enable);
	if (trace26)
		modify_mid_mcr(ED26_IOMMU_MID, ED26_IOMMU_MCR, node, config, enable);
	if (trace27)
		modify_mid_mcr(ED27_IOMMU_MID, ED27_IOMMU_MCR, node, config, enable);
	if (trace28)
		modify_mid_mcr(ED28_IOMMU_MID, ED28_IOMMU_MCR, node, config, enable);
	if (trace29)
		modify_mid_mcr(ED29_IOMMU_MID, ED29_IOMMU_MCR, node, config, enable);
	if (trace30)
		modify_mid_mcr(ED30_IOMMU_MID, ED30_IOMMU_MCR, node, config, enable);
	if (trace31)
		modify_mid_mcr(ED31_IOMMU_MID, ED31_IOMMU_MCR, node, config, enable);
}

static void set_iommu_str_cnt(struct e2k_uncore *uncore,
			    struct hw_perf_event *hwc, u64 val)
{
	u32 mar_lo = 0, mar_hi = 0, mar26_lo = 0, mar26_hi = 0,
	    mar27_lo = 0, mar27_hi = 0, mar28_lo = 0, mar28_hi = 0,
	    mar29_lo = 0, mar29_hi = 0, mar30_lo = 0, mar30_hi = 0,
	    mar31_lo = 0, mar31_hi = 0;
	iommu_config_attr_t config = { .word = hwc->config };
	u64 iommu_mask = config.iommu_mask;
	int node = uncore->node;
	bool trace0, trace26, trace27, trace28, trace29, trace30, trace31;

	if (READ_IDR_REG().mdl == IDR_E2C3_MDL) {
		trace0 = !iommu_mask || (iommu_mask & 0x1);
		trace26 = !iommu_mask || (iommu_mask & 0x2);
		trace27 = !iommu_mask || (iommu_mask & 0x4);
		trace28 = !iommu_mask || (iommu_mask & 0x8);
		trace29 = !iommu_mask || (iommu_mask & 0x10);
		trace30 = !iommu_mask || (iommu_mask & 0x20);
		trace31 = !iommu_mask || (iommu_mask & 0x40);
	} else {
		trace0 = true;
		trace26 = trace27 = trace28 = trace29 = trace30 = trace31 = false;
	}

	/* Use any IOMMU enabled in config, it doesn't matter which one */
	if (trace0) {
		mar_lo = val;
		mar_hi = val >> 32;
	} else if (trace26) {
		mar26_lo = val;
		mar26_hi = val >> 32;
	} else if (trace27) {
		mar27_lo = val;
		mar27_hi = val >> 32;
	} else if (trace28) {
		mar28_lo = val;
		mar28_hi = val >> 32;
	} else if (trace29) {
		mar29_lo = val;
		mar29_hi = val >> 32;
	} else if (trace30) {
		mar30_lo = val;
		mar30_hi = val >> 32;
	} else {
		mar31_lo = val;
		mar31_hi = val >> 32;
	}

	switch (config.counter) {
	case 0:
		sic_write_node_nbsr_reg(node, IOMMU_MAR0_LO, mar_lo);
		sic_write_node_nbsr_reg(node, IOMMU_MAR0_HI, mar_hi);

		if (READ_IDR_REG().mdl != IDR_E2C3_MDL)
			break;

		sic_write_node_nbsr_reg(node, ED26_IOMMU_MAR0_LO, mar26_lo);
		sic_write_node_nbsr_reg(node, ED26_IOMMU_MAR0_HI, mar26_hi);
		sic_write_node_nbsr_reg(node, ED27_IOMMU_MAR0_LO, mar27_lo);
		sic_write_node_nbsr_reg(node, ED27_IOMMU_MAR0_HI, mar27_hi);
		sic_write_node_nbsr_reg(node, ED28_IOMMU_MAR0_LO, mar28_lo);
		sic_write_node_nbsr_reg(node, ED28_IOMMU_MAR0_HI, mar28_hi);
		sic_write_node_nbsr_reg(node, ED29_IOMMU_MAR0_LO, mar29_lo);
		sic_write_node_nbsr_reg(node, ED29_IOMMU_MAR0_HI, mar29_hi);
		sic_write_node_nbsr_reg(node, ED30_IOMMU_MAR0_LO, mar30_lo);
		sic_write_node_nbsr_reg(node, ED30_IOMMU_MAR0_HI, mar30_hi);
		sic_write_node_nbsr_reg(node, ED31_IOMMU_MAR0_LO, mar31_lo);
		sic_write_node_nbsr_reg(node, ED31_IOMMU_MAR0_HI, mar31_hi);
		break;
	case 1:
		sic_write_node_nbsr_reg(node, IOMMU_MAR1_LO, mar_lo);
		sic_write_node_nbsr_reg(node, IOMMU_MAR1_HI, mar_hi);

		if (READ_IDR_REG().mdl != IDR_E2C3_MDL)
			break;

		sic_write_node_nbsr_reg(node, ED26_IOMMU_MAR1_LO, mar26_lo);
		sic_write_node_nbsr_reg(node, ED26_IOMMU_MAR1_HI, mar26_hi);
		sic_write_node_nbsr_reg(node, ED27_IOMMU_MAR1_LO, mar27_lo);
		sic_write_node_nbsr_reg(node, ED27_IOMMU_MAR1_HI, mar27_hi);
		sic_write_node_nbsr_reg(node, ED28_IOMMU_MAR1_LO, mar28_lo);
		sic_write_node_nbsr_reg(node, ED28_IOMMU_MAR1_HI, mar28_hi);
		sic_write_node_nbsr_reg(node, ED29_IOMMU_MAR1_LO, mar29_lo);
		sic_write_node_nbsr_reg(node, ED29_IOMMU_MAR1_HI, mar29_hi);
		sic_write_node_nbsr_reg(node, ED30_IOMMU_MAR1_LO, mar30_lo);
		sic_write_node_nbsr_reg(node, ED30_IOMMU_MAR1_HI, mar30_hi);
		sic_write_node_nbsr_reg(node, ED31_IOMMU_MAR1_LO, mar31_lo);
		sic_write_node_nbsr_reg(node, ED31_IOMMU_MAR1_HI, mar31_hi);
		break;
	}

	pr_debug("hw_event %px: set_cnt %lld\n", hwc, val);
}


static struct e2k_uncore_reg_ops iommu_reg_ops = {
	.get_cnt = get_iommu_str_cnt,
	.set_cfg = set_iommu_str_cfg,
	.set_cnt = set_iommu_str_cnt,
};

static u64 iommu_get_event(struct hw_perf_event *hwc)
{
	iommu_config_attr_t config = { .word = hwc->config };

	return config.event;
}


static int iommu_validate_event(struct e2k_uncore *uncore,
		struct hw_perf_event *hwc)
{
	iommu_config_attr_t config = { .word = hwc->config };

	if (READ_IDR_REG().mdl != IDR_E2C3_MDL && config.iommu_mask &&
			(config.iommu_mask & ~1ull)) {
		pr_info_ratelimited("uncore_iommu: IOMMU{26-31} registers exist only on e2c3\n");
		return -EINVAL;
	}

	return 0;
}

static int iommu_add_event(struct e2k_uncore *uncore, struct perf_event *event)
{
	iommu_config_attr_t config = { .word = event->hw.config }, config2;
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

int __init register_iommu_pmus()
{
	int i, counters = 2;

	for_each_online_node(i) {
		struct e2k_uncore *uncore = kzalloc(sizeof(struct e2k_uncore) +
				counters * sizeof(void *), GFP_KERNEL);
		if (!uncore)
			return -ENOMEM;

		uncore->type = E2K_UNCORE_IOMMU;

		uncore->pmu.event_init	= e2k_uncore_event_init;
		uncore->pmu.task_ctx_nr	= perf_invalid_context;
		uncore->pmu.add		= e2k_uncore_add;
		uncore->pmu.del		= e2k_uncore_del;
		uncore->pmu.start	= e2k_uncore_start;
		uncore->pmu.stop	= e2k_uncore_stop;
		uncore->pmu.read	= e2k_uncore_read;

		uncore->get_event = iommu_get_event;
		uncore->add_event = iommu_add_event;
		uncore->validate_event = iommu_validate_event;

		uncore->reg_ops = &iommu_reg_ops;
		uncore->num_counters = counters;

		uncore->node = i;

		uncore->valid_events = iommu_mcr_valid_events;
		uncore->pmu.attr_groups = iommu_mcr_attr_group;

		snprintf(uncore->name, UNCORE_PMU_NAME_LEN,
				"uncore_iommu_%d", i);

		e2k_uncore_iommu[i] = uncore;
		perf_pmu_register(&uncore->pmu, uncore->name, -1);
	}

	return 0;
}
