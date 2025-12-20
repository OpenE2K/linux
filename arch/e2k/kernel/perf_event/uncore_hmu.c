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

static struct e2k_uncore *e2k_uncore_hmu[MAX_NUMNODES];

typedef union {
	struct {
		u64 event	: 8;
		u64 counter	: 1;
		u64 flt0_off	: 1;
		u64 flt0_rqid	: 7;
		u64 flt0_cid	: 1;
		u64 flt0_bid	: 1;
		u64 flt0_xid	: 1;
		u64 flt1_off	: 1;
		u64 flt1_node	: 2;
		u64 flt1_rnode	: 1;
		u64 hmu_mask	: 4;
		u64 __unused	: 36;
	};
	u64 word;
} hmu_config_attr_t;

PMU_FORMAT_ATTR(event, "config:0-7");
PMU_FORMAT_ATTR(counter, "config:8");
PMU_FORMAT_ATTR(flt0_off, "config:9");
PMU_FORMAT_ATTR(flt0_rqid, "config:10-16");
PMU_FORMAT_ATTR(flt0_cid, "config:17");
PMU_FORMAT_ATTR(flt0_bid, "config:18");
PMU_FORMAT_ATTR(flt0_xid, "config:19");
PMU_FORMAT_ATTR(flt1_off, "config:20");
PMU_FORMAT_ATTR(flt1_node, "config:21-22");
PMU_FORMAT_ATTR(flt1_rnode, "config:23");
PMU_FORMAT_ATTR(hmu_mask, "config:24-27");

static struct attribute *hmu_mcr_format_attr[] = {
	&format_attr_event.attr,
	&format_attr_counter.attr,
	&format_attr_flt0_off.attr,
	&format_attr_flt0_rqid.attr,
	&format_attr_flt0_cid.attr,
	&format_attr_flt0_bid.attr,
	&format_attr_flt0_xid.attr,
	&format_attr_flt1_off.attr,
	&format_attr_flt1_node.attr,
	&format_attr_flt1_rnode.attr,
	&format_attr_hmu_mask.attr,
	NULL,
};

enum {
	MCM0 = 0,
	MCM1,
};


static struct attribute_group hmu_mcr_format_group = {
	.name = "format",
	.attrs = hmu_mcr_format_attr,
};

static const struct attribute_group *hmu_mcr_attr_group[] = {
	&hmu_mcr_format_group,
	&e2k_cpumask_attr_group,
	NULL,
};

static u64 get_hmu_str_cnt(struct e2k_uncore *uncore, struct hw_perf_event *hwc)
{
	u32 hmu0_mar_lo = 0, hmu0_mar_hi = 0, hmu1_mar_lo = 0, hmu1_mar_hi = 0,
	    hmu2_mar_lo = 0, hmu2_mar_hi = 0, hmu3_mar_lo = 0, hmu3_mar_hi = 0;
	hmu_config_attr_t config = { .word = hwc->config };
	u64 val, hmu_mask = config.hmu_mask;
	int node = uncore->node;
	int trace0 = (!hmu_mask || (hmu_mask & 1)),
	    trace1 = (!hmu_mask || (hmu_mask & 2)),
	    trace2 = (!hmu_mask || (hmu_mask & 4)),
	    trace3 = (!hmu_mask || (hmu_mask & 8));

	switch (config.counter) {
	case 0:
		do {
			if (!trace0)
				break;
			hmu0_mar_hi = sic_read_node_nbsr_reg(node, HMU0_MAR0_HI);
			hmu0_mar_lo = sic_read_node_nbsr_reg(node, HMU0_MAR0_LO);
		} while (hmu0_mar_hi != sic_read_node_nbsr_reg(node, HMU0_MAR0_HI));

		if (READ_IDR_REG().mdl == IDR_E2C3_MDL)
			break;

		do {
			if (!trace1)
				break;
			hmu1_mar_hi = sic_read_node_nbsr_reg(node, HMU1_MAR0_HI);
			hmu1_mar_lo = sic_read_node_nbsr_reg(node, HMU1_MAR0_LO);
		} while (hmu1_mar_hi != sic_read_node_nbsr_reg(node, HMU1_MAR0_HI));
		do {
			if (!trace2)
				break;
			hmu2_mar_hi = sic_read_node_nbsr_reg(node, HMU2_MAR0_HI);
			hmu2_mar_lo = sic_read_node_nbsr_reg(node, HMU2_MAR0_LO);
		} while (hmu2_mar_hi != sic_read_node_nbsr_reg(node, HMU2_MAR0_HI));
		do {
			if (!trace3)
				break;
			hmu3_mar_hi = sic_read_node_nbsr_reg(node, HMU3_MAR0_HI);
			hmu3_mar_lo = sic_read_node_nbsr_reg(node, HMU3_MAR0_LO);
		} while (hmu3_mar_hi != sic_read_node_nbsr_reg(node, HMU3_MAR0_HI));
		break;
	case 1:
		do {
			if (!trace0)
				break;
			hmu0_mar_hi = sic_read_node_nbsr_reg(node, HMU0_MAR1_HI);
			hmu0_mar_lo = sic_read_node_nbsr_reg(node, HMU0_MAR1_LO);
		} while (hmu0_mar_hi != sic_read_node_nbsr_reg(node, HMU0_MAR1_HI));

		if (READ_IDR_REG().mdl == IDR_E2C3_MDL)
			break;

		do {
			if (!trace1)
				break;
			hmu1_mar_hi = sic_read_node_nbsr_reg(node, HMU1_MAR1_HI);
			hmu1_mar_lo = sic_read_node_nbsr_reg(node, HMU1_MAR1_LO);
		} while (hmu1_mar_hi != sic_read_node_nbsr_reg(node, HMU1_MAR1_HI));
		do {
			if (!trace2)
				break;
			hmu2_mar_hi = sic_read_node_nbsr_reg(node, HMU2_MAR1_HI);
			hmu2_mar_lo = sic_read_node_nbsr_reg(node, HMU2_MAR1_LO);
		} while (hmu2_mar_hi != sic_read_node_nbsr_reg(node, HMU2_MAR1_HI));
		do {
			if (!trace3)
				break;
			hmu3_mar_hi = sic_read_node_nbsr_reg(node, HMU3_MAR1_HI);
			hmu3_mar_lo = sic_read_node_nbsr_reg(node, HMU3_MAR1_LO);
		} while (hmu3_mar_hi != sic_read_node_nbsr_reg(node, HMU3_MAR1_HI));
		break;
	}

	val = 0;

	if (trace0)
		val += ((u64) hmu0_mar_hi << 32UL) | (u64) hmu0_mar_lo;
	if (trace1)
		val += ((u64) hmu1_mar_hi << 32UL) | (u64) hmu1_mar_lo;
	if (trace2)
		val += ((u64) hmu2_mar_hi << 32UL) | (u64) hmu2_mar_lo;
	if (trace3)
		val += ((u64) hmu3_mar_hi << 32UL) | (u64) hmu3_mar_lo;

	pr_debug("hw_event %px: get_cnt %lld\n", hwc, val);

	return val;
}

static void set_hmu_str_cfg(struct e2k_uncore *uncore,
		struct hw_perf_event *hwc, bool enable)
{
	int node = uncore->node;
	hmu_config_attr_t config = { .word = hwc->config };
	u64 event = config.event;
	e2k_hmu_mcr_t mcr;

	AW(mcr) = sic_read_node_nbsr_reg(node, HMU_MCR);

	mcr.flt0_off = config.flt0_off;
	mcr.flt0_rqid = config.flt0_rqid;
	mcr.flt0_cid = config.flt0_cid;
	mcr.flt0_bid = config.flt0_bid;
	mcr.flt0_xid = config.flt0_xid;
	mcr.flt1_off = config.flt1_off;
	mcr.flt1_node = config.flt1_node;
	mcr.flt1_rnode = config.flt1_rnode;

	switch (config.counter) {
	case 0:
		mcr.v0 = !!enable;
		mcr.es0 = event;
		break;
	case 1:
		mcr.v1 = !!enable;
		mcr.es1 = event;
		break;
	}

	sic_write_node_nbsr_reg(node, HMU_MCR, AW(mcr));

	pr_debug("hw_event %px: set_cfg 0x%x\n", hwc, AW(mcr));
}

static void set_hmu_str_cnt(struct e2k_uncore *uncore,
			    struct hw_perf_event *hwc, u64 val)
{
	u32 hmu0_mar_lo = 0, hmu0_mar_hi = 0, hmu1_mar_lo = 0, hmu1_mar_hi = 0,
	    hmu2_mar_lo = 0, hmu2_mar_hi = 0, hmu3_mar_lo = 0, hmu3_mar_hi = 0;
	hmu_config_attr_t config = { .word = hwc->config };
	u64 hmu_mask = config.hmu_mask;
	int node = uncore->node;
	int trace0 = (!hmu_mask || (hmu_mask & 1)),
	    trace1 = (!hmu_mask || (hmu_mask & 2)),
	    trace2 = (!hmu_mask || (hmu_mask & 4));

	/* Use any counter enabled in config, it doesn't matter which one */
	if (trace0) {
		hmu0_mar_lo = val;
		hmu0_mar_hi = val >> 32;
	} else if (trace1) {
		hmu1_mar_lo = val;
		hmu1_mar_hi = val >> 32;
	} else if (trace2) {
		hmu2_mar_lo = val;
		hmu2_mar_hi = val >> 32;
	} else {
		hmu3_mar_lo = val;
		hmu3_mar_hi = val >> 32;
	}

	switch (config.counter) {
	case 0:
		sic_write_node_nbsr_reg(node, HMU0_MAR0_LO, hmu0_mar_lo);
		sic_write_node_nbsr_reg(node, HMU0_MAR0_HI, hmu0_mar_hi);

		if (READ_IDR_REG().mdl == IDR_E2C3_MDL)
			break;

		sic_write_node_nbsr_reg(node, HMU1_MAR0_LO, hmu1_mar_lo);
		sic_write_node_nbsr_reg(node, HMU1_MAR0_HI, hmu1_mar_hi);
		sic_write_node_nbsr_reg(node, HMU2_MAR0_LO, hmu2_mar_lo);
		sic_write_node_nbsr_reg(node, HMU2_MAR0_HI, hmu2_mar_hi);
		sic_write_node_nbsr_reg(node, HMU3_MAR0_LO, hmu3_mar_lo);
		sic_write_node_nbsr_reg(node, HMU3_MAR0_HI, hmu3_mar_hi);
		break;
	case 1:
		sic_write_node_nbsr_reg(node, HMU0_MAR1_LO, hmu0_mar_lo);
		sic_write_node_nbsr_reg(node, HMU0_MAR1_HI, hmu0_mar_hi);

		if (READ_IDR_REG().mdl == IDR_E2C3_MDL)
			break;

		sic_write_node_nbsr_reg(node, HMU1_MAR1_LO, hmu1_mar_lo);
		sic_write_node_nbsr_reg(node, HMU1_MAR1_HI, hmu1_mar_hi);
		sic_write_node_nbsr_reg(node, HMU2_MAR1_LO, hmu2_mar_lo);
		sic_write_node_nbsr_reg(node, HMU2_MAR1_HI, hmu2_mar_hi);
		sic_write_node_nbsr_reg(node, HMU3_MAR1_LO, hmu3_mar_lo);
		sic_write_node_nbsr_reg(node, HMU3_MAR1_HI, hmu3_mar_hi);
		break;
	}

	pr_debug("hw_event %px: set_cnt %lld\n", hwc, val);
}


static struct e2k_uncore_reg_ops hmu_reg_ops = {
	.get_cnt = get_hmu_str_cnt,
	.set_cfg = set_hmu_str_cfg,
	.set_cnt = set_hmu_str_cnt,
};

static u64 hmu_get_event(struct hw_perf_event *hwc)
{
	hmu_config_attr_t config = { .word = hwc->config };

	return config.event;
}

static struct e2k_uncore_valid_events hmu_mcr_valid_events[] = {
	{ 0x0, 0x23 },
	{ -1, -1}
};

static int hmu_validate_event(struct e2k_uncore *uncore,
		struct hw_perf_event *hwc)
{
	hmu_config_attr_t config = { .word = hwc->config };
	u64 event = config.event;

	if (config.counter == 0 && event == 0x23 ||
	    config.counter == 1 && event == 0x20)
		return -EINVAL;

	if (READ_IDR_REG().mdl != IDR_E2C3_MDL && event == 0xd) {
		pr_info_ratelimited("uncore_hmu: event 0xd exists on e2c3 only\n");
		return -EINVAL;
	}

	if (READ_IDR_REG().mdl != IDR_E2C3_MDL && config.hmu_mask &&
			(config.hmu_mask & ~1ull)) {
		pr_info_ratelimited("uncore_hmu: there are no HMU{1-3} registers on e2c3\n");
		return -EINVAL;
	}

	return 0;
}

static int hmu_add_event(struct e2k_uncore *uncore, struct perf_event *event)
{
	hmu_config_attr_t config = { .word = event->hw.config };
	int i;

	/* validate against running counters */
	for (i = 0; i < uncore->num_counters; i++) {
		struct perf_event *event2 = READ_ONCE(uncore->events[i]);
		hmu_config_attr_t config2;

		if (!event2)
			continue;

		AW(config2) = event2->hw.config;

		/*
		 * Check that there is no conflict with same counter in HMU
		 */
		if (config.counter == config2.counter)
			return -ENOSPC;

		if (config.flt0_off || config2.flt0_off) {
			/* Must use the same configuration */
			if (config.flt0_off != config2.flt0_off ||
			    config.flt0_rqid != config2.flt0_rqid ||
			    config.flt0_cid != config2.flt0_cid ||
			    config.flt0_bid != config2.flt0_bid ||
			    config.flt0_xid != config2.flt0_xid)
				return -ENOSPC;
		}

		if (config.flt1_off || config2.flt1_off) {
			/* Must use the same configuration */
			if (config.flt1_node != config2.flt1_node ||
			    config.flt1_rnode != config2.flt1_rnode)
				return -ENOSPC;
		}
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

int __init register_hmu_pmus()
{
	int i, counters = 2;

	for_each_online_node(i) {
		struct e2k_uncore *uncore = kzalloc(sizeof(struct e2k_uncore) +
				counters * sizeof(void *), GFP_KERNEL);
		if (!uncore)
			return -ENOMEM;

		uncore->type = E2K_UNCORE_HMU;

		uncore->pmu.event_init	= e2k_uncore_event_init,
		uncore->pmu.task_ctx_nr	= perf_invalid_context,
		uncore->pmu.add		= e2k_uncore_add;
		uncore->pmu.del		= e2k_uncore_del;
		uncore->pmu.start	= e2k_uncore_start;
		uncore->pmu.stop	= e2k_uncore_stop;
		uncore->pmu.read	= e2k_uncore_read;

		uncore->get_event = hmu_get_event;
		uncore->add_event = hmu_add_event;
		uncore->validate_event = hmu_validate_event;

		uncore->reg_ops = &hmu_reg_ops;
		uncore->num_counters = counters;

		uncore->node = i;

		uncore->valid_events = hmu_mcr_valid_events;
		uncore->pmu.attr_groups = hmu_mcr_attr_group;

		snprintf(uncore->name, UNCORE_PMU_NAME_LEN, "uncore_hmu_%d", i);

		e2k_uncore_hmu[i] = uncore;
		perf_pmu_register(&uncore->pmu, uncore->name, -1);
	}

	return 0;
}
