/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/list.h>
#include <linux/perf_event.h>
#include <linux/nodemask.h>
#include <linux/slab.h>
#include <asm/sic_regs.h>
#include <asm/sic_regs_access.h>
#include <asm/perf_event_uncore.h>


#define perf_ha_dbg(fmt, args...) pr_info("%s: " fmt, __func__, ##args)

/* As it is possuble to have 48HA in V7 there is no enough room
 * in u64 to have a bit for each HA. To solve the problem all HAs devided to 12
 * groups, 4 HAs in each jne. There is one bit for group
 * of 4 HA in ha_mask. So no possibility to monitor a single HA, just a group only
 */
#define GRSZ	8
typedef union {
	struct {
		u64 event	: 8; /* [ 0: 7] */
		u64 counter	: 1; /* [ 8] */
		u64 flt0_off	: 1; /* [ 9] */
		u64 flt0_rqid	: 8; /* [10:17] */
		u64 flt0_cid	: 1; /* [18] */
		u64 flt0_bid	: 1; /* [19] */
		u64 flt0_xid	: 1; /* [20] */
		u64 flt1_off	: 1; /* [21] */
		u64 flt1_node	: 2; /* [22:23] */
		u64 flt1_rnode	: 1; /* [24] */
		u64 ha_mask	: 8; /* [25:32] */
		u64 ha_num	: 6; /* [33:38] */
		u64 ha_all	: 1; /* [39] */
	};
	u64 word;
} ha_config_attr_t;

PMU_FORMAT_ATTR(event,		"config:0-7");
PMU_FORMAT_ATTR(counter,	"config:8");
PMU_FORMAT_ATTR(flt0_off,	"config:9");
PMU_FORMAT_ATTR(flt0_rqid,	"config:10-17");
PMU_FORMAT_ATTR(flt0_cid,	"config:18");
PMU_FORMAT_ATTR(flt0_bid,	"config:19");
PMU_FORMAT_ATTR(flt0_xid,	"config:20");
PMU_FORMAT_ATTR(flt1_off,	"config:21");
PMU_FORMAT_ATTR(flt1_node,	"config:22-23");
PMU_FORMAT_ATTR(flt1_rnode,	"config:24");
PMU_FORMAT_ATTR(ha_mask,	"config:25-32");
PMU_FORMAT_ATTR(ha_num,		"config:33-38");
PMU_FORMAT_ATTR(ha_all,		"config:39");

static struct attribute *ha_mcr_format_attr[] = {
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
	&format_attr_ha_mask.attr,
	&format_attr_ha_num.attr,
	&format_attr_ha_all.attr,
	NULL,
};

enum {
	MCM0 = 0,
	MCM1,
};


static struct attribute_group ha_mcr_format_group = {
	.name = "format",
	.attrs = ha_mcr_format_attr,
};

static const struct attribute_group *ha_mcr_attr_group[] = {
	&ha_mcr_format_group,
	&e2k_cpumask_attr_group,
	NULL,
};




static void set_ha_str_cfg(struct e2k_uncore *uncore,
			    struct hw_perf_event *hwc, bool enable)
{
	int node = uncore->node;
	ha_config_attr_t config = { .word = hwc->config };
	u64 event = config.event;
	e2k_ha_mcr_t mcr;

	AW(mcr) = sic_read_node_nbsr_reg(node, HA_MCR);

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

	sic_write_node_nbsr_reg(node, HA_MCR, AW(mcr));

	pr_debug("hw_event %px: set_cfg 0x%x\n", hwc, AW(mcr));
}
static u64 ha_mask_of_mch(int mch)
{
	switch (mch) {
	case 0: return 0x00000000030fLL;
	case 1: return 0x0000000030f0LL;
	case 2: return 0x000000f0c00fLL;
	case 3: return 0x000000f0c000LL;
	case 4: return 0x00030f000000LL;
	case 5: return 0x0030f0000000LL;
	case 6: return 0x0f0c00000000LL;
	case 7: return 0xf0c000000000LL;
	default: return 0LL;
	}
	return 0LL;
}


static u64 get_ha_mask_of_node(int node, ha_config_attr_t cfg)
{
	int mch;
	u64 ha_mask = 0;
	u64 ha_group_mask;
	u64 enabled_node_ha = (u64)sic_read_node_nbsr_reg(node, OCN_L3EN0) |
			      (u64)sic_read_node_nbsr_reg(node, OCN_L3EN1) << 32;
	enabled_node_ha = ~enabled_node_ha & CURRENT_HA_MASK;
	if (cfg.ha_all) {
		return enabled_node_ha;
	}
	ha_group_mask = cfg.ha_mask;
	if (ha_group_mask ==  0) {
		return (1 << cfg.ha_num) &  enabled_node_ha;
	}
	for (mch = find_first_bit((const unsigned long *)&ha_group_mask, GRSZ);
	     mch < GRSZ;
	     mch = find_next_bit((const unsigned long *)&ha_group_mask, GRSZ, mch + 1)) {
		ha_mask |= ha_mask_of_mch(mch);
	}
	return ha_mask & enabled_node_ha;
}



static u64 get_ha_mar(int node, int ha, int ha_mar_num)
{
	u64 hamar;
	u64 hamar_hi;
	do {
		hamar = sic_read_ha_reg(node, ha, HA_MAR_LO(ha_mar_num));
		hamar_hi = sic_read_ha_reg(node, ha, HA_MAR_HI(ha_mar_num));
	} while (hamar_hi != sic_read_ha_reg(node, ha, HA_MAR_HI(ha_mar_num)));
	return hamar | (hamar_hi << 32);
}

#define MAX_HA (machine.sic_ha_num)
static u64 get_ha_str_cnt(struct e2k_uncore *uncore, struct hw_perf_event *hwc)
{
	ha_config_attr_t config = { .word = hwc->config };
	int ha;
	u64 ha_mar = 0;
	int node = uncore->node;
	u64 ha_mask = get_ha_mask_of_node(node, config);
	for (ha = find_first_bit((const unsigned long *)&ha_mask, MAX_HA);
	     ha < MAX_HA;
	     ha = find_next_bit((const unsigned long *)&ha_mask, MAX_HA, ha + 1)) {
		ha_mar += get_ha_mar(node, ha, config.counter);
	}
	pr_debug("hw_event %px: get_cnt %lld\n", hwc, ha_mar);
	return ha_mar;
}

static void set_ha_str_cnt(struct e2k_uncore *uncore,
			    struct hw_perf_event *hwc, u64 val)
{
	ha_config_attr_t config = { .word = hwc->config };
	int node = uncore->node;
	ulong ha;
	u64 ha_mask = get_ha_mask_of_node(node, config);
	for (ha = find_first_bit((const unsigned long *)&ha_mask, MAX_HA);
	     ha < MAX_HA;
	     ha = find_next_bit((const unsigned long *)&ha_mask, MAX_HA, ha + 1)) {
		sic_write_ha_reg(node, ha, HA_MAR_LO(config.counter), (u32)(val & 0xffffffff));
		sic_write_ha_reg(node, ha, HA_MAR_HI(config.counter), (u32)(val >> 32));
	}
	pr_debug("%s: hw_event %px: set_cnt %lld\n", __func__, hwc, val);
}


static struct e2k_uncore_reg_ops ha_reg_ops = {
	.get_cnt = get_ha_str_cnt,
	.set_cfg = set_ha_str_cfg,
	.set_cnt = set_ha_str_cnt,
};

static u64 ha_get_event(struct hw_perf_event *hwc)
{
	ha_config_attr_t config = { .word = hwc->config };

	return config.event;
}

static struct e2k_uncore_valid_events ha_mcr_valid_events[] = {
	{ 0, 34 },
	{ -1, -1}
};

static int ha_validate_event(struct e2k_uncore *uncore,
			      struct hw_perf_event *hwc)
{
	ha_config_attr_t config = { .word = hwc->config };
	u64 event = config.event;

	if (config.counter == 1)
		if (event == 32 || event == 22 || event == 13)
			return -EINVAL;
	if (get_ha_mask_of_node(uncore->node, config) == 0) {
		return -EINVAL;
	}
	return 0;
}

static int ha_add_event(struct e2k_uncore *uncore, struct perf_event *event)
{
	ha_config_attr_t config = { .word = event->hw.config };
	int i;

	/* validate against running counters */
	for (i = 0; i < uncore->num_counters; i++) {
		struct perf_event *event2 = READ_ONCE(uncore->events[i]);
		ha_config_attr_t config2;

		if (!event2)
			continue;

		AW(config2) = event2->hw.config;

		/*
		 * Check that there is no conflict with same counter in HA
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

int __init register_ha_pmus(void)
{
	int i, counters = 2;

	for_each_online_node(i) {
		struct e2k_uncore *uncore = kzalloc(sizeof(struct e2k_uncore) +
						    counters * sizeof(void *), GFP_KERNEL);
		if (!uncore)
			return -ENOMEM;

		uncore->type = E2K_UNCORE_HMU;

		uncore->pmu.event_init	= e2k_uncore_event_init;
		uncore->pmu.task_ctx_nr	= perf_invalid_context;
		uncore->pmu.add		= e2k_uncore_add;
		uncore->pmu.del		= e2k_uncore_del;
		uncore->pmu.start	= e2k_uncore_start;
		uncore->pmu.stop	= e2k_uncore_stop;
		uncore->pmu.read	= e2k_uncore_read;

		uncore->get_event = ha_get_event;
		uncore->add_event = ha_add_event;
		uncore->validate_event = ha_validate_event;

		uncore->reg_ops = &ha_reg_ops;
		uncore->num_counters = counters;

		uncore->node = i;

		uncore->valid_events = ha_mcr_valid_events;
		uncore->pmu.attr_groups = ha_mcr_attr_group;

		snprintf(uncore->name, UNCORE_PMU_NAME_LEN, "uncore_ha_%d", i);

		perf_pmu_register(&uncore->pmu, uncore->name, -1);
	}

	return 0;
}
