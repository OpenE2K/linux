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

static u8 mc_enabled[MAX_NUMNODES] __read_mostly;
static struct e2k_uncore *e2k_uncore_mc[MAX_NUMNODES];

typedef union {
	struct {
		u64 event	: 8;
		u64 counter	: 1;
		u64 mc_mask	: 8;
		u64 lb		: 8;
		u64 __unused	: 39;
	};
	u64 word;
} mc_config_attr_t;

PMU_FORMAT_ATTR(event, "config:0-7");
/* 1 bit reserved for software setting of used counter */
PMU_FORMAT_ATTR(mc_mask, "config:9-16");
PMU_FORMAT_ATTR(lb, "config:17-24");

static struct attribute *mc_format_attr[] = {
	&format_attr_event.attr,
	&format_attr_mc_mask.attr,
	&format_attr_lb.attr,
	NULL,
};

static struct e2k_uncore_valid_events mc_valid_events[] = {
	{ 0x0, 0x16 },
	{ -1, -1}
};

static struct attribute_group mc_format_group = {
	.name = "format",
	.attrs = mc_format_attr,
};

static const struct attribute_group *mc_attr_group[] = {
	&mc_format_group,
	&e2k_cpumask_attr_group,
	NULL,
};

static u64 get_mc_str_cnt(struct e2k_uncore *uncore, struct hw_perf_event *hwc)
{
	mc_config_attr_t config = { .word = hwc->config };
	u64 val, ch, counter = config.counter;
	DECLARE_BITMAP(mc_mask, 8);
	int node = uncore->node;

	mc_mask[0] = (config.mc_mask ?: 0xff) & mc_enabled[node];

	val = 0;
	for_each_set_bit(ch, mc_mask, 8) {
		e2k_mc_mon_ctrext_t mc_mon_ctrext;
		u32 mc_mon_ctr;
		e2k_mc_ch_t mc_ch;

		AW(mc_ch) = 0;
		mc_ch.n = ch;

		sic_write_node_nbsr_reg(node, MC_CH, AW(mc_ch));

		do {
			AW(mc_mon_ctrext) = sic_read_node_nbsr_reg(node, MC_MON_CTRext);
			if (counter)
				mc_mon_ctr = sic_read_node_nbsr_reg(node, MC_MON_CTR1);
			else
				mc_mon_ctr = sic_read_node_nbsr_reg(node, MC_MON_CTR0);
		} while (AW(mc_mon_ctrext) != sic_read_node_nbsr_reg(node, MC_MON_CTRext));

		val += ((u64) mc_mon_ctrext.cnt[counter] << 32UL) | (u64) mc_mon_ctr;
	}

	pr_debug("hw_event %px: get_cnt %lld\n", hwc, val);

	return val;
}

static void set_mc_str_cfg(struct e2k_uncore *uncore,
		struct hw_perf_event *hwc, bool enable)
{
	mc_config_attr_t config = { .word = hwc->config };
	u64 ch, counter = config.counter;
	DECLARE_BITMAP(mc_mask, 8);
	e2k_mc_mon_ctl_t mon_ctl;
	int node = uncore->node;

	mc_mask[0] = (config.mc_mask ?: 0xff) & mc_enabled[node];

	for_each_set_bit(ch, mc_mask, 8) {
		e2k_mc_ch_t mc_ch;

		AW(mc_ch) = 0;
		mc_ch.n = ch;

		sic_write_node_nbsr_reg(node, MC_CH, AW(mc_ch));

		if (enable) {
			/* Two-step process:
			 * 1) Set mon_ctl.ld to load initial counters values
			 * 2) Clear mon_ctl.frz to start counting */
			AW(mon_ctl) = sic_read_node_nbsr_reg(node, MC_MON_CTL);
			if (counter)
				mon_ctl.ld1 = 1;
			else
				mon_ctl.ld0 = 1;
			sic_write_node_nbsr_reg(node, MC_MON_CTL, AW(mon_ctl));
			if (counter)
				mon_ctl.ld1 = 0;
			else
				mon_ctl.ld0 = 0;
		} else {
			AW(mon_ctl) = sic_read_node_nbsr_reg(node, MC_MON_CTL);
		}
		if (counter) {
			mon_ctl.frz1 = !enable;
			mon_ctl.es1 = config.event;
			mon_ctl.lb1 = config.lb;
		} else {
			mon_ctl.frz0 = !enable;
			mon_ctl.es0 = config.event;
			mon_ctl.lb0 = config.lb;
		}
		sic_write_node_nbsr_reg(node, MC_MON_CTL, AW(mon_ctl));

		pr_debug("hw_event %px: set_cfg 0x%x, channel %lld\n",
				hwc, AW(mon_ctl), ch);
	}
}

static void set_mc_str_cnt(struct e2k_uncore *uncore,
			    struct hw_perf_event *hwc, u64 val)
{
	mc_config_attr_t config = { .word = hwc->config };
	u64 write_val, ch, counter = config.counter;
	int node = uncore->node;
	DECLARE_BITMAP(mc_mask, 8);
	e2k_mc_mon_ctrext_t mc_mon_ctrext;
	u32 mc_mon_ctr;

	mc_mask[0] = (config.mc_mask ?: 0xff) & mc_enabled[node];

	write_val = val;
	for_each_set_bit(ch, mc_mask, 8) {
		e2k_mc_ch_t mc_ch;

		AW(mc_ch) = 0;
		mc_ch.n = ch;

		sic_write_node_nbsr_reg(node, MC_CH, AW(mc_ch));

		AW(mc_mon_ctrext) = sic_read_node_nbsr_reg(node, MC_MON_CTRext);
		mc_mon_ctrext.cnt[counter] = write_val >> 32;
		mc_mon_ctr = write_val;

		sic_write_node_nbsr_reg(node, MC_MON_CTRext, AW(mc_mon_ctrext));
		if (counter)
			sic_write_node_nbsr_reg(node, MC_MON_CTR1, mc_mon_ctr);
		else
			sic_write_node_nbsr_reg(node, MC_MON_CTR0, mc_mon_ctr);

		/* Set only one configured counter to passed value,
		 * it doesn't matter which one. */
		write_val = 0;
	}

	pr_debug("hw_event %px: set_cnt %lld\n", hwc, val);
}


static struct e2k_uncore_reg_ops mc_reg_ops = {
	.get_cnt = get_mc_str_cnt,
	.set_cfg = set_mc_str_cfg,
	.set_cnt = set_mc_str_cnt,
};

static u64 mc_get_event(struct hw_perf_event *hwc)
{
	mc_config_attr_t config = { .word = hwc->config };

	return config.event;
}

static int mc_validate_event(struct e2k_uncore *uncore,
		struct hw_perf_event *hwc)
{
	mc_config_attr_t config = { .word = hwc->config };
	u64 ch, event = config.event;
	DECLARE_BITMAP(mc_mask, 8);
	int node = uncore->node;

	if (config.lb && (event < 0xe || event > 0x15)) {
		pr_info_ratelimited("uncore_mc: logical bank filter is not available for event %llu\n",
				event);
		return -EINVAL;
	}

	mc_mask[0] = (config.mc_mask ?: 0xff) & mc_enabled[node];

	/* All is good, read MC_STATUS to clear overflow bits */
	for_each_set_bit(ch, mc_mask, 8) {
		e2k_mc_status_t mc_status;
		e2k_mc_ch_t mc_ch;

		AW(mc_ch) = 0;
		mc_ch.n = ch;

		sic_write_node_nbsr_reg(node, MC_CH, AW(mc_ch));

		AW(mc_status) = sic_read_node_nbsr_reg(node, MC_STATUS_E2K);

		if (mc_status.ddrint_err || mc_status.phy_interrupt ||
		    mc_status.phyccm_par_err || mc_status.ecc_err ||
		    mc_status.bridge_par_err || mc_status.dfi_err ||
		    mc_status.dmem_par_err) {
			pr_alert("WARNING: When reading MC_STATUS to clear \"mon{0,1}_of\" bits, some other bits have been cleared too: 0x%x\n",
					AW(mc_status));
			WARN_ON(1);
		}
	}

	return 0;
}

static int mc_add_event(struct e2k_uncore *uncore, struct perf_event *event)
{
	mc_config_attr_t config = { .word = event->hw.config }, config2;
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

int __init register_mc_pmus()
{
	int i, counters = 2;

	for_each_online_node(i) {
		e2k_hmu_mic_t hmu_mic;
		struct e2k_uncore *uncore = kzalloc(sizeof(struct e2k_uncore) +
				counters * sizeof(void *), GFP_KERNEL);
		if (!uncore)
			return -ENOMEM;

		uncore->type = E2K_UNCORE_MC;

		uncore->pmu.event_init	= e2k_uncore_event_init;
		uncore->pmu.task_ctx_nr	= perf_invalid_context;
		uncore->pmu.add		= e2k_uncore_add;
		uncore->pmu.del		= e2k_uncore_del;
		uncore->pmu.start	= e2k_uncore_start;
		uncore->pmu.stop	= e2k_uncore_stop;
		uncore->pmu.read	= e2k_uncore_read;

		uncore->get_event = mc_get_event;
		uncore->add_event = mc_add_event;
		uncore->validate_event = mc_validate_event;

		uncore->reg_ops = &mc_reg_ops;
		uncore->num_counters = counters;

		uncore->node = i;
		AW(hmu_mic) = sic_read_node_nbsr_reg(i, HMU_MIC);
		mc_enabled[i] = hmu_mic.mcen;

		uncore->valid_events = mc_valid_events;
		uncore->pmu.attr_groups = mc_attr_group;

		snprintf(uncore->name, UNCORE_PMU_NAME_LEN,
				"uncore_mc_%d", i);

		e2k_uncore_mc[i] = uncore;
		perf_pmu_register(&uncore->pmu, uncore->name, -1);
	}

	return 0;
}
