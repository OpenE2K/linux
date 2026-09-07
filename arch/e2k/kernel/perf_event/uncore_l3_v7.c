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


static struct e2k_uncore_valid_events l3_v7_valid_events[] = {
	{ 0x0, 0x1 },
	{ 0x4, 0x1e },
	{ 0x20, 0x20 },
	{ 0x24, 0x2c },
	{ 0x30, 0x35 },
	{ 0x38, 0x3a },
	{ -1, -1}
};

typedef union {
	struct {
		u64 counter	: 1;
		u64 bank	: 6;

		u64 ctl_thr	: 8;
		u64 ctl_msk	: 10;
		u64 ctl_sel	: 6;
		u64 ctl_inv	: 1;
		u64 ctl_edg	: 1;
		u64 ctl_stf	: 1;
		u64 ctl_rqf	: 1;
		u64 ctl_sbnk	: 2;

		u64		: 27;
	};

	u64 word;
} l3_v7_config_attr_t;

/* 0-bit reserved for software setting of used counter */
PMU_FORMAT_ATTR(bank, "config:1-6");
PMU_FORMAT_ATTR(ctl_thr, "config:7-14");
PMU_FORMAT_ATTR(ctl_msk, "config:15-24");
PMU_FORMAT_ATTR(ctl_sel, "config:25-30");
PMU_FORMAT_ATTR(ctl_inv, "config:31");
PMU_FORMAT_ATTR(ctl_edg, "config:32");
PMU_FORMAT_ATTR(ctl_stf, "config:33");
PMU_FORMAT_ATTR(ctl_rqf, "config:34");
PMU_FORMAT_ATTR(ctl_sbnk, "config:35-36");

typedef union {
	struct {
		u64 flt0_stf		: 10;
		u64 flt0_rqf_msk	: 3;
		u64 flt0_rqf		: 7;

		u64 flt1_opc_irq_en	: 1;
		u64 flt1_opc_irq	: 6;
		u64 flt1_opc_srq_en	: 1;
		u64 flt1_opc_srq	: 3;
		u64 flt1_opc_injc_en	: 1;
		u64 flt1_opc_injc	: 3;
		u64 flt1_opf		: 10;
		u64 flt1_rem		: 1;
		u64 flt1_loc		: 1;
		u64 flt1_data		: 1;
		u64 flt1_code		: 1;
		u64 flt1_en		: 1;

		u64			: 14;
	};

	u64 word;
} l3_v7_config1_attr_t;

PMU_FORMAT_ATTR(flt0_stf, "config1:0-9");
PMU_FORMAT_ATTR(flt0_rqf_msk, "config1:10-12");
PMU_FORMAT_ATTR(flt0_rqf, "config1:13-19");
PMU_FORMAT_ATTR(flt1_opc_irq_en, "config1:20");
PMU_FORMAT_ATTR(flt1_opc_irq, "config1:21-26");
PMU_FORMAT_ATTR(flt1_opc_srq_en, "config1:27");
PMU_FORMAT_ATTR(flt1_opc_srq, "config1:28-30");
PMU_FORMAT_ATTR(flt1_opc_injc_en, "config1:31");
PMU_FORMAT_ATTR(flt1_opc_injc, "config1:32-34");
PMU_FORMAT_ATTR(flt1_opf, "config1:35-44");
PMU_FORMAT_ATTR(flt1_rem, "config1:45");
PMU_FORMAT_ATTR(flt1_loc, "config1:46");
PMU_FORMAT_ATTR(flt1_data, "config1:47");
PMU_FORMAT_ATTR(flt1_code, "config1:48");
PMU_FORMAT_ATTR(flt1_en, "config1:49");

static struct attribute *e2k_l3_v7_format_attr[] = {
	&format_attr_bank.attr,
	&format_attr_ctl_thr.attr,
	&format_attr_ctl_msk.attr,
	&format_attr_ctl_sel.attr,
	&format_attr_ctl_inv.attr,
	&format_attr_ctl_edg.attr,
	&format_attr_ctl_stf.attr,
	&format_attr_ctl_rqf.attr,
	&format_attr_ctl_sbnk.attr,
	&format_attr_flt0_stf.attr,
	&format_attr_flt0_rqf_msk.attr,
	&format_attr_flt0_rqf.attr,
	&format_attr_flt1_opc_irq_en.attr,
	&format_attr_flt1_opc_irq.attr,
	&format_attr_flt1_opc_srq_en.attr,
	&format_attr_flt1_opc_srq.attr,
	&format_attr_flt1_opc_injc_en.attr,
	&format_attr_flt1_opc_injc.attr,
	&format_attr_flt1_opf.attr,
	&format_attr_flt1_rem.attr,
	&format_attr_flt1_loc.attr,
	&format_attr_flt1_data.attr,
	&format_attr_flt1_code.attr,
	&format_attr_flt1_en.attr,
	NULL,
};

static struct attribute_group e2k_l3_v7_format_group = {
	.name = "format",
	.attrs = e2k_l3_v7_format_attr,
};

static const struct attribute_group *e2k_l3_v7_attr_group[] = {
	&e2k_l3_v7_format_group,
	&e2k_cpumask_attr_group,
	NULL,
};

static u64 get_l3_v7_str_cnt(struct e2k_uncore *uncore, struct hw_perf_event *hwc)
{
	e2k_l3_pmon_cnt_lo lo;
	e2k_l3_pmon_cnt_hi hi;
	l3_v7_config_attr_t config = { .word = hwc->config };
	u8 counter = config.counter;
	u8 bank = config.bank;
	int node = uncore->node;
	u64 val;

	switch (counter) {
	case 0:
		AW(lo) = sic_read_l3_reg(node, bank, L3_PMON_CNT0_LO);
		AW(hi) = sic_read_l3_reg(node, bank, L3_PMON_CNT0_HI);
		break;
	case 1:
		AW(lo) = sic_read_l3_reg(node, bank, L3_PMON_CNT1_LO);
		AW(hi) = sic_read_l3_reg(node, bank, L3_PMON_CNT1_HI);
		break;
	}

	val = ((u64)AW(hi) << 32) | AW(lo);

	return val;
}

static void set_l3_v7_str_cfg(struct e2k_uncore *uncore,
				  struct hw_perf_event *hwc, bool enable)
{
	struct perf_event *event = container_of(hwc, struct perf_event, hw);
	l3_v7_config_attr_t config = { .word = hwc->config };
	l3_v7_config1_attr_t config1 = { .word = event->attr.config1 };
	int node = uncore->node;
	int ctl_reg_offset = 0;
	e2k_l3_pmon_ctl_v7 ctl;
	e2k_l3_pmon_flt0_v7 flt0;
	e2k_l3_pmon_flt1_v7 flt1;

	switch (config.counter) {
	case 0:
		ctl_reg_offset = L3_PMON_CTL0_V7;
		break;
	case 1:
		ctl_reg_offset = L3_PMON_CTL1_V7;
		break;
	}

	AW(ctl) = sic_read_node_nbsr_reg(node, ctl_reg_offset);
	AW(flt0) = sic_read_node_nbsr_reg(node, L3_PMON_FLT0);
	AW(flt1) = sic_read_node_nbsr_reg(node, L3_PMON_FLT1);

	ctl.en = !!enable;
	ctl.thr = config.ctl_thr;
	ctl.msk = config.ctl_msk;
	ctl.sel = config.ctl_sel;
	ctl.inv = config.ctl_inv;
	ctl.edg = config.ctl_edg;
	ctl.stf = config.ctl_stf;
	ctl.rqf = config.ctl_rqf;
	ctl.sbnk = config.ctl_sbnk;

	flt0.stf = config1.flt0_stf;
	flt0.rqf_mask = config1.flt0_rqf_msk;
	flt0.rqf = config1.flt0_rqf;

	flt1.opc_irq_en = config1.flt1_opc_irq_en;
	flt1.opc_irq = config1.flt1_opc_irq;
	flt1.opc_srq_en = config1.flt1_opc_srq_en;
	flt1.opc_srq = config1.flt1_opc_srq;
	flt1.opc_injc_en = config1.flt1_opc_injc_en;
	flt1.opc_injc = config1.flt1_opc_injc;
	flt1.opf = config1.flt1_opf;
	flt1.rem = config1.flt1_rem;
	flt1.loc = config1.flt1_loc;
	flt1.data = config1.flt1_data;
	flt1.code = config1.flt1_code;
	flt1.en = config1.flt1_en;

	sic_write_node_nbsr_reg(node, L3_PMON_FLT0, AW(flt0));
	sic_write_node_nbsr_reg(node, L3_PMON_FLT1, AW(flt1));
	sic_write_node_nbsr_reg(node, ctl_reg_offset, AW(ctl));
}

static void set_l3_v7_str_cnt(struct e2k_uncore *uncore, struct hw_perf_event *hwc, u64 val)
{
	e2k_l3_pmon_cnt_lo lo;
	e2k_l3_pmon_cnt_hi hi;
	l3_v7_config_attr_t config = { .word = hwc->config };
	u8 counter = config.counter;
	u8 bank = config.bank;
	int node = uncore->node;

	AW(lo) = val;
	AW(hi) = val >> 32;

	switch (counter) {
	case 0:
		sic_write_l3_reg(node, bank, L3_PMON_CNT0_LO, AW(lo));
		sic_write_l3_reg(node, bank, L3_PMON_CNT0_HI, AW(hi));
		break;
	case 1:
		sic_write_l3_reg(node, bank, L3_PMON_CNT1_LO, AW(lo));
		sic_write_l3_reg(node, bank, L3_PMON_CNT1_HI, AW(hi));
		break;
	}
}

static struct e2k_uncore_reg_ops l3_v7_reg_ops = {
	.get_cnt = get_l3_v7_str_cnt,
	.set_cfg = set_l3_v7_str_cfg,
	.set_cnt = set_l3_v7_str_cnt,
};

static u64 l3_v7_get_event(struct hw_perf_event *hwc)
{
	l3_v7_config_attr_t config = { .word = hwc->config };

	return config.ctl_sel;
}

static int l3_v7_validate_event(struct e2k_uncore *uncore, struct hw_perf_event *hwc)
{
	struct perf_event *event = container_of(hwc, struct perf_event, hw);
	l3_v7_config1_attr_t config1 = { .word = event->attr.config1 };

	if ((config1.flt0_stf >> 8) == 0x3 || IS_MACHINE_E8V7 && (config1.flt0_stf & 0x2)) {
		pr_info_ratelimited("uncore_l3_v7: invalid flt0_stf value (0x%x)\n",
			config1.flt0_stf);
		return -EINVAL;
	}

	if (IS_MACHINE_E8V7 && (config1.flt0_rqf_msk & 0x4)) {
		pr_info_ratelimited("uncore_l3_v7: invalid flt0_rqf_msk value (0x%x)\n",
			config1.flt0_rqf_msk);
		return -EINVAL;
	}

	if (config1.flt1_opc_injc > 0x3) {
		pr_info_ratelimited("uncore_l3_v7: invalid flt1_opc_injc value (0x%x)\n",
			config1.flt1_opc_injc);
		return -EINVAL;
	}

	return 0;
}

static int l3_v7_add_event(struct e2k_uncore *uncore, struct perf_event *event)
{
	l3_v7_config_attr_t config = { .word = event->hw.config };
	l3_v7_config1_attr_t config1 = { .word = event->attr.config1 };
	int i, used_counter = -1;

	/* validate against running counters */
	for (i = 0; i < uncore->num_counters; i++) {
		struct perf_event *other_event = READ_ONCE(uncore->events[i]);
		l3_v7_config_attr_t other_config;
		l3_v7_config1_attr_t other_config1;

		if (!other_event)
			continue;

		AW(other_config) = other_event->hw.config;
		AW(other_config1) = other_event->attr.config1;

		if (config1.flt0_stf != other_config1.flt0_stf ||
				config1.flt0_rqf_msk != other_config1.flt0_rqf_msk ||
				config1.flt0_rqf != other_config1.flt0_rqf ||
				config1.flt1_opc_irq_en != other_config1.flt1_opc_irq_en ||
				config1.flt1_opc_irq != other_config1.flt1_opc_irq ||
				config1.flt1_opc_srq_en != other_config1.flt1_opc_srq_en ||
				config1.flt1_opc_srq != other_config1.flt1_opc_srq ||
				config1.flt1_opc_injc_en != other_config1.flt1_opc_injc_en ||
				config1.flt1_opc_injc != other_config1.flt1_opc_injc ||
				config1.flt1_opf != other_config1.flt1_opf ||
				config1.flt1_rem != other_config1.flt1_rem ||
				config1.flt1_loc != other_config1.flt1_loc ||
				config1.flt1_data != other_config1.flt1_data ||
				config1.flt1_code != other_config1.flt1_code ||
				config1.flt1_en != other_config1.flt1_en)
			return -ENOSPC;

		used_counter = other_config.counter;
	}

	/* take the first available slot */
	for (i = 0; i < uncore->num_counters; i++) {
		if (cmpxchg(&uncore->events[i], NULL, event) == NULL) {
			event->hw.idx = i;

			config.counter = !used_counter;
			event->hw.config = AW(config);

			return 0;
		}
	}

	return -ENOSPC;
}

int __init register_l3_v7_pmus(void)
{
	int i, counters = 2;

	for_each_online_node(i) {
		struct e2k_uncore *uncore = kzalloc(sizeof(struct e2k_uncore) +
						    counters * sizeof(void *), GFP_KERNEL);
		if (!uncore)
			return -ENOMEM;

		uncore->type = E2K_UNCORE_L3_V7;

		uncore->pmu.event_init	= e2k_uncore_event_init;
		uncore->pmu.task_ctx_nr	= perf_invalid_context;
		uncore->pmu.add		= e2k_uncore_add;
		uncore->pmu.del		= e2k_uncore_del;
		uncore->pmu.start	= e2k_uncore_start;
		uncore->pmu.stop	= e2k_uncore_stop;
		uncore->pmu.read	= e2k_uncore_read;

		uncore->get_event = l3_v7_get_event;
		uncore->add_event = l3_v7_add_event;
		uncore->validate_event = l3_v7_validate_event;

		uncore->reg_ops = &l3_v7_reg_ops;
		uncore->num_counters = counters;

		uncore->node = i;

		uncore->valid_events = l3_v7_valid_events;
		uncore->pmu.attr_groups = e2k_l3_v7_attr_group;

		snprintf(uncore->name, UNCORE_PMU_NAME_LEN, "uncore_l3_v7_%d", i);

		perf_pmu_register(&uncore->pmu, uncore->name, -1);
	}

	return 0;
}
