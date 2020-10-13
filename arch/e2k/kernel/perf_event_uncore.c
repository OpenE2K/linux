#include <linux/list.h>
#include <linux/perf_event.h>
#include <asm/sic_regs.h>
#include <linux/nodemask.h>
#include <asm/perf_event_uncore.h>
#include <linux/slab.h>

static struct e2k_uncore *e2k_uncore_ipcc;
static struct e2k_uncore *e2k_uncore_iocc;
static struct e2k_uncore *e2k_uncore_sic;

/*
 * To add new monitor to uncore perf:
 *
 * 1) Implement 3 register access functions which can:
 *	- set current events count
 *	- get current events count
 *	- set config field of monitor
 *
 * 2) Fill struct e2k_uncore_reg_ops with this functions
 *    (for example ipcc_reg_ops)
 *
 * 3) Fill struct e2k_uncore_event_desc with event descriptions
 *    (for example sic_MCM1_events)
 *    Be careful, values from descriptions are passed by parser
 *    to perf_event_open() into attr.config field
 *
 * 4) Fill struct attribute
 *    (for example e2k_sic_MCM1_events_attrs)
 *
 * 5) Fill struct attribute_group
 *    (for example e2k_sic_MCM1_attr_group)
 *
 * 6) Fill struct e2k_uncore with
 *	Main fields:
 *		- pmu.event_init	= e2k_uncore_event_init
 *		- pmu.add		= e2k_uncore_add
 *		- pmu.del		= e2k_uncore_del
 *		- pmu.start		= e2k_uncore_start
 *		- pmu.stop		= e2k_uncore_stop
 *		- pmu.read		= e2k_uncore_read
 *		- pmu.reg_ops		= ~struct from 1) step~
 *		- pmu.attr_groups	= ~struct from 5) step~
 *		- .name			= ~name~ (is used by sysfs)
 *
 *	Optional fields:
 *		You can use other fields of e2k_uncore
 *		(.node, .idx_at_node) as you want
 *		(for example: allow reg access functions write
 *		directly into neccessary registers).
 *		If you want add another fields.
 *
 * 7) Create array of valid events terminated with -1 and fill
 *    pmu.valid_events with it. It is used for error check
 *    (for example iocc_valid_events).
 *
 * 8) Pass e2k_uncore.pmu and e2k_uncore.name to perf_pmu_register()
 *
 */


/*
 * (void *) is used for flexibility
 */
static void get_ipcc_str_cnt(struct e2k_uncore *uncore, void *result)
{
	e2k_ipcc_str_struct_t reg;
	int node = uncore->node;
	int idx = uncore->idx_at_node;

	reg.E2K_IPCC_STR_reg = sic_get_ipcc_str(node, idx);

	*((int *)result) = reg.E2K_IPCC_STR_ecnt;
}

static void set_ipcc_str_cfg(struct e2k_uncore *uncore, void *val)
{
	e2k_ipcc_str_struct_t reg;
	int node = uncore->node;
	int idx = uncore->idx_at_node;

	reg.E2K_IPCC_STR_reg = sic_get_ipcc_str(node, idx);

	reg.E2K_IPCC_STR_ecf = *((unsigned int *)val);

	sic_set_ipcc_str(node, idx, reg.E2K_IPCC_STR_reg);
}

static void set_ipcc_str_cnt(struct e2k_uncore *uncore, void *val)
{
	e2k_ipcc_str_struct_t reg;
	int node = uncore->node;
	int idx = uncore->idx_at_node;

	reg.E2K_IPCC_STR_reg = sic_get_ipcc_str(node, idx);

	reg.E2K_IPCC_STR_ecnt = *((unsigned int *)val);

	sic_set_ipcc_str(node, idx, reg.E2K_IPCC_STR_reg);
}

static struct e2k_uncore_reg_ops ipcc_reg_ops = {
	.get_cnt = get_ipcc_str_cnt,
	.set_cfg = set_ipcc_str_cfg,
	.set_cnt = set_ipcc_str_cnt,
};

static void get_iocc_str_cnt(struct e2k_uncore *uncore, void *result)
{
	e2k_io_str_struct_t reg;
	int node = uncore->node;
	int idx = uncore->idx_at_node;

	reg.E2K_IO_STR_reg = sic_get_io_str(node, idx);

	*((int *)result) = reg.E2K_IO_STR_rc;
}

static void set_iocc_str_cfg(struct e2k_uncore *uncore, void *val)
{
	e2k_io_str_struct_t reg;
	int event_val = *((int *)val);
	int node = uncore->node;
	int idx = uncore->idx_at_node;

	reg.E2K_IO_STR_reg = sic_get_ipcc_str(node, idx);
	reg.E2K_IO_STR_reg &= ~E2K_IO_STR_EVENT_MASK;
	reg.E2K_IO_STR_reg |= event_val << E2K_IO_STR_EVENT_SHIFT;

	sic_set_io_str(node, idx, reg.E2K_IO_STR_reg);
}

static void set_iocc_str_cnt(struct e2k_uncore *uncore, void *val)
{
	e2k_io_str_struct_t reg;
	int node = uncore->node;
	int idx = uncore->idx_at_node;

	reg.E2K_IO_STR_reg = sic_get_io_str(node, idx);
	reg.E2K_IO_STR_rc = *((unsigned int *)val);

	sic_set_io_str(node, idx, reg.E2K_IO_STR_reg);
}

static struct e2k_uncore_reg_ops iocc_reg_ops = {
	.get_cnt = get_iocc_str_cnt,
	.set_cfg = set_iocc_str_cfg,
	.set_cnt = set_iocc_str_cnt,
};

enum {
	MCM0,
	MCM1,
};

static void get_sic_str_cnt(struct e2k_uncore *uncore, void *result)
{
	e2k_sic_mar_lo_struct_t mar_lo_reg;
	e2k_sic_mar_hi_struct_t mar_hi_reg;

	int node = uncore->node;
	int monitor_id = uncore->idx_at_node;

	u64 _result;

	switch (monitor_id) {
	case MCM0:
		mar_lo_reg.E2K_SIC_MAR_LO_reg =
			sic_read_node_nbsr_reg(node, SIC_sic_mar0_lo);
		mar_hi_reg.E2K_SIC_MAR_HI_reg =
			sic_read_node_nbsr_reg(node, SIC_sic_mar0_hi);
		break;
	case MCM1:
		mar_lo_reg.E2K_SIC_MAR_LO_reg =
			sic_read_node_nbsr_reg(node, SIC_sic_mar1_lo);
		mar_hi_reg.E2K_SIC_MAR_HI_reg =
			sic_read_node_nbsr_reg(node, SIC_sic_mar1_hi);
		break;
	default:
		break;
	}

	_result = (((u64)mar_hi_reg.E2K_SIC_MAR_HI_reg) << 32) |
			mar_lo_reg.E2K_SIC_MAR_LO_reg;

	*((u64 *)result) = _result;
}

static void set_sic_str_cfg(struct e2k_uncore *uncore, void *val)
{
	e2k_sic_mcr_struct_t mcr_reg;
	int node = uncore->node;
	int monitor_id = uncore->idx_at_node;
	u64 _val = *((u64 *)val);

	mcr_reg.E2K_SIC_MCR_reg = sic_read_node_nbsr_reg(node, SIC_sic_mcr);

	switch (monitor_id) {
	case MCM0:
		mcr_reg.E2K_SIC_MCR_v0 = 1;
		mcr_reg.E2K_SIC_MCR_es0 = _val;
		sic_write_node_nbsr_reg(node, SIC_sic_mcr,
				mcr_reg.E2K_SIC_MCR_reg);
	case MCM1:
		mcr_reg.E2K_SIC_MCR_v1 = 1;
		mcr_reg.E2K_SIC_MCR_es1 = _val;
		sic_write_node_nbsr_reg(node, SIC_sic_mcr,
				mcr_reg.E2K_SIC_MCR_reg);
	}

}

static void set_sic_str_cnt(struct e2k_uncore *uncore, void *val)
{
	e2k_sic_mar_lo_struct_t mar_lo_reg;
	e2k_sic_mar_hi_struct_t mar_hi_reg;

	int node = uncore->node;
	int monitor_id = uncore->idx_at_node;

	u64 _val = *((u64 *)val);

	mar_lo_reg.E2K_SIC_MAR_LO_reg = _val;
	mar_hi_reg.E2K_SIC_MAR_HI_reg = _val >> 32;

	switch (monitor_id) {
	case MCM0:
		sic_write_node_nbsr_reg(node, SIC_sic_mar0_lo,
				mar_hi_reg.E2K_SIC_MAR_LO_reg);
		sic_write_node_nbsr_reg(node, SIC_sic_mar0_hi,
				mar_hi_reg.E2K_SIC_MAR_HI_reg);
	case MCM1:
		sic_write_node_nbsr_reg(node, SIC_sic_mar1_lo,
				mar_hi_reg.E2K_SIC_MAR_LO_reg);
		sic_write_node_nbsr_reg(node, SIC_sic_mar1_hi,
				mar_hi_reg.E2K_SIC_MAR_HI_reg);
	default:
		break;
	}
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

static int ipcc_valid_events[] = { 1, 2, -1};

static struct attribute *e2k_ipcc_events_attrs[] = {
	&ipcc_events[0].attr.attr,
	&ipcc_events[1].attr.attr,
	NULL,
};

static struct attribute_group e2k_ipcc_events_group = {
	.name = "events",
	.attrs = e2k_ipcc_events_attrs,
};

PMU_FORMAT_ATTR(event, "config:0-5");

static struct attribute *e2k_uncore_format_attr[] = {
	&format_attr_event.attr,
	NULL,
};

static struct attribute_group e2k_ipcc_format_group = {
	.name = "format",
	.attrs = e2k_uncore_format_attr,
};

static struct attribute_group *e2k_ipcc_attr_group[] = {
	&e2k_ipcc_events_group,
	&e2k_ipcc_format_group,
	NULL,
};

static struct e2k_uncore_event_desc iocc_events[] = {
	E2K_UNCORE_EVENT_DESC(busy,		"event=0x1"),
	E2K_UNCORE_EVENT_DESC(crc_err,		"event=0x2"),
	E2K_UNCORE_EVENT_DESC(time_out,		"event=0x4"),
	E2K_UNCORE_EVENT_DESC(cmn_rc,		"event=0x7"),
	{ /*end: all zeroes */ },
};

static int iocc_valid_events[] = { 1, 2, 4, 7, -1 };

static struct attribute *e2k_iocc_events_attrs[] = {
	&iocc_events[0].attr.attr,
	&iocc_events[1].attr.attr,
	&iocc_events[2].attr.attr,
	NULL,
};

static struct attribute_group e2k_iocc_events_group = {
	.name = "events",
	.attrs = e2k_iocc_events_attrs,
};

static struct attribute_group e2k_iocc_format_group = {
	.name = "format",
	.attrs = e2k_uncore_format_attr,
};

static struct attribute_group *e2k_iocc_attr_group[] = {
	&e2k_iocc_events_group,
	&e2k_iocc_format_group,
	NULL,
};

static struct e2k_uncore_event_desc sic_MCM0_events[] = {
	E2K_UNCORE_EVENT_DESC(mc_read,			"event=0x0"),
	E2K_UNCORE_EVENT_DESC(mc_write_local,		"event=0x1"),
	E2K_UNCORE_EVENT_DESC(mc_read_local_cores,	"event=0x2"),
	E2K_UNCORE_EVENT_DESC(dir_cache_hit,		"event=0x3"),
	E2K_UNCORE_EVENT_DESC(dir_cache_read_hit,	"event=0x4"),
	E2K_UNCORE_EVENT_DESC(retry,			"event=0x5"),
	E2K_UNCORE_EVENT_DESC(retry2_rdbuf_full,	"event=0x6"),
	E2K_UNCORE_EVENT_DESC(retry2_wrbuf,		"event=0x7"),
	E2K_UNCORE_EVENT_DESC(retry2_dm,		"event=0x8"),
	{ /*end: all zeroes */ },
};

static int sic_MCM0_valid_events[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, -1 };

static struct attribute *e2k_sic_MCM0_events_attrs[] = {
	&sic_MCM0_events[0].attr.attr,
	&sic_MCM0_events[1].attr.attr,
	&sic_MCM0_events[2].attr.attr,
	&sic_MCM0_events[3].attr.attr,
	&sic_MCM0_events[4].attr.attr,
	&sic_MCM0_events[5].attr.attr,
	&sic_MCM0_events[6].attr.attr,
	&sic_MCM0_events[7].attr.attr,
	&sic_MCM0_events[8].attr.attr,
	NULL,
};

static struct attribute_group e2k_sic_MCM0_events_group = {
	.name = "events",
	.attrs = e2k_sic_MCM0_events_attrs,
};

static struct attribute_group e2k_sic_MCM0_format_group = {
	.name = "format",
	.attrs = e2k_uncore_format_attr,
};

static struct attribute_group *e2k_sic_MCM0_attr_group[] = {
	&e2k_sic_MCM0_events_group,
	&e2k_sic_MCM0_format_group,
	NULL,
};

static struct e2k_uncore_event_desc sic_MCM1_events[] = {
	E2K_UNCORE_EVENT_DESC(mc_write,			"event=0x0"),
	E2K_UNCORE_EVENT_DESC(mc_read_local,		"event=0x1"),
	E2K_UNCORE_EVENT_DESC(mc_write_local_cores,	"event=0x2"),
	E2K_UNCORE_EVENT_DESC(dir_cache_miss,		"event=0x3"),
	E2K_UNCORE_EVENT_DESC(dir_cache_read_miss,	"event=0x4"),
	E2K_UNCORE_EVENT_DESC(retry1,			"event=0x5"),
	E2K_UNCORE_EVENT_DESC(retry2,			"event=0x6"),
	{ /*end: all zeroes */ },
};

static int sic_MCM1_valid_events[] = { 0, 1, 2, 3, 4, 5, 6, -1 };

static struct attribute *e2k_sic_MCM1_events_attrs[] = {
	&sic_MCM1_events[0].attr.attr,
	&sic_MCM1_events[1].attr.attr,
	&sic_MCM1_events[2].attr.attr,
	&sic_MCM1_events[3].attr.attr,
	&sic_MCM1_events[4].attr.attr,
	&sic_MCM1_events[5].attr.attr,
	&sic_MCM1_events[6].attr.attr,
	NULL,
};

static struct attribute_group e2k_sic_MCM1_events_group = {
	.name = "events",
	.attrs = e2k_sic_MCM1_events_attrs,
};

static struct attribute_group e2k_sic_MCM1_format_group = {
	.name = "format",
	.attrs = e2k_uncore_format_attr,
};

static struct attribute_group *e2k_sic_MCM1_attr_group[] = {
	&e2k_sic_MCM1_events_group,
	&e2k_sic_MCM1_format_group,
	NULL,
};

static struct e2k_uncore *event_to_e2k_uncore(struct perf_event *event)
{
	return container_of(event->pmu, struct e2k_uncore, pmu);
}

static void e2k_uncore_start(struct perf_event *event, int flags)
{
	struct hw_perf_event *hwc = &event->hw;
	struct e2k_uncore *uncore = event_to_e2k_uncore(event);

	if (flags & PERF_EF_RELOAD)
		uncore->reg_ops->set_cnt(uncore, (void *)&hwc->prev_count);

	hwc->state = 0;

	uncore->reg_ops->set_cfg(uncore, (void *)&hwc->config);
	perf_event_update_userpage(event);
}

static int is_valid_event(struct perf_event *event)
{
	struct e2k_uncore *uncore;
	int i;

	uncore = event_to_e2k_uncore(event);
	if (!uncore)
		return -ENODEV;

	for (i = 0; uncore->valid_events[i] != -1; i++) {
		if (event->attr.config == uncore->valid_events[i])
			return 0;
	}

	return -EINVAL;
}

static int e2k_uncore_event_init(struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;

	if (event->attr.type != event->pmu->type)
		return -ENOENT;

	/* Only sampling events are supported */
	if (event->attr.sample_period)
		return -EINVAL;

	/* IPCC and IOCC counters don't have usr/os/guest/host bits */
	if (event->attr.exclude_user || event->attr.exclude_kernel ||
			event->attr.exclude_host || event->attr.exclude_guest)
		return -EINVAL;

	hwc->config = event->attr.config;
	hwc->idx = -1;

	return is_valid_event(event);
}

static int e2k_uncore_add(struct perf_event *event, int flags)
{
	int i;
	struct e2k_uncore *uncore = event_to_e2k_uncore(event);
	struct hw_perf_event *hwc = &event->hw;


	/* are we already assigned? */
	if (hwc->idx != -1 && uncore->events[hwc->idx] == event)
		goto out;

	for (i = 0; i < uncore->num_counters; i++) {
		if (uncore->events[i] == event) {
			hwc->idx = i;
			goto out;
		}
	}

	/* if didn't find, take the first availible counter */
	hwc->idx = -1;
	for (i = 0; i < uncore->num_counters; i++) {
		if (cmpxchg(&uncore->events[i], NULL, event) == NULL) {
			hwc->idx = i;
			break;
		}
	}

out:
	if (hwc->idx == -1) {
		return -EBUSY;
	}

	hwc->state = PERF_HES_UPTODATE | PERF_HES_STOPPED;

	if (flags & PERF_EF_START)
		e2k_uncore_start(event, PERF_EF_RELOAD);

	return 0;
}

static void e2k_uncore_read(struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;
	struct e2k_uncore *uncore = event_to_e2k_uncore(event);

	u64 prev, new;
	s64 delta;

	prev = local64_read(&hwc->prev_count);
	uncore->reg_ops->get_cnt(uncore, &new);
	delta = new - prev;
	local64_add(delta, &event->count);
}

static void e2k_uncore_stop(struct perf_event *event, int flags)
{
	struct hw_perf_event *hwc = &event->hw;
	struct e2k_uncore *uncore = event_to_e2k_uncore(event);

	uncore->reg_ops->set_cfg(uncore, &hwc->config);
	hwc->state |= PERF_HES_STOPPED;

	if ((flags & PERF_EF_UPDATE) && !(hwc->state & PERF_HES_UPTODATE)) {
		e2k_uncore_read(event);
		hwc->state |= PERF_HES_UPTODATE;
	}
}

static void e2k_uncore_del(struct perf_event *event, int flags)
{
	int i;
	struct e2k_uncore *uncore = event_to_e2k_uncore(event);
	struct hw_perf_event *hwc = &event->hw;

	e2k_uncore_stop(event, PERF_EF_UPDATE);

	for (i = 0; i < uncore->num_counters; i++) {
		if (cmpxchg(&uncore->events[i], event, NULL) == event)
			break;
	}

	hwc->idx = -1;
}


static int __init register_ipcc_pmus()
{
	int i;
	int num_counters = NUM_COUNTERS_IPCC;

	e2k_uncore_ipcc = kzalloc(sizeof(struct e2k_uncore) *
			num_counters, GFP_KERNEL);
	if (!e2k_uncore_ipcc)
		return -ENOMEM;

	for (i = 0; i < num_counters; i++) {
		e2k_uncore_ipcc[i].pmu.attr_groups	=
			(const struct attribute_group **)e2k_ipcc_attr_group;
		e2k_uncore_ipcc[i].pmu.event_init	= e2k_uncore_event_init,
		e2k_uncore_ipcc[i].pmu.add		= e2k_uncore_add,
		e2k_uncore_ipcc[i].pmu.del		= e2k_uncore_del,
		e2k_uncore_ipcc[i].pmu.start		= e2k_uncore_start,
		e2k_uncore_ipcc[i].pmu.stop		= e2k_uncore_stop,
		e2k_uncore_ipcc[i].pmu.read		= e2k_uncore_read,

		e2k_uncore_ipcc[i].reg_ops = &ipcc_reg_ops;
		e2k_uncore_ipcc[i].num_counters = 1;

		e2k_uncore_ipcc[i].node = i / IPCC_STR_PER_NODE;
		e2k_uncore_ipcc[i].idx_at_node = i % IPCC_STR_PER_NODE;

		e2k_uncore_ipcc[i].valid_events = ipcc_valid_events;

		sprintf(e2k_uncore_ipcc[i].name, "ipcc_%d_%d",
			e2k_uncore_ipcc[i].node,
			e2k_uncore_ipcc[i].idx_at_node);
	}


	for (i = 0; i < num_counters; i++) {
		perf_pmu_register(&e2k_uncore_ipcc[i].pmu,
				e2k_uncore_ipcc[i].name, -1);
	}

	return 0;
}

static int __init register_iocc_pmus()
{
	int i;
	int num_counters = NUM_COUNTERS_IOCC;

	e2k_uncore_iocc = kzalloc(sizeof(struct e2k_uncore) *
			num_counters, GFP_KERNEL);
	if (!e2k_uncore_iocc)
		return -ENOMEM;

	for (i = 0; i < num_counters; i++) {
		e2k_uncore_iocc[i].pmu.attr_groups	=
			(const struct attribute_group **)e2k_iocc_attr_group;
		e2k_uncore_iocc[i].pmu.event_init	= e2k_uncore_event_init;
		e2k_uncore_iocc[i].pmu.add		= e2k_uncore_add;
		e2k_uncore_iocc[i].pmu.del		= e2k_uncore_del;
		e2k_uncore_iocc[i].pmu.start		= e2k_uncore_start;
		e2k_uncore_iocc[i].pmu.stop		= e2k_uncore_stop;
		e2k_uncore_iocc[i].pmu.read		= e2k_uncore_read;

		e2k_uncore_iocc[i].reg_ops = &iocc_reg_ops;
		e2k_uncore_iocc[i].num_counters = 1;

		e2k_uncore_iocc[i].node = i / IOCC_STR_PER_NODE;
		e2k_uncore_iocc[i].idx_at_node = i % IOCC_STR_PER_NODE;

		e2k_uncore_iocc[i].valid_events = iocc_valid_events;

		sprintf(e2k_uncore_iocc[i].name, "iocc_%d_%d",
			e2k_uncore_iocc[i].node,
			e2k_uncore_iocc[i].idx_at_node);
	}

	for (i = 0; i < num_counters; i++) {
		perf_pmu_register(&e2k_uncore_iocc[i].pmu,
				e2k_uncore_iocc[i].name, -1);
	}

	return 0;
}

static int __init register_sic_pmus()
{
	int i;
	int num_counters = NUM_COUNTERS_SIC;

	e2k_uncore_sic = kzalloc(sizeof(struct e2k_uncore) *
			num_counters, GFP_KERNEL);
	if (!e2k_uncore_sic)
		return -ENOMEM;

	for (i = 0; i < num_counters; i++) {
		e2k_uncore_sic[i].pmu.event_init	= e2k_uncore_event_init,
		e2k_uncore_sic[i].pmu.add		= e2k_uncore_add;
		e2k_uncore_sic[i].pmu.del		= e2k_uncore_del;
		e2k_uncore_sic[i].pmu.start		= e2k_uncore_start;
		e2k_uncore_sic[i].pmu.stop		= e2k_uncore_stop;
		e2k_uncore_sic[i].pmu.read		= e2k_uncore_read;

		e2k_uncore_sic[i].reg_ops = &sic_reg_ops;
		e2k_uncore_sic[i].num_counters = 1;

		e2k_uncore_sic[i].node = i / SIC_STR_PER_NODE;
		e2k_uncore_sic[i].idx_at_node = i % SIC_STR_PER_NODE;

		switch (i % SIC_STR_PER_NODE) {
		case 0:
			e2k_uncore_sic[i].valid_events = sic_MCM0_valid_events;
			e2k_uncore_sic[i].pmu.attr_groups = (const struct
				attribute_group **)e2k_sic_MCM0_attr_group;
			sprintf(e2k_uncore_sic[i].name, "sic_%d_MCM0",
				e2k_uncore_sic[i].node);
			break;

		case 1:
			e2k_uncore_sic[i].valid_events = sic_MCM1_valid_events;
			e2k_uncore_sic[i].pmu.attr_groups = (const struct
				attribute_group **)e2k_sic_MCM1_attr_group;
			sprintf(e2k_uncore_sic[i].name, "sic_%d_MCM1",
				e2k_uncore_sic[i].node);
			break;
		default:
			break;
		}
	}

	for (i = 0; i < num_counters; i++) {
		perf_pmu_register(&e2k_uncore_sic[i].pmu,
				e2k_uncore_sic[i].name, -1);
	}

	return 0;
}

static void __init e2k_uncore_pmu_exit(struct e2k_uncore *uncore,
					int num_per_machine)
{
	int i;

	if (uncore) {

		for (i = 0; i < num_per_machine; i++)
			perf_pmu_unregister(&uncore[i].pmu);

		kfree(uncore);
	}
}

static int __init e2k_uncore_init(void)
{
	int ret = 0;

	if (E2K_UNCORE_HAS_IPCC) {
		ret = register_ipcc_pmus();
		if (ret)
			goto err_ipcc;
	}
	if (E2K_UNCORE_HAS_IOCC) {
		ret = register_iocc_pmus();
		if (ret)
			goto err_iocc;
	}
	if (E2K_UNCORE_HAS_SIC) {
		ret = register_sic_pmus();
		if (ret)
			goto err_sic;
	}

	return 0;

err_sic:
	e2k_uncore_pmu_exit(e2k_uncore_sic, NUM_COUNTERS_SIC);
err_iocc:
	e2k_uncore_pmu_exit(e2k_uncore_iocc, NUM_COUNTERS_IOCC);
err_ipcc:
	e2k_uncore_pmu_exit(e2k_uncore_ipcc, NUM_COUNTERS_IPCC);

	return ret;
}
device_initcall(e2k_uncore_init);
