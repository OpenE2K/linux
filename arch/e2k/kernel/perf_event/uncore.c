/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/perf_event.h>
#include <linux/nodemask.h>
#include <asm/perf_event_uncore.h>

static cpumask_t uncore_cpu_mask;
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
 *    (for example sic_MCM_events)
 *    Be careful, values from descriptions are passed by parser
 *    to perf_event_open() into attr.config field
 *
 * 4) Fill struct attribute
 *    (for example e2k_sic_MCM_events_attrs)
 *
 * 5) Fill struct attribute_group
 *    (for example e2k_sic_MCM_attr_group)
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

ssize_t e2k_uncore_event_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	struct e2k_uncore_event_desc *event =
		container_of(attr, struct e2k_uncore_event_desc, attr);
	return sprintf(buf, "%s", event->config);
}

static ssize_t uncore_get_attr_cpumask(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	return cpumap_print_to_pagebuf(true, buf, &uncore_cpu_mask);
}

static DEVICE_ATTR(cpumask, S_IRUGO, uncore_get_attr_cpumask, NULL);

static struct attribute *uncore_pmu_attrs[] = {
	&dev_attr_cpumask.attr,
	NULL,
};

const struct attribute_group e2k_cpumask_attr_group = {
	.attrs = uncore_pmu_attrs,
};

static struct e2k_uncore *event_to_e2k_uncore(struct perf_event *event)
{
	return container_of(event->pmu, struct e2k_uncore, pmu);
}


void e2k_uncore_start(struct perf_event *event, int flags)
{
	struct hw_perf_event *hwc = &event->hw;
	struct e2k_uncore *uncore = event_to_e2k_uncore(event);

	if (flags & PERF_EF_RELOAD)
		uncore->reg_ops->set_cnt(uncore, hwc,
					 local64_read(&hwc->prev_count));

	hwc->state = 0;

	uncore->reg_ops->set_cfg(uncore, hwc, true);
	perf_event_update_userpage(event);
}


static int uncore_validate_event(struct perf_event *event)
{
	struct e2k_uncore *uncore = event_to_e2k_uncore(event);
	u64 event_id;
	int i, ret;

	event_id = uncore->get_event(&event->hw);

	ret = -EINVAL;
	for (i = 0; uncore->valid_events[i].first != -1 ||
		    uncore->valid_events[i].last != -1; i++) {
		if (event_id >= uncore->valid_events[i].first &&
		    event_id <= uncore->valid_events[i].last) {
			ret = 0;
			break;
		}
	}
	if (ret) {
		pr_info_ratelimited("uncore: event %llu does not exist\n",
				event_id);
		return ret;
	}

	if (uncore->validate_event) {
		ret = uncore->validate_event(uncore, &event->hw);
		if (ret)
			return ret;
	}

	return 0;
}

int e2k_uncore_event_init(struct perf_event *event)
{
	struct e2k_uncore *uncore = event_to_e2k_uncore(event);
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

	return uncore_validate_event(event);
}

int e2k_uncore_add(struct perf_event *event, int flags)
{
	int i, ret;
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

	/* if didn't find, take the first available counter */
	hwc->idx = -1;
	if (uncore->add_event) {
		ret = uncore->add_event(uncore, event);
		if (ret)
			return ret;
	} else {
		for (i = 0; i < uncore->num_counters; i++) {
			if (cmpxchg(&uncore->events[i], NULL, event) == NULL) {
				hwc->idx = i;
				break;
			}
		}
	}

out:
	if (hwc->idx == -1)
		return -EBUSY;

	hwc->state = PERF_HES_UPTODATE | PERF_HES_STOPPED;

	if (flags & PERF_EF_START)
		e2k_uncore_start(event, PERF_EF_RELOAD);

	return 0;
}

void e2k_uncore_read(struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;
	struct e2k_uncore *uncore = event_to_e2k_uncore(event);
	u64 prev, new;

	new = uncore->reg_ops->get_cnt(uncore, hwc);
	prev = local64_xchg(&hwc->prev_count, new);

	local64_add(new - prev, &event->count);

	pr_debug("event %px: updating, prev_count was %lld, now %lld, added delta %lld\n",
		event, prev, new, new - prev);
}

void e2k_uncore_stop(struct perf_event *event, int flags)
{
	struct hw_perf_event *hwc = &event->hw;
	struct e2k_uncore *uncore = event_to_e2k_uncore(event);

	uncore->reg_ops->set_cfg(uncore, hwc, false);
	hwc->state |= PERF_HES_STOPPED;

	if ((flags & PERF_EF_UPDATE) && !(hwc->state & PERF_HES_UPTODATE)) {
		e2k_uncore_read(event);
		hwc->state |= PERF_HES_UPTODATE;
	}
}

void e2k_uncore_del(struct perf_event *event, int flags)
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

static int __init e2k_uncore_init(void)
{
	int init_ret = 0, ret;

	cpumask_set_cpu(0, &uncore_cpu_mask);

	if (E2K_UNCORE_HAS_IPCC) {
		ret = register_ipcc_pmus();
		if (ret) {
			pr_info("WARNING Could not register IPCC pmu\n");
			init_ret = ret;
		}
	}
	if (E2K_UNCORE_HAS_IOCC) {
		ret = register_iocc_pmus();
		if (ret) {
			pr_info("WARNING Could not register IOCC pmu\n");
			init_ret = ret;
		}
	}
	if (E2K_UNCORE_HAS_SIC) {
		ret = register_sic_pmus();
		if (ret) {
			pr_info("WARNING Could not register SIC pmu\n");
			init_ret = ret;
		}
	}
	if (E2K_UNCORE_HAS_HMU) {
		ret = register_hmu_pmus();
		if (ret) {
			pr_info("WARNING Could not register HMU pmu\n");
			init_ret = ret;
		}
	}
	if (E2K_UNCORE_HAS_IOMMU) {
		ret = register_iommu_pmus();
		if (ret) {
			pr_info("WARNING Could not register IOMMU pmu\n");
			init_ret = ret;
		}
	}
	if (E2K_UNCORE_HAS_HC) {
		ret = register_hc_pmus();
		if (ret) {
			pr_info("WARNING Could not register HC pmu\n");
			init_ret = ret;
		}
	}
	if (E2K_UNCORE_HAS_PREPIC) {
		ret = register_prepic_pmus();
		if (ret) {
			pr_info("WARNING Could not register HC pmu\n");
			init_ret = ret;
		}
	}
	if (E2K_UNCORE_HAS_MC) {
		ret = register_mc_pmus();
		if (ret) {
			pr_info("WARNING Could not register MC pmu\n");
			init_ret = ret;
		}
	}

	return init_ret;
}
device_initcall(e2k_uncore_init);
