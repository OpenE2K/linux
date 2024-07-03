/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * This is mainly copied from drivers/perf/arm_spe_pmu.c
 * so any updates to that file should be merged here.
 */
#include <linux/bitops.h>
#include <linux/bug.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/export.h>
#include <linux/perf_event.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/vmalloc.h>

#include <asm/barrier.h>
#include <asm/mmu.h>

struct dimtp_buf {
	int nr_pages;
	bool snapshot;
	void *base;
};

struct dimtp_pmu {
	struct pmu				pmu;
	struct perf_output_handle __percpu	*handle;
};

typedef union {
	struct {
		u64 event	: 8;
		u64 mode	: 4;
		u64 __unused	: 52;
	};
	u64 word;
} dimtp_config_attr_t;

/* Returns -1 in case of bad configuration */
static inline int config_to_size(dimtp_config_attr_t cfg)
{
	switch (cfg.mode) {
	case 2:
	case 8:
		return 8;
	case 3:
	case 9:
		return 16;
	case 10:
		return 32;
	case 11:
		return 64;
	case 12:
		return 128;
	case 13:
		return 256;
	default:
		return -1;
	}
}

PMU_FORMAT_ATTR(event, "config:0-7");
PMU_FORMAT_ATTR(mode, "config:8-11");

static struct attribute *dimtp_format_attr[] = {
	&format_attr_event.attr,
	&format_attr_mode.attr,
	NULL,
};

/* Convert a free-running index from perf into an DIMTP buffer offset */
#define PERF_IDX2OFF(idx, buf)	((idx) % ((buf)->nr_pages << PAGE_SHIFT))
static inline u64 perf_idx_round_down(u64 idx, struct dimtp_buf *buf) {
	u64 buf_size = (buf)->nr_pages << PAGE_SHIFT;

	return (idx / buf_size) * buf_size;
}
static inline u64 perf_idx_round_up(u64 idx, const struct dimtp_buf *buf) {
	u64 buf_size = (buf)->nr_pages << PAGE_SHIFT;

	return ((idx + buf_size - 1) / buf_size) * buf_size;
}

#define to_dimtp_pmu(p) (container_of(p, struct dimtp_pmu, pmu))

static struct attribute_group dimtp_format_group = {
	.name	= "format",
	.attrs	= dimtp_format_attr,
};

static const struct attribute_group *dimtp_attr_groups[] = {
	&dimtp_format_group,
	NULL,
};


static void dimtp_perf_aux_output_end(struct perf_output_handle *handle)
{
	e2k_dimtp_t dimtp;
	struct dimtp_buf *buf = perf_get_aux(handle);
	u64 offset, size;

	machine.save_dimtp(&dimtp);
	offset = dimtp.ind;
	size = offset - PERF_IDX2OFF(handle->head, buf);

	if (buf->snapshot)
		handle->head += size;

	perf_aux_output_end(handle, size);
}

/* Perf callbacks */
static int dimtp_event_init(struct perf_event *event)
{
	struct perf_event_attr *attr = &event->attr;
	dimtp_config_attr_t config = { .word = event->attr.config };
	struct dimtp_pmu *dimtp_pmu = to_dimtp_pmu(event->pmu);

	if (attr->type != event->pmu->type)
		return -ENOENT;

	if (attr->exclude_idle)
		return -EOPNOTSUPP;

	/*
	 * Feedback-directed frequency throttling doesn't work when we
	 * have a buffer of samples. We'd need to manually count the
	 * samples in the buffer when it fills up and adjust the event
	 * count to reflect that. Instead, just force the user to specify
	 * a sample period.
	 */
	if (attr->freq) {
		pr_info_ratelimited("%s: feedback-directed frequency throttling does not work with dimtp, please provide a sampling period\n",
				event->pmu->name);
		return -EINVAL;
	}

	if (event->hw.sample_period < 5) {
		pr_info_ratelimited("%s: dimtp counting period %llu is imprecise and not allowed, please enter a value that is >=5\n",
				event->pmu->name, event->hw.sample_period);
		return -EINVAL;
	}

	if (config_to_size(config) <= 0) {
		pr_info_ratelimited("%s: bad dimtp.mode %d\n",
				event->pmu->name, config.mode);
		return -EINVAL;
	}

	/*
	 * Save configuration
	 */
	if (!event->attr.exclude_user)
		event->hw.config |= ARCH_PERFMON_USR;
	if (!event->attr.exclude_kernel)
		event->hw.config |= ARCH_PERFMON_OS;

	return 0;
}

static void dimtp_pad_buf(struct perf_output_handle *handle, unsigned long len)
{
	struct dimtp_buf *buf = perf_get_aux(handle);
	u64 head = PERF_IDX2OFF(handle->head, buf);

	memset(buf->base + head, 0, len);
	if (!buf->snapshot)
		perf_aux_output_skip(handle, len);
}

static u64 __dimtp_next_off(struct perf_output_handle *handle,
		const struct dimtp_buf *buf)
{
	u64 head, limit, tail, wakeup;

	pr_debug("Initial handle: head 0x%lx, size 0x%lx, wakeup 0x%lx\n",
			handle->head, handle->size, handle->wakeup);

	/*
	 * The head can be misaligned if we used perf_aux_output_skip
	 * to consume handle->size bytes and CIRC_SPACE was used in
	 * perf_aux_output_begin to compute the size, which always
	 * leaves one entry free.
	 *
	 * Deal with this by padding to the next alignment boundary and
	 * moving the head index. If we run out of buffer space, we'll
	 * reduce handle->size to zero and end up reporting truncation.
	 */
	head = PERF_IDX2OFF(handle->head, buf);
	if (!IS_ALIGNED(head, E2K_DIMTP_ALIGN)) {
		unsigned long delta = roundup(head, E2K_DIMTP_ALIGN) - head;

		delta = min(delta, handle->size);
		dimtp_pad_buf(handle, delta);
		head = PERF_IDX2OFF(handle->head, buf);
		WARN_ON_ONCE((s64) handle->size < 0);
	}

	pr_debug("Aligned handle: head 0x%lx, size 0x%lx, wakeup 0x%lx\n",
			handle->head, handle->size, handle->wakeup);

	/* If we've run out of free space, then nothing more to do */
	if (!handle->size)
		goto no_space;

	/* Compute the tail and wakeup indices now that we've aligned head */
	tail = PERF_IDX2OFF(handle->head + handle->size, buf);
	wakeup = PERF_IDX2OFF(handle->wakeup, buf);

	/*
	 * Avoid clobbering unconsumed data. We know we have space, so
	 * if we see head == tail we know that the buffer is empty. If
	 * head > tail, then there's nothing to clobber prior to
	 * wrapping.
	 */
	if (head < tail)
		limit = round_down(tail, E2K_DIMTP_ALIGN);
	else
		limit = buf->nr_pages * PAGE_SIZE;

	pr_debug("Computed head 0x%llx, tail 0x%llx, wakeup 0x%llx, limit 0x%llx\n",
			head, tail, wakeup, limit);

	/*
	 * Wakeup may be arbitrarily far into the future. If it's not in
	 * the current generation, either we'll wrap before hitting it,
	 * or it's in the past and has been handled already.
	 *
	 * If there's a wakeup before we wrap, arrange to be woken up by
	 * the page boundary following it. Keep the tail boundary if
	 * that's lower.
	 */
	if (handle->wakeup < (handle->head + handle->size) && head <= wakeup) {
		limit = min(limit, round_up(wakeup, E2K_DIMTP_ALIGN));
		pr_debug("limit 0x%llx now rounded down to wakeup\n", limit);
	}

	if (limit <= head) {
		dimtp_pad_buf(handle, handle->size);
		goto no_space;
	}

	return limit;

no_space:
	pr_debug("Truncating handle: head 0x%lx, size 0x%lx, wakeup 0x%lx\n",
			handle->head, handle->size, handle->wakeup);
	perf_aux_output_flag(handle, PERF_AUX_FLAG_TRUNCATED);
	perf_aux_output_end(handle, 0);
	return 0;
}


static u64 dimtp_next_off(struct perf_output_handle *handle,
		const struct dimtp_buf *buf, dimtp_config_attr_t config)
{
	u64 limit = __dimtp_next_off(handle, buf);
	u64 head = PERF_IDX2OFF(handle->head, buf);

	/*
	 * If the head has come too close to the end of the buffer,
	 * then pad to the end and recompute the limit.
	 */
	if (limit && (limit - head < config_to_size(config))) {
		dimtp_pad_buf(handle, limit - head);
		limit = __dimtp_next_off(handle, buf);
	}

	return limit;
}

static u64 dimtp_next_snapshot_off(struct perf_output_handle *handle,
		const struct dimtp_buf *buf, dimtp_config_attr_t config)
{
	u64 limit, head;

	head = PERF_IDX2OFF(handle->head, buf);

	/*
	 * On e2k  entry beginning is market with 63rd bit
	 * so there is no need to split buffer in two parts
	 * as ARM SPE driver does - contents of the whole
	 * buffer will still be parseable.
	 */
	limit = buf->nr_pages * PAGE_SIZE;

	/*
	 * If we're within max record size of the limit, we must
	 * pad, move the head index and recompute the limit.
	 */
	if (limit - head < config_to_size(config)) {
		dimtp_pad_buf(handle, limit - head);
		handle->head = perf_idx_round_up(handle->head, buf);
	}

	return limit;
}

static void dimtp_start(struct perf_event *event, int flags)
{
	struct hw_perf_event *hwc = &event->hw;
	dimtp_config_attr_t config = { .word = event->attr.config };
	struct dimtp_pmu *dimtp_pmu = to_dimtp_pmu(event->pmu);
	struct perf_output_handle *handle = this_cpu_ptr(dimtp_pmu->handle);
	struct dimtp_buf *buf;
	e2k_dimcr_t dimcr;
	e2k_dimtp_t dimtp;
	u64 limit;

	hwc->state = 0;

	/* Start a new aux session */
	buf = perf_aux_output_begin(handle, event);
	if (!buf) {
		event->hw.state |= PERF_HES_STOPPED;
		return;
	}

	limit = (buf->snapshot) ? dimtp_next_snapshot_off(handle, buf, config) :
				  dimtp_next_off(handle, buf, config);

	if (flags & PERF_EF_RELOAD) {
		u64 left = local64_read(&hwc->period_left);
		WRITE_DIMAR0_REG_VALUE(-left);

		WRITE_DIMAR1_REG_VALUE(-hwc->sample_period);
	}

	dimtp.base = (unsigned long) buf->base;
	dimtp.ind = PERF_IDX2OFF(handle->head, buf);
	dimtp.size = limit;
	dimtp.rw = 3;
	machine.restore_dimtp(&dimtp);

	AW(dimcr) = 0;
	dimcr.mode = config.mode;
	AS(dimcr)[0].event = config.event;
	AS(dimcr)[0].user = !!(hwc->config & ARCH_PERFMON_USR);
	AS(dimcr)[0].system = !!(hwc->config & ARCH_PERFMON_OS);
	WRITE_DIMCR_REG(dimcr);
}

static void dimtp_stop(struct perf_event *event, int flags)
{
	e2k_dimcr_t dimcr;
	struct dimtp_pmu *dimtp_pmu = to_dimtp_pmu(event->pmu);
	struct hw_perf_event *hwc = &event->hw;
	struct perf_output_handle *handle = this_cpu_ptr(dimtp_pmu->handle);

	/* If we're already stopped, then nothing to do */
	if (hwc->state & PERF_HES_STOPPED)
		return;

	/* Stop all trace generation */
	dimcr = READ_DIMCR_REG();
	dimcr.mode = 0;
	AS(dimcr)[0].system = 0;
	AS(dimcr)[0].user = 0;
	AS(dimcr)[1].system = 0;
	AS(dimcr)[1].user = 0;
	WRITE_DIMCR_REG(dimcr);

	if (flags & PERF_EF_UPDATE) {
		u64 left;

		/*
		 * If there's a fault pending then ensure we contain it
		 * to this buffer, since we might be on the context-switch
		 * path.
		 */
		if (perf_get_aux(handle)) {
			e2k_dibsr_t dibsr;

			dimtp_perf_aux_output_end(handle);

			dibsr = READ_DIBSR_REG();
			if (dibsr.m0) {
				dibsr.m0 = 0;
				WRITE_DIBSR_REG(dibsr);
			}
		}

		left = READ_DIMAR0_REG_VALUE();
		left = (left) ? -left : 1;
		local64_set(&hwc->period_left, left);
		hwc->state |= PERF_HES_UPTODATE;
	}

	hwc->state |= PERF_HES_STOPPED;
}

static int dimtp_add(struct perf_event *event, int flags)
{
	struct hw_perf_event *hwc = &event->hw;
	int ret = 0;

	if (WARN_ON_ONCE(!hwc->sample_period))
		return -EOPNOTSUPP;

	if (__this_cpu_read(perf_monitors_used) & (DIM0 | DIM1))
		return -ENOSPC;

	hwc->state = PERF_HES_UPTODATE | PERF_HES_STOPPED;
	if (flags & PERF_EF_START) {
		dimtp_start(event, PERF_EF_RELOAD);
		if (hwc->state & PERF_HES_STOPPED)
			ret = -EINVAL;
	}

	if (!ret) {
		__this_cpu_write(cpu_events[0], event);
		__this_cpu_or(perf_monitors_used, (DIM0 | DIM1));
	}

	return ret;
}

static void dimtp_del(struct perf_event *event, int flags)
{
	dimtp_stop(event, PERF_EF_UPDATE);

	BUG_ON((__this_cpu_read(perf_monitors_used) & (DIM0 | DIM1) !=
			(DIM0 | DIM1)));
	__this_cpu_write(cpu_events[0], NULL);
	__this_cpu_and(perf_monitors_used, ~(DIM0 | DIM1));
}

static void dimtp_read(struct perf_event *event)
{
}

static void *dimtp_setup_aux(struct perf_event *event, void **pages,
				   int nr_pages, bool snapshot)
{
	int i, cpu = event->cpu;
	struct page **pglist;
	struct dimtp_buf *buf;

	if (!nr_pages)
		return NULL;

	if (cpu == -1)
		cpu = raw_smp_processor_id();

	buf = kzalloc_node(sizeof(*buf), GFP_KERNEL, cpu_to_node(cpu));
	if (!buf)
		return NULL;

	pglist = kcalloc(nr_pages, sizeof(*pglist), GFP_KERNEL);
	if (!pglist)
		goto error_free_buf;

	for (i = 0; i < nr_pages; ++i)
		pglist[i] = virt_to_page(pages[i]);

	buf->base = vmap(pglist, nr_pages, VM_MAP, PAGE_KERNEL);
	if (!buf->base)
		goto error_free_pglist;

	buf->nr_pages	= nr_pages;
	buf->snapshot	= snapshot;

	kfree(pglist);
	return buf;

error_free_pglist:
	kfree(pglist);
	error_free_buf:
	kfree(buf);
	return NULL;
}

static void dimtp_free_aux(void *aux)
{
	struct dimtp_buf *buf = aux;

	vunmap(buf->base);
	kfree(buf);
}

static struct dimtp_pmu dimtp_pmu = {
	.pmu = {
		.capabilities	= PERF_PMU_CAP_EXCLUSIVE | PERF_PMU_CAP_ITRACE,

		/*
		 * We hitch a ride on the software context here, so that
		 * we can support per-task profiling (which is not possible
		 * with the invalid context as it doesn't get sched callbacks).
		 * This requires that userspace either uses a dummy event for
		 * perf_event_open, since the aux buffer is not setup until
		 * a subsequent mmap, or creates the profiling event in a
		 * disabled state and explicitly PERF_EVENT_IOC_ENABLEs it
		 * once the buffer has been created.
		 */
		.task_ctx_nr	= perf_sw_context,

		.event_init	= dimtp_event_init,
		.add		= dimtp_add,
		.del		= dimtp_del,

		.start		= dimtp_start,
		.stop		= dimtp_stop,
		.read		= dimtp_read,

		.setup_aux	= dimtp_setup_aux,
		.free_aux	= dimtp_free_aux,

		.attr_groups	= dimtp_attr_groups,
	}
};

void dimtp_overflow(struct perf_event *event)
{
	struct perf_output_handle *handle;

	WARN_ON_ONCE(event->pmu->type != dimtp_pmu.pmu.type);

	handle = this_cpu_ptr(dimtp_pmu.handle);
	if (!perf_get_aux(handle))
		return;

	dimtp_perf_aux_output_end(handle);

	/*
	 * Ensure perf callbacks have completed, which may disable the
	 * profiling buffer in response to a TRUNCATION flag.
	 */
	irq_work_run();

	/*
	 * We handled the fault (the buffer was full), so resume
	 * profiling as long as we didn't detect truncation.
	 */
	if (handle->aux_flags & PERF_AUX_FLAG_TRUNCATED)
		return;

	/* Start a new aux session */
	dimtp_start(event, PERF_EF_RELOAD);
}

static int __init dimtp_pmu_init(void)
{
	int ret;

	if (machine.native_iset_ver < E2K_ISET_V6)
		return 0;

	dimtp_pmu.handle = alloc_percpu(typeof(*dimtp_pmu.handle));
	if (!dimtp_pmu.handle)
		return -ENOMEM;

	ret = perf_pmu_register(&dimtp_pmu.pmu, "dimtp_trace", -1);
	if (ret)
		goto out_free_handle;

	return 0;

out_free_handle:
	free_percpu(dimtp_pmu.handle);
	return ret;
}
arch_initcall(dimtp_pmu_init);
