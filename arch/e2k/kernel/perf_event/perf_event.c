/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/list.h>
#include <linux/perf_event.h>
#include <asm/e2k_debug.h>

static inline bool is_glue(u64 ip)
{
	return ip >= (u64) __entry_handlers_start && ip < (u64) __entry_handlers_end ||
			ip >= (u64) _t_entry && ip < (u64) _t_entry_end;
}


struct save_stack_address_args {
	struct perf_callchain_entry_ctx *entry;
	u64 top;
	u64 type;
};

static int save_stack_address(e2k_mem_crs_t *frame, unsigned long real_frame_addr,
		unsigned long corrected_frame_addr, chain_write_fn_t write_frame, void *arg)
{
	struct save_stack_address_args *args = arg;
	struct perf_callchain_entry_ctx *entry = args->entry;
	u64 top = args->top;
	u64 type = args->type;
	u64 ip;

	if (unlikely(entry->nr >= entry->max_stack))
		return 1;

	/*
	 * Skip entries that correspond to the perf itself.
	 */
	if (corrected_frame_addr > top)
		return 0;

	/*
	 * When storing user callchain, skip all kernel entries.
	 * When storing kernel callchain, stop at the first user entry.
	 */
	if (AS(frame->cr1_lo).pm) {
		if (type != PERF_CONTEXT_KERNEL)
			return 0;
	} else {
		if (type != PERF_CONTEXT_USER)
			return 1;
	}

	ip = AS_STRUCT(frame->cr0_hi).ip << 3;

	/*
	 * Skip syscall and trap glue cause it obfuscates the trace.
	 */
	if (!is_glue(ip))
		perf_callchain_store(entry, ip);

	return 0;
}

/*
 * Save stack-backtrace addresses into a perf_callchain_entry buffer.
 */
void perf_callchain_user(struct perf_callchain_entry_ctx *entry,
			 struct pt_regs *regs)
{
	struct save_stack_address_args args;

	args.entry = entry;
	args.top = AS(regs->stacks.pcsp_lo).base + AS(regs->stacks.pcsp_hi).ind;
	args.type = PERF_CONTEXT_USER;
	parse_chain_stack(true, NULL, save_stack_address, &args);
}

void perf_callchain_kernel(struct perf_callchain_entry_ctx *entry,
			   struct pt_regs *regs)
{
	struct save_stack_address_args args;

	args.entry = entry;
	args.top = AS(regs->stacks.pcsp_lo).base + AS(regs->stacks.pcsp_hi).ind;
	args.type = PERF_CONTEXT_KERNEL;
	parse_chain_stack(false, NULL, save_stack_address, &args);
}


DEFINE_PER_CPU(struct perf_event * [4], cpu_events);

static struct pmu e2k_pmu;

static void e2k_pmu_read(struct perf_event *event);

static bool skip_event(struct perf_event *event, struct pt_regs *regs)
{
	unsigned long ip = perf_instruction_pointer(regs);

	/* Skip idle */
	if (event->attr.exclude_idle && is_idle_task(current) &&
			(cpu_in_idle(ip) || irq_count() == NMI_OFFSET))
		return true;

	/* Exclude return operation from kernel to user */
	if (event->attr.exclude_kernel && ip >= TASK_SIZE)
		return true;

	/* Exclude call operation from user to kernel */
	if (event->attr.exclude_user && ip < TASK_SIZE)
		return true;

	return false;
}

static int handle_event(struct perf_event *event, struct pt_regs *regs)
{
	struct hw_perf_event *hwc = &event->hw;
	struct perf_sample_data data;

	/*
	 * For some reason this is not done automatically...
	 */
	if (hwc->sample_period)
		hwc->last_period = hwc->sample_period;

	/*
	 * Update event->count
	 */
	e2k_pmu_read(event);

	perf_sample_data_init(&data, 0, hwc->last_period);

	if (skip_event(event, regs))
		return perf_event_account_interrupt(event);
	else
		return perf_event_overflow(event, &data, regs);
}

static s64 monitor_pause(struct perf_event *event,
			 struct hw_perf_event *hwc, int update);

DEFINE_PER_CPU(u8, perf_monitors_used);

void dimcr_continue(e2k_dimcr_t dimcr_old)
{
	struct perf_event *event0, *event1;
	e2k_dimcr_t dimcr;

	event0 = __this_cpu_read(cpu_events[0]);
	event1 = __this_cpu_read(cpu_events[1]);

	/*
	 * Restart counting
	 */
	BUG_ON(event0 && event0->hw.idx != 0 || event1 && event1->hw.idx != 1);
	dimcr = READ_DIMCR_REG();
	AS(dimcr)[0].user = (!event0)
			? AS(dimcr_old)[0].user
			: (!(event0->hw.state & PERF_HES_STOPPED) &&
			   (event0->hw.config & ARCH_PERFMON_USR));
	AS(dimcr)[0].system = (!event0)
			? AS(dimcr_old)[0].system
			: (!(event0->hw.state & PERF_HES_STOPPED) &&
			   (event0->hw.config & ARCH_PERFMON_OS));
	AS(dimcr)[1].user = (!event1)
			? AS(dimcr_old)[1].user
			: (!(event1->hw.state & PERF_HES_STOPPED) &&
			   (event1->hw.config & ARCH_PERFMON_USR));
	AS(dimcr)[1].system = (!event1)
			? AS(dimcr_old)[1].system
			: (!(event1->hw.state & PERF_HES_STOPPED) &&
			   (event1->hw.config & ARCH_PERFMON_OS));
	WRITE_DIMCR_REG(dimcr);
}

void ddmcr_continue(e2k_ddmcr_t ddmcr_old)
{
	struct perf_event *event0, *event1;
	e2k_ddmcr_t ddmcr;

	event0 = __this_cpu_read(cpu_events[2]);
	event1 = __this_cpu_read(cpu_events[3]);

	/*
	 * Restart counting
	 */
	BUG_ON(event0 && event0->hw.idx != 0 || event1 && event1->hw.idx != 1);
	ddmcr = READ_DDMCR_REG();
	AS(ddmcr)[0].user = (!event0)
			? AS(ddmcr_old)[0].user
			: (!(event0->hw.state & PERF_HES_STOPPED) &&
			   (event0->hw.config & ARCH_PERFMON_USR));
	AS(ddmcr)[0].system = (!event0)
			? AS(ddmcr_old)[0].system
			: (!(event0->hw.state & PERF_HES_STOPPED) &&
			   (event0->hw.config & ARCH_PERFMON_OS));
	AS(ddmcr)[1].user = (!event1)
			? AS(ddmcr_old)[1].user
			: (!(event1->hw.state & PERF_HES_STOPPED) &&
			   (event1->hw.config & ARCH_PERFMON_USR));
	AS(ddmcr)[1].system = (!event1)
			? AS(ddmcr_old)[1].system
			: (!(event1->hw.state & PERF_HES_STOPPED) &&
			   (event1->hw.config & ARCH_PERFMON_OS));
	WRITE_DDMCR_REG(ddmcr);
}

static s64 handle_event_overflow(const char *name,
		struct perf_event *event, struct pt_regs *regs)
{
	struct hw_perf_event *hwc = &event->hw;
	s64 period;

	int ret = handle_event(event, regs);
	if (ret)
		monitor_pause(event, hwc, 0);

	period = hwc->sample_period;
	local64_set(&hwc->prev_count, period);

	pr_debug("%s event %lx %shandled, new period %lld\n",
			name, event, (ret) ? "could not be " : "", period);

	return period;
}

void perf_data_overflow_handle(struct pt_regs *regs)
{
	e2k_ddbsr_t ddbsr;
	struct perf_event *event0, *event1;
	u8 monitors_used;

	monitors_used = __this_cpu_read(perf_monitors_used);
	event0 = __this_cpu_read(cpu_events[2]);
	event1 = __this_cpu_read(cpu_events[3]);

	ddbsr = READ_DDBSR_REG();

	pr_debug("data overflow, ddbsr %llx, monitors_used 0x%hhx, events 0x%lx/0x%lx\n",
			AW(ddbsr), monitors_used, event0, event1);

	if (ddbsr.m0 && event0 && (monitors_used & DDM0)) {
		s64 period = handle_event_overflow("DDM0", event0, regs);
		WRITE_DDMAR0_REG(-period);
		ddbsr.m0 = 0;
	}

	if (ddbsr.m1 && event1 && (monitors_used & DDM1)) {
		s64 period = handle_event_overflow("DDM1", event1, regs);
		WRITE_DDMAR1_REG(-period);
		ddbsr.m1 = 0;
	}

	/*
	 * Clear status fields
	 */
	WRITE_DDBSR_REG(ddbsr);
}

void perf_instr_overflow_handle(struct pt_regs *regs)
{
	e2k_dibsr_t dibsr;
	struct perf_event *event0, *event1;
	u8 monitors_used;

	monitors_used = __this_cpu_read(perf_monitors_used);
	event0 = __this_cpu_read(cpu_events[0]);
	event1 = __this_cpu_read(cpu_events[1]);

	dibsr = READ_DIBSR_REG();

	pr_debug("instr overflow, dibsr %x, monitors_used 0x%hhx, events 0x%lx/0x%lx\n",
			AW(dibsr), monitors_used, event0, event1);

	if (dibsr.m0 && event0 && (monitors_used & DIM0)) {
		/* This could be an event from DIMTP overflow */
		if (event0->pmu->type != e2k_pmu.type) {
			dimtp_overflow(event0);
		} else {
			regs->trap->dim_ip = READ_DIMAR0_REG_VALUE();
			regs->trap->dim_ip_valid = 1;
			s64 period = handle_event_overflow("DIM0", event0, regs);
			WRITE_DIMAR0_REG_VALUE(-period);
		}
		dibsr.m0 = 0;
	}

	if (dibsr.m1 && event1 && (monitors_used & DIM1)) {
		regs->trap->dim_ip = READ_DIMAR1_REG_VALUE();
		regs->trap->dim_ip_valid = 1;
		s64 period = handle_event_overflow("DIM1", event1, regs);
		WRITE_DIMAR1_REG_VALUE(-period);
		dibsr.m1 = 0;
	}

	/*
	 * Clear status fields
	 */
	WRITE_DIBSR_REG(dibsr);
}

static void monitor_resume(struct hw_perf_event *hwc, int reload, s64 period)
{
	unsigned long flags;
	e2k_dimcr_t dimcr;
	e2k_ddmcr_t ddmcr;
	e2k_dibcr_t dibcr;
	u8 monitor, event_id;
	int num;

	raw_all_irq_save(flags);

	monitor = (hwc->config & 0xff00) >> 8;
	event_id = hwc->config & 0xff;
	num = hwc->idx;

	/* Clear PERF_HES_STOPPED */
	hwc->state = 0;

	dibcr = READ_DIBCR_REG();
	WARN_ON(dibcr.stop);

	switch (monitor) {
	case DIM0:
	case DIM1:
	case DIM0_DIM1:
		dimcr = READ_DIMCR_REG();
		AS(dimcr)[num].user = !!(hwc->config & ARCH_PERFMON_USR);
		AS(dimcr)[num].system = !!(hwc->config & ARCH_PERFMON_OS);
		AS(dimcr)[num].trap = 1;
		AS(dimcr)[num].event = event_id;
		if (reload) {
			period = -period;

			if (num == 1)
				WRITE_DIMAR1_REG_VALUE(period);
			else
				WRITE_DIMAR0_REG_VALUE(period);
		}
		WRITE_DIMCR_REG(dimcr);
		break;
	case DDM0:
	case DDM1:
	case DDM0_DDM1:
		ddmcr = READ_DDMCR_REG();
		AS(ddmcr)[num].user = !!(hwc->config & ARCH_PERFMON_USR);
		AS(ddmcr)[num].system = !!(hwc->config & ARCH_PERFMON_OS);
		AS(ddmcr)[num].trap = 1;
		AS(ddmcr)[num].event = event_id;
		if (reload) {
			period = -period;

			if (num == 1)
				WRITE_DDMAR1_REG_VALUE(period);
			else
				WRITE_DDMAR0_REG_VALUE(period);
		}
		WRITE_DDMCR_REG(ddmcr);
		break;
	default:
		BUG_ON(1);
	}

	pr_debug("event %hhx:%02hhx: resuming\n", monitor, event_id);

	raw_all_irq_restore(flags);
}

static s64 monitor_pause(struct perf_event *event,
			 struct hw_perf_event *hwc, int update)
{
	unsigned long flags;
	e2k_dimcr_t dimcr;
	e2k_ddmcr_t ddmcr;
	e2k_dibcr_t dibcr;
	u8 monitor, event_id;
	s64 left = 0;
	int num, overflow;

	raw_all_irq_save(flags);

	monitor = (hwc->config & 0xff00) >> 8;
	event_id = hwc->config & 0xff;
	num = hwc->idx;

	hwc->state |= PERF_HES_STOPPED;

	dibcr = READ_DIBCR_REG();
	WARN_ON(dibcr.stop);

	switch (monitor) {
	case DIM0:
	case DIM1:
	case DIM0_DIM1:
		dimcr = READ_DIMCR_REG();
		AS(dimcr)[num].user = 0;
		AS(dimcr)[num].system = 0;
		WRITE_DIMCR_REG(dimcr);
		if (update) {
			e2k_dibsr_t dibsr;

			dibsr = READ_DIBSR_REG();

			overflow = (num == 1 && AS(dibsr).m1) ||
				   (num == 0 && AS(dibsr).m0);

			if (overflow) {
				left = 1;
				pr_debug("event DIM%d: left 0 (1)\n", num);
				/* See comment in monitor_disable() */
				if (num == 1)
					AS(dibsr).m1 = 0;
				else
					AS(dibsr).m0 = 0;
			} else {
				left = (num == 1) ? READ_DIMAR1_REG_VALUE() :
						    READ_DIMAR0_REG_VALUE();
				left = -left;

				pr_debug("event DIM%d: left %lld, dimcr 0x%llx/0x%llx, dibsr 0x%x/0x%x\n",
						num, left, AW(dimcr),
						READ_DIMCR_REG_VALUE(),
						AW(dibsr), READ_DIBSR_REG_VALUE());
			}

			/* We clear m0/m1 even if it is not set. The problem
			 * is that %dibsr is still updated asynchronously
			 * for several cycles after %dimcr write, so it
			 * can be set _after_ we had read %dibsr. */
			WRITE_DIBSR_REG(dibsr);
		}
		break;
	case DDM0:
	case DDM1:
	case DDM0_DDM1:
		ddmcr = READ_DDMCR_REG();
		AS(ddmcr)[num].user = 0;
		AS(ddmcr)[num].system = 0;
		WRITE_DDMCR_REG(ddmcr);
		if (update) {
			e2k_ddbsr_t ddbsr;

			ddbsr = READ_DDBSR_REG();

			overflow = (num == 1 && AS(ddbsr).m1) ||
				   (num == 0 && AS(ddbsr).m0);

			if (overflow) {
				left = 1;
				pr_debug("event DDM%d: left 0 (1)\n", num);
				if (num == 1)
					AS(ddbsr).m1 = 0;
				else
					AS(ddbsr).m0 = 0;
			} else {
				left = (num == 1) ? READ_DDMAR1_REG_VALUE() :
							READ_DDMAR0_REG_VALUE();
				left = -left;

				/*
				 * We could receive some other interrupt right
				 * when ddmar overflowed. Then exc_data_debug
				 * could be lost along with the setting of
				 * %ddbsr.m1 if interrupts in %psr had been
				 * closed just before exc_data_debug arrived.
				 */
				if (cpu_has(CPU_HWBUG_KERNEL_DATA_MONITOR) &&
				    is_sampling_event(event) && left <= 0) {
					pr_debug("event DDM%d: hardware bug, left %lld\n",
						num, left);
					left = 1;
				}
				pr_debug("event DDM%d: left %lld\n", num, left);
			}

			/* We clear m0/m1 even if it is not set. The problem
			 * is that %ddbsr is still updated asynchronously
			 * for several cycles after %ddmcr write, so it
			 * can be set _after_ we had read %ddbsr. */
			WRITE_DDBSR_REG(ddbsr);
		}
		break;
	default:
		BUG_ON(1);
	}

	pr_debug("event %hhx:%02hhx: pausing\n",
			monitor, event_id);

	raw_all_irq_restore(flags);

	return left;
}

static int monitor_enable(u32 monitor, u32 event_id, s64 period,
		struct perf_event *event, int run)
{
	struct hw_perf_event *hwc = &event->hw;
	unsigned long flags;
	e2k_dimcr_t dimcr;
	e2k_ddmcr_t ddmcr;
	e2k_dibcr_t dibcr;
	e2k_dibsr_t dibsr;
	e2k_ddbsr_t ddbsr;
	int num, ret = 0;

	raw_all_irq_save(flags);

	period = -period;

	dibcr = READ_DIBCR_REG();
	WARN_ON(dibcr.stop);

	switch (monitor) {
	case DIM0:
	case DIM1:
	case DIM0_DIM1:
		if (monitor == DIM0_DIM1) {
			if (!(__this_cpu_read(perf_monitors_used) & DIM1)) {
				num = 1;
			} else if (!(__this_cpu_read(perf_monitors_used)
								& DIM0)) {
				num = 0;
			} else {
				ret = -ENOSPC;
				break;
			}

			hwc->idx = num;
		} else {
			num = (monitor == DIM1);

			if (num == 1 &&
				(__this_cpu_read(perf_monitors_used) & DIM1) ||
			    num == 0 &&
			    (__this_cpu_read(perf_monitors_used) & DIM0)) {
				ret = -ENOSPC;
				break;
			}
		}

		dimcr = READ_DIMCR_REG();
		AS(dimcr)[num].user = run && (hwc->config & ARCH_PERFMON_USR) &&
				      !(hwc->state & PERF_HES_STOPPED);
		AS(dimcr)[num].system = 0;
		AS(dimcr)[num].trap = 1;
		AS(dimcr)[num].event = event_id;
		WRITE_DIMCR_REG(dimcr);

		dibsr = READ_DIBSR_REG();

		if (num == 1) {
			WRITE_DIMAR1_REG_VALUE(period);
			AS(dibsr).m1 = 0;

			__this_cpu_write(cpu_events[1], event);

			__this_cpu_or(perf_monitors_used, DIM1);
		} else {
			WRITE_DIMAR0_REG_VALUE(period);
			AS(dibsr).m0 = 0;

			__this_cpu_write(cpu_events[0], event);

			__this_cpu_or(perf_monitors_used, DIM0);
		}

		WRITE_DIBSR_REG(dibsr);

		/*
		 * Start the monitor now that the preparations are done.
		 */
		if (run && (hwc->config & ARCH_PERFMON_OS) &&
		    !(hwc->state & PERF_HES_STOPPED)) {
			AS(dimcr)[num].system = 1;
			WRITE_DIMCR_REG(dimcr);
		}
		break;
	case DDM0:
	case DDM1:
	case DDM0_DDM1:
		if (monitor == DDM0_DDM1) {
			if (!(__this_cpu_read(perf_monitors_used) & DDM1)) {
				num = 1;
			} else if (!(__this_cpu_read(perf_monitors_used)
								& DDM0)) {
				num = 0;
			} else {
				ret = -ENOSPC;
				break;
			}

			hwc->idx = num;
		} else {
			num = (monitor == DDM1);

			if (num == 1 &&
				(__this_cpu_read(perf_monitors_used) & DDM1) ||
			    num == 0 &&
			    (__this_cpu_read(perf_monitors_used) & DDM0)) {
				ret = -ENOSPC;
				break;
			}
		}

		ddmcr = READ_DDMCR_REG();
		AS(ddmcr)[num].user = run && (hwc->config & ARCH_PERFMON_USR) &&
				      !(hwc->state & PERF_HES_STOPPED);
		AS(ddmcr)[num].system = 0;
		AS(ddmcr)[num].trap = 1;
		AS(ddmcr)[num].event = event_id;
		WRITE_DDMCR_REG(ddmcr);

		ddbsr = READ_DDBSR_REG();

		if (num == 1) {
			WRITE_DDMAR1_REG_VALUE(period);
			AS(ddbsr).m1 = 0;

			__this_cpu_write(cpu_events[3], event);

			__this_cpu_or(perf_monitors_used, DDM1);
		} else {
			WRITE_DDMAR0_REG_VALUE(period);
			AS(ddbsr).m0 = 0;

			__this_cpu_write(cpu_events[2], event);

			__this_cpu_or(perf_monitors_used, DDM0);
		}

		WRITE_DDBSR_REG(ddbsr);

		/*
		 * Start the monitor now that the preparations are done.
		 */
		if (run && (hwc->config & ARCH_PERFMON_OS) &&
		    !(hwc->state & PERF_HES_STOPPED)) {
			AS(ddmcr)[num].system = 1;
			WRITE_DDMCR_REG(ddmcr);
		}
		break;
	default:
		BUG_ON(1);
	}

	raw_all_irq_restore(flags);

	return ret;
}

static DEFINE_PER_CPU(int, hw_perf_disable_count);

static s64 monitor_disable(struct hw_perf_event *hwc)
{
	unsigned long flags;
	e2k_dimcr_t dimcr;
	e2k_ddmcr_t ddmcr;
	e2k_dibsr_t dibsr;
	e2k_ddbsr_t ddbsr;
	s64 left;
	int monitor, num;

	monitor = (hwc->config & 0xff00) >> 8;
	num = hwc->idx;

	BUG_ON(!!__this_cpu_read(hw_perf_disable_count) ^
	       !!raw_all_irqs_disabled());
	BUG_ON(!raw_irqs_disabled());

	switch (monitor) {
	case DIM0:
	case DIM1:
	case DIM0_DIM1:
		dimcr = READ_DIMCR_REG();
		AS(dimcr)[num].user = 0;
		AS(dimcr)[num].system = 0;
		/* Note that writing of %dimcr has an important side effect:
		 * it cancels any other pending exc_instr_debug that arrived
		 * while we were still handling this one. */
		WRITE_DIMCR_REG(dimcr);

		raw_all_irq_save(flags);

		left = (num == 1) ? READ_DIMAR1_REG_VALUE() :
				    READ_DIMAR0_REG_VALUE();
		left = -left;

		dibsr = READ_DIBSR_REG();

		if (num == 1) {
			__this_cpu_write(cpu_events[1], NULL);

			BUG_ON(!(__this_cpu_read(perf_monitors_used) & DIM1));
			__this_cpu_and(perf_monitors_used, ~DIM1);

			if (AS(dibsr).m1) {
				left = 1;
				pr_debug("event DIM1: left 0 (1)\n");
				/*
				 * Now clear DIBSR, otherwise an interrupt might
				 * arrive _after_ the event was disabled, and
				 * event handler might re-enable counting (e.g.
				 * if event's frequency has been changed).
				 *
				 * We set left to 1 so that the interrupt will
				 * arrive again after the task has been
				 * scheduled in.
				 *
				 * NOTE: this will lose one event and cause
				 * one spurious interrupt.
				 */
				AS(dibsr).m1 = 0;
			} else {
				pr_debug("event DIM1: left %lld\n", left);
			}
		} else {
			__this_cpu_write(cpu_events[0], NULL);

			BUG_ON(!(__this_cpu_read(perf_monitors_used) & DIM0));
			__this_cpu_and(perf_monitors_used, ~DIM0);

			if (AS(dibsr).m0) {
				left = 1;
				pr_debug("event DIM0: left 0 (1)\n");
				AS(dibsr).m0 = 0;
			} else {
				pr_debug("event DIM0: left %lld\n", left);
			}
		}

		/* We clear m0/m1 even if it is not set. The problem
		 * is that %dibsr is still updated asynchronously
		 * for several cycles after %dimcr write, so it
		 * can be set _after_ we had read %dibsr. */
		WRITE_DIBSR_REG(dibsr);
		break;
	case DDM0:
	case DDM1:
	case DDM0_DDM1:
		ddmcr = READ_DDMCR_REG();
		AS(ddmcr)[num].user = 0;
		AS(ddmcr)[num].system = 0;
		/* Note that writing of %ddmcr has an important side effect:
		 * it cancels any other pending exc_data_debug that arrived
		 * while we were still handling this one. */
		WRITE_DDMCR_REG(ddmcr);

		raw_all_irq_save(flags);

		ddbsr = READ_DDBSR_REG();

		if (num == 1) {
			__this_cpu_write(cpu_events[3], NULL);

			BUG_ON(!(__this_cpu_read(perf_monitors_used) & DDM1));
			__this_cpu_and(perf_monitors_used, ~DDM1);

			if (AS(ddbsr).m1) {
				left = 1;
				pr_debug("event DDM1: left 0 (1)\n");
				AS(ddbsr).m1 = 0;
			} else {
				left = READ_DDMAR1_REG_VALUE();
				left = -left;
				pr_debug("event DDM1: left %lld\n", left);
			}
		} else {
			__this_cpu_write(cpu_events[2], NULL);

			BUG_ON(!(__this_cpu_read(perf_monitors_used) & DDM0));
			__this_cpu_and(perf_monitors_used, ~DDM0);

			if (AS(ddbsr).m0) {
				left = 1;
				pr_debug("event DDM0: left 0 (1)\n");
				AS(ddbsr).m0 = 0;
			} else {
				left = READ_DDMAR0_REG_VALUE();
				left = -left;
				pr_debug("event DDM0: left %lld\n", left);
			}
		}

		/* We clear m0/m1 even if it is not set. The problem
		 * is that %ddbsr is still updated asynchronously
		 * for several cycles after %ddmcr write, so it
		 * can be set _after_ we had read %ddbsr. */
		WRITE_DDBSR_REG(ddbsr);
		break;
	default:
		BUG_ON(1);
	}

	raw_all_irq_restore(flags);

	return left;
}

static s64 monitor_read(u32 monitor, int idx)
{
	s64 left;
	e2k_dibsr_t dibsr;
	e2k_ddbsr_t ddbsr;

	if (monitor == DIM0_DIM1)
		monitor = (idx) ? DIM1 : DIM0;
	else if (monitor == DDM0_DDM1)
		monitor = (idx) ? DDM1 : DDM0;

	switch (monitor) {
	case DIM0:
		dibsr = READ_DIBSR_REG();
		if (AS(dibsr).m0) {
			left = 0;
		} else {
			left = READ_DIMAR0_REG_VALUE();
			left = -left;
		}
		pr_debug("reading DIM0: left %lld (dibsr %d)\n",
				left, AS(dibsr).m0);
		break;
	case DIM1:
		dibsr = READ_DIBSR_REG();
		if (AS(dibsr).m1) {
			left = 0;
		} else {
			left = READ_DIMAR1_REG_VALUE();
			left = -left;
		}
		pr_debug("reading DIM1: left %lld (dibsr %d)\n",
				left, AS(dibsr).m1);
		break;
	case DDM0:
		ddbsr = READ_DDBSR_REG();
		if (AS(ddbsr).m0) {
			left = 0;
		} else {
			left = READ_DDMAR0_REG_VALUE();
			left = -left;
		}
		pr_debug("reading DDM0: left %lld (ddbsr %d)\n",
				left, AS(ddbsr).m0);
		break;
	case DDM1:
		ddbsr = READ_DDBSR_REG();
		if (AS(ddbsr).m1) {
			left = 0;
		} else {
			left = READ_DDMAR1_REG_VALUE();
			left = -left;
		}
		pr_debug("reading DDM1: left %lld (ddbsr %d)\n",
				left, AS(ddbsr).m1);
		break;
	default:
		BUG_ON(1);
	}

	return left;
}


/*
 * On e2k add() and del() functions are more complex than on other
 * architectures: besides starting/stopping the counting they also
 * update perf_event structure.
 *
 * This allows us to select the appropriate counter for DIM0_DIM1 events
 * dynamically. Since perf tries to schedule different event groups
 * together, we cannot select counter at event initialization time.
 *
 * Unfortunately, because of this we must handle overflows from disable()
 * if we catch them, and this can lead to spurious interrupts from monitors
 * if an interrupt was handled here.
 */
static int e2k_pmu_add(struct perf_event *event, int flags)
{
	struct hw_perf_event *hwc = &event->hw;
	s64 period;
	u8 monitor, event_id;

	monitor = (hwc->config & 0xff00) >> 8;
	event_id = hwc->config & 0xff;

	pr_debug("event %lx: enabling %hhx:%02hhx\n"
			"sample_period %lld, left %ld\n",
			event, monitor, event_id, hwc->sample_period,
			local64_read(&hwc->period_left));

	if (hwc->sample_period)
		hwc->last_period = hwc->sample_period;

	if (hwc->sample_period && local64_read(&hwc->period_left))
		period = local64_read(&hwc->period_left);
	else
		period = hwc->sample_period;

	local64_set(&hwc->prev_count, period);

	/*
	 * Zero period means counting from 0
	 * (i.e. we will never stop in this life since
	 * counters are 64-bits long)
	 */
	return monitor_enable((u32) monitor, (u32) event_id, period,
			      event, flags & PERF_EF_START);
}

static void e2k_pmu_update(struct perf_event *event, s64 left)
{
	struct hw_perf_event *hwc = &event->hw;
	s64 prev;

	prev = local64_xchg(&hwc->prev_count, left);

	local64_add(prev - left, &event->count);

	pr_debug("event %lx: updating %llx:%02llx\n"
			"sample_period %lld, count %ld (+%lld)\n"
			"left previously %lld, left now %lld\n",
			event, (hwc->config & 0xff00) >> 8, hwc->config & 0xff,
			hwc->sample_period, local64_read(&event->count),
			prev - left, prev, left);
}

static void e2k_pmu_del(struct perf_event *event, int flags)
{
	struct hw_perf_event *hwc = &event->hw;
	u64 left;

	left = monitor_disable(hwc);
	local64_set(&hwc->period_left, left);

	pr_debug("event %lx: disabling %llx:%02llx\n"
			"sample_period %lld, left %lld\n",
			event, (hwc->config & 0xff00) >> 8,
			hwc->config & 0xff, hwc->sample_period, left);

	e2k_pmu_update(event, left);
}

static void e2k_pmu_read(struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;
	u8 monitor;
	s64 left;

	monitor = (hwc->config & 0xff00) >> 8;
	left = monitor_read((u32) monitor, hwc->idx);

	e2k_pmu_update(event, left);
}

static void e2k_pmu_stop(struct perf_event *event, int flags)
{
	struct hw_perf_event *hwc = &event->hw;
	s64 left;

	left = monitor_pause(event, hwc, flags & PERF_EF_UPDATE);

	if (flags & PERF_EF_UPDATE) {
		local64_set(&hwc->period_left, left);

		pr_debug("event %lx: pausing %llx:%02llx\n"
			"sample_period %lld, left %lld\n",
			event, (hwc->config & 0xff00) >> 8,
			hwc->config & 0xff, hwc->sample_period, left);

		e2k_pmu_update(event, left);
	}
}


static void e2k_pmu_start(struct perf_event *event, int flags)
{
	struct hw_perf_event *hwc = &event->hw;
	s64 left = 0;

	pr_debug("event %lx: resuming %llx:%02llx\n"
		"sample_period %lld\n",
		event, (hwc->config & 0xff00) >> 8, hwc->config & 0xff,
		hwc->sample_period);

	if (flags & PERF_EF_RELOAD) {
		left = local64_read(&hwc->period_left);

		local64_set(&hwc->prev_count, (u64) left);

		pr_debug("event %lx: period_left %lld\n", event, left);
	}

	monitor_resume(hwc, flags & PERF_EF_RELOAD, left);
}


static u8 hardware_events_map[PERF_COUNT_HW_MAX][2] = {
	/* PERF_COUNT_HW_CPU_CYCLES */
	{0, 0},
	/* PERF_COUNT_HW_INSTRUCTIONS */
	{DIM0_DIM1, 0x13},
	/* PERF_COUNT_HW_CACHE_REFERENCES */
	{DDM0, 0x40},
	/* PERF_COUNT_HW_CACHE_MISSES */
	{0, 0},
	/* PERF_COUNT_HW_BRANCH_INSTRUCTIONS */
	{0, 0},
	/* PERF_COUNT_HW_BRANCH_MISSES */
	{0, 0},
	/* PERF_COUNT_HW_BUS_CYCLES */
	{0, 0},
	/* PERF_COUNT_HW_STALLED_CYCLES_FRONTEND */
	{DIM0_DIM1, 0x18},
	/* PERF_COUNT_HW_STALLED_CYCLES_BACKEND = 0x19 + 0x2e + 0x2f */
	{0, 0},
	/* PERF_COUNT_HW_REF_CPU_CYCLES */
	{0, 0}
};

__init
static int init_perf_events_map(void)
{
	if (machine.native_iset_ver >= E2K_ISET_V3) {
		hardware_events_map[PERF_COUNT_HW_CPU_CYCLES][0] = DIM0_DIM1;
		hardware_events_map[PERF_COUNT_HW_CPU_CYCLES][1] = 0x72;
	}

	if (machine.native_iset_ver >= E2K_ISET_V6) {
		hardware_events_map[PERF_COUNT_HW_BRANCH_INSTRUCTIONS][0] = DIM0_DIM1;
		hardware_events_map[PERF_COUNT_HW_BRANCH_INSTRUCTIONS][1] = 0x27;

		hardware_events_map[PERF_COUNT_HW_CACHE_MISSES][0] = DDM0;
		hardware_events_map[PERF_COUNT_HW_CACHE_MISSES][1] = 0x4e;
	}

	return 0;
}
pure_initcall(init_perf_events_map);

static u8 hw_cache_events_map_v3[PERF_COUNT_HW_CACHE_MAX][PERF_COUNT_HW_CACHE_OP_MAX][PERF_COUNT_HW_CACHE_RESULT_MAX][2] = {
	[PERF_COUNT_HW_CACHE_L1D] = {
		[PERF_COUNT_HW_CACHE_OP_WRITE] = {
			[PERF_COUNT_HW_CACHE_RESULT_ACCESS] = {DDM1, 0x1}
		}
	},
	[PERF_COUNT_HW_CACHE_LL] = {
		[PERF_COUNT_HW_CACHE_OP_WRITE] = {
			[PERF_COUNT_HW_CACHE_RESULT_ACCESS] = {DDM1, 0x41}
		}
	},
};

static u8 hw_cache_events_map_v6[PERF_COUNT_HW_CACHE_MAX][PERF_COUNT_HW_CACHE_OP_MAX][PERF_COUNT_HW_CACHE_RESULT_MAX][2] = {
	[PERF_COUNT_HW_CACHE_L1D] = {
		[PERF_COUNT_HW_CACHE_OP_READ] = {
			[PERF_COUNT_HW_CACHE_RESULT_ACCESS] = {DDM0, 0x5},
			[PERF_COUNT_HW_CACHE_RESULT_MISS] = {DDM1, 0x5}
		},
		[PERF_COUNT_HW_CACHE_OP_WRITE] = {
			[PERF_COUNT_HW_CACHE_RESULT_ACCESS] = {DDM0, 0x1},
			[PERF_COUNT_HW_CACHE_RESULT_MISS] = {DDM1, 0x3}
		},
		[PERF_COUNT_HW_CACHE_OP_PREFETCH] = {
			[PERF_COUNT_HW_CACHE_RESULT_ACCESS] = {DDM0, 0x7},
			[PERF_COUNT_HW_CACHE_RESULT_MISS] = {DDM1, 0x6}
		}
	},
	[PERF_COUNT_HW_CACHE_LL] = {
		[PERF_COUNT_HW_CACHE_OP_READ] = {
			[PERF_COUNT_HW_CACHE_RESULT_ACCESS] = {DDM0, 0x4d},
			[PERF_COUNT_HW_CACHE_RESULT_MISS] = {DDM1, 0x4e}
		},
		[PERF_COUNT_HW_CACHE_OP_WRITE] = {
			[PERF_COUNT_HW_CACHE_RESULT_ACCESS] = {DDM1, 0x41},
			[PERF_COUNT_HW_CACHE_RESULT_MISS] = {DDM1, 0x4d}
		},
		[PERF_COUNT_HW_CACHE_OP_PREFETCH] = {
			/* bug 109342 comment 11:
			 * LL-prefetch = l1d-prefetch-miss */
			[PERF_COUNT_HW_CACHE_RESULT_ACCESS] = {DDM1, 0x6},
			[PERF_COUNT_HW_CACHE_RESULT_MISS] = {DDM1, 0x4f}
		}
	},
	[PERF_COUNT_HW_CACHE_DTLB] = {
		[PERF_COUNT_HW_CACHE_OP_READ] = {
			[PERF_COUNT_HW_CACHE_RESULT_ACCESS] = {DDM0, 0x1a},
			[PERF_COUNT_HW_CACHE_RESULT_MISS] = {DDM1, 0x1a}
		},
		[PERF_COUNT_HW_CACHE_OP_WRITE] = {
			[PERF_COUNT_HW_CACHE_RESULT_ACCESS] = {DDM0, 0x1b},
			[PERF_COUNT_HW_CACHE_RESULT_MISS] = {DDM1, 0x1b}
		},
		[PERF_COUNT_HW_CACHE_OP_PREFETCH] = {
			[PERF_COUNT_HW_CACHE_RESULT_ACCESS] = {DDM0, 0x1c},
			[PERF_COUNT_HW_CACHE_RESULT_MISS] = {DDM1, 0x1c}
		}
	}
};

#define MAX_EVENTS 256
static char hw_raw_event_to_iset[MAX_HW_MONITORS][MAX_EVENTS] = {
	[_DDM0] = {
		[0x0 ... 0x3]	= E2K_ISET_SINCE_V3_MASK,
		[0x10 ... 0x16] = E2K_ISET_SINCE_V3_MASK,
		[0x20 ... 0x21] = E2K_ISET_SINCE_V3_MASK,
		[0x30 ... 0x3a] = E2K_ISET_SINCE_V3_MASK,
		[0x40 ... 0x46] = E2K_ISET_SINCE_V3_MASK,
		[0x48]		= E2K_ISET_SINCE_V3_MASK,
		[0x4a ... 0x4b] = E2K_ISET_SINCE_V3_MASK,
		[0x70 ... 0x72] = E2K_ISET_SINCE_V3_MASK,
		[0x17 ... 0x19] = E2K_ISET_SINCE_V3_MASK,
		[0x22 ... 0x24] = E2K_ISET_SINCE_V3_MASK,

		[0x4]		= E2K_ISET_SINCE_V5_MASK,
		[0x47]		= E2K_ISET_SINCE_V5_MASK,

		[0x5 ... 0x7]	= E2K_ISET_SINCE_V6_MASK,
		[0x1a ... 0x1c]	= E2K_ISET_SINCE_V6_MASK,
		[0x49]		= E2K_ISET_SINCE_V6_MASK,
		[0x4c ... 0x4f]	= E2K_ISET_SINCE_V6_MASK,
	},
	[_DDM1] = {
		[0x0 ... 0x2]	= E2K_ISET_SINCE_V3_MASK,
		[0x10 ... 0x16] = E2K_ISET_SINCE_V3_MASK,
		[0x20 ... 0x21] = E2K_ISET_SINCE_V3_MASK,
		[0x30 ... 0x3a] = E2K_ISET_SINCE_V3_MASK,
		[0x40 ... 0x48] = E2K_ISET_SINCE_V3_MASK,
		[0x4a ... 0x4b] = E2K_ISET_SINCE_V3_MASK,
		[0x70 ... 0x72] = E2K_ISET_SINCE_V3_MASK,
		[0x17 ... 0x19] = E2K_ISET_SINCE_V3_MASK,
		[0x22 ... 0x23] = E2K_ISET_SINCE_V3_MASK,

		[0x4]		= E2K_ISET_SINCE_V5_MASK,

		[0x3 ... 0x7]	= E2K_ISET_SINCE_V6_MASK,
		[0x1a ... 0x1c]	= E2K_ISET_SINCE_V6_MASK,
		[0x49]		= E2K_ISET_SINCE_V6_MASK,
		[0x4d ... 0x4f] = E2K_ISET_SINCE_V6_MASK,
	},
	[_DIM0] = {
		[0x0 ... 0x3]	= E2K_ISET_SINCE_V3_MASK,
		[0x7 ... 0xa]	= E2K_ISET_SINCE_V3_MASK,
		[0x10 ... 0x1f] = E2K_ISET_SINCE_V3_MASK,
		[0x20 ... 0x26] = E2K_ISET_SINCE_V3_MASK,
		[0x30 ... 0x3c] = E2K_ISET_SINCE_V3_MASK,
		[0x40 ... 0x4a] = E2K_ISET_SINCE_V3_MASK,
		[0x50 ... 0x5a] = E2K_ISET_SINCE_V3_MASK,
		[0x60 ... 0x69] = E2K_ISET_SINCE_V3_MASK,
		[0x70 ... 0x74] = E2K_ISET_SINCE_V3_MASK,
		[0xf]		= E2K_ISET_SINCE_V3_MASK,
		[0x3d]		= E2K_ISET_SINCE_V3_MASK,

		[0x2d ... 0x2f] = E2K_ISET_SINCE_V5_MASK,

		[0x27]		= E2K_ISET_SINCE_V6_MASK,
	},
	[_DIM1] = {
		/* Almost same as _DIM0 - only 0xf/0x25/0x26 events differ */
		[0x0 ... 0x3]	= E2K_ISET_SINCE_V3_MASK,
		[0x7 ... 0xa]	= E2K_ISET_SINCE_V3_MASK,
		[0x10 ... 0x1f] = E2K_ISET_SINCE_V3_MASK,
		[0x20 ... 0x24] = E2K_ISET_SINCE_V3_MASK,
		[0x30 ... 0x3c] = E2K_ISET_SINCE_V3_MASK,
		[0x40 ... 0x4a] = E2K_ISET_SINCE_V3_MASK,
		[0x50 ... 0x5a] = E2K_ISET_SINCE_V3_MASK,
		[0x60 ... 0x69] = E2K_ISET_SINCE_V3_MASK,
		[0x70 ... 0x74] = E2K_ISET_SINCE_V3_MASK,
		[0x3d]		= E2K_ISET_SINCE_V3_MASK,

		[0x2d ... 0x2f] = E2K_ISET_SINCE_V5_MASK,

		[0x27]		= E2K_ISET_SINCE_V6_MASK,
	},
	[_DDM0_DDM1] = {
		/* Intersection of DDM0/DDM1 */
		[0x4]		= E2K_ISET_SINCE_V5_MASK,
	},
	[_DIM0_DIM1] = {
		/* Intersection of DIM0/DIM1 */
		[0x0 ... 0x3]	= E2K_ISET_SINCE_V3_MASK,
		[0x7 ... 0xa]	= E2K_ISET_SINCE_V3_MASK,
		[0x10 ... 0x1f] = E2K_ISET_SINCE_V3_MASK,
		[0x20 ... 0x24] = E2K_ISET_SINCE_V3_MASK,
		[0x30 ... 0x3c] = E2K_ISET_SINCE_V3_MASK,
		[0x40 ... 0x4a] = E2K_ISET_SINCE_V3_MASK,
		[0x50 ... 0x5a] = E2K_ISET_SINCE_V3_MASK,
		[0x60 ... 0x69] = E2K_ISET_SINCE_V3_MASK,
		[0x70 ... 0x74] = E2K_ISET_SINCE_V3_MASK,
		[0x3d]		= E2K_ISET_SINCE_V3_MASK,

		[0x2d ... 0x2f] = E2K_ISET_SINCE_V5_MASK,

		[0x27]		= E2K_ISET_SINCE_V6_MASK,

		[0x4 ... 0x6]	= E2K_ISET_V3_MASK,
	},
};

static int event_attr_to_monitor_and_id(struct perf_event_attr *attr,
		u8 *monitor, u8 *event_id)
{
	switch (attr->type) {
	case PERF_TYPE_RAW:
		*monitor = (attr->config & 0xff00) >> 8;
		*event_id = attr->config & 0xff;

		if (*monitor >= MAX_HW_MONITORS ||
		    *event_id >= MAX_EVENTS)
			return -EINVAL;

		if (0 == (hw_raw_event_to_iset[*monitor][*event_id] &
				(1 << machine.native_iset_ver)))
			return -EINVAL;

		*monitor = 1 << *monitor;
		break;
	case PERF_TYPE_HARDWARE: {
		u64 num = attr->config;

		if (unlikely(num >= PERF_COUNT_HW_MAX))
			return -EINVAL;

		*monitor = hardware_events_map[num][0];
		*event_id = hardware_events_map[num][1];
		break;
		}
	case PERF_TYPE_HW_CACHE: {
		u64 type, op, result;

		type = attr->config & 0xff;
		op = (attr->config >> 8) & 0xff;
		result = (attr->config >> 16) & 0xff;

		if (unlikely(type >= PERF_COUNT_HW_CACHE_MAX
				|| op >= PERF_COUNT_HW_CACHE_OP_MAX
				|| result >= PERF_COUNT_HW_CACHE_RESULT_MAX))
			return -EINVAL;

		if (machine.native_iset_ver >= E2K_ISET_V6) {
			*monitor = hw_cache_events_map_v6[type][op][result][0];
			*event_id = hw_cache_events_map_v6[type][op][result][1];
		} else {
			*monitor = hw_cache_events_map_v3[type][op][result][0];
			*event_id = hw_cache_events_map_v3[type][op][result][1];
		}
		break;
		}
	default:
		return -ENOENT;
	}

	if (unlikely(!*monitor)) {
		pr_debug("hardware perf_event: config not supported\n");
		return -EINVAL;
	}

	return 0;
}

int e2k_pmu_event_init(struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;
	int err;
	u8 monitor, event_id;

	err = event_attr_to_monitor_and_id(&event->attr, &monitor, &event_id);
	if (err)
		goto error;

	/*
	 * Good, this event will fit. Save configuration.
	 */
	hwc->config = (monitor << 8) | event_id;
	hwc->idx = (monitor == DIM0 || monitor == DDM0) ? 0 : 1;

	if (!event->attr.exclude_user)
		hwc->config |= ARCH_PERFMON_USR;
	if (!event->attr.exclude_kernel)
		hwc->config |= ARCH_PERFMON_OS;

	if (is_sampling_event(event) &&
			cpu_has(CPU_HWBUG_KERNEL_DATA_MONITOR) &&
			(monitor == DDM0 || monitor == DDM1))
		hwc->config &= ~ARCH_PERFMON_OS;

	pr_debug("perf event %lld initialized with config %hhx:%hhx\n",
			event->id, monitor, event_id);

	return 0;

error:
	pr_debug("perf event init failed with %d (type %d, config %llx)\n",
			err, event->attr.type, event->attr.config);

	return err;
}


/*
 * hw counters enabling/disabling.
 *
 * Masking NMIs delays hardware counters delivering.
 */

static DEFINE_PER_CPU(unsigned long, saved_flags);

static void e2k_pmu_disable(struct pmu *pmu)
{
	unsigned long flags;
	int count;

	/*
	 * Note: this does not stop monitors counting, so it is
	 * possible to get interrupt from a monitor if it is not
	 * disabled inside this pmu_disable/pmu_enable section.
	 * For monitors that indeed are disabled the pending
	 * interrupt is cleared when writing to %dimcr/%ddmcr.
	 */
	raw_all_irq_save(flags);

	count = __this_cpu_add_return(hw_perf_disable_count, 1) - 1;
	if (!count)
		__this_cpu_write(saved_flags, flags);
}

static void e2k_pmu_enable(struct pmu *pmu)
{
	int count;

	count = __this_cpu_add_return(hw_perf_disable_count, -1);

	if (!count) {
		unsigned long flags = __this_cpu_read(saved_flags);

		/* Enable NMIs to get all interrupts that might
		 * have arrived while we were disabling perf */
		raw_all_irq_restore(flags);

		BUG_ON(raw_nmi_irqs_disabled_flags(flags));
	}
}

PMU_FORMAT_ATTR(event, "config:0-63");

static struct attribute *e2k_cpu_format_attrs[] = {
	&format_attr_event.attr,
	NULL
};

static const struct attribute_group e2k_cpu_format_attr_group = {
	.name = "format",
	.attrs = e2k_cpu_format_attrs
};

/* Needed for event aliases from tools/perf/pmu-events/ to work */
static const struct attribute_group *e2k_pmu_attr_groups[] = {
	&e2k_cpu_format_attr_group,
	NULL
};

/* Performance monitoring unit for e2k */
static struct pmu e2k_pmu = {
	.pmu_enable	= e2k_pmu_enable,
	.pmu_disable	= e2k_pmu_disable,

	.event_init	= e2k_pmu_event_init,
	.add		= e2k_pmu_add,
	.del		= e2k_pmu_del,

	.start		= e2k_pmu_start,
	.stop		= e2k_pmu_stop,
	.read		= e2k_pmu_read,

	.attr_groups	= e2k_pmu_attr_groups,
};


static int __init init_hw_perf_events(void)
{
	return perf_pmu_register(&e2k_pmu, "cpu", PERF_TYPE_RAW);
}
early_initcall(init_hw_perf_events);

