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
	if (frame->cr1.pm) {
		if (type != PERF_CONTEXT_KERNEL)
			return 0;
	} else {
		if (type != PERF_CONTEXT_USER)
			return 1;
	}

	ip = get_cr0_ip(frame->cr0);

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
	args.top = PCSP_PTR(regs->stacks.pcsp);
	args.type = PERF_CONTEXT_USER;
	parse_chain_stack(true, NULL, save_stack_address, &args);
}

void perf_callchain_kernel(struct perf_callchain_entry_ctx *entry,
			   struct pt_regs *regs)
{
	struct save_stack_address_args args;

	args.entry = entry;
	args.top = PCSP_PTR(regs->stacks.pcsp);
	args.type = PERF_CONTEXT_KERNEL;
	parse_chain_stack(false, NULL, save_stack_address, &args);
}

/*
 * 0: dimar0
 * 1: dimar1
 * 2: ddmar0
 * 3: ddmar1
 * 4: ddmar2
 * 5: ddmar3
 * 6: dimar2
 * 7: dimar3
 */
DEFINE_PER_CPU(struct perf_event * [8], cpu_events);

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

DEFINE_PER_CPU(u16, perf_monitors_used);

void dimcr_continue(e2k_dimcr_t dimcr_old)
{
	struct perf_event *event0, *event1;
	union core_event_config config0, config1;
	e2k_dimcr_t dimcr;

	event0 = __this_cpu_read(cpu_events[0]);
	event1 = __this_cpu_read(cpu_events[1]);
	if (event0)
		config0 = (union core_event_config) { .word = event0->hw.config };
	if (event1)
		config1 = (union core_event_config) { .word = event1->hw.config };

	/*
	 * Restart counting
	 */
	BUG_ON(event0 && event0->hw.idx != 0 || event1 && event1->hw.idx != 1);
	dimcr = read_DIMCR_reg();
	dimcr.dimar[0].user = (!event0)
			? dimcr_old.dimar[0].user
			: (!(event0->hw.state & PERF_HES_STOPPED) && config0.user);
	dimcr.dimar[0].system = (!event0)
			? dimcr_old.dimar[0].system
			: (!(event0->hw.state & PERF_HES_STOPPED) && config0.system);
	dimcr.dimar[1].user = (!event1)
			? dimcr_old.dimar[1].user
			: (!(event1->hw.state & PERF_HES_STOPPED) && config1.user);
	dimcr.dimar[1].system = (!event1)
			? dimcr_old.dimar[1].system
			: (!(event1->hw.state & PERF_HES_STOPPED) && config1.system);
	write_DIMCR_reg(dimcr);
}

void dimcr1_continue(e2k_dimcr_t dimcr1_old)
{
	struct perf_event *event2, *event3;
	union core_event_config config2, config3;
	e2k_dimcr_t dimcr1;

	if (!cpu_has(CPU_FEAT_ISET_V7) || cpu_has(CPU_HWBUG_DIMCR1))
		return;

	event2 = __this_cpu_read(cpu_events[6]);
	event3 = __this_cpu_read(cpu_events[7]);
	if (event2)
		config2 = (union core_event_config) { .word = event2->hw.config };
	if (event3)
		config3 = (union core_event_config) { .word = event3->hw.config };

	/*
	 * Restart counting
	 */
	BUG_ON(event2 && event2->hw.idx != 2 || event3 && event3->hw.idx != 3);
	dimcr1 = read_DIMCR1_reg();
	dimcr1.dimar[0].user = (!event2)
			? dimcr1_old.dimar[0].user
			: (!(event2->hw.state & PERF_HES_STOPPED) && config2.user);
	dimcr1.dimar[0].system = (!event2)
			? dimcr1_old.dimar[0].system
			: (!(event2->hw.state & PERF_HES_STOPPED) && config2.system);
	dimcr1.dimar[1].user = (!event3)
			? dimcr1_old.dimar[1].user
			: (!(event3->hw.state & PERF_HES_STOPPED) && config3.user);
	dimcr1.dimar[1].system = (!event3)
			? dimcr1_old.dimar[1].system
			: (!(event3->hw.state & PERF_HES_STOPPED) && config3.system);
	write_DIMCR1_reg(dimcr1);
}

void ddmcr_continue(e2k_ddmcr_t ddmcr_old)
{
	struct perf_event *event0, *event1;
	union core_event_config config0, config1;
	e2k_ddmcr_t ddmcr;

	event0 = __this_cpu_read(cpu_events[2]);
	event1 = __this_cpu_read(cpu_events[3]);
	if (event0)
		config0 = (union core_event_config) { .word = event0->hw.config };
	if (event1)
		config1 = (union core_event_config) { .word = event1->hw.config };

	/*
	 * Restart counting
	 */
	BUG_ON(event0 && event0->hw.idx != 0 || event1 && event1->hw.idx != 1);
	ddmcr = READ_DDMCR_REG();
	ddmcr.ddmar[0].user = (!event0)
			? ddmcr_old.ddmar[0].user
			: (!(event0->hw.state & PERF_HES_STOPPED) && config0.user);
	ddmcr.ddmar[0].system = (!event0)
			? ddmcr_old.ddmar[0].system
			: (!(event0->hw.state & PERF_HES_STOPPED) && config0.system);
	ddmcr.ddmar[1].user = (!event1)
			? ddmcr_old.ddmar[1].user
			: (!(event1->hw.state & PERF_HES_STOPPED) && config1.user);
	ddmcr.ddmar[1].system = (!event1)
			? ddmcr_old.ddmar[1].system
			: (!(event1->hw.state & PERF_HES_STOPPED) && config1.system);
	WRITE_DDMCR_REG(ddmcr);
}

void ddmcr1_continue(e2k_ddmcr_t ddmcr1_old)
{
	struct perf_event *event2, *event3;
	union core_event_config config2, config3;
	e2k_ddmcr_t ddmcr1;

	if (!cpu_has(CPU_FEAT_ISET_V7))
		return;

	event2 = __this_cpu_read(cpu_events[4]);
	event3 = __this_cpu_read(cpu_events[5]);
	if (event2)
		config2 = (union core_event_config) { .word = event2->hw.config };
	if (event3)
		config3 = (union core_event_config) { .word = event3->hw.config };

	/*
	 * Restart counting
	 */
	BUG_ON(event2 && event2->hw.idx != 2 || event3 && event3->hw.idx != 3);
	ddmcr1 = READ_DDMCR1_REG();
	ddmcr1.ddmar[0].user = (!event2)
			? ddmcr1_old.ddmar[0].user
			: (!(event2->hw.state & PERF_HES_STOPPED) && config2.user);
	ddmcr1.ddmar[0].system = (!event2)
			? ddmcr1_old.ddmar[0].system
			: (!(event2->hw.state & PERF_HES_STOPPED) && config2.system);
	ddmcr1.ddmar[1].user = (!event3)
			? ddmcr1_old.ddmar[1].user
			: (!(event3->hw.state & PERF_HES_STOPPED) && config3.user);
	ddmcr1.ddmar[1].system = (!event3)
			? ddmcr1_old.ddmar[1].system
			: (!(event3->hw.state & PERF_HES_STOPPED) && config3.system);
	WRITE_DDMCR1_REG(ddmcr1);
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
	struct perf_event *event0, *event1, *event2, *event3;
	u16 monitors_used;

	monitors_used = __this_cpu_read(perf_monitors_used);
	event0 = __this_cpu_read(cpu_events[2]);
	event1 = __this_cpu_read(cpu_events[3]);
	event2 = __this_cpu_read(cpu_events[4]);
	event3 = __this_cpu_read(cpu_events[5]);

	ddbsr = READ_DDBSR_REG();

	pr_debug("data overflow, ddbsr %llx, monitors_used 0x%hhx, events 0x%lx/0x%lx\n",
		 AW(ddbsr), monitors_used, event0, event1);

	if (ddbsr.m0 && event0 && (monitors_used & _BITUL(DDM0))) {
		s64 period = handle_event_overflow("DDM0", event0, regs);
		WRITE_DDMAR0_REG(-period);
		ddbsr.m0 = 0;
	}

	if (ddbsr.m1 && event1 && (monitors_used & _BITUL(DDM1))) {
		s64 period = handle_event_overflow("DDM1", event1, regs);
		WRITE_DDMAR1_REG(-period);
		ddbsr.m1 = 0;
	}

	if (ddbsr.m2 && event2 && (monitors_used & _BITUL(DDM2))) {
		s64 period = handle_event_overflow("DDM2", event2, regs);
		WRITE_DDMAR2_REG(-period);
		ddbsr.m2 = 0;
	}

	if (ddbsr.m3 && event3 && (monitors_used & _BITUL(DDM3))) {
		s64 period = handle_event_overflow("DDM3", event3, regs);
		WRITE_DDMAR3_REG(-period);
		ddbsr.m3 = 0;
	}

	/*
	 * Clear status fields
	 */
	WRITE_DDBSR_REG(ddbsr);
}

void perf_instr_overflow_handle(struct pt_regs *regs)
{
	e2k_dibsr_t dibsr;
	struct perf_event *event0, *event1, *event2, *event3;
	u16 monitors_used;

	monitors_used = __this_cpu_read(perf_monitors_used);
	event0 = __this_cpu_read(cpu_events[0]);
	event1 = __this_cpu_read(cpu_events[1]);
	event2 = __this_cpu_read(cpu_events[6]);
	event3 = __this_cpu_read(cpu_events[7]);

	dibsr = read_DIBSR_reg();

	pr_debug("instr overflow, dibsr %x, monitors_used 0x%hhx, events 0x%lx/0x%lx\n",
		 AW(dibsr), monitors_used, event0, event1);

	if (dibsr.m0 && event0 && (monitors_used & _BITUL(DIM0))) {
		/* This could be an event from DIMTP overflow */
		if (event0->pmu->type != e2k_pmu.type) {
			dimtp_overflow(event0);
		} else {
			regs->trap->dim_ip = read_DIMAR0_reg_value();
			regs->trap->dim_ip_valid = 1;
			s64 period = handle_event_overflow("DIM0", event0, regs);
			write_DIMAR0_reg_value(-period);
		}
		dibsr.m0 = 0;
	}

	if (dibsr.m1 && event1 && (monitors_used & _BITUL(DIM1))) {
		regs->trap->dim_ip = read_DIMAR1_reg_value();
		regs->trap->dim_ip_valid = 1;
		s64 period = handle_event_overflow("DIM1", event1, regs);
		write_DIMAR1_reg_value(-period);
		dibsr.m1 = 0;
	}

	if (dibsr.m2 && event2 && (monitors_used & _BITUL(DIM2))) {
		regs->trap->dim_ip = read_DIMAR2_reg_value();
		regs->trap->dim_ip_valid = 1;
		s64 period = handle_event_overflow("DIM2", event2, regs);
		write_DIMAR2_reg_value(-period);
		dibsr.m2 = 0;
	}

	if (dibsr.m3 && event3 && (monitors_used & _BITUL(DIM3))) {
		regs->trap->dim_ip = read_DIMAR3_reg_value();
		regs->trap->dim_ip_valid = 1;
		s64 period = handle_event_overflow("DIM3", event3, regs);
		write_DIMAR3_reg_value(-period);
		dibsr.m3 = 0;
	}

	/*
	 * Clear status fields
	 */
	write_DIBSR_reg(dibsr);
}

static void monitor_resume(struct hw_perf_event *hwc, int reload, s64 period)
{
	union core_event_config config = (union core_event_config) { .word = hwc->config };
	unsigned long flags;
	e2k_dimcr_t dimcr, dimcr1;
	e2k_ddmcr_t ddmcr, ddmcr1;
	e2k_dibcr_t dibcr;
	int num;

	raw_all_irq_save(flags);

	num = hwc->idx;

	/* Clear PERF_HES_STOPPED */
	hwc->state = 0;

	dibcr = read_DIBCR_reg();
	WARN_ON(dibcr.stop);

	if (config.instruction && num <= 1) {
		/* DIM0 / DIM1 */
		dimcr = read_DIMCR_reg();
		dimcr.dimar[num].user = config.user;
		dimcr.dimar[num].system = config.system;
		dimcr.dimar[num].trap = 1;
		dimcr.dimar[num].event = config.event_id;
		if (reload) {
			period = -period;

			if (num == 1)
				write_DIMAR1_reg_value(period);
			else
				write_DIMAR0_reg_value(period);
		}
		write_DIMCR_reg(dimcr);
	} else if (config.instruction && num >= 2) {
		/* DIM2 / DIM3 */
		dimcr1 = read_DIMCR1_reg();
		dimcr1.dimar[num - 2].user = config.user;
		dimcr1.dimar[num - 2].system = config.system;
		dimcr1.dimar[num - 2].trap = 1;
		dimcr1.dimar[num - 2].event = config.event_id;
		if (reload) {
			period = -period;

			if (num == 3)
				write_DIMAR3_reg_value(period);
			else
				write_DIMAR2_reg_value(period);
		}
		write_DIMCR1_reg(dimcr1);
	} else if (!config.instruction && num <= 1) {
		/* DDM0 / DDM1 */
		ddmcr = READ_DDMCR_REG();
		ddmcr.ddmar[num].user = config.user;
		ddmcr.ddmar[num].system = config.system;
		ddmcr.ddmar[num].trap = 1;
		ddmcr.ddmar[num].event = config.event_id;
		if (reload) {
			period = -period;

			if (num == 1)
				WRITE_DDMAR1_REG_VALUE(period);
			else
				WRITE_DDMAR0_REG_VALUE(period);
		}
		WRITE_DDMCR_REG(ddmcr);
	} else if (!config.instruction && num >= 2) {
		/* DDM2 / DDM3 */
		ddmcr1 = READ_DDMCR1_REG();
		ddmcr1.ddmar[num - 2].user = config.user;
		ddmcr1.ddmar[num - 2].system = config.system;
		ddmcr1.ddmar[num - 2].trap = 1;
		ddmcr1.ddmar[num - 2].event = config.event_id;
		if (reload) {
			period = -period;

			if (num == 3)
				WRITE_DDMAR3_REG_VALUE(period);
			else
				WRITE_DDMAR2_REG_VALUE(period);
		}
		WRITE_DDMCR1_REG(ddmcr1);
	} else {
		WARN_ONCE(1, "event %hhx:%hhx:%02hhx: resuming",
				config.mask, config.monitor, config.event_id);
	}

	pr_debug("event %hhx:%hhx:%02hhx: resuming\n",
			config.mask, config.monitor, config.event_id);

	raw_all_irq_restore(flags);
}

static s64 monitor_pause(struct perf_event *event,
			 struct hw_perf_event *hwc, int update)
{
	union core_event_config config = (union core_event_config) { .word = hwc->config };
	unsigned long flags;
	e2k_dimcr_t dimcr, dimcr1;
	e2k_ddmcr_t ddmcr, ddmcr1;
	e2k_dibcr_t dibcr;
	s64 left = 0;
	int num, overflow;

	raw_all_irq_save(flags);

	num = hwc->idx;

	hwc->state |= PERF_HES_STOPPED;

	dibcr = read_DIBCR_reg();
	WARN_ON(dibcr.stop);

	if (config.instruction && num <= 1) {
		/* DIM0 / DIM1 */
		dimcr = read_DIMCR_reg();
		dimcr.dimar[num].user = 0;
		dimcr.dimar[num].system = 0;
		write_DIMCR_reg(dimcr);
		if (update) {
			e2k_dibsr_t dibsr = read_DIBSR_reg();

			overflow = (num == 1 && dibsr.m1) || (num == 0 && dibsr.m0);
			if (overflow) {
				left = 1;
				pr_debug("event DIM%d: left 0 (1)\n", num);
				/* See comment in monitor_disable() */
				if (num == 1)
					dibsr.m1 = 0;
				else
					dibsr.m0 = 0;
			} else {
				left = (num == 1) ? read_DIMAR1_reg_value() :
						    read_DIMAR0_reg_value();
				left = -left;

				pr_debug("event DIM%d: left %lld, dimcr 0x%llx/0x%llx, dibsr 0x%x/0x%x\n",
					 num, left, AW(dimcr), AW(read_DIMCR_reg()),
					 AW(dibsr), AW(read_DIBSR_reg()));
			}

			/* We clear m0/m1 even if it is not set. The problem
			 * is that %dibsr is still updated asynchronously
			 * for several cycles after %dimcr write, so it
			 * can be set _after_ we had read %dibsr. */
			write_DIBSR_reg(dibsr);
		}
	} else if (config.instruction && num >= 2) {
		/* DIM2 / DIM3 */
		dimcr1 = read_DIMCR1_reg();
		dimcr1.dimar[num - 2].user = 0;
		dimcr1.dimar[num - 2].system = 0;
		write_DIMCR1_reg(dimcr1);
		if (update) {
			e2k_dibsr_t dibsr = read_DIBSR_reg();

			overflow = (num == 3 && dibsr.m3) || (num == 2 && dibsr.m2);
			if (overflow) {
				left = 1;
				pr_debug("event DIM%d: left 0 (1)\n", num);
				/* See comment in monitor_disable() */
				if (num == 3)
					dibsr.m3 = 0;
				else
					dibsr.m2 = 0;
			} else {
				left = (num == 3) ? read_DIMAR3_reg_value() :
						    read_DIMAR2_reg_value();
				left = -left;

				pr_debug("event DIM%d: left %lld, dimcr1 0x%llx/0x%llx, dibsr 0x%x/0x%x\n",
					 num, left, AW(dimcr1), AW(read_DIMCR1_reg()),
					 AW(dibsr), AW(read_DIBSR_reg()));
			}

			/* We clear m2/m3 even if it is not set. The problem
			 * is that %dibsr is still updated asynchronously
			 * for several cycles after %dimcr write, so it
			 * can be set _after_ we had read %dibsr. */
			write_DIBSR_reg(dibsr);
		}
	} else if (!config.instruction && num <= 1) {
		/* DDM0 / DDM1 */
		ddmcr = READ_DDMCR_REG();
		ddmcr.ddmar[num].user = 0;
		ddmcr.ddmar[num].system = 0;
		WRITE_DDMCR_REG(ddmcr);
		if (update) {
			e2k_ddbsr_t ddbsr = READ_DDBSR_REG();

			overflow = (num == 1 && ddbsr.m1) || (num == 0 && ddbsr.m0);
			if (overflow) {
				left = 1;
				pr_debug("event DDM%d: left 0 (1)\n", num);
				if (num == 1)
					ddbsr.m1 = 0;
				else
					ddbsr.m0 = 0;
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
	} else if (!config.instruction && num >= 2) {
		/* DDM2 / DDM3 */
		ddmcr1 = READ_DDMCR1_REG();
		ddmcr1.ddmar[num - 2].user = 0;
		ddmcr1.ddmar[num - 2].system = 0;
		WRITE_DDMCR1_REG(ddmcr1);
		if (update) {
			e2k_ddbsr_t ddbsr = READ_DDBSR_REG();

			overflow = (num == 3 && ddbsr.m3) || (num == 2 && ddbsr.m2);
			if (overflow) {
				left = 1;
				pr_debug("event DDM%d: left 0 (1)\n", num);
				if (num == 3)
					ddbsr.m3 = 0;
				else
					ddbsr.m2 = 0;
			} else {
				left = (num == 3) ? READ_DDMAR3_REG_VALUE() :
						    READ_DDMAR2_REG_VALUE();
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

			/* We clear m2/m3 even if it is not set. The problem
			 * is that %ddbsr is still updated asynchronously
			 * for several cycles after %ddmcr write, so it
			 * can be set _after_ we had read %ddbsr. */
			WRITE_DDBSR_REG(ddbsr);
		}
	} else {
		WARN_ONCE(1, "event %hhx:%hhx:%02hhx: pausing",
				config.mask, config.monitor, config.event_id);
	}

	pr_debug("event %hhx:%hhx:%02hhx: pausing\n",
			config.mask, config.monitor, config.event_id);

	raw_all_irq_restore(flags);

	return left;
}

static int monitor_enable(s64 period, struct perf_event *event, int run)
{
	struct hw_perf_event *hwc = &event->hw;
	union core_event_config config = (union core_event_config) { .word = hwc->config };
	unsigned long flags;
	e2k_dimcr_t dimcr, dimcr1;
	e2k_ddmcr_t ddmcr, ddmcr1;
	e2k_dibcr_t dibcr;
	e2k_dibsr_t dibsr;
	e2k_ddbsr_t ddbsr;
	int num, ret = 0;
	u16 monitors_used;
	u8 monitor;

	raw_all_irq_save(flags);

	period = -period;

	dibcr = read_DIBCR_reg();
	WARN_ON(dibcr.stop);

	monitors_used = __this_cpu_read(perf_monitors_used);

	/* Find available slot if event is supported in several slots.
	 *
	 * Check `cfg.mask` first since `config.monitor` can be 0 (DDM0) */
	if (config.mask) {
		if (config.dim3 && !(monitors_used & _BITUL(DIM3))) {
			monitor = DIM3;
			hwc->idx = 3;
		} else if (config.dim2 && !(monitors_used & _BITUL(DIM2))) {
			monitor = DIM2;
			hwc->idx = 2;
		} else if (config.dim1 && !(monitors_used & _BITUL(DIM1))) {
			monitor = DIM1;
			hwc->idx = 1;
		} else if (config.dim0 && !(monitors_used & _BITUL(DIM0))) {
			monitor = DIM0;
			hwc->idx = 0;
		} else if (config.ddm3 && !(monitors_used & _BITUL(DDM3))) {
			monitor = DDM3;
			hwc->idx = 3;
		} else if (config.ddm2 && !(monitors_used & _BITUL(DDM2))) {
			monitor = DDM2;
			hwc->idx = 2;
		} else if (config.ddm1 && !(monitors_used & _BITUL(DDM1))) {
			monitor = DDM1;
			hwc->idx = 1;
		} else if (config.ddm0 && !(monitors_used & _BITUL(DDM0))) {
			monitor = DDM0;
			hwc->idx = 0;
		} else {
			ret = -ENOSPC;
			goto out_irq;
		}
	} else {
		switch (config.monitor) {
		case DIM0_DIM1:
			if (!(monitors_used & _BITUL(DIM1))) {
				monitor = DIM1;
				hwc->idx = 1;
			} else if (!(monitors_used & _BITUL(DIM0))) {
				monitor = DIM0;
				hwc->idx = 0;
			} else {
				ret = -ENOSPC;
				goto out_irq;
			}
			break;
		case DDM0_DDM1:
			if (!(monitors_used & _BITUL(DDM1))) {
				monitor = DDM1;
				hwc->idx = 1;
			} else if (!(monitors_used & _BITUL(DDM0))) {
				monitor = DDM0;
				hwc->idx = 0;
			} else {
				ret = -ENOSPC;
				goto out_irq;
			}
			break;
		default:
			monitor = config.monitor;
			break;
		}
	}

	switch (monitor) {
	case DIM0:
	case DIM1:
		if (monitor == DIM1 && (monitors_used & _BITUL(DIM1)) ||
		    monitor == DIM0 && (monitors_used & _BITUL(DIM0))) {
			ret = -ENOSPC;
			break;
		}

		dimcr = read_DIMCR_reg();
		num = (monitor == DIM1);
		dimcr.dimar[num].user = run && config.user && !(hwc->state & PERF_HES_STOPPED);
		dimcr.dimar[num].system = 0;
		dimcr.dimar[num].trap = 1;
		dimcr.dimar[num].event = config.event_id;
		write_DIMCR_reg(dimcr);

		dibsr = read_DIBSR_reg();

		if (monitor == DIM1) {
			write_DIMAR1_reg_value(period);
			dibsr.m1 = 0;

			__this_cpu_write(cpu_events[1], event);
			__this_cpu_or(perf_monitors_used, _BITUL(DIM1));
		} else {
			write_DIMAR0_reg_value(period);
			dibsr.m0 = 0;

			__this_cpu_write(cpu_events[0], event);
			__this_cpu_or(perf_monitors_used, _BITUL(DIM0));
		}

		write_DIBSR_reg(dibsr);

		/*
		 * Start the monitor now that the preparations are done.
		 */
		if (run && config.system && !(hwc->state & PERF_HES_STOPPED)) {
			dimcr.dimar[num].system = 1;
			write_DIMCR_reg(dimcr);
		}
		break;
	case DIM2:
	case DIM3:
		if (monitor == DIM3 && (monitors_used & _BITUL(DIM3)) ||
		    monitor == DIM2 && (monitors_used & _BITUL(DIM2))) {
			ret = -ENOSPC;
			break;
		}

		dimcr1 = read_DIMCR1_reg();
		num = (monitor == DIM3);
		dimcr1.dimar[num].user = run && config.user && !(hwc->state & PERF_HES_STOPPED);
		dimcr1.dimar[num].system = 0;
		dimcr1.dimar[num].trap = 1;
		dimcr1.dimar[num].event = config.event_id;
		write_DIMCR1_reg(dimcr1);

		dibsr = read_DIBSR_reg();

		if (num == 1) {
			write_DIMAR3_reg_value(period);
			dibsr.m3 = 0;

			__this_cpu_write(cpu_events[7], event);
			__this_cpu_or(perf_monitors_used, _BITUL(DIM3));
		} else {
			write_DIMAR2_reg_value(period);
			dibsr.m2 = 0;

			__this_cpu_write(cpu_events[6], event);
			__this_cpu_or(perf_monitors_used, _BITUL(DIM2));
		}

		write_DIBSR_reg(dibsr);

		/*
		 * Start the monitor now that the preparations are done.
		 */
		if (run && config.system && !(hwc->state & PERF_HES_STOPPED)) {
			dimcr1.dimar[num].system = 1;
			write_DIMCR1_reg(dimcr1);
		}
		break;
	case DDM0:
	case DDM1:
		if (monitor == DDM1 && (monitors_used & _BITUL(DDM1)) ||
		    monitor == DDM0 && (monitors_used & _BITUL(DDM0))) {
			ret = -ENOSPC;
			break;
		}

		ddmcr = READ_DDMCR_REG();
		num = (monitor == DDM1);
		ddmcr.ddmar[num].user = run && config.user && !(hwc->state & PERF_HES_STOPPED);
		ddmcr.ddmar[num].system = 0;
		ddmcr.ddmar[num].trap = 1;
		ddmcr.ddmar[num].event = config.event_id;
		WRITE_DDMCR_REG(ddmcr);

		ddbsr = READ_DDBSR_REG();

		if (num == 1) {
			WRITE_DDMAR1_REG_VALUE(period);
			ddbsr.m1 = 0;

			__this_cpu_write(cpu_events[3], event);
			__this_cpu_or(perf_monitors_used, _BITUL(DDM1));
		} else {
			WRITE_DDMAR0_REG_VALUE(period);
			ddbsr.m0 = 0;

			__this_cpu_write(cpu_events[2], event);
			__this_cpu_or(perf_monitors_used, _BITUL(DDM0));
		}

		WRITE_DDBSR_REG(ddbsr);

		/*
		 * Start the monitor now that the preparations are done.
		 */
		if (run && config.system && !(hwc->state & PERF_HES_STOPPED)) {
			ddmcr.ddmar[num].system = 1;
			WRITE_DDMCR_REG(ddmcr);
		}
		break;
	case DDM2:
	case DDM3:
		if (monitor == DDM3 && (monitors_used & _BITUL(DDM3)) ||
		    monitor == DDM2 && (monitors_used & _BITUL(DDM2))) {
			ret = -ENOSPC;
			break;
		}

		ddmcr1 = READ_DDMCR1_REG();
		num = (monitor == DDM3);
		ddmcr1.ddmar[num].user = run && config.user && !(hwc->state & PERF_HES_STOPPED);
		ddmcr1.ddmar[num].system = 0;
		ddmcr1.ddmar[num].trap = 1;
		ddmcr1.ddmar[num].event = config.event_id;
		WRITE_DDMCR1_REG(ddmcr1);

		ddbsr = READ_DDBSR_REG();

		if (num == 1) {
			WRITE_DDMAR3_REG_VALUE(period);
			ddbsr.m3 = 0;

			__this_cpu_write(cpu_events[5], event);
			__this_cpu_or(perf_monitors_used, _BITUL(DDM3));
		} else {
			WRITE_DDMAR2_REG_VALUE(period);
			ddbsr.m2 = 0;

			__this_cpu_write(cpu_events[4], event);
			__this_cpu_or(perf_monitors_used, _BITUL(DDM2));
		}

		WRITE_DDBSR_REG(ddbsr);

		/*
		 * Start the monitor now that the preparations are done.
		 */
		if (run && config.system && !(hwc->state & PERF_HES_STOPPED)) {
			ddmcr1.ddmar[num].system = 1;
			WRITE_DDMCR1_REG(ddmcr1);
		}
		break;
	default:
		WARN_ONCE(1, "event %hhx:%hhx:%02hhx: enabling",
				config.mask, config.monitor, config.event_id);
		break;
	}

out_irq:
	raw_all_irq_restore(flags);

	return ret;
}

static DEFINE_PER_CPU(int, hw_perf_disable_count);

static s64 monitor_disable(const struct hw_perf_event *hwc)
{
	union core_event_config config = (union core_event_config) { .word = hwc->config };
	unsigned long flags;
	e2k_dimcr_t dimcr, dimcr1;
	e2k_ddmcr_t ddmcr, ddmcr1;
	e2k_dibsr_t dibsr;
	e2k_ddbsr_t ddbsr;
	s64 left;
	int num;

	num = hwc->idx;

	BUG_ON(!!__this_cpu_read(hw_perf_disable_count) ^ !!raw_all_irqs_disabled());
	BUG_ON(!raw_irqs_disabled());

	if (config.instruction && num <= 1) {
		/* DIM0 / DIM1 */
		dimcr = read_DIMCR_reg();
		dimcr.dimar[num].user = 0;
		dimcr.dimar[num].system = 0;
		/* Note that writing of %dimcr has an important side effect:
		 * it cancels any other pending exc_instr_debug that arrived
		 * while we were still handling this one. */
		write_DIMCR_reg(dimcr);

		raw_all_irq_save(flags);

		left = (num == 1) ? read_DIMAR1_reg_value() : read_DIMAR0_reg_value();
		left = -left;

		dibsr = read_DIBSR_reg();

		if (num == 1) {
			__this_cpu_write(cpu_events[1], NULL);

			BUG_ON(!(__this_cpu_read(perf_monitors_used) & _BITUL(DIM1)));
			__this_cpu_and(perf_monitors_used, ~_BITUL(DIM1));

			if (dibsr.m1) {
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
				dibsr.m1 = 0;
			} else {
				pr_debug("event DIM1: left %lld\n", left);
			}
		} else {
			__this_cpu_write(cpu_events[0], NULL);

			BUG_ON(!(__this_cpu_read(perf_monitors_used) & _BITUL(DIM0)));
			__this_cpu_and(perf_monitors_used, ~_BITUL(DIM0));

			if (dibsr.m0) {
				left = 1;
				pr_debug("event DIM0: left 0 (1)\n");
				dibsr.m0 = 0;
			} else {
				pr_debug("event DIM0: left %lld\n", left);
			}
		}

		/* We clear m0/m1 even if it is not set. The problem
		 * is that %dibsr is still updated asynchronously
		 * for several cycles after %dimcr write, so it
		 * can be set _after_ we had read %dibsr. */
		write_DIBSR_reg(dibsr);
	} else if (config.instruction && num >= 2) {
		/* DIM2 / DIM3 */
		dimcr1 = read_DIMCR1_reg();
		dimcr1.dimar[num - 2].user = 0;
		dimcr1.dimar[num - 2].system = 0;
		/* Note that writing of %dimcr has an important side effect:
		 * it cancels any other pending exc_instr_debug that arrived
		 * while we were still handling this one. */
		write_DIMCR1_reg(dimcr1);

		raw_all_irq_save(flags);

		left = (num == 3) ? read_DIMAR3_reg_value() : read_DIMAR2_reg_value();
		left = -left;

		dibsr = read_DIBSR_reg();

		if (num == 3) {
			__this_cpu_write(cpu_events[7], NULL);

			BUG_ON(!(__this_cpu_read(perf_monitors_used) & _BITUL(DIM3)));
			__this_cpu_and(perf_monitors_used, ~_BITUL(DIM3));

			if (dibsr.m3) {
				left = 1;
				pr_debug("event DIM3: left 0 (1)\n");
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
				dibsr.m3 = 0;
			} else {
				pr_debug("event DIM3: left %lld\n", left);
			}
		} else {
			__this_cpu_write(cpu_events[6], NULL);

			BUG_ON(!(__this_cpu_read(perf_monitors_used) & _BITUL(DIM2)));
			__this_cpu_and(perf_monitors_used, ~_BITUL(DIM2));

			if (dibsr.m2) {
				left = 1;
				pr_debug("event DIM2: left 0 (1)\n");
				dibsr.m2 = 0;
			} else {
				pr_debug("event DIM2: left %lld\n", left);
			}
		}

		/* We clear m2/m3 even if it is not set. The problem
		 * is that %dibsr is still updated asynchronously
		 * for several cycles after %dimcr write, so it
		 * can be set _after_ we had read %dibsr. */
		write_DIBSR_reg(dibsr);
	} else if (!config.instruction && num <= 1) {
		/* DDM0 / DDM1 */
		ddmcr = READ_DDMCR_REG();
		ddmcr.ddmar[num].user = 0;
		ddmcr.ddmar[num].system = 0;
		/* Note that writing of %ddmcr has an important side effect:
		 * it cancels any other pending exc_data_debug that arrived
		 * while we were still handling this one. */
		WRITE_DDMCR_REG(ddmcr);

		raw_all_irq_save(flags);

		ddbsr = READ_DDBSR_REG();

		if (num == 1) {
			__this_cpu_write(cpu_events[3], NULL);

			BUG_ON(!(__this_cpu_read(perf_monitors_used) & _BITUL(DDM1)));
			__this_cpu_and(perf_monitors_used, ~_BITUL(DDM1));

			if (ddbsr.m1) {
				left = 1;
				pr_debug("event DDM1: left 0 (1)\n");
				ddbsr.m1 = 0;
			} else {
				left = READ_DDMAR1_REG_VALUE();
				left = -left;
				pr_debug("event DDM1: left %lld\n", left);
			}
		} else {
			__this_cpu_write(cpu_events[2], NULL);

			BUG_ON(!(__this_cpu_read(perf_monitors_used) & _BITUL(DDM0)));
			__this_cpu_and(perf_monitors_used, ~_BITUL(DDM0));

			if (ddbsr.m0) {
				left = 1;
				pr_debug("event DDM0: left 0 (1)\n");
				ddbsr.m0 = 0;
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
	} else if (!config.instruction && num >= 2) {
		/* DDM2 / DDM3 */
		ddmcr1 = READ_DDMCR1_REG();
		ddmcr1.ddmar[num - 2].user = 0;
		ddmcr1.ddmar[num - 2].system = 0;
		/* Note that writing of %ddmcr1 has an important side effect:
		 * it cancels any other pending exc_data_debug that arrived
		 * while we were still handling this one. */
		WRITE_DDMCR1_REG(ddmcr1);

		raw_all_irq_save(flags);

		ddbsr = READ_DDBSR_REG();

		if (num == 3) {
			__this_cpu_write(cpu_events[5], NULL);

			BUG_ON(!(__this_cpu_read(perf_monitors_used) & _BITUL(DDM3)));
			__this_cpu_and(perf_monitors_used, ~_BITUL(DDM3));

			if (ddbsr.m3) {
				left = 1;
				pr_debug("event DDM3: left 0 (1)\n");
				ddbsr.m3 = 0;
			} else {
				left = READ_DDMAR3_REG_VALUE();
				left = -left;
				pr_debug("event DDM3: left %lld\n", left);
			}
		} else {
			__this_cpu_write(cpu_events[4], NULL);

			BUG_ON(!(__this_cpu_read(perf_monitors_used) & _BITUL(DDM2)));
			__this_cpu_and(perf_monitors_used, ~_BITUL(DDM2));

			if (ddbsr.m2) {
				left = 1;
				pr_debug("event DDM2: left 0 (1)\n");
				ddbsr.m2 = 0;
			} else {
				left = READ_DDMAR2_REG_VALUE();
				left = -left;
				pr_debug("event DDM2: left %lld\n", left);
			}
		}

		/* We clear m2/m3 even if it is not set. The problem
		 * is that %ddbsr is still updated asynchronously
		 * for several cycles after %ddmcr1 write, so it
		 * can be set _after_ we had read %ddbsr. */
		WRITE_DDBSR_REG(ddbsr);
	} else {
		WARN_ONCE(1, "event %hhx:%hhx:%02hhx: disabling",
				config.mask, config.monitor, config.event_id);
		raw_all_irq_save(flags);
		left = 1;
	}

	raw_all_irq_restore(flags);

	return left;
}

static s64 monitor_read(const struct hw_perf_event *hwc)
{
	union core_event_config config = (union core_event_config) { .word = hwc->config };
	s64 left;
	e2k_dibsr_t dibsr;
	e2k_ddbsr_t ddbsr;

	if (config.instruction) {
		switch (hwc->idx) {
		case 0:
			dibsr = read_DIBSR_reg();
			left = (dibsr.m0) ? 0 : -(s64) read_DIMAR0_reg_value();
			pr_debug("reading DIM0: left %lld (dibsr %d)\n", left, dibsr.m0);
			break;
		case 1:
			dibsr = read_DIBSR_reg();
			left = (dibsr.m1) ? 0 : -(s64) read_DIMAR1_reg_value();
			pr_debug("reading DIM1: left %lld (dibsr %d)\n", left, dibsr.m1);
			break;
		case 2:
			dibsr = read_DIBSR_reg();
			left = (dibsr.m2) ? 0 : -(s64) read_DIMAR2_reg_value();
			pr_debug("reading DIM2: left %lld (dibsr %d)\n", left, dibsr.m2);
			break;
		case 3:
			dibsr = read_DIBSR_reg();
			left = (dibsr.m3) ? 0 : -(s64) read_DIMAR3_reg_value();
			pr_debug("reading DIM3: left %lld (dibsr %d)\n", left, dibsr.m3);
			break;
		default:
			WARN_ONCE(1, "event %hhx:%hhx:%02hhx: reading, idx=%d",
				config.mask, config.monitor, config.event_id, hwc->idx);
			left = 1;
			break;
		}
	} else {
		switch (hwc->idx) {
		case 0:
			ddbsr = READ_DDBSR_REG();
			left = (ddbsr.m0) ? 0 : -(s64) READ_DDMAR0_REG_VALUE();
			pr_debug("reading DDM0: left %lld (ddbsr %d)\n", left, ddbsr.m0);
			break;
		case 1:
			ddbsr = READ_DDBSR_REG();
			left = (ddbsr.m1) ? 0 : -(s64) READ_DDMAR1_REG_VALUE();
			pr_debug("reading DDM1: left %lld (ddbsr %d)\n", left, ddbsr.m1);
			break;
		case 2:
			ddbsr = READ_DDBSR_REG();
			left = (ddbsr.m2) ? 0 : -(s64) READ_DDMAR2_REG_VALUE();
			pr_debug("reading DDM2: left %lld (ddbsr %d)\n", left, ddbsr.m2);
			break;
		case 3:
			ddbsr = READ_DDBSR_REG();
			left = (ddbsr.m3) ? 0 : -(s64) READ_DDMAR3_REG_VALUE();
			pr_debug("reading DDM3: left %lld (ddbsr %d)\n", left, ddbsr.m3);
			break;
		default:
			WARN_ONCE(1, "event %hhx:%hhx:%02hhx: reading, idx=%d",
				config.mask, config.monitor, config.event_id, hwc->idx);
			left = 1;
			break;
		}
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
	union core_event_config config = (union core_event_config) { .word = hwc->config };
	s64 period;

	pr_debug("event %lx: enabling %hhx:%hhx:%02hhx\n"
		 "sample_period %lld, left %ld\n",
		 event, config.mask, config.monitor, config.event_id,
		 hwc->sample_period, local64_read(&hwc->period_left));

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
	return monitor_enable(period, event, flags & PERF_EF_START);
}

static void e2k_pmu_update(struct perf_event *event, s64 left)
{
	struct hw_perf_event *hwc = &event->hw;
	union core_event_config config = (union core_event_config) { .word = hwc->config };
	s64 prev;

	prev = local64_xchg(&hwc->prev_count, left);

	local64_add(prev - left, &event->count);

	pr_debug("event %lx: updating %hhx:%hhx:%02hhx\n"
		 "sample_period %lld, count %ld (+%lld)\n"
		 "left previously %lld, left now %lld\n",
		 event, config.mask, config.monitor, config.event_id,
		 hwc->sample_period, local64_read(&event->count),
		 prev - left, prev, left);
}

static void e2k_pmu_del(struct perf_event *event, int flags)
{
	struct hw_perf_event *hwc = &event->hw;
	u64 left;

	left = monitor_disable(hwc);
	local64_set(&hwc->period_left, left);

	union core_event_config config = (union core_event_config) { .word = hwc->config };
	pr_debug("event %lx: disabling %hhx:%hhx:%02hhx\n"
		 "sample_period %lld, left %lld\n",
		 event, config.mask, config.monitor, config.event_id,
		 hwc->sample_period, left);

	e2k_pmu_update(event, left);
}

static void e2k_pmu_read(struct perf_event *event)
{
	s64 left = monitor_read(&event->hw);
	e2k_pmu_update(event, left);
}

static void e2k_pmu_stop(struct perf_event *event, int flags)
{
	struct hw_perf_event *hwc = &event->hw;
	s64 left;

	left = monitor_pause(event, hwc, flags & PERF_EF_UPDATE);

	if (flags & PERF_EF_UPDATE) {
		local64_set(&hwc->period_left, left);

		union core_event_config config = (union core_event_config) { .word = hwc->config };
		pr_debug("event %lx: pausing %hhx:%hhx:%02hhx\n"
			 "sample_period %lld, left %lld\n",
			 event, config.mask, config.monitor, config.event_id,
			 hwc->sample_period, left);

		e2k_pmu_update(event, left);
	}
}


static void e2k_pmu_start(struct perf_event *event, int flags)
{
	struct hw_perf_event *hwc = &event->hw;
	union core_event_config config = (union core_event_config) { .word = hwc->config };
	s64 left = 0;

	pr_debug("event %lx: resuming %hhx:%hhx:%02hhx\n"
		 "sample_period %lld\n",
		 event, config.mask, config.monitor, config.event_id,
		 hwc->sample_period);

	if (flags & PERF_EF_RELOAD) {
		left = local64_read(&hwc->period_left);

		local64_set(&hwc->prev_count, (u64) left);

		pr_debug("event %lx: period_left %lld\n", event, left);
	}

	monitor_resume(hwc, flags & PERF_EF_RELOAD, left);
}


#define config_monitor(_monitor, _event_id) \
	((union core_event_config) { \
		.monitor = (_monitor), \
		.event_id = (_event_id), \
		.mask = 0 \
	})

#define DDM0_CONFIG 0x01
#define DDM1_CONFIG 0x02
#define DDM2_CONFIG 0x04
#define DDM3_CONFIG 0x08
#define DIM0_CONFIG 0x10
#define DIM1_CONFIG 0x20
#define DIM2_CONFIG 0x40
#define DIM3_CONFIG 0x80
#define DIM012_CONFIG	(DIM0_CONFIG | DIM1_CONFIG | DIM2_CONFIG)
#define DIM0123_CONFIG	(DIM0_CONFIG | DIM1_CONFIG | DIM2_CONFIG | DIM3_CONFIG)
#define config_mask(_mask, _event_id) \
	((union core_event_config) { \
		.monitor = 0, \
		.event_id = (_event_id), \
		.mask = (_mask) \
	})

/* This also corresponds to C setting all unintialized fields to 0 */
#define config_invalid() ((union core_event_config) { \
		.monitor = 0, \
		.event_id = 0, \
		.mask = 0 \
	})

static inline bool is_config_invalid(union core_event_config config)
{
	return !config.mask && !config.monitor;
}

static union core_event_config hw_events_map[PERF_COUNT_HW_MAX] __ro_after_init = {
	/* PERF_COUNT_HW_CPU_CYCLES */
	config_monitor(DIM0_DIM1, 0x72),
	/* PERF_COUNT_HW_INSTRUCTIONS */
	config_monitor(DIM0_DIM1, 0x13),
	/* PERF_COUNT_HW_CACHE_REFERENCES */
	config_monitor(DDM0, 0x40),
	/* PERF_COUNT_HW_CACHE_MISSES */
	config_invalid(),
	/* PERF_COUNT_HW_BRANCH_INSTRUCTIONS */
	config_invalid(),
	/* PERF_COUNT_HW_BRANCH_MISSES */
	config_invalid(),
	/* PERF_COUNT_HW_BUS_CYCLES */
	config_invalid(),
	/* PERF_COUNT_HW_STALLED_CYCLES_FRONTEND */
	config_monitor(DIM0_DIM1, 0x18),
	/* PERF_COUNT_HW_STALLED_CYCLES_BACKEND = 0x19 + 0x2e + 0x2f */
	config_invalid(),
	/* PERF_COUNT_HW_REF_CPU_CYCLES */
	config_invalid()
};

static union core_event_config hw_cache_events_map[PERF_COUNT_HW_CACHE_MAX]
		[PERF_COUNT_HW_CACHE_OP_MAX][PERF_COUNT_HW_CACHE_RESULT_MAX] __ro_after_init = {
	[PERF_COUNT_HW_CACHE_L1D] = {
		[PERF_COUNT_HW_CACHE_OP_WRITE] = {
			[PERF_COUNT_HW_CACHE_RESULT_ACCESS] = config_monitor(DDM1, 0x1)
		}
	},
	[PERF_COUNT_HW_CACHE_LL] = {
		[PERF_COUNT_HW_CACHE_OP_WRITE] = {
			[PERF_COUNT_HW_CACHE_RESULT_ACCESS] = config_monitor(DDM1, 0x41)
		}
	},
};

static __init int init_perf_events_map(void)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		hw_events_map[PERF_COUNT_HW_BRANCH_INSTRUCTIONS] = config_monitor(DIM0_DIM1, 0x27);
		hw_events_map[PERF_COUNT_HW_CACHE_MISSES] = config_monitor(DDM0, 0x4e);

		hw_cache_events_map[PERF_COUNT_HW_CACHE_L1D]
				   [PERF_COUNT_HW_CACHE_OP_READ]
				   [PERF_COUNT_HW_CACHE_RESULT_ACCESS] = config_monitor(DDM0, 0x5);
		hw_cache_events_map[PERF_COUNT_HW_CACHE_L1D]
				   [PERF_COUNT_HW_CACHE_OP_READ]
				   [PERF_COUNT_HW_CACHE_RESULT_MISS] = config_monitor(DDM1, 0x5);
		hw_cache_events_map[PERF_COUNT_HW_CACHE_L1D]
				   [PERF_COUNT_HW_CACHE_OP_WRITE]
				   [PERF_COUNT_HW_CACHE_RESULT_ACCESS] = config_monitor(DDM0, 0x1);
		hw_cache_events_map[PERF_COUNT_HW_CACHE_L1D]
				   [PERF_COUNT_HW_CACHE_OP_WRITE]
				   [PERF_COUNT_HW_CACHE_RESULT_MISS] = config_monitor(DDM1, 0x3);
		hw_cache_events_map[PERF_COUNT_HW_CACHE_L1D]
				   [PERF_COUNT_HW_CACHE_OP_PREFETCH]
				   [PERF_COUNT_HW_CACHE_RESULT_ACCESS] = config_monitor(DDM0, 0x7);
		hw_cache_events_map[PERF_COUNT_HW_CACHE_L1D]
				   [PERF_COUNT_HW_CACHE_OP_PREFETCH]
				   [PERF_COUNT_HW_CACHE_RESULT_MISS] = config_monitor(DDM1, 0x6);

		hw_cache_events_map[PERF_COUNT_HW_CACHE_LL]
				   [PERF_COUNT_HW_CACHE_OP_READ]
				   [PERF_COUNT_HW_CACHE_RESULT_ACCESS] = config_monitor(DDM0, 0x4d);
		hw_cache_events_map[PERF_COUNT_HW_CACHE_LL]
				   [PERF_COUNT_HW_CACHE_OP_READ]
				   [PERF_COUNT_HW_CACHE_RESULT_MISS] = config_monitor(DDM1, 0x4e);
		hw_cache_events_map[PERF_COUNT_HW_CACHE_LL]
				   [PERF_COUNT_HW_CACHE_OP_WRITE]
				   [PERF_COUNT_HW_CACHE_RESULT_ACCESS] = config_monitor(DDM1, 0x41);
		hw_cache_events_map[PERF_COUNT_HW_CACHE_LL]
				   [PERF_COUNT_HW_CACHE_OP_WRITE]
				   [PERF_COUNT_HW_CACHE_RESULT_MISS] = config_monitor(DDM1, 0x4d);
		/* bug 109342 comment 11: LL-prefetch = l1d-prefetch-miss */
		hw_cache_events_map[PERF_COUNT_HW_CACHE_LL]
				   [PERF_COUNT_HW_CACHE_OP_PREFETCH]
				   [PERF_COUNT_HW_CACHE_RESULT_ACCESS] = config_monitor(DDM1, 0x6);
		hw_cache_events_map[PERF_COUNT_HW_CACHE_LL]
				   [PERF_COUNT_HW_CACHE_OP_PREFETCH]
				   [PERF_COUNT_HW_CACHE_RESULT_MISS] = config_monitor(DDM1, 0x4f);

		hw_cache_events_map[PERF_COUNT_HW_CACHE_DTLB]
				   [PERF_COUNT_HW_CACHE_OP_READ]
				   [PERF_COUNT_HW_CACHE_RESULT_ACCESS] = config_monitor(DDM0, 0x1a);
		hw_cache_events_map[PERF_COUNT_HW_CACHE_DTLB]
				   [PERF_COUNT_HW_CACHE_OP_READ]
				   [PERF_COUNT_HW_CACHE_RESULT_MISS] = config_monitor(DDM1, 0x1a);
		hw_cache_events_map[PERF_COUNT_HW_CACHE_DTLB]
				   [PERF_COUNT_HW_CACHE_OP_WRITE]
				   [PERF_COUNT_HW_CACHE_RESULT_ACCESS] = config_monitor(DDM0, 0x1b);
		hw_cache_events_map[PERF_COUNT_HW_CACHE_DTLB]
				   [PERF_COUNT_HW_CACHE_OP_WRITE]
				   [PERF_COUNT_HW_CACHE_RESULT_MISS] = config_monitor(DDM1, 0x1b);
		hw_cache_events_map[PERF_COUNT_HW_CACHE_DTLB]
				   [PERF_COUNT_HW_CACHE_OP_PREFETCH]
				   [PERF_COUNT_HW_CACHE_RESULT_ACCESS] = config_monitor(DDM0, 0x1c);
		hw_cache_events_map[PERF_COUNT_HW_CACHE_DTLB]
				   [PERF_COUNT_HW_CACHE_OP_PREFETCH]
				   [PERF_COUNT_HW_CACHE_RESULT_MISS] = config_monitor(DDM1, 0x1c);
	}

	if (machine.native_iset_ver >= E2K_ISET_V7) {
		hw_events_map[PERF_COUNT_HW_CPU_CYCLES] = config_mask(DIM0123_CONFIG, 0x72);
		hw_events_map[PERF_COUNT_HW_INSTRUCTIONS] = config_mask(DIM012_CONFIG, 0x13);
		hw_events_map[PERF_COUNT_HW_STALLED_CYCLES_FRONTEND] =
						config_mask(DIM0123_CONFIG, 0x18);
		hw_events_map[PERF_COUNT_HW_BRANCH_MISSES] = config_mask(DIM0123_CONFIG, 0x98);
	}

	return 0;
}
pure_initcall(init_perf_events_map);

#define MAX_EVENTS 256
static const char hw_raw_event_to_iset[MAX_HW_MONITORS][MAX_EVENTS] = {
	[DDM0] = {
		[0x0 ... 0x3]	= E2K_ISET_SINCE_V3_MASK,
		[0x10 ... 0x19] = E2K_ISET_SINCE_V3_MASK,
		[0x20 ... 0x24] = E2K_ISET_SINCE_V3_MASK,
		[0x30]		= E2K_ISET_SINCE_V3_MASK,
		[0x31 ... 0x32] = E2K_ISET_V3_MASK | E2K_ISET_SINCE_V7_MASK,
		[0x33 ... 0x34] = E2K_ISET_SINCE_V3_MASK,
		/* Same as 0x37 on v4-v6 */
		[0x35]		= E2K_ISET_V3_MASK | E2K_ISET_SINCE_V7_MASK,
		[0x36 ... 0x3a] = E2K_ISET_SINCE_V3_MASK,
		[0x40 ... 0x46] = E2K_ISET_SINCE_V3_MASK,
		[0x48]		= E2K_ISET_SINCE_V3_MASK,
		[0x4a ... 0x4b] = E2K_ISET_SINCE_V3_MASK,
		[0x70 ... 0x72] = E2K_ISET_SINCE_V3_MASK,

		[0x4]		= E2K_ISET_SINCE_V5_MASK,
		[0x47]		= E2K_ISET_SINCE_V5_MASK,

		[0x5 ... 0x7]	= E2K_ISET_SINCE_V6_MASK,
		[0x1a ... 0x1c]	= E2K_ISET_SINCE_V6_MASK,
		[0x49]		= E2K_ISET_SINCE_V6_MASK,
		[0x4c ... 0x4f]	= E2K_ISET_SINCE_V6_MASK,

		[0x8 ... 0x9]	= E2K_ISET_SINCE_V7_MASK,
		[0x1d ... 0x1e]	= E2K_ISET_SINCE_V7_MASK,
		[0x3b]		= E2K_ISET_SINCE_V7_MASK,
	},
	[DDM1] = {
		[0x0 ... 0x2]	= E2K_ISET_SINCE_V3_MASK,
		[0x10 ... 0x19]	= E2K_ISET_SINCE_V3_MASK,
		[0x20 ... 0x24]	= E2K_ISET_SINCE_V3_MASK,
		[0x30 ... 0x39]	= E2K_ISET_SINCE_V3_MASK,
		[0x3a]		= E2K_ISET_V3_MASK | E2K_ISET_SINCE_V7_MASK,
		[0x40 ... 0x48]	= E2K_ISET_SINCE_V3_MASK,
		[0x4a ... 0x4b]	= E2K_ISET_SINCE_V3_MASK,
		[0x70 ... 0x72]	= E2K_ISET_SINCE_V3_MASK,

		[0x4]		= E2K_ISET_SINCE_V5_MASK,

		[0x3]		= E2K_ISET_SINCE_V6_MASK,
		[0x5 ... 0x7]	= E2K_ISET_SINCE_V6_MASK,
		[0x1a ... 0x1c]	= E2K_ISET_SINCE_V6_MASK,
		[0x49]		= E2K_ISET_SINCE_V6_MASK,
		[0x4d ... 0x4f]	= E2K_ISET_SINCE_V6_MASK,

		[0x8 ... 0xa]	= E2K_ISET_SINCE_V7_MASK,
		[0x1d ... 0x1e]	= E2K_ISET_SINCE_V7_MASK,
		[0x3b ... 0x3e] = E2K_ISET_SINCE_V7_MASK,
	},
	[DIM0] = {
		[0x0 ... 0x3]	= E2K_ISET_SINCE_V3_MASK,
		[0x7 ... 0xa]	= E2K_ISET_SINCE_V3_MASK,
		[0xf]		= E2K_ISET_SINCE_V3_MASK,
		[0x10 ... 0x26]	= E2K_ISET_SINCE_V3_MASK,
		[0x30 ... 0x3d]	= E2K_ISET_SINCE_V3_MASK,
		[0x40 ... 0x4a]	= E2K_ISET_SINCE_V3_MASK,
		[0x50 ... 0x5a]	= E2K_ISET_SINCE_V3_MASK,
		[0x60 ... 0x69]	= E2K_ISET_SINCE_V3_MASK,
		[0x70 ... 0x74]	= E2K_ISET_SINCE_V3_MASK,

		[0x2d ... 0x2f]	= E2K_ISET_SINCE_V5_MASK,

		[0x27]		= E2K_ISET_SINCE_V6_MASK,

		[0x28]		= E2K_ISET_SINCE_V7_MASK,
		[0x80 ... 0x99] = E2K_ISET_SINCE_V7_MASK,
		[0x9c ... 0x9f] = E2K_ISET_SINCE_V7_MASK,
	},
	[DIM1] = {
		/* Almost same as _DIM0 - only 0xf/0x25/0x26 events differ */
		[0x0 ... 0x3]	= E2K_ISET_SINCE_V3_MASK,
		[0x7 ... 0xa]	= E2K_ISET_SINCE_V3_MASK,
		[0x10 ... 0x24]	= E2K_ISET_SINCE_V3_MASK,
		[0x30 ... 0x3d]	= E2K_ISET_SINCE_V3_MASK,
		[0x40 ... 0x4a]	= E2K_ISET_SINCE_V3_MASK,
		[0x50 ... 0x5a]	= E2K_ISET_SINCE_V3_MASK,
		[0x60 ... 0x69]	= E2K_ISET_SINCE_V3_MASK,
		[0x70 ... 0x74]	= E2K_ISET_SINCE_V3_MASK,

		[0x2d ... 0x2f]	= E2K_ISET_SINCE_V5_MASK,

		[0x27]		= E2K_ISET_SINCE_V6_MASK,

		[0x28]		= E2K_ISET_SINCE_V7_MASK,
		[0x80 ... 0x99] = E2K_ISET_SINCE_V7_MASK,
		[0x9c ... 0x9f] = E2K_ISET_SINCE_V7_MASK,
	},
	[DIM2] = {
		[0x2]		= E2K_ISET_SINCE_V7_MASK,
		[0x7]		= E2K_ISET_SINCE_V7_MASK,
		[0x11]		= E2K_ISET_SINCE_V7_MASK,
		[0x13 ... 0x14] = E2K_ISET_SINCE_V7_MASK,
		[0x18 ... 0x19] = E2K_ISET_SINCE_V7_MASK,
		[0x1b]		= E2K_ISET_SINCE_V7_MASK,
		[0x1f]		= E2K_ISET_SINCE_V7_MASK,
		[0x21]		= E2K_ISET_SINCE_V7_MASK,
		[0x26]		= E2K_ISET_SINCE_V7_MASK,
		[0x28 ... 0x2a] = E2K_ISET_SINCE_V7_MASK,
		[0x2f ... 0x30] = E2K_ISET_SINCE_V7_MASK,
		[0x32]		= E2K_ISET_SINCE_V7_MASK,
		[0x34]		= E2K_ISET_SINCE_V7_MASK,
		[0x36]		= E2K_ISET_SINCE_V7_MASK,
		[0x39]		= E2K_ISET_SINCE_V7_MASK,
		[0x3c ... 0x3d] = E2K_ISET_SINCE_V7_MASK,
		[0x42]		= E2K_ISET_SINCE_V7_MASK,
		[0x44]		= E2K_ISET_SINCE_V7_MASK,
		[0x48]		= E2K_ISET_SINCE_V7_MASK,
		[0x50]		= E2K_ISET_SINCE_V7_MASK,
		[0x53]		= E2K_ISET_SINCE_V7_MASK,
		[0x56]		= E2K_ISET_SINCE_V7_MASK,
		[0x5a]		= E2K_ISET_SINCE_V7_MASK,
		[0x62]		= E2K_ISET_SINCE_V7_MASK,
		[0x66]		= E2K_ISET_SINCE_V7_MASK,
		[0x72]		= E2K_ISET_SINCE_V7_MASK,
		[0x83]		= E2K_ISET_SINCE_V7_MASK,
		[0x85]		= E2K_ISET_SINCE_V7_MASK,
		[0x87]		= E2K_ISET_SINCE_V7_MASK,
		[0x8c ... 0x8d] = E2K_ISET_SINCE_V7_MASK,
		[0x8f ... 0x90] = E2K_ISET_SINCE_V7_MASK,
		[0x92]		= E2K_ISET_SINCE_V7_MASK,
		[0x96 ... 0x98] = E2K_ISET_SINCE_V7_MASK,
		[0x9f]		= E2K_ISET_SINCE_V7_MASK,
	},
	[DIM3] = {
		[0x3]		= E2K_ISET_SINCE_V7_MASK,
		[0x8]		= E2K_ISET_SINCE_V7_MASK,
		[0x11]		= E2K_ISET_SINCE_V7_MASK,
		[0x14 ... 0x15] = E2K_ISET_SINCE_V7_MASK,
		[0x18 ... 0x19] = E2K_ISET_SINCE_V7_MASK,
		[0x1c]		= E2K_ISET_SINCE_V7_MASK,
		[0x26]		= E2K_ISET_SINCE_V7_MASK,
		[0x28 ... 0x2a] = E2K_ISET_SINCE_V7_MASK,
		[0x2f ... 0x30] = E2K_ISET_SINCE_V7_MASK,
		[0x32]		= E2K_ISET_SINCE_V7_MASK,
		[0x34]		= E2K_ISET_SINCE_V7_MASK,
		[0x36]		= E2K_ISET_SINCE_V7_MASK,
		[0x3a]		= E2K_ISET_SINCE_V7_MASK,
		[0x3c ... 0x3d] = E2K_ISET_SINCE_V7_MASK,
		[0x42]		= E2K_ISET_SINCE_V7_MASK,
		[0x45]		= E2K_ISET_SINCE_V7_MASK,
		[0x49]		= E2K_ISET_SINCE_V7_MASK,
		[0x51]		= E2K_ISET_SINCE_V7_MASK,
		[0x53]		= E2K_ISET_SINCE_V7_MASK,
		[0x57]		= E2K_ISET_SINCE_V7_MASK,
		[0x5a]		= E2K_ISET_SINCE_V7_MASK,
		[0x63]		= E2K_ISET_SINCE_V7_MASK,
		[0x67]		= E2K_ISET_SINCE_V7_MASK,
		[0x72]		= E2K_ISET_SINCE_V7_MASK,
		[0x84]		= E2K_ISET_SINCE_V7_MASK,
		[0x86 ... 0x87] = E2K_ISET_SINCE_V7_MASK,
		[0x8b]		= E2K_ISET_SINCE_V7_MASK,
		[0x8e ... 0x8f] = E2K_ISET_SINCE_V7_MASK,
		[0x91 ... 0x92] = E2K_ISET_SINCE_V7_MASK,
		[0x95]		= E2K_ISET_SINCE_V7_MASK,
		[0x97 ... 0x98] = E2K_ISET_SINCE_V7_MASK,
		[0x9f]		= E2K_ISET_SINCE_V7_MASK,
	},
	[DDM0_DDM1] = {
		/* Intersection of DDM0/DDM1 */
		[0x4]		= E2K_ISET_SINCE_V5_MASK,
	},
	[DIM0_DIM1] = {
		/* Intersection of DIM0/DIM1 */
		[0x0 ... 0x3]	= E2K_ISET_SINCE_V3_MASK,
		[0x7 ... 0xa]	= E2K_ISET_SINCE_V3_MASK,
		[0x10 ... 0x24]	= E2K_ISET_SINCE_V3_MASK,
		[0x30 ... 0x3d]	= E2K_ISET_SINCE_V3_MASK,
		[0x40 ... 0x4a]	= E2K_ISET_SINCE_V3_MASK,
		[0x50 ... 0x5a]	= E2K_ISET_SINCE_V3_MASK,
		[0x60 ... 0x69]	= E2K_ISET_SINCE_V3_MASK,
		[0x70 ... 0x74]	= E2K_ISET_SINCE_V3_MASK,

		[0x2d ... 0x2f]	= E2K_ISET_SINCE_V5_MASK,

		[0x27]		= E2K_ISET_SINCE_V6_MASK,

		[0x28]		= E2K_ISET_SINCE_V7_MASK,
		[0x80 ... 0x99] = E2K_ISET_SINCE_V7_MASK,
		[0x9c ... 0x9f] = E2K_ISET_SINCE_V7_MASK,
	},
	[DDM2] = {
		[0x0 ... 0x1d]	= E2K_ISET_SINCE_V7_MASK,
	},
	[DDM3] = {
		[0x0 ... 0x37]	= E2K_ISET_SINCE_V7_MASK,
	}
};

bool hw_event_supported(u8 monitor, u8 event_id)
{
	if (monitor >= MAX_HW_MONITORS || event_id >= MAX_EVENTS)
		return false;

	return !!(hw_raw_event_to_iset[monitor][event_id] & (1 << machine.native_iset_ver));
}

/*
 * Configuration for raw events (PERF_TYPE_RAW) as specified by user,
 * this corresponds to `perf_event_attr.config`.
 */
union attr_raw_config {
	struct {
		u8 event_id;

		/* Either set immediately by user in old rMMEE (M - monitor,
		 * E - event) format, or is updated dynamically based on `mask`
		 * field if user used new rMM00EE (M - mask, E - event) format */
		u8 monitor;

		union {
			struct {
				u8 ddm0 : 1;
				u8 ddm1 : 1;
				u8 ddm2 : 1;
				u8 ddm3 : 1;
				u8 dim0 : 1;
				u8 dim1 : 1;
				u8 dim2 : 1;
				u8 dim3 : 1;
			};
			u8 mask;
		};
	};
	u64 word;
};

/**
 * event_attr_to_monitor_and_id - take event as specified by user and convert to
 *				  internal `hw_perf_event.config` representation.
 * @attr: user's configuration of event
 * @config: kernel's configuration is returned here
 *
 * Returns error if event is not supported by current hardware.
 */
static int event_attr_to_monitor_and_id(const struct perf_event_attr *attr,
					union core_event_config *config)
{
	switch (attr->type) {
	case PERF_TYPE_RAW: {
		union attr_raw_config cfg = (union attr_raw_config) { .word = attr->config };

		pr_debug("initializing raw event %hhx:%hhx:%02hhx\n",
			cfg.mask, cfg.monitor, cfg.event_id);

		if (cfg.mask && cfg.monitor)
			return -EINVAL;

		/* Check `cfg.mask` first since `config.monitor` can be 0 (DDM0) */
		if (cfg.mask) {
			if ((cfg.dim0 || cfg.dim1 || cfg.dim2 || cfg.dim3) &&
			    (cfg.ddm0 || cfg.ddm1 || cfg.ddm2 || cfg.ddm3))
				return -EINVAL;

			if (cfg.dim0 && !hw_event_supported(DIM0, cfg.event_id) ||
			    cfg.dim1 && !hw_event_supported(DIM1, cfg.event_id) ||
			    cfg.dim2 && !hw_event_supported(DIM2, cfg.event_id) ||
			    cfg.dim3 && !hw_event_supported(DIM3, cfg.event_id) ||
			    cfg.ddm0 && !hw_event_supported(DDM0, cfg.event_id) ||
			    cfg.ddm1 && !hw_event_supported(DDM1, cfg.event_id) ||
			    cfg.ddm2 && !hw_event_supported(DDM2, cfg.event_id) ||
			    cfg.ddm3 && !hw_event_supported(DDM3, cfg.event_id))
				return -EINVAL;
		} else {
			if (!hw_event_supported(cfg.monitor, cfg.event_id))
				return -EINVAL;
		}

		*config = (union core_event_config) {
			.mask = cfg.mask,
			.monitor = cfg.monitor,
			.event_id = cfg.event_id
		};
		break;
	}
	case PERF_TYPE_HARDWARE: {
		u64 num = attr->config;
		if (unlikely(num >= PERF_COUNT_HW_MAX))
			return -EINVAL;

		union core_event_config cfg = hw_events_map[num];
		if (is_config_invalid(cfg)) {
			pr_debug("hardware perf_event: config not supported\n");
			return -EINVAL;
		}

		*config = cfg;
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

		union core_event_config cfg = hw_cache_events_map[type][op][result];
		if (is_config_invalid(cfg)) {
			pr_debug("hardware perf_event: config not supported\n");
			return -EINVAL;
		}

		*config = cfg;
		break;
	}
	default:
		return -ENOENT;
	}

	return 0;
}

static int e2k_pmu_event_init(struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;
	union core_event_config config;
	int err;

	err = event_attr_to_monitor_and_id(&event->attr, &config);
	if (err)
		goto error;

	if (config.monitor == DIM2 || config.monitor == DIM3) {
		err = -EINVAL;
		goto error;
	}

	/*
	 * Good, this event will fit. Save configuration.
	 */

	config.user = !event->attr.exclude_user;
	config.system = !event->attr.exclude_kernel;
	config.instruction = config.dim0 || config.dim1 || config.dim2 || config.dim3 ||
			     config.monitor == DIM0 || config.monitor == DIM1 ||
			     config.monitor == DIM2 || config.monitor == DIM3 ||
			     config.monitor == DIM0_DIM1;

	if (is_sampling_event(event) &&
	    cpu_has(CPU_HWBUG_KERNEL_DATA_MONITOR) &&
	    (config.monitor == DDM0_DDM1 || config.monitor == DDM0 ||
	     config.monitor == DDM1 || config.monitor == DDM2 || config.monitor == DDM3)) {
		config.system = 0;
	}

	hwc->config = config.word;
	hwc->idx = (config.monitor == DIM3 || config.monitor == DDM3) ? 3 :
		   (config.monitor == DIM2 || config.monitor == DDM2) ? 2 :
		   (config.monitor == DIM1 || config.monitor == DDM1) ? 1 :
		   0;

	pr_debug("perf event %lld initialized with config %hhx:%hhx:%hhx\n",
		 event->id, config.mask, config.monitor, config.event_id);

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
	 * interrupt is cleared when writing to %dimcr[1]/%ddmcr[1].
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

ssize_t events_sysfs_show(struct device *dev,
				struct device_attribute *attr, char *page)
{
	struct perf_pmu_events_attr *pmu_attr =
			container_of(attr, struct perf_pmu_events_attr, attr);

	return sprintf(page, "event=0x%02llx\n", pmu_attr->id);
}

EVENT_ATTR(cpu-cycles,			CPU_CYCLES		);
EVENT_ATTR(instructions,		INSTRUCTIONS		);
EVENT_ATTR(cache-references,		CACHE_REFERENCES	);
EVENT_ATTR(cache-misses, 		CACHE_MISSES		);
EVENT_ATTR(branch-instructions,		BRANCH_INSTRUCTIONS	);
EVENT_ATTR(branch-misses,		BRANCH_MISSES		);
EVENT_ATTR(bus-cycles,			BUS_CYCLES		);
EVENT_ATTR(stalled-cycles-frontend,	STALLED_CYCLES_FRONTEND	);
EVENT_ATTR(stalled-cycles-backend,	STALLED_CYCLES_BACKEND	);
EVENT_ATTR(ref-cycles,			REF_CPU_CYCLES		);

static struct attribute *e2k_pmu_events_attrs[] = {
	/* Define in same order for is_visible() to work */
	EVENT_PTR(CPU_CYCLES),
	EVENT_PTR(INSTRUCTIONS),
	EVENT_PTR(CACHE_REFERENCES),
	EVENT_PTR(CACHE_MISSES),
	EVENT_PTR(BRANCH_INSTRUCTIONS),
	EVENT_PTR(BRANCH_MISSES),
	EVENT_PTR(BUS_CYCLES),
	EVENT_PTR(STALLED_CYCLES_FRONTEND),
	EVENT_PTR(STALLED_CYCLES_BACKEND),
	EVENT_PTR(REF_CPU_CYCLES),
	NULL
};

static umode_t is_visible(struct kobject *kobj, struct attribute *attr, int idx)
{
	struct perf_pmu_events_attr *pmu_attr;

	if (idx >= PERF_COUNT_HW_MAX)
		return 0;

	pmu_attr = container_of(attr, struct perf_pmu_events_attr, attr.attr);
	/* str trumps id */
	return (pmu_attr->event_str ||
		!is_config_invalid(hw_events_map[idx])) ? attr->mode : 0;
}

static struct attribute_group e2k_pmu_events_group = {
	.name = "events",
	.attrs = e2k_pmu_events_attrs,
	.is_visible = is_visible,
};

PMU_FORMAT_ATTR(event, "config:0-63");

static struct attribute *e2k_pmu_format_attrs[] = {
	&format_attr_event.attr,
	NULL
};

static const struct attribute_group e2k_pmu_format_group = {
	.name = "format",
	.attrs = e2k_pmu_format_attrs
};

/* Needed for event aliases from tools/perf/pmu-events/ to work */
static const struct attribute_group *e2k_pmu_attr_groups[] = {
	&e2k_pmu_events_group,
	&e2k_pmu_format_group,
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

