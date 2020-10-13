#include <linux/list.h>
#include <linux/perf_event.h>
#include <asm/e2k_debug.h>

extern char _t_entry[];
extern char _t_entry_end[];
extern char __entry_handlers_start[];
extern char __entry_handlers_end[];
static inline bool is_glue(u64 ip)
{
	return ip >= (u64) __entry_handlers_start &&
					ip < (u64) __entry_handlers_end
			|| ip >= (u64) _t_entry && ip < (u64) _t_entry_end;
}


static int save_stack_address(struct task_struct *task,
		e2k_mem_crs_t *frame, unsigned long frame_address,
		void *data1, void *data2, void *data3)
{
	struct perf_callchain_entry *entry = data1;
	u64 top = (u64) data2;
	u64 type = (u64) data3;
	u64 ip;

	if (unlikely(entry->nr >= PERF_MAX_STACK_DEPTH))
		return 1;

	/*
	 * Skip entries that correspond to the perf itself.
	 */
	if (frame_address >= top)
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
void perf_callchain_user(struct perf_callchain_entry *entry,
			 struct pt_regs *regs)
{
	perf_callchain_store(entry, AS(regs->crs.cr0_hi).ip << 3);

	parse_chain_stack(NULL, save_stack_address, entry,
			(void *) (AS(regs->stacks.pcsp_lo).base +
				  AS(regs->stacks.pcsp_hi).ind),
			(void *) PERF_CONTEXT_USER);
}

void perf_callchain_kernel(struct perf_callchain_entry *entry,
			   struct pt_regs *regs)
{
	perf_callchain_store(entry, AS(regs->crs.cr0_hi).ip << 3);

	parse_chain_stack(NULL, save_stack_address, entry,
			(void *) (AS(regs->stacks.pcsp_lo).base +
				  AS(regs->stacks.pcsp_hi).ind),
			(void *) PERF_CONTEXT_KERNEL);
}


/*
 * Hardware counters support
 *
 * DIM0 has all counters from DIM1 and some more. So events for
 * DIM1 are marked with DIM0_DIM1, and the actual used monitor
 * will be determined at runtime.
 */

enum {
	_DDM0 = 0,
	_DDM1,
	_DIM0,
	_DIM1,
	MAX_HW_MONITORS
};

#define DDM0 (1 << _DDM0)
#define DDM1 (1 << _DDM1)
#define DIM0 (1 << _DIM0)
#define DIM1 (1 << _DIM1)
#define DIM0_DIM1 (1 << MAX_HW_MONITORS)

static DEFINE_PER_CPU(struct perf_event * [4], cpu_events);
static DEFINE_PER_CPU(int, monitors_spurious);

static void e2k_pmu_read(struct perf_event *event);

static int handle_event(struct perf_event *event, struct pt_regs *regs,
			unsigned long ip)
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

	if (!(hwc->config & ARCH_PERFMON_OS))
		regs = find_user_regs(regs);

	if (!(event->attr.exclude_idle && current->pid == 0))
		return perf_event_overflow(event, &data, regs);

	return 0;
}

static s64 monitor_pause(struct hw_perf_event *hwc, int update);

static DEFINE_PER_CPU(u8, perf_monitors_used);

int perf_data_overflow_handle(struct pt_regs *regs)
{
	unsigned long flags, ip;
	e2k_ddbsr_t ddbsr;
	struct perf_event *event;
	struct hw_perf_event *hwc;
	s64 period;
	int ret, handled = 1;

	/*
	 * Make sure another overflow does not happen while
	 * we are handling this one to avoid races.
	 */
	raw_all_irq_save(flags);

	AW(ddbsr) = E2K_GET_MMUREG(ddbsr);
	if (!AS(ddbsr).m0 && !AS(ddbsr).m1)
		pr_debug("perf: spurious exc_data_debug\n");

	pr_debug("data overflow, ddbsr %llx\n", AW(ddbsr));

	if (AS(ddbsr).m0) {
		event = __get_cpu_var(cpu_events)[2];

		if (event && (__get_cpu_var(perf_monitors_used) & DDM0)) {
			hwc = &event->hw;

			if ((event->attr.sample_type & PERF_SAMPLE_IP) &&
					machine.iset_ver >= E2K_ISET_V2)
				ip = E2K_GET_MMUREG(ddmar0);
			else
				ip = -1UL;

			ret = handle_event(event, regs, ip);
			if (ret)
				monitor_pause(hwc, 0);

			AS(ddbsr).m0 = 0;

			period = hwc->sample_period;

			E2K_SET_MMUREG(ddmar0, -period);

			local64_set(&hwc->prev_count, period);

			pr_debug("DDM0 event %lx %shandled, new period %lld\n",
				event, (ret) ? "could not be " : "", period);
		} else {
			handled = !!(__get_cpu_var(monitors_spurious) & DDM0);
		}
	}

	if (AS(ddbsr).m1) {
		event = __get_cpu_var(cpu_events)[3];

		if (event && (__get_cpu_var(perf_monitors_used) & DDM1)) {
			hwc = &event->hw;

			if ((event->attr.sample_type & PERF_SAMPLE_IP) &&
					machine.iset_ver >= E2K_ISET_V2)
				ip = E2K_GET_MMUREG(ddmar1);
			else
				ip = -1UL;

			ret = handle_event(event, regs, ip);
			if (ret)
				monitor_pause(hwc, 0);

			AS(ddbsr).m1 = 0;

			period = hwc->sample_period;

			E2K_SET_MMUREG(ddmar1, -period);

			local64_set(&hwc->prev_count, period);

			pr_debug("DDM1 event %lx %shandled, new period %lld\n",
				event, (ret) ? "could not be " : "", period);
		} else {
			handled = !!(__get_cpu_var(monitors_spurious) & DDM1);
		}
	}

	pr_debug("data overflow handled\n");

	E2K_SET_MMUREG(ddbsr, AW(ddbsr));

	raw_all_irq_restore(flags);

	/* Check for breakpoints */
	if (handled && (AS(ddbsr).b0 || AS(ddbsr).b1 ||
			AS(ddbsr).b2 || AS(ddbsr).b3))
		handled = 0;

	return handled;
}

int perf_instr_overflow_handle(struct pt_regs *regs)
{
	unsigned long flags, ip;
	e2k_dibsr_t dibsr;
	struct perf_event *event;
	struct hw_perf_event *hwc;
	s64 period;
	int ret, handled = 1;

	/*
	 * Make sure another overflow does not happen while
	 * we are handling this one to avoid races.
	 */
	raw_all_irq_save(flags);

	AW(dibsr) = E2K_GET_SREG(dibsr);
	if (!AS(dibsr).m0 && !AS(dibsr).m1)
		pr_debug("perf: spurious exc_instr_debug\n");

	pr_debug("instr overflow, dibsr %x\n", AW(dibsr));

	if (AS(dibsr).m0) {
		event = __get_cpu_var(cpu_events)[0];

		if (event && (__get_cpu_var(perf_monitors_used) & DIM0)) {
			hwc = &event->hw;

			if ((event->attr.sample_type & PERF_SAMPLE_IP) &&
					machine.iset_ver >= E2K_ISET_V2)
				ip = E2K_GET_DSREG(dimar0);
			else
				ip = -1UL;

			ret = handle_event(event, regs, ip);
			if (ret)
				monitor_pause(hwc, 0);

			AS(dibsr).m0 = 0;

			period = hwc->sample_period;

			E2K_SET_DSREG(dimar0, -period);

			local64_set(&hwc->prev_count, period);

			pr_debug("DIM0 event %lx %shandled, new period %lld\n",
				event, (ret) ? "could not be " : "", period);
		} else {
			handled = !!(__get_cpu_var(monitors_spurious) & DIM0);
		}
	}

	if (AS(dibsr).m1) {
		event = __get_cpu_var(cpu_events)[1];

		if (event && (__get_cpu_var(perf_monitors_used) & DIM1)) {
			hwc = &event->hw;

			if ((event->attr.sample_type & PERF_SAMPLE_IP) &&
					machine.iset_ver >= E2K_ISET_V2)
				ip = E2K_GET_DSREG(dimar1);
			else
				ip = -1UL;

			ret = handle_event(event, regs, ip);
			if (ret)
				monitor_pause(hwc, 0);

			AS(dibsr).m1 = 0;

			period = hwc->sample_period;

			E2K_SET_DSREG(dimar1, -period);

			local64_set(&hwc->prev_count, period);

			pr_debug("DIM1 event %lx %shandled, new period %lld\n",
				event, (ret) ? "could not be " : "", period);
		} else {
			handled = !!(__get_cpu_var(monitors_spurious) & DIM1);
		}
	}

	pr_debug("instr overflow handled\n");

	E2K_SET_SREG(dibsr, AW(dibsr));

	raw_all_irq_restore(flags);

	/* Check for breakpoints */
	if (handled && (AS(dibsr).b0 || AS(dibsr).b1 ||
			AS(dibsr).b2 || AS(dibsr).b3))
		handled = 0;

	return handled;
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

	hwc->config |= ARCH_PERFMON_ENABLED;

	AW(dibcr) = E2K_GET_SREG(dibcr);
	WARN_ON(AS(dibcr).stop);

	switch (monitor) {
	case DIM0:
	case DIM1:
	case DIM0_DIM1:
		AW(dimcr) = E2K_GET_DSREG(dimcr);
		AS(dimcr)[num].user = !!(hwc->config & ARCH_PERFMON_USR);
		AS(dimcr)[num].system = !!(hwc->config & ARCH_PERFMON_OS);
		AS(dimcr)[num].trap = 1;
		AS(dimcr)[num].event = event_id;
		if (reload) {
			period = -period;

			if (num == 1)
				E2K_SET_DSREG(dimar1, period);
			else
				E2K_SET_DSREG(dimar0, period);
		}
		E2K_SET_DSREG(dimcr, AW(dimcr));
		break;
	case DDM0:
	case DDM1:
		AW(ddmcr) = E2K_GET_MMUREG(ddmcr);
		AS(ddmcr)[num].user = !!(hwc->config & ARCH_PERFMON_USR);
		AS(ddmcr)[num].system = !!(hwc->config & ARCH_PERFMON_OS);
		AS(ddmcr)[num].trap = 1;
		AS(ddmcr)[num].event = event_id;
		if (reload) {
			period = -period;

			if (num == 1)
				E2K_SET_MMUREG(ddmar1, period);
			else
				E2K_SET_MMUREG(ddmar0, period);
		}
		E2K_SET_MMUREG(ddmcr, AW(ddmcr));
		break;
	default:
		BUG_ON(1);
	}

	pr_debug("event %hhx:%02hhx: resuming\n", monitor, event_id);

	raw_all_irq_restore(flags);
}

static s64 monitor_pause(struct hw_perf_event *hwc, int update)
{
	unsigned long flags;
	e2k_dimcr_t dimcr;
	e2k_ddmcr_t ddmcr;
	e2k_dibcr_t dibcr;
	u8 monitor, event_id;
	s64 left = 0;
	int num;

	raw_all_irq_save(flags);

	monitor = (hwc->config & 0xff00) >> 8;
	event_id = hwc->config & 0xff;
	num = hwc->idx;

	hwc->config &= ~ARCH_PERFMON_ENABLED;

	AW(dibcr) = E2K_GET_SREG(dibcr);
	WARN_ON(AS(dibcr).stop);

	switch (monitor) {
	case DIM0:
	case DIM1:
	case DIM0_DIM1:
		AW(dimcr) = E2K_GET_DSREG(dimcr);
		AS(dimcr)[num].user = 0;
		AS(dimcr)[num].system = 0;
		E2K_SET_DSREG(dimcr, AW(dimcr));
		if (update) {
			e2k_dibsr_t dibsr;

			AW(dibsr) = E2K_GET_SREG(dibsr);

			if (num == 1) {
				if (AS(dibsr).m1) {
					left = 1;
					pr_debug("event DIM1: left 0 (1)\n");
					/* See comment in monitor_disable() */
					AS(dibsr).m1 = 0;
					E2K_SET_DSREG(dibsr, AW(dibsr));
				} else {
					left = E2K_GET_DSREG(dimar1);
					left = -left;
					pr_debug("event DIM1: left %lld\n",
							left);
				}
			} else {
				if (AS(dibsr).m0) {
					left = 1;
					pr_debug("event DIM0: left 0 (1)\n");
					AS(dibsr).m0 = 0;
					E2K_SET_DSREG(dibsr, AW(dibsr));
				} else {
					left = E2K_GET_DSREG(dimar0);
					left = -left;
					pr_debug("event DIM0: left %lld\n",
							left);
				}
			}
		}
		break;
	case DDM0:
	case DDM1:
		AW(ddmcr) = E2K_GET_MMUREG(ddmcr);
		AS(ddmcr)[num].user = 0;
		AS(ddmcr)[num].system = 0;
		E2K_SET_MMUREG(ddmcr, AW(ddmcr));
		if (update) {
			e2k_ddbsr_t ddbsr;

			AW(ddbsr) = E2K_GET_MMUREG(ddbsr);

			if (num == 1) {
				if (AS(ddbsr).m1) {
					left = 1;
					pr_debug("event DDM1: left 0 (1)\n");
					AS(ddbsr).m1 = 0;
					E2K_SET_MMUREG(ddbsr, AW(ddbsr));
				} else {
					left = E2K_GET_MMUREG(ddmar1);
					left = -left;
					pr_debug("event DDM1: left %lld\n",
							left);
				}
			} else {
				if (AS(ddbsr).m0) {
					left = 1;
					pr_debug("event DDM0: left 0 (1)\n");
					AS(ddbsr).m0 = 0;
					E2K_SET_MMUREG(ddbsr, AW(ddbsr));
				} else {
					left = E2K_GET_MMUREG(ddmar0);
					left = -left;
					pr_debug("event DDM0: left %lld\n",
							left);
				}
			}
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

	AW(dibcr) = E2K_GET_SREG(dibcr);
	WARN_ON(AS(dibcr).stop);

	switch (monitor) {
	case DIM0:
	case DIM1:
	case DIM0_DIM1:
		if (monitor == DIM0_DIM1) {
			if (!(__get_cpu_var(perf_monitors_used) & DIM1)) {
				num = 1;
			} else if (!(__get_cpu_var(perf_monitors_used) & DIM0)) {
				num = 0;
			} else {
				ret = -ENOSPC;
				break;
			}

			hwc->idx = num;
		} else {
			num = (monitor == DIM1);

			if (num == 1 && (__get_cpu_var(perf_monitors_used) & DIM1) ||
			    num == 0 && (__get_cpu_var(perf_monitors_used) & DIM0)) {
				ret = -ENOSPC;
				break;
			}
		}

		AW(dimcr) = E2K_GET_DSREG(dimcr);
		AS(dimcr)[num].user = run && (hwc->config & ARCH_PERFMON_USR) &&
				      (hwc->config & ARCH_PERFMON_ENABLED);
		AS(dimcr)[num].system = 0;
		AS(dimcr)[num].trap = 1;
		AS(dimcr)[num].event = event_id;
		E2K_SET_DSREG(dimcr, AW(dimcr));

		AW(dibsr) = E2K_GET_SREG(dibsr);

		if (num == 1) {
			E2K_SET_DSREG(dimar1, period);
			AS(dibsr).m1 = 0;

			__get_cpu_var(cpu_events)[1] = event;

			__get_cpu_var(perf_monitors_used) |= DIM1;
		} else {
			E2K_SET_DSREG(dimar0, period);
			AS(dibsr).m0 = 0;

			__get_cpu_var(cpu_events)[0] = event;

			__get_cpu_var(perf_monitors_used) |= DIM0;
		}

		E2K_SET_SREG(dibsr, AW(dibsr));

		/*
		 * Start the monitor now that the preparations are done.
		 */
		if (run && (hwc->config & ARCH_PERFMON_OS) &&
		    (hwc->config & ARCH_PERFMON_ENABLED)) {
			AS(dimcr)[num].system = 1;
			E2K_SET_DSREG(dimcr, AW(dimcr));
		}
		break;
	case DDM0:
	case DDM1:
		num = (monitor == DDM1);

		if (num == 1 && (__get_cpu_var(perf_monitors_used) & DDM1) ||
		    num == 0 && (__get_cpu_var(perf_monitors_used) & DDM0)) {
			ret = -ENOSPC;
			break;
		}

		AW(ddmcr) = E2K_GET_MMUREG(ddmcr);
		AS(ddmcr)[num].user = run && (hwc->config & ARCH_PERFMON_USR) &&
				      (hwc->config & ARCH_PERFMON_ENABLED);
		AS(ddmcr)[num].system = 0;
		AS(ddmcr)[num].trap = 1;
		AS(ddmcr)[num].event = event_id;
		E2K_SET_MMUREG(ddmcr, AW(ddmcr));

		AW(ddbsr) = E2K_GET_MMUREG(ddbsr);

		if (num == 1) {
			E2K_SET_MMUREG(ddmar1, period);
			AS(ddbsr).m1 = 0;

			__get_cpu_var(cpu_events)[3] = event;

			__get_cpu_var(perf_monitors_used) |= DDM1;
		} else {
			E2K_SET_MMUREG(ddmar0, period);
			AS(ddbsr).m0 = 0;

			__get_cpu_var(cpu_events)[2] = event;

			__get_cpu_var(perf_monitors_used) |= DDM0;
		}

		E2K_SET_MMUREG(ddbsr, AW(ddbsr));

		/*
		 * Start the monitor now that the preparations are done.
		 */
		if (run && (hwc->config & ARCH_PERFMON_OS) &&
		    (hwc->config & ARCH_PERFMON_ENABLED)) {
			AS(ddmcr)[num].system = 1;
			E2K_SET_MMUREG(ddmcr, AW(ddmcr));
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

	BUG_ON(!!__get_cpu_var(hw_perf_disable_count) ^
	       !!raw_all_irqs_disabled());
	BUG_ON(!raw_irqs_disabled());

	switch (monitor) {
	case DIM0:
	case DIM1:
	case DIM0_DIM1:
		AW(dimcr) = E2K_GET_DSREG(dimcr);
		AS(dimcr)[num].user = 0;
		AS(dimcr)[num].system = 0;
		E2K_SET_DSREG(dimcr, AW(dimcr));

		raw_all_irq_save(flags);

		AW(dibsr) = E2K_GET_SREG(dibsr);

		if (num == 1) {
			__get_cpu_var(cpu_events)[1] = NULL;
			__get_cpu_var(monitors_spurious) |= DIM1;

			BUG_ON(!(__get_cpu_var(perf_monitors_used) & DIM1));
			__get_cpu_var(perf_monitors_used) &= ~DIM1;

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
				E2K_SET_DSREG(dibsr, AW(dibsr));
			} else {
				left = E2K_GET_DSREG(dimar1);
				left = -left;
				pr_debug("event DIM1: left %lld\n", left);
			}
		} else {
			__get_cpu_var(cpu_events)[0] = NULL;
			__get_cpu_var(monitors_spurious) |= DIM0;

			BUG_ON(!(__get_cpu_var(perf_monitors_used) & DIM0));
			__get_cpu_var(perf_monitors_used) &= ~DIM0;

			if (AS(dibsr).m0) {
				left = 1;
				pr_debug("event DIM0: left 0 (1)\n");
				AS(dibsr).m0 = 0;
				E2K_SET_DSREG(dibsr, AW(dibsr));
			} else {
				left = E2K_GET_DSREG(dimar0);
				left = -left;
				pr_debug("event DIM0: left %lld\n", left);
			}
		}
		break;
	case DDM0:
	case DDM1:
		AW(ddmcr) = E2K_GET_MMUREG(ddmcr);
		AS(ddmcr)[num].user = 0;
		AS(ddmcr)[num].system = 0;
		E2K_SET_MMUREG(ddmcr, AW(ddmcr));

		raw_all_irq_save(flags);

		AW(ddbsr) = E2K_GET_MMUREG(ddbsr);

		if (num == 1) {
			__get_cpu_var(cpu_events)[3] = NULL;
			__get_cpu_var(monitors_spurious) |= DDM1;

			BUG_ON(!(__get_cpu_var(perf_monitors_used) & DDM1));
			__get_cpu_var(perf_monitors_used) &= ~DDM1;

			if (AS(ddbsr).m1) {
				left = 1;
				pr_debug("event DDM1: left 0 (1)\n");
				AS(ddbsr).m1 = 0;
				E2K_SET_MMUREG(ddbsr, AW(ddbsr));
			} else {
				left = E2K_GET_MMUREG(ddmar1);
				left = -left;
				pr_debug("event DDM1: left %lld\n", left);
			}
		} else {
			__get_cpu_var(cpu_events)[2] = NULL;
			__get_cpu_var(monitors_spurious) |= DDM0;

			BUG_ON(!(__get_cpu_var(perf_monitors_used) & DDM0));
			__get_cpu_var(perf_monitors_used) &= ~DDM0;

			if (AS(ddbsr).m0) {
				left = 1;
				pr_debug("event DDM0: left 0 (1)\n");
				AS(ddbsr).m0 = 0;
				E2K_SET_MMUREG(ddbsr, AW(ddbsr));
			} else {
				left = E2K_GET_MMUREG(ddmar0);
				left = -left;
				pr_debug("event DDM0: left %lld\n", left);
			}
		}
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

	switch (monitor) {
	case DIM0:
		AW(dibsr) = E2K_GET_SREG(dibsr);
		if (AS(dibsr).m0) {
			left = 0;
		} else {
			left = E2K_GET_DSREG(dimar0);
			left = -left;
		}
		pr_debug("reading DIM0: left %lld (dibsr %d)\n",
				left, AS(dibsr).m0);
		break;
	case DIM1:
		AW(dibsr) = E2K_GET_SREG(dibsr);
		if (AS(dibsr).m1) {
			left = 0;
		} else {
			left = E2K_GET_DSREG(dimar1);
			left = -left;
		}
		pr_debug("reading DIM1: left %lld (dibsr %d)\n",
				left, AS(dibsr).m1);
		break;
	case DDM0:
		AW(ddbsr) = E2K_GET_MMUREG(ddbsr);
		if (AS(ddbsr).m0) {
			left = 0;
		} else {
			left = E2K_GET_MMUREG(ddmar0);
			left = -left;
		}
		pr_debug("reading DDM0: left %lld (ddbsr %d)\n",
				left, AS(ddbsr).m0);
		break;
	case DDM1:
		AW(ddbsr) = E2K_GET_MMUREG(ddbsr);
		if (AS(ddbsr).m1) {
			left = 0;
		} else {
			left = E2K_GET_MMUREG(ddmar1);
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
			"sample_period %lld, left %lld\n",
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
			"sample_period %lld, count %lld (+%lld)\n"
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

	left = monitor_pause(hwc, flags & PERF_EF_UPDATE);

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

	pr_debug("event %lx: resuming %llx:%02llx\n",
			event, (hwc->config & 0xff00) >> 8, hwc->config & 0xff);

	if (flags & PERF_EF_RELOAD) {
		left = local64_read(&hwc->period_left);

		local64_set(&hwc->prev_count, (u64) -left);

		pr_debug("event %lx: new period %lld\n", event, left);
	}

	monitor_resume(hwc, flags & PERF_EF_RELOAD, left);
}


static u8 hardware_events_map[PERF_COUNT_HW_MAX][2] = {
	/* PERF_COUNT_HW_CPU_CYCLES */
	{0, 0},
	/* PERF_COUNT_HW_INSTRUCTIONS */
	{DIM0_DIM1, 0x14},
	/* PERF_COUNT_HW_CACHE_REFERENCES */
	{DDM0, 0x0},
	/* PERF_COUNT_HW_CACHE_MISSES */
	{0, 0},
	/* PERF_COUNT_HW_BRANCH_INSTRUCTIONS */
	{0, 0},
	/* PERF_COUNT_HW_BRANCH_MISSES */
	{0, 0},
	/* PERF_COUNT_HW_BUS_CYCLES */
	{0, 0}
};

static int init_perf_events_map()
{
	if (machine.iset_ver >= E2K_ISET_V2) {
		hardware_events_map[PERF_COUNT_HW_CPU_CYCLES][0] = DIM0_DIM1;
		hardware_events_map[PERF_COUNT_HW_CPU_CYCLES][1] = 0x72;
	}

	return 0;
}
pure_initcall(init_perf_events_map);

static u8 hw_cache_events_map[PERF_COUNT_HW_CACHE_MAX][PERF_COUNT_HW_CACHE_OP_MAX][PERF_COUNT_HW_CACHE_RESULT_MAX][2] = {
	/* PERF_COUNT_HW_CACHE_L1D */
	[0] = {
		/* PERF_COUNT_HW_CACHE_OP_WRITE */
		[1] = {
			/* PERF_COUNT_HW_CACHE_RESULT_ACCESS */
			[0] = {DDM1, 0x1}
		}
	},
	/* PERF_COUNT_HW_CACHE_LL */
	[2] = {
		/* PERF_COUNT_HW_CACHE_OP_WRITE */
		[1] = {
			/* PERF_COUNT_HW_CACHE_RESULT_ACCESS */
			[0] = {DDM1, 0x41}
		}
	},
};

#define MAX_EVENTS 256
static char hw_raw_event_to_iset[MAX_HW_MONITORS][MAX_EVENTS] = {
	[_DDM0] = {
		[0x0 ... 0x3]	= E2K_ISET_SINCE_V1_MASK,
		[0x10 ... 0x14] = E2K_ISET_SINCE_V1_MASK,
		[0x20 ... 0x21] = E2K_ISET_SINCE_V1_MASK,
		[0x30 ... 0x36] = E2K_ISET_SINCE_V1_MASK,
		[0x40 ... 0x46] = E2K_ISET_SINCE_V1_MASK,
		[0x48]		= E2K_ISET_SINCE_V1_MASK,

		[0x15 ... 0x16] = E2K_ISET_SINCE_V2_MASK,
		[0x37 ... 0x3a] = E2K_ISET_SINCE_V2_MASK,
		[0x4a ... 0x4b] = E2K_ISET_SINCE_V2_MASK,
		[0x70 ... 0x72] = E2K_ISET_SINCE_V2_MASK,

		[0x17 ... 0x19] = E2K_ISET_SINCE_V3_MASK,
		[0x22 ... 0x24] = E2K_ISET_SINCE_V3_MASK,

		[0x49]		= E2K_ISET_V2_MASK,
		[0x4c ... 0x4f] = E2K_ISET_V2_MASK,
	},
	[_DDM1] = {
		[0x0 ... 0x2]	= E2K_ISET_SINCE_V1_MASK,
		[0x10 ... 0x15] = E2K_ISET_SINCE_V1_MASK,
		[0x20 ... 0x21] = E2K_ISET_SINCE_V1_MASK,
		[0x30 ... 0x37] = E2K_ISET_SINCE_V1_MASK,
		[0x40 ... 0x48] = E2K_ISET_SINCE_V1_MASK,

		[0x16]		= E2K_ISET_SINCE_V2_MASK,
		[0x38 ... 0x3a] = E2K_ISET_SINCE_V2_MASK,
		[0x4a ... 0x4b] = E2K_ISET_SINCE_V2_MASK,
		[0x70 ... 0x72] = E2K_ISET_SINCE_V2_MASK,

		[0x17 ... 0x19] = E2K_ISET_SINCE_V3_MASK,
		[0x22 ... 0x23] = E2K_ISET_SINCE_V3_MASK,

		[0x4c ... 0x4f] = E2K_ISET_V2_MASK,
	},
	[_DIM0] = {
		[0x0 ... 0x3]	= E2K_ISET_SINCE_V1_MASK,
		[0x7 ... 0xa]	= E2K_ISET_SINCE_V1_MASK,
		[0x10 ... 0x1e] = E2K_ISET_SINCE_V1_MASK,
		[0x20 ... 0x24] = E2K_ISET_SINCE_V1_MASK,
		[0x30 ... 0x3c] = E2K_ISET_SINCE_V1_MASK,
		[0x40 ... 0x4a] = E2K_ISET_SINCE_V1_MASK,
		[0x50 ... 0x5a] = E2K_ISET_SINCE_V1_MASK,
		[0x60 ... 0x67] = E2K_ISET_SINCE_V1_MASK,
		[0x70 ... 0x71] = E2K_ISET_SINCE_V1_MASK,

		[0x1f]		= E2K_ISET_SINCE_V2_MASK,
		[0x68 ... 0x69] = E2K_ISET_SINCE_V2_MASK,
		[0x70 ... 0x74] = E2K_ISET_SINCE_V2_MASK,

		[0xf]		= E2K_ISET_SINCE_V3_MASK,
		[0x25 ... 0x26] = E2K_ISET_SINCE_V3_MASK,
		[0x3d]		= E2K_ISET_SINCE_V3_MASK,

		[0x4 ... 0x6]	= E2K_ISET_V1_MASK | E2K_ISET_V2_MASK,
		[0x25 ... 0x26] = E2K_ISET_SINCE_V1_MASK,
	},
	[_DIM1] = {
		/* Almost same as _DIM0 - only 0x25/0x26 events differ */
		[0x0 ... 0x3]	= E2K_ISET_SINCE_V1_MASK,
		[0x7 ... 0xa]	= E2K_ISET_SINCE_V1_MASK,
		[0x10 ... 0x1e] = E2K_ISET_SINCE_V1_MASK,
		[0x20 ... 0x24] = E2K_ISET_SINCE_V1_MASK,
		[0x30 ... 0x3c] = E2K_ISET_SINCE_V1_MASK,
		[0x40 ... 0x4a] = E2K_ISET_SINCE_V1_MASK,
		[0x50 ... 0x5a] = E2K_ISET_SINCE_V1_MASK,
		[0x60 ... 0x67] = E2K_ISET_SINCE_V1_MASK,
		[0x70 ... 0x71] = E2K_ISET_SINCE_V1_MASK,

		[0x1f]		= E2K_ISET_SINCE_V2_MASK,
		[0x68 ... 0x69] = E2K_ISET_SINCE_V2_MASK,
		[0x70 ... 0x74] = E2K_ISET_SINCE_V2_MASK,

		[0xf]		= E2K_ISET_SINCE_V3_MASK,
		[0x25 ... 0x26] = E2K_ISET_SINCE_V3_MASK,
		[0x3d]		= E2K_ISET_SINCE_V3_MASK,

		[0x4 ... 0x6]	= E2K_ISET_V1_MASK | E2K_ISET_V2_MASK,
	},
};

static int event_attr_to_monitor_and_id(struct perf_event_attr *attr,
		u8 *monitor, u8 *event_id)
{
	switch (attr->type) {
	case PERF_TYPE_RAW:
		*monitor = (attr->config & 0xff00) >> 8;
		*event_id = attr->config & 0xff;

		if (*monitor >= MAX_HW_MONITORS)
			return -EINVAL;

		if (0 == (hw_raw_event_to_iset[*monitor][*event_id] &
				(1 << machine.iset_ver)))
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

		*monitor = hw_cache_events_map[type][op][result][0];
		*event_id = hw_cache_events_map[type][op][result][1];
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

static DEFINE_MUTEX(reserve_mutex);

int e2k_pmu_event_init(struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;
	int err;
	u8 monitor, event_id;
	u8 group_monitors_used = 0;

	/*
	 * Protect against concurrent group editing
	 */
	mutex_lock(&reserve_mutex);

	err = event_attr_to_monitor_and_id(&event->attr, &monitor, &event_id);
	if (err)
		goto out_unlock;

	/*
	 * Check that the event fits into the group.
	 */
	if (event->group_leader != event) {
		struct perf_event *sibling;

		list_for_each_entry(sibling, &event->group_leader->sibling_list,
				group_entry) {
			if (event->attr.type != PERF_TYPE_RAW
					&& event->attr.type !=
						PERF_TYPE_HARDWARE
					&& event->attr.type !=
						PERF_TYPE_HW_CACHE)
				continue;

			group_monitors_used |=
					(sibling->hw.config & 0xff00) >> 8;
		}
	}

	if (monitor & DIM0_DIM1) {
		if (group_monitors_used & (DIM1 | DIM0_DIM1))
			monitor = DIM0;
		else if (group_monitors_used & DIM0)
			monitor = DIM1;
	}

	if (group_monitors_used & monitor) {
		err = -ENOSPC;
		goto out_unlock;
	}

	mutex_unlock(&reserve_mutex);

	/*
	 * Good, this event will fit. Save configuration.
	 */
	hwc->config = (monitor << 8) | event_id;
	hwc->idx = (monitor == DIM0 || monitor == DDM0) ? 0 : 1;

	hwc->config |= ARCH_PERFMON_ENABLED;

	if (!event->attr.exclude_user)
		hwc->config |= ARCH_PERFMON_USR;
	/* On old processors kernel profiling does not work
	 * since debug interrupts can not be masked. */
	if (!event->attr.exclude_kernel && machine.iset_ver > E2K_ISET_V1)
		hwc->config |= ARCH_PERFMON_OS;

	pr_debug("perf event %lld initialized with config %hhx:%hhx\n",
			event->id, monitor, event_id);

	return 0;

out_unlock:
	mutex_unlock(&reserve_mutex);

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
	 * possible to get interrupt _after_ monitor was disabled.
	 * Such interrupt will be discarded as spurious.
	 */
	raw_all_irq_save(flags);

	count = __get_cpu_var(hw_perf_disable_count)++;
	if (!count)
		__get_cpu_var(saved_flags) = flags;
}

static void e2k_pmu_enable(struct pmu *pmu)
{
	int count;

	count = --__get_cpu_var(hw_perf_disable_count);

	if (!count) {
		unsigned long flags = __get_cpu_var(saved_flags);

		preempt_disable();

		/* Enable NMIs to get all interrupts that might
		 * have arrived while we were disabling perf */
		raw_all_irq_restore(flags);

		/* After the handling of interrupts we can clear this */
		__get_cpu_var(monitors_spurious) = 0;

		preempt_enable();

		BUG_ON(raw_nmi_irqs_disabled_flags(flags));
	}
}


/* Performance monitoring unit for e2k */
static struct pmu e2k_pmu = {
	.pmu_enable	= e2k_pmu_enable,
	.pmu_disable	= e2k_pmu_disable,
	.add		= e2k_pmu_add,
	.del		= e2k_pmu_del,
	.start		= e2k_pmu_start,
	.stop		= e2k_pmu_stop,
	.read		= e2k_pmu_read,
	.event_init	= e2k_pmu_event_init
};


static int __init init_hw_perf_events(void)
{
	return perf_pmu_register(&e2k_pmu, "cpu", PERF_TYPE_RAW);
}
early_initcall(init_hw_perf_events);

