/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * IOHUB system timer/watchdog/reset/power emulation.
 * Based on e2k lms simulator.
 */

#include <linux/kvm_host.h>
#include <linux/slab.h>
#include <linux/math64.h>
#include <linux/pci.h>
#include <asm/kvm/runstate.h>
#include <asm/e2k_debug.h>
#include <asm/sclkr.h>  /* get  redpill value*/

#include "ioepic.h"
#include "irq.h"
#include "lt.h"

#define mod_64(x, y) ((x) % (y))

#define PRId64 "d"
#define PRIx64 "llx"
#define PRIu64 "u"
#define PRIo64 "o"

#undef	DEBUG_COUNT_MODE
#undef	DebugCOUNT
#define	DEBUG_COUNT_MODE	0	/* counter updates debugging */
#if DEBUG_COUNT_MODE
#define	DebugCOUNT(fmt, args...)					\
		pr_info("%s(): " fmt, __func__, ##args);
#else
#define	DebugCOUNT(fmt, args...)
#endif

#undef	DEBUG_VERBOSE_COUNT_MODE
#undef	DebugVCOUNT
#define	DEBUG_VERBOSE_COUNT_MODE	0	/* counter updates verbose */
						/* debugging */
#define	DebugVCOUNT(fmt, args...)					\
({									\
	if (DEBUG_VERBOSE_COUNT_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_SYS_TIMER_MODE
#undef	DebugSYSTM
#define	DEBUG_SYS_TIMER_MODE	0	/* system timer debugging */
#define	DebugSYSTM(fmt, args...)					\
({									\
	if (DEBUG_SYS_TIMER_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_IRQ_MODE
#undef	DebugIRQ
#define	DEBUG_IRQ_MODE		0	/* IRQs debugging */
#define	DebugIRQ(fmt, args...)						\
({									\
	if (DEBUG_IRQ_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_HR_TIMER_MODE
#undef	DebugHRTM
#define	DEBUG_HR_TIMER_MODE	0	/* high resolution timer debugging */
#define	DebugHRTM(fmt, args...)					\
({									\
	if (DEBUG_HR_TIMER_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_LT_REGS_MODE
#undef	DebugLTREGS
#define	DEBUG_LT_REGS_MODE	0	/* system timer debugging */
#if	DEBUG_LT_REGS_MODE
#define	lt_reg_debug(fmt, arg...)	pr_err("%s() : " fmt, __func__, ##arg)
#else
#define	lt_reg_debug(fmt, arg...)
#endif	/* DEBUG_LT_REGS_MODE */

static bool wd_debug = false;
#undef	DEBUG_WD_REGS_MODE
#undef	DebugWD
#define	DEBUG_WD_REGS_MODE	(false && wd_debug)	/* watchdog timer */
							/* debugging */
#define	DebugWD(fmt, args...)						\
({									\
	if (DEBUG_WD_REGS_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_MMIO_SHUTDOWN_MODE
#undef	DebugMMIOSHUTDOWN
#define	DEBUG_MMIO_SHUTDOWN_MODE	0	/* MMIO shutdown debugging */
#define	DebugMMIOSHUTDOWN(fmt, args...)					\
({									\
	if (DEBUG_MMIO_SHUTDOWN_MODE || kvm_debug)			\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#define	HRTIMER_EXPIRES_PERCENT		90	/* percents */
/* If hrtimer expires on HRTIMER_EXPIRES_PERCENTs it does not reactivate */
#define	HRTIMER_EXPIRES_APPROX(time)	\
		(((time) / 100) * HRTIMER_EXPIRES_PERCENT)

/*
 * Bug 129924: sometimes guest doesn't make it in time to ack watchdog interrupt, and reboots.
 * Since lintel is currently the only user of watchdog, and it doesn't expect reboot, disable it.
 * Send another normal interrupt instead.
 */
#define	ENABLE_WATCHDOG_RESET	0

static inline struct kvm_lt *to_lt(struct kvm_io_device *dev)
{
	return container_of(dev, struct kvm_lt, dev);
}

static inline struct kvm_lt *sys_timer_to_lt(struct kvm_timer *timer)
{
	return container_of(timer, struct kvm_lt, sys_timer);
}

static inline struct kvm_lt *wd_timer_to_lt(struct kvm_timer *timer)
{
	return container_of(timer, struct kvm_lt, wd_timer);
}

static inline u64 cycles_to_count(struct kvm_lt *lt, u64 cycles)
{
	return mul_u64_u32_div(cycles, lt->frequency, lt->ticks_per_sec);
}

static inline u64 count_to_cycles(struct kvm_lt *lt, u64 counter)
{
	return mul_u64_u32_div(counter, lt->ticks_per_sec, lt->frequency);
}

static int lt_get_sys_timer_limits(struct kvm_lt *lt, u64 *limitp, u64 *startp)
{
	u32 start, limit;

	if (lt->regs.counter_limit.c_l != 0) {
		if (lt->regs.counter_control.s_s) {
			limit = lt->regs.counter_limit.c_l;
			start = MIN_SYS_TIMER_COUNT;
		} else {
			limit = MAX_SYS_TIMER_COUNT;
			if (lt->regs.counter_start.c_st_v != 0) {
				start = lt->regs.counter_start.c_st_v;
			} else {
				start = MIN_SYS_TIMER_COUNT;
			}
		}
	} else {
		limit = MAX_SYS_TIMER_COUNT;
		if (lt->regs.counter_start.c_st_v != 0) {
			start = lt->regs.counter_start.c_st_v;
		} else {
			start = MIN_SYS_TIMER_COUNT;
		}
	}
	ASSERT(limit > start);
	*limitp = limit;
	*startp = start;
	return 0;
}

static int lt_get_wd_timer_limits(struct kvm_lt *lt, u64 *limitp, u64 *startp)
{
	u64 limit;
	u32 start;

	if (lt->regs.wd_limit.wd_l == 0) {
		/* wd timer is OFF */
		start = 0;
		limit = -1ULL;
	} else {
		start = 0;
		limit = lt->regs.wd_limit.wd_l;
	}
	*limitp = limit;
	*startp = start;
	return 0;
}

static int lt_get_reset_counter_limits(struct kvm_lt *lt, u64 *limitp,
					u64 *startp)
{
	*limitp = -1ULL;
	*startp = 0;
	return 0;
}

static int lt_get_power_counter_limits(struct kvm_lt *lt, u64 *limitp,
					u64 *startp)
{
	*limitp = -1ULL;
	*startp = 0;
	return 0;
}

static int lt_get_timer_limits(struct kvm_lt *lt, struct kvm_timer *timer,
				u64 *limitp, u64 *startp)
{
	switch (timer->type) {
	case kvm_sys_timer_type:
		return lt_get_sys_timer_limits(lt, limitp, startp);
	case kvm_wd_timer_type:
		return lt_get_wd_timer_limits(lt, limitp, startp);
	case kvm_reset_timer_type:
		return lt_get_reset_counter_limits(lt, limitp, startp);
	case kvm_power_timer_type:
		return lt_get_power_counter_limits(lt, limitp, startp);
	default:
		pr_err("%s() : %d is unsupported or invalid timer type\n",
			__func__, timer->type);
		return -EINVAL;
	}
}

static u64 kvm_get_up_to_date_timer(struct kvm_vcpu *vcpu, struct kvm_lt *lt,
					struct kvm_timer *timer)
{
	u64 running_time;
	s64 running_cycles;
	s64 running_ns, host_ns;
	s64 cycles, host_cycles;
	ktime_t now;
	u64 now_ns;
	u64 counter, host_counter;
	u64 start64, limit64;
	u32 start, limit, start_count, new_count;
	u64 prescaler;
	int miss_times;
	unsigned long flags;
	struct kvm_arch *ka = &vcpu->kvm->arch;

	ASSERT(timer != NULL);
	ASSERT(vcpu != NULL);

	raw_spin_lock_irqsave(&timer->lock, flags);

	if (unlikely(timer->period == 0)) {
		raw_spin_unlock_irqrestore(&timer->lock, flags);
		return 0;
	}
	start_count = timer->start_count;
	running_time = kvm_do_get_guest_vcpu_running_time(vcpu);
	cycles = get_cycles();
	now = timer->timer.base->get_time();
	now_ns = ktime_to_ns(now);
	/* sh_sclkm3 - summary time when each vcpu of guest was out of cpu */
	if (!redpill)
		now_ns -= ka->sh_sclkm3;
	DebugVCOUNT("%s : running cycles at start 0x%llx, now 0x%llx, "
		"current cycles 0x%llx, start counter 0x%x period ns 0x%llx\n",
		timer->name, timer->running_time, running_time,
		cycles, start_count, timer->period);
	DebugVCOUNT("%s : host start time at nsec 0x%llx, now 0x%llx\n",
		timer->name, timer->host_start_ns, now_ns);

	running_cycles = running_time - timer->running_time;
	if (running_cycles < 0) {
		/* BUG(); probably it starts on or migrate to other VCPU/CPU */
		running_cycles = 0;
	}
	running_ns = cycles_2nsec(running_cycles);
	host_ns = now_ns - timer->host_start_ns;
	if (host_ns < 0) {
		/* BUG(); probably it starts on or migrate to other CPU */
		host_ns = 0;
	}
	host_cycles = nsecs_2cycles(host_ns);
	DebugVCOUNT("%s : current running cycles 0x%llx ns 0x%llx\n",
		timer->name, running_cycles, running_ns);
	DebugVCOUNT("%s : host    running cycles 0x%llx ns 0x%llx\n",
		timer->name, host_cycles, host_ns);

	lt_get_timer_limits(lt, timer, &limit64, &start64);
	limit = limit64;
	start = start64;
	ASSERT(limit > start);

	if (timer->type == kvm_wd_timer_type)
		prescaler = lt->regs.wd_prescaler.wd_c + 1;
	else
		prescaler = 1;

	counter = cycles_to_count(lt, running_cycles) / prescaler + start_count;
	host_counter = cycles_to_count(lt, host_cycles) / prescaler +
		start_count;

	if (host_counter > limit) {
		miss_times = (host_counter - limit) / (limit - start);
		new_count = mod_64(host_counter - limit, limit - start);
		new_count += start;
	} else {
		miss_times = 0;
		new_count = host_counter;
	}

	/* update timer counter value */
	if (timer->type == kvm_sys_timer_type) {
		lt->regs.counter.c = new_count;
	} else if (timer->type == kvm_wd_timer_type) {
		lt->regs.wd_counter.wd_c = new_count;
	} else {
		pr_err("%s(): %d is unsupported or invalid timer type\n",
			__func__, timer->type);
	}
	timer->start_count = new_count;
	timer->host_start_ns = now_ns;
	timer->running_time = running_time;

	raw_spin_unlock_irqrestore(&timer->lock, flags);

	DebugCOUNT("%s : guest running cycles 0x%llx "
		"counter 0x%llx : %lld%%\n",
		timer->name, running_cycles, counter,
		(counter * 100) / host_counter);
	DebugCOUNT("%s : host  running cycles 0x%llx counter 0x%llx\n",
		timer->name, host_cycles, host_counter);
	if (miss_times > 0) {
		DebugHRTM("%s : host counter 0x%llx limit 0x%x start 0x%x "
			"miss times %d : new counter 0x%x\n",
			timer->name, host_counter, limit, start, miss_times,
			new_count);
	} else {
		DebugHRTM("%s : host counter 0x%llx limit 0x%x start 0x%x "
			"new counter 0x%x\n",
			timer->name, host_counter, limit, start,
			new_count);
	}

	return host_counter;
}
static u64 kvm_get_up_to_date_count(struct kvm_vcpu *vcpu, struct kvm_lt *lt,
					struct kvm_timer *timer)
{
	s64 host_ns, host_cycles;
	u64 host_counter;
	ktime_t now;
	u64 now_ns;
	u64 start, limit, new_count;
	struct kvm_arch *ka = &vcpu->kvm->arch;
#if DEBUG_COUNT_MODE
	s64 running_time, running_cycles, running_ns, cycles, counter;
	int miss_times = 0;
	unsigned long flags;

	ASSERT(timer != NULL);
	ASSERT(vcpu != NULL);
	raw_local_irq_save(flags);
	running_time = kvm_do_get_guest_vcpu_running_time(vcpu);
	cycles = get_cycles();
	now = ktime_get();
	raw_local_irq_restore(flags);
#else
	now = ktime_get();
#endif
	now_ns = ktime_to_ns(now);
	/* sh_sclkm3 - summary time when each vcpu of guest was out of cpu */
	if (!redpill)
		now_ns -= ka->sh_sclkm3;
	DebugCOUNT("%s : running cycles at start 0x%llx, now 0x%llx, "
		"current cycles 0x%llx\n",
		timer->name, timer->running_time, running_time, cycles);
	DebugCOUNT("%s : host start time at nsec 0x%llx, now 0x%llx\n",
		timer->name, timer->host_start_ns, now_ns);

	timer->vcpu = vcpu;
#if DEBUG_COUNT_MODE
	running_cycles = running_time - timer->running_time;
	ASSERT(running_cycles >= 0);
	running_ns = cycles_2nsec(running_cycles);
#endif
	host_ns = now_ns - timer->host_start_ns;
	if (redpill)
		ASSERT(host_ns >= 0);
	host_cycles = nsecs_2cycles(host_ns);
	DebugCOUNT("%s : current running cycles 0x%llx ns 0x%llx\n",
		timer->name, running_cycles, running_ns);
	DebugCOUNT("%s : host    running cycles 0x%llx ns 0x%llx\n",
		timer->name, host_cycles, host_ns);

	lt_get_timer_limits(lt, timer, &limit, &start);
#if DEBUG_COUNT_MODE
	ASSERT(limit > start);

	counter = cycles_to_count(lt, running_cycles);
#endif
	host_counter = cycles_to_count(lt, host_cycles);
	DebugCOUNT("%s : host  cycles 0x%llx counter 0x%llx\n",
		timer->name, host_cycles, host_counter);
	DebugCOUNT("%s : guest cycles 0x%llx counter 0x%llx : %lld%%\n",
		timer->name, running_cycles, counter,
		(counter * 100) / host_counter);

	if (host_counter > limit) {
#if DEBUG_COUNT_MODE
		miss_times = (host_counter - limit) / ((limit + 1) - start);
#endif
		new_count = mod_64(host_counter - limit, (limit + 1) - start);
	} else {
		new_count = host_counter;
	}

	/* update counter value */
	if (timer->type == kvm_reset_timer_type) {
		lt->regs.reset_counter_lo.rs_c = new_count & 0xffffffff;
		lt->regs.reset_counter_hi.rs_c = (new_count >> 32) & 0xffffffff;
	} else if (timer->type == kvm_power_timer_type) {
		lt->regs.power_counter_lo.pw_c = new_count & 0xffffffff;
		lt->regs.power_counter_hi.pw_c = (new_count >> 32) & 0xffffffff;
	} else {
		pr_err("%s(): %d is unsupported or invalid timer type\n",
			__func__, timer->type);
	}

#if DEBUG_COUNT_MODE
	if (miss_times > 0) {
		DebugHRTM("%s : host counter 0x%llx limit 0x%llx start 0x%llx "
			"miss times %d : new counter 0x%llx\n",
			timer->name, host_counter, limit, start, miss_times,
			new_count);
	} else {
		DebugVCOUNT("%s : host counter 0x%llx limit 0x%llx "
			"start 0x%llx new counter 0x%llx\n",
			timer->name, host_counter, limit, start, new_count);
	}
#endif

	return host_counter;
}

static inline bool lt_in_range(struct kvm_lt *lt, gpa_t addr)
{
	return ((addr >= lt->base_address &&
		 (addr < lt->base_address + LT_MMIO_LENGTH)));
}
static inline u32 lt_get_reg(struct kvm_lt *lt, int reg_off)
{
	lt_reg_debug("%02x : %08x from %px\n",
		reg_off, *((u32 *) ((void *)(&lt->regs) + reg_off)),
		((u32 *) ((void *)(&lt->regs) + reg_off)));
	return *((u32 *) ((void *)(&lt->regs) + reg_off));
}

static inline void lt_set_reg(struct kvm_lt *lt, int reg_off, u32 val)
{
	*((u32 *) ((void *)(&lt->regs) + reg_off)) = val;
	lt_reg_debug("%02x : %08x to %px\n",
		reg_off, *((u32 *) ((void *)(&lt->regs) + reg_off)),
		((u32 *) ((void *)(&lt->regs) + reg_off)));
}

static u32 update_counter_value(struct kvm_vcpu *vcpu, struct kvm_lt *lt)
{
	kvm_get_up_to_date_timer(vcpu, lt, &lt->sys_timer);
	return lt->regs.counter.reg;
}

static u32 update_wd_counter_value(struct kvm_vcpu *vcpu, struct kvm_lt *lt)
{
	u64 new_counter;

	new_counter = kvm_get_up_to_date_timer(vcpu, lt, &lt->wd_timer);
	if (lt->regs.wd_limit.wd_l == 0) {
		/* wd timer is not started */
	} else if (!lt->wd_timer.hrtimer_started) {
		/* it need update event bit state */
		ASSERT(!(lt->regs.wd_control.w_out_e));

		if (new_counter >= lt->regs.wd_limit.wd_l) {
			lt->regs.wd_control.w_evn = 1;
		}
	}
	return lt->regs.wd_counter.reg;
}

static u64 update_reset_counter_value(struct kvm_vcpu *vcpu, struct kvm_lt *lt)
{
	u64 counter;

	counter = kvm_get_up_to_date_count(vcpu, lt, &lt->reset_count);
	return counter;
}

static u64 update_power_counter_value(struct kvm_vcpu *vcpu, struct kvm_lt *lt)
{
	u64 counter;

	counter = kvm_get_up_to_date_count(vcpu, lt, &lt->power_count);
	return counter;
}

static void start_lt_timer(struct kvm_vcpu *vcpu, struct kvm_lt *lt,
				struct kvm_timer *lt_timer,
				u32 start_count, u64 cycles_period,
				bool start_hrtimer)
{
	ktime_t now;
	u64 ns_period;

	ns_period = cycles_2nsec(cycles_period);

	if (ns_period == 0) {
		lt_timer->period = 0;
		return;
	}

	/*
	 * Do not allow the guest to program periodic timers with small
	 * interval, since the hrtimers are not throttled by the host
	 * scheduler.
	 */
	if (ns_period < NSEC_PER_MSEC / 2) {
		ns_period = NSEC_PER_MSEC / 2;
	}

	ASSERT(!hrtimer_active(&lt_timer->timer));

	lt_timer->vcpu = vcpu;
	lt_timer->start_count = start_count;
	lt_timer->period = ns_period;
	now = lt_timer->timer.base->get_time();
	lt_timer->host_start_ns = ktime_to_ns(now);
	lt_timer->running_time =
		kvm_get_guest_vcpu_running_time(vcpu);
	if (start_hrtimer) {
		hrtimer_start(&lt_timer->timer,
				ktime_add_ns(now, ns_period),
				HRTIMER_MODE_ABS);
		lt_timer->hrtimer_started = true;
	} else {
		lt_timer->hrtimer_started = false;
	}
	DebugSYSTM("%s hrtimer is %s at host ns 0x%llx start count 0x%x, "
		"period 0x%llx\n",
		lt_timer->name,
		(lt_timer->hrtimer_started) ? "started" : "not started",
		lt_timer->host_start_ns, start_count, ns_period);
	DebugSYSTM("%s        running time cycles 0x%llx\n",
		lt_timer->name, lt_timer->running_time);

	DebugSYSTM("%s freq is %" PRId64 "Mhz, now 0x%016" PRIx64 ", "
		"timer period cycles 0x%" PRIx64 ", nsec %lldns, "
		"expire @ 0x%016" PRIx64 ".\n",
		lt_timer->name, lt->frequency, ktime_to_ns(now),
		cycles_period, lt_timer->period,
		ktime_to_ns(ktime_add_ns(now, lt_timer->period)));
}

static void restart_sys_timer(struct kvm_vcpu *vcpu, struct kvm_lt *lt,
				u32 start_count)
{
	u64 limit;
	u64 increments, cycles_increments;

	hrtimer_cancel(&lt->sys_timer.timer);
	kthread_flush_work(&lt->sys_timer.expired);
	DebugSYSTM("COUNTER hrtimer canceled at now 0x%llx\n",
		ktime_to_ns(ktime_get()));

	lt->regs.counter.c = start_count;

	if (!lt->regs.counter_control.s_s) {
		/* timer is not started */
		return;
	}

	limit = (start_count <= lt->regs.counter_limit.c_l) ?
			lt->regs.counter_limit.c_l : MAX_SYS_TIMER_COUNT;
	increments = limit - start_count;
	cycles_increments = count_to_cycles(lt, increments);
	DebugSYSTM("COUNTER from 0x%x to limit 0x%llx, increments: 0x%llx "
		"cycles 0x%llx\n",
		lt->regs.counter.c, limit, increments, cycles_increments);
	start_lt_timer(vcpu, lt, &lt->sys_timer,
			start_count, cycles_increments,
			true	/* start hrtimer */);
}

static void reset_sys_timer(struct kvm_vcpu *vcpu, struct kvm_lt *lt)
{
	lt->regs.counter.c = MIN_SYS_TIMER_COUNT;
}

static void restart_wd_timer(struct kvm_vcpu *vcpu, struct kvm_lt *lt)
{
	u32 limit;
	u64 increments, cycles_increments;

	hrtimer_cancel(&lt->wd_timer.timer);
	kthread_flush_work(&lt->wd_timer.expired);
	DebugSYSTM("COUNTER hrtimer canceled at now 0x%llx\n",
		ktime_to_ns(ktime_get()));
	if (lt->regs.wd_limit.wd_l == 0) {
		/* wd timer is not started */
		DebugWD("WD_COUNTER is not started\n");
		return;
	}
	limit = lt->regs.wd_limit.wd_l;
	ASSERT(lt->regs.wd_counter.wd_c == 0 && limit > 0);
	increments = limit;
	increments *= (lt->regs.wd_prescaler.wd_c + 1);
	cycles_increments = count_to_cycles(lt, increments);
	DebugWD("WD_COUNTER from 0x%x to limit 0x%x, increments: 0x%llx "
		"* prescaler 0x%x cycles 0x%llx w_out_e %d\n",
		lt->regs.wd_counter.wd_c, limit, increments,
		lt->regs.wd_prescaler.wd_c + 1, cycles_increments,
		lt->regs.wd_control.w_out_e);
	start_lt_timer(vcpu, lt, &lt->wd_timer, 0, cycles_increments,
			!!(lt->regs.wd_control.w_out_e));
}

static void generate_interrupt(struct kvm *kvm, lt_irq_map_t irq_id,
				bool active)
{
	DebugIRQ("IRQ #%d level is %d\n", irq_id, active);
	kvm_set_irq(kvm, irq_id, irq_id, active, false);
}

static void generate_and_reset_interrupt(struct kvm *kvm, lt_irq_map_t irq_id)
{
	generate_interrupt(kvm, irq_id, true);
	generate_interrupt(kvm, irq_id, false);
}

static void generate_watchdog_reset(struct kvm_vcpu *vcpu, struct kvm_lt *lt)
{
	if (ENABLE_WATCHDOG_RESET) {
		lt->regs.wd_control.w_evn = 0;
		vcpu->arch.exit_shutdown_terminate = KVM_EXIT_E2K_RESTART;
		DebugMMIOSHUTDOWN("%s(): rebooting guest\n", __func__);
	} else {
		generate_and_reset_interrupt(vcpu->kvm, lt->wd_timer_irq_id);
	}
}

static int lt_mmio_read_64(struct kvm_vcpu *vcpu, struct kvm_lt *lt,
				unsigned int offset, void *data)
{
	u64 result;
	const char *reg_name = "???";

	mutex_lock(&lt->lock);
	switch (offset) {
	case RESET_COUNTER:
		result = update_reset_counter_value(vcpu, lt);
		reg_name = "Reset Counter";
		break;
	case POWER_COUNTER:
		result = update_power_counter_value(vcpu, lt);
		reg_name = "Power Counter";
		break;
	default:
		pr_err("%s() : invalid system timer register offset 0x%x\n",
			__func__, offset);
		result = 0xffffffffffffffffULL;
		break;
	}
	mutex_unlock(&lt->lock);

	*(u64 *)data = result;

	lt_reg_debug("%s data 0x%llx\n", reg_name, *(u64 *)data);

	return 0;
}

static int lt_mmio_read(struct kvm_vcpu *vcpu, struct kvm_io_device *this,
				gpa_t address, int len, void *data)
{
	struct kvm_lt *lt = to_lt(this);
	unsigned int offset = address - lt->base_address;
	u32 result;
	const char *reg_name = "???";

	lt_reg_debug("address 0x%llx, offset %02x, len %d to %px\n",
		address, offset, len, data);

	if (!lt_in_range(lt, address))
		return -EOPNOTSUPP;

	if (len == 8) {
		/* 8 bytes access */
		return lt_mmio_read_64(vcpu, lt, offset, data);
	}

	ASSERT(len == 4); /* 4 bytes access */

	mutex_lock(&lt->lock);
	switch (offset) {
	case COUNTER_LIMIT:
		result = lt->regs.counter_limit.reg;
		if (lt->regs.counter_control.s_s ||
					!lt->regs.counter_control.inv_l) {
			/* counter started or should not invert */
			lt->regs.counter_limit.l = 0;
			lt->regs.counter_start.l = 0;
			lt->regs.counter.l = 0;
		}
		reg_name = "Counter Limit";
		break;
	case COUNTER_START_VALUE:
		result = lt->regs.counter_start.reg;
		reg_name = "Counter Start Value";
		break;
	case COUNTER:
		result = update_counter_value(vcpu, lt);
		reg_name = "Counter";
		break;
	case COUNTER_CONTROL:
		result = lt->regs.counter_control.reg;
		reg_name = "Counter Control";
		break;
	case WD_COUNTER:
		result = update_wd_counter_value(vcpu, lt);
		reg_name = "WD Counter";
		wd_debug = true;
		break;
	case WD_PRESCALER:
		result = lt->regs.wd_prescaler.reg;
		reg_name = "WD Prescaler";
		wd_debug = true;
		break;
	case WD_LIMIT:
		result = lt->regs.wd_limit.reg;
		reg_name = "WD Limit";
		wd_debug = true;
		break;
	case WD_CONTROL:
		update_wd_counter_value(vcpu, lt);
		result = lt->regs.wd_control.reg;
		reg_name = "WD Control";
		wd_debug = true;
		break;
	case RESET_COUNTER_L: {
		u64 full_count;
		full_count = update_reset_counter_value(vcpu, lt);
		result = full_count & 0xffffffffUL;
		lt->regs.latched_reset_counter =
				(full_count >> 32) & 0xffffffffUL;
		reg_name = "Reset Counter Lo";
		break;
	}
	case RESET_COUNTER_H:
		result = lt->regs.latched_reset_counter;
		reg_name = "Reset Counter Hi";
		break;
	case POWER_COUNTER_L: {
		u64 full_count;
		full_count = update_power_counter_value(vcpu, lt);
		result = full_count & 0xffffffffUL;
		lt->regs.latched_power_counter =
				(full_count >> 32) & 0xffffffffUL;
		reg_name = "Power Counter Lo";
		break;
	}
	case POWER_COUNTER_H:
		result = lt->regs.latched_power_counter;
		reg_name = "Power Counter Hi";
		break;
	default:
		pr_err("%s() : invalid system timer register offset 0x%x\n",
			__func__, offset);
		result = 0xffffffff;
		break;
	}
	mutex_unlock(&lt->lock);

	*(u32 *)data = result;

	lt_reg_debug("%s data 0x%x\n", reg_name, *(u32 *)data);

	return 0;
}

static int lt_mmio_write_64(struct kvm_vcpu *vcpu, struct kvm_lt *lt,
				unsigned int offset, const void *data)
{
	const char *reg_name = "???";

	mutex_lock(&lt->lock);
	switch (offset) {
	case RESET_COUNTER:
		/* nothing effect */
		reg_name = "Reset Counter";
		break;
	case POWER_COUNTER:
		/* nothing effect */
		reg_name = "Power Counter";
		break;
	default:
		pr_err("%s() : invalid system timer register offset 0x%x\n",
			__func__, offset);
		break;
	}
	mutex_unlock(&lt->lock);

	lt_reg_debug("%s data is not changed 0x%llx\n", reg_name, *(u64 *)data);

	return 0;
}

static int lt_mmio_write(struct kvm_vcpu *vcpu, struct kvm_io_device *this,
				gpa_t address, int len, const void *data)
{
	struct kvm_lt *lt = to_lt(this);
	unsigned int offset = address - lt->base_address;
	u32 val;
	const char *reg_name = "???";

	lt_reg_debug("address 0x%llx, offset %02x, len %d from %px\n",
		address, offset, len, data);

	if (!lt_in_range(lt, address))
		return -EOPNOTSUPP;

	if (len == 8) {
		/* 8 bytes access */
		return lt_mmio_write_64(vcpu, lt, offset, data);
	}

	ASSERT(len == 4); /* 4 bytes access */

	val = *(u32 *)data;

	mutex_lock(&lt->lock);
	switch (offset) {
	case COUNTER_LIMIT: {
		counter_limit_t limit;

		limit.reg = val;
		lt->regs.counter_limit.c_l = limit.c_l;
		if (lt->regs.counter_control.s_s ||
					!lt->regs.counter_control.inv_l) {
			/* counter started or should not invert */
			lt->regs.counter_limit.l = 0;
			lt->regs.counter_start.l = 0;
			lt->regs.counter.l = 0;
		}
		if (lt->regs.counter_control.s_s) {
			restart_sys_timer(vcpu, lt, MIN_SYS_TIMER_COUNT);
		}
		reg_name = "Counter Limit";
		break;
	}
	case COUNTER_START_VALUE: {
		counter_start_t start;

		start.reg = val;
		lt->regs.counter_start.c_st_v = start.c_st_v;
		if (!lt->regs.counter_control.s_s) {
			restart_sys_timer(vcpu, lt, start.c_st_v);
		}
		reg_name = "Counter Start Value";
		break;
	}
	case COUNTER:
		pr_err("%s(): register Counter cannot be written\n", __func__);
		reg_name = "Counter";
		break;
	case COUNTER_CONTROL: {
		counter_control_t control;
		u32 start;
		bool already_started;

		already_started = !!lt->regs.counter_control.s_s;
		control.reg = val;
		lt->regs.counter_control.s_s = control.s_s;
		lt->regs.counter_control.inv_l = control.inv_l;
		lt->regs.counter_control.l_ini = control.l_ini;
		if (!already_started && control.s_s) {
			if (control.inv_l) {
				lt->regs.counter_limit.l = control.l_ini;
				lt->regs.counter_start.l = control.l_ini;
				lt->regs.counter.l = control.l_ini;
			}
		}
		if (already_started ^ control.s_s) {
			start = lt->regs.counter_start.c_st_v;
		} else {
			start = MIN_SYS_TIMER_COUNT;
		}
		restart_sys_timer(vcpu, lt, start);
		if (lt->regs.counter.l) {
			generate_and_reset_interrupt(vcpu->kvm,
							lt->sys_timer_irq_id);
		}
		reg_name = "Counter Control";
		break;
	}
	case WD_COUNTER:
		lt->regs.wd_counter.wd_c = 0;	/* counter reset */
		wd_debug = true;
		restart_wd_timer(vcpu, lt);
		reg_name = "WD Counter";
		break;
	case WD_PRESCALER:
		lt->regs.wd_counter.wd_c = 0;	/* counter reset */
		lt->regs.wd_prescaler.reg =
			(val + 1) * vcpu->kvm->arch.wd_prescaler_mult - 1;
		wd_debug = true;
		restart_wd_timer(vcpu, lt);
		reg_name = "WD Prescaler";
		break;
	case WD_LIMIT:
		lt->regs.wd_counter.wd_c = 0;	/* counter reset */
		lt->regs.wd_limit.reg = val;
		wd_debug = true;
		restart_wd_timer(vcpu, lt);
		reg_name = "WD Limit";
		break;
	case WD_CONTROL: {
		wd_control_t control;
		bool was_oe = lt->regs.wd_control.w_out_e;

		control.reg = val;
		control.unused = 0;
		update_wd_counter_value(vcpu, lt);
		lt->regs.wd_control.w_out_e = control.w_out_e;
		lt->regs.wd_control.w_m = control.w_m;
		if (control.w_evn) {
			/* reset bit by writing 1 to bit */
			lt->regs.wd_control.w_evn = 0;
		}

		wd_debug = true;

		/* Check if timer already fired and event is waiting */
		if (!was_oe && control.w_out_e && lt->regs.wd_control.w_evn) {
			DebugWD("w_evn is set when enabling watchdog timer\n");
			if (!control.w_m) {
				generate_watchdog_reset(vcpu, lt);
			} else {
				generate_and_reset_interrupt(vcpu->kvm, lt->wd_timer_irq_id);
			}
		}

		/* Start/stop the timer after enabling/disabling w_out_e */
		if (was_oe != control.w_out_e) {
			DebugWD("%s watchdog timer\n", control.w_out_e ?
				"Enabling" : "Disabling");
			lt->regs.wd_counter.wd_c = 0;
			restart_wd_timer(vcpu, lt);
		}
		reg_name = "WD Control";
		break;
	}
	case RESET_COUNTER_L:
		/* nothing effect */
		reg_name = "Reset Counter Lo";
		break;
	case RESET_COUNTER_H:
		/* nothing effect */
		reg_name = "Reset Counter Hi";
		break;
	case POWER_COUNTER_L:
		/* nothing effect */
		reg_name = "Power Counter Lo";
		break;
	case POWER_COUNTER_H:
		/* nothing effect */
		reg_name = "Power Counter Hi";
		break;
	default:
		pr_err("%s() : invalid system timer register offset 0x%x\n",
			__func__, offset);
		break;
	}
	mutex_unlock(&lt->lock);

	lt_reg_debug("%s data 0x%x\n", reg_name, *(u32 *)data);
	if (wd_debug) {
		DebugWD("%s data 0x%x\n", reg_name, *(u32 *)data);
		if (offset == WD_CONTROL) {
			DebugWD("%s new state 0x%x\n",
				reg_name, lt->regs.wd_control.reg);
		}
		wd_debug = false;
	}

	return 0;
}

static void lt_sys_timer_do_work(struct kthread_work *work)
{
	struct kvm_timer *timer = container_of(work, struct kvm_timer, expired);
	struct kvm *kvm = timer->kvm;
	struct kvm_lt *lt = sys_timer_to_lt(timer);

	if (timer->work == kvm_set_reset_irq_timer_work) {
		generate_and_reset_interrupt(kvm, lt->sys_timer_irq_id);
	} else {
		pr_err("%s(): %d is unknown or unsupported timer "
			"expires work\n",
			__func__, timer->work);
	}
}

static void lt_wd_timer_do_work(struct kthread_work *work)
{
	struct kvm_timer *timer = container_of(work, struct kvm_timer, expired);
	struct kvm *kvm = timer->kvm;
	struct kvm_lt *lt = wd_timer_to_lt(timer);

	if (timer->work == kvm_set_reset_irq_timer_work) {
		generate_and_reset_interrupt(kvm, lt->wd_timer_irq_id);
	} else if (timer->work == kvm_watchdog_reset_timer_work) {
		generate_watchdog_reset(timer->vcpu, lt);
	} else {
		pr_err("%s(): %d is unknown or unsupported timer "
			"expires work\n",
			__func__, timer->work);
	}
}

static void do_lt_sys_timer(struct kvm_vcpu *vcpu, void *data)
{
	struct kvm_lt *lt = data;
	u64 counter;

	ASSERT(lt->regs.counter_control.s_s);

	counter = kvm_get_up_to_date_timer(vcpu, lt, &lt->sys_timer);

	if (lt->regs.counter_limit.c_l != 0) {
		if (counter < lt->regs.counter_limit.c_l) {
			DebugHRTM("counter 0x%llx did not reach 0x%x "
				"limit value",
				counter, lt->regs.counter_limit.c_l);
		}
	} else {
		if (counter < MAX_SYS_TIMER_COUNT) {
			DebugHRTM("counter 0x%llx did not reach 0x%x max value",
				counter, MAX_SYS_TIMER_COUNT);
		}
	}

	if (lt->regs.counter_control.inv_l) {
		lt->regs.counter_limit.l = !(lt->regs.counter_limit.l);
		lt->regs.counter_start.l = !(lt->regs.counter_start.l);
		lt->regs.counter.l = !(lt->regs.counter.l);
	} else {
		lt->regs.counter_limit.l = 1;
		lt->regs.counter_start.l = 1;
		lt->regs.counter.l = 1;
	}

	reset_sys_timer(vcpu, lt);

	if (lt->regs.counter.l) {
		lt->sys_timer.work = kvm_set_reset_irq_timer_work;
		kthread_queue_work(lt->sys_timer.worker,
					&lt->sys_timer.expired);
	}
}

static void do_lt_wd_timer(struct kvm_vcpu *vcpu, void *data)
{
	struct kvm_lt *lt = data;
	bool old_wd_event = lt->regs.wd_control.w_evn;
	u64 counter;

	counter = kvm_get_up_to_date_timer(vcpu, lt, &lt->wd_timer);

	if (lt->regs.wd_limit.wd_l != 0) {
		if (counter < lt->regs.wd_limit.wd_l) {
			DebugHRTM("wd counter 0x%llx did not reach 0x%x "
				"limit value",
				counter, lt->regs.wd_limit.wd_l);
		}
	}

	lt->regs.wd_counter.wd_c = 0;	/* counter reset */

	lt->regs.wd_control.w_evn = 1;
	if (lt->regs.wd_control.w_out_e) {
		if (!lt->regs.wd_control.w_m || old_wd_event) {
			lt->wd_timer.work = kvm_watchdog_reset_timer_work;
		} else {
			lt->wd_timer.work = kvm_set_reset_irq_timer_work;
		}
		kthread_queue_work(lt->wd_timer.worker,
					&lt->wd_timer.expired);
	}
}

enum hrtimer_restart lt_timer_fn(struct kvm_lt *lt, struct kvm_timer *ktimer)
{
	struct kvm_vcpu *vcpu;
	s64 period = ktimer->period;

	vcpu = ktimer->vcpu;
	if (!vcpu)
		return HRTIMER_NORESTART;

	DebugSYSTM("%s started on VCPU #%d\n", ktimer->name, vcpu->vcpu_id);

	ktimer->t_ops->timer_fn(vcpu, lt);

	if (ktimer->t_ops->is_periodic(ktimer)) {
		hrtimer_add_expires_ns(&ktimer->timer, period);
		DebugSYSTM("%s periodic timer restarted "
			"at host ns 0x%llx expires at 0x%llx\n",
			ktimer->name, ktimer->host_start_ns,
			hrtimer_get_expires_ns(&ktimer->timer));
		return HRTIMER_RESTART;
	}
	DebugSYSTM("%s handled\n", ktimer->name);
	return HRTIMER_NORESTART;
}

static enum hrtimer_restart lt_sys_timer_fn(struct hrtimer *data)
{
	struct kvm_lt *lt;
	struct kvm_timer *sys_timer;

	sys_timer = container_of(data, struct kvm_timer, timer);
	lt = sys_timer_to_lt(sys_timer);
	return lt_timer_fn(lt, sys_timer);
}

static enum hrtimer_restart lt_wd_timer_fn(struct hrtimer *data)
{
	struct kvm_lt *lt;
	struct kvm_timer *wd_timer;

	wd_timer = container_of(data, struct kvm_timer, timer);
	lt = wd_timer_to_lt(wd_timer);
	return lt_timer_fn(lt, wd_timer);
}

static bool lt_is_periodic(struct kvm_timer *ktimer)
{
	return true;	/* sys timer and dw timer are periodic */
}

void kvm_lt_reset(struct kvm_lt *lt)
{

	/* Stop the timer in case it's a reset to an active state */
	hrtimer_cancel(&lt->sys_timer.timer);
	kthread_flush_work(&lt->sys_timer.expired);
	hrtimer_cancel(&lt->wd_timer.timer);
	kthread_flush_work(&lt->wd_timer.expired);

	lt->base_address = 0;
	lt->sys_timer_irq_id = SYS_TIMER_IRQ_ID;
	lt->wd_timer_irq_id = WD_TIMER_IRQ_ID;

	/* registers state on reset */
	lt_set_reg(lt, COUNTER_CONTROL, 0);
	lt_set_reg(lt, WD_COUNTER, 0);
	lt_set_reg(lt, WD_PRESCALER, 0x00001000);
	lt_set_reg(lt, WD_LIMIT, 0x00002fb2);
	lt_set_reg(lt, WD_CONTROL, 0);
	lt_set_reg(lt, RESET_COUNTER_L, 0);
	lt_set_reg(lt, RESET_COUNTER_H, 0);
	lt_set_reg(lt, POWER_COUNTER_L, 0);
	lt_set_reg(lt, POWER_COUNTER_H, 0);
}

static const struct kvm_io_device_ops lt_mmio_ops = {
	.read	= lt_mmio_read,
	.write	= lt_mmio_write,
};

static const struct kvm_timer_ops lt_sys_timer_ops = {
	.is_periodic	= lt_is_periodic,
	.timer_fn	= do_lt_sys_timer,
};

static const struct kvm_timer_ops lt_wd_timer_ops = {
	.is_periodic	= lt_is_periodic,
	.timer_fn	= do_lt_wd_timer,
};

struct kvm_lt *kvm_create_lt(struct kvm *kvm, int node_id, u32 ticks_per_sec,
				u32 sys_timer_freq)
{
	struct kvm_lt *lt;
	pid_t pid_nr;

	ASSERT(kvm_get_lt(kvm, node_id) == NULL);

	lt = kzalloc(sizeof(struct kvm_lt), GFP_KERNEL);
	if (!lt)
		return NULL;

	mutex_init(&lt->lock);

	lt->kvm = kvm;
	lt->ticks_per_sec = ticks_per_sec;
	lt->frequency = sys_timer_freq;

	pid_nr = task_pid_nr(current);

	hrtimer_init(&lt->sys_timer.timer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS);
	lt->sys_timer.timer.function = lt_sys_timer_fn;
	lt->sys_timer.name = "sys timer";
	lt->sys_timer.type = kvm_sys_timer_type;
	lt->sys_timer.t_ops = &lt_sys_timer_ops;
	raw_spin_lock_init(&lt->sys_timer.lock);
	lt->sys_timer.worker = kthread_create_worker(0, "kvm-sys-timer/%d/%d",
							pid_nr, node_id);
	if (IS_ERR(lt->sys_timer.worker))
		goto fail_sys_timer;
	kthread_init_work(&lt->sys_timer.expired, lt_sys_timer_do_work);
	lt->sys_timer.kvm = kvm;

	hrtimer_init(&lt->wd_timer.timer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS);
	lt->wd_timer.timer.function = lt_wd_timer_fn;
	lt->wd_timer.name = "wd timer";
	lt->wd_timer.type = kvm_wd_timer_type;
	lt->wd_timer.t_ops = &lt_wd_timer_ops;
	raw_spin_lock_init(&lt->wd_timer.lock);
	lt->wd_timer.worker = kthread_create_worker(0, "kvm-wd-timer/%d/%d",
							pid_nr, node_id);
	if (IS_ERR(lt->wd_timer.worker))
		goto fail_wd_timer;
	kthread_init_work(&lt->wd_timer.expired, lt_wd_timer_do_work);
	lt->wd_timer.kvm = kvm;

	lt->reset_count.name = "reset counter";
	lt->reset_count.type = kvm_reset_timer_type;
	lt->reset_count.running_time = 0;	/* from reset */

	lt->power_count.name = "power counter";
	lt->power_count.type = kvm_power_timer_type;
	lt->power_count.running_time = 0;	/* from power */

	kvm_lt_reset(lt);

	kvm_set_lt(kvm, node_id, lt);

	return lt;

fail_wd_timer:
	kthread_destroy_worker(lt->sys_timer.worker);
fail_sys_timer:
	kfree(lt);
	return NULL;
}

int kvm_lt_set_base(struct kvm *kvm, int node_id, unsigned long new_base)
{
	struct kvm_lt *lt = kvm_get_lt(kvm, node_id);
	int ret;
	u32 lt_freq = 10000000;

	if (is_prototype())
		lt_freq = 500000;

	if (lt == NULL) {
		kvm_create_lt(kvm, node_id, cpu_freq_hz,
			lt_freq	/* now fixed, but is better to pass */
				/* qemu as machine parameter and */
				/* repass from qemu to KVM through ioctl() */);
		lt = kvm_get_lt(kvm, node_id);
		if (lt == NULL) {
			pr_err("%s(): sys timer node #%d is not yet created, "
				"ignore setup\n",
				__func__, node_id);
			return -ENODEV;
		}
	}
	if (lt->base_address == new_base) {
		pr_info("%s(): sys timer node #%d base 0x%lx is the same, "
			"so ignore update\n",
			__func__, node_id, new_base);
		return 0;
	}

	mutex_lock(&kvm->slots_lock);
	if (lt->base_address != 0) {
		/* base address was already set, so update */
		kvm_io_bus_unregister_dev(kvm, KVM_MMIO_BUS, &lt->dev);
	}
	lt->base_address = new_base;
	kvm_iodevice_init(&lt->dev, &lt_mmio_ops);
	ret = kvm_io_bus_register_dev(kvm, KVM_MMIO_BUS, new_base,
				      LT_MMIO_LENGTH, &lt->dev);
	mutex_unlock(&kvm->slots_lock);
	if (ret < 0) {
		kvm_set_lt(kvm, node_id, NULL);
		kfree(lt);
		pr_err("%s(): could not register sys timer node #%d as MMIO "
			"bus device, error %d\n",
			__func__, node_id, ret);
	}

	return ret;
}

void kvm_free_lt(struct kvm *kvm, int node_id)
{
	struct kvm_lt *lt = kvm_get_lt(kvm, node_id);

	if (lt) {
		if (lt->base_address != 0) {
			/* mutex_lock(&kvm->slots_lock); */
			kvm_io_bus_unregister_dev(kvm, KVM_MMIO_BUS, &lt->dev);
			lt->base_address = 0;
			/* mutex_unlock(&kvm->slots_lock); */
		}
		hrtimer_cancel(&lt->sys_timer.timer);
		kthread_flush_work(&lt->sys_timer.expired);
		kthread_destroy_worker(lt->sys_timer.worker);
		hrtimer_cancel(&lt->wd_timer.timer);
		kthread_flush_work(&lt->wd_timer.expired);
		kthread_destroy_worker(lt->wd_timer.worker);
		kfree(lt);
		kvm_set_lt(kvm, node_id, NULL);
	}
}
void kvm_free_all_lt(struct kvm *kvm)
{
	int node_id;

	for (node_id = 0; node_id < KVM_MAX_EIOHUB_NUM; node_id++) {
		kvm_free_lt(kvm, node_id);
	}
}
