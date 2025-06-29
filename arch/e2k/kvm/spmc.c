/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * IOHUB-2/EIOHub System Power Management Controller emulation.
 * Based on e2k lms simulator implementation.
 */

#include <linux/kvm_host.h>
#include <linux/slab.h>
#include <linux/math64.h>
#include <asm/e2k_debug.h>
#include <asm/kvm/runstate.h>
#include <asm/spmc_regs.h>

#include "ioepic.h"
#include "irq.h"
#include "spmc.h"

#define mod_64(x, y) ((x) % (y))

#undef	DEBUG_TIMER_MODE
#undef	DebugTM
#define	DEBUG_TIMER_MODE	0	/* system timer debugging */
#define	DebugTM(fmt, args...)						\
({									\
	if (DEBUG_TIMER_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_VERBOSE_TIMER_MODE
#undef	DebugVTM
#define	DEBUG_VERBOSE_TIMER_MODE	0	/* system timer verbode */
						/* debugging */
#define	DebugVTM(fmt, args...)						\
({									\
	if (DEBUG_VERBOSE_TIMER_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_SCI_MODE
#undef	DebugSCI
#define	DEBUG_SCI_MODE		0	/* SPMC IRQs debugging */
#define	DebugSCI(fmt, args...)						\
({									\
	if (DEBUG_SCI_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_IRQ_MODE
#undef	DebugIRQ
#define	DEBUG_IRQ_MODE		0	/* IRQs debugging */
#define	DebugIRQ(fmt, args...)						\
({									\
	if (DEBUG_IRQ_MODE || kvm_debug)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_HR_TIMER_MODE
#undef	DebugHRTM
#define	DEBUG_HR_TIMER_MODE	0	/* high resolution timer debugging */
#define	DebugHRTM(fmt, args...)						\
({									\
	if (DEBUG_HR_TIMER_MODE || kvm_debug)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_SPMC_STATUS_MODE
#undef	DebugSTS
#define	DEBUG_SPMC_STATUS_MODE	0	/* SPMC status updates debugging */
#define	DebugSTS(fmt, args...)						\
({									\
	if (DEBUG_SPMC_STATUS_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_SPMC_SHUTDOWN_MODE
#undef	DebugSHUTDOWN
#define	DEBUG_SPMC_SHUTDOWN_MODE	0	/* SPMC shutdown debugging */
#define	DebugSHUTDOWN(fmt, args...)					\
({									\
	if (DEBUG_SPMC_SHUTDOWN_MODE || kvm_debug)			\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	VERBOSE_DEBUG_SPMC_REGS_MODE
#undef	DebugREGS
#define	VERBOSE_DEBUG_SPMC_REGS_MODE	0	/* SPMC registers verbode */
						/* debugging */
#if	VERBOSE_DEBUG_SPMC_REGS_MODE
#define	spmc_reg_debug(fmt, arg...)	pr_err("%s() : " fmt, __func__, ##arg)
#else
#define	spmc_reg_debug(fmt, arg...)
#endif	/* VERBOSE_DEBUG_SPMC_REGS_MODE */

/* SPMC register read/write debug: 0 - OFF, 1 - ON */
#undef	DEBUG_SPMC_REGS_MODE
#define	DEBUG_SPMC_REGS_MODE		0

#define	HRTIMER_EXPIRES_PERCENT		90	/* percents */
/* If hrtimer expires on HRTIMER_EXPIRES_PERCENTs it does not reactivate */
#define	HRTIMER_EXPIRES_APPROX(time)	\
		(((time) / 100) * HRTIMER_EXPIRES_PERCENT)

static inline struct kvm_spmc *to_spmc(struct kvm_io_device *dev)
{
	return container_of(dev, struct kvm_spmc, dev);
}

static inline struct kvm_spmc *timer_to_spmc(struct kvm_timer *timer)
{
	return container_of(timer, struct kvm_spmc, sci_timer);
}

static inline u64 cycles_to_count(struct kvm_spmc *spmc, u64 cycles)
{
	return mul_u64_u32_div(cycles, spmc->frequency, spmc->ticks_per_sec);
}

static inline u64 count_to_cycles(struct kvm_spmc *spmc, u64 counter)
{
	return mul_u64_u32_div(counter, spmc->ticks_per_sec, spmc->frequency);
}

#if	DEBUG_SPMC_REGS_MODE
static inline void dump_spmc_pm_timer(u32 reg)
{
	spmc_pm_tmr_t timer;

	timer.reg = reg;
	pr_cont("PM Timer: counter 0x%08x", timer.counter);
}
static inline void dump_spmc_pm1_status(u32 reg)
{
	spmc_pm1_sts_t status;

	status.reg = reg;
	pr_cont("PM1 Status: 0x%08x : ON: %s %s %s %s %s %s  "
		"State: AC_power %d Bat_low %d",
		reg,
		(status.tmr_sts) ? "Timer" : "",
		(status.ac_power_sts) ? "AC_power" : "",
		(status.batlow_sts) ? "Bat_low" : "",
		(status.atn_sts) ? "Atn_suspend" : "",
		(status.pwrbtn_sts) ? "Power_batton" : "",
		(status.wak_sts) ? "Wake_event" : "",
		status.ac_power_state,
		status.batlow_state);
}
static inline void dump_spmc_pm1_enable(u32 reg)
{
	spmc_pm1_en_t enable;

	enable.reg = reg;
	pr_cont("PM1 Enable: 0x%08x : ON: %s %s %s %s  "
		"Time: %d bits",
		reg,
		(enable.tmr_en) ? "Timer" : "",
		(enable.ac_pwr_en) ? "AC_power" : "",
		(enable.batlow_en) ? "Bat_low" : "",
		(enable.pwrbtn_en) ? "Power_batton" : "",
		(enable.tmr_32) ? 32 : 24);
}
static inline void dump_spmc_pm1_control(u32 reg)
{
	spmc_pm1_cnt_t control;

	control.reg = reg;
	pr_cont("PM1 Control: 0x%08x : ACPI: %s  Sleep: %s",
		reg,
		(control.sci_en) ? "enable" : "disable",
		(control.slp_en) ? "enable" : "disable");
	if (control.slp_en) {
		pr_cont(" type: S%d", control.slp_typx);
	}
}
static inline void dump_spmc_atnsus_counter(u32 reg)
{
	spmc_atnsus_cnt_t suspend;

	suspend.reg = reg;
	pr_cont("Attention Suspend: counter: 0x%08x", suspend.counter);
}
static inline void dump_spmc_pu_rst_counter(u32 reg)
{
	spmc_pu_rst_cnt_t reset;

	reset.reg = reg;
	pr_cont("Power Up Reset: counter: 0x%08x", reset.counter);
}
static inline void dump_spmc_register(int reg_off, u32 value, const char *title)
{
	pr_cont("%s", title);

	switch (reg_off) {
	case ACPI_SPMC_PM_TMR:
		dump_spmc_pm_timer(value);
		break;
	case ACPI_SPMC_PM1_STS:
		dump_spmc_pm1_status(value);
		break;
	case ACPI_SPMC_PM1_EN:
		dump_spmc_pm1_enable(value);
		break;
	case ACPI_SPMC_PM1_CNT:
		dump_spmc_pm1_control(value);
		break;
	case ACPI_SPMC_ATNSUS_CNT:
		dump_spmc_atnsus_counter(value);
		break;
	case ACPI_SPMC_PURST_CNT:
		dump_spmc_pu_rst_counter(value);
		break;
	default:
		pr_cont("Invalid SPMC register offset 0x%x", reg_off);
		break;
	}
	pr_info("\n");
}
#else	/* DEBUG_SPMC_REGS_MODE == 0 */
static inline void dump_spmc_pm_timer(u32 reg)
{
}
static inline void dump_spmc_pm1_status(u32 reg)
{
}
static inline void dump_spmc_pm1_enable(u32 reg)
{
}
static inline void dump_spmc_pm1_control(u32 reg)
{
}
static inline void dump_spmc_atnsus_counter(u32 reg)
{
}
static inline void dump_spmc_pu_rst_counter(u32 reg)
{
}
static inline void dump_spmc_register(int reg_off, u32 value, const char *title)
{
}
#endif	/* DEBUG_SPMC_REGS_MODE */

static u64 kvm_get_up_to_date_sci_timer(struct kvm_vcpu *vcpu,
					struct kvm_spmc *spmc)
{
	struct kvm_timer *timer = &spmc->sci_timer;
	u64 running_time;
	s64 running_cycles;
	s64 running_ns, host_ns;
	s64 cycles, host_cycles;
	ktime_t now;
	u64 now_ns;
	u64 counter, host_counter;
	u32 limit, start_count, new_count;
	unsigned long flags;

	DebugSCI("started: g_mode #%d timer period 0x%llx\n",
		spmc->g_state, timer->period);

	if (spmc->g_state != SPMC_G0_STATE) {
		/* timer is not incremented, so return current value */
		return spmc->regs.pm_timer.counter;
	}

	ASSERT(timer != NULL);

	if (vcpu == NULL) {
		/* call from hrtimer handler, it need use last VCPU */
		vcpu = timer->vcpu;
	}

	raw_spin_lock_irqsave(&timer->lock, flags);

	if (unlikely(timer->period == 0)) {
		raw_spin_unlock_irqrestore(&timer->lock, flags);
		return spmc->regs.pm_timer.counter;
	}
	start_count = timer->start_count;
	running_time =
		(vcpu != NULL) ? kvm_do_get_guest_vcpu_running_time(vcpu) : 0;
	cycles = get_cycles();
	now = timer->timer.base->get_time();
	now_ns = ktime_to_ns(now);
	DebugSCI("%s : running cycles at start 0x%llx, now 0x%llx, "
		"current cycles 0x%llx, start counter 0x%x period ns 0x%llx\n",
		timer->name, timer->running_time, running_time,
		cycles, start_count, timer->period);
	DebugSCI("%s : host start time at nsec 0x%llx, now 0x%llx\n",
		timer->name, timer->host_start_ns, now_ns);

	running_cycles = running_time - timer->running_time;
	if (running_cycles < 0) {
		/* probably it starts on or migrates to other VCPU/CPU */
		running_cycles = 0;
	}
	running_ns = cycles_2nsec(running_cycles);
	host_ns = now_ns - timer->host_start_ns;
	if (host_ns < 0) {
		/* probably it starts on or migrates to other CPU */
		host_ns = 0;
	}
	host_cycles = nsecs_2cycles(host_ns);
	DebugSCI("%s : current running cycles 0x%llx ns 0x%llx\n",
		timer->name, running_cycles, running_ns);
	DebugSCI("%s : host    running cycles 0x%llx ns 0x%llx\n",
		timer->name, host_cycles, host_ns);

	limit = kvm_get_sci_timer_limit(spmc);

	counter = cycles_to_count(spmc, running_cycles) + start_count;
	host_counter = cycles_to_count(spmc, host_cycles) + start_count;
	new_count = host_counter & kvm_get_sci_timer_max_mask(spmc);

	/* update timer counter value */
	if (timer->type == kvm_sci_timer_type) {
		spmc->regs.pm_timer.counter = new_count;
	} else {
		pr_err("%s(): %d is unsupported or invalid timer type\n",
			__func__, timer->type);
	}
	timer->start_count = new_count;
	timer->host_start_ns = now_ns;
	timer->running_time = running_time;
	timer->vcpu = vcpu;

	raw_spin_unlock_irqrestore(&timer->lock, flags);

	DebugSCI("%s : guest running cycles 0x%llx "
		"counter 0x%llx : %lld%%\n",
		timer->name, running_cycles, counter,
		(counter * 100) / host_counter);
	DebugSCI("%s : host  running cycles 0x%llx counter 0x%llx\n",
		timer->name, host_cycles, host_counter);
	DebugSCI("%s : host counter 0x%llx limit 0x%x : new counter 0x%x\n",
		timer->name, host_counter, limit, new_count);

	return host_counter;
}

static inline bool spmc_in_range(struct kvm_spmc *spmc, gpa_t addr)
{
	return addr >= spmc->base_address + SPMC_REGS_CFG_OFFSET &&
			addr < spmc->base_address + SPMC_REGS_CFG_OFFSET +
							SPMC_REGS_CFG_LENGTH;
}
static inline u32 spmc_get_reg(struct kvm_spmc *spmc, int reg_off)
{
	int reg_no = reg_off - SPMC_REGS_CFG_OFFSET;

	ASSERT(reg_no >= 0 && reg_no < SPMC_REGS_CFG_LENGTH);

	spmc_reg_debug("%02x : %08x from %px\n",
		reg_off, *((u32 *) ((void *)(&spmc->regs) + reg_no)),
		((u32 *) ((void *)(&spmc->regs) + reg_no)));
	return *((u32 *) ((void *)(&spmc->regs) + reg_no));
}

static inline void spmc_set_reg(struct kvm_spmc *spmc, int reg_off, u32 val)
{
	int reg_no = reg_off - SPMC_REGS_CFG_OFFSET;

	ASSERT(reg_no >= 0 && reg_no < SPMC_REGS_CFG_LENGTH);

	*((u32 *) ((void *)(&spmc->regs) + reg_no)) = val;
	spmc_reg_debug("%02x : %08x to %px\n",
		reg_off, *((u32 *) ((void *)(&spmc->regs) + reg_no)),
		((u32 *) ((void *)(&spmc->regs) + reg_no)));
}

static inline bool get_sci_timer_status(struct kvm_spmc *spmc)
{
	return !!spmc->regs.pm1_status.tmr_sts;
}

static inline void set_sci_timer_status(struct kvm_spmc *spmc)
{
	spmc->regs.pm1_status.tmr_sts = 1;
	DebugSTS("sci timer status, pm1_status : 0x%08x\n",
		spmc->regs.pm1_status.reg);
}

static inline bool get_ac_power_status(struct kvm_spmc *spmc)
{
	return !!spmc->regs.pm1_status.ac_power_sts;
}

static inline void set_ac_power_status(struct kvm_spmc *spmc)
{
	spmc->regs.pm1_status.ac_power_sts = 1;
	DebugSTS("ac power status, pm1_status : 0x%08x\n",
		spmc->regs.pm1_status.reg);
}

static inline bool get_batton_low_status(struct kvm_spmc *spmc)
{
	return !!spmc->regs.pm1_status.batlow_sts;
}

static inline void set_batton_low_status(struct kvm_spmc *spmc)
{
	spmc->regs.pm1_status.batlow_sts = 1;
	DebugSTS("batton low status, pm1_status : 0x%08x\n",
		spmc->regs.pm1_status.reg);
}

static inline bool get_power_batton_status(struct kvm_spmc *spmc)
{
	return !!spmc->regs.pm1_status.pwrbtn_sts;
}

static inline void set_power_batton_status(struct kvm_spmc *spmc)
{
	spmc->regs.pm1_status.pwrbtn_sts = 1;
	DebugSTS("power batton status, pm1_status : 0x%08x\n",
		spmc->regs.pm1_status.reg);
}

static inline bool get_wake_up_event_status(struct kvm_spmc *spmc)
{
	return !!spmc->regs.pm1_status.wak_sts;
}

static inline void set_wake_up_event_status(struct kvm_spmc *spmc)
{
	spmc->regs.pm1_status.wak_sts = 1;
	DebugSTS("wake up event status, pm1_status : 0x%08x\n",
		spmc->regs.pm1_status.reg);
}

static inline void set_sleep_state_enable(struct kvm_spmc *spmc)
{
	spmc->regs.pm1_control.slp_en = 1;
}

static inline void reset_sleep_state_enable(struct kvm_spmc *spmc)
{
	spmc->regs.pm1_control.slp_en = 0;
}

static void generate_interrupt(struct kvm *kvm, spmc_irq_map_t irq_id,
				bool active)
{
	DebugIRQ("IRQ #%d level is %d\n", irq_id, active);
	kvm_set_irq(kvm, irq_id, irq_id, active, false);
}

static bool spmc_calculate_sci(struct kvm_spmc *spmc)
{
	return kvm_spmc_acpi_enable(spmc) &&
			(kvm_sci_timer_enable(spmc) &&
				get_sci_timer_status(spmc)) ||
			(kvm_spmc_ac_power_enable(spmc) &&
				get_ac_power_status(spmc)) ||
			(kvm_spmc_batton_low_enable(spmc) &&
				get_batton_low_status(spmc)) ||
			((spmc->g_state == SPMC_G0_STATE) &&
				kvm_spmc_power_batton_enable(spmc) &&
					get_power_batton_status(spmc));
}

static void spmc_check_sci(struct kvm_spmc *spmc)
{
	bool new_sci = spmc_calculate_sci(spmc);

	if (new_sci != spmc->sci_state) {
		generate_interrupt(spmc->kvm, spmc->sci_timer_irq_id, new_sci);
		spmc->sci_state = new_sci;
	}
}

static void update_sleep_state(struct kvm_vcpu *vcpu, struct kvm_spmc *spmc)
{
	if (kvm_spmc_sleep_state_enable(spmc)) {
		spmc->s_state = kvm_spmc_sleep_state(spmc);

		switch (spmc->s_state) {
		case SPMC_S0_SLEEP_STATE:
			spmc->g_state = SPMC_G0_STATE;
			break;
		case SPMC_S3_SLEEP_STATE:
		case SPMC_S4_SLEEP_STATE:
			spmc->g_state = SPMC_G1_STATE;
			pr_err("%s(): unimplemented sleep state %d\n",
				__func__, spmc->s_state);
			break;
		case SPMC_S5_SLEEP_STATE:
			spmc->g_state = SPMC_G2_STATE;
			vcpu->arch.exit_shutdown_terminate = KVM_EXIT_E2K_SHUTDOWN;
			DebugSHUTDOWN("SPMC shutdown\n");
			break;
		default:
			pr_err("%s(): unknown sleep state %d\n",
				__func__, spmc->s_state);
			break;
		}
		reset_sleep_state_enable(spmc);
	}
}

static u32 update_sci_timer_value(struct kvm_vcpu *vcpu, struct kvm_spmc *spmc)
{
	kvm_get_up_to_date_sci_timer(vcpu, spmc);
	return spmc->regs.pm_timer.reg;
}

static void start_sci_timer(struct kvm_vcpu *vcpu, struct kvm_spmc *spmc,
				u32 start_count, u64 cycles_period)
{
	struct kvm_timer *sci_timer = &spmc->sci_timer;
	ktime_t now;
	u64 ns_period;
	s64 offset, ns_expired;

	ns_period = cycles_2nsec(cycles_period);
	if (ns_period == 0) {
		sci_timer->period = 0;
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


	ASSERT(!hrtimer_active(&sci_timer->timer));

	sci_timer->vcpu = vcpu;
	sci_timer->start_count = start_count;
	sci_timer->period = ns_period;
	now = sci_timer->timer.base->get_time();
	sci_timer->host_start_ns = ktime_to_ns(now);
	sci_timer->running_time =
		(vcpu) ? kvm_get_guest_vcpu_running_time(vcpu) : 0;
	ns_expired = ns_period;
	if (start_count > 0) {
		/* counter statrs from current freezed value */
		offset = count_to_cycles(spmc, start_count);
		ns_expired -= cycles_2nsec(offset % cycles_period);
		ASSERT(ns_expired >= 0);
	}
	hrtimer_start(&sci_timer->timer,
			ktime_add_ns(now, ns_expired),
			HRTIMER_MODE_ABS);
	DebugTM("%s started hrtimer at host ns 0x%llx start count 0x%x, "
		"period 0x%llx\n",
		sci_timer->name, sci_timer->host_start_ns,
		start_count, ns_period);
	DebugTM("%s        running time cycles 0x%llx\n",
		sci_timer->name, sci_timer->running_time);

	DebugTM("%s freq is %d Hz, now 0x%llx, timer period cycles 0x%llx, "
		"nsec %lld, expire @ 0x%llx\n",
		sci_timer->name, spmc->frequency, ktime_to_ns(now),
		cycles_period, sci_timer->period,
		hrtimer_get_expires_ns(&sci_timer->timer));
}

static void restart_sci_timer(struct kvm_vcpu *vcpu, struct kvm_spmc *spmc)
{
	u32 start, limit;
	u64 increments, cycles_increments;

	hrtimer_cancel(&spmc->sci_timer.timer);
	kthread_flush_work(&spmc->sci_timer.expired);
	DebugTM("PM timer counter hrtimer canceled at now 0x%llx\n",
		ktime_to_ns(ktime_get()));
	if (spmc->g_state != SPMC_G0_STATE) {
		/* timer is not active and freez at current state */
		return;
	}
	start = spmc->regs.pm_timer.counter;	/* current start value */
	limit = kvm_get_sci_timer_limit(spmc);

	increments = limit - 0	/* counter start value */;
	cycles_increments = count_to_cycles(spmc, increments);
	DebugTM("PM timer counter from 0x%x to limit 0x%x, increments: 0x%llx "
		"cycles 0x%llx\n",
		start, limit, increments, cycles_increments);
	start_sci_timer(vcpu, spmc, start, cycles_increments);
}

static int spmc_conf_io_read(struct kvm_vcpu *vcpu, struct kvm_io_device *this,
				gpa_t address, int len, void *data)
{
	struct kvm_spmc *spmc = to_spmc(this);
	unsigned int offset = address - spmc->base_address;
	u32 result, mask, reg;
	const char *reg_name = "???";

	spmc_reg_debug("address 0x%llx, offset %02x, len %d to %px\n",
		address, offset, len, data);

	if (!spmc_in_range(spmc, address))
		return -EOPNOTSUPP;

	if (len == 1) {
		mask = 0x000000ffUL;
	} else if (len == 2) {
		mask = 0x0000ffffUL;
	} else if (len == 4) {
		mask = 0xffffffffUL;
	} else {
		ASSERT(len == 4 || len == 2 || len == 1);
	}

	mutex_lock(&spmc->lock);
	switch (offset) {
	case ACPI_SPMC_PM_TMR:
		reg = update_sci_timer_value(vcpu, spmc);
		result = reg & mask;
		reg_name = "PM Timer";
		break;
	case ACPI_SPMC_PM1_STS:
		reg = spmc->regs.pm1_status.reg;
		result = reg & mask;
		reg_name = "PM1 Status";
		break;
	case ACPI_SPMC_PM1_EN: {
		spmc_pm1_en_t pm_enable;

		pm_enable.reg = 0;
		pm_enable.tmr_en = spmc->regs.pm1_enable.tmr_en;
		pm_enable.tmr_32 = spmc->regs.pm1_enable.tmr_32;
		pm_enable.ac_pwr_en = spmc->regs.pm1_enable.ac_pwr_en;
		pm_enable.batlow_en = spmc->regs.pm1_enable.batlow_en;
		pm_enable.pwrbtn_en = spmc->regs.pm1_enable.pwrbtn_en;
		reg = pm_enable.reg;
		result = reg & mask;
		reg_name = "PM1 Enable";
		break;
	}
	case ACPI_SPMC_PM1_CNT: {
		spmc_pm1_cnt_t pm_control;

		pm_control.reg = 0;
		pm_control.sci_en = spmc->regs.pm1_control.sci_en;
		pm_control.slp_typx = spmc->regs.pm1_control.slp_typx;
		reg = pm_control.reg;
		result = reg & mask;
		reg_name = "PM1 Control";
		break;
	}
	case ACPI_SPMC_ATNSUS_CNT:
		reg = spmc->regs.atnsus_counter.counter;
		result = reg & mask;
		reg_name = "ATteNtion Suspend counter";
		break;
	case ACPI_SPMC_PURST_CNT:
		reg = spmc->regs.pu_rst_counter.counter;
		result = reg & mask;
		reg_name = "Power Up Reset counter";
		break;
	default:
		reg = 0xffffffff;
		result = reg & mask;
		pr_err("%s() : invalid SPMC register offset 0x%x\n",
			__func__, offset);
		break;
	}
	mutex_unlock(&spmc->lock);

	*(u32 *)data = result;

	spmc_reg_debug("%s data 0x%08x\n", reg_name, *(u32 *)data);

	dump_spmc_register(offset, reg, "get SPMC register: ");

	return 0;
}

static int spmc_conf_io_write(struct kvm_vcpu *vcpu, struct kvm_io_device *this,
				gpa_t address, int len, const void *data)
{
	struct kvm_spmc *spmc = to_spmc(this);
	unsigned int offset = address - spmc->base_address;
	u32 val, mask, reg;
	bool acpi_was_enable;
	const char *reg_name = "???";

	spmc_reg_debug("address 0x%llx, offset %02x, len %d 0x%08x from %px\n",
		address, offset, len, *(u32 *)data, data);

	if (!spmc_in_range(spmc, address))
		return -EOPNOTSUPP;

	val = *(u32 *)data;
	reg = 0xffffffff;
	if (len == 1) {
		val &= 0xff;
		mask = 0xffffff00UL;
	} else if (len == 2) {
		val &= 0xffff;
		mask = 0xffff0000UL;
	} else if (len == 4) {
		mask = 0xffffffffUL;
	} else {
		ASSERT(len == 4 || len == 2 || len == 1);
	}

	mutex_lock(&spmc->lock);
	acpi_was_enable = kvm_spmc_acpi_enable(spmc);
	if (likely(acpi_was_enable)) {
		switch (offset) {
		case ACPI_SPMC_PM_TMR:
			spmc->regs.pm_timer.counter &= mask;
			spmc->regs.pm_timer.counter |= val;
			reg = spmc->regs.pm_timer.reg;
			reg_name = "PM Timer";
			break;
		case ACPI_SPMC_PM1_STS: {
			spmc_pm1_sts_t pm_status;

			pm_status.reg = val;
			if (pm_status.tmr_sts) {
				/* clear timer status bit */
				spmc->regs.pm1_status.tmr_sts = 0;
			}
			if (pm_status.ac_power_sts) {
				/* clear ac power status bit */
				spmc->regs.pm1_status.ac_power_sts = 0;
			}
			if (pm_status.batlow_sts) {
				/* clear batton low status bit */
				spmc->regs.pm1_status.batlow_sts = 0;
			}
			if (pm_status.pwrbtn_sts) {
				/* clear power batton status bit */
				spmc->regs.pm1_status.pwrbtn_sts = 0;
			}
			if (pm_status.wak_sts) {
				/* clear wake up event status bit */
				spmc->regs.pm1_status.wak_sts = 0;
			}
			reg = spmc->regs.pm1_status.reg;
			reg_name = "PM1 Status";
			break;
		}
		case ACPI_SPMC_PM1_EN: {
			spmc_pm1_en_t pm_enable;
			bool was_tmr32 = kvm_sci_timer_32(spmc);

			pm_enable.reg = val;
			spmc->regs.pm1_enable.tmr_en = pm_enable.tmr_en;
			spmc->regs.pm1_enable.tmr_32 = pm_enable.tmr_32;
			spmc->regs.pm1_enable.ac_pwr_en = pm_enable.ac_pwr_en;
			spmc->regs.pm1_enable.batlow_en = pm_enable.batlow_en;
			spmc->regs.pm1_enable.pwrbtn_en = pm_enable.pwrbtn_en;
			reg = spmc->regs.pm1_enable.reg;
			reg_name = "PM1 Enable";
			if (was_tmr32 != kvm_sci_timer_32(spmc)) {
				restart_sci_timer(vcpu, spmc);
			}

			break;
		}
		case ACPI_SPMC_PM1_CNT: {
			spmc_pm1_cnt_t pm_control;

			pm_control.reg = val;
			spmc->regs.pm1_control.sci_en = pm_control.sci_en;
			spmc->regs.pm1_control.slp_typx = pm_control.slp_typx;
			spmc->regs.pm1_control.slp_en = pm_control.slp_en;
			reg = spmc->regs.pm1_control.reg;
			reg_name = "PM1 Control";
			update_sleep_state(vcpu, spmc);
			break;
		}
		case ACPI_SPMC_ATNSUS_CNT:
			if (spmc->g_state == SPMC_G0_STATE) {
				spmc->regs.atnsus_counter.counter &= mask;
				spmc->regs.atnsus_counter.counter |= val;
			}
			reg = spmc->regs.atnsus_counter.reg;
			reg_name = "ATteNtion Suspend counter";
			break;
		case ACPI_SPMC_PURST_CNT:
			if (spmc->g_state == SPMC_G0_STATE) {
				if (val < SPMC_PU_RST_CNT_MIN) {
					val = SPMC_PU_RST_CNT_MIN;
				}
				spmc->regs.pu_rst_counter.counter &= mask;
				spmc->regs.pu_rst_counter.counter |= val;
			}
			reg = spmc->regs.pu_rst_counter.reg;
			reg_name = "Power Up Reset counter";
			break;
		default:
			pr_err("%s() : invalid SPMC register offset 0x%x\n",
				__func__, offset);
			break;
		}
		spmc_check_sci(spmc);
	} else {
		/* SPMC/ACPI disabled and can only enable the mode */
		switch (offset) {
		case ACPI_SPMC_PM1_CNT: {
			spmc_pm1_cnt_t pm_control;

			pm_control.reg = val;
			spmc->regs.pm1_control.sci_en = pm_control.sci_en;
			kvm_get_up_to_date_sci_timer(vcpu, spmc);
			reg = spmc->regs.pm1_control.reg;
			reg_name = "PM1 Control";
			break;
		}
		case ACPI_SPMC_PM_TMR:
		case ACPI_SPMC_PM1_STS:
		case ACPI_SPMC_PM1_EN:
			/* cannot be updated */
			pr_warn("%s(): SPMC/ACPI disabled, so writing to "
				"SPMC register 0x%x is ignored\n",
				__func__, offset);
			break;
		case ACPI_SPMC_ATNSUS_CNT:
			spmc->regs.atnsus_counter.counter &= mask;
			spmc->regs.atnsus_counter.counter |= val;
			reg = spmc->regs.atnsus_counter.reg;
			reg_name = "ATteNtion Suspend counter";
			break;
		case ACPI_SPMC_PURST_CNT:
			if (val < SPMC_PU_RST_CNT_MIN) {
				val = SPMC_PU_RST_CNT_MIN;
			}
			spmc->regs.pu_rst_counter.counter &= mask;
			spmc->regs.pu_rst_counter.counter |= val;
			reg = spmc->regs.pu_rst_counter.reg;
			reg_name = "Power Up Reset counter";
			break;
		default:
			pr_err("%s() : invalid SPMC register offset 0x%x\n",
				__func__, offset);
			break;
		}
	}
	mutex_unlock(&spmc->lock);

	spmc_reg_debug("%s data 0x%08x\n", reg_name, reg);

	dump_spmc_register(offset, reg, "set SPMC register: ");

	return 0;
}

static void spmc_sci_timer_do_work(struct kthread_work *work)
{
	struct kvm_timer *timer = container_of(work, struct kvm_timer, expired);
	struct kvm *kvm = timer->kvm;
	struct kvm_spmc *spmc = timer_to_spmc(timer);

	if (timer->work == kvm_set_irq_timer_work) {
		ASSERT(spmc->sci_state == false);
		generate_interrupt(kvm, spmc->sci_timer_irq_id, true);
		spmc->sci_state = true;
	} else if (timer->work == kvm_reset_irq_timer_work) {
		ASSERT(spmc->sci_state == true);
		generate_interrupt(kvm, spmc->sci_timer_irq_id, false);
		spmc->sci_state = false;
	} else {
		pr_err("%s(): %d is unknown or unsupported timer "
			"expires work\n",
			__func__, timer->work);
	}
}

static void do_sci_timer(struct kvm_vcpu *vcpu, void *data)
{
	struct kvm_spmc *spmc = data;
	struct kvm_timer *sci_timer = &spmc->sci_timer;
	u64 counter;
	u32 limit, period_start;

	counter = kvm_get_up_to_date_sci_timer(vcpu, spmc);
	limit = kvm_get_sci_timer_limit(spmc);
	period_start = sci_timer->period_start;

	if ((counter - period_start) > limit + limit / 4) {
		DebugHRTM("timer counter 0x%llx, period start at 0x%x "
			"exceeded limit 0x%x on +0x%llx)",
			counter, period_start, limit,
			(counter - period_start) - limit);
	} else if ((counter - period_start) < (limit - limit / 8)) {
		DebugHRTM("timer counter 0x%llx, period start at 0x%x "
			"did not reach limit 0x%x on -0x%llx",
			counter, period_start, limit,
			limit - (counter - period_start));
	}
	sci_timer->period_start = counter & kvm_get_sci_timer_max_mask(spmc);

	/* set SCI timer status bit */
	set_sci_timer_status(spmc);

	if (kvm_sci_timer_enable(spmc)) {
		/* it need generate SCI interrupt */
		sci_timer->work = kvm_set_irq_timer_work;
		kthread_queue_work(sci_timer->worker, &sci_timer->expired);
	}
}

static enum hrtimer_restart sci_timer_fn(struct kvm_spmc *spmc,
						struct kvm_timer *ktimer)
{
	struct kvm_vcpu *vcpu;
	s64 period = ktimer->period;

	vcpu = ktimer->vcpu;

	if (vcpu != NULL) {
		DebugVTM("%s started on VCPU #%d\n",
			ktimer->name, vcpu->vcpu_id);
	} else {
		DebugVTM("%s started on background stack\n", ktimer->name);
	}

	ktimer->t_ops->timer_fn(vcpu, spmc);

	if (ktimer->t_ops->is_periodic(ktimer)) {
		hrtimer_add_expires_ns(&ktimer->timer, period);
		DebugVTM("%s periodic timer restarted "
			"at host ns 0x%llx expires at 0x%llx\n",
			ktimer->name, ktimer->host_start_ns,
			hrtimer_get_expires_ns(&ktimer->timer));
		return HRTIMER_RESTART;
	}
	DebugVTM("%s handled\n", ktimer->name);
	return HRTIMER_NORESTART;
}

static enum hrtimer_restart spmc_sci_timer_fn(struct hrtimer *data)
{
	struct kvm_spmc *spmc;
	struct kvm_timer *sci_timer;

	sci_timer = container_of(data, struct kvm_timer, timer);
	spmc = timer_to_spmc(sci_timer);
	return sci_timer_fn(spmc, sci_timer);
}

static bool sci_is_periodic(struct kvm_timer *ktimer)
{
	return true;	/* SCI timer are periodic */
}

static void kvm_spmc_reset(struct kvm_spmc *spmc)
{

	/* Stop the timer in case it's a reset to an active state */
	hrtimer_cancel(&spmc->sci_timer.timer);
	kthread_flush_work(&spmc->sci_timer.expired);

	spmc->base_address = 0;
	spmc->sci_timer_irq_id = SPMC_SCI_IRQ_ID;

	/* registers state on reset */
	spmc_set_reg(spmc, ACPI_SPMC_PM_TMR, 0);
	spmc_set_reg(spmc, ACPI_SPMC_PM1_STS, 0);
	spmc_set_reg(spmc, ACPI_SPMC_PM1_EN, 0);
	spmc_set_reg(spmc, ACPI_SPMC_PM1_CNT, 0);
	spmc_set_reg(spmc, ACPI_SPMC_ATNSUS_CNT, 0x00370000);
	spmc_set_reg(spmc, ACPI_SPMC_PURST_CNT, 0x00370000);

	spmc->sci_state = false;
	spmc->s_state = SPMC_S0_SLEEP_STATE;
	spmc->g_state = SPMC_G0_STATE;

	restart_sci_timer(NULL, spmc);
}

static const struct kvm_io_device_ops spmc_conf_io_ops = {
	.read	= spmc_conf_io_read,
	.write	= spmc_conf_io_write,
};

static const struct kvm_timer_ops spmc_sci_timer_ops = {
	.is_periodic	= sci_is_periodic,
	.timer_fn	= do_sci_timer,
};

struct kvm_spmc *kvm_create_spmc(struct kvm *kvm, int node_id,
			u32 ticks_per_sec,	/* CPU frequency at herz */
			u32 spmc_timer_freq)	/* PM timer frequency at herz */
{
	struct kvm_spmc *spmc;
	pid_t pid_nr;

	ASSERT(kvm_get_spmc(kvm, node_id) == NULL);

	spmc = kzalloc(sizeof(struct kvm_spmc), GFP_KERNEL);
	if (!spmc)
		return NULL;

	mutex_init(&spmc->lock);

	spmc->kvm = kvm;
	spmc->ticks_per_sec = ticks_per_sec;
	spmc->frequency = spmc_timer_freq;

	pid_nr = task_pid_nr(current);

	hrtimer_init(&spmc->sci_timer.timer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS);
	spmc->sci_timer.timer.function = spmc_sci_timer_fn;
	spmc->sci_timer.name = "pm timer";
	spmc->sci_timer.type = kvm_sci_timer_type;
	spmc->sci_timer.t_ops = &spmc_sci_timer_ops;
	raw_spin_lock_init(&spmc->sci_timer.lock);
	spmc->sci_timer.worker = kthread_create_worker(0, "kvm-pmtmr/%d/%d",
							pid_nr, node_id);
	if (IS_ERR(spmc->sci_timer.worker))
		goto fail_sci_timer;
	kthread_init_work(&spmc->sci_timer.expired, spmc_sci_timer_do_work);
	spmc->sci_timer.kvm = kvm;

	kvm_spmc_reset(spmc);

	kvm_set_spmc(kvm, node_id, spmc);

	return spmc;

fail_sci_timer:
	kfree(spmc);
	return NULL;
}

int kvm_spmc_set_base(struct kvm *kvm, int node_id, unsigned long conf_base)
{
	struct kvm_spmc *spmc = kvm_get_spmc(kvm, node_id);
	int ret;

	if (spmc == NULL) {
		kvm_create_spmc(kvm, node_id, cpu_freq_hz,
			EIOH_SPMC_PM_TIMER_FREQ	/* only SPMC of EIOHub */
						/* is now supported */);
		spmc = kvm_get_spmc(kvm, node_id);
		if (spmc == NULL) {
			pr_err("%s(): SPMC node #%d could not be created, "
				"ignore setup\n",
				__func__, node_id);
			return -ENODEV;
		}
	}
	if (spmc->base_address == conf_base) {
		pr_info("%s(): SPMC node #%d base 0x%lx is the same, "
			"so ignore update\n",
			__func__, node_id, conf_base);
		return 0;
	}

	mutex_lock(&kvm->slots_lock);
	if (spmc->base_address != 0) {
		/* base address was already set, so update */
		kvm_io_bus_unregister_dev(kvm, KVM_MMIO_BUS, &spmc->dev);
	}
	spmc->base_address = conf_base;
	kvm_iodevice_init(&spmc->dev, &spmc_conf_io_ops);
	ret = kvm_io_bus_register_dev(kvm, KVM_MMIO_BUS,
			conf_base + SPMC_REGS_CFG_OFFSET, SPMC_REGS_CFG_LENGTH,
			&spmc->dev);
	mutex_unlock(&kvm->slots_lock);
	if (ret < 0) {
		kvm_set_spmc(kvm, node_id, NULL);
		kfree(spmc);
		pr_err("%s(): could not register SPMC node #%d as PIO "
			"bus device, error %d\n",
			__func__, node_id, ret);
	}

	return ret;
}

void kvm_free_spmc(struct kvm *kvm, int node_id)
{
	struct kvm_spmc *spmc = kvm_get_spmc(kvm, node_id);

	if (spmc) {
		if (spmc->base_address != 0) {
			mutex_lock(&kvm->slots_lock);
			kvm_io_bus_unregister_dev(kvm, KVM_MMIO_BUS,
							&spmc->dev);
			spmc->base_address = 0;
			mutex_unlock(&kvm->slots_lock);
		}
		hrtimer_cancel(&spmc->sci_timer.timer);
		kthread_flush_work(&spmc->sci_timer.expired);
		kthread_destroy_worker(spmc->sci_timer.worker);
		kfree(spmc);
		kvm_set_spmc(kvm, node_id, NULL);
	}
}
void kvm_free_all_spmc(struct kvm *kvm)
{
	int node_id;

	for (node_id = 0; node_id < KVM_MAX_EIOHUB_NUM; node_id++) {
		kvm_free_spmc(kvm, node_id);
	}
}
