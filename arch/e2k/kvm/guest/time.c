/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * KVM guest time implementation.
 *
 * This is implemented in terms of a clocksource driver which uses
 * the hypervisor clock as a nanosecond timebase, and a clockevent
 * driver which uses the hypervisor's timer mechanism.
 *
 * Based on Xen implementation: arch/x86/xen/time.c
 */
#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <linux/kthread.h>
#include <linux/clocksource.h>
#include <linux/clockchips.h>
#include <linux/ktime.h>
#include <linux/kernel_stat.h>

#include <asm/console.h>
#include <asm/timer.h>
#include <asm/l_timer.h>
#include <asm/trap_table.h>
#include <asm/irq_regs.h>
#include <asm/pic.h>

#include <asm/kvm/guest.h>
#include <asm/kvm/hypercall.h>
#include <asm/kvm/guest/irq.h>

#include <asm/kvm/guest/cpu.h>

#include "time.h"
#include "irq.h"
#include "cpu.h"
#include "traps.h"
#include "pic.h"

#undef	DEBUG_KVM_MODE
#undef	DebugKVM
#define	DEBUG_KVM_MODE	1	/* kernel virtual machine debugging */
#define	DebugKVM(fmt, args...)						\
({									\
	if (DEBUG_KVM_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

/* On VIRQ VCUPs common printk() cannot be used, because of thread */
/* running on these VCPUs has not task structure */
#undef	DEBUG_DUMP_KVM_MODE
#undef	DebugDKVM
#define	DEBUG_DUMP_KVM_MODE	0	/* kernel virtual machine debugging */
#define	DebugDKVM(fmt, args...)						\
({									\
	if (DEBUG_DUMP_KVM_MODE)					\
		dump_printk("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_EARLY_TIME_MODE
#undef	DebugKVMET
#define	DEBUG_KVM_EARLY_TIME_MODE	0	/* KVM early time/timer */
						/* debugging */
#define	DebugKVMET(fmt, args...)					\
({									\
	if (DEBUG_KVM_EARLY_TIME_MODE)					\
		dump_printk("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_TIME_MODE
#undef	DebugKVMT
#define	DEBUG_KVM_TIME_MODE	0	/* KVM time/timer debugging */
#define	DebugKVMT(fmt, args...)						\
({									\
	if (DEBUG_KVM_TIME_MODE)					\
		dump_printk("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_IRQ_MODE
#undef	DebugKVMIRQ
#define	DEBUG_KVM_IRQ_MODE	0	/* kernel virtual IRQ debugging */
#define	DebugKVMIRQ(fmt, args...)					\
({									\
	if (DEBUG_KVM_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_DIRECT_IRQ_MODE
#undef	DebugDIRQ
#define	DEBUG_DIRECT_IRQ_MODE	0	/* direct IRQ injection debugging */
#define	DebugDIRQ(fmt, args...)						\
({									\
	if (DEBUG_DIRECT_IRQ_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_TIME_INTR_MODE
#undef	DebugKVMTI
#define	DEBUG_KVM_TIME_INTR_MODE	0	/* KVM timer interrupt */
						/* debugging */
#define	DebugKVMTI(fmt, args...)					\
({									\
	if (DEBUG_KVM_TIME_INTR_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_TIMER_MODE
#undef	DebugKVMTM
#define	DEBUG_KVM_TIMER_MODE	0	/* KVM timer debugging */
#define	DebugKVMTM(fmt, args...)					\
({									\
	if (DEBUG_KVM_TIMER_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#define KVM_SHIFT 22

/* Xen may fire a timer up to this many ns early */
#define TIMER_SLOP	100000
#define NS_PER_TICK	(1000000000LL / HZ)
#define NSEC_AT_SEC	1000000000LL

/* snapshots of runstate info */
static DEFINE_PER_CPU(kvm_runstate_info_t, kvm_runstate_snapshot);

/* unused ns of stolen and blocked time */
static DEFINE_PER_CPU(u64, kvm_residual_stolen);
static DEFINE_PER_CPU(u64, kvm_residual_blocked);

extern ktime_t tick_period;

/*
 * Runstate accounting
 */
static u64 get_runstate_snapshot(kvm_runstate_info_t *res)
{
	kvm_runstate_info_t *state;
	u64 state_time;
	u64 cur_time;

	BUG_ON(preemptible());

	state = kvm_vcpu_runstate_info();

	/*
	 * The runstate info is always updated by the hypervisor on
	 * the current CPU, so there's no need to use anything
	 * stronger than a compiler barrier when fetching it.
	 */
	do {
		state_time = state->state_entry_time;
		rmb();	/* wait for all read completed */
		*res = *state;
		barrier();
		cur_time = HYPERVISOR_get_host_runstate_ktime();
	} while (state->state_entry_time != state_time);
	return cur_time;
}

static unsigned long get_running_time(bool early)
{
	kvm_runstate_info_t state;
	u64 now;
	u64 running;
	u64 in_hcall;
	u64 blocked;

	now = get_runstate_snapshot(&state);

	WARN_ON(!early && state.state != RUNSTATE_running);

	running = state.time[RUNSTATE_running];
	in_hcall = state.time[RUNSTATE_in_hcall];
	blocked = state.time[RUNSTATE_blocked];
	if (running == 0) {
		E2K_LMS_HALT_OK;
	}
	DebugKVMTM("time running 0x%llx in hcall 0x%llx blocked 0x%llx "
		"now 0x%llx\n",
		running, in_hcall, blocked, now);
	if (now < state.state_entry_time)
		now = state.state_entry_time;
	running += (now - state.state_entry_time);
	DebugKVMTM("time runnable 0x%llx in QEMU 0x%llx in trap 0x%llx\n",
		state.time[RUNSTATE_runnable],
		state.time[RUNSTATE_in_QEMU],
		state.time[RUNSTATE_in_trap]);
	DebugKVMTM("entry time 0x%llx running 0x%llx total 0x%llx\n",
		state.state_entry_time, running, running + in_hcall + blocked);

	return running + in_hcall + blocked;
}

static void do_stolen_accounting(int cpu, bool early)
{
	kvm_runstate_info_t state;
	kvm_runstate_info_t *snap;
	s64 blocked, runnable, in_QEMU, in_trap, offline, stolen;
	u64 ticks;

	get_runstate_snapshot(&state);

	WARN_ON(!early && state.state != RUNSTATE_running);

	snap = &per_cpu(kvm_runstate_snapshot, cpu);

	/* work out how much time the VCPU has not been runn*ing*  */
	blocked = state.time[RUNSTATE_blocked] - snap->time[RUNSTATE_blocked];
	runnable = state.time[RUNSTATE_runnable] -
				snap->time[RUNSTATE_runnable];
	in_QEMU = state.time[RUNSTATE_in_QEMU] - snap->time[RUNSTATE_in_QEMU];
	in_trap = state.time[RUNSTATE_in_trap] - snap->time[RUNSTATE_in_trap];
	offline = state.time[RUNSTATE_offline] - snap->time[RUNSTATE_offline];

	*snap = state;

	/*
	 * Add the appropriate number of ticks of stolen time,
	 * including any left-overs from last time.
	 */
	stolen = runnable + in_QEMU + in_trap + offline +
			per_cpu(kvm_residual_stolen, cpu);

	if (stolen < 0)
		stolen = 0;

	ticks = iter_div_u64_rem(stolen, NS_PER_TICK, &stolen);
	per_cpu(kvm_residual_stolen, cpu) = stolen;

//	account_steal_ticks(ticks);

	/*
	 * Add the appropriate number of ticks of blocked time,
	 * including any left-overs from last time.
	 */
	blocked += per_cpu(kvm_residual_blocked, cpu);

	if (blocked < 0)
		blocked = 0;

	ticks = iter_div_u64_rem(blocked, NS_PER_TICK, &blocked);
	per_cpu(kvm_residual_blocked, cpu) = blocked;

	account_idle_ticks(ticks);
}

int kvm_read_current_timer(unsigned long *timer_val)
{
	*timer_val = get_running_time(false);
	return 0;
}

static void kvm_read_wallclock(struct timespec64 *ts)
{
	kvm_time_t *time_info = kvm_vcpu_time_info();
	long sec;

	do {
		sec = time_info->wall_time.tv_sec;
		ts->tv_sec = sec;
		ts->tv_nsec = time_info->wall_time.tv_nsec;
		rmb();	/* wait for all read completed */
	} while (sec != time_info->wall_time.tv_sec);
}

static void kvm_get_host_timeofday(struct timespec64 *ts)
{
	kvm_time_t *time_info = kvm_vcpu_time_info();
	long sec;

	do {
		sec = time_info->sys_time.tv_sec;
		ts->tv_sec = sec;
		ts->tv_nsec = time_info->sys_time.tv_nsec;
		rmb();	/* wait for all read completed */
	} while (sec != time_info->sys_time.tv_sec);
}

u64 kvm_clocksource_read(void)
{
	kvm_time_t *time_info = kvm_vcpu_time_info();
	long nsec;
	long sec;

	do {
		sec = time_info->sys_time.tv_sec;
		nsec = time_info->sys_time.tv_nsec;
		rmb();	/* wait for all read completed */
	} while (sec != time_info->sys_time.tv_sec);
	return sec * NSEC_AT_SEC + nsec;
}

static u64 kvm_clocksource_get_cycles(struct clocksource *cs)
{
	return kvm_clocksource_read();
}

unsigned long kvm_get_wallclock(void)
{
	struct timespec64 ts;

	kvm_read_wallclock(&ts);
	return ts.tv_sec;
}

int kvm_set_wallclock(unsigned long now)
{
	/* do nothing for domU */
	return -1;
}

void __init kvm_clock_init(void)
{
	machine.set_wallclock = &kvm_set_wallclock;
	machine.get_wallclock = &kvm_get_wallclock;
}

static struct clocksource kvm_clocksource __read_mostly = {
	.name = "kvm_clock",
	.rating = 400,
	.read = kvm_clocksource_get_cycles,
	.mask = ~0,
	.mult = 1 << KVM_SHIFT,		/* time directly in nanoseconds */
	.shift = KVM_SHIFT,
	.flags = CLOCK_SOURCE_IS_CONTINUOUS,
};

/*
   KVM guest clockevent implementation

   Xen has two clockevent implementations:

   The old timer_op one works with all released versions of Xen prior
   to version 3.0.4.  This version of the hypervisor provides a
   single-shot timer with nanosecond resolution.  However, sharing the
   same event channel is a 100Hz tick which is delivered while the
   vcpu is running.  We don't care about or use this tick, but it will
   cause the core time code to think the timer fired too soon, and
   will end up resetting it each time.  It could be filtered, but
   doing so has complications when the ktime clocksource is not yet
   the xen clocksource (ie, at boot time).

   The new vcpu_op-based timer interface allows the tick timer period
   to be changed or turned off.  The tick timer is not useful as a
   periodic timer because events are only delivered to running vcpus.
   The one-shot timer can report when a timeout is in the past, so
   set_next_event is capable of returning -ETIME when appropriate.
   This interface is used when available.
*/


/*
  Get a hypervisor absolute time.  In theory we could maintain an
  offset between the kernel's time and the hypervisor's time, and
  apply that to a kernel's absolute timeout.  Unfortunately the
  hypervisor and kernel times can drift even if the kernel is using
  the Xen clocksource, because ntp can warp the kernel's clocksource.
*/
/* FIXME: the function was declared but never referenced at now */
/* static */ s64 get_abs_timeout(unsigned long delta)
{
	return kvm_clocksource_read() + delta;
}

static int kvm_timerop_shutdown(struct clock_event_device *evt)
{
	/* The 0 delta shuts the clock down. */
	HYPERVISOR_set_clockevent(0);

	return 0;
}

static int kvm_timerop_set_next_event(unsigned long delta,
				      struct clock_event_device *evt)
{
	WARN_ON(!clockevent_state_oneshot(evt));

	DebugKVMT("starts hyper call to set clockevent delta 0x%lx\n",
		delta);
	HYPERVISOR_set_clockevent(delta);

	/* We may have missed the deadline, but there's no real way of
	   knowing for sure.  If the event was in the past, then we'll
	   get an immediate interrupt. */

	return 0;
}

static const struct clock_event_device kvm_timerop_clockevent = {
	.name = "kvm_clockevent",
	.features = CLOCK_EVT_FEAT_ONESHOT,

	.max_delta_ns = 0xffffffff,
	.min_delta_ns = TIMER_SLOP,

	.mult = 1,
	.shift = 0,
	.rating = 90,

	.set_state_shutdown = kvm_timerop_shutdown,
	.set_next_event = kvm_timerop_set_next_event,
};


static const struct clock_event_device *kvm_clockevent =
	&kvm_timerop_clockevent;
static DEFINE_PER_CPU(struct clock_event_device, kvm_clock_events);
static DEFINE_PER_CPU(bool, kvm_clock_inited) = false;

static __initdata struct task_struct clock_event_early_task;
int stop_early_timer_interrupt;
static bool timer_interrupt_set = false;

#ifdef	CONFIG_DIRECT_VIRQ_INJECTION
static irqreturn_t kvm_early_timer_direct_intr(int irq, void *dev_id)
{
	struct clock_event_device *evt;
	kvm_virq_info_t *virq_info;
	int cpu = cpu_from_irq(irq);

	DebugKVMET("started for virtual IRQ #%d\n", irq);

	evt = (struct clock_event_device *)dev_id;
	virq_info = virq_info_from_irq(irq);

	if (stop_early_timer_interrupt) {
		DebugKVMET("erly timer IRQ #%d stopped\n", irq);
		return IRQ_NONE;
	}
	if (evt->event_handler) {
		DebugKVMET("will start event handler %px\n",
			evt->event_handler);

		BUG_ON(!irqs_disabled());

		evt->event_handler(evt);
		do_stolen_accounting(cpu, true);
		return IRQ_HANDLED;
	} else {
		pr_warn("%s(): early timer clock event device has not "
			"handler to run on VCPU #%d\n", __func__, cpu);
	}
	return IRQ_NONE;
}
#else	/* !CONFIG_DIRECT_VIRQ_INJECTION */
static irqreturn_t kvm_early_timer_direct_intr(int irq, void *dev_id)
{
	pr_err("%s(): direct VIRQs injection disabled, turn ON config mode to "
		"enable\n", __func__);
	return IRQ_NONE;
}
#endif	/* CONFIG_DIRECT_VIRQ_INJECTION */

static int kvm_early_setup_timer(int cpu)
{
	const char *name;
	struct clock_event_device *evt;
	unsigned long irqflags;
	int ret;

	printk(KERN_INFO "installing KVM guest early timer for CPU %d\n", cpu);

	name = kasprintf(GFP_KERNEL, "timer/%d", cpu);
	if (!name)
		name = "<timer kasprintf failed>";

	DebugKVM("kvm_clock_events %px cpu %d\n",
		&per_cpu(kvm_clock_events, cpu), cpu);
	evt = &per_cpu(kvm_clock_events, cpu);
	memcpy(evt, kvm_clockevent, sizeof(*evt));

	evt->cpumask = cpumask_of(cpu);
	evt->irq = KVM_VIRQ_TIMER;
	DebugKVM("CPU #%d timer evt %px IRQ %d mult %d\n",
		cpu, evt, evt->irq, evt->mult);
	stop_early_timer_interrupt = 0;
	global_clock_event = evt;

	irqflags = kvm_get_default_virq_flags(KVM_VIRQ_TIMER);

	if (irqflags & BY_DIRECT_INJ_VIRQ_FLAG) {
		ret = kvm_request_virq(KVM_VIRQ_TIMER,
				&kvm_early_timer_direct_intr, cpu,
				BY_DIRECT_INJ_VIRQ_FLAG,
				name, evt);
		if (ret == 0) {
			timer_interrupt_set = true;
			return 0;
		}
		DebugDIRQ("could not request direct early timer VIRQ %s "
			"injection\n", name);
	} else {
		/* unknown mode to request VIRQ delivery */
		BUG_ON(true);
		ret = -EINVAL;
	}
	if (ret) {
		panic("could not register early timer VIRQ #%d\n",
			KVM_VIRQ_TIMER);
	}
	return ret;
}

__init int kvm_setup_sw_timer(void)
{
	const char *name;
	struct clock_event_device *evt;
	ktime_t next;
	int cpu = raw_smp_processor_id();
	unsigned long irqflags;
	unsigned long flags;
	int ret;

	if (!paravirt_enabled())
		return 0;
	if (timer_interrupt_set) {
		printk(KERN_INFO "KVM guest timer for CPU %d already set\n",
			cpu);
		return 0;
	}
	printk(KERN_INFO "installing KVM guest timer for CPU %d\n", cpu);

	name = kasprintf(GFP_KERNEL, "timer/%d", cpu);
	if (!name)
		name = "<timer kasprintf failed>";

	evt = &per_cpu(kvm_clock_events, cpu);
	if (evt != global_clock_event) {
		memcpy(evt, kvm_clockevent, sizeof(*evt));
		evt->cpumask = cpumask_of(cpu);
		evt->irq = KVM_VIRQ_TIMER;
		DebugKVM("CPU #%d timer evt %px mult %d\n",
			cpu, evt, evt->mult);
	}
	/* stop early timer handler */
	clockevents_shutdown(evt);

	irqflags = kvm_get_default_virq_flags(KVM_VIRQ_TIMER);

	ret = -ENOSYS;
	if (irqflags & BY_DIRECT_INJ_VIRQ_FLAG) {
		ret = kvm_request_virq(KVM_VIRQ_TIMER,
				&kvm_early_timer_direct_intr, cpu,
				BY_DIRECT_INJ_VIRQ_FLAG,
				name, evt);
		if (ret == 0) {
			goto ok;
		}
		DebugDIRQ("could not request direct timer VIRQ %s "
			"injection\n", name);
	} else {
		BUG();
	}
	if (ret) {
		panic("could not register timer VIRQ #%d for CPU #%d\n",
			KVM_VIRQ_TIMER, cpu);
	}
ok:
	local_irq_save(flags);
	DebugKVM("timer next event 0x%llx current time 0x%llx period 0x%llx\n",
		ktime_to_ns(evt->next_event), ktime_to_ns(ktime_get()),
		ktime_to_ns(TICK_NSEC));
	next = ktime_add(ktime_get(), TICK_NSEC);
	DebugKVM("set timer next event 0x%llx\n",
		ktime_to_ns(next));
/* FIXME: not implemented how program next event
	if (clockevents_program_event(evt, next, ktime_get()))
		panic("could not programm timer events for VCPU #%d\n",
			cpu);
*/
	local_irq_restore(flags);

	DebugKVM("KVM guest timer for CPU %d installed\n", cpu);
	return ret;
}

static __init int kvm_setup_timer(void)
{
	if (IS_HV_GM())
		return 0;

	return kvm_setup_sw_timer();
}
early_initcall(kvm_setup_timer);

static void kvm_teardown_timer(int cpu)
{
	struct clock_event_device *evt;
	evt = &per_cpu(kvm_clock_events, cpu);
	kvm_free_virq(KVM_VIRQ_TIMER, cpu, evt);
}

static void kvm_setup_cpu_clockevents(void)
{
	BUG_ON(preemptible());

	clockevents_register_device(this_cpu_ptr(&kvm_clock_events));
	__this_cpu_write(kvm_clock_inited, true);
}

/* FIXME: should be implemented some other way */
void kvm_wait_timer_tick(void)
{
	unsigned long start_jiffies;

	start_jiffies = jiffies;
	do {
		barrier();
	} while (jiffies == start_jiffies);
}

static void kvm_timer_resume(void)
{
	int cpu = smp_processor_id();

	DebugKVM("started on CPU #%d\n", cpu);
	stop_early_timer_interrupt = 1;
	if (!__this_cpu_read(kvm_clock_inited))
		return;
	clockevents_shutdown(this_cpu_ptr(&kvm_clock_events));
	clocksource_unregister(&kvm_clocksource);
	__this_cpu_write(kvm_clock_inited, false);
	kvm_teardown_timer(cpu);
}

static int
kvm_timer_panic(struct notifier_block *this, unsigned long event, void *ptr)
{
	kvm_timer_resume();

	return NOTIFY_DONE;
}

static struct notifier_block resume_block = {
	.notifier_call = kvm_timer_panic,
};

__init void kvm_time_init_clockevents(void)
{
	int cpu = smp_processor_id();
	int ret;

	kvm_virqs_init(cpu);
	/* Local APIC support on guest is not ready at present time, */
	/* so temporarly disable APIC timer */
	disable_apic_timer = true;
#ifdef CONFIG_EPIC
	/* Same with CEPIC paravirt model. Do not disable timer for HW EPIC */
	disable_epic_timer = true;
#endif

	ret = kvm_early_setup_timer(cpu);
	if (ret) {
		pr_err("%s(): could not setup guest timer, error %d\n",
			__func__, ret);
		clocksource_unregister(&kvm_clocksource);
		return;
	}
	kvm_setup_cpu_clockevents();
	atomic_notifier_chain_register(&panic_notifier_list, &resume_block);
}

__init void kvm_time_init_clocksource(void)
{
	struct timespec64 tp;

	clocksource_register_hz(&kvm_clocksource, NSEC_PER_SEC);

	/* Set initial system time with full resolution */
	kvm_read_wallclock(&tp);
	do_settimeofday64(&tp);
}

__init void kvm_time_init(void)
{
	struct timespec64 tp;

	kvm_setup_boot_local_pic_virq();

	native_time_init();

	if (IS_HV_GM())
		return;

	/* Set initial system time with full resolution */
	kvm_get_host_timeofday(&tp);
	do_settimeofday64(&tp);

	timer_interrupt_set = true;
	if (timer_interrupt_set)
		return;

	kvm_time_init_clockevents();
	kvm_time_init_clocksource();
}

void kvm_time_shutdown(void)
{
	if (IS_HV_GM())
		return;

	kvm_timer_resume();
}
