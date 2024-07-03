/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*P:800
 * Interrupts (traps) are complicated enough to earn their own file.
 * There are three classes of interrupts:
 *
 * 1) Real hardware interrupts which occur while we're running the Guest,
 * 2) Interrupts for virtual devices attached to the Guest, and
 * 3) Traps and faults from the Guest.
 *
 * Real hardware interrupts must be delivered to the Host, not the Guest.
 * Virtual interrupts must be delivered to the Guest, but we make them look
 * just like real hardware would deliver them.  Traps from the Guest can be set
 * up to go directly back into the Guest, but sometimes the Host wants to see
 * them first, so we also have a way of "reflecting" them into the Guest as if
 * they had been delivered to it directly.
:*/
#include <linux/uaccess.h>
#include <linux/interrupt.h>
#include <linux/export.h>
#include <linux/sched.h>
#include <linux/kvm_host.h>
#include <asm/e2k_debug.h>
#include <asm/kvm/irq.h>
#include <asm/kvm/guest/irq.h>
#include <asm/kvm/runstate.h>

#include "pic.h"
#include "irq.h"

#undef	DEBUG_KVM_MODE
#undef	DebugKVM
#define	DEBUG_KVM_MODE	0	/* kernel virtual machine debugging */
#define	DebugKVM(fmt, args...)						\
({									\
	if (DEBUG_KVM_MODE || kvm_debug)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_TIME_MODE
#undef	DebugKVMT
#define	DEBUG_KVM_TIME_MODE	0	/* KVM time/timer debugging */
#define	DebugKVMT(fmt, args...)						\
({									\
	if (DEBUG_KVM_TIME_MODE)					\
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

#undef	DEBUG_KVM_APIC_TIMER_MODE
#undef	DebugKVMAT
#define	DEBUG_KVM_APIC_TIMER_MODE	0	/* KVM LAPIC timer debugging */
#define	DebugKVMAT(fmt, args...)					\
({									\
	if (DEBUG_KVM_APIC_TIMER_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#define	HRTIMER_EXPIRES_PERCENT		90	/* percents */
/* If hrtimer expires on HRTIMER_EXPIRES_PERCENTs it does not reactivate */
#define	HRTIMER_EXPIRES_APPROX(time)	\
		(((time) / 100) * HRTIMER_EXPIRES_PERCENT)

/*H:200
 * The Guest Timer.
 *
 * The Guest uses the LHCALL_SET_CLOCKEVENT hypercall to tell us how long to
 * the next timer interrupt (in nanoseconds).  We use the high-resolution timer
 * infrastructure to set a callback at that time.
 *
 * 0 means "turn off the clock".
 * FIXME: clock device should be on each VCPU
 */
static ktime_t expires;
void kvm_guest_set_clockevent(struct kvm_vcpu *vcpu, unsigned long delta)
{
	ktime_t real_time;

	DebugKVMTM("started for delta %ld\n", delta);
	if (unlikely(delta == 0)) {
		/* Clock event device is shutting down. */
		hrtimer_cancel(&vcpu->arch.hrt);
		DebugKVM("Clock event device is shutting down\n");
		return;
	}

	/*
	 * We use wallclock time here, so the Guest might not be running for
	 * all the time between now and the timer interrupt it asked for.  This
	 * is almost always the right thing to do.
	 */
	real_time = ktime_get();
	if (ktime_to_ns(real_time) - ktime_to_ns(expires) >
		(delta + (delta >> 4))) {
		DebugKVMTM("current time 0x%llx too bigger of expires time "
			"0x%llx jiffies 0x%lx\n",
			ktime_to_ns(real_time), ktime_to_ns(expires),
			jiffies);
	} else {
		DebugKVMTM("current time 0x%llx, expires time "
			"0x%llx jiffies 0x%lx\n",
			ktime_to_ns(real_time), ktime_to_ns(expires),
			jiffies);
	}

again:
	if (!hrtimer_active(&vcpu->arch.hrt)) {
		vcpu->arch.hrt_period = delta;
		expires = ktime_add_ns(real_time, delta);
		hrtimer_start(&vcpu->arch.hrt, expires, HRTIMER_MODE_ABS);
		vcpu->arch.hrt_running_start =
			kvm_get_guest_vcpu_running_time(vcpu);
		DebugKVMTM("starts hrtimer for expires time 0x%llx "
			"current 0x%llx\n",
			ktime_to_ns(expires), ktime_to_ns(real_time));
	} else if (hrtimer_callback_running(&vcpu->arch.hrt)) {
		BUG_ON(vcpu->arch.hrt_period != 0);
		hrtimer_add_expires_ns(&vcpu->arch.hrt, delta);
		vcpu->arch.hrt_period = delta;
		vcpu->arch.hrt_running_start =
			kvm_get_guest_vcpu_running_time(vcpu);
		DebugKVMTM("hrtimer is in interrupt handler now, "
			"so only restart\n");
	} else {
		/* timer is active probably is completing, so waiting */
		DebugKVMTM("hrtimer is completing, small waiting\n");
		cpu_relax();
		goto again;
	}
}

/* This is the function called when the Guest's timer expires. */
static enum hrtimer_restart clockdev_fn(struct hrtimer *timer)
{
	struct kvm_vcpu *vcpu = container_of(timer, struct kvm_vcpu, arch.hrt);
	int irq = vcpu->arch.hrt_virq_no;
	long period = vcpu->arch.hrt_period;
	s64 running_start;
	s64 running_time;
	s64 running;

	/* Remember the first interrupt is the timer interrupt. */
	DebugKVMTM("process %s (%d): started to set local timer IRQ #%d "
		"on VCPU #%d\n",
		current->comm, current->pid, irq, vcpu->vcpu_id);
	running_start = vcpu->arch.hrt_running_start;
	running_time = kvm_get_guest_vcpu_running_time(vcpu);
	running = cycles_2nsec(running_time - running_start);
	BUG_ON(running < 0);
	if (running < HRTIMER_EXPIRES_APPROX(period)) {
		hrtimer_add_expires_ns(&vcpu->arch.hrt,
					(period - running));
		return HRTIMER_RESTART;
	}
	vcpu->arch.hrt_period = 0;	/* signal timer interrupt happened */
					/* to clock event program function */
	kvm_vcpu_interrupt(vcpu, irq);

	if (vcpu->arch.hrt_period != 0) {
		/* the timer was reprogrammed, so restart timer */
		return HRTIMER_RESTART;
	}
	return HRTIMER_NORESTART;
}

/* This sets up the timer for the VCPU */
void kvm_init_clockdev(struct kvm_vcpu *vcpu)
{
	DebugKVM("started to set up the early timer for the VCPU #%d\n",
		vcpu->vcpu_id);

	if (vcpu->arch.is_hv && kvm_vcpu_is_bsp(vcpu)) {
		int ret, irq;

		irq = vcpu->vcpu_id * KVM_NR_VIRQS_PER_CPU + KVM_VIRQ_TIMER;
		ret = kvm_get_guest_direct_virq(vcpu, irq, KVM_VIRQ_TIMER);
		if (ret != 0) {
			pr_err("%s(): could not register early timer "
				"VIRQ #%d on VCPU #%d\n",
				__func__,
				KVM_VIRQ_TIMER +
					(KVM_NR_VIRQS_PER_CPU * vcpu->vcpu_id),
				vcpu->vcpu_id);
			E2K_KVM_BUG_ON(true);
		}
		DebugKVM("VCPU #%d VIRQ #%d %s was registered on host "
			"as IRQ #%d\n",
			vcpu->vcpu_id, KVM_VIRQ_TIMER,
			kvm_get_virq_name(KVM_VIRQ_TIMER), irq);
	}
	hrtimer_init(&vcpu->arch.hrt, CLOCK_MONOTONIC, HRTIMER_MODE_ABS);
	vcpu->arch.hrt.function = clockdev_fn;
	DebugKVM("created early timer for the VCPU #%d at %px base 0x%lx\n",
		vcpu->vcpu_id, &vcpu->arch.hrt, vcpu->arch.hrt.base);
}

void kvm_cancel_clockdev(struct kvm_vcpu *vcpu)
{
	DebugKVM("started to cancel the timer for the VCPU #%d\n",
		vcpu->vcpu_id);
	if (unlikely(vcpu->arch.hrt.base == NULL)) {
		return;	/* is not yet inited */
	}
	/* Clock event device is shutting down. */
	hrtimer_cancel(&vcpu->arch.hrt);
	DebugKVM("VCPU #%d early timer at %px was shutting down\n",
		vcpu->vcpu_id, &vcpu->arch.hrt);
	if (vcpu->arch.apic != NULL) {
		hrtimer_cancel(&vcpu->arch.apic->lapic_timer.timer);
		DebugKVM("VCPU #%d local apic timer at %px was shutting down\n",
			vcpu->vcpu_id, &vcpu->arch.apic->lapic_timer.timer);
	}
}

static void
do_kvm_apic_timer_fn(struct kvm_vcpu *vcpu)
{
	DebugKVMAT("will inject apic timer IRQ on VCPU #%d\n", vcpu->vcpu_id);
	kvm_inject_apic_timer_irqs(vcpu);
}

enum hrtimer_restart kvm_apic_timer_fn(struct hrtimer *data)
{
	struct kvm_vcpu *vcpu;
	struct kvm_timer *ktimer = container_of(data, struct kvm_timer, timer);
	struct kvm_lapic *apic;
	s64 period = ktimer->period;
	s64 running_start;
	s64 running_now;
	s64 running;
	bool handled = false;

	vcpu = ktimer->vcpu;
	if (!vcpu)
		return HRTIMER_NORESTART;

	DebugKVMAT("started on VCPU #%d\n", vcpu->vcpu_id);

	/* stolen time should be accounted and if it is considerable */
	/* the timer should be restarted on stolen time */
	apic = vcpu->arch.apic;
	if (apic == NULL)
		return HRTIMER_NORESTART;
	running_start = apic->lapic_timer.running_time;
	running_now = kvm_get_guest_vcpu_running_time(vcpu);
	running = cycles_2nsec(running_now - running_start);
/*	BUG_ON(running < 0);	probably it starts on other CPU */
	DebugKVMAT("running start 0x%llx now 0x%llx ns 0x%llx period 0x%llx\n",
		running_start, running_now, running, period);
	if (running < 0)
		running = 0;
	if (running < HRTIMER_EXPIRES_APPROX(period) &&
		/*
		 * Do not allow the guest to program periodic timers with small
		 * interval, since the hrtimers are not throttled by the host
		 * scheduler.
		 */
		(period - running) >= NSEC_PER_MSEC / 2) {
		hrtimer_add_expires_ns(&ktimer->timer, (period - running));
		DebugKVMAT("apic timer add expires 0x%llx and restarted\n",
			period - running);
		return HRTIMER_RESTART;
	}

	/*
	 * There is a race window between reading and incrementing, but we do
	 * not care about potentially loosing timer events in the !reinject
	 * case anyway.
	 */
	if (ktimer->reinject || !atomic_read(&ktimer->pending)) {
		atomic_inc(&ktimer->pending);
	}
	if (apic_has_pending_timer(vcpu)) {
		ktimer->period = 0;	/* signal timer interrupt is handling */
					/* to lapic timer start function */
		do_kvm_apic_timer_fn(vcpu);
		handled = true;
	}

	if (ktimer->t_ops->is_periodic(ktimer)) {
		apic->lapic_timer.running_time =
			kvm_get_guest_vcpu_running_time(apic->vcpu);
		ktimer->period = period;
		hrtimer_add_expires_ns(&ktimer->timer, period);
		DebugKVMAT("apic periodic timer add expires 0x%llx and "
			"restarted\n", period);
		return HRTIMER_RESTART;
	}
	if (handled && ktimer->period != 0) {
		/* the timer was reprogrammed, so restart timer */
		return HRTIMER_RESTART;
	}
	DebugKVMAT("apic timer handles\n");
	return HRTIMER_NORESTART;
}

static void
do_kvm_epic_timer_fn(struct kvm_vcpu *vcpu)
{
	DebugKVMAT("will inject epic timer IRQ on VCPU #%d\n", vcpu->vcpu_id);
	kvm_inject_epic_timer_irqs(vcpu);
}

enum hrtimer_restart kvm_epic_timer_fn(struct hrtimer *data)
{
	struct kvm_vcpu *vcpu;
	struct kvm_timer *ktimer = container_of(data, struct kvm_timer, timer);
	struct kvm_cepic *epic;
	s64 period = ktimer->period;
	s64 running_start;
	s64 running_now;
	s64 running;
	bool handled = false;

	vcpu = ktimer->vcpu;
	if (!vcpu)
		return HRTIMER_NORESTART;

	DebugKVMAT("started on VCPU #%d\n", vcpu->vcpu_id);

	/* stolen time should be accounted and if it is considerable */
	/* the timer should be restarted on stolen time */
	epic = vcpu->arch.epic;
	if (epic == NULL)
		return HRTIMER_NORESTART;
	running_start = epic->cepic_timer.running_time;
	running_now = kvm_get_guest_vcpu_running_time(vcpu);
	running = cycles_2nsec(running_now - running_start);
/*	BUG_ON(running < 0);	probably it starts on other CPU */
	DebugKVMAT("running start 0x%llx now 0x%llx ns 0x%llx period 0x%llx\n",
		running_start, running_now, running, period);
	if (running < 0)
		running = 0;
	if (running < HRTIMER_EXPIRES_APPROX(period) &&
		/*
		 * Do not allow the guest to program periodic timers with small
		 * interval, since the hrtimers are not throttled by the host
		 * scheduler.
		 */
		(period - running) >= NSEC_PER_MSEC / 2) {
		hrtimer_add_expires_ns(&ktimer->timer, (period - running));
		DebugKVMAT("epic timer add expires 0x%llx and restarted\n",
			period - running);
		return HRTIMER_RESTART;
	}

	/*
	 * There is a race window between reading and incrementing, but we do
	 * not care about potentially losing timer events in the !reinject
	 * case anyway.
	 */
	if (ktimer->reinject || !atomic_read(&ktimer->pending))
		atomic_inc(&ktimer->pending);

	if (epic_has_pending_timer(vcpu)) {
		ktimer->period = 0;	/* signal timer interrupt is handling */
					/* to cepic timer start function */
		do_kvm_epic_timer_fn(vcpu);
		handled = true;
	}

	if (ktimer->t_ops->is_periodic(ktimer)) {
		epic->cepic_timer.running_time =
			kvm_get_guest_vcpu_running_time(epic->vcpu);
		ktimer->period = period;
		hrtimer_add_expires_ns(&ktimer->timer, period);
		DebugKVMAT("epic periodic timer add expires 0x%llx restarted\n",
			period);
		return HRTIMER_RESTART;
	}
	if (handled && ktimer->period != 0) {
		/* the timer was reprogrammed, so restart timer */
		return HRTIMER_RESTART;
	}
	DebugKVMAT("epic timer handles\n");
	return HRTIMER_NORESTART;
}
