/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Virtual IRQ manager
 */

#include <linux/types.h>
#include <linux/err.h>
#include <linux/kvm_host.h>
#include <linux/kvm.h>
#include <asm/process.h>
#include <asm/e2k_debug.h>
#include "process.h"
#include "irq.h"
#include "time.h"
#include "lapic.h"
#include "intercepts.h"

#undef	DEBUG_KVM_MODE
#undef	DebugKVM
#define	DEBUG_KVM_MODE	0	/* kernel virtual machine debugging */
#define	DebugKVM(fmt, args...)						\
({									\
	if (DEBUG_KVM_MODE || kvm_debug)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_THREAD_MODE
#undef	DebugKVMT
#define	DEBUG_KVM_THREAD_MODE	0	/* KVM thread debugging */
#define	DebugKVMT(fmt, args...)						\
({									\
	if (DEBUG_KVM_THREAD_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_IRQ_MODE
#undef	DebugKVMIRQ
#define	DEBUG_KVM_IRQ_MODE	0	/* KVM IRQ manage debugging */
#define	DebugKVMIRQ(fmt, args...)					\
({									\
	if (DEBUG_KVM_IRQ_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_DIRECT_VIRQ_MODE
#undef	DebugDVIRQ
#define	DEBUG_KVM_DIRECT_VIRQ_MODE	0	/* KVM direct IRQ manage */
						/* debugging */
#define	DebugDVIRQ(fmt, args...)					\
({									\
	if (DEBUG_KVM_DIRECT_VIRQ_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_GET_VIRQ_MODE
#undef	DebugGVIRQ
#define	DEBUG_KVM_GET_VIRQ_MODE	0	/* KVM get & register IRQ debug */
#define	DebugGVIRQ(fmt, args...)					\
({									\
	if (DEBUG_KVM_GET_VIRQ_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_INTR_MODE
#undef	DebugKVMINTR
#define	DEBUG_KVM_INTR_MODE	0	/* KVM interrupt recieve debugging */
#define	DebugKVMINTR(fmt, args...)					\
({									\
	if (DEBUG_KVM_INTR_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_INJECT_INTR_MODE
#undef	DebugKVMII
#define	DEBUG_KVM_INJECT_INTR_MODE	0	/* KVM interrupt injection */
						/* debugging */
#define	DebugKVMII(fmt, args...)					\
({									\
	if (DEBUG_KVM_INJECT_INTR_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_INJECT_NMI_MODE
#undef	DebugKVMNMI
#define	DEBUG_KVM_INJECT_NMI_MODE	0	/* KVM not masked interrupt */
						/* injection debugging */
#define	DebugKVMNMI(fmt, args...)					\
({									\
	if (DEBUG_KVM_INJECT_NMI_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_SHUTDOWN_MODE
#undef	DebugKVMSH
#define	DEBUG_KVM_SHUTDOWN_MODE	0	/* KVM shutdown debugging */
#define	DebugKVMSH(fmt, args...)					\
({									\
	if (DEBUG_KVM_SHUTDOWN_MODE || kvm_debug)			\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

extern bool debug_VIRQs;
#undef	DEBUG_KVM_VIRQs_MODE
#undef	DebugVIRQs
#define	DEBUG_KVM_VIRQs_MODE	0	/* VIRQs debugging */
#define	DebugVIRQs(fmt, args...)					\
({									\
	if (DEBUG_KVM_VIRQs_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#define CREATE_TRACE_POINTS
#include "trace-virq.h"

static void kvm_register_vcpu_interrupt(struct kvm_vcpu *vcpu,
		int irq, int virq_id);
static int kvm_wake_up_virq(kvm_guest_virq_t *guest_virq,
				bool inject, bool do_wake_up);

int debug_guest_virqs = 0;

static int find_irq_on_virq_id(struct kvm *kvm, int vcpu_id, int virq_id)
{
	kvm_guest_virq_t *guest_virq;
	unsigned long flags;
	int irq;

	raw_spin_lock_irqsave(&kvm->arch.virq_lock, flags);
	for (irq = 0; irq < KVM_MAX_NR_VIRQS; irq++) {
		guest_virq = &kvm->arch.guest_virq[irq];
		if (guest_virq->flags == 0)
			continue;
		if (guest_virq->virq_id != virq_id)
			continue;
		E2K_KVM_BUG_ON(guest_virq->vcpu == NULL);
		if (guest_virq->vcpu->vcpu_id == vcpu_id) {
			raw_spin_unlock_irqrestore(&kvm->arch.virq_lock, flags);
			return irq;
		}
	}
	raw_spin_unlock_irqrestore(&kvm->arch.virq_lock, flags);
	return -1;
}

#ifdef	CONFIG_DIRECT_VIRQ_INJECTION
int kvm_get_guest_direct_virq(struct kvm_vcpu *vcpu, int irq, int virq_id)
{
	struct kvm *kvm = vcpu->kvm;
	kvm_guest_virq_t *guest_virq;
	int old_irq;

	DebugGVIRQ("started on VCPU #%d for IRQ #%d VIRQ ID #%d\n",
		vcpu->vcpu_id, irq, virq_id);
	if (virq_id >= KVM_NR_VIRQS) {
		DebugGVIRQ("invalid VIRQ ID #%d for IRQ #%d\n",
			virq_id, irq);
		return -EINVAL;
	}
	if (irq >= KVM_MAX_NR_VIRQS) {
		DebugGVIRQ("invalid IRQ num #%d VIRQ ID #%d\n",
			irq, virq_id);
		return -EINVAL;
	}
	old_irq = find_irq_on_virq_id(vcpu->kvm, vcpu->vcpu_id, virq_id);
	if (likely(old_irq < 0)) {
		/* VIRQ has not been registered */
		;
	} else if (old_irq == irq) {
		pr_warn("%s(): VIRQ #%d %s has been already registered "
			"as IRQ #%d on VCPU #%d\n",
			__func__, virq_id, kvm_get_virq_name(virq_id),
			old_irq, vcpu->vcpu_id);
		return 0;
	} else {
		pr_err("%s(): VIRQ #%d %s has been already registered "
			"on VCPU #%d as IRQ #%d instead of #%d\n",
			__func__, virq_id, kvm_get_virq_name(virq_id),
			vcpu->vcpu_id, old_irq, irq);
		return -EEXIST;
	}
	raw_spin_lock(&kvm->arch.virq_lock);
	guest_virq = &kvm->arch.guest_virq[irq];
	if (guest_virq->vcpu != NULL) {
		raw_spin_unlock(&kvm->arch.virq_lock);
		pr_err("%s(): IRQ #%d VIRQ #%d %s was already registered "
			"on VCPU #%d\n",
			__func__, irq, virq_id, kvm_get_virq_name(virq_id),
			guest_virq->vcpu->vcpu_id);
		return -EEXIST;
	}
	guest_virq->virq_id = virq_id;
	guest_virq->host_task = current;
	guest_virq->vcpu = vcpu;
	guest_virq->flags = DIRECT_INJ_VIRQ_FLAG;
	guest_virq->count =
		kvm_get_guest_virqs_atomic_counter(vcpu, virq_id);
	atomic_set(guest_virq->count, 0);
	kvm_register_vcpu_interrupt(vcpu, irq, virq_id);
	set_thread_flag(TIF_VIRQS_ACTIVE);
	if (irq > kvm->arch.max_irq_no)
		kvm->arch.max_irq_no = irq;
	raw_spin_unlock(&kvm->arch.virq_lock);

	if (virq_id == KVM_VIRQ_LAPIC) {
		kvm_lapic_virq_setup(vcpu);
	}

	DebugKVM("vcpu #%d virq #%d %s was registered on host as irq #%d\n",
		vcpu->vcpu_id, virq_id,
		kvm_get_virq_name(virq_id), irq);
	return 0;
}

int kvm_free_guest_direct_virq(struct kvm *kvm, int irq)
{
	kvm_guest_virq_t *guest_virq;

	DebugKVMSH("started for IRQ #%d\n", irq);
	if (irq >= KVM_MAX_NR_VIRQS) {
		DebugKVMSH("invalid IRQ num #%d\n", irq);
		return -EINVAL;
	}
	guest_virq = &kvm->arch.guest_virq[irq];
	if (guest_virq->flags == 0) {
		DebugKVMSH("IRQ #%d is not active\n", irq);
		return 0;
	}
	if (!(guest_virq->flags & DIRECT_INJ_VIRQ_FLAG)) {
		pr_err("%s(): IRQ #%d is not of direct type ???\n", __func__, irq);
		return 0;
	}
	raw_spin_lock_irq(&kvm->arch.virq_lock);
	if (guest_virq->host_task == NULL) {
		raw_spin_unlock_irq(&kvm->arch.virq_lock);
		pr_err("%s(): IRQ #%d VIRQ ID %s (#%d) is not active\n",
			__func__, irq, kvm_get_virq_name(guest_virq->virq_id),
			guest_virq->virq_id);
		return 0;
	}
	guest_virq->flags = 0;
	guest_virq->host_task = NULL;
	guest_virq->vcpu = NULL;
	clear_thread_flag(TIF_VIRQS_ACTIVE);
	raw_spin_unlock_irq(&kvm->arch.virq_lock);

	DebugKVMSH("IRQ #%d VIRQ ID %s (#%d) was deleted\n",
		irq, kvm_get_virq_name(guest_virq->virq_id),
		guest_virq->virq_id);

	return 0;
}
#else	/* !CONFIG_DIRECT_VIRQ_INJECTION */
int kvm_get_guest_direct_virq(struct kvm_vcpu *vcpu, int irq, int virq_id)
{
	pr_err("Direct VIRQ cannot be registered, turn on config flag to "
		"enable this mode\n");
	return -ENOSYS;
}
int kvm_free_guest_direct_virq(struct kvm *kvm, int irq)
{
	pr_warn("Direct VIRQ cannot be freed, turn on config flag "
		"to enable this mode\n");
	return -ENOSYS;
}
#endif	/* CONFIG_DIRECT_VIRQ_INJECTION */

static void
kvm_register_vcpu_interrupt(struct kvm_vcpu *vcpu, int irq, int virq_id)
{
	DebugGVIRQ("started for VCPU #%d IRQ #%d VIRQ ID #%d\n",
		vcpu->vcpu_id, irq, virq_id);
	switch (virq_id) {
	case KVM_VIRQ_TIMER:
		vcpu->arch.hrt_virq_no = irq;
		DebugGVIRQ("set IRQ #%d for timer VCPU #%d\n",
			irq, vcpu->vcpu_id);
		break;
	case KVM_VIRQ_LAPIC:
		WARN_ON(vcpu->arch.apic == NULL);
		vcpu->arch.apic->virq_no = irq;
		DebugGVIRQ("set IRQ #%d for local APIC of VCPU #%d\n",
			irq, vcpu->vcpu_id);
		break;
	case KVM_VIRQ_CEPIC:
		WARN_ON(vcpu->arch.epic == NULL);
		vcpu->arch.epic->virq_no = irq;
		DebugGVIRQ("set IRQ #%d for CEPIC of VCPU #%d\n",
			irq, vcpu->vcpu_id);
		break;
	case KVM_VIRQ_HVC:
		DebugGVIRQ("hvc console VIRQ, nothing to do\n");
		break;
	default:
		printk(KERN_WARNING "Bad VIRQ ID #%d\n", virq_id);
		break;
	}
}

/*
 * User Applications to support virtual machine emulation (for example QEMU)
 * can send virtual interrupts using ioctl() KVM_INTERRUPT
 * Argument 'virq_id' here is number of VIRQ from interface host <-> guest
 * see include/asm/kvm/irq.h
 */
int kvm_vcpu_ioctl_interrupt(struct kvm_vcpu *vcpu, int virq_id)
{
	int irq;

	DebugKVMINTR("started for VIRQ ID #%d on VCPU #%d\n",
		virq_id, vcpu->vcpu_id);
	irq = find_irq_on_virq_id(vcpu->kvm, vcpu->vcpu_id, virq_id);
	if (irq < 0) {
		DebugKVMINTR("could not find IRQ which VIRQ ID #%d on "
			"VCPU #%d bind to\n",
			virq_id, vcpu->vcpu_id);
		return -ENODEV;
	} else {
		DebugKVMINTR("started for VIRQ ID #%d on VCPU #%d "
			"bind to IRQ #%d\n",
			virq_id, vcpu->vcpu_id, irq);
	}
	return kvm_vcpu_interrupt(vcpu, irq);
}

/*
 * VCPU virtual IRQ handler
 * Argument 'irq' here is internel number of IRQ which guest VIRQ bind to
 * (index at table of all guest VIRQs, (VIRQ-ID, VCPU-ID) <-> IRQ)
 */
int kvm_vcpu_interrupt(struct kvm_vcpu *vcpu, int irq)
{
	struct kvm *kvm = vcpu->kvm;
	kvm_guest_virq_t *guest_virq;
	int virq_id;
	int virqs_num;
	bool do_wake_up;
	bool has_pending_virqs;
	unsigned long flags;

	DebugKVMINTR("started for virtual interrupt #%d\n", irq);
	if (irq < 0 || irq >= KVM_MAX_NR_VIRQS)
		return -EINVAL;

	raw_spin_lock_irqsave(&kvm->arch.virq_lock, flags);
	guest_virq = &kvm->arch.guest_virq[irq];

	if (guest_virq->vcpu == NULL) {
		/* virtual IRQ does not exist or register */
		pr_warn("%s(): virtual IRQ #%d does not exist or register\n",
			__func__, irq);
		raw_spin_unlock_irqrestore(&kvm->arch.virq_lock, flags);
		if (likely(kvm->arch.reboot || kvm->arch.halted)) {
			return 0;
		} else {
			return -ENODEV;
		}
	}
	if (guest_virq->stop_handler) {
		/* virtual IRQ already stopped */
		raw_spin_unlock_irqrestore(&kvm->arch.virq_lock, flags);
		return -EINTR;
	}
	virq_id = guest_virq->virq_id;
	DebugVIRQs("started for VIRQ #%d (VCPU #%d, %s)\n",
		irq, vcpu->vcpu_id, kvm_get_virq_name(virq_id));

	BUG_ON(vcpu != guest_virq->vcpu);

	has_pending_virqs = kvm_test_pending_virqs(vcpu);
	virqs_num = atomic_inc_return(guest_virq->count);
	DebugVIRQs("injected on VCPU #%d, pending flag %d VIRQs number is %d\n",
		vcpu->vcpu_id, has_pending_virqs, virqs_num);
	GTI_BUG_ON(virqs_num > MAX_PENDING_VIRQS);

	/*
	 * Common NOTE: guest VIRQs model support arbitrary number of
	 * different types and injection modes of VIRQ.
	 * But in practice only one type of VIRQs can happen after local APIC
	 * initialization (KVM_VIRQ_LAPIC). All guest IRQs will be passed
	 * through LAPIC, so virqs_num is precise counter of current pending
	 * VIRQs.
	 * At the beginning of guest kernel booting is used second type
	 * of guest VIRQs (KVM_VIRQ_TIMER) and the timer VIRQ is single too at
	 * this time, so virqs_num is too precise.
	 */
	if (!has_pending_virqs && virqs_num <= 1) {
		/* first VIRQs and none other pending VIRQs */
		/* so it can be first VIRQs or last VIRQs is handling */
		/* by guest right now. Pass new interrupt to guest */
		do_wake_up = true;
	} else if (!has_pending_virqs && virqs_num > 1) {
		/* one more VIRQs and other pending VIRQs is already handling */
		/* Do not pass new interrupt because of old interrupt is */
		/* in progress */
		do_wake_up = false;
	} else if (has_pending_virqs && virqs_num <= 1) {
		/* first VIRQS and there are other pending VIRQs */
		/* it can be if host want pass new interrupt, but guest */
		/* is now handling old interrupt and see already new VIRQ */
		/* so do not pass new interrupt, host should deliver old */
		do_wake_up = false;
	} else if (has_pending_virqs && virqs_num > 1) {
		/* one more VIRQs and there are other pending VIRQs */
		/* it can be if host should pass interrupt, but */
		/* 1) host has not still time do it, so do not pass new */
		/* interrupt, host should  deliver old */
		/* 2) guest VCPU is on idle and host should wake up guest */
		if (vcpu->arch.on_idle || vcpu->arch.on_spinlock ||
				vcpu->arch.on_csd_lock)
			do_wake_up = true;
		else
			do_wake_up = false;
	} else {
		/* unknown and impossible case */
		WARN_ON(true);
		do_wake_up = true;
	}
	trace_kvm_vcpu_interrupt(vcpu, virq_id, has_pending_virqs, virqs_num,
				 do_wake_up);
	kvm_wake_up_virq(guest_virq, true, /* inject */ do_wake_up);
	raw_spin_unlock_irqrestore(&kvm->arch.virq_lock, flags);
	return 0;
}

static inline int
kvm_wake_up_direct_virq(kvm_guest_virq_t *guest_virq,
				bool inject, bool do_wake_up)
{
	struct task_struct *task;
	int virq_id = guest_virq->virq_id;
	int virqs_num;
	int ret;

	if (!(guest_virq->flags & DIRECT_INJ_VIRQ_FLAG))
		E2K_KVM_BUG_ON(true);
	virqs_num = atomic_read(guest_virq->count);
	if (!(inject || do_wake_up)) {
		trace_kvm_virq_wake_up(guest_virq->vcpu, virq_id,
			need_not_virq_wake_up, virqs_num, inject, do_wake_up);
		return 0;
	}
	task = guest_virq->host_task;
	if (unlikely(task == NULL))
		return -EINVAL;

	virqs_num = atomic_read(guest_virq->count);
	DebugVIRQs("VIRQ %s pending counter is %d\n",
		kvm_get_virq_name(virq_id), virqs_num);
	if (virqs_num <= 0) {
		/* none pending VIRQs */
		trace_kvm_virq_wake_up(guest_virq->vcpu, virq_id,
			no_pending_virq_wake_up, virqs_num, inject, do_wake_up);
		return 0;
	}
	kvm_set_pending_virqs(guest_virq->vcpu);
	if (task == current) {
		DebugDVIRQ("current %s (%d) is VCPU thread to inject "
			"VIRQ %s\n",
			task->comm, task->pid, kvm_get_virq_name(virq_id));
		DebugVIRQs("current %s (%d) is VCPU thread to inject "
			"VIRQ %s\n",
			task->comm, task->pid, kvm_get_virq_name(virq_id));
		trace_kvm_virq_wake_up(guest_virq->vcpu, virq_id,
			current_vcpu_virq_wake_up, virqs_num, inject, do_wake_up);
		return virqs_num;
	}

	/* received some VIRQs, so activate VCPU thread if it is on idle */
	if (!(guest_virq->vcpu->arch.on_idle ||
			guest_virq->vcpu->arch.on_spinlock ||
			guest_virq->vcpu->arch.on_csd_lock)) {
		trace_kvm_virq_wake_up(guest_virq->vcpu, virq_id,
			active_vcpu_virq_wake_up, virqs_num, inject, do_wake_up);
		return virqs_num;
	}
	ret = wake_up_process(task);
	if (ret) {
		DebugDVIRQ("wakeed up guest VIRQ %s VCPU thread %s (%d)\n",
			kvm_get_virq_name(virq_id), task->comm, task->pid);
		DebugVIRQs("wakeed up guest VIRQ %s VCPU thread %s (%d)\n",
			kvm_get_virq_name(virq_id), task->comm, task->pid);
	} else {
		DebugDVIRQ("guest VIRQ %s VCPU thread already is running, "
			"pending VIRQs counter is %d\n",
			kvm_get_virq_name(virq_id), virqs_num);
		DebugVIRQs("guest VIRQ %s VCPU thread %s (%d) already "
			"is running, pending counter is %d\n",
			kvm_get_virq_name(virq_id), task->comm, task->pid,
			virqs_num);
	}
	kvm_vcpu_kick(guest_virq->vcpu);
	trace_kvm_virq_wake_up(guest_virq->vcpu, virq_id,
			vcpu_virq_waked_up, virqs_num, inject, do_wake_up);
	return virqs_num;
}

static int kvm_wake_up_virq(kvm_guest_virq_t *guest_virq,
				bool do_inject, bool do_wake_up)
{
	int virq_id = guest_virq->virq_id;
	int virqs_num;

	virqs_num = atomic_read(guest_virq->count);
	DebugVIRQs("VIRQ %s pending counter is %d\n",
		kvm_get_virq_name(virq_id), virqs_num);
	if (virqs_num <= 0) {
		/* none pending VIRQs */
		trace_kvm_virq_wake_up(guest_virq->vcpu, virq_id,
			no_pending_virq_wake_up, virqs_num, do_inject, do_wake_up);
		return 0;
	}
	if (guest_virq->flags & DIRECT_INJ_VIRQ_FLAG) {
		return kvm_wake_up_direct_virq(guest_virq,
						do_inject, do_wake_up);
	} else {
		BUG_ON(true);
	}
	return 0;
}

/*
 * spinlock (kvm->arch.virq_lock) should be take by caller
 */
int kvm_find_pending_virqs(struct kvm_vcpu *vcpu, bool inject, bool wakeup)
{
	struct kvm *kvm = vcpu->kvm;
	struct kvm_vcpu *virq_vcpu;
	kvm_guest_virq_t *guest_virq;
	int irq;
	int ret;
	int virqs_num = 0;

	for (irq = 0; irq <= kvm->arch.max_irq_no; irq++) {
		guest_virq = &kvm->arch.guest_virq[irq];
		virq_vcpu = guest_virq->vcpu;
		if (virq_vcpu == NULL || IS_ERR(virq_vcpu))
			continue;
		if (virq_vcpu != vcpu)
			continue;
		ret = atomic_read(guest_virq->count);
		virqs_num += ret;
		if (ret == 0 || !(inject || wakeup))
			continue;
		ret = kvm_wake_up_virq(guest_virq, inject, wakeup);
		if (ret < 0) {
			pr_err("%s(): waking up of VCPU #%d VIRQ #%d failed, "
				"error %d\n",
				__func__, vcpu->vcpu_id, guest_virq->virq_id,
				ret);
		}
	}
	return virqs_num;
}

/*
 * spinlock (kvm->arch.virq_lock) should be take by caller
 */
int kvm_dec_vcpu_pending_virq(struct kvm_vcpu *vcpu, int virq_no)
{
	struct kvm *kvm = vcpu->kvm;
	struct kvm_vcpu *virq_vcpu;
	kvm_guest_virq_t *guest_virq;
	int virqs_num = 0;

	guest_virq = &kvm->arch.guest_virq[virq_no];
	virq_vcpu = guest_virq->vcpu;
	if (virq_vcpu == NULL || IS_ERR(virq_vcpu))
		return 0;
	GTI_BUG_ON(virq_vcpu != vcpu);
	virqs_num = atomic_dec_return(guest_virq->count);

	if (virqs_num > 0) {
		DebugVIRQs("there are %d VIRQs on VCPU #%d\n",
			virqs_num, vcpu->vcpu_id);
	}
	return virqs_num;
}

void kvm_inject_lapic_virq(struct kvm_lapic *apic)
{
	struct kvm_vcpu *vcpu = apic->vcpu;

	DebugKVMII("started on VCPU #%d\n", vcpu->vcpu_id);
	kvm_vcpu_interrupt(vcpu, apic->virq_no);
}

void kvm_inject_cepic_virq(struct kvm_cepic *epic)
{
	struct kvm_vcpu *vcpu = epic->vcpu;

	DebugKVMII("started on VCPU #%d\n", vcpu->vcpu_id);
	DebugKVMII("epic->virq_no = %d\n", epic->virq_no);
	kvm_vcpu_interrupt(vcpu, epic->virq_no);
}

void kvm_inject_nmi(struct kvm_vcpu *vcpu)
{
	DebugKVMNMI("started on VCPU #%d\n", vcpu->vcpu_id);
	kvm_pic_nmi_deliver(vcpu);
}

void kvm_free_all_VIRQs(struct kvm *kvm)
{
	kvm_guest_virq_t *guest_virq;
	int irq;

	DebugKVMSH("started\n");
	for (irq = 0; irq <= kvm->arch.max_irq_no; irq++) {
		guest_virq = &kvm->arch.guest_virq[irq];
		if (guest_virq->flags & DIRECT_INJ_VIRQ_FLAG) {
			kvm_free_guest_direct_virq(kvm, irq);
		}
	}
}
