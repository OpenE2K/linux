/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Common API for in kernel interrupt controller
 */

#include <linux/kvm_host.h>
#include <linux/kvm_irqfd.h>
#include <linux/irq.h>
#include <trace/events/kvm.h>
#include <asm/kvm/trace_kvm.h>
#include <asm/kvm/trace_kvm_hv.h>

#include "irq.h"
#include "pic.h"
#include "ioapic.h"
#include "ioepic.h"
#include "sic-nbsr.h"
#include "../../l/kernel/irq/apic/apic-msidef.h"
#include "../../l/kernel/irq/epic/io_epic.h"

#undef	DEBUG_IRQ_DELIVER_MODE
#undef	DebugIRQ
#define	DEBUG_IRQ_DELIVER_MODE	0	/* IRQ deliver debugging */
#define	DebugIRQ(fmt, args...)						\
({									\
	if (DEBUG_IRQ_DELIVER_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

static inline int kvm_irq_line_state(unsigned long *irq_state,
				     int irq_source_id, int level)
{
	/* Logical OR for level trig interrupt */
	if (level)
		set_bit(irq_source_id, irq_state);
	else
		clear_bit(irq_source_id, irq_state);

	return !!(*irq_state);
}

static int kvm_set_ioapic_irq(struct kvm_kernel_irq_routing_entry *e,
				struct kvm *kvm, int irq_source_id, int level,
				bool line_status)
{
	struct kvm_ioapic *ioapic = kvm->arch.vioapic;
	level = kvm_irq_line_state(&ioapic->irq_states[e->irqchip.pin],
				   irq_source_id, level);

	return kvm_ioapic_set_irq(ioapic, e->irqchip.pin, level);
}

static int kvm_set_ioepic_irq(struct kvm_kernel_irq_routing_entry *e,
				struct kvm *kvm, int irq_source_id, int level,
				bool line_status)
{
	struct kvm_ioepic *ioepic = kvm->arch.ioepic;

	level = kvm_irq_line_state(&ioepic->irq_states[e->irqchip.pin],
				   irq_source_id, level);

	return kvm_ioepic_set_irq(ioepic, e->irqchip.pin, level);
}

inline static bool kvm_is_dm_lowest_prio(struct kvm_lapic_irq *irq)
{
	return irq->delivery_mode == APIC_DM_LOWEST;
}


#ifdef CONFIG_KVM_HW_VIRTUALIZATION
static u32 convert_apic_to_epic_dlvm(u32 apic_dlvm)
{
	u32 epic_dlvm;

	switch (apic_dlvm) {
	case APIC_DM_LOWEST:
	case APIC_DM_FIXED:
	case APIC_DM_EXTINT:
		epic_dlvm = CEPIC_ICR_DLVM_FIXED_EXT;
		break;
	case APIC_DM_SMI:
		epic_dlvm = CEPIC_ICR_DLVM_SMI;
		break;
	case APIC_DM_NMI:
		epic_dlvm = CEPIC_ICR_DLVM_NMI;
		break;
	case APIC_DM_INIT:
		epic_dlvm = CEPIC_ICR_DLVM_INIT;
		break;
	case APIC_DM_STARTUP:
		epic_dlvm = CEPIC_ICR_DLVM_STARTUP;
		break;
	case APIC_DM_REMRD:
	default:
		pr_err("Unsupported delivery mode %x\n", apic_dlvm);
		epic_dlvm = CEPIC_ICR_DLVM_FIXED_EXT;
		break;
	}

	return epic_dlvm;
}

static u32 convert_apic_to_epic_shorthand(u32 apic_shorthand)
{
	u32 epic_shorthand;

	switch (apic_shorthand) {
	case APIC_DEST_NOSHORT:
		epic_shorthand = CEPIC_ICR_DST_FULL;
		break;
	case APIC_DEST_SELF:
		epic_shorthand = CEPIC_ICR_DST_SELF;
		break;
	case APIC_DEST_ALLINC:
		epic_shorthand = CEPIC_ICR_DST_ALLINC;
		break;
	case APIC_DEST_ALLBUT:
		epic_shorthand = CEPIC_ICR_DST_ALLBUT;
		break;
	default:
		pr_err("Bad dest shorthand value %x\n", apic_shorthand);
		epic_shorthand = CEPIC_ICR_DST_FULL;
		break;
	}

	return epic_shorthand;
}


int kvm_irq_delivery_to_hw_apic(struct kvm *kvm, struct kvm_lapic *src,
		struct kvm_lapic_irq *irq_apic)
{
	struct kvm_cepic_irq irq_epic;
	int src_id = 0;

	irq_epic.dest_id = irq_apic->dest_id;
	irq_epic.vector = irq_apic->vector;
	irq_epic.trig_mode = irq_apic->trig_mode;
	irq_epic.delivery_mode =
		convert_apic_to_epic_dlvm(irq_apic->delivery_mode);
	irq_epic.shorthand =
		convert_apic_to_epic_shorthand(irq_apic->shorthand);
	if (src)
		src_id = kvm_vcpu_to_full_cepic_id(src->vcpu);
	else
		if (irq_epic.shorthand == CEPIC_ICR_DST_ALLBUT ||
			irq_epic.shorthand == CEPIC_ICR_DST_SELF)
			pr_err("%s(): Unknown source for vector 0x%x\n",
				__func__, irq_epic.vector);

	return kvm_irq_delivery_to_hw_epic(kvm, src_id, &irq_epic);
}
#endif

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
int kvm_irq_delivery_to_sw_apic(struct kvm *kvm, struct kvm_lapic *src,
		struct kvm_lapic_irq *irq)
{
	int r = -1;
	unsigned long i;
	struct kvm_vcpu *vcpu, *lowest = NULL;

	if (irq->dest_mode == 0 && irq->dest_id == 0xff &&
			kvm_is_dm_lowest_prio(irq))
		printk(KERN_INFO "kvm: apic: phys broadcast and lowest prio\n");

	kvm_for_each_vcpu(i, vcpu, kvm) {
		if (!kvm_apic_present(vcpu))
			continue;

		if (!kvm_apic_match_dest(vcpu, src, irq->shorthand,
					irq->dest_id, irq->dest_mode))
			continue;

		if (!kvm_is_dm_lowest_prio(irq)) {
			if (r < 0)
				r = 0;
			r += kvm_apic_set_irq(vcpu, irq);
		} else {
			if (!lowest)
				lowest = vcpu;
			else if (kvm_apic_compare_prio(vcpu, lowest) < 0)
				lowest = vcpu;
		}
	}

	if (lowest)
		r = kvm_apic_set_irq(lowest, irq);

	return r;
}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

#ifdef CONFIG_KVM_HW_VIRTUALIZATION
/* VCPU is not running now. Set bit in the PMIRR copy in hw context */
static int kvm_hw_epic_set_irq_vector(struct kvm_vcpu *vcpu, unsigned int vector)
{
	if (vector >= CEPIC_PMIRR_NR_BITS || vector == 0) {
		pr_err("Error: Invalid EPIC vector value %u\n", vector);
		return -EINVAL;
	}

	if (unlikely(epic_bgi_mode)) {
		vcpu->arch.hw_ctxt.cepic->pmirr_byte[vector] = 1;
	} else {
		unsigned int epic_pmirr = vector >> 6;
		atomic64_or(BIT_ULL_MASK(vector & 0x3f),
			    &vcpu->arch.hw_ctxt.cepic->pmirr[epic_pmirr]);
	}

	return 0;
}

/* VCPU is not running now. Set bit in the PNMIRR copy in hw context */
static int kvm_hw_epic_set_smi(struct kvm_vcpu *vcpu)
{
	union cepic_pnmirr reg = {
		.raw = 0,
		.smi = 1,
	};

	atomic_or(reg.raw, &vcpu->arch.hw_ctxt.cepic->pnmirr);

	return 0;
}

static int kvm_hw_epic_set_nm_special(struct kvm_vcpu *vcpu)
{
	union cepic_pnmirr reg = {
		.raw = 0,
		.nm_special = 1,
	};

	atomic_or(reg.raw, &vcpu->arch.hw_ctxt.cepic->pnmirr);

	return 0;
}

static int kvm_hw_epic_set_nmi(struct kvm_vcpu *vcpu)
{
	union cepic_pnmirr reg = {
		.raw = 0,
		.nmi = 1,
	};

	atomic_or(reg.raw, &vcpu->arch.hw_ctxt.cepic->pnmirr);

	return 0;
}

static int kvm_hw_epic_set_init(struct kvm_vcpu *vcpu)
{
	union cepic_pnmirr reg = {
		.raw = 0,
		.init = 1,
	};

	atomic_or(reg.raw, &vcpu->arch.hw_ctxt.cepic->pnmirr);

	return 0;
}

static int kvm_hw_epic_set_startup(struct kvm_vcpu *vcpu, unsigned int vector)
{
	union cepic_pnmirr reg = {
		.raw = 0,
		.startup = 1,
		.startup_entry = vector & CEPIC_PNMIRR_STARTUP_ENTRY,
	};

	atomic_or(reg.raw, &vcpu->arch.hw_ctxt.cepic->pnmirr);

	return 0;
}

/*
 * Lintel uses:
 * - SMI for devices, hidden from x86
 * - NM-special for broadcast IPI
 * - INIT and STARTUP for waking up a secondary CPU
 */
static int kvm_hw_epic_deliver_to_pirr(struct kvm_vcpu *vcpu, unsigned int vector,
				u8 dlvm)
{
	switch (dlvm) {
	case CEPIC_ICR_DLVM_FIXED_EXT:
	case CEPIC_ICR_DLVM_FIXED_IPI:
		return kvm_hw_epic_set_irq_vector(vcpu, vector);
	case CEPIC_ICR_DLVM_SMI:
		return kvm_hw_epic_set_smi(vcpu);
	case CEPIC_ICR_DLVM_NM_SPECIAL:
		return kvm_hw_epic_set_nm_special(vcpu);
	case CEPIC_ICR_DLVM_NMI:
		return kvm_hw_epic_set_nmi(vcpu);
	case CEPIC_ICR_DLVM_INIT:
		return kvm_hw_epic_set_init(vcpu);
	case CEPIC_ICR_DLVM_STARTUP:
		return kvm_hw_epic_set_startup(vcpu, vector);
	default:
		pr_err("IOEPIC: unsupported dlvm 0x%x (vect 0x%x)\n", dlvm,
			vector);
		return -EINVAL;
	}
}
#endif

/* vcpu->vcpu_id is either physical EPIC or APIC id */
u32 kvm_vcpu_to_full_cepic_id(const struct kvm_vcpu *vcpu)
{
	return vcpu->vcpu_id;
}

/* VCPU is running now. Send an interrupt to guest through host's ICR */
int kvm_hw_epic_deliver_to_icr(struct kvm_vcpu *vcpu, unsigned int vector, u8 dlvm)
{
	union cepic_icr reg;

	/*
	 * Wait if other IPI is currently being delivered
	 */
	epic_wait_icr_idle();

	/*
	 * Set destination in CEPIC_ICR2
	 */
	reg.raw = 0;
	reg.dst = kvm_vcpu_to_full_cepic_id(vcpu);
	reg.gst_id = vcpu->kvm->arch.vm_id;
	reg.dst_sh = CEPIC_ICR_DST_FULL;
	reg.dlvm = dlvm;
	reg.vect = vector;

	/*
	 * Send the guest interrupt
	 */
	epic_write_d(CEPIC_ICR, reg.raw);

	return 0;
}

static int kvm_epic_match_dest(int cepic_id, int src, int short_hand, int dest)
{
	int result = 0;

	DebugIRQ("cepic_id 0x%x, src 0x%x, dest 0x%x, short_hand 0x%x\n",
		   cepic_id, src, dest, short_hand);

	switch (short_hand) {
	case CEPIC_ICR_DST_FULL:
		result = cepic_id == dest;
		break;
	case CEPIC_ICR_DST_SELF:
		result = cepic_id == src;
		break;
	case CEPIC_ICR_DST_ALLBUT:
		result = cepic_id != src;
		break;
	case CEPIC_ICR_DST_ALLINC:
		result = 1;
		break;
	default:
		pr_warn("Bad dest shorthand value %x\n", short_hand);
		break;
	}

	return result;
}

static void kvm_wake_up_irq(struct kvm_vcpu *vcpu)
{
	/* There is no need to kick the target vcpu into hypervisor mode:
	 * - if it is running in guest mode then hardware EPIC support will
	 *   deliver the interrupt directly to guest's EPIC and trigger
	 *   interrupt (kernel mode) in guest;
	 * - if it is running in QEMU mode/preempted or halted then
	 *   kvm_vcpu_wake_up() will correspondingly either do nothing
	 *   or unhalt it. */
	kvm_vcpu_wake_up(vcpu);
}

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
int kvm_irq_delivery_to_sw_epic(struct kvm *kvm, int src,
		struct kvm_cepic_irq *irq)
{
	unsigned long i;
	int cepic_id;
	struct kvm_vcpu *vcpu;

	kvm_for_each_vcpu(i, vcpu, kvm) {
		cepic_id = kvm_epic_id(vcpu->arch.epic);
		if (kvm_epic_match_dest(cepic_id, src, irq->shorthand,
					irq->dest_id)) {
			int ret = kvm_epic_set_irq(vcpu, irq);

			if (ret >= 0) {
				kvm_wake_up_irq(vcpu);
			}
			return (ret >= 0) ? 0 : ret;
		}
	}

	return -ESRCH;
}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

#ifdef CONFIG_KVM_HW_VIRTUALIZATION
static int kvm_irq_delivery_to_hw_epic_single(struct kvm_vcpu *vcpu,
		const struct kvm_cepic_irq *irq)
{
	unsigned long flags;
	bool dat_active;
	int ret;

	raw_spin_lock_irqsave(&vcpu->arch.epic_dat_lock, flags);
	dat_active = vcpu->arch.epic_dat_active;
	trace_irq_delivery(irq->vector, irq->delivery_mode,
			vcpu->vcpu_id, vcpu->arch.epic_dat_active);

	if (dat_active) {
		ret = kvm_hw_epic_deliver_to_icr(vcpu, irq->vector, irq->delivery_mode);
		/*
		 * Although kvm_irq_delivery_*() functions do set the
		 * required condition for the target VCPU wake up
		 * (either in P[N]MIRR in memory or in registers),
		 * there might be a race if we do not wait for ICR.stat:
		 *
		 *       VCPU0                        VCPU1
		 * --------------------------------------------------------
		 * DAT is active
		 *                          Sees that epic_dat_active()
		 *                          is true and calls
		 *                          kvm_hw_epic_deliver_to_icr()
		 *
		 *                          Sends an IPI through ICR,
		 *                          it hits in DAT and sends
		 *                          message to target PREPIC
		 * invalidates DAT in all
		 * PREPICs (while IPI is
		 * still in flight)
		 *
		 * Checks for pending
		 * interrupts in
		 * kvm_arch_vcpu_runnable()
		 *
		 * Goes to sleep
		 *                          IPI finally arrives at
		 *                          target PREPIC and sets
		 *                          corresponding bit in
		 *                          memory PMIRR
		 *
		 * In the end VCPU0 is sleeping and does not know
		 * about the pending IPI.
		 */
		epic_wait_icr_idle();
	} else {
		ret = kvm_hw_epic_deliver_to_pirr(vcpu, irq->vector, irq->delivery_mode);
	}
	raw_spin_unlock_irqrestore(&vcpu->arch.epic_dat_lock, flags);

	if (!ret) {
		/* In [dat_active] case the target vcpu will see
		* the interrupt in kvm_vcpu_check_block() (see
		* comment before kvm_arch_vcpu_blocking()). */
		if (!dat_active)
			kvm_wake_up_irq(vcpu);
	}

	return ret;
}

int kvm_irq_delivery_to_hw_epic(struct kvm *kvm, int src,
		const struct kvm_cepic_irq *irq)
{
	struct kvm_vcpu *vcpu;
	bool delivered = false;
	int cepic_id;
	unsigned long i;
	int shorthand = irq->shorthand, dest_id = irq->dest_id;

	kvm_for_each_vcpu(i, vcpu, kvm) {
		cepic_id = kvm_vcpu_to_full_cepic_id(vcpu);
		if (!kvm_epic_match_dest(cepic_id, src, shorthand, dest_id))
			continue;

		if (!kvm_irq_delivery_to_hw_epic_single(vcpu, irq)) {
			delivered = true;
			/* Stop if there is a single destination */
			if (shorthand == CEPIC_ICR_DST_FULL ||
			    shorthand == CEPIC_ICR_DST_SELF) {
				break;
			}
		}
	}

	return delivered ? 0 : -ESRCH;
}

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
int kvm_hw_epic_sysrq_deliver(struct kvm_vcpu *vcpu)
{
	struct kvm_cepic_irq irq;

	irq.vector = vcpu->arch.sysrq_showstate_vector;
	irq.delivery_mode = CEPIC_ICR_DLVM_FIXED_EXT;
	irq.trig_mode = 0; /* Edge */
	irq.shorthand = CEPIC_ICR_DST_FULL;
	irq.dest_id = kvm_vcpu_to_full_cepic_id(vcpu);

	return kvm_irq_delivery_to_hw_epic(vcpu->kvm, 0, &irq);
}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

#ifdef CONFIG_KVM_ASYNC_PF
int kvm_hw_epic_async_pf_wake_deliver(struct kvm_vcpu *vcpu)
{
	struct kvm_cepic_irq irq;

	irq.vector = vcpu->arch.apf.apf_ready_vector;
	irq.delivery_mode = CEPIC_ICR_DLVM_FIXED_EXT;
	irq.trig_mode = 0;
	irq.shorthand = CEPIC_ICR_DST_FULL;
	irq.dest_id = kvm_vcpu_to_full_cepic_id(vcpu);

	return kvm_irq_delivery_to_hw_epic(vcpu->kvm, vcpu->vcpu_id, &irq);
}
#endif /* CONFIG_KVM_ASYNC_PF */

void kvm_int_violat_delivery_to_hw_epic(struct kvm *kvm)
{
	unsigned long i;
	struct kvm_vcpu *vcpu;

	kvm_for_each_vcpu(i, vcpu, kvm)
		set_bit(CEPIC_PNMIRR_INT_VIOLAT_BIT,
			(void *)&vcpu->arch.hw_ctxt.cepic->pnmirr);
}

void kvm_deliver_cepic_epic_interrupt(void)
{
	struct kvm_cepic_irq irq;
	union cepic_epic_int2 reg;
	struct kvm_vcpu *vcpu = kvm_get_running_vcpu();
	/* Rely on CEPIC_EPIC_INT being delivered before migrations
	 * (see comment in save_epic_context())	*/
	u32 src = epic_read_guest_w(CEPIC_ID);

	reg.raw = epic_read_d(CEPIC_EPIC_INT2);

	if (WARN_ONCE(!vcpu, "vcpu is NULL inside CEPIC_EPIC_INT handler"))
		return;

	if (WARN_ONCE(vcpu->kvm->arch.vm_id != reg.gst_id,
			"Received CEPIC_EPIC_INT with bad gst_id %d\n", reg.gst_id))
		return;

	irq.dest_id = reg.gst_dst;
	irq.vector = reg.vect;
	irq.trig_mode = 0;
	irq.delivery_mode = reg.dlvm;
	irq.shorthand = reg.dst_sh;

	kvm_irq_delivery_to_epic(vcpu->kvm, src, &irq);
}
#else
void kvm_int_violat_delivery_to_hw_epic(struct kvm *kvm)
{
	/* Nothing to do */
}
#endif /* CONFIG_KVM_HW_VIRTUALIZATION */

int kvm_cpu_has_pending_apic_timer(struct kvm_vcpu *vcpu)
{
	//TODO apic on top of hw epic support
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	if (lapic_in_kernel(vcpu))
		return apic_has_pending_timer(vcpu);
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	return 0;
}

/* This is called from pv_wait hcall (CEPIC DAT is active) */
int kvm_cpu_has_pending_epic_timer(struct kvm_vcpu *vcpu)
{
	union cepic_cir reg_cir;
	u64 pmirr;
	int vect = vcpu->arch.timer_vector;

	reg_cir.raw = epic_read_guest_w(CEPIC_CIR);

	if (!reg_cir.stat)
		return false;

	if (reg_cir.vect == vect)
		return true;

	pmirr = epic_read_guest_d(CEPIC_PMIRR + (vect >> 6) * 8);

	return !!(pmirr & (1ULL << (vect & 0x3f)));
}

/*
 * check if there are pending timer events
 * to be processed.
 */
int kvm_cpu_has_pending_timer(struct kvm_vcpu *vcpu)
{
	return !vcpu->arch.hcall_irqs_disabled && kvm_cpu_has_pending_pic_timer(vcpu);

}
EXPORT_SYMBOL(kvm_cpu_has_pending_timer);

int kvm_set_apic_msi(struct kvm_kernel_irq_routing_entry *e,
		struct kvm *kvm, int irq_source_id, int level, bool line_status)
{
	struct kvm_lapic_irq irq;

	irq.dest_id = (e->msi.address_lo &
			MSI_ADDR_DEST_ID_MASK) >> MSI_ADDR_DEST_ID_SHIFT;
	irq.vector = (e->msi.data &
			MSI_DATA_VECTOR_MASK) >> MSI_DATA_VECTOR_SHIFT;
	irq.dest_mode = (1 << MSI_ADDR_DEST_MODE_SHIFT) & e->msi.address_lo;
	irq.trig_mode = (1 << MSI_DATA_TRIGGER_SHIFT) & e->msi.data;
	irq.delivery_mode = e->msi.data & 0x700;
	irq.level = 1;
	irq.shorthand = 0;

	/* TODO Deal with RH bit of MSI message address */
	return kvm_irq_delivery_to_apic(kvm, NULL, &irq);
}

int kvm_set_epic_msi(struct kvm_kernel_irq_routing_entry *e,
		struct kvm *kvm, int irq_source_id, int level, bool line_status)
{
	struct kvm_cepic_irq irq;
	union IO_EPIC_MSG_ADDR_LOW addr_low;
	union IO_EPIC_MSG_DATA data;

	addr_low.raw = e->msi.address_lo;
	data.raw = e->msi.data;

	irq.dest_id = addr_low.dst;
	irq.vector = data.vector;
	irq.delivery_mode = data.dlvm;
	irq.shorthand = 0;

	return kvm_irq_delivery_to_epic(kvm, 0, &irq);
}

int kvm_set_msi(struct kvm_kernel_irq_routing_entry *e,
		struct kvm *kvm, int irq_source_id, int level, bool line_status)
{
	u64 address = (u64) e->msi.address_hi << 32 | e->msi.address_lo;

	DebugIRQ("IRQ #%d level %d line status %d\n",
		irq_source_id, level, line_status);
	if (!level)
		return -EOPNOTSUPP;

	trace_kvm_e2k_msi(address, e->msi.data);

	int ret = kvm_set_pic_msi(e, kvm, irq_source_id, level, line_status);
	/* This is what KVM UAPI expects */
	return (ret) ? -1 : 1;
}
EXPORT_SYMBOL(kvm_set_msi);

int kvm_set_routing_entry(struct kvm *kvm,
				struct kvm_kernel_irq_routing_entry *e,
				const struct kvm_irq_routing_entry *ue)
{
	int r = -EINVAL;
	int delta;
	unsigned max_pin;

	DebugIRQ("started for entry type #%d gsi #%d\n", ue->type, ue->gsi);
	switch (ue->type) {
	case KVM_IRQ_ROUTING_IRQCHIP:
		DebugIRQ("routing IRQCHIP\n");
		delta = 0;
		switch (ue->u.irqchip.irqchip) {
		case KVM_IRQCHIP_IOAPIC:
			max_pin = KVM_IOAPIC_NUM_PINS;
			e->set = kvm_set_ioapic_irq;
			DebugIRQ("IRQCHIP is IOAPIC pin #%d\n",
				ue->u.irqchip.pin);
			break;
		case KVM_IRQCHIP_IOEPIC:
			max_pin = KVM_IOEPIC_NUM_PINS;
			e->set = kvm_set_ioepic_irq;
			DebugIRQ("IRQCHIP is IOEPIC pin #%d\n",
				ue->u.irqchip.pin);
			break;
		default:
			DebugIRQ("IRQCHIP is unknown\n");
			goto out;
		}
		e->irqchip.irqchip = ue->u.irqchip.irqchip;
		e->irqchip.pin = ue->u.irqchip.pin + delta;
		if (e->irqchip.pin >= max_pin)
			goto out;
		break;
	case KVM_IRQ_ROUTING_MSI:
		DebugIRQ("routing MSI\n");
		e->set = kvm_set_msi;
		e->msi.address_lo = ue->u.msi.address_lo;
		e->msi.address_hi = ue->u.msi.address_hi;
		e->msi.data = ue->u.msi.data;
		break;
	default:
		DebugIRQ("routing unknown\n");
		goto out;
	}

	r = 0;
out:
	return r;
}

bool kvm_arch_has_irq_bypass(void)
{
	return kvm_irq_bypass;
}

static int kvm_irq_bypass_check_msi(struct kvm *kvm, struct kvm_kernel_irq_routing_entry *e)
{
	kvm_nbsr_t *nbsr = kvm->arch.nbsr;
	kvm_nbsr_regs_t *node_nbsr = &nbsr->nodes[0];
	struct kvm_vcpu *vcpu;
	union IO_EPIC_MSG_ADDR_LOW addr_low;
	union IO_EPIC_MSG_DATA data;
	u32 g_rt_msi_lo, g_rt_msi_hi;
	unsigned long i;

	addr_low.raw = e->msi.address_lo;
	data.raw = e->msi.data;

	mutex_lock(&nbsr->lock);
	g_rt_msi_lo = node_nbsr->regs[offset_to_no(SIC_rt_msi)];
	g_rt_msi_hi = node_nbsr->regs[offset_to_no(SIC_rt_msi_h)];
	mutex_unlock(&nbsr->lock);

	/* Check for valid MSI address, msg_type, dlvm */
	if (g_rt_msi_hi != e->msi.address_hi ||
			g_rt_msi_lo >> E2K_SIC_ALIGN_RT_MSI != addr_low.MSI ||
			addr_low.msg_type ||
			data.dlvm)
		return -EINVAL;

	/* Check for valid destination id */
	kvm_for_each_vcpu(i, vcpu, kvm) {
		int cepic_id = kvm_vcpu_to_full_cepic_id(vcpu);
		if (kvm_epic_match_dest(cepic_id, -1, CEPIC_ICR_DST_FULL, addr_low.dst))
			return 0;
	}

	return -EINVAL;
}

static int kvm_irq_bypass_get_msi_entry(struct kvm *kvm, unsigned int host_irq,
		unsigned int guest_irq, struct ioepic_vcpu_info *vcpu_info)
{
	struct kvm_kernel_irq_routing_entry *e;
	struct kvm_irq_routing_table *irq_rt;
	struct irq_data *irqd = irq_get_irq_data(host_irq);
	int idx, ret = 0;

	if (!kvm_arch_has_assigned_device(kvm))
		return -EINVAL;

	idx = srcu_read_lock(&kvm->irq_srcu);
	irq_rt = srcu_dereference(kvm->irq_routing, &kvm->irq_srcu);
	if (guest_irq >= irq_rt->nr_rt_entries ||
	    hlist_empty(&irq_rt->map[guest_irq])) {
		pr_warn("no route for guest_irq %u/%u (broken user space?)\n",
			     guest_irq, irq_rt->nr_rt_entries);
		ret = -EINVAL;
		goto out;
	}

	hlist_for_each_entry(e, &irq_rt->map[guest_irq], link) {
		if (e->type != KVM_IRQ_ROUTING_MSI)
			continue;

		/* There should be only one MSI routing entry for a given guest irq */
		if (vcpu_info->msi_valid) {
			pr_warn("%s(): multiple MSI routing entries for guest irq %d\n",
				__func__, guest_irq);
			ret = -EINVAL;
			goto out;
		}

		ret = kvm_irq_bypass_check_msi(kvm, e);
		if (!ret) {
			/* Valid configuration: pass to device, except use host MSI address */
			ret = irq_chip_compose_msi_msg(irqd, &vcpu_info->msi);
			if (ret)
				goto out;
			vcpu_info->msi.address_lo |= e->msi.address_lo & (E2K_SIC_SIZE_RT_MSI - 1);
			vcpu_info->msi.data = e->msi.data;
		} else {
			/*
			 * If guest has an broken MSI configuration (e.g. between writing
			 * MSI registers) - write zeroes to the device.
			 */
			pr_warn("%s(): invalid guest MSI configuration: irq %d : addr_hi = 0x%08x, addr_lo = 0x%08x, data = 0x%08x\n",
				__func__, guest_irq, e->msi.address_hi, e->msi.address_lo,
				e->msi.data);
			vcpu_info->msi.address_hi = 0;
			vcpu_info->msi.address_lo = 0;
			vcpu_info->msi.data = 0;
		}
		vcpu_info->msi_valid = true;
	}
out:
	srcu_read_unlock(&kvm->irq_srcu, idx);
	return ret;
}

int kvm_arch_irq_bypass_add_producer(struct irq_bypass_consumer *cons,
				      struct irq_bypass_producer *prod)
{
	struct kvm_kernel_irqfd *irqfd =
		container_of(cons, struct kvm_kernel_irqfd, consumer);
	struct kvm *kvm = irqfd->kvm;
	struct ioepic_vcpu_info info = {
		.valid = true,
		.msi_valid = false,
		.ioepic_pt_pin = &kvm->arch.ioepic_pt_pin,
		.vmid = kvm->arch.vm_id,
		.int_table = __pa(page_address(kvm->arch.epic_pages))
	};
	int ret;

	ret = kvm_irq_bypass_get_msi_entry(kvm, prod->irq, irqfd->gsi, &info);
	if (ret)
		return ret;

	ret = irq_set_vcpu_affinity(prod->irq, &info);
	if (!ret)
		irqfd->producer = prod;

	/* Do not forward error for PCI INTx */
	if (ret == -EACCES)
		return 0;
	else
		return ret;
}
void kvm_arch_irq_bypass_del_producer(struct irq_bypass_consumer *cons,
				      struct irq_bypass_producer *prod)
{
	struct kvm_kernel_irqfd *irqfd =
		container_of(cons, struct kvm_kernel_irqfd, consumer);
	struct ioepic_vcpu_info info = {
		.valid = false,
		.ioepic_pt_pin = &irqfd->kvm->arch.ioepic_pt_pin
	};
	int ret;

	irqfd->producer = NULL;

	ret = irq_set_vcpu_affinity(prod->irq, &info);
	if (ret && ret != -EACCES)
		pr_err("%s(): error setting vcpu affinity\n", __func__);
}

void kvm_arch_irq_bypass_stop(struct irq_bypass_consumer *cons)
{
	/* Nothing to do */
}

void kvm_arch_irq_bypass_start(struct irq_bypass_consumer *cons)
{
	/* Nothing to do */
}

int kvm_arch_update_irqfd_routing(struct kvm *kvm, unsigned int host_irq,
				   uint32_t guest_irq, bool set)
{
	struct ioepic_vcpu_info info = {
		.valid = true,
		.msi_valid = false,
		.ioepic_pt_pin = &kvm->arch.ioepic_pt_pin,
		.vmid = kvm->arch.vm_id,
		.int_table = __pa(page_address(kvm->arch.epic_pages))
	};
	int ret;

	ret = kvm_irq_bypass_get_msi_entry(kvm, host_irq, guest_irq, &info);
	if (ret)
		return ret;

	/* Routing updates come from QEMU, and QEMU controls only MSI routes */
	if (!info.msi_valid) {
		pr_info("%s(): skipping non-MSI route (guest irq %d)\n", __func__, guest_irq);
		return 0;
	}

	pr_info("%s(): MSI irq %d : addr_hi = 0x%08x, addr_lo = 0x%08x, data = 0x%08x\n",
		__func__, host_irq, info.msi.address_hi, info.msi.address_lo, info.msi.data);

	/* No need to call set_vcpu_affinity, since we only need to update the MSI config */
	pci_write_msi_msg(host_irq, &info.msi);

	return 0;
}

void kvm_arch_start_assignment(struct kvm *kvm)
{
	atomic_inc(&kvm->arch.assigned_device_count);
}
EXPORT_SYMBOL_GPL(kvm_arch_start_assignment);

void kvm_arch_end_assignment(struct kvm *kvm)
{
	atomic_dec(&kvm->arch.assigned_device_count);
}
EXPORT_SYMBOL_GPL(kvm_arch_end_assignment);

bool kvm_arch_has_assigned_device(struct kvm *kvm)
{
	return atomic_read(&kvm->arch.assigned_device_count);
}
EXPORT_SYMBOL_GPL(kvm_arch_has_assigned_device);
