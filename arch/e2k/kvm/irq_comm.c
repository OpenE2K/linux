/*
 * irq_comm.c: Common API for in kernel interrupt controller
 * Copyright (c) 2007, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 * Authors:
 *   Yaozu (Eddie) Dong <Eddie.dong@intel.com>
 *
 */

#include <linux/kvm_host.h>
#include <trace/events/kvm.h>
#include <asm/kvm/trace_kvm_hv.h>

#include <asm/epic.h>
#include <asm/msidef.h>
#ifdef CONFIG_IA64
#include <asm/iosapic.h>
#endif

#include "irq.h"
#include "pic.h"
#include "ioapic.h"
#include "ioepic.h"

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

static int kvm_set_pic_irq(struct kvm_kernel_irq_routing_entry *e,
				struct kvm *kvm, int irq_source_id, int level,
				bool line_status)
{
#ifdef CONFIG_X86
	struct kvm_pic *pic = pic_irqchip(kvm);
	level = kvm_irq_line_state(&pic->irq_states[e->irqchip.pin],
				   irq_source_id, level);
	return kvm_pic_set_irq(pic, e->irqchip.pin, level);
#else
	return -1;
#endif
}

static int kvm_set_ioapic_irq(struct kvm_kernel_irq_routing_entry *e,
				struct kvm *kvm, int irq_source_id, int level,
				bool line_status)
{
	struct kvm_ioapic *ioapic = kvm->arch.vioapic[e->gsi / 64];
	level = kvm_irq_line_state(&ioapic->irq_states[e->irqchip.pin],
				   irq_source_id, level);

	return kvm_ioapic_set_irq(ioapic, e->irqchip.pin, level);
}

static int kvm_set_ioepic_irq(struct kvm_kernel_irq_routing_entry *e,
				struct kvm *kvm, int irq_source_id, int level,
				bool line_status)
{
	struct kvm_ioepic *ioepic = kvm->arch.ioepic[e->gsi / 64];

	level = kvm_irq_line_state(&ioepic->irq_states[e->irqchip.pin],
				   irq_source_id, level);

	return kvm_ioepic_set_irq(ioepic, e->irqchip.pin, level);
}

inline static bool kvm_is_dm_lowest_prio(struct kvm_lapic_irq *irq)
{
#ifdef CONFIG_IA64
	return irq->delivery_mode ==
		(IOSAPIC_LOWEST_PRIORITY << IOSAPIC_DELIVERY_SHIFT);
#else
	return irq->delivery_mode == APIC_DM_LOWEST;
#endif
}


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

int kvm_irq_delivery_to_sw_apic(struct kvm *kvm, struct kvm_lapic *src,
		struct kvm_lapic_irq *irq)
{
	int i, r = -1;
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

/* VCPU is not running now. Set bit in the PMIRR copy in hw context */
static int kvm_hw_epic_set_irq_vector(struct kvm_vcpu *vcpu, unsigned int vector)
{
	if (vector >= CEPIC_PMIRR_NR_BITS || vector == 0) {
		pr_err("Error: Invalid EPIC vector value %u\n", vector);
		return -1;
	}

	if (unlikely(epic_bgi_mode)) {
		vcpu->arch.hw_ctxt.cepic->pmirr_byte[vector] = 1;
	} else {
		unsigned int epic_pmirr = vector >> 6;
		atomic64_or(BIT_ULL_MASK(vector & 0x3f),
			    &vcpu->arch.hw_ctxt.cepic->pmirr[epic_pmirr]);
	}

	return 1;
}

/* VCPU is not running now. Set bit in the PNMIRR copy in hw context */
static int kvm_hw_epic_set_smi(struct kvm_vcpu *vcpu)
{
	union cepic_pnmirr reg;

	reg.raw = 0;
	reg.bits.smi = 1;

	atomic_or(reg.raw, &vcpu->arch.hw_ctxt.cepic->pnmirr);

	return 1;
}

static int kvm_hw_epic_set_nm_special(struct kvm_vcpu *vcpu)
{
	union cepic_pnmirr reg;

	reg.raw = 0;
	reg.bits.nm_special = 1;

	atomic_or(reg.raw, &vcpu->arch.hw_ctxt.cepic->pnmirr);

	return 1;
}

static int kvm_hw_epic_set_nmi(struct kvm_vcpu *vcpu)
{
	union cepic_pnmirr reg;

	reg.raw = 0;
	reg.bits.nmi = 1;

	atomic_or(reg.raw, &vcpu->arch.hw_ctxt.cepic->pnmirr);

	return 1;
}

static int kvm_hw_epic_set_init(struct kvm_vcpu *vcpu)
{
	union cepic_pnmirr reg;

	reg.raw = 0;
	reg.bits.init = 1;

	atomic_or(reg.raw, &vcpu->arch.hw_ctxt.cepic->pnmirr);

	return 1;
}

static int kvm_hw_epic_set_startup(struct kvm_vcpu *vcpu, unsigned int vector)
{
	union cepic_pnmirr reg;

	reg.raw = 0;
	reg.bits.startup = 1;
	reg.bits.startup_entry = vector & CEPIC_PNMIRR_STARTUP_ENTRY;

	atomic_or(reg.raw, &vcpu->arch.hw_ctxt.cepic->pnmirr);

	return 1;
}

/*
 * Lintel uses:
 * - SMI for devices, hidden from x86
 * - NM-special for broadcast IPI
 * - INIT and STARTUP for waking up a secondary CPU
 */
int kvm_hw_epic_deliver_to_pirr(struct kvm_vcpu *vcpu, unsigned int vector,
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
		return -1;
	}
}

u32 kvm_vcpu_to_full_cepic_id(const struct kvm_vcpu *vcpu)
{
	union cepic_id epic_reg_id;

	epic_reg_id.raw = 0;

	if (!kvm_vcpu_is_epic(vcpu) && kvm_vcpu_is_hw_apic(vcpu)) {
		epic_reg_id.bits.cepicn = vcpu->arch.hard_cpu_id;
	} else {
		epic_reg_id.bits.cepicn = vcpu->vcpu_id /
						vcpu->kvm->arch.num_numa_nodes;
		epic_reg_id.bits.prepicn = vcpu->arch.node_id;
	}

	return epic_reg_id.raw;
}

/* VCPU is running now. Send an interrupt to guest through host's ICR */
int kvm_hw_epic_deliver_to_icr(struct kvm_vcpu *vcpu, unsigned int vector,
				u8 dlvm)
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
	reg.bits.dst = kvm_vcpu_to_full_cepic_id(vcpu);
	reg.bits.gst_id = vcpu->kvm->arch.vmid.nr;
	reg.bits.dst_sh = CEPIC_ICR_DST_FULL;
	reg.bits.dlvm = dlvm;
	reg.bits.vect = vector;

	/*
	 * Send the guest interrupt
	 */
	epic_write_d(CEPIC_ICR, reg.raw);

	return 1;
}

int kvm_epic_match_dest(int cepic_id, int src, int short_hand, int dest)
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

//TODO fix this and all other delivery functions to return 0 on success and proper errno on error
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
		ret = kvm_hw_epic_deliver_to_icr(vcpu,
				irq->vector, irq->delivery_mode);
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
		ret = kvm_hw_epic_deliver_to_pirr(vcpu,
				irq->vector, irq->delivery_mode);
	}
	raw_spin_unlock_irqrestore(&vcpu->arch.epic_dat_lock, flags);

	if (ret == 1) {
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
	int i, cepic_id;
	int shorthand = irq->shorthand, dest_id = irq->dest_id;

	kvm_for_each_vcpu(i, vcpu, kvm) {
		cepic_id = kvm_vcpu_to_full_cepic_id(vcpu);
		if (!kvm_epic_match_dest(cepic_id, src, shorthand, dest_id))
			continue;

		if (kvm_irq_delivery_to_hw_epic_single(vcpu, irq) == 1) {
			delivered = true;
			/* Stop if there is a single destination */
			if (shorthand == CEPIC_ICR_DST_FULL ||
					shorthand == CEPIC_ICR_DST_SELF) {
				break;
			}
		}
	}

	return delivered ? 1 : -1;
}

int kvm_hw_epic_sysrq_deliver(struct kvm_vcpu *vcpu)
{
	struct kvm_cepic_irq irq;

	irq.vector = SYSRQ_SHOWSTATE_EPIC_VECTOR;
	irq.delivery_mode = CEPIC_ICR_DLVM_FIXED_EXT;
	irq.trig_mode = 0; /* Edge */
	irq.shorthand = CEPIC_ICR_DST_FULL;
	irq.dest_id = kvm_vcpu_to_full_cepic_id(vcpu);

	return kvm_irq_delivery_to_hw_epic(vcpu->kvm, 0, &irq);
}

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

int kvm_irq_delivery_to_sw_epic(struct kvm *kvm, int src,
		struct kvm_cepic_irq *irq)
{
	int i;
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
			return ret;
		}
	}

	return -1;
}

void kvm_int_violat_delivery_to_hw_epic(struct kvm *kvm)
{
	int i;
	struct kvm_vcpu *vcpu;

	kvm_for_each_vcpu(i, vcpu, kvm)
		set_bit(CEPIC_PNMIRR_INT_VIOLAT_BIT,
			(void *)&vcpu->arch.hw_ctxt.cepic->pnmirr);
}

void kvm_deliver_cepic_epic_interrupt(void)
{
	struct kvm_cepic_irq irq;
	union cepic_epic_int2 reg;
	struct kvm *kvm;
	u32 src = cepic_id_short_to_full(read_epic_id());
	struct kvm_vcpu *vcpu = current_thread_info()->vcpu;

	reg.raw = epic_read_d(CEPIC_EPIC_INT2);

	if (WARN_ONCE(!vcpu, "vcpu is NULL inside CEPIC_EPIC_INT handler"))
		return;

	kvm = vcpu->kvm;
	if (WARN_ONCE(kvm->arch.vmid.nr != reg.bits.gst_id,
			"Received CEPIC_EPIC_INT with bad gst_id %d\n", reg.bits.gst_id))
		return;

	irq.dest_id = reg.bits.gst_dst;
	irq.vector = reg.bits.vect;
	irq.trig_mode = 0;
	irq.delivery_mode = reg.bits.dlvm;
	irq.shorthand = reg.bits.dst_sh;

	kvm_irq_delivery_to_epic(kvm, src, &irq);
}

int kvm_cpu_has_pending_apic_timer(struct kvm_vcpu *vcpu)
{
	if (lapic_in_kernel(vcpu))
		return apic_has_pending_timer(vcpu);

	return 0;
}

/* This is called from pv_wait hcall (CEPIC DAT is active) */
int kvm_cpu_has_pending_epic_timer(struct kvm_vcpu *vcpu)
{
	union cepic_cir reg_cir;
	u64 pmirr;

	reg_cir.raw = epic_read_guest_w(CEPIC_CIR);

	if (!reg_cir.bits.stat)
		return false;

	if (reg_cir.bits.vect == CEPIC_TIMER_VECTOR)
		return true;

	pmirr = epic_read_guest_d(CEPIC_PMIRR + (CEPIC_TIMER_VECTOR >> 6) * 8);

	return !!(pmirr & (1ULL << (CEPIC_TIMER_VECTOR & 0x3f)));
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

	irq.dest_id = addr_low.bits.dst;
	irq.vector = data.bits.vector;
	irq.delivery_mode = data.bits.dlvm;
	irq.shorthand = 0;

	return kvm_irq_delivery_to_epic(kvm, 0, &irq);
}

int kvm_set_msi(struct kvm_kernel_irq_routing_entry *e,
		struct kvm *kvm, int irq_source_id, int level, bool line_status)
{
	DebugIRQ("IRQ #%d level %d line status %d\n",
		irq_source_id, level, line_status);
	if (!level)
		return -1;

	trace_kvm_msi_set_irq(e->msi.address_lo, e->msi.data);

	return kvm_set_pic_msi(e, kvm, irq_source_id, level, line_status);
}
EXPORT_SYMBOL(kvm_set_msi);

int kvm_request_irq_source_id(struct kvm *kvm)
{
	unsigned long *bitmap = &kvm->arch.irq_sources_bitmap;
	int irq_source_id;

	mutex_lock(&kvm->irq_lock);
	irq_source_id = find_first_zero_bit(bitmap, BITS_PER_LONG);

	if (irq_source_id >= BITS_PER_LONG) {
		printk(KERN_WARNING "kvm: exhaust allocatable IRQ sources!\n");
		irq_source_id = -EFAULT;
		goto unlock;
	}

	ASSERT(irq_source_id != KVM_USERSPACE_IRQ_SOURCE_ID);
	set_bit(irq_source_id, bitmap);
unlock:
	mutex_unlock(&kvm->irq_lock);

	return irq_source_id;
}

#if 0
void kvm_free_irq_source_id(struct kvm *kvm, int irq_source_id)
{
	int i;

	ASSERT(irq_source_id != KVM_USERSPACE_IRQ_SOURCE_ID);

	mutex_lock(&kvm->irq_lock);
	if (irq_source_id < 0 ||
	    irq_source_id >= BITS_PER_LONG) {
		printk(KERN_ERR "kvm: IRQ source ID out of range!\n");
		goto unlock;
	}
	clear_bit(irq_source_id, &kvm->arch.irq_sources_bitmap);
	if (!irqchip_in_kernel(kvm))
		goto unlock;

	for (i = 0; i < KVM_IOAPIC_NUM_PINS; i++) {
		clear_bit(irq_source_id, &kvm->arch.vioapic->irq_states[i]);
		if (i >= 16)
			continue;
#ifdef CONFIG_X86
		clear_bit(irq_source_id, &pic_irqchip(kvm)->irq_states[i]);
#endif
	}
unlock:
	mutex_unlock(&kvm->irq_lock);
}
#endif

void kvm_register_irq_mask_notifier(struct kvm *kvm, int irq,
				    struct kvm_irq_mask_notifier *kimn)
{
	mutex_lock(&kvm->irq_lock);
	kimn->irq = irq;
	hlist_add_head_rcu(&kimn->link, &kvm->arch.mask_notifier_list);
	mutex_unlock(&kvm->irq_lock);
}

void kvm_unregister_irq_mask_notifier(struct kvm *kvm, int irq,
				      struct kvm_irq_mask_notifier *kimn)
{
	mutex_lock(&kvm->irq_lock);
	hlist_del_rcu(&kimn->link);
	mutex_unlock(&kvm->irq_lock);
	synchronize_rcu();
}

void kvm_fire_mask_notifiers(struct kvm *kvm, int irq, bool mask)
{
	struct kvm_irq_mask_notifier *kimn;

	rcu_read_lock();
	hlist_for_each_entry_rcu(kimn, &kvm->arch.mask_notifier_list, link)
		if (kimn->irq == irq)
			kimn->func(kimn, mask);
	rcu_read_unlock();
}

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
		case KVM_IRQCHIP_PIC_MASTER:
			e->set = kvm_set_pic_irq;
			max_pin = 16;
			DebugIRQ("IRQCHIP is PIC master\n");
			break;
		case KVM_IRQCHIP_PIC_SLAVE:
			e->set = kvm_set_pic_irq;
			max_pin = 16;
			delta = 8;
			DebugIRQ("IRQCHIP is PIC slave\n");
			break;
		case KVM_IRQCHIP_IOAPIC:
			max_pin = KVM_IOAPIC_NUM_PINS;
			e->set = kvm_set_ioapic_irq;
			DebugIRQ("IRQCHIP is IOAPIC pin #%d\n",
				ue->u.irqchip.pin);
			break;
		case KVM_IRQCHIP_IOEPIC_NODE0:
			max_pin = KVM_IOEPIC_NUM_PINS;
			e->set = kvm_set_ioepic_irq;
			DebugIRQ("IRQCHIP is IOEPIC_NODE0 pin #%d\n",
				ue->u.irqchip.pin);
			break;
		case KVM_IRQCHIP_IOEPIC_NODE1:
			max_pin = KVM_IOEPIC_NUM_PINS;
			e->set = kvm_set_ioepic_irq;
			DebugIRQ("IRQCHIP is IOEPIC_NODE1 pin #%d\n",
				ue->u.irqchip.pin);
			break;
		case KVM_IRQCHIP_IOEPIC_NODE2:
			max_pin = KVM_IOEPIC_NUM_PINS;
			e->set = kvm_set_ioepic_irq;
			DebugIRQ("IRQCHIP is IOEPIC_NODE2 pin #%d\n",
				ue->u.irqchip.pin);
			break;
		case KVM_IRQCHIP_IOEPIC_NODE3:
			max_pin = KVM_IOEPIC_NUM_PINS;
			e->set = kvm_set_ioepic_irq;
			DebugIRQ("IRQCHIP is IOEPIC_NODE3 pin #%d\n",
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

#define IOAPIC_ROUTING_ENTRY(irq) \
	{ .gsi = irq, .type = KVM_IRQ_ROUTING_IRQCHIP,	\
	  .u.irqchip.irqchip = KVM_IRQCHIP_IOAPIC, .u.irqchip.pin = (irq) }
#define ROUTING_ENTRY1(irq) IOAPIC_ROUTING_ENTRY(irq)

#ifdef CONFIG_X86
#  define PIC_ROUTING_ENTRY(irq) \
	{ .gsi = irq, .type = KVM_IRQ_ROUTING_IRQCHIP,	\
	  .u.irqchip.irqchip = SELECT_PIC(irq), .u.irqchip.pin = (irq) % 8 }
#  define ROUTING_ENTRY2(irq) \
	IOAPIC_ROUTING_ENTRY(irq), PIC_ROUTING_ENTRY(irq)
#else
#  define ROUTING_ENTRY2(irq) \
	IOAPIC_ROUTING_ENTRY(irq)
#endif

#define IOAPIC_ROUTING_ENTRY_NODE_1(irq) \
	{ .gsi = irq + 64, .type = KVM_IRQ_ROUTING_IRQCHIP,	\
	  .u.irqchip.irqchip = KVM_IRQCHIP_IOAPIC, .u.irqchip.pin = (irq) }

#define IOAPIC_ROUTING_ENTRY_NODE_2(irq) \
	{ .gsi = irq + 128, .type = KVM_IRQ_ROUTING_IRQCHIP,	\
	  .u.irqchip.irqchip = KVM_IRQCHIP_IOAPIC, .u.irqchip.pin = (irq) }

#define IOAPIC_ROUTING_ENTRY_NODE_3(irq) \
	{ .gsi = irq + 192, .type = KVM_IRQ_ROUTING_IRQCHIP,	\
	  .u.irqchip.irqchip = KVM_IRQCHIP_IOAPIC, .u.irqchip.pin = (irq) }

static const struct kvm_irq_routing_entry default_routing[] = {
	ROUTING_ENTRY2(0), ROUTING_ENTRY2(1),
	ROUTING_ENTRY2(2), ROUTING_ENTRY2(3),
	ROUTING_ENTRY2(4), ROUTING_ENTRY2(5),
	ROUTING_ENTRY2(6), ROUTING_ENTRY2(7),
	ROUTING_ENTRY2(8), ROUTING_ENTRY2(9),
	ROUTING_ENTRY2(10), ROUTING_ENTRY2(11),
	ROUTING_ENTRY2(12), ROUTING_ENTRY2(13),
	ROUTING_ENTRY2(14), ROUTING_ENTRY2(15),
	ROUTING_ENTRY1(16), ROUTING_ENTRY1(17),
	ROUTING_ENTRY1(18), ROUTING_ENTRY1(19),
	ROUTING_ENTRY1(20), ROUTING_ENTRY1(21),
	ROUTING_ENTRY1(22), ROUTING_ENTRY1(23),
#ifdef CONFIG_IA64
	ROUTING_ENTRY1(24), ROUTING_ENTRY1(25),
	ROUTING_ENTRY1(26), ROUTING_ENTRY1(27),
	ROUTING_ENTRY1(28), ROUTING_ENTRY1(29),
	ROUTING_ENTRY1(30), ROUTING_ENTRY1(31),
	ROUTING_ENTRY1(32), ROUTING_ENTRY1(33),
	ROUTING_ENTRY1(34), ROUTING_ENTRY1(35),
	ROUTING_ENTRY1(36), ROUTING_ENTRY1(37),
	ROUTING_ENTRY1(38), ROUTING_ENTRY1(39),
	ROUTING_ENTRY1(40), ROUTING_ENTRY1(41),
	ROUTING_ENTRY1(42), ROUTING_ENTRY1(43),
	ROUTING_ENTRY1(44), ROUTING_ENTRY1(45),
	ROUTING_ENTRY1(46), ROUTING_ENTRY1(47),
#endif
#ifdef CONFIG_E2K
	IOAPIC_ROUTING_ENTRY_NODE_1(0), IOAPIC_ROUTING_ENTRY_NODE_1(1),
	IOAPIC_ROUTING_ENTRY_NODE_1(2), IOAPIC_ROUTING_ENTRY_NODE_1(3),
	IOAPIC_ROUTING_ENTRY_NODE_1(4), IOAPIC_ROUTING_ENTRY_NODE_1(5),
	IOAPIC_ROUTING_ENTRY_NODE_1(6), IOAPIC_ROUTING_ENTRY_NODE_1(7),
	IOAPIC_ROUTING_ENTRY_NODE_1(8), IOAPIC_ROUTING_ENTRY_NODE_1(9),
	IOAPIC_ROUTING_ENTRY_NODE_1(10), IOAPIC_ROUTING_ENTRY_NODE_1(11),
	IOAPIC_ROUTING_ENTRY_NODE_1(12), IOAPIC_ROUTING_ENTRY_NODE_1(13),
	IOAPIC_ROUTING_ENTRY_NODE_1(14), IOAPIC_ROUTING_ENTRY_NODE_1(15),
	IOAPIC_ROUTING_ENTRY_NODE_1(16), IOAPIC_ROUTING_ENTRY_NODE_1(17),
	IOAPIC_ROUTING_ENTRY_NODE_1(18), IOAPIC_ROUTING_ENTRY_NODE_1(19),
	IOAPIC_ROUTING_ENTRY_NODE_1(20), IOAPIC_ROUTING_ENTRY_NODE_1(21),
	IOAPIC_ROUTING_ENTRY_NODE_1(22), IOAPIC_ROUTING_ENTRY_NODE_1(23),

	IOAPIC_ROUTING_ENTRY_NODE_2(0), IOAPIC_ROUTING_ENTRY_NODE_2(1),
	IOAPIC_ROUTING_ENTRY_NODE_2(2), IOAPIC_ROUTING_ENTRY_NODE_2(3),
	IOAPIC_ROUTING_ENTRY_NODE_2(4), IOAPIC_ROUTING_ENTRY_NODE_2(5),
	IOAPIC_ROUTING_ENTRY_NODE_2(6), IOAPIC_ROUTING_ENTRY_NODE_2(7),
	IOAPIC_ROUTING_ENTRY_NODE_2(8), IOAPIC_ROUTING_ENTRY_NODE_2(9),
	IOAPIC_ROUTING_ENTRY_NODE_2(10), IOAPIC_ROUTING_ENTRY_NODE_2(11),
	IOAPIC_ROUTING_ENTRY_NODE_2(12), IOAPIC_ROUTING_ENTRY_NODE_2(13),
	IOAPIC_ROUTING_ENTRY_NODE_2(14), IOAPIC_ROUTING_ENTRY_NODE_2(15),
	IOAPIC_ROUTING_ENTRY_NODE_2(16), IOAPIC_ROUTING_ENTRY_NODE_2(17),
	IOAPIC_ROUTING_ENTRY_NODE_2(18), IOAPIC_ROUTING_ENTRY_NODE_2(19),
	IOAPIC_ROUTING_ENTRY_NODE_2(20), IOAPIC_ROUTING_ENTRY_NODE_2(21),
	IOAPIC_ROUTING_ENTRY_NODE_2(22), IOAPIC_ROUTING_ENTRY_NODE_2(23),

	IOAPIC_ROUTING_ENTRY_NODE_3(0), IOAPIC_ROUTING_ENTRY_NODE_3(1),
	IOAPIC_ROUTING_ENTRY_NODE_3(2), IOAPIC_ROUTING_ENTRY_NODE_3(3),
	IOAPIC_ROUTING_ENTRY_NODE_3(4), IOAPIC_ROUTING_ENTRY_NODE_3(5),
	IOAPIC_ROUTING_ENTRY_NODE_3(6), IOAPIC_ROUTING_ENTRY_NODE_3(7),
	IOAPIC_ROUTING_ENTRY_NODE_3(8), IOAPIC_ROUTING_ENTRY_NODE_3(9),
	IOAPIC_ROUTING_ENTRY_NODE_3(10), IOAPIC_ROUTING_ENTRY_NODE_3(11),
	IOAPIC_ROUTING_ENTRY_NODE_3(12), IOAPIC_ROUTING_ENTRY_NODE_3(13),
	IOAPIC_ROUTING_ENTRY_NODE_3(14), IOAPIC_ROUTING_ENTRY_NODE_3(15),
	IOAPIC_ROUTING_ENTRY_NODE_3(16), IOAPIC_ROUTING_ENTRY_NODE_3(17),
	IOAPIC_ROUTING_ENTRY_NODE_3(18), IOAPIC_ROUTING_ENTRY_NODE_3(19),
	IOAPIC_ROUTING_ENTRY_NODE_3(20), IOAPIC_ROUTING_ENTRY_NODE_3(21),
	IOAPIC_ROUTING_ENTRY_NODE_3(22), IOAPIC_ROUTING_ENTRY_NODE_3(23),
#endif
};

int kvm_setup_apic_irq_routing(struct kvm *kvm)
{
	return kvm_set_irq_routing(kvm, default_routing,
				   ARRAY_SIZE(default_routing), 0);
}

int kvm_setup_epic_irq_routing(struct kvm *kvm)
{
	int i, node, ret;
	struct kvm_irq_routing_entry *default_routing_ioepic;
	int nr_entries = KVM_IOEPIC_NUM_PINS * 4;

	default_routing_ioepic = vmalloc(sizeof(struct kvm_irq_routing_entry) * nr_entries);

	for (i = 0; i < nr_entries; i++) {
		node = i / 64;

		default_routing_ioepic[i].gsi = i;
		default_routing_ioepic[i].type = KVM_IRQ_ROUTING_IRQCHIP;
		default_routing_ioepic[i].flags = 0;
		default_routing_ioepic[i].u.irqchip.irqchip = KVM_IRQCHIP_IOEPIC_NODE0 + node;
		default_routing_ioepic[i].u.irqchip.pin = i % 64;
	}


	ret = kvm_set_irq_routing(kvm, default_routing_ioepic, nr_entries, 0);

	vfree(default_routing_ioepic);

	return ret;
}

void kvm_irq_routing_update_epic(struct kvm *kvm)
{
	if (ioepic_in_kernel(kvm) || !irqchip_in_kernel(kvm))
		return;
	kvm_make_scan_ioepic_request(kvm);
}

void kvm_post_irq_routing_update_epic(struct kvm *kvm)
{
	if (ioepic_in_kernel(kvm) || !irqchip_in_kernel(kvm))
		return;
	kvm_make_scan_ioepic_request(kvm);
}

void kvm_irq_routing_update_apic(struct kvm *kvm)
{
	if (ioapic_in_kernel(kvm) || !irqchip_in_kernel(kvm))
		return;
	kvm_make_scan_ioapic_request(kvm);
}

void kvm_post_irq_routing_update_apic(struct kvm *kvm)
{
	if (ioapic_in_kernel(kvm) || !irqchip_in_kernel(kvm))
		return;
	kvm_make_scan_ioapic_request(kvm);
}

void kvm_arch_irq_routing_update(struct kvm *kvm)
{
	kvm_irq_routing_update_pic(kvm);
}

void kvm_arch_post_irq_routing_update(struct kvm *kvm)
{
	kvm_post_irq_routing_update_pic(kvm);
}
