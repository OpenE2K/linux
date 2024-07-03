/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Local APIC virtualization
 * Based on Xen 3.1 code
 * Based on arch/x86/kvm/lapic.c code
 */

#include <linux/kvm_host.h>
#include <linux/kvm.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/smp.h>
#include <linux/hrtimer.h>
#include <linux/io.h>
#include <linux/export.h>
#include <linux/math64.h>
#include <asm/epic.h>
#include <asm/processor.h>
#include <asm/page.h>
#include <asm/current.h>
#include <asm/apicdef.h>
#include <asm/atomic.h>
#include <asm/kvm/runstate.h>
#include <asm/kvm/guest/irq.h>
#include <trace/events/kvm.h>
#include <asm/kvm/trace_kvm.h>

#undef	DEBUG

#include "pic.h"
#include "ioapic.h"
#include "irq.h"
#include "lapic.h"

#define mod_64(x, y) ((x) % (y))

#define PRId64 "d"
#define PRIx64 "llx"
#define PRIu64 "u"
#define PRIo64 "o"

#define APIC_BUS_CYCLE_NS 1

#ifdef	DEBUG
#define apic_debug(fmt, arg...)		pr_warn(fmt, ##arg)
#define	apic_reg_debug(fmt, arg...)	pr_warn(fmt, ##arg)
#else	/* ! DEBUG */
#define apic_debug(fmt, arg...)
#define	apic_reg_debug(fmt, arg...)
#endif	/* DEBUG */

#undef	DEBUG_KVM_IRQ_MODE
#undef	DebugKVMIRQ
#define	DEBUG_KVM_IRQ_MODE	0	/* kernel APIC IRQs debugging */
#define	DebugKVMIRQ(fmt, args...)					\
({									\
	if (DEBUG_KVM_IRQ_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_VECTOR_MODE
#undef	DebugKVMVEC
#define	DEBUG_KVM_VECTOR_MODE	0	/* kernel APIC IRQs debugging */
#define	DebugKVMVEC(fmt, args...)					\
({									\
	if (DEBUG_KVM_VECTOR_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_TIMER_MODE
#undef	DebugKVMTM
#define	DEBUG_KVM_TIMER_MODE	0	/* kernel apic timer debugging */
#define	DebugKVMTM(fmt, args...)					\
({									\
	if (DEBUG_KVM_TIMER_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_TIMER_MODE
#undef	DebugTM
#define	DEBUG_TIMER_MODE	0	/* kernel local apic timer debugging */
#define	DebugTM(fmt, args...)						\
({									\
	if (DEBUG_TIMER_MODE)						\
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

#undef	DEBUG_KVM_SHUTDOWN_MODE
#undef	DebugKVMSH
#define	DEBUG_KVM_SHUTDOWN_MODE	0	/* KVM shutdown debugging */
#define	DebugKVMSH(fmt, args...)					\
({									\
	if (DEBUG_KVM_SHUTDOWN_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

bool debug_VIRQs = false;
#undef	DEBUG_KVM_VIRQs_MODE
#undef	DebugVIRQs
#define	DEBUG_KVM_VIRQs_MODE	debug_VIRQs	/* VIRQs debugging */
#define	DebugVIRQs(fmt, args...)					\
({									\
	if (DEBUG_KVM_VIRQs_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_SHOW_GUEST_STACKS_MODE
#undef	DebugGST
#define	DEBUG_SHOW_GUEST_STACKS_MODE	true	/* show all guest stacks */
#define	DebugGST(fmt, args...)						\
({									\
	if (DEBUG_SHOW_GUEST_STACKS_MODE)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#define APIC_LVT_NUM			6
/* 14 is the version for Xeon and Pentium 8.4.8*/
#define LAPIC_MMIO_LENGTH		(1 << 12)

#define VEC_POS(v) ((v) & (32 - 1))
#define REG_POS(v) (((v) >> 5) << 4)

static inline u32 apic_get_reg(struct kvm_lapic *apic, int reg_off)
{
	apic_reg_debug("apic_get_reg(0x%x) = 0x%x from %px\n",
		reg_off, *((u32 *) (apic->regs + reg_off)),
		((u32 *) (apic->regs + reg_off)));
	return *((u32 *) (apic->regs + reg_off));
}

static inline void apic_set_reg(struct kvm_lapic *apic, int reg_off, u32 val)
{
	*((u32 *) (apic->regs + reg_off)) = val;
	apic_reg_debug("apic_set_reg(0x%x) = 0x%x to %px\n",
		reg_off, *((u32 *) (apic->regs + reg_off)),
		((u32 *) (apic->regs + reg_off)));
}

static inline int apic_test_and_set_vector(int vec, void *bitmap)
{
	return test_and_set_bit(VEC_POS(vec), (bitmap) + REG_POS(vec));
}

static inline int apic_test_and_clear_vector(int vec, void *bitmap)
{
	return test_and_clear_bit(VEC_POS(vec), (bitmap) + REG_POS(vec));
}

static inline void apic_set_vector(int vec, void *bitmap)
{
	set_bit(VEC_POS(vec), (bitmap) + REG_POS(vec));
}

static inline void apic_clear_vector(int vec, void *bitmap)
{
	clear_bit(VEC_POS(vec), (bitmap) + REG_POS(vec));
}

static inline int apic_hw_enabled(struct kvm_lapic *apic)
{
	return (apic)->vcpu->arch.apic_base == APIC_BASE;
}

static inline int apic_sw_enabled(struct kvm_lapic *apic)
{
	return apic_get_reg(apic, APIC_SPIV) & APIC_SPIV_APIC_ENABLED;
}

static inline int apic_enabled(struct kvm_lapic *apic)
{
	return apic_sw_enabled(apic) &&	apic_hw_enabled(apic);
}

#define LVT_MASK	\
	(APIC_LVT_MASKED | APIC_SEND_PENDING | APIC_VECTOR_MASK)

#define LINT_MASK	\
	(LVT_MASK | APIC_MODE_MASK | APIC_INPUT_POLARITY | \
	 APIC_LVT_REMOTE_IRR | APIC_LVT_LEVEL_TRIGGER)

static inline int kvm_apic_id(struct kvm_lapic *apic)
{
	return GET_APIC_ID(apic_get_reg(apic, APIC_ID));
}

static inline int apic_lvt_enabled(struct kvm_lapic *apic, int lvt_type)
{
	return !(apic_get_reg(apic, lvt_type) & APIC_LVT_MASKED);
}

static inline int apic_lvt_vector(struct kvm_lapic *apic, int lvt_type)
{
	return apic_get_reg(apic, lvt_type) & APIC_VECTOR_MASK;
}

static inline int apic_lvtt_period(struct kvm_lapic *apic)
{
	return apic_get_reg(apic, APIC_LVTT) & APIC_LVT_TIMER_PERIODIC;
}

static inline int apic_lvt_nmi_mode(u32 lvt_val)
{
	return (lvt_val & (APIC_MODE_MASK | APIC_LVT_MASKED)) == APIC_DM_NMI;
}

void kvm_apic_set_version(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic = vcpu->arch.apic;
	u32 v = SET_APIC_VERSION(APIC_VERSION);

	if (!irqchip_in_kernel(vcpu->kvm))
		return;

	v |= SET_APIC_MAXLVT(APIC_MAXLVT);

	apic_set_reg(apic, APIC_LVR, v);
}

static inline int apic_x2apic_mode(struct kvm_lapic *apic)
{
	return apic->vcpu->arch.apic_base & X2APIC_ENABLE;
}

static unsigned int apic_lvt_mask[APIC_LVT_NUM] = {
	LVT_MASK | APIC_LVT_TIMER_PERIODIC,	/* LVTT */
	LVT_MASK | APIC_MODE_MASK,	/* LVTTHMR */
	LVT_MASK | APIC_MODE_MASK,	/* LVTPC */
	LINT_MASK, LINT_MASK,	/* LVT0-1 */
	LVT_MASK		/* LVTERR */
};

static int find_highest_vector(void *bitmap)
{
	u32 *word = bitmap;
	int word_offset = MAX_APIC_VECTOR >> 5;

	while ((word_offset != 0) && (word[(--word_offset) << 2] == 0))
		continue;

	if (likely(!word_offset && !word[0]))
		return -1;
	else
		return fls(word[word_offset << 2]) - 1 + (word_offset << 5);
}

static inline int apic_test_and_set_irr(int vec, struct kvm_lapic *apic)
{
	if (unlikely(apic_test_and_set_vector(vec, apic->regs + APIC_IRR)))
		return 1;

	apic->irr_pending = true;
	return 0;
}

static inline int apic_search_irr(struct kvm_lapic *apic)
{
	return find_highest_vector(apic->regs + APIC_IRR);
}

static inline int apic_find_highest_irr(struct kvm_lapic *apic)
{
	int result;

	result = apic_search_irr(apic);
	if (!apic->irr_pending) {
		if (result == -1)
			return -1;
		apic->irr_pending = true;
	}
	ASSERT(result == -1 || result >= 16);

	return result;
}

static inline void apic_clear_irr(int vec, struct kvm_lapic *apic)
{
	apic->irr_pending = false;
	apic_clear_vector(vec, apic->regs + APIC_IRR);
	if (apic_search_irr(apic) != -1)
		apic->irr_pending = true;
}

int kvm_lapic_find_highest_irr(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic = vcpu->arch.apic;
	int highest_irr;

	/* This may race with setting of irr in __apic_accept_irq() and
	 * value returned may be wrong, but kvm_vcpu_kick() in __apic_accept_irq
	 * will cause vmexit immediately and the value will be recalculated
	 * on the next vmentry.
	 */
	if (!apic)
		return 0;
	highest_irr = apic_find_highest_irr(apic);

	return highest_irr;
}

static int __apic_accept_irq(struct kvm_lapic *apic, int delivery_mode,
			     int vector, int level, int trig_mode);

int kvm_apic_set_irq(struct kvm_vcpu *vcpu, struct kvm_lapic_irq *irq)
{
	struct kvm_lapic *apic = vcpu->arch.apic;

	DebugKVMIRQ("started for VCPU #%d vector 0x%x\n",
		vcpu->vcpu_id, irq->vector);
	if (unlikely(!apic->virq_is_setup)) {
		pr_warn_once("%s(): VCPU #%d lapic VIRQ is not yet setup by guest, "
			"so ignore interrupt #%d\n",
			__func__, vcpu->vcpu_id, irq->vector);
		return 0;
	}
	return __apic_accept_irq(apic, irq->delivery_mode, irq->vector,
			irq->level, irq->trig_mode);
}

static inline int apic_find_highest_isr(struct kvm_lapic *apic)
{
	int result;

	result = find_highest_vector(apic->regs + APIC_ISR);
	ASSERT(result == -1 || result >= 16);

	return result;
}

static void apic_update_ppr(struct kvm_lapic *apic)
{
	u32 tpr, isrv, ppr;
	int isr;

	tpr = apic_get_reg(apic, APIC_TASKPRI);
	isr = apic_find_highest_isr(apic);
	isrv = (isr != -1) ? isr : 0;

	if ((tpr & 0xf0) >= (isrv & 0xf0))
		ppr = tpr & 0xff;
	else
		ppr = isrv & 0xf0;

	apic_debug("vlapic %px, ppr 0x%x, isr 0x%x, isrv 0x%x",
		   apic, ppr, isr, isrv);

	apic_set_reg(apic, APIC_PROCPRI, ppr);
}

static void apic_set_tpr(struct kvm_lapic *apic, u32 tpr)
{
	apic_set_reg(apic, APIC_TASKPRI, tpr);
	apic_update_ppr(apic);
}

int kvm_apic_match_physical_addr(struct kvm_lapic *apic, u16 dest)
{
	return dest == 0xff || kvm_apic_id(apic) == dest;
}

int kvm_apic_match_logical_addr(struct kvm_lapic *apic, u8 mda)
{
	int result = 0;
	u32 logical_id;

	if (apic_x2apic_mode(apic)) {
		logical_id = apic_get_reg(apic, APIC_LDR);
		return logical_id & mda;
	}

	logical_id = GET_APIC_LOGICAL_ID(apic_get_reg(apic, APIC_LDR));

	switch (apic_get_reg(apic, APIC_DFR)) {
	case APIC_DFR_FLAT:
		if (logical_id & mda)
			result = 1;
		break;
	case APIC_DFR_CLUSTER:
		if (((logical_id >> 4) == (mda >> 0x4))
		    && (logical_id & mda & 0xf))
			result = 1;
		break;
	default:
		printk(KERN_WARNING "Bad DFR vcpu %d: %08x\n",
		       apic->vcpu->vcpu_id, apic_get_reg(apic, APIC_DFR));
		break;
	}

	return result;
}

int kvm_apic_match_dest(struct kvm_vcpu *vcpu, struct kvm_lapic *source,
			   int short_hand, int dest, int dest_mode)
{
	int result = 0;
	struct kvm_lapic *target = vcpu->arch.apic;

	apic_debug("target %px, source %px, dest 0x%x, "
		   "dest_mode 0x%x, short_hand 0x%x\n",
		   target, source, dest, dest_mode, short_hand);

	ASSERT(target);
	switch (short_hand) {
	case APIC_DEST_NOSHORT:
		if (dest_mode == 0)
			/* Physical mode. */
			result = kvm_apic_match_physical_addr(target, dest);
		else
			/* Logical mode. */
			result = kvm_apic_match_logical_addr(target, dest);
		break;
	case APIC_DEST_SELF:
		result = (target == source);
		break;
	case APIC_DEST_ALLINC:
		result = 1;
		break;
	case APIC_DEST_ALLBUT:
		result = (target != source);
		break;
	default:
		printk(KERN_WARNING "Bad dest shorthand value %x\n",
		       short_hand);
		break;
	}

	return result;
}

/*
 * Add a pending IRQ into lapic.
 * Return 1 if successfully added and 0 if discarded.
 */
static int __apic_accept_irq(struct kvm_lapic *apic, int delivery_mode,
			     int vector, int level, int trig_mode)
{
	int result = 0;
	struct kvm_vcpu *vcpu = apic->vcpu;

	DebugKVMAT("started for VCPU #%d vector 0x%x, delivery mode %d "
		"level %d trigger mode %d\n",
		apic->vcpu->vcpu_id, vector, delivery_mode, level, trig_mode);
	switch (delivery_mode) {
	case APIC_DM_LOWEST:
		DebugKVMAT("delivery mode is APIC_DM_LOWEST\n");
		vcpu->arch.apic_arb_prio++;
	case APIC_DM_FIXED:
		DebugKVMAT("delivery mode is APIC_DM_FIXED\n");
		/* FIXME add logic for vcpu on reset */
		if (unlikely(!apic_enabled(apic)))
			break;

		if (trig_mode) {
			apic_debug("level trig mode for vector %d", vector);
			apic_set_vector(vector, apic->regs + APIC_TMR);
		} else {
			apic_clear_vector(vector, apic->regs + APIC_TMR);
		}
		result = !apic_test_and_set_irr(vector, apic);
		trace_kvm_apic_accept_irq(vcpu->vcpu_id, delivery_mode,
					  trig_mode, vector, !result);
		if (!result) {
			if (trig_mode) {
				apic_debug("level trig mode repeatedly for "
						"vector %x", vector);
				DebugVIRQs("LAPIC #%d level trig mode "
					"repeatedly for vector %x\n",
					vcpu->vcpu_id, vector);
			} else {
				apic_debug("edge mode coalesced interrupt for "
						"vector %x", vector);
				DebugVIRQs("LAPIC #%d edge mode VIRQ coalesced "
					"for vector %x\n",
					vcpu->vcpu_id, vector);
				if (vector == 0x49 ||
					vector == 0x40 ||
					vector == 0x81 ||
					vector == 0xfd ||
					(vector == 0xef &&
						apic_lvtt_period(apic)))
					break;
				if (vector == 0xef &&
					!apic_lvtt_period(apic) &&
					atomic_read(
						&apic->lapic_timer.pending) <=
							2 &&
					atomic_read(
						&apic->lapic_timer.pending) >
							0)
					/* it can be while switch periodic */
					/* mode to one shot or back */
					break;
			}
			DebugVIRQs("LAPIC #%d current pending VIRQs num %d\n",
				vcpu->vcpu_id,
				kvm_read_guest_lapic_virqs_num(vcpu));
			break;
		}

		DebugVIRQs("LAPIC #%d set vector %x, current pending "
			"VIRQs num %d",
			vcpu->vcpu_id, vector,
			kvm_read_guest_lapic_virqs_num(vcpu));
		kvm_inject_lapic_virq(apic);
		break;

	case APIC_DM_REMRD:
		DebugKVMVEC("delivery mode is APIC_DM_REMRD\n");
		printk(KERN_DEBUG "Ignoring delivery mode 3\n");
		break;

	case APIC_DM_SMI:
		DebugKVMVEC("delivery mode is APIC_DM_SMI\n");
		printk(KERN_DEBUG "Ignoring guest SMI\n");
		break;

	case APIC_DM_NMI:
		DebugKVMVEC("delivery mode is APIC_DM_NMI\n");
		result = 1;
		kvm_inject_nmi(vcpu);
		kvm_vcpu_kick(vcpu);
		break;

	case APIC_DM_INIT:
		DebugKVMVEC("delivery mode is APIC_DM_INIT\n");
		if (level) {
			result = 1;
			if (vcpu->arch.mp_state == KVM_MP_STATE_RUNNABLE)
				printk(KERN_DEBUG
				       "INIT on a runnable vcpu %d\n",
				       vcpu->vcpu_id);
			vcpu->arch.mp_state = KVM_MP_STATE_INIT_RECEIVED;
			kvm_inject_lapic_virq(apic);
		} else {
			apic_debug("Ignoring de-assert INIT to vcpu %d\n",
				   vcpu->vcpu_id);
		}
		break;

	case APIC_DM_STARTUP:
		DebugKVMVEC("delivery mode is APIC_DM_STARTUP\n");
		apic_debug("SIPI to vcpu %d vector 0x%02x\n",
			   vcpu->vcpu_id, vector);
		if (vcpu->arch.mp_state == KVM_MP_STATE_INIT_RECEIVED) {
			result = 1;
			vcpu->arch.sipi_vector = vector;
			vcpu->arch.mp_state = KVM_MP_STATE_SIPI_RECEIVED;
			kvm_inject_lapic_virq(apic);
		}
		break;

	case APIC_DM_EXTINT:
		DebugKVMVEC("delivery mode is APIC_DM_EXTINT\n");
		/*
		 * Should only be called by kvm_apic_local_deliver() with LVT0,
		 * before NMI watchdog was enabled. Already handled by
		 * kvm_apic_accept_pic_intr().
		 */
		break;

	default:
		printk(KERN_ERR "TODO: unsupported delivery mode %x\n",
		       delivery_mode);
		break;
	}
	return result;
}

int kvm_apic_compare_prio(struct kvm_vcpu *vcpu1, struct kvm_vcpu *vcpu2)
{
	return vcpu1->arch.apic_arb_prio - vcpu2->arch.apic_arb_prio;
}

#ifdef CONFIG_KVM_HW_VIRTUALIZATION
static u32 hw_apic_find_cepic_priority(struct kvm_lapic *apic)
{
	int i;

	for (i = MAX_CEPIC_PRIORITY; i >= 0; i--) {
		if (apic->cepic_vector[i])
			return i;
	}

	pr_err("%s(): could not find cepic priority\n", __func__);

	return 0;
}

void hw_apic_set_eoi(struct kvm_lapic *apic)
{
	union cepic_eoi reg_eoi;
	union cepic_cpr reg_cpr;
	u32 cepic_priority = hw_apic_find_cepic_priority(apic);
	u32 cepic_vector = apic->cepic_vector[cepic_priority];

	reg_eoi.raw = 0;
	reg_eoi.bits.rcpr = cepic_priority;
	epic_write_guest_w(CEPIC_EOI, reg_eoi.raw);

	/* Restore CPR */
	reg_cpr.raw = 0;
	reg_cpr.bits.cpr = cepic_priority;
	epic_write_guest_w(CEPIC_CPR, reg_cpr.raw);

	kvm_ioapic_update_eoi(apic->vcpu->kvm, cepic_vector);

	apic->cepic_vector[cepic_priority] = 0;
}
#endif

void sw_apic_set_eoi(struct kvm_lapic *apic)
{
	int vector = apic_find_highest_isr(apic);
	/*
	 * Not every write EOI will has corresponding ISR,
	 * one example is when Kernel check timer on setup_IO_APIC
	 */
	if (vector == -1)
		return;

	apic_clear_vector(vector, apic->regs + APIC_ISR);
	apic_update_ppr(apic);

	apic_clear_vector(vector, apic->regs + APIC_TMR);
	if (!(apic_get_reg(apic, APIC_SPIV) & APIC_SPIV_DIRECTED_EOI))
		kvm_ioapic_update_eoi(apic->vcpu->kvm, vector);
}

static void apic_send_ipi(struct kvm_lapic *apic)
{
	u32 icr_low = apic_get_reg(apic, APIC_ICR);
	u32 icr_high = apic_get_reg(apic, APIC_ICR2);
	struct kvm_lapic_irq irq;

	irq.vector = icr_low & APIC_VECTOR_MASK;
	irq.delivery_mode = icr_low & APIC_MODE_MASK;
	irq.dest_mode = icr_low & APIC_DEST_MASK;
	irq.level = icr_low & APIC_INT_ASSERT;
	irq.trig_mode = icr_low & APIC_INT_LEVELTRIG;
	irq.shorthand = icr_low & APIC_SHORT_MASK;
	if (apic_x2apic_mode(apic))
		irq.dest_id = icr_high;
	else
		irq.dest_id = GET_APIC_DEST_FIELD(icr_high);

	trace_kvm_apic_ipi(icr_low, irq.dest_id);

	apic_debug("icr_high 0x%x, icr_low 0x%x, "
		   "short_hand 0x%x, dest 0x%x, trig_mode 0x%x, level 0x%x, "
		   "dest_mode 0x%x, delivery_mode 0x%x, vector 0x%x\n",
		   icr_high, icr_low, irq.shorthand, irq.dest_id,
		   irq.trig_mode, irq.level, irq.dest_mode, irq.delivery_mode,
		   irq.vector);

	kvm_irq_delivery_to_apic(apic->vcpu->kvm, apic, &irq);
}

#ifdef CONFIG_KVM_HW_VIRTUALIZATION
u32 hw_apic_get_tmcct(struct kvm_lapic *apic)
{
	return epic_read_guest_w(CEPIC_TIMER_CUR);
}
#endif

u32 sw_apic_get_tmcct(struct kvm_lapic *apic)
{
	struct kvm_vcpu *vcpu;
	s64 remaining;
	s64 running_time;
	s64 ns;
	s64 cycles;
	u64 tmcct;
	unsigned long flags;

	ASSERT(apic != NULL);

	/* if initial count is 0, current count should also be 0 */
	if (apic_get_reg(apic, APIC_TMICT) == 0)
		return 0;

	raw_local_irq_save(flags);

	vcpu = apic->vcpu;
	BUG_ON(kvm_get_guest_vcpu_runstate(vcpu) != RUNSTATE_in_hcall &&
		kvm_get_guest_vcpu_runstate(vcpu) != RUNSTATE_in_intercept);
	running_time = kvm_do_get_guest_vcpu_running_time(vcpu);
	cycles = get_cycles();
	DebugKVMTM("running time at start 0x%llx, now 0x%llx, cycles 0x%llx "
		"period 0x%llx\n",
		apic->lapic_timer.running_time, running_time, cycles,
		apic->lapic_timer.period);
	running_time -= apic->lapic_timer.running_time;
	DebugKVMTM("running 0x%llx\n", running_time);
	raw_local_irq_restore(flags);
	BUG_ON(running_time < 0);
	remaining = apic->lapic_timer.period - cycles_2nsec(running_time);
	if (remaining < 0)
		remaining = 0;
	DebugKVMTM("remaining time 0x%llx\n", remaining);

	if (apic->lapic_timer.period != 0) {
		ns = mod_64(remaining, apic->lapic_timer.period);
	} else {
		ns = 0;
	}
	cycles = nsecs_2cycles(ns);
	tmcct = div64_u64(cycles,
			 (APIC_BUS_CYCLE_NS * apic->divide_count));
	if (tmcct > 0xffffffffUL)
		tmcct = 0xffffffffUL;
	DebugKVMTM("ns 0x%llx, cycles 0x%llx tmcct 0x%llx\n",
		ns, cycles, tmcct);

	return tmcct;
}

static inline void report_tpr_access(struct kvm_lapic *apic, bool write)
{
	pr_err("report_tpr_access() is not yet implemented\n");
	ASSERT(1);
}

#ifdef CONFIG_KVM_HW_VIRTUALIZATION
u32 hw_apic_read_nm(struct kvm_lapic *apic)
{
	return epic_read_guest_w(CEPIC_PNMIRR);
}
#endif

u32 sw_apic_read_nm(struct kvm_lapic *apic)
{
	return apic_get_reg(apic, APIC_NM);
}

static u32 __apic_read(struct kvm_lapic *apic, unsigned int offset)
{
	u32 val = 0;

	if (offset >= LAPIC_MMIO_LENGTH)
		return 0;

	switch (offset) {
	case APIC_ID:
		if (apic_x2apic_mode(apic))
			val = kvm_apic_id(apic);
		else
			val = kvm_apic_id(apic) << 24;
		break;
	case APIC_ARBPRI:
		printk(KERN_WARNING "Access APIC ARBPRI register "
		       "which is for P6\n");
		break;

	case APIC_TMCCT:	/* Timer CCR */
		val = apic_get_tmcct(apic);
		break;

	case APIC_TASKPRI:
		report_tpr_access(apic, false);
		/* fall thru */
		break;
	case APIC_VECT:	/* Timer CCR */
		val = kvm_get_apic_interrupt(apic->vcpu);
		break;

	case APIC_NM:
		val = apic_read_nm(apic);
		break;

	default:
		apic_update_ppr(apic);
		val = apic_get_reg(apic, offset);
		break;
	}

	return val;
}

static inline struct kvm_lapic *to_lapic(struct kvm_io_device *dev)
{
	return container_of(dev, struct kvm_lapic, dev);
}

static int apic_reg_read(struct kvm_lapic *apic, u32 offset, int len,
		void *data)
{
	unsigned char alignment = offset & 0xf;
	u32 result;
	/* this bitmask has a bit cleared for each reserver register */
	static const u64 rmask = 0x43ff01ffffffe70eULL;

	if ((alignment + len) > 4) {
		apic_debug("KVM_APIC_READ: alignment error %x %d\n",
			   offset, len);
		return 1;
	}

	if (offset <= 0x3f0 && !(rmask & (1ULL << (offset >> 4)))) {
		apic_debug("KVM_APIC_READ: read reserved register %x\n",
			   offset);
		return 1;
	}

	result = __apic_read(apic, offset & ~0xf);

	trace_kvm_apic_read(offset, result);

	switch (len) {
	case 1:
	case 2:
	case 4:
		memcpy(data, (char *)&result + alignment, len);
		break;
	default:
		printk(KERN_ERR "Local APIC read with len = %x, "
		       "should be 1,2, or 4 instead\n", len);
		break;
	}
	return 0;
}

static int apic_mmio_in_range(struct kvm_lapic *apic, gpa_t addr)
{
	return apic_hw_enabled(apic) &&
	    addr >= apic->base_address &&
	    addr < apic->base_address + LAPIC_MMIO_LENGTH;
}

static int apic_mmio_read(struct kvm_vcpu *vcpu, struct kvm_io_device *this,
				gpa_t address, int len, void *data)
{
	struct kvm_lapic *apic = to_lapic(this);
	u32 offset = address - apic->base_address;

	if (!apic_mmio_in_range(apic, address))
		return -EOPNOTSUPP;

	apic_reg_debug("started to mmio read address 0x%lx, offset 0x%lx, "
		"len %d to %px\n",
		address, offset, len, data);

	apic_reg_read(apic, offset, len, data);
	apic_reg_debug("mmio read data 0x%lx\n", *(u64 *)data);

	return 0;
}

static void update_divide_count(struct kvm_lapic *apic)
{
	u32 tmp1, tmp2, tdcr;

	tdcr = apic_get_reg(apic, APIC_TDCR);
	tmp1 = tdcr & 0xf;
	tmp2 = ((tmp1 & 0x3) | ((tmp1 & 0x8) >> 1)) + 1;
	apic->divide_count = 0x1 << (tmp2 & 0x7);

	apic_debug("timer divide count is 0x%x\n",
				   apic->divide_count);
}

#ifdef CONFIG_KVM_HW_VIRTUALIZATION
void start_hw_apic_timer(struct kvm_lapic *apic, u32 apic_tmict)
{
	epic_write_guest_w(CEPIC_TIMER_INIT, apic_tmict);
	epic_write_guest_w(CEPIC_TIMER_CUR, apic_tmict);
}
#endif

void start_sw_apic_timer(struct kvm_lapic *apic, u32 apic_tmict)
{
	ktime_t now;
	long period;
	long cycles;

	hrtimer_cancel(&apic->lapic_timer.timer);
	apic_set_reg(apic, APIC_TMICT, apic_tmict);

	now = apic->lapic_timer.timer.base->get_time();
	cycles = get_cycles();
	period = cycles_2nsec((u64)apic_get_reg(apic, APIC_TMICT) *
				APIC_BUS_CYCLE_NS * apic->divide_count);
	DebugKVMTM("APIC TMICT 0x%x period 0x%lx cpu_freq_hz 0x%x "
		"cycles 0x%lx\n",
		apic_get_reg(apic, APIC_TMICT),
		period, cpu_freq_hz, cycles);
	if (unlikely(!apic->lapic_timer.started))
		apic->lapic_timer.started = true;
	atomic_set(&apic->lapic_timer.pending, 0);

	if (period == 0) {
		apic->lapic_timer.period = 0;
		return;
	}
	/*
	 * Do not allow the guest to program periodic timers with small
	 * interval, since the hrtimers are not throttled by the host
	 * scheduler.
	 */
	if (apic_lvtt_period(apic)) {
		if (period < NSEC_PER_MSEC/2)
			period = NSEC_PER_MSEC/2;
	}

again:
	if (!hrtimer_active(&apic->lapic_timer.timer)) {
		apic->lapic_timer.period = period;
		cycles = get_cycles();
		hrtimer_start(&apic->lapic_timer.timer,
			      ktime_add_ns(now, period),
			      HRTIMER_MODE_ABS);
		apic->lapic_timer.running_time =
			kvm_get_guest_vcpu_running_time(apic->vcpu);
		DebugKVMTM("started lapic hrtimer now 0x%llx period 0x%lx "
			"running time 0x%llx, cycles 0x%lx\n",
			ktime_to_ns(now), period,
			apic->lapic_timer.running_time, cycles);
	} else if (hrtimer_callback_running(&apic->lapic_timer.timer)) {
		BUG_ON(apic->lapic_timer.period != 0);
		cycles = get_cycles();
		hrtimer_add_expires_ns(&apic->lapic_timer.timer, period);
		apic->lapic_timer.period = period;
		apic->lapic_timer.running_time =
			kvm_get_guest_vcpu_running_time(apic->vcpu);
		DebugKVMTM("restarted lapic hrtimer now 0x%llx period 0x%lx "
			"running time 0x%llx, cycles 0x%lx\n",
			ktime_to_ns(now), period,
			apic->lapic_timer.running_time, cycles);
	} else {
		/* timer is active probably is completing, so waiting */
		DebugKVMTM("hrtimer is completing, small waiting\n");
		cpu_relax();
		goto again;
	}

	DebugTM("%s: bus cycle is %" PRId64 "ns, now 0x%016"
			   PRIx64 ", "
			   "timer initial count 0x%x, period %lldns, "
			   "expire @ 0x%016" PRIx64 ".\n", __func__,
			   APIC_BUS_CYCLE_NS, ktime_to_ns(now),
			   apic_get_reg(apic, APIC_TMICT),
			   apic->lapic_timer.period,
			   ktime_to_ns(ktime_add_ns(now,
					apic->lapic_timer.period)));
}

static void apic_manage_nmi_watchdog(struct kvm_lapic *apic, u32 lvt0_val)
{
	int nmi_wd_enabled = apic_lvt_nmi_mode(apic_get_reg(apic, APIC_LVT0));

	if (apic_lvt_nmi_mode(lvt0_val)) {
		if (!nmi_wd_enabled) {
			apic_debug("Receive NMI setting on APIC_LVT0 "
				   "for cpu %d\n", apic->vcpu->vcpu_id);
			apic->vcpu->kvm->arch.vapics_in_nmi_mode++;
		}
	} else if (nmi_wd_enabled) {
		apic->vcpu->kvm->arch.vapics_in_nmi_mode--;
	}
}

#ifdef CONFIG_KVM_HW_VIRTUALIZATION
void hw_apic_write_nm(struct kvm_lapic *apic, u32 val)
{
	union cepic_pnmirr reg_pnmirr, val_pnmirr;

	reg_pnmirr.raw = epic_read_guest_w(CEPIC_PNMIRR);
	val_pnmirr.raw = val;

	if (reg_pnmirr.bits.nmi && val_pnmirr.bits.nmi)
		reg_pnmirr.bits.nmi = 0;

	if (reg_pnmirr.raw & CEPIC_PNMIRR_BIT_MASK)
		pr_err("%s(): unsupported CEPIC NMI type\n", __func__);

	epic_write_guest_w(CEPIC_PNMIRR, reg_pnmirr.raw);
}

void hw_apic_write_lvtt(struct kvm_lapic *apic, u32 apic_lvtt)
{
	bool periodic = apic_lvtt & APIC_LVT_TIMER_PERIODIC;
	bool masked = apic_lvtt & APIC_LVT_MASKED;
	u32 vector = apic_lvtt & APIC_VECTOR_MASK;
	union cepic_timer_lvtt reg_lvtt;

	reg_lvtt.raw = 0;
	reg_lvtt.bits.mode = periodic;
	reg_lvtt.bits.mask = masked;
	reg_lvtt.bits.vect = vector;
	epic_write_guest_w(CEPIC_TIMER_LVTT, reg_lvtt.raw);
}
#endif

static int apic_reg_write(struct kvm_lapic *apic, u32 reg, u32 val)
{
	int ret = 0;

	trace_kvm_apic_write(reg, val);

	switch (reg) {
	case APIC_BSP:		/* Local APIC BSP */
	case APIC_ID:		/* Local APIC ID */
		if (!apic_x2apic_mode(apic))
			apic_set_reg(apic, APIC_ID, val);
		else
			ret = 1;
		break;

	case APIC_TASKPRI:
		report_tpr_access(apic, true);
		apic_set_tpr(apic, val & 0xff);
		break;

	case APIC_EOI:
		apic_set_eoi(apic);
		break;

	case APIC_LDR:
		if (!apic_x2apic_mode(apic))
			apic_set_reg(apic, APIC_LDR, val & APIC_LDR_MASK);
		else
			ret = 1;
		break;

	case APIC_DFR:
		if (!apic_x2apic_mode(apic))
			apic_set_reg(apic, APIC_DFR, val | 0x0FFFFFFF);
		else
			ret = 1;
		break;

	case APIC_SPIV: {
		u32 mask = 0x3ff;
		if (apic_get_reg(apic, APIC_LVR) & APIC_LVR_DIRECTED_EOI)
			mask |= APIC_SPIV_DIRECTED_EOI;
		apic_set_reg(apic, APIC_SPIV, val & mask);
		if (!(val & APIC_SPIV_APIC_ENABLED)) {
			int i;
			u32 lvt_val;

			for (i = 0; i < APIC_LVT_NUM; i++) {
				lvt_val = apic_get_reg(apic,
						       APIC_LVTT + 0x10 * i);
				apic_set_reg(apic, APIC_LVTT + 0x10 * i,
					     lvt_val | APIC_LVT_MASKED);
			}
			atomic_set(&apic->lapic_timer.pending, 0);

		}
		break;
	}
	case APIC_ICR:
		/* No delay here, so we always clear the pending bit */
		apic_set_reg(apic, APIC_ICR, val & ~(1 << 12));
		apic_send_ipi(apic);
		break;

	case APIC_ICR2:
		if (!apic_x2apic_mode(apic))
			val &= 0xff000000;
		apic_set_reg(apic, APIC_ICR2, val);
		break;

	case APIC_LVT0:
		apic_manage_nmi_watchdog(apic, val);
	case APIC_LVTTHMR:
	case APIC_LVTPC:
	case APIC_LVT1:
	case APIC_LVTERR:
		/* TODO: Check vector */
		if (!apic_sw_enabled(apic))
			val |= APIC_LVT_MASKED;

		val &= apic_lvt_mask[(reg - APIC_LVTT) >> 4];
		apic_set_reg(apic, reg, val);

		break;

	case APIC_LVTT:
		apic_write_lvtt(apic, val);
		apic_set_reg(apic, reg, val);

	case APIC_TMICT:
		if (!apic->lapic_timer.started) {
			DebugKVMSH("VCPU #%d local apic timer is starting up\n",
				apic->vcpu->vcpu_id);
		}
		start_apic_timer(apic, val);
		break;

	case APIC_TDCR:
		if (val & 4)
			printk(KERN_ERR "KVM_WRITE:TDCR %x\n", val);
		apic_set_reg(apic, APIC_TDCR, val);
		update_divide_count(apic);
		break;

	case APIC_ESR:
		if (apic_x2apic_mode(apic) && val != 0) {
			printk(KERN_ERR "KVM_WRITE:ESR not zero %x\n", val);
			ret = 1;
		}
		break;

	case APIC_SELF_IPI:
		if (apic_x2apic_mode(apic)) {
			apic_reg_write(apic, APIC_ICR, 0x40000 | (val & 0xff));
		} else
			ret = 1;
		break;

	case APIC_NM:
		apic_write_nm(apic, val);
		break;

	default:
		ret = 1;
		break;
	}
	if (ret)
		apic_debug("Local APIC Write to read-only register %x\n", reg);
	return ret;
}

static int apic_mmio_write(struct kvm_vcpu *vcpu, struct kvm_io_device *this,
				gpa_t address, int len, const void *data)
{
	struct kvm_lapic *apic = to_lapic(this);
	unsigned int offset = address - apic->base_address;
	u32 val;

	if (!apic_mmio_in_range(apic, address))
		return -EOPNOTSUPP;

	/*
	 * APIC register must be aligned on 128-bits boundary.
	 * 32/64/128 bits registers must be accessed thru 32 bits.
	 * Refer SDM 8.4.1
	 */
	if (len != 4 || (offset & 0xf)) {
		/* Don't shout loud, $infamous_os would cause only noise. */
		apic_debug("apic write: bad size=%d %lx\n", len, (long)address);
		return 0;
	}

	val = *(u32 *)data;

	/* too common printing */
	if (offset != APIC_EOI)
		apic_debug("%s: offset 0x%x with length 0x%x, and value is "
			   "0x%x\n", __func__, offset, len, val);

	apic_reg_write(apic, offset & 0xff0, val);

	return 0;
}

void kvm_free_lapic(struct kvm_vcpu *vcpu)
{
	if (!vcpu->arch.apic)
		return;

	if (!kvm_vcpu_is_hw_apic(vcpu))
		hrtimer_cancel(&vcpu->arch.apic->lapic_timer.timer);

	if (vcpu->arch.apic->regs_page)
		__free_page(vcpu->arch.apic->regs_page);

	kfree(vcpu->arch.apic);
	vcpu->arch.apic = NULL;
}

/*
 *----------------------------------------------------------------------
 * LAPIC interface
 *----------------------------------------------------------------------
 */

void kvm_lapic_set_base(struct kvm_vcpu *vcpu, u64 value)
{
	struct kvm_lapic *apic = vcpu->arch.apic;

	if (!apic) {
		vcpu->arch.apic_base = value;
		return;
	}

	vcpu->arch.apic_base = value;
	if (apic_x2apic_mode(apic)) {
		u32 id = kvm_apic_id(apic);
		u32 ldr = ((id & ~0xf) << 16) | (1 << (id & 0xf));
		apic_set_reg(apic, APIC_LDR, ldr);
	}
	apic->base_address = apic->vcpu->arch.apic_base;

	/* with FSB delivery interrupt, we can restart APIC functionality */
	apic_debug("apic base msr is 0x%016" PRIx64 ", and base address is "
		   "0x%lx.\n", apic->vcpu->arch.apic_base, apic->base_address);

}

void kvm_lapic_reset(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic;
	unsigned int reg;
	int i;

	apic_debug("%s\n", __func__);

	ASSERT(vcpu);
	apic = vcpu->arch.apic;
	ASSERT(apic != NULL);

	/* Stop the timer in case it's a reset to an active apic */
	if (!kvm_vcpu_is_hw_apic(vcpu)) {
		hrtimer_cancel(&apic->lapic_timer.timer);
		DebugKVMSH("VCPU #%d local apic at %px was shutting down\n",
			vcpu->vcpu_id, &apic->lapic_timer.timer);
	}

	apic_set_reg(apic, APIC_ID, vcpu->vcpu_id << 24);

	kvm_apic_set_version(apic->vcpu);

	for (i = 0; i < APIC_LVT_NUM; i++)
		apic_set_reg(apic, APIC_LVTT + 0x10 * i, APIC_LVT_MASKED);
	apic_set_reg(apic, APIC_LVT0,
		     SET_APIC_DELIVERY_MODE(0, APIC_MODE_EXTINT));
	apic_set_reg(apic, APIC_LVT2, APIC_LVT_MASKED);
	apic_set_reg(apic, APIC_DSP, APIC_LVT_MASKED);
	apic_set_reg(apic, APIC_LVT4, APIC_LVT_MASKED);

	apic_set_reg(apic, APIC_DFR, 0xffffffffU);
	apic_set_reg(apic, APIC_SPIV, 0xff);
	apic_set_reg(apic, APIC_TASKPRI, 0);
	apic_set_reg(apic, APIC_LDR, 0);
	apic_set_reg(apic, APIC_ESR, 0);
	apic_set_reg(apic, APIC_ICR, 0);
	apic_set_reg(apic, APIC_ICR2, 0);
	apic_set_reg(apic, APIC_TDCR, 0);
	apic_set_reg(apic, APIC_TMICT, 0);
	for (i = 0; i < 8; i++) {
		apic_set_reg(apic, APIC_IRR + 0x10 * i, 0);
		apic_set_reg(apic, APIC_ISR + 0x10 * i, 0);
		apic_set_reg(apic, APIC_TMR + 0x10 * i, 0);
	}

	reg = APIC_NM_PCI | APIC_NM_SPECIAL | APIC_NM_TIMER |
		APIC_NM_NMI_DEBUG_MASK | APIC_NM_INTQLAPIC_MASK |
			APIC_NM_INT_VIOLAT_MASK;
	apic_set_reg(apic, APIC_M_ERM, reg);
	apic_set_reg(apic, APIC_NM, reg);

	apic->irr_pending = false;
	update_divide_count(apic);
	if (!kvm_vcpu_is_hw_apic(vcpu)) {
		atomic_set(&apic->lapic_timer.pending, 0);
		apic->lapic_timer.started = false;
	}
	reg = APIC_BSP_ENABLE;
	if (kvm_vcpu_is_bsp(vcpu))
		reg |= APIC_BSP_IS_BSP;
	apic_set_reg(apic, APIC_BSP, reg);
	apic_update_ppr(apic);

	vcpu->arch.apic_arb_prio = 0;
	apic->virq_is_setup = false;

	apic_debug(KERN_INFO "%s: vcpu=%px, id=%d, base_msr="
		   "0x%016" PRIx64 ", base_address=0x%0lx.\n", __func__,
		   vcpu, kvm_apic_id(apic),
		   vcpu->arch.apic_base, apic->base_address);
}

void kvm_lapic_virq_setup(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic;

	apic = vcpu->arch.apic;
	E2K_KVM_BUG_ON(apic == NULL);
	if (unlikely(apic->virq_is_setup)) {
		pr_warn("%s(): VCPU #%d lapic VIRQ has been already setup\n",
			__func__, vcpu->vcpu_id);
	} else {
		apic->virq_is_setup = true;
	}
}

/*
 * Reset & restart LAPIC
 */
void kvm_lapic_restart(struct kvm_vcpu *vcpu)
{
	int irq, ret;

	kvm_lapic_reset(vcpu);

	if (vcpu->arch.is_hv) {
		irq = vcpu->vcpu_id * KVM_NR_VIRQS + KVM_VIRQ_LAPIC;
		ret = kvm_get_guest_direct_virq(vcpu, irq, KVM_VIRQ_LAPIC);
		E2K_KVM_BUG_ON(ret != 0);
		kvm_lapic_virq_setup(vcpu);
	} else if (vcpu->arch.is_pv) {
		/* paravirtualized guest should register VCPUs itself */
		;
	}
}

bool kvm_apic_present(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.apic && apic_hw_enabled(vcpu->arch.apic);
}

int kvm_lapic_enabled(struct kvm_vcpu *vcpu)
{
	return kvm_apic_present(vcpu) && apic_sw_enabled(vcpu->arch.apic);
}

/*
 *----------------------------------------------------------------------
 * timer interface
 *----------------------------------------------------------------------
 */

static bool lapic_is_periodic(struct kvm_timer *ktimer)
{
	struct kvm_lapic *apic = container_of(ktimer, struct kvm_lapic,
					      lapic_timer);
	return apic_lvtt_period(apic);
}

int apic_has_pending_timer(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *lapic = vcpu->arch.apic;

	if (lapic && apic_enabled(lapic) && apic_lvt_enabled(lapic, APIC_LVTT))
		return atomic_read(&lapic->lapic_timer.pending);

	return 0;
}

static int kvm_apic_local_deliver(struct kvm_lapic *apic, int lvt_type)
{
	u32 reg = apic_get_reg(apic, lvt_type);
	int vector, mode, trig_mode;

	if (apic_hw_enabled(apic) && !(reg & APIC_LVT_MASKED)) {
		vector = reg & APIC_VECTOR_MASK;
		mode = reg & APIC_MODE_MASK;
		trig_mode = reg & APIC_LVT_LEVEL_TRIGGER;
		return __apic_accept_irq(apic, mode, vector, 1, trig_mode);
	}
	return 0;
}

void kvm_apic_nmi_wd_deliver(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic = vcpu->arch.apic;

	if (apic)
		kvm_apic_local_deliver(apic, APIC_LVT0);
}

int kvm_apic_sysrq_deliver(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic = vcpu->arch.apic;

	DebugGST("started for VCPU #%d\n", vcpu->vcpu_id);
	if (apic && apic_hw_enabled(apic)) {
		/* set NMI interrupt type as reason to interrupt */
		apic_set_reg(apic, APIC_NM, APIC_NM_NMI);

		return __apic_accept_irq(apic,
				APIC_DM_FIXED,
				SYSRQ_SHOWSTATE_APIC_VECTOR,
				1,	/* level */
				1);	/* trigger mode */
	}
	return 0;
}

int kvm_apic_nmi_deliver(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic = vcpu->arch.apic;

	if (apic && apic_hw_enabled(apic)) {
		/* NMI is not used only to dump active stack on VCPU */
		/* DO_DUMP_VCPU_STACK(vcpu) = true; */
		return __apic_accept_irq(apic,
				APIC_DM_FIXED,
				KVM_NMI_APIC_VECTOR,
				1,	/* level */
				1);	/* trigger mode */
	}
	return 0;
}

static const struct kvm_timer_ops lapic_timer_ops = {
	.is_periodic = lapic_is_periodic,
};

static const struct kvm_io_device_ops apic_mmio_ops = {
	.read     = apic_mmio_read,
	.write    = apic_mmio_write,
};

int kvm_create_lapic(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic;
	int ret = 0;

	ASSERT(vcpu != NULL);
	apic_debug("apic_init %d\n", vcpu->vcpu_id);

	apic = kzalloc(sizeof(*apic), GFP_KERNEL);
	if (!apic) {
		ret = -ENOMEM;
		goto nomem;
	}

	vcpu->arch.apic = apic;

	apic->regs_page = alloc_page(GFP_KERNEL);
	if (apic->regs_page == NULL) {
		printk(KERN_ERR "malloc apic regs error for vcpu %x\n",
		       vcpu->vcpu_id);
		ret = -ENOMEM;
		goto nomem_free_apic;
	}
	apic->regs = page_address(apic->regs_page);
	memset(apic->regs, 0, PAGE_SIZE);
	apic->vcpu = vcpu;

	/* If possible, use hardware CEPIC timer instead */
	if (!kvm_vcpu_is_hw_apic(vcpu)) {
		hrtimer_init(&apic->lapic_timer.timer, CLOCK_MONOTONIC,
			     HRTIMER_MODE_ABS);
		apic->lapic_timer.timer.function = kvm_apic_timer_fn;
		apic->lapic_timer.t_ops = &lapic_timer_ops;
		apic->lapic_timer.kvm = vcpu->kvm;
		apic->lapic_timer.vcpu = vcpu;
	}

	apic->base_address = APIC_DEFAULT_PHYS_BASE;
	vcpu->arch.apic_base = APIC_DEFAULT_PHYS_BASE;

	kvm_iodevice_init(&apic->dev, &apic_mmio_ops);

	return 0;
nomem_free_apic:
	kfree(apic);
nomem:
	return ret;
}

void kvm_print_APIC_field(struct kvm_lapic *apic, int base)
{
	int i;

	for (i = 0; i < 8; i++)
		pr_cont("%08x", apic_get_reg(apic, base + i*0x10));

	pr_cont("\n");
}

void kvm_print_local_APIC(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic;
	unsigned int v, icr;

	apic = vcpu->arch.apic;
	if (apic == NULL) {
		pr_info("local APIC on VCPU #%d is absent\n",
			vcpu->vcpu_id);
		return;
	} else {
		pr_info("local APIC contents on VCPU #%d\n",
			vcpu->vcpu_id);
	}
	v = kvm_apic_id(apic);
	pr_info("... APIC ID:      %08x\n", v);
	v = apic_get_reg(apic, APIC_LVR);
	pr_info("... APIC VERSION: %08x\n", v);

	v = apic_get_reg(apic, APIC_LDR);
	pr_info("... APIC LDR: %08x\n", v);
	if (!apic_x2apic_mode(apic)) {
		v = apic_get_reg(apic, APIC_DFR);
		pr_info("... APIC DFR: %08x\n", v);
	}
	v = apic_get_reg(apic, APIC_SPIV);
	pr_info("... APIC SPIV: %08x\n", v);

	v = apic_get_reg(apic, APIC_PROCPRI);
	pr_info("... APIC PROCPRI: %08x\n", v);

	pr_info("... IRR PENDING %d\n", apic->irr_pending);
	pr_info("... APIC ISR field: ");
	kvm_print_APIC_field(apic, APIC_ISR);
	pr_info("... APIC TMR field: ");
	kvm_print_APIC_field(apic, APIC_TMR);
	pr_info("... APIC IRR field: ");
	kvm_print_APIC_field(apic, APIC_IRR);

	icr = apic_get_reg(apic, APIC_ICR);
	pr_info("... APIC ICR: %08x\n", icr);
	icr = apic_get_reg(apic, APIC_ICR2);
	pr_info("... APIC ICR2: %08x\n", icr);

	v = apic_get_reg(apic, APIC_LVTT);
	pr_info("... APIC LVTT: %08x\n", v);

	v = apic_get_reg(apic, APIC_LVT0);
	pr_info("... APIC LVT0: %08x\n", v);
	v = apic_get_reg(apic, APIC_LVT1);
	pr_info("... APIC LVT1: %08x\n", v);

	v = apic_get_reg(apic, APIC_LVTERR);
	pr_info("... APIC LVTERR: %08x\n", v);

	v = apic_get_reg(apic, APIC_TMICT);
	pr_info("... APIC TMICT: %08x\n", v);
	v = apic_get_reg(apic, APIC_TMCCT);
	pr_info("... APIC TMCCT: %08x\n", v);
	v = apic_get_reg(apic, APIC_TDCR);
	pr_info("... APIC TDCR: %08x\n", v);

	pr_info("local APIC on VCPU #%d timer state:\n",
		vcpu->vcpu_id);
	pr_info("... started %d pending %d period 0x%llx start at 0x%llx\n",
		apic->lapic_timer.started,
		atomic_read(&apic->lapic_timer.pending),
		apic->lapic_timer.period,
		apic->lapic_timer.running_time);
}

int kvm_apic_has_interrupt(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic = vcpu->arch.apic;
	int highest_irr;
	int old_highest_irr;

	if (!apic || !apic_enabled(apic))
		return -1;

	old_highest_irr = apic_find_highest_irr(apic);
	apic_update_ppr(apic);
	highest_irr = apic_find_highest_irr(apic);
	if ((highest_irr == -1) ||
	    ((highest_irr & 0xF0) <= apic_get_reg(apic, APIC_PROCPRI))) {
		pr_err("highest_irr 0x%x before update 0x%x\n",
			highest_irr, old_highest_irr);
		kvm_print_local_APIC(vcpu);
		return -1;
	}
	return highest_irr;
}

int kvm_apic_accept_pic_intr(struct kvm_vcpu *vcpu)
{
	u32 lvt0 = apic_get_reg(vcpu->arch.apic, APIC_LVT0);
	int r = 0;

	if (kvm_vcpu_is_bsp(vcpu)) {
		if (!apic_hw_enabled(vcpu->arch.apic))
			r = 1;
		if ((lvt0 & APIC_LVT_MASKED) == 0 &&
		    GET_APIC_DELIVERY_MODE(lvt0) == APIC_MODE_EXTINT)
			r = 1;
	}
	return r;
}

void kvm_inject_apic_timer_irqs(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic = vcpu->arch.apic;

	DebugKVMAT("started timer pending %d\n",
		atomic_read(&apic->lapic_timer.pending));
	if (apic && atomic_read(&apic->lapic_timer.pending) > 0) {
		if (kvm_apic_local_deliver(apic, APIC_LVTT)) {
			atomic_dec(&apic->lapic_timer.pending);
			DebugKVMAT("delivered timer pending %d\n",
				atomic_read(&apic->lapic_timer.pending));
		} else {
			DebugKVMAT("local APIC timer interrupt was coalesced "
				"for VCPU #%d\n", vcpu->vcpu_id);
			if (!apic_lvtt_period(apic) &&
				(atomic_read(&apic->lapic_timer.pending) > 1 ||
				atomic_read(&apic->lapic_timer.pending) == 0)) {
				/* it can be while switch periodic */
				/* mode to one shot or back */
				E2K_LMS_HALT_OK;
			}
		}
	}
}

#ifdef CONFIG_KVM_HW_VIRTUALIZATION
int kvm_get_hw_apic_interrupt(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic = vcpu->arch.apic;
	union cepic_vect_inta reg_vect_inta;
	union cepic_cpr reg_cpr;
	union cepic_cir reg_cir;

	reg_cir.raw = epic_read_guest_w(CEPIC_CIR);
	reg_cpr.raw = epic_read_guest_w(CEPIC_CPR);
	reg_vect_inta.raw = epic_read_guest_w(CEPIC_VECT_INTA);

	if (reg_vect_inta.bits.vect != reg_cir.bits.vect)
		pr_err("CEPIC inta and cir vectors don't match: 0x%x 0x%x\n",
			reg_vect_inta.bits.vect, reg_cir.bits.vect);
	if (reg_vect_inta.bits.cpr != reg_cpr.bits.cpr)
		pr_err("CEPIC inta and cpr prio don't match: 0x%x 0x%x\n",
			reg_vect_inta.bits.cpr, reg_cpr.bits.cpr);

	apic->cepic_vector[reg_vect_inta.bits.cpr] = reg_vect_inta.bits.vect;

	/* Update CPR and clear CIR */
	reg_cpr.bits.cpr = (reg_vect_inta.bits.vect >> 8) + 1;
	reg_cir.raw = 0;

	epic_write_guest_w(CEPIC_CPR, reg_cpr.raw);
	epic_write_guest_w(CEPIC_CIR, reg_cir.raw);

	return reg_vect_inta.bits.vect;
}
#endif

int kvm_get_sw_apic_interrupt(struct kvm_vcpu *vcpu)
{
	int vector = kvm_apic_has_interrupt(vcpu);
	struct kvm_lapic *apic = vcpu->arch.apic;
	unsigned long flags;

	DebugKVMAT("vector is 0x%x\n", vector);
	if (vector == -1)
		return -1;

	apic_set_vector(vector, apic->regs + APIC_ISR);
	apic_update_ppr(apic);
	apic_clear_irr(vector, apic);
	apic_debug("kvm_get_apic_interrupt() vector is 0x%x\n", vector);

	if (kvm_test_pending_virqs(vcpu)) {
		int virqs_num;

		raw_spin_lock_irqsave(&vcpu->kvm->arch.virq_lock, flags);
		virqs_num = kvm_dec_vcpu_pending_virq(vcpu, apic->virq_no);
		if (!apic->irr_pending) {
			/* nothing more pending VIRQs, clear flag */
			kvm_clear_pending_virqs(vcpu);
			/* only APIC interrupts can be now injected */
			E2K_KVM_BUG_ON(kvm_get_pending_virqs_num(vcpu) != 0);
		}
		/* clear flag to enable new injections to handle */
		/* remaining here pending VIRQs on IRR or new one */
		kvm_clear_virqs_injected(vcpu);
		trace_kvm_apic_irq_vector(vcpu->vcpu_id, vector, virqs_num);
		raw_spin_unlock_irqrestore(&vcpu->kvm->arch.virq_lock, flags);
	} else {
		trace_kvm_apic_irq_vector(vcpu->vcpu_id, vector, -1);
	}

	DebugVIRQs("LAPIC #%d VIRQ vector is %x\n",
		vcpu->vcpu_id, vector);
	return vector;
}

#if 0
void kvm_apic_post_state_restore(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic = vcpu->arch.apic;

	apic->base_address = vcpu->arch.apic_base;
	kvm_apic_set_version(vcpu);

	apic_update_ppr(apic);
	hrtimer_cancel(&apic->lapic_timer.timer);
	update_divide_count(apic);
	start_apic_timer(apic);
	apic->irr_pending = true;
}
#endif

void __kvm_migrate_apic_timer(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic = vcpu->arch.apic;
	struct hrtimer *timer;

	if (!apic)
		return;

	timer = &apic->lapic_timer.timer;
	if (hrtimer_cancel(timer)) {
		apic->lapic_timer.running_time =
			kvm_get_guest_vcpu_running_time(apic->vcpu);
		hrtimer_start_expires(timer, HRTIMER_MODE_ABS);
	}
}

#ifdef	CONFIG_VIRT_LOCAL_APIC
void kvm_lapic_sync_from_vapic(struct kvm_vcpu *vcpu)
{
	u32 data;

	if (test_bit(KVM_APIC_PV_EOI_PENDING, &vcpu->arch.apic_attention))
		apic_sync_pv_eoi_from_guest(vcpu, vcpu->arch.apic);

	if (!test_bit(KVM_APIC_CHECK_VAPIC, &vcpu->arch.apic_attention))
		return;

	if (kvm_read_guest_cached(vcpu->kvm, &vcpu->arch.apic->vapic_cache,
					&data, sizeof(u32)))
		return;

	apic_set_tpr(vcpu->arch.apic, data & 0xff);
}

void kvm_lapic_sync_to_vapic(struct kvm_vcpu *vcpu)
{
	u32 data, tpr;
	int max_irr, max_isr;
	struct kvm_lapic *apic = vcpu->arch.apic;

	apic_sync_pv_eoi_to_guest(vcpu, apic);

	if (!test_bit(KVM_APIC_CHECK_VAPIC, &vcpu->arch.apic_attention))
		return;

	tpr = kvm_apic_get_reg(apic, APIC_TASKPRI) & 0xff;
	max_irr = apic_find_highest_irr(apic);
	if (max_irr < 0)
		max_irr = 0;
	max_isr = apic_find_highest_isr(apic);
	if (max_isr < 0)
		max_isr = 0;
	data = (tpr & 0xff) | ((max_isr & 0xf0) << 8) | (max_irr << 24);

	kvm_write_guest_cached(vcpu->kvm, &vcpu->arch.apic->vapic_cache, &data,
				sizeof(u32));
}
#endif	/* CONFIG_VIRT_LOCAL_APIC */

void kvm_lapic_set_vapic_addr(struct kvm_vcpu *vcpu, gpa_t vapic_addr)
{
	if (!irqchip_in_kernel(vcpu->kvm))
		return;

	vcpu->arch.apic->vapic_addr = vapic_addr;
}

bool kvm_vcpu_has_apic_interrupts(const struct kvm_vcpu *vcpu)
{
	return !vcpu->arch.hcall_irqs_disabled && kvm_test_pending_virqs(vcpu);
}

bool kvm_check_lapic_priority(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic = vcpu->arch.apic;
	u32 ppr = apic_get_reg(apic, APIC_PROCPRI);
	int max_irr = apic_find_highest_irr(apic);

	if ((max_irr & 0xf0) <= ppr)
		return false;
	else
		return true;
}
