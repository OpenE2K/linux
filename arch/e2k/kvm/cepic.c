/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * CEPIC virtualization.
 * Based on Xen 3.1 code.
 * Based on arch/x86/kvm/cepic.c code.
 */

#include <linux/kvm_host.h>
#include <linux/kvm.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/smp.h>
#include <linux/irq.h>
#include <linux/hrtimer.h>
#include <linux/io.h>
#include <linux/export.h>
#include <linux/math64.h>
#include <asm/processor.h>
#include <asm/page.h>
#include <asm/current.h>
#include <asm/epic.h>
#include <asm/atomic.h>
#include <asm/kvm/runstate.h>
#include <trace/events/kvm.h>
#include <asm/kvm/trace_kvm.h>

#undef	DEBUG

#include "ioapic.h"
#include "ioepic.h"
#include "irq.h"
#include "cepic.h"

#define mod_64(x, y) ((x) % (y))

#define PRId64 "d"
#define PRIx64 "llx"
#define PRIu64 "u"
#define PRIo64 "o"

#ifdef	DEBUG
#define epic_debug(fmt, arg...)		pr_warn(fmt, ##arg)
#define	epic_reg_debug(fmt, arg...)	pr_warn(fmt, ##arg)
#else	/* ! DEBUG */
#define epic_debug(fmt, arg...)
#define	epic_reg_debug(fmt, arg...)
#endif	/* DEBUG */

#undef	DEBUG_KVM_IRQ_MODE
#undef	DebugKVMIRQ
#define	DEBUG_KVM_IRQ_MODE	0	/* kernel EPIC IRQs debugging */
#define	DebugKVMIRQ(fmt, args...)					\
({									\
	if (DEBUG_KVM_IRQ_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_TIMER_MODE
#undef	DebugKVMTM
#define	DEBUG_KVM_TIMER_MODE	0	/* kernel epic timer debugging */
#define	DebugKVMTM(fmt, args...)					\
({									\
	if (DEBUG_KVM_TIMER_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_EPIC_TIMER_MODE
#undef	DebugKVMAT
#define	DEBUG_KVM_EPIC_TIMER_MODE	0	/* KVM CEPIC timer debugging */
#define	DebugKVMAT(fmt, args...)					\
({									\
	if (DEBUG_KVM_EPIC_TIMER_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_VIRQs_MODE
#undef	DebugVIRQs
#define	DEBUG_KVM_VIRQs_MODE	0	/* VIRQs debugging */
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

#define CEPIC_MMIO_LENGTH		(4 * PAGE_SIZE)
/* followed define is not in epicdef.h */
#define EPIC_SHORT_MASK			0xc0000
#define EPIC_DEST_NOSHORT		0x0
#define EPIC_DEST_MASK			0x800
#define MAX_EPIC_VECTOR			1024

static inline u32 epic_get_reg_w(struct kvm_cepic *epic, int reg_off)
{
	epic_reg_debug("%s(0x%x) = 0x%x from %px\n",
		__func__, reg_off, *((u32 *) (epic->regs + reg_off)),
		((u32 *) (epic->regs + reg_off)));
	return *((u32 *) (epic->regs + reg_off));
}

static inline void epic_set_reg_w(struct kvm_cepic *epic, int reg_off, u32 val)
{
	*((u32 *) (epic->regs + reg_off)) = val;
	epic_reg_debug("%s(0x%x) = 0x%x to %px\n",
		__func__, reg_off, *((u32 *) (epic->regs + reg_off)),
		((u32 *) (epic->regs + reg_off)));
}

static inline u64 epic_get_reg_d(struct kvm_cepic *epic, int reg_off)
{
	epic_reg_debug("%s(0x%x) = 0x%x from %px\n",
		__func__, reg_off, *((u64 *) (epic->regs + reg_off)),
		((u64 *) (epic->regs + reg_off)));
	return *((u64 *) (epic->regs + reg_off));
}

static inline void epic_set_reg_d(struct kvm_cepic *epic, int reg_off, u32 val)
{
	*((u64 *) (epic->regs + reg_off)) = val;
	epic_reg_debug("%s(0x%x) = 0x%x to %px\n",
		__func__, reg_off, *((u64 *) (epic->regs + reg_off)),
		((u64 *) (epic->regs + reg_off)));
}

static inline int epic_hw_enabled(struct kvm_cepic *epic)
{
	return (epic)->vcpu->arch.epic_base == EPIC_DEFAULT_PHYS_BASE;
}

static inline int epic_sw_enabled(struct kvm_cepic *epic)
{
	union cepic_ctrl reg;

	reg.raw = epic_get_reg_w(epic, CEPIC_CTRL);

	return reg.bits.soft_en;
}

static inline int epic_enabled(struct kvm_cepic *epic)
{
	return epic_sw_enabled(epic) &&	epic_hw_enabled(epic);
}

int kvm_epic_id(struct kvm_cepic *epic)
{
	return epic_get_reg_w(epic, CEPIC_ID);
}

static inline int epic_lvtt_enabled(struct kvm_cepic *epic)
{
	union cepic_timer_lvtt reg;

	reg.raw = epic_get_reg_w(epic, CEPIC_TIMER_LVTT);

	return !(reg.bits.mask);
}

static inline int epic_lvtt_period(struct kvm_cepic *epic)
{
	union cepic_timer_lvtt reg;

	reg.raw = epic_get_reg_w(epic, CEPIC_TIMER_LVTT);

	return reg.bits.mode;
}

static inline int epic_test_and_set_irr(int vec, struct kvm_cepic *epic)
{
	u64 *cepic_pmirr = epic->regs + CEPIC_PMIRR;

	epic->irr_pending = true;

	return test_and_set_bit(vec & 0x3f, (void *)&cepic_pmirr[vec >> 6]);
}

static inline int epic_search_irr(struct kvm_cepic *epic)
{
	u64 *cepic_pmirr = epic->regs + CEPIC_PMIRR;
	int reg_num;

	for (reg_num = CEPIC_PMIRR_NR_DREGS - 1; reg_num >= 0; reg_num--)
		if (cepic_pmirr[reg_num])
			return fls64(cepic_pmirr[reg_num]) - 1 + (reg_num << 6);

	return -1;
}

static inline int epic_find_highest_irr(struct kvm_cepic *epic)
{
	int result;

	if (epic->irr_pending) {
		result = epic_search_irr(epic);
		if (result == -1) {
			pr_warn("CEPIC fixing incorrect irr_pending\n");
			epic->irr_pending = false;
		}
		return result;
	}

	return -1;
}

static inline void epic_clear_irr(int vec, struct kvm_cepic *epic)
{
	u64 *cepic_pmirr = epic->regs + CEPIC_PMIRR;

	clear_bit(vec & 0x3f, (void *)&cepic_pmirr[vec >> 6]);

	if (epic_search_irr(epic) == -1)
		epic->irr_pending = false;
}

static int __epic_accept_irq(struct kvm_cepic *epic, int delivery_mode,
			     int vector, int trig_mode);

int kvm_epic_set_irq(struct kvm_vcpu *vcpu, struct kvm_cepic_irq *irq)
{
	struct kvm_cepic *epic = vcpu->arch.epic;

	DebugKVMIRQ("started for VCPU #%d vector 0x%x\n",
		vcpu->vcpu_id, irq->vector);
	return __epic_accept_irq(epic, irq->delivery_mode, irq->vector,
			irq->trig_mode);
}

/*
 * Add a pending IRQ into cepic.
 * Return 1 if successfully added and 0 if discarded.
 */
static int __epic_accept_irq(struct kvm_cepic *epic, int delivery_mode,
			     int vector, int trig_mode)
{
	int result = 0;
	unsigned int reg_cir;
	struct kvm_vcpu *vcpu = epic->vcpu;

	DebugKVMAT("started for VCPU #%d vector 0x%x, dlvm %d trigger %d\n",
		epic->vcpu->vcpu_id, vector, delivery_mode, trig_mode);
	switch (delivery_mode) {
	case CEPIC_ICR_DLVM_FIXED_EXT:
	case CEPIC_ICR_DLVM_FIXED_IPI:
		DebugKVMAT("delivery mode is CEPIC_DLVM_FIXED\n");
		if (unlikely(!epic_enabled(epic)))
			break;

		reg_cir = epic_get_reg_w(epic, CEPIC_CIR);
		if (reg_cir == 0) {
			epic_set_reg_w(epic, CEPIC_CIR, vector);
			kvm_inject_cepic_virq(epic);
			result = 1;
		} else {
			/*
			 * Save it on PMIRR. VIRQ will be injected later,
			 * in CEPIC_EOI
			 */
			result = !epic_test_and_set_irr(vector, epic);
			if (!result)
				DebugVIRQs("CEPIC #%d vector 0x%x already set in PMIRR. Lost interrupt\n",
					vcpu->vcpu_id, vector);
		}

		trace_kvm_epic_accept_irq(vcpu->vcpu_id, delivery_mode,
					  trig_mode, vector, !result);
		break;
	case CEPIC_ICR_DLVM_NMI:
		DebugKVMAT("delivery mode is CEPIC_DLVM_NMI\n");
		result = 1;
		kvm_inject_nmi(vcpu);
		kvm_vcpu_kick(vcpu);
		break;
	default:
		pr_err("TODO: unsupported delivery mode %x\n",
		       delivery_mode);
		break;
	}
	return result;
}

static void epic_send_ipi(struct kvm_cepic *epic)
{
	union cepic_icr reg_icr;
	struct kvm_cepic_irq irq;

	reg_icr.raw = epic_get_reg_d(epic, CEPIC_ICR);

	irq.vector = reg_icr.bits.vect;
	irq.delivery_mode = reg_icr.bits.dlvm;
	irq.trig_mode = 0; /* Edge */
	irq.shorthand = reg_icr.bits.dst_sh;
	irq.dest_id = reg_icr.bits.dst;

	trace_kvm_epic_ipi(irq.dest_id, irq.vector);

	epic_debug("cepic_icr 0x%lx, short_hand 0x%x, dest 0x%x, trig_mode 0x%x, delivery_mode 0x%x, vector 0x%x\n",
		   reg_icr.raw, irq.shorthand, irq.dest_id,
		   irq.trig_mode, irq.delivery_mode,
		   irq.vector);

	kvm_irq_delivery_to_epic(epic->vcpu->kvm, kvm_epic_id(epic), &irq);
}

int kvm_epic_inta(struct kvm_vcpu *vcpu)
{
	struct kvm_cepic *epic = vcpu->arch.epic;
	int vector;
	unsigned int cpr;
	union cepic_vect_inta reg_inta;

	if (!epic || !epic_enabled(epic))
		return -1;

	/* Read CEPIC_INTA */
	vector = epic_get_reg_w(epic, CEPIC_CIR);
	cpr = epic_get_reg_w(epic, CEPIC_CPR);

	/* Update CEPIC_CPR. CEPIC_CIR and CEPIC_PMIRR are updated in EOI */
	epic_set_reg_w(epic, CEPIC_CPR, vector & 0x300);

	DebugKVMAT("vector is 0x%x\n", vector);
	if (vector == -1)
		return -1;

	epic_debug("kvm_get_epic_interrupt() vector is 0x%x\n", vector);

	reg_inta.raw = 0;
	reg_inta.bits.vect = vector;
	reg_inta.bits.cpr = cpr;

	return reg_inta.raw;
}

static u32 __epic_read(struct kvm_cepic *epic, unsigned int offset)
{
	u32 val = 0xffffffff;

	switch (offset) {
	case CEPIC_VECT_INTA:
		val = kvm_epic_inta(epic->vcpu);
		break;
	default:
		val = epic_get_reg_w(epic, offset);
		break;
	}

	return val;
}

static inline struct kvm_cepic *to_cepic(struct kvm_io_device *dev)
{
	return container_of(dev, struct kvm_cepic, dev);
}

static void epic_reg_read(struct kvm_cepic *epic, u32 offset, int len,
		void *data)
{
	if ((len != 4) || (len != 8)) {
		epic_debug("KVM_EPIC_READ: unsupported len %d offset %x\n",
			   len, offset);
		*(unsigned int *)data = -1UL;
		return;
	}

	if (len == 4) {
		unsigned int result;

		/* Do not model accesses to PREPIC */
		if (offset < PAGE_SIZE)
			result = __epic_read(epic, offset);
		else
			result = 0;

		trace_kvm_epic_read_w(offset, result);

		memcpy(data, (unsigned int *)&result, len);
	} else {
		unsigned long result;

		/* Do not model accesses to PREPIC */
		if (offset < PAGE_SIZE)
			result = epic_get_reg_d(epic, offset);
		else
			result = 0;

		trace_kvm_epic_read_d(offset, result);

		memcpy(data, (unsigned long *)&result, len);
	}
}

static int epic_mmio_in_range(struct kvm_cepic *epic, gpa_t addr)
{
	return epic_hw_enabled(epic) &&
		addr >= epic->base_address &&
		addr < epic->base_address + CEPIC_MMIO_LENGTH;
}

static int epic_mmio_read(struct kvm_vcpu *vcpu, struct kvm_io_device *this,
				gpa_t address, int len, void *data)
{
	struct kvm_cepic *epic = to_cepic(this);
	unsigned long int offset = address - epic->base_address;

	epic_reg_debug("started to mmio read address 0x%lx, offset 0x%lx,len %d to %px\n",
		address, offset, len, data);
	if (!epic_mmio_in_range(epic, address))
		return -EOPNOTSUPP;

	epic_reg_read(epic, offset, len, data);
	epic_reg_debug("mmio read data 0x%lx\n", *(u64 *)data);

	return 0;
}

static void start_epic_timer(struct kvm_cepic *epic)
{
	ktime_t now = epic->cepic_timer.timer.base->get_time();
	long period;
	long cycles;

	hrtimer_cancel(&epic->cepic_timer.timer);

	cycles = get_cycles();
	period = (u64)epic_get_reg_w(epic, CEPIC_TIMER_INIT) * NSEC_PER_SEC /
		epic->cepic_freq;
	DebugKVMTM("CEPIC_TIMER_INIT 0x%x period 0x%lx cpu_freq_hz 0x%x cycles 0x%lx\n",
		epic_get_reg_w(epic, CEPIC_TIMER_INIT),
		period, cpu_freq_hz, cycles);
	if (unlikely(!epic->cepic_timer.started))
		epic->cepic_timer.started = true;
	atomic_set(&epic->cepic_timer.pending, 0);

	if (period == 0) {
		epic->cepic_timer.period = 0;
		return;
	}

	if (epic_get_reg_w(epic, CEPIC_TIMER_DIV) != CEPIC_TIMER_DIV_1) {
		pr_warn("ERROR: CEPIC timer div != 1 not supported\n");
		return;
	}

	/*
	 * Do not allow the guest to program periodic timers with small
	 * interval, since the hrtimers are not throttled by the host
	 * scheduler.
	 */
	if (epic_lvtt_period(epic)) {
		if (period < NSEC_PER_MSEC/2)
			period = NSEC_PER_MSEC/2;
	}

again:
	if (!hrtimer_active(&epic->cepic_timer.timer)) {
		epic->cepic_timer.period = period;
		cycles = get_cycles();
		hrtimer_start(&epic->cepic_timer.timer,
			      ktime_add_ns(now, period),
			      HRTIMER_MODE_ABS);
		epic->cepic_timer.running_time =
			kvm_get_guest_vcpu_running_time(epic->vcpu);
		DebugKVMTM("started cepic hrtimer now 0x%llx period 0x%lx running time 0x%llx, cycles 0x%lx\n",
			ktime_to_ns(now), period,
			epic->cepic_timer.running_time, cycles);
	} else if (hrtimer_callback_running(&epic->cepic_timer.timer)) {
		BUG_ON(epic->cepic_timer.period != 0);
		cycles = get_cycles();
		hrtimer_add_expires_ns(&epic->cepic_timer.timer, period);
		epic->cepic_timer.period = period;
		epic->cepic_timer.running_time =
			kvm_get_guest_vcpu_running_time(epic->vcpu);
		DebugKVMTM("restarted cepic hrtimer now 0x%llx period 0x%lx running time 0x%llx, cycles 0x%lx\n",
			ktime_to_ns(now), period,
			epic->cepic_timer.running_time, cycles);
	} else {
		/* timer is active probably is completing, so waiting */
		DebugKVMTM("hrtimer is completing, small waiting\n");
		cpu_relax();
		goto again;
	}
}

/* Returns 0 if nothing is waiting on CEPIC_PMIRR, 1 otherwise */
static void epic_check_pmirr(struct kvm_cepic *epic)
{
	int max_irr;

	max_irr = epic_find_highest_irr(epic);

	if (max_irr == -1) {
		epic_set_reg_w(epic, CEPIC_CIR, 0);
	} else {
		epic_clear_irr(max_irr, epic);
		epic_set_reg_w(epic, CEPIC_CIR, max_irr);
		kvm_inject_cepic_virq(epic);
	}
}

static void epic_write_eoi(struct kvm_cepic *epic, u32 val)
{
	unsigned int vector = epic_get_reg_w(epic, CEPIC_CIR);
	union cepic_eoi reg_eoi;
	union cepic_cpr reg_cpr;

	reg_eoi.raw = val;
	reg_cpr.raw = 0;

	reg_cpr.bits.cpr = reg_eoi.bits.rcpr;

	epic_set_reg_w(epic, CEPIC_CPR, reg_cpr.raw);

	kvm_ioepic_update_eoi(epic->vcpu->kvm, vector, 1);

	epic_check_pmirr(epic);

	trace_kvm_epic_eoi(vector);
}

static void epic_reg_write_w(struct kvm_cepic *epic, u32 reg, u32 val)
{
	epic_set_reg_w(epic, reg, val);

	switch (reg) {
	case CEPIC_EOI:
		epic_write_eoi(epic, val);
		break;
	case CEPIC_TIMER_INIT:
		start_epic_timer(epic);
		break;
	case CEPIC_ICR:
		epic_send_ipi(epic);
		break;
	}
}

static void epic_reg_write_d(struct kvm_cepic *epic, u32 reg, u32 val)
{
	epic_set_reg_d(epic, reg, val);

	if (reg == CEPIC_ICR)
		epic_send_ipi(epic);
}

static int epic_mmio_write(struct kvm_vcpu *vcpu, struct kvm_io_device *this,
				gpa_t address, int len, const void *data)
{
	struct kvm_cepic *epic = to_cepic(this);
	unsigned int offset = address - epic->base_address;

	if (!epic_mmio_in_range(epic, address))
		return -EOPNOTSUPP;

	if (len != 4 && len != 8) {
		epic_debug("epic write: bad size=%d %lx\n", len, (long)address);
		return 0;
	}

	epic_debug("%s: offset 0x%x with length 0x%x, and value is 0x%lx\n",
			__func__, offset, len, val);

	/* Do not model accesses to PREPIC regs */
	if (offset < PAGE_SIZE)
		if (len == 4) {
			u32 val;
			val = *(u32 *)data;

			trace_kvm_epic_write_w(offset, val);
			epic_reg_write_w(epic, offset, val);
		} else {
			u64 val;
			val = *(u64 *)data;

			trace_kvm_epic_write_d(offset, val);
			epic_reg_write_d(epic, offset, val);
		}

	return 0;
}

void kvm_free_cepic(struct kvm_vcpu *vcpu)
{
	if (!vcpu->arch.epic)
		return;

	hrtimer_cancel(&vcpu->arch.epic->cepic_timer.timer);

	if (vcpu->arch.epic->regs_page)
		__free_page(vcpu->arch.epic->regs_page);

	kfree(vcpu->arch.epic);
	vcpu->arch.epic = NULL;
}

/*
 *----------------------------------------------------------------------
 * CEPIC interface
 *----------------------------------------------------------------------
 */

/* Initialize all registers, as if this were the reset state on host */
void kvm_cepic_reset(struct kvm_vcpu *vcpu)
{
	struct kvm_cepic *epic;
	int i;
	union cepic_ctrl reg_ctrl;

	epic_debug("%s\n", __func__);

	ASSERT(vcpu);
	epic = vcpu->arch.epic;
	ASSERT(epic != NULL);

	/* Stop the timer in case it's a reset to an active epic */
	hrtimer_cancel(&epic->cepic_timer.timer);

	/* Initialize all registers as on CEPIC reset */
	reg_ctrl.raw = 0;
	reg_ctrl.bits.bsp_core = kvm_vcpu_is_bsp(vcpu);
	epic_set_reg_w(epic, CEPIC_CTRL, reg_ctrl.raw);

	epic_set_reg_w(epic, CEPIC_ID, vcpu->vcpu_id);
	epic_set_reg_w(epic, CEPIC_CPR, 0);
	epic_set_reg_w(epic, CEPIC_ESR, 0);
	epic_set_reg_w(epic, CEPIC_ESR2, 0);
	epic_set_reg_w(epic, CEPIC_EOI, 0);
	epic_set_reg_w(epic, CEPIC_CIR, 0);
	for (i = 0; i < CEPIC_PMIRR_NR_DREGS; i++)
		epic_set_reg_d(epic, CEPIC_PMIRR + i * 8, 0);
	epic_set_reg_w(epic, CEPIC_PNMIRR, 0);
	epic_set_reg_d(epic, CEPIC_ICR, 0);
	epic_set_reg_w(epic, CEPIC_TIMER_LVTT, 0);
	epic_set_reg_w(epic, CEPIC_TIMER_INIT, 0);
	epic_set_reg_w(epic, CEPIC_TIMER_CUR, 0);
	epic_set_reg_w(epic, CEPIC_TIMER_DIV, 0);
	epic_set_reg_w(epic, CEPIC_NM_TIMER_LVTT, 0);
	epic_set_reg_w(epic, CEPIC_NM_TIMER_INIT, 0);
	epic_set_reg_w(epic, CEPIC_NM_TIMER_CUR, 0);
	epic_set_reg_w(epic, CEPIC_NM_TIMER_DIV, 0);
	epic_set_reg_w(epic, CEPIC_SVR, 0);
	epic_set_reg_w(epic, CEPIC_PNMIRR_MASK, 0);
	epic_set_reg_w(epic, CEPIC_VECT_INTA, 0);

	epic->irr_pending = false;
	atomic_set(&epic->cepic_timer.pending, 0);
	epic->cepic_timer.started = false;

	epic_debug("%s: vcpu=%px, id=%d, base_address=0x%lx\n",
		__func__, vcpu, kvm_epic_id(epic), epic->base_address);
}

#if 0
bool kvm_epic_present(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.epic && epic_hw_enabled(vcpu->arch.epic);
}

int kvm_cepic_enabled(struct kvm_vcpu *vcpu)
{
	return kvm_epic_present(vcpu) && epic_sw_enabled(vcpu->arch.epic);
}
#endif

/*
 *----------------------------------------------------------------------
 * timer interface
 *----------------------------------------------------------------------
 */

static bool cepic_is_periodic(struct kvm_timer *ktimer)
{
	struct kvm_cepic *epic = container_of(ktimer, struct kvm_cepic,
					      cepic_timer);
	return epic_lvtt_period(epic);
}

int epic_has_pending_timer(struct kvm_vcpu *vcpu)
{
	struct kvm_cepic *cepic = vcpu->arch.epic;

	if (cepic && epic_enabled(cepic) && epic_lvtt_enabled(cepic))
		return atomic_read(&cepic->cepic_timer.pending);

	return 0;
}

static int kvm_epic_lvtt_deliver(struct kvm_cepic *epic)
{
	union cepic_timer_lvtt reg;

	reg.raw = epic_get_reg_w(epic, CEPIC_TIMER_LVTT);

	if (epic_hw_enabled(epic) && !(reg.bits.mask))
		return __epic_accept_irq(epic, CEPIC_ICR_DLVM_FIXED_EXT,
					reg.bits.vect, 0);

	return 0;
}

int kvm_sw_epic_sysrq_deliver(struct kvm_vcpu *vcpu)
{
	struct kvm_cepic *epic = vcpu->arch.epic;

	DebugGST("started for VCPU #%d\n", vcpu->vcpu_id);
	if (epic && epic_hw_enabled(epic)) {
		return __epic_accept_irq(epic,
				CEPIC_ICR_DLVM_FIXED_EXT,
				SYSRQ_SHOWSTATE_EPIC_VECTOR,
				0);	/* trigger mode */
	}
	return 0;
}

int kvm_epic_nmi_deliver(struct kvm_vcpu *vcpu)
{
	struct kvm_cepic *epic = vcpu->arch.epic;

	DebugGST("started for VCPU #%d\n", vcpu->vcpu_id);
	if (epic && epic_hw_enabled(epic)) {
		return __epic_accept_irq(epic,
				CEPIC_ICR_DLVM_FIXED_EXT,
				KVM_NMI_EPIC_VECTOR,
				0);	/* trigger mode */
	}
	return 0;
}

static const struct kvm_timer_ops cepic_timer_ops = {
	.is_periodic = cepic_is_periodic,
};

static const struct kvm_io_device_ops epic_mmio_ops = {
	.read     = epic_mmio_read,
	.write    = epic_mmio_write,
};

int kvm_create_cepic(struct kvm_vcpu *vcpu)
{
	struct kvm_cepic *epic;

	/* No need for CEPIC model, if hardware support is available */
	if (vcpu->kvm->arch.is_hv)
		return 0;

	ASSERT(vcpu != NULL);
	epic_debug("epic_init %d\n", vcpu->vcpu_id);

	epic = kzalloc(sizeof(*epic), GFP_KERNEL);
	if (!epic)
		goto nomem;

	vcpu->arch.epic = epic;

	epic->regs_page = alloc_page(GFP_KERNEL);
	if (epic->regs_page == NULL) {
		pr_err("malloc epic regs error for vcpu %x\n", vcpu->vcpu_id);
		goto nomem_free_epic;
	}
	epic->regs = page_address(epic->regs_page);
	memset(epic->regs, 0, PAGE_SIZE);
	epic->vcpu = vcpu;
	epic->cepic_freq = vcpu->kvm->arch.cepic_freq;

	hrtimer_init(&epic->cepic_timer.timer, CLOCK_MONOTONIC,
		     HRTIMER_MODE_ABS);
	epic->cepic_timer.timer.function = kvm_epic_timer_fn;
	epic->cepic_timer.t_ops = &cepic_timer_ops;
	epic->cepic_timer.kvm = vcpu->kvm;
	epic->cepic_timer.vcpu = vcpu;

	epic->base_address = EPIC_DEFAULT_PHYS_BASE;
	vcpu->arch.epic_base = EPIC_DEFAULT_PHYS_BASE;

	kvm_cepic_reset(vcpu);
	kvm_iodevice_init(&epic->dev, &epic_mmio_ops);

	return 0;
nomem_free_epic:
	kfree(epic);
	vcpu->arch.epic = NULL;
nomem:
	return -ENOMEM;
}

void kvm_inject_epic_timer_irqs(struct kvm_vcpu *vcpu)
{
	struct kvm_cepic *epic = vcpu->arch.epic;

	DebugKVMAT("started timer pending %d\n",
		atomic_read(&epic->cepic_timer.pending));
	if (epic && atomic_read(&epic->cepic_timer.pending) > 0) {
		if (kvm_epic_lvtt_deliver(epic)) {
			atomic_dec(&epic->cepic_timer.pending);
			DebugKVMAT("delivered timer pending %d\n",
				atomic_read(&epic->cepic_timer.pending));
		} else {
			DebugKVMAT("local EPIC timer interrupt was coalesced for VCPU #%d\n",
				vcpu->vcpu_id);
			if (!epic_lvtt_period(epic) &&
				(atomic_read(&epic->cepic_timer.pending) > 1 ||
				atomic_read(&epic->cepic_timer.pending) == 0)) {
				/* it can be while switch periodic */
				/* mode to one shot or back */
				E2K_LMS_HALT_OK;
			}
		}
	}
}

