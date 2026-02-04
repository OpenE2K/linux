/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024 MCST
 */

#include <linux/cpu.h>
#include <linux/kernel.h>
#include <linux/kvm_host.h>
#include <linux/sched/idle.h>
#include <linux/sched/signal.h>

#include <asm/e2k_api.h>
#include <asm/aau_context.h>
#include <asm/cpu_regs.h>
#include <asm/hw_prefetchers.h>
#include <asm/kdebug.h>
#include <asm/kvm/cpu_hv_regs_access.h>
#include <asm/kvm/mmu_hv_regs_access.h>
#include <asm/machdep.h>
#include <asm/pic.h>
#include <asm/sic_regs_access.h>
#include <asm/trap_def.h>
#include <asm/trap_table.h>
#ifdef CONFIG_SCLKR_CLOCKSOURCE
#include <asm/sclkr.h>
#endif
#include <asm/kvm_host.h>
#include <asm/kvm/uaccess.h>
#include <asm/kvm/trace_kvm_hv.h>

#include "iset-kvm.h"
#include "../../l/kernel/irq/epic/epic.h"

#if	defined(CONFIG_KVM_HW_VIRTUALIZATION) && !defined(CONFIG_KVM_GUEST_KERNEL)
/* it is hardware virtualized host */

/*
 * mem_wait_vcpumask_set/reset() waits for interrupt or set/reset vcpu bit in vcpus mask.
 * Note that there can be spurious wakeups as only whole cache lines can be watched.
 */
static void mem_wait_vcpumask_set_reset(int vcpuid, struct cpumask *vcpumask, bool set)
{
	unsigned long *addr = cpumask_bits(vcpumask);
	unsigned long *vcpu_p = (addr) + BIT_WORD(vcpuid);
	unsigned long vcpu_mask = BIT_MASK(vcpuid);

	if (set) {
		E2K_WATCH_FOR_MASK_SET_64(vcpu_p, vcpu_mask);
	} else {
		E2K_WATCH_FOR_MASK_RESET_64(vcpu_p, vcpu_mask);
	}
}
void mem_wait_vcpumask_set(int vcpuid, struct cpumask *vcpumask)
{
	mem_wait_vcpumask_set_reset(vcpuid, vcpumask, true);
}
void mem_wait_vcpumask_reset(int vcpuid, struct cpumask *vcpumask)
{
	mem_wait_vcpumask_set_reset(vcpuid, vcpumask, false);
}

static void clear_guest_epic(void)
{
	union cepic_ctrl2 reg;

	reg.raw = epic_read_w(CEPIC_CTRL2);
	reg.clear_gst = 1;
	epic_write_w(CEPIC_CTRL2, reg.raw);
}

void save_epic_context(struct kvm_vcpu_arch *vcpu)
{
	epic_page_t *cepic = vcpu->hw_ctxt.cepic;
	union cepic_epic_int reg_epic_int;
	unsigned int i;

	WARN_ON_ONCE(!irqs_disabled());

	/* Should not happen: scheduler is always called with open interrupts
	 * so CEPIC_EPIC_INT must have been delivered before calling vcpu_put
	 * (and in case we are in kvm_arch_vcpu_blocking() - it is also called
	 * with open interrupts). */
	reg_epic_int.raw = epic_read_w(CEPIC_EPIC_INT);
	WARN_ON_ONCE(reg_epic_int.stat);

	kvm_epic_timer_stop(false);
	kvm_epic_invalidate_dat(vcpu);

	cepic->ctrl = epic_read_guest_w(CEPIC_CTRL);
	cepic->id = epic_read_guest_w(CEPIC_ID);
	cepic->cpr = epic_read_guest_w(CEPIC_CPR);
	cepic->esr = epic_read_guest_w(CEPIC_ESR);
	cepic->esr2.raw = epic_read_guest_w(CEPIC_ESR2);
	cepic->icr.raw = epic_read_guest_d(CEPIC_ICR);
	cepic->timer_lvtt.raw = epic_read_guest_w(CEPIC_TIMER_LVTT);
	cepic->timer_init = epic_read_guest_w(CEPIC_TIMER_INIT);
	cepic->timer_cur = epic_read_guest_w(CEPIC_TIMER_CUR);
	cepic->timer_div = epic_read_guest_w(CEPIC_TIMER_DIV);
	cepic->svr = epic_read_guest_w(CEPIC_SVR);
	cepic->pnmirr_mask = epic_read_guest_w(CEPIC_PNMIRR_MASK);

	/* Save PMIRR, PNMIRR, ESR_NEW and CIR, and clear them in hardware */
	for (i = 0; i < CEPIC_PMIRR_NR_DREGS; i++) {
		u64 pmirr_reg = epic_read_guest_d(CEPIC_PMIRR + i * 8);
		u64 pmirr_old = atomic64_fetch_or(pmirr_reg, &cepic->pmirr[i]);
		u64 pmirr_new = pmirr_old | pmirr_reg;
		if (pmirr_new)
			trace_save_pmirr(i, pmirr_new);
	}
	atomic_or(epic_read_guest_w(CEPIC_PNMIRR), &cepic->pnmirr);
	if (cepic->pnmirr.counter)
		trace_save_pnmirr(cepic->pnmirr.counter);

	atomic_or(epic_read_guest_w(CEPIC_ESR_NEW), &cepic->esr_new);
	cepic->cir.raw = epic_read_guest_w(CEPIC_CIR);
	if (cepic->cir.stat)
		trace_save_cir(cepic->cir.raw);

	WARN_ONCE(cepic->icr.stat || cepic->esr2.stat ||
		  cepic->timer_lvtt.stat,
		  "CEPIC stat bit is set upon guest saving: icr 0x%llx, esr2 0x%x, timer_lvtt 0x%x",
		  cepic->icr.raw, cepic->esr2.raw, cepic->timer_lvtt.raw);

	clear_guest_epic();
}

void restore_epic_context(const struct kvm_vcpu_arch *vcpu)
{
	epic_page_t *cepic = vcpu->hw_ctxt.cepic;
	unsigned int i, j, epic_pnmirr;
	unsigned long epic_pmirr;

	WARN_ON_ONCE(!irqs_disabled());

	kvm_hv_epic_load(arch_to_vcpu(vcpu));

	/*
	 * If cir.stat = 1, then cir.vect should be raised in PMIRR instead
	 * CEPIC_CIR is not restored here to avoid overwriting another interrupt
	 */
	if (cepic->cir.stat) {
		unsigned int vector = cepic->cir.vect;

		trace_restore_cir(cepic->cir.raw);
		set_bit(vector & 0x3f, (void *)&cepic->pmirr[vector >> 6].counter);
		cepic->cir.raw = 0;
	}
	epic_write_guest_w(CEPIC_CTRL, cepic->ctrl);
	epic_write_guest_w(CEPIC_ID, cepic->id);
	epic_write_guest_w(CEPIC_CPR, cepic->cpr);
	epic_write_guest_w(CEPIC_ESR, cepic->esr);
	epic_write_guest_w(CEPIC_ESR2, cepic->esr2.raw);
	epic_write_guest_d(CEPIC_ICR, cepic->icr.raw);
	epic_write_guest_w(CEPIC_TIMER_LVTT, cepic->timer_lvtt.raw);
	epic_write_guest_w(CEPIC_TIMER_INIT, cepic->timer_init);
	epic_write_guest_w(CEPIC_TIMER_CUR, cepic->timer_cur);
	epic_write_guest_w(CEPIC_TIMER_DIV, cepic->timer_div);
	epic_write_guest_w(CEPIC_SVR, cepic->svr);
	epic_write_guest_w(CEPIC_PNMIRR_MASK, cepic->pnmirr_mask);
	for (i = 0; i < CEPIC_PMIRR_NR_DREGS; i++) {
		epic_pmirr = cepic->pmirr[i].counter;
		if (epic_pmirr)
			cepic->pmirr[i].counter = 0;
		if (epic_bgi_mode) {
			for (j = 0; j < 64; j++)
				if (cepic->pmirr_byte[64 * i + j]) {
					epic_pmirr |= 1UL << j;
					cepic->pmirr_byte[64 * i + j] = 0;
				}
		}

		if (epic_pmirr) {
			epic_write_d(CEPIC_PMIRR_OR + i * 8, epic_pmirr);
			trace_restore_pmirr(i, epic_pmirr);
		}
	}
	epic_pnmirr = cepic->pnmirr.counter;
	if (epic_pnmirr) {
		atomic_set(&cepic->pnmirr, 0);
		trace_restore_pnmirr(epic_pnmirr);
	}
	if (epic_bgi_mode) {
		for (j = 5; j < 14; j++)
			if (cepic->pnmirr_byte[j]) {
				epic_pnmirr |= 1UL << (j + 4);
				cepic->pnmirr_byte[j] = 0;
			}
	}
	epic_write_w(CEPIC_PNMIRR_OR, epic_pnmirr);
	epic_write_w(CEPIC_ESR_NEW_OR, cepic->esr_new.counter);
	cepic->esr_new.counter = 0;

	kvm_epic_timer_start();
	kvm_epic_enable_int();
}

void kvm_epic_vcpu_blocking(struct kvm_vcpu_arch *vcpu)
{
	save_epic_context(vcpu);
}

void kvm_epic_vcpu_unblocking(struct kvm_vcpu_arch *vcpu)
{
	restore_epic_context(vcpu);
}
#endif /* CONFIG_KVM_HW_VIRTUALIZATION && !CONFIG_KVM_GUEST_KERNEL */

