/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/cpu.h>
#include <linux/kernel.h>
#include <linux/kvm_host.h>
#include <linux/sched/idle.h>
#include <linux/sched/signal.h>

#include <asm/e2k_api.h>
#ifdef CONFIG_USE_AAU
#include <asm/aau_context.h>
#endif
#include <asm/cpu_regs.h>
#include <asm/epic.h>
#include <asm/hw_prefetchers.h>
#include <asm/kdebug.h>
#include <asm/kvm/cpu_hv_regs_access.h>
#include <asm/kvm/mmu_hv_regs_access.h>
#include <asm/machdep.h>
#include <asm/pic.h>
#include <asm/sic_regs_access.h>
#include <asm/trap_def.h>
#include <asm/trap_table.h>
#include <asm/sclkr.h>
#include <asm/kvm_host.h>
#include <asm/kvm/uaccess.h>
#include <asm/kvm/trace_kvm_hv.h>

/******************************* DEBUG DEFINES ********************************/
#undef	DEBUG_PF_MODE
#define	DEBUG_PF_MODE	0	/* Page fault */
#define	DebugPF(...)	DebugPrint(DEBUG_PF_MODE ,##__VA_ARGS__)
/******************************************************************************/

unsigned long rrd_v6(int reg)
{
	switch (reg) {
	case E2K_REG_HCEM:
		return READ_HCEM_REG();
	case E2K_REG_HCEB:
		return READ_HCEB_REG();
	case E2K_REG_OSCUTD:
		return NATIVE_READ_OSCUTD_REG_VALUE();
	case E2K_REG_OSCUIR:
		return NATIVE_READ_OSCUIR_REG_VALUE();
	}

	return 0;
}

void rwd_v6(int reg, unsigned long value)
{
	switch (reg) {
	case E2K_REG_HCEM:
		WRITE_HCEM_REG(value);
		return;
	case E2K_REG_HCEB:
		WRITE_HCEB_REG(value);
		return;
	case E2K_REG_OSCUTD:
		NATIVE_WRITE_OSCUTD_REG_VALUE(value);
		return;
	case E2K_REG_OSCUIR:
		NATIVE_WRITE_OSCUIR_REG_VALUE(value);
		return;
	}
}

void save_dimtp_v6(e2k_dimtp_t *dimtp)
{
	dimtp->lo = NATIVE_GET_DSREG_CLOSED(dimtp.lo);
	dimtp->hi = NATIVE_GET_DSREG_CLOSED(dimtp.hi);
}

void restore_dimtp_v6(const e2k_dimtp_t *dimtp)
{
	NATIVE_SET_DSREGS_CLOSED_NOEXC(dimtp.lo, dimtp.hi, dimtp->lo, dimtp->hi, 4, 6);
}

void clear_dimtp_v6(void)
{
	NATIVE_SET_DSREGS_CLOSED_NOEXC(dimtp.lo, dimtp.hi, 0ull, 0ull, 4, 6);
}

#ifdef CONFIG_MLT_STORAGE
static bool read_MLT_entry_v6(e2k_mlt_entry_t *mlt, int entry_num)
{
	AW(mlt->dw0) = NATIVE_READ_MLT_REG(
		(REG_MLT_TYPE << REG_MLT_TYPE_SHIFT) |
		(entry_num << REG_MLT_N_SHIFT));

	if (!AS_V6_STRUCT(mlt->dw0).val)
		return false;

	AW(mlt->dw1) = NATIVE_READ_MLT_REG(1 << REG_MLT_DW_SHIFT |
			REG_MLT_TYPE << REG_MLT_TYPE_SHIFT |
			entry_num << REG_MLT_N_SHIFT);
	AW(mlt->dw2) = NATIVE_READ_MLT_REG(2 << REG_MLT_DW_SHIFT |
			REG_MLT_TYPE << REG_MLT_TYPE_SHIFT |
			entry_num << REG_MLT_N_SHIFT);

	return true;
}

void get_and_invalidate_MLT_context_v6(e2k_mlt_t *mlt_state)
{
	int i;

	mlt_state->num = 0;

	for (i = 0; i < NATIVE_MLT_SIZE; i++) {
		e2k_mlt_entry_t *mlt = &mlt_state->mlt[mlt_state->num];

		if (read_MLT_entry_v6(mlt, i))
			mlt_state->num++;
	}

	NATIVE_SET_MMUREG(mlt_inv, 0);
}
#endif

unsigned long native_read_MMU_OS_PPTB_reg_value(void)
{
	return NATIVE_READ_MMU_OS_PPTB_REG_VALUE();
}
void native_write_MMU_OS_PPTB_reg_value(unsigned long value)
{
	NATIVE_WRITE_MMU_OS_PPTB_REG_VALUE(value);
}

unsigned long native_read_MMU_OS_VPTB_reg_value(void)
{
	return NATIVE_READ_MMU_OS_VPTB_REG_VALUE();
}
void native_write_MMU_OS_VPTB_reg_value(unsigned long value)
{
	NATIVE_WRITE_MMU_OS_VPTB_REG_VALUE(value);
}

unsigned long native_read_MMU_OS_VAB_reg_value(void)
{
	return NATIVE_READ_MMU_OS_VAB_REG_VALUE();
}
void native_write_MMU_OS_VAB_reg_value(unsigned long value)
{
	NATIVE_WRITE_MMU_OS_VAB_REG_VALUE(value);
}

#if	defined(CONFIG_KVM_HW_VIRTUALIZATION) && \
				!defined(CONFIG_KVM_GUEST_KERNEL)
static void clear_guest_epic(void)
{
	union cepic_ctrl2 reg;

	reg.raw = epic_read_w(CEPIC_CTRL2);
	reg.bits.clear_gst = 1;
	epic_write_w(CEPIC_CTRL2, reg.raw);
}

static void save_epic_context(struct kvm_vcpu_arch *vcpu)
{
	epic_page_t *cepic = vcpu->hw_ctxt.cepic;
	union cepic_epic_int reg_epic_int;
	unsigned int i;

	/* Shuld not happen: scheduler is always called with open interrupts
	 * so CEPIC_EPIC_INT must have been delivered before calling vcpu_put
	 * (and in case we are in kvm_arch_vcpu_blocking() - it is also called
	 * with open interrupts). */
	reg_epic_int.raw = epic_read_w(CEPIC_EPIC_INT);
	WARN_ON_ONCE(reg_epic_int.bits.stat);

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
	if (cepic->cir.bits.stat)
		trace_save_cir(cepic->cir.raw);

	WARN_ONCE(cepic->icr.bits.stat || cepic->esr2.bits.stat ||
			cepic->timer_lvtt.bits.stat,
			"CEPIC stat bit is set upon guest saving: icr 0x%llx, esr2 0x%x, timer_lvtt 0x%x",
			cepic->icr.raw, cepic->esr2.raw, cepic->timer_lvtt.raw);

	clear_guest_epic();
}

static void restore_epic_context(const struct kvm_vcpu_arch *vcpu)
{
	epic_page_t *cepic = vcpu->hw_ctxt.cepic;
	unsigned int i, j, epic_pnmirr;
	unsigned long epic_pmirr;

	kvm_hv_epic_load(arch_to_vcpu(vcpu));

	/*
	 * If cir.stat = 1, then cir.vect should be raised in PMIRR instead
	 * CEPIC_CIR is not restored here to avoid overwriting another interrupt
	 */
	if (cepic->cir.bits.stat) {
		unsigned int vector = cepic->cir.bits.vect;

		trace_restore_cir(cepic->cir.raw);
		set_bit(vector & 0x3f,
				(void *)&cepic->pmirr[vector >> 6].counter);
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

void save_kvm_context_v6(struct kvm_vcpu_arch *vcpu)
{
	struct kvm_hw_cpu_context *hw_ctxt = &vcpu->hw_ctxt;
	unsigned long flags;
	struct kvm_arch *ka = &arch_to_vcpu(vcpu)->kvm->arch;
	e2k_mmu_cr_t mmu_cr, old_mmu_cr;

	/*
	 * Stack registers
	 */
	AW(hw_ctxt->sh_psp_lo) = READ_SH_PSP_LO_REG_VALUE();
	AW(hw_ctxt->sh_psp_hi) = READ_SH_PSP_HI_REG_VALUE();
	AW(hw_ctxt->sh_pcsp_lo) = READ_SH_PCSP_LO_REG_VALUE();
	AW(hw_ctxt->sh_pcsp_hi) = READ_SH_PCSP_HI_REG_VALUE();
	AW(hw_ctxt->sh_pshtp) = READ_SH_PSHTP_REG_VALUE();
	hw_ctxt->sh_pcshtp = READ_SH_PCSHTP_REG_VALUE();
	AW(hw_ctxt->sh_wd) = READ_SH_WD_REG_VALUE();
	AW(hw_ctxt->bu_psp_lo) = READ_BU_PSP_LO_REG_VALUE();
	AW(hw_ctxt->bu_psp_hi) = READ_BU_PSP_HI_REG_VALUE();
	AW(hw_ctxt->bu_pcsp_lo) = READ_BU_PCSP_LO_REG_VALUE();
	AW(hw_ctxt->bu_pcsp_hi) = READ_BU_PCSP_HI_REG_VALUE();

	/*
	 * MMU shadow context
	 */
	AW(hw_ctxt->sh_mmu_cr) = READ_SH_MMU_CR_REG_VALUE();
	hw_ctxt->sh_pid = READ_SH_PID_REG_VALUE();
	hw_ctxt->sh_os_pptb = READ_SH_OS_PPTB_REG_VALUE();
	hw_ctxt->gp_pptb = READ_GP_PPTB_REG_VALUE();
	hw_ctxt->sh_os_vptb = READ_SH_OS_VPTB_REG_VALUE();
	hw_ctxt->sh_os_vab = READ_SH_OS_VAB_REG_VALUE();
	hw_ctxt->gid = READ_GID_REG_VALUE();

	/*
	 * CPU shadow context
	 */
	AW(hw_ctxt->sh_oscud_lo) = READ_SH_OSCUD_LO_REG_VALUE();
	AW(hw_ctxt->sh_oscud_hi) = READ_SH_OSCUD_HI_REG_VALUE();
	AW(hw_ctxt->sh_osgd_lo) = READ_SH_OSGD_LO_REG_VALUE();
	AW(hw_ctxt->sh_osgd_hi) = READ_SH_OSGD_HI_REG_VALUE();
	AW(hw_ctxt->sh_oscutd) = READ_SH_OSCUTD_REG_VALUE();
	AW(hw_ctxt->sh_oscuir) = READ_SH_OSCUIR_REG_VALUE();

	hw_ctxt->sh_osr0 = READ_SH_OSR0_REG_VALUE();

	raw_spin_lock_irqsave(&ka->sh_sclkr_lock, flags);
	/* The last still runnig vcpu saves it sclkm3.
	 * Guest time run paused */
	if (ka->num_sclkr_run-- == 1) {
		ka->sh_sclkm3 = READ_SH_SCLKM3_REG_VALUE() - read_sclkr_sync();
	}
	raw_spin_unlock_irqrestore(&ka->sh_sclkr_lock, flags);

	AW(hw_ctxt->sh_core_mode) = READ_SH_CORE_MODE_REG_VALUE();

	/*
	 * VIRT_CTRL_* registers
	 */
	hw_ctxt->virt_ctrl_cu = READ_VIRT_CTRL_CU_REG();
	hw_ctxt->virt_ctrl_mu = READ_VIRT_CTRL_MU_REG();
	AW(hw_ctxt->g_w_imask_mmu_cr) = READ_G_W_IMASK_MMU_CR_REG_VALUE();

	/*
	 * INTC_INFO_* registers have to be saved immediately upon
	 * interception to handle it, so they are not saved here,
	 * but the hardware pointers should be cleared and VCPU marked as
	 * updated to recover ones if need.
	 */
	READ_INTC_PTR_CU();
	kvm_set_intc_info_cu_is_updated(arch_to_vcpu(vcpu));
	READ_INTC_PTR_MU();
	kvm_set_intc_info_mu_is_updated(arch_to_vcpu(vcpu));

	/*
	 * CEPIC context
	 * See comment before kvm_arch_vcpu_blocking() for details
	 * about KVM_MP_STATE_HALTED
	 */
	if (cpu_has(CPU_FEAT_EPIC) && vcpu->mp_state != KVM_MP_STATE_HALTED)
		save_epic_context(vcpu);

	/*
	 * Binco context
	 *
	 * Note that reading higher 32 bits of %u2_pptb depends
	 * on %mmu_cr.{slma,spae} bits, so we want to save %u2_pptb
	 * using guest's values of those bits; also cr0_pg=1 enables
	 * secondary space support and upt=0 avoids undefined
	 * behavior.
	 */
	raw_all_irq_save(flags);

	AW(old_mmu_cr) = NATIVE_GET_MMUREG(mmu_cr);
	mmu_cr = old_mmu_cr;
	mmu_cr.slma = hw_ctxt->sh_mmu_cr.slma;
	mmu_cr.spae = hw_ctxt->sh_mmu_cr.spae;
	mmu_cr.cr0_pg = 1;
	mmu_cr.upt = 0;
	NATIVE_SET_MMUREG(mmu_cr, AW(mmu_cr));
	hw_ctxt->u2_pptb = NATIVE_GET_MMUREG(u2_pptb);
	NATIVE_SET_MMUREG(mmu_cr, AW(old_mmu_cr));

	raw_all_irq_restore(flags);

	hw_ctxt->pid2 = NATIVE_GET_MMUREG(pid2);
	hw_ctxt->mpt_b = NATIVE_GET_MMUREG(mpt_b);
	hw_ctxt->pci_l_b = NATIVE_GET_MMUREG(pci_l_b);
	hw_ctxt->ph_h_b = NATIVE_GET_MMUREG(ph_h_b);
	hw_ctxt->ph_hi_l_b = NATIVE_GET_MMUREG(ph_hi_l_b);
	hw_ctxt->ph_hi_h_b = NATIVE_GET_MMUREG(ph_hi_h_b);
	hw_ctxt->pat = NATIVE_GET_MMUREG(pat);
	hw_ctxt->pdpte0 = NATIVE_GET_MMUREG(pdpte0);
	hw_ctxt->pdpte1 = NATIVE_GET_MMUREG(pdpte1);
	hw_ctxt->pdpte2 = NATIVE_GET_MMUREG(pdpte2);
	hw_ctxt->pdpte3 = NATIVE_GET_MMUREG(pdpte3);
}

void restore_kvm_context_v6(const struct kvm_vcpu_arch *vcpu)
{
	const struct kvm_hw_cpu_context *hw_ctxt = &vcpu->hw_ctxt;
	unsigned long flags;
	struct kvm_arch *ka = &arch_to_vcpu(vcpu)->kvm->arch;
	e2k_mmu_cr_t mmu_cr, old_mmu_cr;

	/*
	 * Stack registers
	 */
	WRITE_SH_PSP_LO_REG_VALUE(AW(hw_ctxt->sh_psp_lo));
	WRITE_SH_PSP_HI_REG_VALUE(AW(hw_ctxt->sh_psp_hi));
	WRITE_SH_PCSP_LO_REG_VALUE(AW(hw_ctxt->sh_pcsp_lo));
	WRITE_SH_PCSP_HI_REG_VALUE(AW(hw_ctxt->sh_pcsp_hi));
	WRITE_SH_PSHTP_REG_VALUE(AW(hw_ctxt->sh_pshtp));
	WRITE_SH_PCSHTP_REG_SVALUE(hw_ctxt->sh_pcshtp);
	WRITE_SH_WD_REG_VALUE(AW(hw_ctxt->sh_wd));
	WRITE_BU_PSP_LO_REG_VALUE(AW(hw_ctxt->bu_psp_lo));
	WRITE_BU_PSP_HI_REG_VALUE(AW(hw_ctxt->bu_psp_hi));
	WRITE_BU_PCSP_LO_REG_VALUE(AW(hw_ctxt->bu_pcsp_lo));
	WRITE_BU_PCSP_HI_REG_VALUE(AW(hw_ctxt->bu_pcsp_hi));

	/*
	 * MMU shadow context
	 */
	WRITE_SH_MMU_CR_REG_VALUE(AW(hw_ctxt->sh_mmu_cr));
	WRITE_SH_PID_REG_VALUE(hw_ctxt->sh_pid);
	WRITE_SH_OS_PPTB_REG_VALUE(hw_ctxt->sh_os_pptb);
	WRITE_GP_PPTB_REG_VALUE(hw_ctxt->gp_pptb);
	WRITE_SH_OS_VPTB_REG_VALUE(hw_ctxt->sh_os_vptb);
	WRITE_SH_OS_VAB_REG_VALUE(hw_ctxt->sh_os_vab);
	WRITE_GID_REG_VALUE(hw_ctxt->gid);

	/*
	 * CPU shadow context
	 */
	WRITE_SH_OSCUD_LO_REG_VALUE(AW(hw_ctxt->sh_oscud_lo));
	WRITE_SH_OSCUD_HI_REG_VALUE(AW(hw_ctxt->sh_oscud_hi));
	WRITE_SH_OSGD_LO_REG_VALUE(AW(hw_ctxt->sh_osgd_lo));
	WRITE_SH_OSGD_HI_REG_VALUE(AW(hw_ctxt->sh_osgd_hi));
	WRITE_SH_OSCUTD_REG_VALUE(AW(hw_ctxt->sh_oscutd));
	WRITE_SH_OSCUIR_REG_VALUE(AW(hw_ctxt->sh_oscuir));

	WRITE_SH_OSR0_REG_VALUE(hw_ctxt->sh_osr0);
	/* sclkm3 = sclkm3 + ("current read_sclkr_sync()" -
	 *	"read_sclkr_sync() when last vcpu leaves cpu")
	 * sclkm3 has a summary time when each vcpu of guest was out of cpu
	 */
	raw_spin_lock_irqsave(&ka->sh_sclkr_lock, flags);
	/* The first activated vcpu calculates sclkm3 for
	 * itself and all subsequent activated vcpu-s.*/
	if (ka->num_sclkr_run++ == 0) {
		ka->sh_sclkm3 = read_sclkr_sync() + ka->sh_sclkm3;
		/* Guest time run resumed (including still sleeping vcpu-s) */
	}
	WRITE_SH_SCLKM3_REG_VALUE(ka->sh_sclkm3);
	raw_spin_unlock_irqrestore(&ka->sh_sclkr_lock, flags);

	WRITE_SH_CORE_MODE_REG_VALUE(AW(hw_ctxt->sh_core_mode));

	/*
	 * VIRT_CTRL_* registers
	 */
	WRITE_VIRT_CTRL_CU_REG(hw_ctxt->virt_ctrl_cu);
	WRITE_VIRT_CTRL_MU_REG(hw_ctxt->virt_ctrl_mu);
	WRITE_G_W_IMASK_MMU_CR_REG_VALUE(AW(hw_ctxt->g_w_imask_mmu_cr));

	/*
	 * INTC_INFO_* registers were saved immediately upon
	 * interception to handle it, and will be restored
	 * by interceptions handler if it need.
	 */

	/*
	 * CEPIC context
	 */
	if (cpu_has(CPU_FEAT_EPIC) && vcpu->mp_state != KVM_MP_STATE_HALTED)
		restore_epic_context(vcpu);

	/*
	 * Binco context
	 *
	 * Note that writing higher 32 bits of %u2_pptb depends
	 * on %mmu_cr.{slma,spae} bits, so we want to save %u2_pptb
	 * using guest's values of those bits; also cr0_pg=1 enables
	 * secondary space support.
	 */
	raw_all_irq_save(flags);

	AW(old_mmu_cr) = NATIVE_GET_MMUREG(mmu_cr);
	mmu_cr = old_mmu_cr;
	mmu_cr.slma = hw_ctxt->sh_mmu_cr.slma;
	mmu_cr.spae = hw_ctxt->sh_mmu_cr.spae;
	mmu_cr.cr0_pg = 1;
	NATIVE_SET_MMUREG(mmu_cr, AW(mmu_cr));
	NATIVE_SET_MMUREG(u2_pptb, hw_ctxt->u2_pptb);
	NATIVE_SET_MMUREG(mmu_cr, AW(old_mmu_cr));

	raw_all_irq_restore(flags);

	NATIVE_SET_MMUREG(pid2, hw_ctxt->pid2);
	NATIVE_SET_MMUREG(mpt_b, hw_ctxt->mpt_b);
	NATIVE_SET_MMUREG(pci_l_b, hw_ctxt->pci_l_b);
	NATIVE_SET_MMUREG(ph_h_b, hw_ctxt->ph_h_b);
	NATIVE_SET_MMUREG(ph_hi_l_b, hw_ctxt->ph_hi_l_b);
	NATIVE_SET_MMUREG(ph_hi_h_b, hw_ctxt->ph_hi_h_b);
	NATIVE_SET_MMUREG(pat, hw_ctxt->pat);
	NATIVE_SET_MMUREG(pdpte0, hw_ctxt->pdpte0);
	NATIVE_SET_MMUREG(pdpte1, hw_ctxt->pdpte1);
	NATIVE_SET_MMUREG(pdpte2, hw_ctxt->pdpte2);
	NATIVE_SET_MMUREG(pdpte3, hw_ctxt->pdpte3);
}
#else /* !CONFIG_KVM_HW_VIRTUALIZATION || CONFIG_KVM_GUEST_KERNEL */
void restore_kvm_context_v6(const struct kvm_vcpu_arch *vcpu)
{
}

void save_kvm_context_v6(struct kvm_vcpu_arch *vcpu)
{
}
#endif	/* CONFIG_KVM_HW_VIRTUALIZATION && !CONFIG_KVM_GUEST_KERNEL */

#ifdef CONFIG_USE_AAU
/* calculate current array prefetch buffer indices values
 * (see chapter 1.10.2 in "Scheduling") */
void calculate_aau_aaldis_aaldas_v6(const struct pt_regs *regs,
		e2k_aalda_t *aaldas, struct e2k_aau_context *context)
{
	memset(aaldas, 0, AALDAS_REGS_NUM * sizeof(aaldas[0]));
}

/* See chapter 1.10.3 in "Scheduling" */
void do_aau_fault_v6(int aa_field, struct pt_regs *regs)
{
	bool user = user_mode(regs);
	const e2k_aau_t	*const aau_regs = regs->aau_context;
	u32		aafstr = aau_regs->aafstr;
	unsigned int	aa_bit = 0;
	tc_cond_t	condition;
	tc_mask_t	mask;

	regs->trap->nr_page_fault_exc = exc_data_page_num;

	DebugPF("do_aau_fault: enter aau fault handler, TICKS = %ld\n"
		"aa_field = 0x%x\ndo_aau_fault: aafstr = 0x%x\n",
		get_cycles(), aa_field, aafstr);

	/* condition.store = 0
	 * condition.fault_type = 0 */
	AW(condition) = 0;
	AS(condition).fmt = LDST_BYTE_FMT;
	AS(condition).spec = 1;
	AW(mask) = 0;

	while (aa_bit < 4) {
		u64 area_num, mrng, addr1, addr2, d_num;
		e2k_fapb_instr_t *fapb_addr;
		e2k_fapb_instr_t fapb;
		int ret;

		if (!(aa_field & 0x1) || !(aafstr & 0x1))
			goto next_area;

		area_num = (aafstr >> 1) & 0x3f;
		DebugPF("do_aau_fault: got interrupt on %d mova channel, area %lld\n",
				aa_bit, area_num);

		if (area_num < 32)
			fapb_addr = (e2k_fapb_instr_t *)(AS(regs->ctpr2).ta_base
					+ 16 * area_num);
		else
			fapb_addr = (e2k_fapb_instr_t *)(AS(regs->ctpr2).ta_base
					+ 16 * (area_num - 32) + 8);

		if (!user) {
			fapb = *fapb_addr;
		} else if ((ret = host_get_user(AW(fapb), (u64 __user *) fapb_addr, regs))) {
			if (ret == -EAGAIN)
				break;
			goto die;
		}

		if (area_num >= 32 && AS(fapb).dpl) {
			/* See bug #53880 */
			pr_notice_once("%s [%d]: AAU is working in dpl mode (FAPB at %px)\n",
					current->comm, current->pid, fapb_addr);
			area_num -= 32;
			fapb_addr -= 1;
			if (!user) {
				fapb = *fapb_addr;
			} else if ((ret = host_get_user(AW(fapb),
					(u64 __user *) fapb_addr, regs))) {
				if (ret == -EAGAIN)
					break;
				goto die;
			}
		}

		if (!regs->aasr.iab) {
			WARN_ONCE(1, "%s [%d]: AAU fault happened but iab in AASR register was not set\n",
					current->comm, current->pid);
			goto die;
		}

		mrng = AS(fapb).mrng ?: 32;

		d_num = AS(fapb).d;
		if (AS(aau_regs->aads[d_num]).lo.tag == AAD_AAUSAP) {
			addr1 = AS(aau_regs->aads[d_num]).lo.sap_base +
					(regs->stacks.top & ~0xffffffffULL);
		} else {
			addr1 = AS(aau_regs->aads[d_num]).lo.ap_base;
		}
		addr1 += AALDI_SIGN_EXTEND(aau_regs->aaldi[area_num]);
		addr2 = addr1 + mrng - 1;
		if (unlikely((addr1 & ~E2K_VA_MASK) || (addr2 & ~E2K_VA_MASK))) {
			pr_notice_once("Bad address: addr 0x%llx, ind 0x%llx, mrng 0x%llx, fapb 0x%llx\n",
					addr1, aau_regs->aaldi[area_num], mrng,
					(unsigned long long) AW(fapb));

			addr1 &= E2K_VA_MASK;
			addr2 &= E2K_VA_MASK;
		}
		DebugPF("do_aau_fault: address1 = 0x%llx, address2 = 0x%llx, mrng=%lld\n",
				addr1, addr2, mrng);

		do_aau_page_fault(regs, addr1, condition, mask, aa_bit);
		if (ret) {
			if (ret == 2) {
				/*
				 * Special case of trap handling on host:
				 *	host inject the trap to guest
				 */
				return;
			}
			goto die;
		}
		if ((addr1 & PAGE_MASK) != (addr2 & PAGE_MASK)) {
			ret = do_aau_page_fault(regs, addr2, condition, mask,
						aa_bit);
			if (ret) {
				if (ret == 2) {
					/*
					* Special case of trap handling on host:
					*	host inject the trap to guest
					*/
					return;
				}
				goto die;
			}
		}

next_area:
		aa_bit++;
		aafstr >>= 8;
		aa_field >>= 1;
	}

	DebugPF("do_aau_fault: exit aau fault handler, TICKS = %ld\n",
			get_cycles());

	return;

die:
	if (user)
		force_sig(SIGSEGV);
	else
		die("AAU error", regs, 0);
}
#endif /* CONFIG_USE_AAU */

/* mem_wait_idle() waits for interrupt or modification
 * of need_resched.  Note that there can be spurious
 * wakeups as only whole cache lines can be watched. */
static void __cpuidle mem_wait_idle(void)
{
	unsigned long need_resched_mask = (1ul << TIF_NEED_RESCHED) |
			(IS_ENABLED(CONFIG_PREEMPT_LAZY) ? (1ul << TIF_NEED_RESCHED_LAZY) : 0);
	E2K_WATCH_FOR_MODIFICATION_64(&current_thread_info()->flags, need_resched_mask);
}

void __cpuidle C1_enter_v6(void)
{
	if (IS_HV_GM()) {
		/* Do not set TIF_POLLING_NRFLAG in guest since
		 * "wait int" here will be intercepted and guest
		 * will be put to sleep. */
		mem_wait_idle();
	} else {
		if (!current_set_polling_and_test())
			mem_wait_idle();
		current_clr_polling();
	}
}

void __cpuidle C3_enter_v6(void)
{
	unsigned long flags;
	unsigned int node = numa_node_id();
	phys_addr_t nbsr_phys = sic_get_node_nbsr_phys_base(node);
	int core = read_pic_id() % cpu_max_cores_num();
	int reg = PMC_FREQ_CORE_N_SLEEP(core);
	freq_core_sleep_t C3 = { .cmd = 3 };
	struct hw_prefetchers_state pref_state;

	raw_all_irq_save(flags);

	pref_state = hw_prefetchers_save();

	C3_WAIT_INT_V6(AW(C3), nbsr_phys + reg);

	if (cpu_has(CPU_HWBUG_C3_SYNC)) {
		freq_core_sleep_t fr_state;
		do {
			fr_state.word = sic_read_node_nbsr_reg(node, reg);
		} while (fr_state.status != 0 /* C0 */);
	}

	hw_prefetchers_restore(pref_state);

	raw_all_irq_restore(flags);
}