/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef __KVM_E2K_INTERCEPTS_H
#define __KVM_E2K_INTERCEPTS_H

#include <linux/kvm_host.h>
#include <asm/cpu_regs_types.h>
#include <asm/kvm/cpu_hv_regs_types.h>
#include <asm/kvm/cpu_hv_regs_access.h>

#include "mmu_defs.h"

#undef	DEBUG_INTC_TIRs_MODE
#undef	DebugTIRs
#define	DEBUG_INTC_TIRs_MODE 0	/* intercept TIRs debugging */
#define	DebugTIRs(fmt, args...)					\
({									\
	if (DEBUG_INTC_TIRs_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

/* intersepts handlers */
typedef int (*exc_intc_handler_t)(struct kvm_vcpu *vcpu, pt_regs_t *regs);
typedef int (*mu_intc_handler_t)(struct kvm_vcpu *vcpu,
			intc_info_mu_t *intc_info_mu, pt_regs_t *regs);

extern int parse_INTC_registers(struct kvm_vcpu_arch *vcpu);

typedef struct cond_exc_info {
	int	no;		/* relative number at VIRT_CTRL_CU.exc_c & */
				/* INTC_INFO_CU[0].exc_c fields */
	u64	exc_mask;	/* mask of absolute numbers of exceptions at */
				/* TIR[].hi.exc field and exc_..._num */
	const char *name;	/* exception (trap) name */
} cond_exc_info_t;

typedef struct mu_event_desc {
	intc_info_mu_event_code_t code;		/* event code */
	mu_intc_handler_t handler;		/* intercept handler */
	const char *name;			/* event name */
} mu_event_desc_t;

static inline void
kvm_set_vcpu_intc_TIR_lo(struct kvm_vcpu *vcpu,
				int TIR_no, e2k_tir_lo_t TIR_lo)
{
	struct kvm_intc_cpu_context *intc_ctxt = &vcpu->arch.intc_ctxt;

	intc_ctxt->TIRs[TIR_no].TIR_lo = TIR_lo;
}

static inline void
kvm_set_vcpu_intc_TIR_hi(struct kvm_vcpu *vcpu,
				int TIR_no, e2k_tir_hi_t TIR_hi)
{
	struct kvm_intc_cpu_context *intc_ctxt = &vcpu->arch.intc_ctxt;

	intc_ctxt->TIRs[TIR_no].TIR_hi = TIR_hi;
}

static inline void
kvm_set_vcpu_intc_TIRs_num(struct kvm_vcpu *vcpu, int TIRs_num)
{
	vcpu->arch.intc_ctxt.nr_TIRs = TIRs_num;
}

static inline void
kvm_clear_vcpu_intc_TIRs_num(struct kvm_vcpu *vcpu)
{
	kvm_set_vcpu_intc_TIRs_num(vcpu, -1);
}

static inline bool
kvm_is_empty_vcpu_intc_TIRs(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.intc_ctxt.nr_TIRs < 0;
}

static inline e2k_tir_lo_t
kvm_get_vcpu_intc_TIR_lo(struct kvm_vcpu *vcpu, int TIR_no)
{
	struct kvm_intc_cpu_context *intc_ctxt = &vcpu->arch.intc_ctxt;
	e2k_tir_lo_t TIR_lo;

	BUG_ON(TIR_no > kvm_get_vcpu_intc_TIRs_num(vcpu));
	TIR_lo = intc_ctxt->TIRs[TIR_no].TIR_lo;
	return TIR_lo;
}

static inline e2k_tir_hi_t
kvm_get_vcpu_intc_TIR_hi(struct kvm_vcpu *vcpu, int TIR_no)
{
	struct kvm_intc_cpu_context *intc_ctxt = &vcpu->arch.intc_ctxt;
	e2k_tir_hi_t TIR_hi;

	BUG_ON(TIR_no > kvm_get_vcpu_intc_TIRs_num(vcpu));
	TIR_hi = intc_ctxt->TIRs[TIR_no].TIR_hi;
	return TIR_hi;
}

static inline void
kvm_update_vcpu_intc_TIR(struct kvm_vcpu *vcpu,
		int TIR_no, e2k_tir_hi_t TIR_hi, e2k_tir_lo_t TIR_lo)
{
	e2k_tir_lo_t g_TIR_lo;
	e2k_tir_hi_t g_TIR_hi;
	int TIRs_num;
	int tir;

	TIRs_num = kvm_get_vcpu_intc_TIRs_num(vcpu);
	if (TIRs_num < TIR_no) {
		for (tir = TIRs_num + 1; tir < TIR_no; tir++) {
			g_TIR_lo.TIR_lo_reg = GET_CLEAR_TIR_LO(tir);
			g_TIR_hi.TIR_hi_reg = GET_CLEAR_TIR_HI(tir);
			kvm_set_vcpu_intc_TIR_lo(vcpu, tir, g_TIR_lo);
			kvm_set_vcpu_intc_TIR_hi(vcpu, tir, g_TIR_hi);
		}
		g_TIR_lo.TIR_lo_reg = GET_CLEAR_TIR_LO(TIR_no);
		g_TIR_hi.TIR_hi_reg = GET_CLEAR_TIR_HI(TIR_no);
	} else {
		g_TIR_hi = kvm_get_vcpu_intc_TIR_hi(vcpu, TIR_no);
		g_TIR_lo = kvm_get_vcpu_intc_TIR_lo(vcpu, TIR_no);
		BUG_ON(g_TIR_hi.TIR_hi_j != TIR_no);
		if (TIR_lo.TIR_lo_ip == 0 && g_TIR_lo.TIR_lo_ip != 0) {
			/* some traps can be caused by kernel and have not */
			/* precision IP (for example hardware stack bounds) */
			TIR_lo.TIR_lo_ip = g_TIR_lo.TIR_lo_ip;
		} else if (TIR_lo.TIR_lo_ip != 0 && g_TIR_lo.TIR_lo_ip == 0) {
			/* new trap IP will be common for other traps */
			;
		} else {
			/* guest TIRs have always precision IP */
			;
		}
	}
	g_TIR_hi.TIR_hi_reg |= TIR_hi.TIR_hi_reg;
	g_TIR_lo.TIR_lo_reg = TIR_lo.TIR_lo_reg;
	kvm_set_vcpu_intc_TIR_hi(vcpu, TIR_no, g_TIR_hi);
	kvm_set_vcpu_intc_TIR_lo(vcpu, TIR_no, g_TIR_lo);
	if (TIR_no > TIRs_num)
		kvm_set_vcpu_intc_TIRs_num(vcpu, TIR_no);
}

static inline void
kvm_need_pass_vcpu_exception(struct kvm_vcpu *vcpu, u64 exc_mask)
{
	u64 tir_exc = vcpu->arch.intc_ctxt.exceptions;

	exc_mask &= tir_exc;
	E2K_KVM_BUG_ON(exc_mask == 0);
	vcpu->arch.intc_ctxt.exc_to_pass |= exc_mask;
}

static inline void
kvm_need_create_vcpu_exception(struct kvm_vcpu *vcpu, u64 exc_mask)
{
	u64 tir_exc = vcpu->arch.intc_ctxt.exceptions;

	exc_mask &= ~tir_exc;
	E2K_KVM_BUG_ON(exc_mask == 0);
	vcpu->arch.intc_ctxt.exc_to_create |= exc_mask;
}

static inline void
kvm_need_create_vcpu_exc_and_IP(struct kvm_vcpu *vcpu, u64 exc_mask, gva_t IP)
{
	E2K_KVM_BUG_ON(vcpu->arch.intc_ctxt.exc_IP_to_create != 0);
	kvm_need_create_vcpu_exception(vcpu, exc_mask);
	vcpu->arch.intc_ctxt.exc_IP_to_create = IP;
}

static inline void
kvm_need_delete_vcpu_exception(struct kvm_vcpu *vcpu, u64 exc_mask)
{
	u64 tir_exc = vcpu->arch.intc_ctxt.exceptions;

	exc_mask &= tir_exc;
	E2K_KVM_BUG_ON(exc_mask == 0);
	vcpu->arch.intc_ctxt.exc_to_delete |= exc_mask;
}

static inline bool
kvm_has_vcpu_exception(struct kvm_vcpu *vcpu, u64 exc_mask)
{
	u64 tir_exc = vcpu->arch.intc_ctxt.exceptions;

	return (exc_mask & tir_exc) != 0;
}

static inline bool
kvm_has_vcpu_exc_recovery_point(struct kvm_vcpu *vcpu)
{
	return kvm_has_vcpu_exception(vcpu, exc_recovery_point_mask);
}

static inline void kvm_clear_vcpu_trap_cellar(struct kvm_vcpu *vcpu)
{
	void *tc_kaddr = vcpu->arch.mmu.tc_kaddr;
	kernel_trap_cellar_t *tc;

	tc = tc_kaddr;
	if (tc == NULL)
		return;	/* trap cellar is not inited by guest */

	/* MMU TRAP_COUNT cannot be set, so write flag of end of records */
	AW(tc->condition) = -1;
	vcpu->arch.mmu.tc_num = 0;
	kvm_write_pv_vcpu_mmu_TRAP_COUNT_reg(vcpu, 0 * 3);
}

/* FIXME: simulator bug: simulator does not reexecute requests */
/* from INTC_INFO_MU unlike the hardware, so do it by software */
static inline void kvm_restore_vcpu_trap_cellar(struct kvm_vcpu *vcpu)
{
	kvm_intc_cpu_context_t *intc_ctxt = &vcpu->arch.intc_ctxt;
	intc_info_mu_t *mu = intc_ctxt->mu;
	intc_info_mu_t *mu_event;
	unsigned long intc_mu_to_move = intc_ctxt->intc_mu_to_move;
	int mu_num = intc_ctxt->mu_num;
	int evn_no;
	void *tc_kaddr = vcpu->arch.mmu.tc_kaddr;
	kernel_trap_cellar_t *tc;
	kernel_trap_cellar_ext_t *tc_ext;
	tc_opcode_t opcode;
	int cnt, fmt;

	tc = tc_kaddr;
	tc_ext = tc_kaddr + TC_EXT_OFFSET;
	cnt = 0;

	for (evn_no = 0;
			intc_mu_to_move != 0 && evn_no < mu_num;
					intc_mu_to_move >>= 1, evn_no++) {
		if (likely(!(intc_mu_to_move & 0x1)))
			continue;
		E2K_KVM_BUG_ON(cnt >= HW_TC_SIZE);
		mu_event = &mu[evn_no];
		tc->address = mu_event->gva;
		tc->condition = mu_event->condition;
		AW(opcode) = AS(mu_event->condition).opcode;
		fmt = AS(opcode).fmt;
		if (fmt == LDST_QP_FMT)
			tc_ext->mask = mu_event->mask;
		if (AS(mu_event->condition).store) {
			NATIVE_MOVE_TAGGED_DWORD(&mu_event->data, &tc->data);
			if (fmt == LDST_QP_FMT) {
				NATIVE_MOVE_TAGGED_DWORD(&mu_event->data_ext,
								&tc_ext->data);
			}
		}
		cnt++;
		tc++;
		tc_ext++;
	}
	E2K_KVM_BUG_ON(intc_mu_to_move != 0);

	/* MMU TRAP_COUNT cannot be set, so write flag of end of records */
	AW(tc->condition) = -1;

	intc_ctxt->intc_mu_to_move = 0;
}

extern const cond_exc_info_t cond_exc_info_table[INTC_CU_COND_EXC_MAX];
extern exc_intc_handler_t intc_exc_table[INTC_CU_COND_EXC_MAX];

static inline exc_intc_handler_t
kvm_get_cond_exc_handler(int exc_no)
{
	E2K_KVM_BUG_ON(exc_no < 0 || exc_no >= INTC_CU_COND_EXC_MAX);
	return intc_exc_table[exc_no];
}

static inline void
kvm_set_cond_exc_handler(int exc_no, exc_intc_handler_t handler)
{
	E2K_KVM_BUG_ON(exc_no < 0 || exc_no >= INTC_CU_COND_EXC_MAX);
	intc_exc_table[exc_no] = handler;
}

static inline int kvm_cond_exc_no_to_exc_mask(int exc_no)
{
	E2K_KVM_BUG_ON(exc_no < 0 || exc_no >= INTC_CU_COND_EXC_MAX);
	E2K_KVM_BUG_ON(cond_exc_info_table[exc_no].no != exc_no &&
				cond_exc_info_table[exc_no].no >= 0);
	return cond_exc_info_table[exc_no].exc_mask;
}

static inline const char *kvm_cond_exc_no_to_exc_name(int exc_no)
{
	E2K_KVM_BUG_ON(exc_no < 0 || exc_no >= INTC_CU_COND_EXC_MAX);
	E2K_KVM_BUG_ON(cond_exc_info_table[exc_no].no != exc_no &&
				cond_exc_info_table[exc_no].no >= 0);
	return cond_exc_info_table[exc_no].name;
}

static inline void
kvm_pass_cond_exc_to_vcpu(struct kvm_vcpu *vcpu, int exc_no)
{
	u64 exc_mask;

	exc_mask = kvm_cond_exc_no_to_exc_mask(exc_no);
	kvm_need_pass_vcpu_exception(vcpu, exc_mask);
}

static inline void
kvm_inject_trap_TIR(struct kvm_vcpu *vcpu, int TIR_no,
			unsigned long trap_mask, e2k_addr_t IP)
{
	e2k_tir_hi_t TIR_hi;
	e2k_tir_lo_t TIR_lo;

	TIR_lo.TIR_lo_reg = GET_CLEAR_TIR_LO(TIR_no);
	TIR_lo.TIR_lo_ip = IP;
	TIR_hi.TIR_hi_reg = GET_CLEAR_TIR_HI(TIR_no);
	TIR_hi.TIR_hi_exc = trap_mask;
	kvm_update_vcpu_intc_TIR(vcpu, TIR_no, TIR_hi, TIR_lo);
	DebugTIRs("trap is injected to guest TIRs #%d hi 0x%016llx "
		"lo 0x%016llx\n",
		TIR_no, TIR_hi.TIR_hi_reg, TIR_lo.TIR_lo_reg);
}

static inline void
kvm_inject_interrupt(struct kvm_vcpu *vcpu, pt_regs_t *regs)
{
	int TIR_no = kvm_get_vcpu_intc_TIRs_num(vcpu);

	if (TIR_no >= 1)
		kvm_inject_trap_TIR(vcpu, TIR_no, exc_interrupt_mask, 0);
	else
		kvm_inject_trap_TIR(vcpu, 1, exc_interrupt_mask,
			regs->crs.cr0_hi.CR0_hi_IP);
}

static inline void
kvm_inject_last_wish(struct kvm_vcpu *vcpu, pt_regs_t *regs)
{
	kvm_inject_trap_TIR(vcpu, 0, exc_last_wish_mask,
				regs->crs.cr0_hi.CR0_hi_IP);
}

static inline void
kvm_inject_software_trap(struct kvm_vcpu *vcpu, pt_regs_t *regs)
{
	kvm_inject_trap_TIR(vcpu, 0, exc_software_trap_mask,
				regs->crs.cr0_hi.CR0_hi_IP);
}

static inline void
kvm_inject_data_page_exc_on_IP(struct kvm_vcpu *vcpu, u64 ip)
{
	kvm_inject_trap_TIR(vcpu, 1, exc_data_page_mask, ip);
}

static inline void
kvm_inject_data_page_exc(struct kvm_vcpu *vcpu, pt_regs_t *regs)
{
	struct trap_pt_regs *trap = regs->trap;
	u64 ip;

	if (trap && trap->nr_TIRs >= 1 &&
			(trap->TIRs[1].TIR_hi.exc &
			(exc_data_page_mask | exc_recovery_point_mask))) {
		/* Synchronous page fault */
		ip = trap->TIRs[1].TIR_lo.TIR_lo_ip;
	} else if (trap && trap->nr_TIRs >= 0 &&
			(trap->TIRs[0].TIR_hi.exc & exc_data_page_mask)) {
		/* Hardware stacks SPILL/FILL operation (or some
		 * other hardware activity like CUT access). */
		ip = trap->TIRs[0].TIR_lo.TIR_lo_ip;
	} else {
		WARN_ON_ONCE(1);
		/* Precise IP unknown, so take IP of intercepted command */
		ip = AS(regs->crs.cr0_hi).ip << 3;
	}
	kvm_inject_data_page_exc_on_IP(vcpu, ip);
}

static inline void
kvm_inject_instr_page_exc(struct kvm_vcpu *vcpu, pt_regs_t *regs,
				unsigned long trap_mask, e2k_addr_t IP)
{
	kvm_inject_trap_TIR(vcpu, 0, trap_mask, IP);
}

static inline void
kvm_inject_ainstr_page_exc(struct kvm_vcpu *vcpu, pt_regs_t *regs,
				unsigned long trap_mask, e2k_addr_t IP)
{
	kvm_inject_trap_TIR(vcpu, 0, trap_mask,
				regs->crs.cr0_hi.CR0_hi_IP);
}

static inline void
kvm_inject_aau_page_exc(struct kvm_vcpu *vcpu, pt_regs_t *regs,
			unsigned int aa_no)
{
	struct trap_pt_regs *trap = regs->trap;
	u64 ip;
	e2k_tir_hi_t TIR_hi;
	e2k_tir_lo_t TIR_lo;
	int TIR_no = 0;

	if (trap && trap->nr_TIRs >= 0 && trap->TIRs[0].TIR_hi.aa != 0) {
		/* Hardware stacks SPILL/FILL operation (or some
		 * other hardware activity like CUT access). */
		ip = trap->TIRs[0].TIR_lo.TIR_lo_ip;
	} else {
		/* Precise IP unknown, so take IP of intercepted command */
		pr_err("%s(): unknown precise IP, so take IP of intercepted "
			"command\n", __func__);
		ip = regs->crs.cr0_hi.CR0_hi_IP;
	}

	TIR_lo.TIR_lo_reg = GET_CLEAR_TIR_LO(TIR_no);
	TIR_lo.TIR_lo_ip = ip;
	TIR_hi.TIR_hi_reg = GET_CLEAR_TIR_HI(TIR_no);
	TIR_hi.aa = (1UL << aa_no);
	kvm_update_vcpu_intc_TIR(vcpu, TIR_no, TIR_hi, TIR_lo);
	DebugTIRs("AAU trap is injected to guest TIRs #%d hi 0x%016llx "
		"lo 0x%016llx\n",
		TIR_no, TIR_hi.TIR_hi_reg, TIR_lo.TIR_lo_reg);
}

/*
 * CU interceptions events service
 */
static inline void
kvm_reset_intc_info_cu_is_deleted(intc_info_cu_entry_t *info)
{
	info->no_restore = false;
}
static inline void
kvm_set_intc_info_cu_is_deleted(intc_info_cu_entry_t *info)
{
	info->no_restore = true;
}
static inline bool
kvm_is_intc_info_cu_deleted(intc_info_cu_entry_t *info)
{
	return info->no_restore;
}

static inline void
kvm_delete_intc_info_cu(struct kvm_vcpu *vcpu, intc_info_cu_entry_t *info)
{
	if (!likely(kvm_is_intc_info_cu_deleted(info))) {
		kvm_set_intc_info_cu_is_deleted(info);
		kvm_set_intc_info_cu_is_updated(vcpu);
	}
}

/*
 * MMU interceptions events service
 */
static inline void
kvm_reset_intc_info_mu_is_deleted(intc_info_mu_t *info)
{
	info->no_restore = false;
}
static inline void
kvm_set_intc_info_mu_is_deleted(intc_info_mu_t *info)
{
	info->no_restore = true;
}
static inline bool
kvm_is_intc_info_mu_deleted(intc_info_mu_t *info)
{
	return info->no_restore;
}

static inline void
kvm_delete_intc_info_mu(struct kvm_vcpu *vcpu, intc_info_mu_t *info)
{
	if (!likely(kvm_is_intc_info_mu_deleted(info))) {
		kvm_set_intc_info_mu_is_deleted(info);
		kvm_set_intc_info_mu_is_updated(vcpu);
	}
}

extern const mu_event_desc_t mu_events_desc_table[MU_INTC_EVENTS_MAX];

static inline const mu_event_desc_t *kvm_get_mu_event_desc(int evn_code)
{
	const mu_event_desc_t *mu_event;

	E2K_KVM_BUG_ON(evn_code < 0 || evn_code >= MU_INTC_EVENTS_MAX);
	mu_event = &mu_events_desc_table[evn_code];
	E2K_KVM_BUG_ON(mu_event->code != evn_code);
	return mu_event;
}

static inline mu_intc_handler_t kvm_get_mu_event_handler(int evn_code)
{
	const mu_event_desc_t *mu_event;

	mu_event = kvm_get_mu_event_desc(evn_code);
	return mu_event->handler;
}

static inline const char *kvm_get_mu_event_name(int evn_code)
{
	const mu_event_desc_t *mu_event;

	mu_event = kvm_get_mu_event_desc(evn_code);
	return mu_event->name;
}

#ifdef CONFIG_KVM_ASYNC_PF
extern intc_info_mu_event_code_t get_event_code(struct kvm_vcpu *vcpu,
					int ev_no);
extern bool intc_mu_record_asynchronous(struct kvm_vcpu *vcpu, int ev_no);
#endif /* CONFIG_KVM_ASYNC_PF */

#endif	/* __KVM_E2K_INTERCEPTS_H */
