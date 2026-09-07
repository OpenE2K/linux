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
#include <asm/aau_context.h>
#include <asm/cpu_regs.h>
#include <asm/hw_prefetchers.h>
#include <asm/kdebug.h>
#include <asm/kvm/cpu_hv_regs_access.h>
#include <asm/kvm/mmu_hv_regs_access.h>
#include <asm/machdep.h>
#include <asm/pic.h>
#include <asm/sic_regs.h>
#include <asm/sic_regs_access.h>
#include <asm/trap_def.h>
#include <asm/trap_table.h>
#include <asm/sclkr.h>
#include <asm/kvm_host.h>
#include <asm/kvm/uaccess.h>
#include <asm/kvm/trace_kvm_hv.h>

#include "iset-kvm.h"

/******************************* DEBUG DEFINES ********************************/
#undef	DEBUG_PF_MODE
#define	DEBUG_PF_MODE	0	/* Page fault */
#define	DebugPF(...)	DebugPrint(DEBUG_PF_MODE ,##__VA_ARGS__)
/******************************************************************************/


#ifdef CONFIG_MLT_STORAGE
static bool read_MLT_entry_v6(e2k_mlt_entry_t *mlt, int entry_num)
{
	AW(mlt->dw0) = NATIVE_READ_MLT_REG((REG_MLT_TYPE << REG_MLT_TYPE_SHIFT) |
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

#if	defined(CONFIG_KVM_HW_VIRTUALIZATION) && !defined(CONFIG_KVM_GUEST_KERNEL)
/* it is hardware virtualized host */

void save_kvm_context_v6(struct kvm_vcpu_arch *vcpu)
{
	kvm_save_host_context(arch_to_vcpu(vcpu), E2K_ISET_V6);
}

void restore_kvm_context_v6(const struct kvm_vcpu_arch *vcpu)
{
	kvm_restore_host_context(arch_to_vcpu(vcpu), E2K_ISET_V6);
}

#else /* !CONFIG_KVM_HW_VIRTUALIZATION || CONFIG_KVM_GUEST_KERNEL */
/* it is native kernel without virtualization */
/* or paravirtualized guest kernel */

void restore_kvm_context_v6(const struct kvm_vcpu_arch *vcpu)
{
}

void save_kvm_context_v6(struct kvm_vcpu_arch *vcpu)
{
}
#endif /* CONFIG_KVM_HW_VIRTUALIZATION && !CONFIG_KVM_GUEST_KERNEL */

/* calculate current array prefetch buffer indices values
 * (see chapter 1.10.2 in "Scheduling") */
void calculate_aau_aaldis_aaldas_v6(const struct pt_regs *regs,
				    e2k_aalda_t *aaldas, e2k_aau_t *context)
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
	condition.fmt = LDST_BYTE_FMT;
	condition.spec = 1;
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
			fapb_addr = (e2k_fapb_instr_t *) (regs->ctpr2.ta_base
							  + 16 * area_num);
		else
			fapb_addr = (e2k_fapb_instr_t *) (regs->ctpr2.ta_base
							  + 16 * (area_num - 32) + 8);

		if (!user) {
			fapb = *fapb_addr;
		} else if ((ret = host_get_user(AW(fapb), (u64 __user __force *)fapb_addr, regs))) {
			if (ret == -EAGAIN)
				break;
			goto die;
		}

		if (area_num >= 32 && fapb.dpl) {
			/* See bug #53880 */
			pr_notice_once("%s [%d]: AAU is working in dpl mode (FAPB at %px)\n",
				       current->comm, current->pid, fapb_addr);
			area_num -= 32;
			fapb_addr -= 1;
			if (!user) {
				fapb = *fapb_addr;
			} else if ((ret = host_get_user(AW(fapb),
					(u64 __user __force *) fapb_addr, regs))) {
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

		mrng = fapb.mrng ?: 32;

		d_num = fapb.d;
		if (aau_regs->aads[d_num].tag == AAD_AAUSAP) {
			addr1 = aau_regs->aads[d_num].sap_base +
					(regs->stacks.top & ~0xffffffffULL);
		} else {
			addr1 = aau_regs->aads[d_num].ap_base;
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

/* mem_wait_idle() waits for interrupt or modification
 * of need_resched.  Note that there can be spurious
 * wakeups as only whole cache lines can be watched. */
static void __cpuidle mem_wait_idle(void)
{
	unsigned long flags;
	unsigned long need_resched_mask = (1ul << TIF_NEED_RESCHED) |
			(IS_ENABLED(CONFIG_PREEMPT_LAZY) ? (1ul << TIF_NEED_RESCHED_LAZY) : 0);
	bool cpu_hwbug_wait_int = cpu_has(CPU_HWBUG_WAIT_INT);

	if (cpu_hwbug_wait_int)
		raw_all_irq_save(flags);
	E2K_WATCH_FOR_MODIFICATION_64(&current_thread_info()->flags, need_resched_mask);
	if (cpu_hwbug_wait_int)
		raw_all_irq_restore(flags);
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
	int reg = PMC_FREQ_CORE_SLEEP(core, cpu_has(CPU_FEAT_ISET_V7));
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

