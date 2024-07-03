/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/kernel.h>
#include <linux/ratelimit.h>
#include <linux/sched/signal.h>

#ifdef CONFIG_USE_AAU
#include <asm/aau_context.h>
#endif
#include <asm/e2k_api.h>
#include <asm/atomic_api.h>
#include <asm/cpu_regs.h>
#include <asm/head.h>
#include <asm/kdebug.h>
#include <asm/regs_state.h>
#include <asm/tags.h>
#include <asm/traps.h>
#include <asm/trap_table.h>
#include <asm/debug_print.h>
#include <asm/kvm/uaccess.h>

/******************************* DEBUG DEFINES ********************************/
#undef	DEBUG_PF_MODE
#define	DEBUG_PF_MODE	0	/* Page fault */
#define	DebugPF(...)	DebugPrint(DEBUG_PF_MODE ,##__VA_ARGS__)
/******************************************************************************/

u64 native_get_cu_hw1_v5()
{
	return NATIVE_READ_CU_HW1_REG_VALUE();
}

void native_set_cu_hw1_v5(u64 cu_hw1)
{
	NATIVE_WRITE_CU_HW1_REG_VALUE(cu_hw1);
	E2K_WAIT_ALL;
}

__section(".entry.text")
notrace __interrupt
void save_local_gregs_v5(struct local_gregs *gregs, bool is_signal)
{
	gregs->bgr = NATIVE_READ_BGR_REG();
	init_BGR_reg(); /* enable whole GRF */
	if (is_signal)
		SAVE_GREGS_SIGNAL(gregs->g, E2K_ISET_V5);
	NATIVE_WRITE_BGR_REG(gregs->bgr);
}

__section(".entry.text")
notrace __interrupt
void save_kernel_gregs_v5(struct kernel_gregs *gregs)
{
	NATIVE_SAVE_GREG(&gregs->g[GUEST_VCPU_STATE_GREGS_PAIRS_INDEX],
		&gregs->g[CURRENT_TASK_GREGS_PAIRS_INDEX],
		GUEST_VCPU_STATE_GREG, CURRENT_TASK_GREG, E2K_ISET_V5);
	NATIVE_SAVE_GREG(&gregs->g[MY_CPU_OFFSET_GREGS_PAIRS_INDEX],
		&gregs->g[SMP_CPU_ID_GREGS_PAIRS_INDEX],
		MY_CPU_OFFSET_GREG, SMP_CPU_ID_GREG, E2K_ISET_V5);
}

notrace __interrupt
void save_gregs_on_mask_v5(struct e2k_global_regs *gregs, bool dirty_bgr,
				unsigned long mask_not_save)
{
	gregs->bgr = NATIVE_READ_BGR_REG();
	init_BGR_reg(); /* enable whole GRF */
	if (mask_not_save == (GLOBAL_GREGS_USER_MASK | KERNEL_GREGS_MASK)) {
		/* it is same case as save all excluding global register */
		/* %g0 - %g15 and registers used by kernel %gN - %gN+3 */
		/* now N=16 see asm/glob_regs.h */
		SAVE_GREGS_EXCEPT_GLOBAL_AND_KERNEL(gregs->g, E2K_ISET_V5);
	} else if (mask_not_save == KERNEL_GREGS_MASK) {
		/* it is same case as save all excluding registers used */
		/* by kernel %gN - %gN+3 now N=16 see asm/glob_regs.h */
		SAVE_GREGS_EXCEPT_KERNEL(gregs->g, E2K_ISET_V5);
	} else if (mask_not_save == 0) {
		/* save all registers */
		SAVE_ALL_GREGS(gregs->g, E2K_ISET_V5);
	} else {
		/* common case with original mask */
		DO_SAVE_GREGS_ON_MASK(gregs->g, E2K_ISET_V5, mask_not_save);
	}
	if (!dirty_bgr)
		NATIVE_WRITE_BGR_REG(gregs->bgr);
}

__section(".entry.text")
notrace __interrupt
void save_gregs_v5(struct e2k_global_regs *gregs)
{
	gregs->bgr = NATIVE_READ_BGR_REG();
	init_BGR_reg(); /* enable whole GRF */
	SAVE_GREGS(gregs->g, true, E2K_ISET_V5);
	NATIVE_WRITE_BGR_REG(gregs->bgr);
}

__section(".entry.text")
notrace __interrupt
void save_gregs_dirty_bgr_v5(struct e2k_global_regs *gregs)
{
	gregs->bgr = NATIVE_READ_BGR_REG();
	init_BGR_reg(); /* enable whole GRF */
	SAVE_GREGS(gregs->g, true, E2K_ISET_V5);
}

__section(".entry.text")
notrace __interrupt
void restore_local_gregs_v5(const struct local_gregs *gregs, bool is_signal)
{
	init_BGR_reg();
	if (is_signal)
		RESTORE_GREGS_SIGNAL(gregs->g, E2K_ISET_V5);
	NATIVE_WRITE_BGR_REG(gregs->bgr);
}

notrace __interrupt
void restore_gregs_on_mask_v5(struct e2k_global_regs *gregs, bool dirty_bgr,
				unsigned long mask_not_restore)
{
	init_BGR_reg(); /* enable whole GRF */
	if (mask_not_restore == (GLOBAL_GREGS_USER_MASK | KERNEL_GREGS_MASK)) {
		/* it is same case as restore all excluding global register */
		/* %g0 - %g15 and registers used by kernel %gN - %gN+3 */
		/* now N=16 see asm/glob_regs.h */
		RESTORE_GREGS_EXCEPT_GLOBAL_AND_KERNEL(gregs->g, E2K_ISET_V5);
	} else if (mask_not_restore == KERNEL_GREGS_MASK) {
		/* it is same case as restore all excluding registers used */
		/* by kernel %gN - %gN+3 now N=16 see asm/glob_regs.h */
		RESTORE_GREGS_EXCEPT_KERNEL(gregs->g, E2K_ISET_V5);
	} else if (mask_not_restore == 0) {
		/* restore all registers */
		RESTORE_ALL_GREGS(gregs->g, E2K_ISET_V5);
	} else {
		/* common case with original mask */
		DO_RESTORE_GREGS_ON_MASK(gregs->g, E2K_ISET_V5,
							mask_not_restore);
	}
	if (!dirty_bgr)
		NATIVE_WRITE_BGR_REG(gregs->bgr);
}

__section(".entry.text")
notrace __interrupt
void restore_gregs_v5(const struct e2k_global_regs *gregs)
{
	init_BGR_reg();  /* enable whole GRF */
	RESTORE_GREGS(gregs->g, true, E2K_ISET_V5);
	NATIVE_WRITE_BGR_REG(gregs->bgr);
}

notrace
void qpswitchd_sm(int greg)
{
	E2K_QPSWITCHD_SM_GREG(greg);
}

#ifdef CONFIG_USE_AAU
static inline u64 signext(u64 val, int nr)
{
	s64 sval = (s64) val;

	return (u64) ((sval << (63 - nr)) >> (63 - nr));
}

/* calculate current array prefetch buffer indices values
 * (see chapter 1.10.2 in "Scheduling") */
void calculate_aau_aaldis_aaldas_v5(const struct pt_regs *regs,
		e2k_aalda_t *aaldas, e2k_aau_t *context)
{
	bool user;
	u64 areas, area_num, iter_count;
	u64 *aaldis = context->aaldi;

	memset(aaldas, 0, AALDAS_REGS_NUM * sizeof(aaldas[0]));
	memset(aaldis, 0, AALDIS_REGS_NUM * sizeof(aaldis[0]));

	/* It is first guest run to set initial state of AAU */
	if (unlikely(!regs))
		return;

	user = user_mode(regs);

	/* get_user() is used here */
	WARN_ON_ONCE(user && __raw_irqs_disabled());

	/* See bug 33621 comment 2 and bug 52350 comment 29 */
	iter_count = regs->ilcr1 - regs->lsr1;
	if (get_ldmc(regs->lsr) && !regs->lsr1)
		iter_count += get_ecnt(regs->ilcr) - get_ecnt(regs->lsr) - 1;

	/*
	 * Calculate areas in the following order:
	 *
	 *   0 -> 32 -> 1 -> 33 -> 2 -> ... -> 62 -> 31 -> 63
	 *
	 * until all the set bits in aaldv are checked.
	 */
	for (area_num = 0, areas = AW(context->aaldv); areas != 0;
			areas &= ~(1UL << area_num),
			area_num = (area_num < 32) ? (area_num + 32)
						   : (area_num - 31)) {
		e2k_fapb_instr_t *fapb_addr;
		e2k_fapb_instr_t fapb;
		e2k_aalda_t tmp_aalda;
		u64 step, ind, iter;
		int ret;

		if (!(AW(context->aaldv) & (1UL << area_num)))
			continue;

		iter = iter_count + ((AW(context->aaldm) & (1UL << area_num))
				>> area_num);

		if (iter == 0) {
			AW(context->aaldv) &= ~(1UL << area_num);
			continue;
		}

		if (area_num < 32)
			fapb_addr = (e2k_fapb_instr_t *)
				(AS(regs->ctpr2).ta_base + 16 * area_num);
		else
			fapb_addr = (e2k_fapb_instr_t *)
					(AS(regs->ctpr2).ta_base + 8 +
						16 * (area_num - 32));

		if (!user) {
			fapb = *fapb_addr;
		} else if ((ret = host_get_user(AW(fapb), (u64 *) fapb_addr, regs))) {
			if (ret == -EAGAIN)
				break;
			force_sig(SIGSEGV);
			return;
		}

		if (area_num >= 32 && AS(fapb).dpl) {
			/* See bug #53880 */
			pr_info_once("%s [%d]: AAU is working in dpl mode "
				"(FAPB at %px)\n",
				current->comm, current->pid, fapb_addr);

			aaldas[area_num] = aaldas[area_num - 32];
			aaldis[area_num] = aaldis[area_num - 32];
			continue;
		}

		if (!AS(fapb).fmt)
			continue;

		step = context->aaincrs[AS(fapb).incr];
		step = signext(step, 48);
		step = step << (AS(fapb).fmt - 1);

		ind = context->aainds[AS(fapb).ind];
		ind = signext(ind, 48);
		ind += AS(fapb).disp + step * iter;

		AS(tmp_aalda).exc = 0;
		AS(tmp_aalda).root = (AS(context->aads[AS(fapb).d]).lo.tag ==
				AAD_AAUDS);

		aaldas[area_num] = tmp_aalda;

		aaldis[area_num] = ind;
	}
}

/* See chapter 1.10.3 in "Scheduling" */
void do_aau_fault_v5(int aa_field, struct pt_regs *regs)
{
	bool user = user_mode(regs);
	const e2k_aau_t	*const aau_regs = regs->aau_context;
	u32		aafstr = aau_regs->aafstr;
	unsigned int	aa_bit = 0;
	u64		iter_count;
	tc_cond_t	condition;
	tc_mask_t	mask;

	regs->trap->nr_page_fault_exc = exc_data_page_num;

	/* See bug 33621 comment 2 and bug 52350 comment 29 */
	iter_count = regs->ilcr1 - regs->lsr1;
	if (get_ldmc(regs->lsr) && !regs->lsr1)
		iter_count += get_ecnt(regs->ilcr) - get_ecnt(regs->lsr) - 1;

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
		u64 area_num, mrng, addr1, addr2, step, ind, d_num;
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
		} else if ((ret = host_get_user(AW(fapb), (u64 *) fapb_addr, regs))) {
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
					(u64 *) fapb_addr, regs))) {
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

		step = aau_regs->aaincrs[AS(fapb).incr];
		step = signext(step, 48);
		step = step << (AS(fapb).fmt - 1);

		ind = aau_regs->aainds[AS(fapb).ind];
		ind = signext(ind, 48);
		ind += AS(fapb).disp + step * iter_count;

		mrng = AS(fapb).mrng ?: 32;

		d_num = AS(fapb).d;
		if (AS(aau_regs->aads[d_num]).lo.tag == AAD_AAUSAP) {
			addr1 = AS(aau_regs->aads[d_num]).lo.sap_base + ind +
					(regs->stacks.top & ~0xffffffffULL);
		} else {
			addr1 = AS(aau_regs->aads[d_num]).lo.ap_base + ind;
		}
		addr2 = addr1 + mrng - 1;
		if (unlikely((addr1 & ~E2K_VA_MASK) || (addr2 & ~E2K_VA_MASK))){
			pr_notice_once("Bad address: addr 0x%llx, ind 0x%llx, mrng 0x%llx, step 0x%llx, fapb 0x%llx\n",
					addr1, ind, mrng, step,
					(unsigned long long)AW(fapb));

			addr1 &= E2K_VA_MASK;
			addr2 &= E2K_VA_MASK;
		}
		DebugPF("do_aau_fault: address1 = 0x%llx, address2 = 0x%llx, mrng=%lld\n",
				addr1, addr2, mrng);

		ret = do_aau_page_fault(regs, addr1, condition, mask, aa_bit);
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

notrace void save_aaldi_v5(u64 *aaldis)
{
	SAVE_AALDIS_V5(aaldis);
}

/*
 * It's taken that aasr was get earlier(from get_aau_context caller)
 * and comparison with aasr.iab was taken.
 */
notrace void get_aau_context_v5(e2k_aau_t *context, e2k_aasr_t aasr)
{
	GET_AAU_CONTEXT_V5(context, aasr);
}
#endif /* CONFIG_USE_AAU */

