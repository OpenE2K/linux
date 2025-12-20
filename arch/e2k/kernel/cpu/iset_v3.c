/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/cpu.h>
#include <linux/sched/signal.h>

#include <asm/mmu_regs_access.h>
#include <asm/e2k_api.h>
#include <asm/cpu_regs.h>
#include <asm/hw_prefetchers.h>
#include <asm/machdep.h>
#include <asm/nmi.h>
#include <asm/pic.h>
#include <asm/sic_regs.h>
#include <asm/regs_state.h>
#ifdef CONFIG_USE_AAU
#include <asm/aau_context.h>
#endif
#include <asm/trap_table.h>
#include <asm/kdebug.h>
#include <asm/kvm/uaccess.h>

/******************************* DEBUG DEFINES ********************************/
#undef	DEBUG_PF_MODE
#define	DEBUG_PF_MODE	0	/* Page fault */
#define	DebugPF(...)	DebugPrint(DEBUG_PF_MODE ,##__VA_ARGS__)
/******************************************************************************/

unsigned long rrd_v3(int reg)
{
	return 0;
}

void rwd_v3(int reg, unsigned long value)
{
}

u64 native_get_cu_hw1_v3()
{
	panic("No %%cu_hw1 in instruction set v3\n");
}

void native_set_cu_hw1_v3(u64 cu_hw1)
{
	panic("No %%cu_hw1 in instruction set v3\n");
}

#ifdef CONFIG_MLT_STORAGE
void invalidate_MLT_v3()
{
	NATIVE_SET_MMUREG(mlt_inv, 0);
}

static bool read_MLT_entry_v3(e2k_mlt_entry_t *mlt, int entry_num)
{
	AW(mlt->dw0) = NATIVE_READ_MLT_REG(REG_MLT_TYPE << REG_MLT_TYPE_SHIFT |
					   entry_num << REG_MLT_N_SHIFT);

	if (!AS_V3_STRUCT(mlt->dw0).val)
		return false;

	AW(mlt->dw1) = NATIVE_READ_MLT_REG(1 << REG_MLT_DW_SHIFT |
			REG_MLT_TYPE << REG_MLT_TYPE_SHIFT |
			entry_num << REG_MLT_N_SHIFT);
	AW(mlt->dw2) = NATIVE_READ_MLT_REG(2 << REG_MLT_DW_SHIFT |
			REG_MLT_TYPE << REG_MLT_TYPE_SHIFT |
			entry_num << REG_MLT_N_SHIFT);

	return true;
}

void get_and_invalidate_MLT_context_v3(e2k_mlt_t *mlt_state)
{
	int i;

	mlt_state->num = 0;

	for (i = 0; i < NATIVE_MLT_SIZE; i++) {
		e2k_mlt_entry_t *mlt = &mlt_state->mlt[mlt_state->num];

		if (read_MLT_entry_v3(mlt, i))
			mlt_state->num++;
	}

	NATIVE_SET_MMUREG(mlt_inv, 0);
}
#endif

__section(".entry.text")
notrace __interrupt
void save_local_gregs_v3(struct local_gregs *gregs, bool is_signal)
{
	gregs->bgr = NATIVE_READ_BGR_REG();
	init_BGR_reg(); /* enable whole GRF */
	if (is_signal)
		SAVE_GREGS_SIGNAL(gregs->g, E2K_ISET_V3);
	NATIVE_WRITE_BGR_REG(gregs->bgr);
}

__section(".entry.text")
notrace __interrupt
void save_kernel_gregs_v3(struct kernel_gregs *gregs)
{
	NATIVE_SAVE_GREG(&gregs->g[GUEST_VCPU_STATE_GREGS_PAIRS_INDEX],
		&gregs->g[CURRENT_TASK_GREGS_PAIRS_INDEX],
		GUEST_VCPU_STATE_GREG, CURRENT_TASK_GREG, E2K_ISET_V3);
	NATIVE_SAVE_GREG(&gregs->g[MY_CPU_OFFSET_GREGS_PAIRS_INDEX],
		&gregs->g[SMP_CPU_ID_GREGS_PAIRS_INDEX],
		MY_CPU_OFFSET_GREG, SMP_CPU_ID_GREG, E2K_ISET_V3);
}

notrace __interrupt
void save_gregs_on_mask_v3(struct e2k_global_regs *gregs, bool dirty_bgr,
				unsigned long mask_not_save)
{
	gregs->bgr = NATIVE_READ_BGR_REG();
	init_BGR_reg(); /* enable whole GRF */
	if (mask_not_save == (GLOBAL_GREGS_USER_MASK | KERNEL_GREGS_MASK)) {
		/* it is same case as save all excluding global register */
		/* %g0 - %g15 and registers used by kernel %gN - %gN+3 */
		/* now N=16 see asm/glob_regs.h */
		SAVE_GREGS_EXCEPT_GLOBAL_AND_KERNEL(gregs->g, E2K_ISET_V3);
	} else if (mask_not_save == KERNEL_GREGS_MASK) {
		/* it is same case as save all excluding registers used */
		/* by kernel %gN - %gN+3 now N=16 see asm/glob_regs.h */
		SAVE_GREGS_EXCEPT_KERNEL(gregs->g, E2K_ISET_V3);
	} else if (mask_not_save == 0) {
		/* save all registers */
		SAVE_ALL_GREGS(gregs->g, E2K_ISET_V3);
	} else {
		/* common case with original mask */
		DO_SAVE_GREGS_ON_MASK(gregs->g, E2K_ISET_V3, mask_not_save);
	}
	if (!dirty_bgr)
		NATIVE_WRITE_BGR_REG(gregs->bgr);
}

__section(".entry.text")
notrace __interrupt
void save_gregs_v3(struct e2k_global_regs *gregs)
{
	gregs->bgr = NATIVE_READ_BGR_REG();
	init_BGR_reg(); /* enable whole GRF */
	SAVE_GREGS_EXCEPT_KERNEL(gregs->g, E2K_ISET_V3);
	NATIVE_WRITE_BGR_REG(gregs->bgr);
}

__section(".entry.text")
notrace __interrupt
void save_gregs_dirty_bgr_v3(struct e2k_global_regs *gregs)
{
	gregs->bgr = NATIVE_READ_BGR_REG();
	init_BGR_reg(); /* enable whole GRF */
	SAVE_GREGS(gregs->g, true, E2K_ISET_V3);
}

__section(".entry.text")
notrace __interrupt
void restore_local_gregs_v3(const struct local_gregs *gregs, bool is_signal)
{
	init_BGR_reg();
	if (is_signal)
		RESTORE_GREGS_SIGNAL(gregs->g, E2K_ISET_V3);
	NATIVE_WRITE_BGR_REG(gregs->bgr);
}

notrace __interrupt
void restore_gregs_on_mask_v3(struct e2k_global_regs *gregs, bool dirty_bgr,
				unsigned long mask_not_restore)
{
	init_BGR_reg(); /* enable whole GRF */
	if (mask_not_restore == (GLOBAL_GREGS_USER_MASK | KERNEL_GREGS_MASK)) {
		/* it is same case as restore all excluding global register */
		/* %g0 - %g15 and registers used by kernel %gN - %gN+3 */
		/* now N=16 see asm/glob_regs.h */
		RESTORE_GREGS_EXCEPT_GLOBAL_AND_KERNEL(gregs->g, E2K_ISET_V3);
	} else if (mask_not_restore == KERNEL_GREGS_MASK) {
		/* it is same case as restore all excluding registers used */
		/* by kernel %gN - %gN+3 now N=16 see asm/glob_regs.h */
		RESTORE_GREGS_EXCEPT_KERNEL(gregs->g, E2K_ISET_V3);
	} else if (mask_not_restore == 0) {
		/* restore all registers */
		RESTORE_ALL_GREGS(gregs->g, E2K_ISET_V3);
	} else {
		/* common case with original mask */
		DO_RESTORE_GREGS_ON_MASK(gregs->g, E2K_ISET_V3,
							mask_not_restore);
	}
	if (!dirty_bgr)
		NATIVE_WRITE_BGR_REG(gregs->bgr);
}

__section(".entry.text")
notrace __interrupt
void restore_gregs_v3(const struct e2k_global_regs *gregs)
{
	init_BGR_reg();  /* enable whole GRF */
	RESTORE_GREGS(gregs->g, true, E2K_ISET_V3);
	NATIVE_WRITE_BGR_REG(gregs->bgr);
}

#ifdef CONFIG_USE_AAU
/* calculate current array prefetch buffer indices values
 * (see chapter 1.10.2 in "Scheduling") */
void calculate_aau_aaldis_aaldas_v3(const struct pt_regs *regs,
		e2k_aalda_t *aaldas, e2k_aau_t *context)
{
	bool user;
	u64 areas, area_num, iter_count;
	u64 *aaldis = context->aaldi;

	DebugPF("started for aasr 0x%x, aafstr 0x%x\n",
		regs->aasr.word, context->aafstr);

	memset(aaldas, 0, AALDAS_REGS_NUM * sizeof(aaldas[0]));
	memset(aaldis, 0, AALDIS_REGS_NUM * sizeof(aaldis[0]));

	/* It is first guest run to set initial state of AAU */
	if (unlikely(!regs))
		return;

	user = user_mode(regs);

	/* get_user() is used here */
	WARN_ON_ONCE(user && __raw_irqs_disabled());

	/* See bug 33621 comment 2 and bug 52350 comment 29 */
	iter_count = get_lcnt(regs->ilcr) - get_lcnt(regs->lsr);
	if (get_ldmc(regs->lsr) && !get_lcnt(regs->lsr))
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
		DebugPF("current area #%lld iter count %lld, iter %lld\n",
			area_num, iter_count, iter);

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
			goto die;
		}
		DebugPF("FAPB at %px instruction 0x%llx, fmt %d, si %d\n",
			fapb_addr, AW(fapb), AS(fapb).fmt, AS(fapb).si);

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

		AS(tmp_aalda).root = (AS(context->aads[AS(fapb).d]).lo.tag ==
				AAD_AAUDS);

		if (AS(fapb).si) {
			AS(tmp_aalda).cincr = 0;
			AS(tmp_aalda).exc = 0;
			aaldas[area_num] = tmp_aalda;
			DebugPF("calculated aalda[%lld] is 0x%x\n",
				area_num, tmp_aalda.word);
			continue;
		}

		ind = (context->aainds[AS(fapb).ind] + AS(fapb).disp)
				& 0xffffffffULL;
		step = (context->aaincrs[AS(fapb).incr] << (AS(fapb).fmt - 1))
				& 0xffffffffULL;
		if (context->aaincrs[AS(fapb).incr] >> 31)
			step = step | 0xffffffff00000000ULL;
		ind += step * iter;
		DebugPF("calculated ind 0x%llx step 0x%llx iter 0x%llx\n",
			ind, step, iter);
		if (ind >> 32) {
			AS(tmp_aalda).cincr = 1;
			AS(tmp_aalda).exc = AALDA_EIO;
		} else {
			AS(tmp_aalda).cincr = 0;
			AS(tmp_aalda).exc = 0;
		}

		aaldas[area_num] = tmp_aalda;
		DebugPF("calculated aalda[%lld] is 0x%x\n",
			area_num, tmp_aalda.word);

		aaldis[area_num] = ind & 0xffffffffULL;
		DebugPF("calculated aaldi[%lld] is 0x%llx\n",
			area_num, aaldis[area_num]);
	}

	return;

die:
	force_sig(SIGSEGV);
}

/* See chapter 1.10.3 in "Scheduling" */
void do_aau_fault_v3(int aa_field, struct pt_regs *regs)
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
	iter_count = get_lcnt(regs->ilcr) - get_lcnt(regs->lsr);
	if (get_ldmc(regs->lsr) && !get_lcnt(regs->lsr))
		iter_count += get_ecnt(regs->ilcr) - get_ecnt(regs->lsr) - 1;

	DebugPF("enter, aa_field 0x%x, aasr 0x%x, aafstr = 0x%x\n",
		aa_field, regs->aasr.word, aafstr);

	/* condition.store = 0
	 * condition.fault_type = 0 */
	AW(condition) = 0;
	AS(condition).fmt = LDST_BYTE_FMT;
	AS(condition).spec = 1;
	AW(mask) = 0;

	while (aa_bit < 4) {
		u64 area_num, mrng, d_num, addr1, addr2;
		e2k_fapb_instr_t *fapb_addr;
		e2k_fapb_instr_t fapb;
		u32 step, ind, disp;
		int ret;

		if (!(aa_field & 0x1) || !(aafstr & 0x1))
			goto next_area;

		area_num = (aafstr >> 1) & 0x3f;
		DebugPF("got interrupt on %d mova channel, area %lld\n",
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
		DebugPF("FAPB at %px instruction 0x%llx\n", fapb_addr, AW(fapb));

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

		step = aau_regs->aaincrs[AS(fapb).incr] << (AS(fapb).fmt - 1);
		disp = AS(fapb).disp + step * iter_count;
		d_num = AS(fapb).d;
		if (unlikely(AS(fapb).si))
			pr_notice_once("WARNING: %s (%d): uses secondary indexes at IP 0x%lx, ignoring\n",
					current->comm, current->pid, fapb_addr);

		ind = aau_regs->aainds[AS(fapb).ind] + disp;
		mrng = AS(fapb).mrng ?: 32;

		if (AS(aau_regs->aads[d_num]).lo.tag == AAD_AAUSAP) {
			addr1 = AS(aau_regs->aads[d_num]).lo.sap_base + ind +
					(regs->stacks.top & ~0xffffffffULL);
		} else {
			addr1 = AS(aau_regs->aads[d_num]).lo.ap_base + ind;
		}
		addr2 = addr1 + mrng - 1;
		DebugPF("AAD #%lld addr 0x%llx index 0x%x mrng 0x%llx, disp 0x%x, step 0x%x\n",
				d_num, addr1, ind, mrng, disp, step);
		if (unlikely((addr1 & ~E2K_VA_MASK) || (addr2 & ~E2K_VA_MASK))){
			pr_notice_once("Bad address: addr 0x%llx, ind 0x%x, mrng 0x%llx, disp 0x%x, step 0x%x, fapb 0x%lx\n",
					addr1, ind, mrng, disp,
					step, (unsigned long)AW(fapb));

			addr1 &= E2K_VA_MASK;
			addr2 &= E2K_VA_MASK;
		}
		DebugPF("address1 = 0x%llx, address2 = 0x%llx, mrng=%lld\n",
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
		if ((addr1 & 0xfffUL) > (addr2 & 0xfffUL)) {
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

	DebugPF("exit aau fault handler\n");

	return;

die:
	if (user)
		force_sig(SIGSEGV);
	else
		die("AAU error", regs, 0);
}

notrace void save_aaldi_v3(u64 *aaldis)
{
	SAVE_AALDIS_V3(aaldis);
}

/*
 * It's taken that aasr was get earlier(from get_aau_context caller)
 * and comparison with aasr.iab was taken.
 */
notrace void get_aau_context_v3(e2k_aau_t *context, e2k_aasr_t aasr)
{
	GET_AAU_CONTEXT_V3(context, aasr);
}
#endif /* CONFIG_USE_AAU */

/* SCLKR/SCLKM1/SCLKM2 implemented only on machine from e2s */

unsigned long native_read_SCLKR_reg_value(void)
{
	return NATIVE_READ_SCLKR_REG_VALUE();
}

unsigned long native_read_SCLKM1_reg_value(void)
{
	return NATIVE_READ_SCLKM1_REG_VALUE();
}

unsigned long native_read_SCLKM2_reg_value(void)
{
	return NATIVE_READ_SCLKM2_REG_VALUE();
}

void native_write_SCLKR_reg_value(unsigned long reg_value)
{
	NATIVE_WRITE_SCLKR_REG_VALUE(reg_value);
}

void native_write_SCLKM1_reg_value(unsigned long reg_value)
{
	NATIVE_WRITE_SCLKM1_REG_VALUE(reg_value);
}

void native_write_SCLKM2_reg_value(unsigned long reg_value)
{
	NATIVE_WRITE_SCLKM2_REG_VALUE(reg_value);
}

__section(".C1_wait_trap.text")
static noinline notrace void C1_wait_trap(void)
{
	/* Interrupts must be enabled in the ".wait_trap.text" section
	 * so that the wakeup IRQ is not missed by handle_wtrap().
	 *
	 * Cannot use normal `local_irq_enable()` here since this function
	 * is special - it can terminate at any point. */
	raw_all_irq_enable();

	C1_WAIT_TRAP_V3();
	/* Will not get here */
}

void __cpuidle C1_enter_v3(void)
{
	/* C1 state: just stop until a trap wakes us */
	WARN_ON_ONCE(!irqs_disabled());

	/* Make sure no NMI messes up our IRQ tracing */
	raw_all_irq_disable();
	trace_hardirqs_on();

	C1_wait_trap();
	local_irq_disable();
}

__section(".C3_wait_trap.text")
static noinline notrace void C3_wait_trap(bool nmi_only)
{
	e2k_st_core_t st_core;
	int cpuid = read_pic_id();
	int reg = SIC_st_core(cpuid % cpu_max_cores_num());
	int node = numa_node_id();
	phys_addr_t nbsr_phys = sic_get_node_nbsr_phys_base(node);

	/* Only NMIs that go through APIC are allowed: if we receive local
	 * NMI (or just a local exception) hardware will block.  So here we
	 * disable all other sources (and reenable them in handle_wtrap());
	 * it must be done under all closed interrupts so that handle_wtrap()
	 * does not try to read uninitalized values from [current->thread.C3].
	 *
	 * Newer processors have a much better "wait int" interface that
	 * doesn't have this problem (and some others) and should be used
	 * instead. */
	WARN_ON_ONCE(!raw_all_irqs_disabled());
	NATIVE_SET_MMUREG(mlt_inv, 0);
	current->thread.C3.ddbcr = READ_DDBCR_REG();
	current->thread.C3.dibcr = READ_DIBCR_REG();
	current->thread.C3.ddmcr = READ_DDMCR_REG();
	current->thread.C3.dimcr = READ_DIMCR_REG();

	WRITE_DDBCR_REG_VALUE(0);
	WRITE_DIBCR_REG_VALUE(0);
	WRITE_DDMCR_REG_VALUE(0);
	WRITE_DIMCR_REG_VALUE(0);

	current->thread.C3.pref_state = hw_prefetchers_save();

	AW(st_core) = sic_read_node_nbsr_reg(node, reg);
	st_core.val = 0;
	if (IS_MACHINE_E1CP)
		st_core.e1cp.pmc_rst = 1;

	/* Interrupts must be enabled in the ".wait_trap.text" section
	 * so that the wakeup IRQ is not missed by handle_wtrap(). */
	if (nmi_only)
		raw_local_irq_disable();
	else
		raw_all_irq_enable();

	C3_WAIT_TRAP_V3(AW(st_core), nbsr_phys, reg);
	/* Will not get here */
}

void __cpuidle C3_enter_v3(void)
{
	WARN_ON_ONCE(!irqs_disabled());

	/* Make sure no NMI messes up our IRQ tracing */
	raw_all_irq_disable();
	trace_hardirqs_on();

	C3_wait_trap(false);
	local_irq_disable();
}

#ifdef CONFIG_SMP
void native_clock_off_v3(void)
{
	unsigned long flags;

	/* Make sure we do not race with `callin_go` write */
	raw_all_irq_save(flags);
	if (!cpumask_test_cpu(read_pic_id(), &callin_go))
		C3_wait_trap(true);
	raw_all_irq_restore(flags);
}

static void clock_on_v3_ipi(void *unused)
{
	/* Handling is done in handle_wtrap() */
}

void native_clock_on_v3(int cpu)
{
	/* Wake CPU disabled by clk_off(CPU_HOTPLUG_CLOCK_OFF) */
	nmi_call_function_single_offline(cpu, clock_on_v3_ipi, NULL, true, 0);
}
#endif
