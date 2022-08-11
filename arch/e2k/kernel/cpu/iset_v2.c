#include <linux/cpu.h>
#include <linux/kernel.h>
#include <linux/sched/signal.h>

#include <asm/e2k_api.h>
#include <asm/cpu_regs.h>
#include <asm/head.h>
#include <asm/machdep.h>
#include <asm/pic.h>
#include <asm/ptrace.h>
#include <asm/regs_state.h>
#include <asm/sic_regs.h>
#include <asm/aau_context.h>
#include <asm/traps.h>
#include <asm/trap_table.h>
#include <asm/kvm/uaccess.h>

/******************************* DEBUG DEFINES ********************************/
#undef	DEBUG_PF_MODE
#define	DEBUG_PF_MODE	0	/* Page fault */
#define	DebugPF(...)	DebugPrint(DEBUG_PF_MODE ,##__VA_ARGS__)
/******************************************************************************/

unsigned long rrd_v2(int reg)
{
	return 0;
}

void rwd_v2(int reg, unsigned long value)
{
}

u64 native_get_cu_hw1_v2()
{
	panic("No %%cu_hw1 in instruction set v2\n");
}

void native_set_cu_hw1_v2(u64 cu_hw1)
{
	panic("No %%cu_hw1 in instruction set v2\n");
}

__section(".entry.text")
notrace __interrupt
void save_local_gregs_v2(struct local_gregs *gregs, bool is_signal)
{
	gregs->bgr = NATIVE_READ_BGR_REG();
	init_BGR_reg(); /* enable whole GRF */
	if (is_signal)
		SAVE_GREGS_SIGNAL(gregs->g, E2K_ISET_V2);
	NATIVE_WRITE_BGR_REG(gregs->bgr);
}

__section(".entry.text")
notrace __interrupt
void save_kernel_gregs_v2(struct kernel_gregs *gregs)
{
	NATIVE_SAVE_GREG(&gregs->g[GUEST_VCPU_STATE_GREGS_PAIRS_INDEX],
		&gregs->g[CURRENT_TASK_GREGS_PAIRS_INDEX],
		GUEST_VCPU_STATE_GREG, CURRENT_TASK_GREG, E2K_ISET_V2);
	NATIVE_SAVE_GREG(&gregs->g[MY_CPU_OFFSET_GREGS_PAIRS_INDEX],
		&gregs->g[SMP_CPU_ID_GREGS_PAIRS_INDEX],
		MY_CPU_OFFSET_GREG, SMP_CPU_ID_GREG, E2K_ISET_V2);
}

notrace __interrupt
void save_gregs_on_mask_v2(struct global_regs *gregs, bool dirty_bgr,
				unsigned long mask_not_save)
{
	gregs->bgr = NATIVE_READ_BGR_REG();
	init_BGR_reg(); /* enable whole GRF */
	if (mask_not_save == (GLOBAL_GREGS_USER_MASK | KERNEL_GREGS_MASK)) {
		/* it is same case as save all excluding global register */
		/* %g0 - %g15 and registers used by kernel %gN - %gN+3 */
		/* now N=16 see asm/glob_regs.h */
		SAVE_GREGS_EXCEPT_GLOBAL_AND_KERNEL(gregs->g, E2K_ISET_V2);
	} else if (mask_not_save == KERNEL_GREGS_MASK) {
		/* it is same case as save all excluding registers used */
		/* by kernel %gN - %gN+3 now N=16 see asm/glob_regs.h */
		SAVE_GREGS_EXCEPT_KERNEL(gregs->g, E2K_ISET_V2);
	} else if (mask_not_save == 0) {
		/* save all registers */
		SAVE_ALL_GREGS(gregs->g, E2K_ISET_V2);
	} else {
		/* common case with original mask */
		DO_SAVE_GREGS_ON_MASK(gregs->g, E2K_ISET_V2, mask_not_save);
	}
	if (!dirty_bgr)
		NATIVE_WRITE_BGR_REG(gregs->bgr);
}

__section(".entry.text")
notrace __interrupt
void save_gregs_v2(struct global_regs *gregs)
{
	gregs->bgr = NATIVE_READ_BGR_REG();
	init_BGR_reg(); /* enable whole GRF */
	SAVE_GREGS_EXCEPT_KERNEL(gregs->g, E2K_ISET_V2);
	NATIVE_WRITE_BGR_REG(gregs->bgr);
}

__section(".entry.text")
notrace __interrupt
void save_gregs_dirty_bgr_v2(struct global_regs *gregs)
{
	gregs->bgr = NATIVE_READ_BGR_REG();
	init_BGR_reg(); /* enable whole GRF */
	SAVE_GREGS(gregs->g, true, E2K_ISET_V2);
}

__section(".entry.text")
notrace __interrupt
void restore_local_gregs_v2(const struct local_gregs *gregs, bool is_signal)
{
	init_BGR_reg();
	if (is_signal)
		RESTORE_GREGS_SIGNAL(gregs->g, E2K_ISET_V2);
	NATIVE_WRITE_BGR_REG(gregs->bgr);
}

notrace __interrupt
void restore_gregs_on_mask_v2(struct global_regs *gregs, bool dirty_bgr,
				unsigned long mask_not_restore)
{
	init_BGR_reg(); /* enable whole GRF */
	if (mask_not_restore == (GLOBAL_GREGS_USER_MASK | KERNEL_GREGS_MASK)) {
		/* it is same case as restore all excluding global register */
		/* %g0 - %g15 and registers used by kernel %gN - %gN+3 */
		/* now N=16 see asm/glob_regs.h */
		RESTORE_GREGS_EXCEPT_GLOBAL_AND_KERNEL(gregs->g, E2K_ISET_V2);
	} else if (mask_not_restore == KERNEL_GREGS_MASK) {
		/* it is same case as restore all excluding registers used */
		/* by kernel %gN - %gN+3 now N=16 see asm/glob_regs.h */
		RESTORE_GREGS_EXCEPT_KERNEL(gregs->g, E2K_ISET_V2);
	} else if (mask_not_restore == 0) {
		/* restore all registers */
		RESTORE_ALL_GREGS(gregs->g, E2K_ISET_V2);
	} else {
		/* common case with original mask */
		DO_RESTORE_GREGS_ON_MASK(gregs->g, E2K_ISET_V2,
							mask_not_restore);
	}
	if (!dirty_bgr)
		NATIVE_WRITE_BGR_REG(gregs->bgr);
}

__section(".entry.text")
notrace __interrupt
void restore_gregs_v2(const struct global_regs *gregs)
{
	init_BGR_reg();  /* enable whole GRF */
	RESTORE_GREGS(gregs->g, true, E2K_ISET_V2);
	NATIVE_WRITE_BGR_REG(gregs->bgr);
}

#ifdef CONFIG_USE_AAU
/* calculate current array prefetch buffer indices values
 * (see chapter 1.10.2 in "Scheduling") */
void calculate_aau_aaldis_aaldas_v2(const struct pt_regs *regs,
		struct thread_info *ti, e2k_aau_t *context)
{
	u64 areas, area_num, iter_count;
	e2k_aalda_t *aaldas = ti->aalda;
	u64 *aaldis = context->aaldi;
	/* get_user() is used here */
	WARN_ON_ONCE(regs && __raw_irqs_disabled());

	DebugPF("started for aasr 0x%x, aafstr 0x%x\n",
		context->aasr.word, context->aafstr);

	memset(aaldas, 0, AALDAS_REGS_NUM * sizeof(aaldas[0]));
	memset(aaldis, 0, AALDIS_REGS_NUM * sizeof(aaldis[0]));

	/* It is first guest run to set initial state of AAU */
	if (unlikely(!regs))
		return;

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

# if __LCC__ >= 120
		/*
		 * tmp is used to avoid compiler issue with passing
		 * union's fields into inline asm. Bug 76907.
		 */
		u64 tmp;
		long ret_get_user;

		ret_get_user = host_get_user(tmp, (u64 *)fapb_addr, regs);
		if (ret_get_user) {
			if (ret_get_user == -EAGAIN)
				break;
			else
				goto die;
		}
		fapb.word = tmp;
# else
		long ret_get_user;

		ret_get_user = host_get_user(AW(fapb), (u64 *)fapb_addr, regs);
		if (ret_get_user) {
			if (ret_get_user == -EAGAIN)
				break;
			else
				goto die;
		}
# endif
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
void do_aau_fault_v2(int aa_field, struct pt_regs *regs)
{
	const e2k_aau_t	*const aau_regs = regs->aau_context;
	u32		aafstr = aau_regs->aafstr;
	unsigned int	aa_bit = 0;
	u64		iter_count;
	tc_cond_t	condition;
	tc_mask_t	mask;
	int		ret;
	long ret_get_user;

	regs->trap->nr_page_fault_exc = exc_data_page_num;

	/* See bug 33621 comment 2 and bug 52350 comment 29 */
	iter_count = get_lcnt(regs->ilcr) - get_lcnt(regs->lsr);
	if (get_ldmc(regs->lsr) && !get_lcnt(regs->lsr))
		iter_count += get_ecnt(regs->ilcr) - get_ecnt(regs->lsr) - 1;

	DebugPF("enter, aa_field 0x%x, aasr 0x%x, aafstr = 0x%x\n",
		aa_field, aau_regs->aasr.word, aafstr);

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

		ret_get_user = host_get_user(AW(fapb), (u64 *)fapb_addr, regs);
		if (ret_get_user) {
			if (ret_get_user == -EAGAIN)
				break;
			else
				goto die;
		}

		DebugPF("FAPB at %px instruction 0x%llx\n",
			fapb_addr, AW(fapb));

		if (area_num >= 32 && AS(fapb).dpl) {
			/* See bug #53880 */
			pr_notice_once("%s [%d]: AAU is working in dpl mode (FAPB at %px)\n",
				current->comm, current->pid, fapb_addr);
			area_num -= 32;
			fapb_addr -= 1;
			ret_get_user = host_get_user(AW(fapb),
						(u64 *)fapb_addr, regs);
			if (ret_get_user) {
				if (ret_get_user == -EAGAIN)
					break;
				else
					goto die;
			}
		}

		if (!AS(aau_regs->aasr).iab) {
			WARN_ONCE(1, "%s [%d]: AAU fault happened but iab in AASR register was not set\n",
				current->comm, current->pid);
			goto die;
		}
		step = aau_regs->aaincrs[AS(fapb).incr] << (AS(fapb).fmt - 1);
		disp = AS(fapb).disp + step * iter_count;
		d_num = AS(fapb).d;
		if (unlikely(AS(fapb).si))
			pr_notice_once("WARNING: %s (%d): uses secondary "
				"indexes at IP 0x%lx, ignoring\n",
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
		DebugPF("AAD #%lld addr 0x%llx index 0x%x mrng"
			" 0x%llx, disp 0x%x, step 0x%x\n",
			d_num, addr1, ind, mrng, disp, step);
		if (unlikely((addr1 & ~E2K_VA_MASK) || (addr2 & ~E2K_VA_MASK))){
			pr_notice_once("Bad address: addr 0x%llx,"
				" ind 0x%x, mrng 0x%llx,"
				" disp 0x%x, step 0x%x, fapb 0x%lx\n",
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
	force_sig(SIGSEGV);
}

notrace void save_aaldi_v2(u64 *aaldis)
{
	SAVE_AALDIS_V2(aaldis);
}

/*
 * It's taken that aasr was get earlier(from get_aau_context caller)
 * and comparison with aasr.iab was taken.
 */
notrace void get_aau_context_v2(e2k_aau_t *context)
{
	GET_AAU_CONTEXT_V2(context);
}
#endif /* CONFIG_USE_AAU */

#ifdef CONFIG_MLT_STORAGE
static bool read_MLT_entry_v2(e2k_mlt_entry_t *mlt, int entry_num)
{
	AS_WORD(mlt->dw0) = NATIVE_READ_MLT_REG(
		(REG_MLT_TYPE << REG_MLT_TYPE_SHIFT) |
		(entry_num << REG_MLT_N_SHIFT));

	if (!AS_V2_STRUCT(mlt->dw0).val)
		return false;

	AS_WORD(mlt->dw1) = NATIVE_READ_MLT_REG(
		(1 << REG_MLT_DW_SHIFT) |
		(REG_MLT_TYPE << REG_MLT_TYPE_SHIFT) |
		(entry_num << REG_MLT_N_SHIFT));
	AS_WORD(mlt->dw2) = NATIVE_READ_MLT_REG(
		(2 << REG_MLT_DW_SHIFT) |
		(REG_MLT_TYPE << REG_MLT_TYPE_SHIFT) |
		(entry_num << REG_MLT_N_SHIFT));

	return true;
}

static void invalidate_MLT_entry_v2(e2k_mlt_entry_t *mlt)
{
	ldst_rec_op_t opc = {
		.fmt = 1,
		.mas = MAS_MLT_NOP_UNLOCK,
	};

	opc.rg_deprecated = AS_V2_STRUCT(mlt->dw0).rg;

	NATIVE_RECOVERY_STORE(&opc, 0x0, AW(opc), 2);
}

void invalidate_MLT_v2()
{
	int i;

	for (i = 0; i < NATIVE_MLT_SIZE; i++) {
		e2k_mlt_entry_t mlt;

		if (read_MLT_entry_v2(&mlt, i))
			invalidate_MLT_entry_v2(&mlt);
	}
}

void get_and_invalidate_MLT_context_v2(e2k_mlt_t *mlt_state)
{
	int i;

	mlt_state->num = 0;

	for (i = 0; i < NATIVE_MLT_SIZE; i++) {
		e2k_mlt_entry_t *mlt = &mlt_state->mlt[mlt_state->num];

		if (read_MLT_entry_v2(mlt, i)) {
			invalidate_MLT_entry_v2(mlt);
			mlt_state->num++;
		}
	}
}
#endif

__section(".C1_wait_trap.text")
static noinline notrace void C1_wait_trap(void)
{
	/* Interrupts must be enabled in the ".wait_trap.text" section
	 * so that the wakeup IRQ is not missed by handle_wtrap(). */
	local_irq_enable();

	C1_WAIT_TRAP_V3();
	/* Will not get here */
}

void __cpuidle C1_enter_v2(void)
{
	/* C1 state: just stop until a trap wakes us */
	WARN_ON_ONCE(!irqs_disabled());
	C1_wait_trap();
	local_irq_disable();
}
