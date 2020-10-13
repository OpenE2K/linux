/*
 * $Id: aau.c,v 1.27 2009/03/03 18:04:06 atic Exp $
 *
 * AAU page_miss handle module (get some from mm/fault.c)
 *
 */
#include <asm/e2k_api.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/mm.h>

#include <asm/cpu_regs_access.h>
#include <asm/aau_regs.h>
#include <asm/aau_context.h>
#include <asm/traps.h>
#include <asm/current.h>
#include <asm/ptrace.h>
#include <asm/siginfo.h>
#include <asm/hardirq.h>
//#include <asm/pgtable.h>
#include <asm/pgalloc.h>
#include <asm/console.h>
#include <asm/uaccess.h>

/******************************* DEBUG DEFINES ********************************/
#undef	DEBUG_AAU_CHECK
#undef	DEBUG_PF_MODE

#define DEBUG_AAU_CHECK		0
#define DbgChk	if (DEBUG_AAU_CHECK) printk

#define	DEBUG_PF_MODE		0	/* Page fault */
#define DebugPF(...)		DebugPrint(DEBUG_PF_MODE ,##__VA_ARGS__)
/******************************************************************************/

/* constants to pick LSR register fields up */
#define LSR_LCNT_MASK 0xFFFFFFFF

#define bool int

/* See chapter 1.10.3 in "Scheduling" */
void
do_aau_fault(int aa_field, struct pt_regs *regs)
{
	const e2k_aau_t	*const aau_regs = regs->aau_context;
	u32		aafstr = aau_regs->aafstr;
	unsigned int	aa_bit = 0;
	u64		iter_count;
	tc_cond_t	condition;

	DebugPF("\ndo_aau_fault: enter aau fault handler, TICKS = %lld\n",
			get_cycles());

	regs->trap->nr_page_fault_exc = exc_data_page_num;

	/* See bug 33621 comment 2 and bug 52350 comment 29 */
	iter_count = get_lcnt(regs->ilcr) - get_lcnt(regs->lsr);
	if (get_ldmc(regs->lsr) && !get_lcnt(regs->lsr))
		iter_count += get_ecnt(regs->ilcr) - get_ecnt(regs->lsr) - 1;

	DebugPF("do_aau_fault: aa_field = 0x%x\n", aa_field);
	DebugPF("do_aau_fault: aafstr = 0x%x\n", aafstr);
	DbgChk("do_aau_fault: ((regs->ilcr) & LSR_LCNT_MASK) = %d\n",
					(int)((regs->ilcr) & LSR_LCNT_MASK));
	DbgChk("do_aau_fault: ((regs->lsr) & LSR_LCNT_MASK) = %d\n",
					(int)((regs->lsr) & LSR_LCNT_MASK));
	DbgChk("do_aau_fault: iter_count = %lld\n", iter_count);

	/* condition.store = 0
	 * condition.spec = 0
	 * condition.fault_type = 0 */
	AW(condition) = 0;

	while (aa_bit < 4) {
		u64 area_num, mrng, d_num, addr1, addr2;
		e2k_fapb_instr_t *fapb_addr;
		e2k_fapb_instr_t fapb;
		u32 step, ind, disp;
		bool be;

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

		if (get_user(AW(fapb), (u64 *)fapb_addr))
			goto die;

		if (area_num >= 32 && AS(fapb).dpl) {
			static int once = 1;
			if (unlikely(once)) {
				/* See bug #53880 */
				once = 0;
				printk("%s [%d]: AAU is working in dpl mode "
					"(FAPB at %p)\n", current->comm,
					current->pid, fapb_addr);
			}
			area_num -= 32;
			fapb_addr -= 1;
			if (get_user(AW(fapb), (u64 *)fapb_addr))
				goto die;
		}

		if (!AS(aau_regs->aasr).iab) {
			printk("%s [%d]: AAU fault happened but "
					"iab in AASR register was not set\n",
					current->comm, current->pid);
			WARN_ON(1);
			goto die;
		}
		step = aau_regs->aaincrs[AS(fapb).incr] << (AS(fapb).fmt - 1);
		disp = AS(fapb).disp + step * iter_count;
		d_num = AS(fapb).d;
		be = AS(fapb).be;
		if (unlikely(AS(fapb).si))
			printk_once(KERN_NOTICE "WARNING: %s (%d): uses "
				"secondary indexes at IP 0x%lx, ignoring\n",
				current->comm, current->pid, fapb_addr);

		ind = aau_regs->aainds[AS(fapb).ind] + disp;
		mrng = AS(fapb).mrng ?: 32;

		addr1 = AS(aau_regs->aads[d_num]).lo.base + ind;
		addr2 = addr1 + mrng - 1;
		if (unlikely((addr1 & ~E2K_VA_MASK) || (addr2 & ~E2K_VA_MASK))){
			static int once = 1;

			if (once) {
				once = 0;
				printk("Bad address: base 0x%lx, ind 0x%x, "
					"mrng 0x%lx, disp 0x%x, step 0x%x, "
					"fapb 0x%lx\n",
					AS(aau_regs->aads[d_num]).lo.base,
					ind, mrng, disp, step, AW(fapb));
			}

			addr1 &= E2K_VA_MASK;
			addr2 &= E2K_VA_MASK;
		}
		DebugPF("do_aau_fault: address1 = 0x%lx, address2 = 0x%lx, mrng=%lld\n",
				addr1, addr2, mrng);

		(void) do_page_fault(regs, addr1, &condition, 0);
		if ((addr1 & 0xfffUL) > (addr2 & 0xfffUL))
			(void) do_page_fault(regs, addr2, &condition, 0);

next_area:
		aa_bit++;
		aafstr >>= 8;
		aa_field >>= 1;
	}

	DebugPF("do_aau_fault: exit aau fault handler, TICKS = %lld\n",
		get_cycles());

	return;

die:
	force_sig(SIGSEGV, current);
}
