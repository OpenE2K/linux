/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * GETSP operation parser
 */

#include <linux/ratelimit.h>

#include <asm/cpu_regs.h>
#include <asm/e2k_api.h>
#include <linux/uaccess.h>
#include <asm/current.h>
#include <asm/debug_print.h>
#include <asm/process.h>
#include <asm/traps.h>


#undef	DEBUG_US_EXPAND
#undef	DebugUS
#define	DEBUG_US_EXPAND		0	/* User stacks */
#define DebugUS(...)		DebugPrint(DEBUG_US_EXPAND ,##__VA_ARGS__)


static enum getsp_action get_getsp_32(u32 *value, unsigned long address,
				      void __user **fault_addr)
{
	if (access_ok((void __user *) address, sizeof(*value))) {
		/* Exception on user instruction */
		u32 __user *u_address = (u32 __user *) address;
		if (__get_user(*value, u_address)) {
			*fault_addr = u_address;
			return GETSP_OP_SIGSEGV;
		}
		return 0;
	} else if (address >= (unsigned long) __entry_handlers_start &&
		   address < (unsigned long) __entry_handlers_end) {
		/* Exception in fast system call */
		*value = *(u32 *) address;
		return 0;
	} else {
		DebugUS("suspicious trap ip, should not happen\n");
		return GETSP_OP_FAIL;
	}
}

static enum getsp_action get_getsp_16(u16 *value, unsigned long address,
				      void __user **fault_addr)
{
	if (access_ok((void __user *) address, sizeof(*value))) {
		/* Exception on user instruction */
		u16 __user *u_address = (u16 __user *) address;
		if (__get_user(*value, u_address)) {
			*fault_addr = u_address;
			return GETSP_OP_SIGSEGV;
		}
		return 0;
	} else if (address >= (unsigned long) __entry_handlers_start &&
		   address < (unsigned long) __entry_handlers_end) {
		/* Exception in fast system call */
		*value = *(u16 *) address;
		return 0;
	} else {
		DebugUS("suspicious trap ip, should not happen\n");
		return GETSP_OP_FAIL;
	}
}

static enum getsp_action parse_getsp_literal_operand(e2k_addr_t trap_ip,
						     instr_hs_t hs, instr_als_t als0,
						     s64 *incr, void __user **fault_addr)
{
	unsigned long lts;
	int lts_num;
	enum getsp_action ret;

	lts_num = AW(als0.alf2.src2) & INSTR_SRC2_LTS_NUM_MASK;
	lts = (unsigned long) &E2K_GET_INSTR_SYL(trap_ip,
			(hs.lng + 1) * 2 - hs.pl - hs.cd - lts_num - 1);

	if (instr_src2_is_lts16(als0.alf2.src2)) {
		if (lts_num > 1)
			return GETSP_OP_FAIL;

		if (AW(als0.alf2.src2) & INSTR_SRC2_LTS_SHIFT_MASK)
			lts += 2;

		s16 simm16;
		ret = get_getsp_16((u16 *) &simm16, lts, fault_addr);
		if (ret)
			return ret;

		*incr = (s64) simm16;
	} else if (instr_src2_is_lts32(als0.alf2.src2)) {
		s32 simm32;
		ret = get_getsp_32((u32 *) &simm32, lts, fault_addr);
		if (ret)
			return ret;

		*incr = (s64) simm32;
	} else if (instr_src2_is_lts64(als0.alf2.src2)) {
		u32 lo, hi;

		if (lts_num > 2)
			return GETSP_OP_FAIL;

		ret = get_getsp_32(&lo, lts, fault_addr);
		if (ret)
			return ret;
		ret = get_getsp_32(&hi, lts - 4, fault_addr);
		if (ret)
			return ret;

		*incr = (u64) lo | ((u64) hi << 32);
	} else {
		DebugUS("not known literal operand\n");
		return GETSP_OP_FAIL;
	}

	DebugUS("LTS%d=0x%llx lng=%d pl=%d cd=%d\n", lts_num, *incr, hs.lng, hs.pl, hs.cd);

	return 0;
}

static enum getsp_action get_getsp_greg(int greg_num, s64 *greg, bool use_dword)
{
	u64 gr;
	u8 tag;

	switch (greg_num) {
	case LOCAL_GREGS_START ... (LOCAL_GREGS_START + LOCAL_GREGS_NUM - 1):
		load_value_and_tagd(
			(const volatile void *)&current->thread.u_gregs.g[greg_num - LOCAL_GREGS_START].base,
			&gr, &tag);
		break;
	default:
		DebugUS("Invalid greg_num %d\n", greg_num);
		return GETSP_OP_FAIL;
	}

	if (use_dword && tag || !use_dword && (tag & 3)) {
		DebugUS("Invalid tag 0x%hhx for greg num %d with greg val %llu, dword=%d\n",
			tag, greg_num, gr, (int) use_dword);
		return GETSP_OP_FAIL;
	}

	*greg = gr;

	return 0;
}

static enum getsp_action parse_getsp_greg_operand(instr_als_t als0, s64 *incr, bool use_dword)
{
	int		greg_num;
	e2k_bgr_t	bgr, oldbgr;
	unsigned long	flags;
	enum getsp_action ret;

	greg_num = AW(als0.alf2.src2) & INSTR_SRC_DST_GREG_NUM_MASK;

	raw_local_irq_save(flags);

	bgr = read_BGR_reg();
	oldbgr = bgr;
	bgr.val = E2K_INITIAL_BGR_VAL;
	write_BGR_reg(bgr);

	if ((ret = get_getsp_greg(greg_num, incr, use_dword)))
		DebugUS("greg num %d, greg val 0x%llx\n", greg_num, *incr);

	write_BGR_reg(oldbgr);

	raw_local_irq_restore(flags);

	return ret;
}

static enum getsp_action parse_getsp_reg_operand(instr_src_t src2,
		 const struct pt_regs *regs, s64 *incr, void __user **fault_addr)
{
	unsigned long ps_top = (unsigned long)U_PSP_PTR(regs->stacks.psp);
	unsigned long u_ps_top = ps_top - PSHTP_MEM_INDEX(regs->stacks.pshtp);
	int ind_d, offset_d;
	unsigned long raddr, flags;

	if (!src2.rt7) {
		/* Instruction set 6.3.1.1 */
		e2k_br_t br = { .word = regs->crs.cr1.br };
		int rnum_d = AW(src2) & ~0x80;
		ind_d = 2 * br.rbs + (2 * br.rcur + rnum_d) % br_rsz_full_d(br);
	} else {
		/* Instruction set 6.3.1.2 */
		ind_d = AW(src2) & ~0xc0;
	}

	offset_d = 2 * regs->crs.cr1.wbs - ind_d;
	raddr = ps_top - ((offset_d + 1) / 2) * 32;
	if (offset_d % 2)
		raddr += machine.qnr1_offset;
	if (raddr < PAGE_OFFSET && raddr >= u_ps_top) {
		raddr += PSP_BASE(current_thread_info()->k_psp) - u_ps_top;
		raw_all_irq_save(flags);
		COPY_STACKS_TO_MEMORY();
		raw_all_irq_restore(flags);

		*incr = *(s64 *) raddr;
	} else {
		if (__get_user(*incr, (s64 __user *) raddr)) {
			*fault_addr = (s64 __user *) raddr;
			return GETSP_OP_SIGSEGV;
		}
	}

	return 0;
}

enum getsp_action parse_getsp_operation(const struct pt_regs *regs, s64 *incr,
					void __user **fault_addr)
{
	instr_hs_t hs;
	instr_als_t als0;
	instr_ales_t ales0 = { .word = 0 };
	e2k_tir_t tir = regs->trap->TIR;
	unsigned long trap_ip = tir.ip;
	enum getsp_action ret;

	*incr = USER_C_STACK_BYTE_INCR;

	DebugUS("started for IP 0x%lx, TIR_hi 0x%llx\n", trap_ip, HI(tir));
	if (!cpu_has(CPU_FEAT_ISET_V7) && !tir.al0) {
		DebugUS("exception is not for ALS0\n");
		return GETSP_OP_FAIL;
	}

	if (!(user_mode(regs) && (trap_ip >= (unsigned long) __entry_handlers_start &&
				  trap_ip < (unsigned long) __entry_handlers_end ||
				  access_ok((void __user *) trap_ip, E2K_INSTR_MAX_SIZE)))) {
		DebugUS("suspicious trap ip, should not happen\n");
		return GETSP_OP_FAIL;
	}

	ret = get_getsp_32(&AW(hs), (unsigned long) &E2K_GET_INSTR_HS(trap_ip),
			   fault_addr);
	if (ret)
		return ret;
	if (!hs.al0) {
		DebugUS("missing ALS0 Syllable: 0x%08x\n", AW(hs));
		return GETSP_OP_FAIL;
	}

	ret = get_getsp_32(&AW(als0), (unsigned long) &E2K_GET_INSTR_ALS0(trap_ip, hs.s),
			   fault_addr);
	if (ret)
		return ret;
	DebugUS("ALS0 syllable 0x%08x get from addr 0x%px\n", AW(als0), fault_addr);

	u32 cop = als0.alf2.cop;
	if (cop != GETSP_ALS_COP && cop != GETSPD_ALS_COP && cop != DRTOAP_ALS_COP ||
	    (cop == GETSP_ALS_COP || cop == GETSPD_ALS_COP) && !hs.ale0 ||
	    als0.alf2.opce != USD_ALS_OPCE) {
		DebugUS("ALS0 0x%x is neither GETSP nor GETSAP\n", AW(als0));
		return GETSP_OP_FAIL;
	}

	if (cop == GETSP_ALS_COP || cop == GETSPD_ALS_COP) {
		ret = get_getsp_16(&AW(ales0),
				(unsigned long) &E2K_GET_INSTR_ALES0(trap_ip, hs.mdl), fault_addr);
		if (ret)
			return ret;
		DebugUS("ALES0 syllable 0x%04x\n", AW(ales0));

		if (ales0.alef2.opc2 != EXT_ALES_OPC2) {
			DebugUS("ALES0 opcode #2 0x%02x is not EXT, so it is not GETSP\n",
				ales0.alef2.opc2);
			return GETSP_OP_FAIL;
		}
	}

	bool use_dword = (cop == GETSPD_ALS_COP);
	if (instr_src2_is_lts16(als0.alf2.src2) || instr_src2_is_lts32(als0.alf2.src2) ||
			instr_src2_is_lts64(als0.alf2.src2)) {
		ret = parse_getsp_literal_operand(trap_ip, hs, als0, incr, fault_addr);
	} else if (instr_src2_is_greg(als0.alf2.src2)) {
		ret = parse_getsp_greg_operand(als0, incr, use_dword);
	} else if (instr_src2_is_rf_reg(als0.alf2.src2)) {
		ret = parse_getsp_reg_operand(als0.alf2.src2, regs, incr, fault_addr);
	} else {
		ret = GETSP_OP_FAIL;
	}
	if (ret) {
		if (ret != GETSP_OP_SIGSEGV) {
			DebugUS("Parsing getsp operation at 0x%lx (HS 0x%x, ALS0 0x%x, ALES0 0x%hx) failed with %d\n",
				trap_ip, AW(hs), AW(als0), AW(ales0), ret);
		}
		return ret;
	}

	if (!use_dword)
		*incr = (s64) (s32) *incr;

	if (*incr < 0) {
		*incr = round_up(-(*incr), PAGE_SIZE);
		*incr = max(USER_C_STACK_BYTE_INCR, (unsigned long)*incr);
		DebugUS("expand on %lld bytes detected\n", *incr);
		return GETSP_OP_INCREMENT;
	}

	DebugUS("constrict on %lld bytes detected\n", *incr);
	return GETSP_OP_DECREMENT;
}

