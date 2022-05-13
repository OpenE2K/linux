/*
 * arch/e2k/kernel/getsp.c
 *
 * GETSP operation parser
 *
 * Copyright 2017 Pavel V. Panteleev (panteleev_p@mcst.ru)
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


static int parse_getsp_literal_operand(e2k_addr_t trap_ip, instr_hs_t hs,
		instr_als_t als0, int *incr, void __user **fault_addr)
{
	instr_syl_t	*lts;
	int		lts_num, lts_mask = 0, lts_shift = 0;
	bool		lts_sign_ext = false;

	lts_num = als0.alf2.src2 & INSTR_SRC2_LTS_NUM_MASK;

	if ((als0.alf2.src2 & INSTR_SRC2_BIT_MASK) == INSTR_SRC2_16BIT_VALUE) {
		WARN_ON_ONCE(lts_num > 1);
		if (als0.alf2.src2 & INSTR_SRC2_LTS_SHIFT_MASK) {
			lts_shift = INSTR_LTS_16BIT_SHIFT;
			lts_mask = INSTR_LTS_16BIT_SHIFT_MASK;
			lts_sign_ext = false;
		} else {
			lts_shift = INSTR_LTS_16BIT_NOSHIFT;
			lts_mask = INSTR_LTS_16BIT_NOSHIFT_MASK;
			lts_sign_ext = true;
		}
	} else if ((als0.alf2.src2 & INSTR_SRC2_BIT_MASK) ==
			INSTR_SRC2_32BIT_VALUE) {
		lts_mask = INSTR_LTS_32BIT_MASK;
		lts_shift = INSTR_LTS_32BIT_SHIFT;
		lts_sign_ext = false;
	} else {
		DebugUS("not known literal operand\n");
		return -EINVAL;
	}

	lts = &E2K_GET_INSTR_SYL(trap_ip, (hs.lng + 1) * 2 - hs.pl - hs.cd - lts_num - 1);
	if (get_user(*incr, lts)) {
		*fault_addr = lts;
		return -EFAULT;
	}

	DebugUS("LTS%d=0x%x lng=%d pl=%d cd=%d lts_shift=0x%x lts_mask=0x%x\n",
		lts_num, *incr, hs.lng, hs.pl, hs.cd,
		lts_shift, lts_mask);

	*incr = ((s32) ((*incr) & lts_mask)) >> lts_shift;
	if (lts_sign_ext)
		*incr = (((s32) *incr) << INSTR_LTS_16BIT_SHIFT) >>
							INSTR_LTS_16BIT_SHIFT;

	return 0;
}

static int get_getsp_greg(int greg_num, int *greg)
{
	struct thread_info* ti = current_thread_info();
	register u32 gr;
	u32 tag;

	switch (greg_num) {
	case 16:
		E2K_LOAD_VAL_AND_TAG(&ti->k_gregs.g[0].base, gr, tag);
		break;
	case 17:
		E2K_LOAD_VAL_AND_TAG(&ti->k_gregs.g[1].base, gr, tag);
		break;
	case 18:
		E2K_LOAD_VAL_AND_TAG(&ti->k_gregs.g[2].base, gr, tag);
		break;
	case 19:
		E2K_LOAD_VAL_AND_TAG(&ti->k_gregs.g[3].base, gr, tag);
		break;
	case 20:
		E2K_GET_GREG_VAL_AND_TAG(20, gr, tag);
		break;
	case 21:
		E2K_GET_GREG_VAL_AND_TAG(21, gr, tag);
		break;
	case 22:
		E2K_GET_GREG_VAL_AND_TAG(22, gr, tag);
		break;
	case 23:
		E2K_GET_GREG_VAL_AND_TAG(23, gr, tag);
		break;
	case 24:
		E2K_GET_GREG_VAL_AND_TAG(24, gr, tag);
		break;
	case 25:
		E2K_GET_GREG_VAL_AND_TAG(25, gr, tag);
		break;
	case 26:
		E2K_GET_GREG_VAL_AND_TAG(26, gr, tag);
		break;
	case 27:
		E2K_GET_GREG_VAL_AND_TAG(27 , gr, tag);
		break;
	case 28:
		E2K_GET_GREG_VAL_AND_TAG(28, gr, tag);
		break;
	case 29:
		E2K_GET_GREG_VAL_AND_TAG(29, gr, tag);
		break;
	case 30:
		E2K_GET_GREG_VAL_AND_TAG(30, gr, tag);
		break;
	case 31:
		E2K_GET_GREG_VAL_AND_TAG(31, gr, tag);
		break;
	default:
		DebugUS("Invalid greg_num %d\n", greg_num);
		return -ESRCH;
	}

	if (tag) {
		DebugUS("Invalid tag 0x%x for greg num %d with greg val %u\n",
			tag, greg_num, gr);
		return -EINVAL;
	}

	*greg = gr;

	return 0;
}

static int parse_getsp_greg_operand(instr_als_t als0, int *incr)
{
	int		greg_num;
	e2k_bgr_t	bgr, oldbgr;
	unsigned long	flags;
	int ret;

	greg_num = als0.alf2.src2 & INSTR_SRC2_GREG_NUM_MASK;

	raw_local_irq_save(flags);

	bgr = READ_BGR_REG();
	oldbgr = bgr;
	bgr.BGR_val = E2K_INITIAL_BGR_VAL;
	WRITE_BGR_REG_VALUE(AW(bgr));

	if ((ret = get_getsp_greg(greg_num, incr)))
		DebugUS("greg num %d, greg val 0x%x\n", greg_num, *incr);

	WRITE_BGR_REG_VALUE(AW(oldbgr));

	raw_local_irq_restore(flags);

	return ret;
}

static int parse_getsp_reg_operand(instr_src_t src2, const struct pt_regs *regs,
		int *incr, void __user **fault_addr)
{
	unsigned long ps_top = AS(regs->stacks.psp_lo).base + AS(regs->stacks.psp_hi).ind;
	unsigned long u_ps_top = ps_top - GET_PSHTP_MEM_INDEX(regs->stacks.pshtp);
	int ind_d, offset_d, ret;
	unsigned long raddr, flags;

	if (!src2.rt7) {
		/* Instruction set 6.3.1.1 */
		e2k_br_t br = { .word = AS(regs->crs.cr1_hi).br };
		int rnum_d = AW(src2) & ~0x80;
		ind_d = 2 * br.rbs + (2 * br.rcur + rnum_d) % br_rsz_full_d(br);
	} else {
		/* Instruction set 6.3.1.2 */
		ind_d = AW(src2) & ~0xc0;
	}

	offset_d = 2 * AS(regs->crs.cr1_lo).wbs - ind_d;
	raddr = ps_top - ((offset_d + 1) / 2) * 32;
	if (offset_d % 2)
		raddr += ((machine.native_iset_ver < E2K_ISET_V5) ? 8 : 16);
	if (raddr < PAGE_OFFSET && raddr >= u_ps_top)
		raddr += AS(current_thread_info()->k_psp_lo).base - u_ps_top;

	raw_all_irq_save(flags);
	COPY_STACKS_TO_MEMORY();
	raw_all_irq_restore(flags);
	ret = __get_user(*incr, (int __user *) raddr);
	if (ret)
		*fault_addr = (int __user *) raddr;
	return ret;
}

enum getsp_action parse_getsp_operation(const struct pt_regs *regs, int *incr,
		void __user **fault_addr)
{
	instr_syl_t __user *syl;
	instr_hs_t hs;
	instr_als_t als0 = { .word = 0 };
	instr_ales_t ales0 = { .word = 0 };
	instr_src_t src2;
	e2k_tir_hi_t tir_hi = { .word = regs->trap->TIR_hi };
	e2k_tir_lo_t tir_lo = { .word = regs->trap->TIR_lo };
	unsigned long trap_ip = tir_lo.TIR_lo_ip;
	int ret;

	*incr = USER_C_STACK_BYTE_INCR;

	DebugUS("started for IP 0x%lx, TIR_hi_al 0x%x\n", trap_ip, tir_hi.TIR_hi_al);
	if (!(tir_hi.TIR_hi_al & ALS0_mask)) {
		DebugUS("exception is not for ALS0\n");
		return GETSP_OP_FAIL;
	}

	syl = &E2K_GET_INSTR_HS(trap_ip);
	if (get_user(AW(hs), syl)) {
		*fault_addr = syl;
		return GETSP_OP_SIGSEGV;
	}
	if (!hs.al0) {
		DebugUS("missing ALS0 Syllable: 0x%08x\n", AW(hs));
		return GETSP_OP_FAIL;
	}

	syl = &E2K_GET_INSTR_ALS0(trap_ip, hs.s);
	if (get_user(AW(als0), syl)) {
		*fault_addr = syl;
		return GETSP_OP_SIGSEGV;
	}
	DebugUS("ALS0 syllable 0x%08x get from addr 0x%px\n", AW(als0), syl);

	if (als0.alf2.cop != GETSP_ALS_COP && als0.alf2.cop != DRTOAP_ALS_COP ||
			als0.alf2.cop == GETSP_ALS_COP && !hs.ale0 ||
			als0.alf2.opce != USD_ALS_OPCE) {
		DebugUS("ALS0 0x%x is neither GETSP nor GETSAP\n", AW(als0));
		return GETSP_OP_FAIL;
	}
	if (als0.alf2.opc == GETSP_ALS_COP) {
		instr_semisyl_t __user *half_syl = &E2K_GET_INSTR_ALES0(trap_ip, hs.mdl);
		if (get_user(AW(ales0), half_syl)) {
			*fault_addr = half_syl;
			return GETSP_OP_SIGSEGV;
		}
		DebugUS("ALES0 syllable 0x%04x get from addr 0x%px\n", AW(ales0), half_syl);
		if (ales0.alef2.opc2 != EXT_ALES_OPC2) {
			DebugUS("ALES0 opcode #2 0x%02x is not EXT, so it is not GETSP\n",
					ales0.alef2.opc2);
			return GETSP_OP_FAIL;
		}
	}

	AW(src2) = als0.alf2.src2;
	if ((als0.alf2.src2 & INSTR_SRC2_BIT_MASK) == INSTR_SRC2_16BIT_VALUE ||
	    (als0.alf2.src2 & INSTR_SRC2_BIT_MASK) == INSTR_SRC2_32BIT_VALUE) {
		ret = parse_getsp_literal_operand(trap_ip, hs, als0, incr, fault_addr);
	} else if ((als0.alf2.src2 & INSTR_SRC2_GREG_MASK) == INSTR_SRC2_GREG_VALUE) {
		ret = parse_getsp_greg_operand(als0, incr);
	} else if (!src2.rt7 || src2.rt7 && !src2.rt6) {
		ret = parse_getsp_reg_operand(src2, regs, incr, fault_addr);
	} else {
		ret = -EINVAL;
	}
	if (ret == -EFAULT) {
		return GETSP_OP_SIGSEGV;
	} else if (ret) {
		DebugUS("Parsing getsp operation at 0x%lx (HS 0x%x, ALS0 0x%x, ALES0 0x%hx) failed with %d",
				trap_ip, AW(hs), AW(als0), AW(ales0), ret);
		return GETSP_OP_FAIL;
	}

	if (*incr < 0) {
		*incr = round_up(-(*incr), PAGE_SIZE);
		*incr = max(USER_C_STACK_BYTE_INCR, (unsigned long)*incr);
		DebugUS("expand on %d bytes detected\n", *incr);
		return GETSP_OP_INCREMENT;
	}

	DebugUS("constrict on %d bytes detected\n", *incr);
	return GETSP_OP_DECREMENT;
}

