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
#include <asm/traps.h>

#include <asm-generic/bug.h>


#undef	DEBUG_US_EXPAND
#undef	DebugUS
#define	DEBUG_US_EXPAND		0	/* User stacks */
#define DebugUS(...)		DebugPrint(DEBUG_US_EXPAND ,##__VA_ARGS__)


static inline bool parse_getsp_literal_operand(e2k_addr_t trap_ip,
				instr_hs_t hs, instr_alsf2_t als0, int *incr)
{
	instr_syl_t	*lts;
	int		lts_num;
	int		lts_mask = 0;
	int		lts_shift = 0;
	bool		lts_sign_ext = false;

	lts_num = AS(als0).src2 & INSTR_SRC2_LTS_NUM_MASK;

	if ((AS(als0).src2 & INSTR_SRC2_BIT_MASK) == INSTR_SRC2_16BIT_VALUE) {
		BUG_ON(lts_num > 1);
		if (AS(als0).src2 & INSTR_SRC2_LTS_SHIFT_MASK) {
			lts_shift = INSTR_LTS_16BIT_SHIFT;
			lts_mask = INSTR_LTS_16BIT_SHIFT_MASK;
			lts_sign_ext = false;
		} else {
			lts_shift = INSTR_LTS_16BIT_NOSHIFT;
			lts_mask = INSTR_LTS_16BIT_NOSHIFT_MASK;
			lts_sign_ext = true;
		}
	} else if ((AS(als0).src2 & INSTR_SRC2_BIT_MASK) ==
			INSTR_SRC2_32BIT_VALUE) {
		lts_mask = INSTR_LTS_32BIT_MASK;
		lts_shift = INSTR_LTS_32BIT_SHIFT;
		lts_sign_ext = false;
	} else {
		DebugUS("not known literal operand\n");
		return false;
	}

	lts = &E2K_GET_INSTR_SYL(trap_ip, (AS(hs).lng + 1) * 2 - AS(hs).pl -
						AS(hs).cd - lts_num - 1);
	__get_user(*incr, lts);

	DebugUS("LTS%d=0x%x lng=%d pl=%d cd=%d lts_shift=0x%x lts_mask=0x%x\n",
		lts_num, *incr, AS(hs).lng, AS(hs).pl, AS(hs).cd,
		lts_shift, lts_mask);

	*incr = ((s32) ((*incr) & lts_mask)) >> lts_shift;
	if (lts_sign_ext)
		*incr = (((s32) *incr) << INSTR_LTS_16BIT_SHIFT) >>
							INSTR_LTS_16BIT_SHIFT;

	return true;
}

static inline bool get_getsp_greg(int greg_num, int *greg)
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
		return false;
	}

	if (tag) {
		DebugUS("Invalid tag 0x%x for greg num %d with greg val %u\n",
			tag, greg_num, gr);
		return false;
	}

	*greg = gr;

	return true;
}

static inline bool parse_getsp_greg_operand(instr_alsf2_t als0, int *incr,
					    bool *status)
{
	int		greg_num;
	e2k_bgr_t	bgr, oldbgr;
	unsigned long	flags;

	if ((AS(als0).src2 & INSTR_SRC2_GREG_MASK) != INSTR_SRC2_GREG_VALUE) {
		DebugUS("not greg operand\n");
		return false;
	}

	greg_num = AS(als0).src2 & INSTR_SRC2_GREG_NUM_MASK;

	raw_local_irq_save(flags);

	bgr = READ_BGR_REG();
	oldbgr = bgr;
	bgr.BGR_val = E2K_INITIAL_BGR_VAL;
	WRITE_BGR_REG_VALUE(AS_WORD(bgr));

	if (*status = get_getsp_greg(greg_num, incr))
		DebugUS("greg num %d, greg val 0x%x\n", greg_num, *incr);

	WRITE_BGR_REG_VALUE(AS_WORD(oldbgr));

	raw_local_irq_restore(flags);

	return true;
}

int parse_getsp_operation(struct trap_pt_regs *regs, int *incr)
{
	instr_hs_t hs;
	instr_alsf2_t als0;
	instr_alesf2_t ales0;
	instr_syl_t *user_sp;
	instr_semisyl_t *user_semisp;
	e2k_addr_t trap_ip;
	e2k_tir_hi_t tir_hi;
	e2k_tir_lo_t tir_lo;

	*incr = USER_C_STACK_BYTE_INCR;

	tir_lo.TIR_lo_reg = regs->TIR_lo;
	trap_ip = tir_lo.TIR_lo_ip;
	tir_hi.TIR_hi_reg = regs->TIR_hi;

	DebugUS("started for IP 0x%lx, TIR_hi_al 0x%x\n",
		trap_ip, tir_hi.TIR_hi_al);
	if (!(tir_hi.TIR_hi_al & ALS0_mask)) {
		DebugUS("exeption is not for ALS0\n");
		return GETSP_OP_IGNORE;
	}

	user_sp = &E2K_GET_INSTR_HS(trap_ip);
	__get_user(AS_WORD(hs), user_sp);
	if (!(AS_STRUCT(hs).al & ALS0_mask)) {
		DebugUS("command has not AL0 Syllable: 0x%08x\n", AW(hs));
		return GETSP_OP_IGNORE;
	}

	user_sp = &E2K_GET_INSTR_ALS0(trap_ip, (AS_STRUCT(hs).s));
	__get_user(AS_WORD(als0), user_sp);
	DebugUS("ALS0 syllable 0x%08x get from addr 0x%px\n", AW(als0), user_sp);
	if (AS_STRUCT(als0).cop == DRTOAP_ALS_COP &&
		AS_STRUCT(als0).opce == USD_ALS_OPCE &&
		!(AS_STRUCT(hs).ale & ALS0_mask)) {
		DebugUS("detected GETSAP operation: ALS0.cop 0x%02x opce 0x%02x\n",
			AS_STRUCT(als0).cop, AS_STRUCT(als0).opce);
		return GETSP_OP_INCREMENT;
	} else if (!(AS_STRUCT(hs).ale & ALS0_mask)) {
		DebugUS("command has not ALU0 extention syllable, so can not be GETSP\n");
		return GETSP_OP_IGNORE;
	} else if (AS_STRUCT(als0).opce != USD_ALS_OPCE) {
		DebugUS("command ALU0.opce 0x%x is not USD, so it can not be GETSP\n",
				AS(als0).opce);
		return GETSP_OP_IGNORE;
	}

	user_semisp = &E2K_GET_INSTR_ALES0(trap_ip, AS_STRUCT(hs).mdl);
	__get_user(AS_WORD(ales0), user_semisp);
	DebugUS("ALES0 syllable 0x%04x get from addr 0x%px\n",
			AS_WORD(ales0), user_semisp);
	if (AS_STRUCT(ales0).opc2 != EXT_ALES_OPC2) {
		DebugUS("ALES0 opcode #2 0x%02x is not EXT, so it is not GETSP\n",
				AS_STRUCT(ales0).opc2);
		return GETSP_OP_IGNORE;
	} else if (AS(als0).cop != GETSP_ALS_COP) {
		DebugUS("could not detect SP operation\n");
		return GETSP_OP_IGNORE;
	}
	DebugUS("detected GETSP operation: ALS0.cop 0x%02x\n", AS(als0).cop);

	if (!parse_getsp_literal_operand(trap_ip, hs, als0, incr)) {
		struct thread_info *ti = current_thread_info();
		bool status;

		if (!parse_getsp_greg_operand(als0, incr, &status)) {
			pr_info_ratelimited("'%s'(%d) has not literal or greg operand for getsp\n",
				current->comm, current->pid);

			*incr = max((unsigned long long)incr,
					(ti->u_stack.top - ti->u_stack.bottom) / 2);

			/*
			 * Don't use GETSP_OP_IGNORE for 2 reasons:
			 * 1. there are old programs with getsp operand in regs
			 * 2. case of stack underflow is very rare
			 */
			return GETSP_OP_INCREMENT;
		} else if (!status) {
			return GETSP_OP_IGNORE;
		}
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

