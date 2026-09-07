/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Templates for cBPF JIT compiler.
 */

#include <asm/asm-offsets.h>
#include <asm/alternative-asm.h>
#include <asm/trap_table.S.h>

#include "cbpf_jit.h"

/*
 * This file contains templates for cBPF JIT compiler.
 *
 * Refer to common assembler header for description what the templates are.
 */

/*
 *  Register assignment for cBPF jited program:
 *
 *  -----------------------------
 *  |     BPF argument (dr0)    |
 *  |    or return value (r0)   |
 *  -----------------------------
 *  |        Reg A (r4)         | <--- r_A
 *  -----------------------------
 *  |        Reg X (r5)         | <--- r_X
 *  -----------------------------
 *  |         TMP regs          | <--- r_TMP1
 *  |         (r6 - r7)         | <--- r_TMP2
 *  -----------------------------
 *  |                           | <--- r_MEM
 *  |       16 registers for    |
 *  |        scratch memory     |
 *  |         (if needed)       |
 *  |                           |
 *  -----------------------------
 *  |                           | <--- b[0]
 *  |       8 registers for     | <--- b[1]
 *  |       calling helpers     | <--- b[2]
 *  |         (if needed)       | <--- b[3]
 *  |                           |
 *  -----------------------------
 */

#define r_A r4
#define dr_A dr4
#define r_X r5
#define r_TMP1 r6
#define dr_TMP1 dr6
#define dr_TMP2 dr7
#define r_MEM r8

/*
 * If cBPF program need a helper call in one of its templates, then we must
 * reserve some stack space for call parameters that are passed via registers.
 * There are three possible functions that can be called from jited cBPF
 * program: skb_copy_bits(), bpf_internal_load_pointer_neg_helper() and
 * skb_get_poff(). All of them have `MAX_ARGS_NUM' or less parameters, so we
 * need not reserve more than MAX_ARGS_NUM * 8 bytes. In addition to space
 * reserved for call parameters, jited cBPF program may need 4 bytes to provide
 * a destination buffer for skb_copy_bits().
 *
 * Allocating stack frame is a cheap operation, so we will allocate `STK_SIZE'
 * bytes regardless of whether cBPF program requires helper calls or not.
 */
#define MAX_ARGS_NUM 4
#define STK_SIZE (MAX_ARGS_NUM * 8 + 4)

/*
 * CPU_HWBUG_JUMP: as HW bug 146897 workaround is implemented by JIT,
 * the templates in this file need no workaround. This assembler
 * directive turns the workaround off.
 */
#if __iset__ <= 6
.fix_lcc_bug149113
#endif

/*
 * This file contains only templates. They are copied by JIT to another
 * location before being executed. So mark all templates as read-only.
 */
.section .rodata

/* Template for prologue */
SYM_FUNC_START_SIZED(cbpf_jit_prologue)
BPF_TEMPL_LABEL(BPF_JIT_WSZ_LABEL(cbpf_jit_prologue))
BPF_TEMPL_LABEL(BPF_JIT_RBS_LABEL(cbpf_jit_prologue))
{
	getsp,0 -STK_SIZE, %dr_TMP2
	setwd wsz = 0x4, nfx = 0x1
	setbn rsz = 0x3, rbs = 0x4, rcur = 0x0
	adds,1 0x0, 0x0, %r_A
	adds,2 0x0, 0x0, %r_X
}
SYM_FUNC_END_SIZED(cbpf_jit_prologue)


/* Templates for 'add' commands */
SYM_FUNC_START_SIZED(cbpf_jit_alu_add_x)
{
	adds,0 %r_A, %r_X, %r_A
}
SYM_FUNC_END_SIZED(cbpf_jit_alu_add_x)

SYM_FUNC_START_SIZED(cbpf_jit_alu_add_k)
BPF_TEMPL_LABEL(BPF_JIT_K_LABEL(cbpf_jit_alu_add_k))
{
	adds,0 %r_A, _f32s,_lts0 0x0, %r_A
}
SYM_FUNC_END_SIZED(cbpf_jit_alu_add_k)


/* Templates for 'sub' commands */
SYM_FUNC_START_SIZED(cbpf_jit_alu_sub_x)
{
	subs,0 %r_A, %r_X, %r_A
}
SYM_FUNC_END_SIZED(cbpf_jit_alu_sub_x)

SYM_FUNC_START_SIZED(cbpf_jit_alu_sub_k)
BPF_TEMPL_LABEL(BPF_JIT_K_LABEL(cbpf_jit_alu_sub_k))
{
	subs,0 %r_A, _f32s,_lts0 0x0, %r_A
}
SYM_FUNC_END_SIZED(cbpf_jit_alu_sub_k)


/* Templates for 'and' commands */
SYM_FUNC_START_SIZED(cbpf_jit_alu_and_x)
{
	ands,0 %r_A, %r_X, %r_A
}
SYM_FUNC_END_SIZED(cbpf_jit_alu_and_x)

SYM_FUNC_START_SIZED(cbpf_jit_alu_and_k)
BPF_TEMPL_LABEL(BPF_JIT_K_LABEL(cbpf_jit_alu_and_k))
{
	ands,0 %r_A, _f32s,_lts0 0x0, %r_A
}
SYM_FUNC_END_SIZED(cbpf_jit_alu_and_k)


/* Templates for 'or' commands */
SYM_FUNC_START_SIZED(cbpf_jit_alu_or_x)
{
	ors,0 %r_A, %r_X, %r_A
}
SYM_FUNC_END_SIZED(cbpf_jit_alu_or_x)

SYM_FUNC_START_SIZED(cbpf_jit_alu_or_k)
BPF_TEMPL_LABEL(BPF_JIT_K_LABEL(cbpf_jit_alu_or_k))
{
	ors,0 %r_A, _f32s,_lts0 0x0, %r_A
}
SYM_FUNC_END_SIZED(cbpf_jit_alu_or_k)


/* Templates for 'xor' commands */
SYM_FUNC_START_SIZED(cbpf_jit_alu_xor_x)
{
	xors,0 %r_A, %r_X, %r_A
}
SYM_FUNC_END_SIZED(cbpf_jit_alu_xor_x)

SYM_FUNC_START_SIZED(cbpf_jit_alu_xor_k)
BPF_TEMPL_LABEL(BPF_JIT_K_LABEL(cbpf_jit_alu_xor_k))
{
	xors,0 %r_A, _f32s,_lts0 0x0, %r_A
}
SYM_FUNC_END_SIZED(cbpf_jit_alu_xor_k)


/* Templates for 'shl' commands */
SYM_FUNC_START_SIZED(cbpf_jit_alu_shl_x)
{
	shls,0 %r_A, %r_X, %r_A
}
SYM_FUNC_END_SIZED(cbpf_jit_alu_shl_x)

SYM_FUNC_START_SIZED(cbpf_jit_alu_shl_k)
BPF_TEMPL_LABEL(BPF_JIT_K_LABEL(cbpf_jit_alu_shl_k))
{
	shls,0 %r_A, _f32s,_lts0 0x0, %r_A
}
SYM_FUNC_END_SIZED(cbpf_jit_alu_shl_k)


/* Templates for 'shr' commands */
SYM_FUNC_START_SIZED(cbpf_jit_alu_shr_x)
{
	shrs,0 %r_A, %r_X, %r_A
}
SYM_FUNC_END_SIZED(cbpf_jit_alu_shr_x)

SYM_FUNC_START_SIZED(cbpf_jit_alu_shr_k)
BPF_TEMPL_LABEL(BPF_JIT_K_LABEL(cbpf_jit_alu_shr_k))
{
	shrs,0 %r_A, _f32s,_lts0 0x0, %r_A
}
SYM_FUNC_END_SIZED(cbpf_jit_alu_shr_k)


/* Templates for 'mul' commands */
SYM_FUNC_START_SIZED(cbpf_jit_alu_mul_x)
{
	muls,0 %r_A, %r_X, %r_A
}
SYM_FUNC_END_SIZED(cbpf_jit_alu_mul_x)

SYM_FUNC_START_SIZED(cbpf_jit_alu_mul_k)
BPF_TEMPL_LABEL(BPF_JIT_K_LABEL(cbpf_jit_alu_mul_k))
{
	muls,0 %r_A, _f32s,_lts0 0x0, %r_A
}
SYM_FUNC_END_SIZED(cbpf_jit_alu_mul_k)


/*
 * Templates for 'div' commands
 * BPF programm returns 0 if X is zero
 */
SYM_FUNC_START_SIZED(cbpf_jit_alu_div_x)
ALTERNATIVE_1_ALTINSTR
	{
		cmpesb,0 %r_X, 0x0, %pred0
		return %ctpr3
	}
	{
		nop 1
		udivs,5 %r_A, %r_X, %r_A ? ~ %pred0
	}
ALTERNATIVE_2_OLDINSTR
	{
		nop 1
		cmpesb,0 %r_X, 0x0, %pred0
		return %ctpr3
	}
	{
		udivs,5 %r_A, %r_X, %r_A ? ~ %pred0
	}
ALTERNATIVE_3_FEATURE(CPU_FEAT_ISET_V6)
{
	adds,0 0x0, 0x0, %r0 ? %pred0
	ct %ctpr3 ? %pred0
}
SYM_FUNC_END_SIZED(cbpf_jit_alu_div_x)

SYM_FUNC_START_SIZED(cbpf_jit_alu_div_k)
BPF_TEMPL_LABEL(BPF_JIT_K_LABEL(cbpf_jit_alu_div_k))
{
	udivs,5 %r_A, _f32s,_lts0 0x0, %r_A
}
SYM_FUNC_END_SIZED(cbpf_jit_alu_div_k)


/*
 * Templates for 'mod' commands
 * BPF programm returns 0 if X is zero
 */
SYM_FUNC_START_SIZED(cbpf_jit_alu_mod_x)
ALTERNATIVE_1_ALTINSTR
	{
		cmpesb,0 %r_X, 0x0, %pred0
		return %ctpr3
	}
	{
		sxt,5 0x6, %r_A, %dr_A ? ~ %pred0
	}
	{
		nop 1
		umodx,5 %dr_A, %r_X, %r_A ? ~ %pred0
	}
	{
		adds,0 0x0, 0x0, %r0 ? %pred0
		ct %ctpr3 ? %pred0
	}
ALTERNATIVE_2_ALTINSTR2
	{
		cmpesb,0 %r_X, 0x0, %pred0
		return %ctpr3
	}
	{
		sxt,5 0x6, %r_A, %dr_A ? ~ %pred0
	}
	{
		umodx,5 %dr_A, %r_X, %r_A ? ~ %pred0
	}
	{
		adds,0 0x0, 0x0, %r0 ? %pred0
		ct %ctpr3 ? %pred0
	}
ALTERNATIVE_3_OLDINSTR2
	{
		nop 1
		cmpesb,0 %r_X, 0x0, %pred0
		return %ctpr3
	}
	{
		sxt,5 0x6, %r_A, %dr_A ? ~ %pred0
	}
	{
		umodx,5 %dr_A, %r_X, %r_A ? ~ %pred0
		adds,0 0x0, 0x0, %r0 ? %pred0
		ct %ctpr3 ? %pred0
	}
ALTERNATIVE_4_FEATURE2(CPU_FEAT_ISET_V7, CPU_FEAT_ISET_V6)
SYM_FUNC_END_SIZED(cbpf_jit_alu_mod_x)

SYM_FUNC_START_SIZED(cbpf_jit_alu_mod_k)
{
	sxt,5 0x6, %r_A, %dr_A
}
BPF_TEMPL_LABEL(BPF_JIT_K_LABEL(cbpf_jit_alu_mod_k))
{
	umodx,5 %dr_A, _f32s,_lts0 0x0, %r_A
}
SYM_FUNC_END_SIZED(cbpf_jit_alu_mod_k)


/* Template for sign change of register A */
SYM_FUNC_START_SIZED(cbpf_jit_alu_neg)
{
	subs,0 0x0, %r_A, %r_A
}
SYM_FUNC_END_SIZED(cbpf_jit_alu_neg)


/* Templates for moving values between A and X */
SYM_FUNC_START_SIZED(cbpf_jit_misc_txa)
{
	adds,0 0x0, %r_X, %r_A
}
SYM_FUNC_END_SIZED(cbpf_jit_misc_txa)

SYM_FUNC_START_SIZED(cbpf_jit_misc_tax)
{
	adds,0 0x0, %r_A, %r_X
}
SYM_FUNC_END_SIZED(cbpf_jit_misc_tax)


/* Templates for return from BPF programs */
SYM_FUNC_START_SIZED(cbpf_jit_ret_a)
{
	nop 5
	adds,0 0x0, %r_A, %r0
	return %ctpr3
}
{
	ct %ctpr3
}
SYM_FUNC_END_SIZED(cbpf_jit_ret_a)

SYM_FUNC_START_SIZED(cbpf_jit_ret_k)
BPF_TEMPL_LABEL(BPF_JIT_K_LABEL(cbpf_jit_ret_k))
{
	nop 5
	adds,0 0x0, _f32s,_lts0 0x0, %r0
	return %ctpr3
}
{
	ct %ctpr3
}
SYM_FUNC_END_SIZED(cbpf_jit_ret_k)


/*
 * Templates for loading and storing
 * to and from BPF scratch memory
 */
SYM_FUNC_START_SIZED(cbpf_jit_ld_mem)
BPF_TEMPL_LABEL(BPF_JIT_MEM_SRC_LABEL(cbpf_jit_ld_mem))
{
	adds,0 0x0, %r_MEM, %r_A
}
SYM_FUNC_END_SIZED(cbpf_jit_ld_mem)

SYM_FUNC_START_SIZED(cbpf_jit_ldx_mem)
BPF_TEMPL_LABEL(BPF_JIT_MEM_SRC_LABEL(cbpf_jit_ldx_mem))
{
	adds,0 0x0, %r_MEM, %r_X
}
SYM_FUNC_END_SIZED(cbpf_jit_ldx_mem)

SYM_FUNC_START_SIZED(cbpf_jit_st)
BPF_TEMPL_LABEL(BPF_JIT_MEM_DST_LABEL(cbpf_jit_st))
{
	adds,0 0x0, %r_A, %r_MEM
}
SYM_FUNC_END_SIZED(cbpf_jit_st)

SYM_FUNC_START_SIZED(cbpf_jit_stx)
BPF_TEMPL_LABEL(BPF_JIT_MEM_DST_LABEL(cbpf_jit_stx))
{
	adds,0 0x0, %r_X, %r_MEM
}
SYM_FUNC_END_SIZED(cbpf_jit_stx)


/* Templates for loading values to A and X */
SYM_FUNC_START_SIZED(cbpf_jit_ld_imm)
BPF_TEMPL_LABEL(BPF_JIT_K_LABEL(cbpf_jit_ld_imm))
{
	adds,0 0x0, _f32s,_lts0 0x0, %r_A
}
SYM_FUNC_END_SIZED(cbpf_jit_ld_imm)

SYM_FUNC_START_SIZED(cbpf_jit_ldx_imm)
BPF_TEMPL_LABEL(BPF_JIT_K_LABEL(cbpf_jit_ldx_imm))
{
	adds,0 0x0, _f32s,_lts0 0x0, %r_X
}
SYM_FUNC_END_SIZED(cbpf_jit_ldx_imm)

SYM_FUNC_START_SIZED(cbpf_jit_ld_w_len)
ALTERNATIVE_1_ALTINSTR
	{
		nop 4
		ldw,0 [ %dr0 + _f32s,_lts0 SKB_LEN ], %r_A
	}
ALTERNATIVE_2_OLDINSTR
	{
		nop 2
		ldw,0 [ %dr0 + _f32s,_lts0 SKB_LEN ], %r_A
	}
ALTERNATIVE_3_FEATURE(CPU_FEAT_ISET_V6)
SYM_FUNC_END_SIZED(cbpf_jit_ld_w_len)

SYM_FUNC_START_SIZED(cbpf_jit_ldx_w_len)
ALTERNATIVE_1_ALTINSTR
	{
		nop 4
		ldw,0 [ %dr0 + _f32s,_lts0 SKB_LEN ], %r_X
	}
ALTERNATIVE_2_OLDINSTR
	{
		nop 2
		ldw,0 [ %dr0 + _f32s,_lts0 SKB_LEN ], %r_X
	}
ALTERNATIVE_3_FEATURE(CPU_FEAT_ISET_V6)
SYM_FUNC_END_SIZED(cbpf_jit_ldx_w_len)

SYM_FUNC_START_SIZED(cbpf_jit_ldx_b_msh_neg_k)
BPF_TEMPL_LABEL(BPF_JIT_FUNC_LABEL(cbpf_jit_ldx_b_msh_neg_k, bpf_internal_load_pointer_neg_helper))
BPF_TEMPL_LABEL(BPF_JIT_K_LABEL(cbpf_jit_ldx_b_msh_neg_k))
{
	nop 4
	addd,0 %dr0, 0x0, %db[0]
	adds,1 0x0, _f32s,_lts0 0x0, %b[1]
	adds,2 0x0, 0x1, %b[2]
	disp %ctpr1, $cbpf_jit_ldx_b_msh_neg_k
}
BPF_TEMPL_LABEL(BPF_JIT_WBS_LABEL(cbpf_jit_ldx_b_msh_neg_k, bpf_internal_load_pointer_neg_helper))
{
	call %ctpr1, wbs = 0x0
}
ALTERNATIVE_1_ALTINSTR
	{
		cmpedb,0 %db[0], 0x0, %pred0
		return %ctpr3
	}
	{
		nop 2
		ldb,0 [ 0x0 + %db[0] ], %r_TMP1 ? ~ %pred0
	}
ALTERNATIVE_2_OLDINSTR
	{
		nop 1
		cmpedb,0 %db[0], 0x0, %pred0
		return %ctpr3
	}
	{
		ldb,0 [ 0x0 + %db[0] ], %r_TMP1 ? ~ %pred0
	}
ALTERNATIVE_3_FEATURE(CPU_FEAT_ISET_V6)
{
	nop 1
	adds,1 0x0, 0x0, %r0 ? %pred0
	ct %ctpr3 ? %pred0
}
{
	ands,0 %r_TMP1, 0xf, %r_TMP1
}
{
	shls,0 %r_TMP1, 0x2, %r_X
}
SYM_FUNC_END_SIZED(cbpf_jit_ldx_b_msh_neg_k)

SYM_FUNC_START_SIZED(cbpf_jit_ldx_b_msh_pos_k)
BPF_TEMPL_LABEL(BPF_JIT_FUNC_LABEL(cbpf_jit_ldx_b_msh_pos_k, skb_copy_bits))
BPF_TEMPL_LABEL(BPF_JIT_K_LABEL(cbpf_jit_ldx_b_msh_pos_k))
{
	adds,0 0x0, _f32s,_lts0 0x0, %b[1]
	disp %ctpr1, $cbpf_jit_ldx_b_msh_pos_k
}
{
	nop 3
	addd,0 %dr0, 0x0, %db[0]
	addd,1 0x0, %dr_TMP2, %db[2]
	adds,2 0x0, 0x1, %b[3]
}
BPF_TEMPL_LABEL(BPF_JIT_WBS_LABEL(cbpf_jit_ldx_b_msh_pos_k, skb_copy_bits))
{
	call %ctpr1, wbs = 0x0
}
ALTERNATIVE_1_ALTINSTR
	{
		cmpedb,0 %db[0], 0x0, %pred0
		return %ctpr3
	}
	{
		nop 2
		ldb,0 [ 0x0 + %dr_TMP2 ], %r_TMP1 ? %pred0
	}
ALTERNATIVE_2_OLDINSTR
	{
		nop 1
		cmpedb,0 %db[0], 0x0, %pred0
		return %ctpr3
	}
	{
		ldb,0 [ 0x0 + %dr_TMP2 ], %r_TMP1 ? %pred0
	}
ALTERNATIVE_3_FEATURE(CPU_FEAT_ISET_V6)
{
	nop 1
	adds,1 0x0, 0x0, %r0 ? ~ %pred0
	ct %ctpr3 ? ~ %pred0
}
{
	ands,0 %r_TMP1, 0xf, %r_TMP1
}
{
	shls,0 %r_TMP1, 0x2, %r_X
}
SYM_FUNC_END_SIZED(cbpf_jit_ldx_b_msh_pos_k)

SYM_FUNC_START_SIZED(cbpf_jit_ld_w_abs_neg_k)
BPF_TEMPL_LABEL(BPF_JIT_FUNC_LABEL(cbpf_jit_ld_w_abs_neg_k, bpf_internal_load_pointer_neg_helper))
BPF_TEMPL_LABEL(BPF_JIT_K_LABEL(cbpf_jit_ld_w_abs_neg_k))
{
	nop 4
	addd,0 %dr0, 0x0, %db[0]
	adds,1 0x0, _f32s,_lts0 0x0, %b[1]
	adds,2 0x0, 0x4, %b[2]
	disp %ctpr1, $cbpf_jit_ld_w_abs_neg_k
}
BPF_TEMPL_LABEL(BPF_JIT_WBS_LABEL(cbpf_jit_ld_w_abs_neg_k, bpf_internal_load_pointer_neg_helper))
{
	call %ctpr1, wbs = 0x0
}
ALTERNATIVE_1_ALTINSTR
	{
		cmpedb,0 %db[0], 0x0, %pred0
		return %ctpr3
	}
	{
		nop 2
		ldw,0 [ 0x0 + %db[0] ], %r_A ? ~ %pred0
	}
ALTERNATIVE_2_OLDINSTR
	{
		nop 1
		cmpedb,0 %db[0], 0x0, %pred0
		return %ctpr3
	}
	{
		ldw,0 [ 0x0 + %db[0] ], %r_A ? ~ %pred0
	}
ALTERNATIVE_3_FEATURE(CPU_FEAT_ISET_V6)
{
	nop 1
	adds,1 0x0, 0x0, %r0 ? %pred0
	ct %ctpr3 ? %pred0
}
/* swap bytes from BE to LE */
{
	addd,0 0x0, _f64,_lts0 0x8080808000010203, %dr_TMP1
	sxt,1 0x6, %r_A, %dr_A
}
{
	nop 3
	pshufb,0 %dr_A, %dr_A, %dr_TMP1, %dr_A
}
SYM_FUNC_END_SIZED(cbpf_jit_ld_w_abs_neg_k)

SYM_FUNC_START_SIZED(cbpf_jit_ld_w_abs_pos_k)
BPF_TEMPL_LABEL(BPF_JIT_FUNC_LABEL(cbpf_jit_ld_w_abs_pos_k, skb_copy_bits))
BPF_TEMPL_LABEL(BPF_JIT_K_LABEL(cbpf_jit_ld_w_abs_pos_k))
{
	adds,0 0x0, _f32s,_lts0 0x0, %b[1]
	disp %ctpr1, $cbpf_jit_ld_w_abs_pos_k
}
{
	nop 3
	addd,0 %dr0, 0x0, %db[0]
	addd,1 0x0, %dr_TMP2, %db[2]
	adds,2 0x0, 0x4, %b[3]
}
BPF_TEMPL_LABEL(BPF_JIT_WBS_LABEL(cbpf_jit_ld_w_abs_pos_k, skb_copy_bits))
{
	call %ctpr1, wbs = 0x0
}
ALTERNATIVE_1_ALTINSTR
	{
		cmpedb,0 %db[0], 0x0, %pred0
		return %ctpr3
	}
	{
		nop 2
		ldw,0 [ 0x0 + %dr_TMP2 ], mas = 0x8, %r_A ? %pred0
	}
ALTERNATIVE_2_OLDINSTR
	{
		nop 1
		cmpedb,0 %db[0], 0x0, %pred0
		return %ctpr3
	}
	{
		ldw,0 [ 0x0 + %dr_TMP2 ], mas = 0x8, %r_A ? %pred0
	}
ALTERNATIVE_3_FEATURE(CPU_FEAT_ISET_V6)
{
	nop 1
	adds,1 0x0, 0x0, %r0 ? ~ %pred0
	ct %ctpr3 ? ~ %pred0
}
SYM_FUNC_END_SIZED(cbpf_jit_ld_w_abs_pos_k)

SYM_FUNC_START_SIZED(cbpf_jit_ld_h_abs_neg_k)
BPF_TEMPL_LABEL(BPF_JIT_FUNC_LABEL(cbpf_jit_ld_h_abs_neg_k, bpf_internal_load_pointer_neg_helper))
BPF_TEMPL_LABEL(BPF_JIT_K_LABEL(cbpf_jit_ld_h_abs_neg_k))
{
	nop 4
	addd,0 %dr0, 0x0, %db[0]
	adds,1 0x0, _f32s,_lts0 0x0, %b[1]
	adds,2 0x0, 0x2, %b[2]
	disp %ctpr1, $cbpf_jit_ld_h_abs_neg_k
}
BPF_TEMPL_LABEL(BPF_JIT_WBS_LABEL(cbpf_jit_ld_h_abs_neg_k, bpf_internal_load_pointer_neg_helper))
{
	call %ctpr1, wbs = 0x0
}
ALTERNATIVE_1_ALTINSTR
	{
		cmpedb,0 %db[0], 0x0, %pred0
		return %ctpr3
	}
	{
		nop 2
		ldh,0 [ 0x0 + %db[0] ], %r_A ? ~ %pred0
	}
ALTERNATIVE_2_OLDINSTR
	{
		nop 1
		cmpedb,0 %db[0], 0x0, %pred0
		return %ctpr3
	}
	{
		ldh,0 [ 0x0 + %db[0] ], %r_A ? ~ %pred0
	}
ALTERNATIVE_3_FEATURE(CPU_FEAT_ISET_V6)
{
	nop 1
	adds,1 0x0, 0x0, %r0 ? %pred0
	ct %ctpr3 ? %pred0
}
/* swap bytes from BE to LE */
{
	addd,0 0x0, _f64,_lts0 0x8080808080800001, %dr_TMP1
	sxt,1 0x6, %r_A, %dr_A
}
{
	nop 3
	pshufb,0 %dr_A, %dr_A, %dr_TMP1, %dr_A
}
SYM_FUNC_END_SIZED(cbpf_jit_ld_h_abs_neg_k)

SYM_FUNC_START_SIZED(cbpf_jit_ld_h_abs_pos_k)
BPF_TEMPL_LABEL(BPF_JIT_FUNC_LABEL(cbpf_jit_ld_h_abs_pos_k, skb_copy_bits))
BPF_TEMPL_LABEL(BPF_JIT_K_LABEL(cbpf_jit_ld_h_abs_pos_k))
{
	adds,0 0x0, _f32s,_lts0 0x0, %b[1]
	disp %ctpr1, $cbpf_jit_ld_h_abs_pos_k
}
{
	nop 3
	addd,0 %dr0, 0x0, %db[0]
	addd,1 0x0, %dr_TMP2, %db[2]
	adds,2 0x0, 0x2, %b[3]
}
BPF_TEMPL_LABEL(BPF_JIT_WBS_LABEL(cbpf_jit_ld_h_abs_pos_k, skb_copy_bits))
{
	call %ctpr1, wbs = 0x0
}
ALTERNATIVE_1_ALTINSTR
	{
		cmpedb,0 %db[0], 0x0, %pred0
		return %ctpr3
	}
	{
		nop 2
		ldh,0 [ 0x0 + %dr_TMP2 ], mas = 0x8, %r_A ? %pred0
	}
ALTERNATIVE_2_OLDINSTR
	{
		nop 1
		cmpedb,0 %db[0], 0x0, %pred0
		return %ctpr3
	}
	{
		ldh,0 [ 0x0 + %dr_TMP2 ], mas = 0x8, %r_A ? %pred0
	}
ALTERNATIVE_3_FEATURE(CPU_FEAT_ISET_V6)
{
	nop 1
	adds,1 0x0, 0x0, %r0 ? ~ %pred0
	ct %ctpr3 ? ~ %pred0
}
SYM_FUNC_END_SIZED(cbpf_jit_ld_h_abs_pos_k)

SYM_FUNC_START_SIZED(cbpf_jit_ld_b_abs_neg_k)
BPF_TEMPL_LABEL(BPF_JIT_FUNC_LABEL(cbpf_jit_ld_b_abs_neg_k, bpf_internal_load_pointer_neg_helper))
BPF_TEMPL_LABEL(BPF_JIT_K_LABEL(cbpf_jit_ld_b_abs_neg_k))
{
	nop 4
	addd,0 %dr0, 0x0, %db[0]
	adds,1 0x0, _f32s,_lts0 0x0, %b[1]
	adds,2 0x0, 0x1, %b[2]
	disp %ctpr1, $cbpf_jit_ld_b_abs_neg_k
}
BPF_TEMPL_LABEL(BPF_JIT_WBS_LABEL(cbpf_jit_ld_b_abs_neg_k, bpf_internal_load_pointer_neg_helper))
{
	call %ctpr1, wbs = 0x0
}
ALTERNATIVE_1_ALTINSTR
	{
		cmpedb,0 %db[0], 0x0, %pred0
		return %ctpr3
	}
	{
		nop 2
		ldb,0 [ 0x0 + %db[0] ], %r_A ? ~ %pred0
	}
ALTERNATIVE_2_OLDINSTR
	{
		nop 1
		cmpedb,0 %db[0], 0x0, %pred0
		return %ctpr3
	}
	{
		ldb,0 [ 0x0 + %db[0] ], %r_A ? ~ %pred0
	}
ALTERNATIVE_3_FEATURE(CPU_FEAT_ISET_V6)
{
	nop 1
	adds,1 0x0, 0x0, %r0 ? %pred0
	ct %ctpr3 ? %pred0
}
SYM_FUNC_END_SIZED(cbpf_jit_ld_b_abs_neg_k)

SYM_FUNC_START_SIZED(cbpf_jit_ld_b_abs_pos_k)
BPF_TEMPL_LABEL(BPF_JIT_FUNC_LABEL(cbpf_jit_ld_b_abs_pos_k, skb_copy_bits))
BPF_TEMPL_LABEL(BPF_JIT_K_LABEL(cbpf_jit_ld_b_abs_pos_k))
{
	adds,0 0x0, _f32s,_lts0 0x0, %b[1]
	disp %ctpr1, $cbpf_jit_ld_b_abs_pos_k
}
{
	nop 3
	addd,0 %dr0, 0x0, %db[0]
	addd,1 0x0, %dr_TMP2, %db[2]
	adds,2 0x0, 0x1, %b[3]
}
BPF_TEMPL_LABEL(BPF_JIT_WBS_LABEL(cbpf_jit_ld_b_abs_pos_k, skb_copy_bits))
{
	call %ctpr1, wbs = 0x0
}
ALTERNATIVE_1_ALTINSTR
	{
		cmpedb,0 %db[0], 0x0, %pred0
		return %ctpr3
	}
	{
		nop 2
		ldb,0 [ 0x0 + %dr_TMP2 ], %r_A ? %pred0
	}
ALTERNATIVE_2_OLDINSTR
	{
		nop 1
		cmpedb,0 %db[0], 0x0, %pred0
		return %ctpr3
	}
	{
		ldb,0 [ 0x0 + %dr_TMP2 ], %r_A ? %pred0
	}
ALTERNATIVE_3_FEATURE(CPU_FEAT_ISET_V6)
{
	nop 1
	adds,1 0x0, 0x0, %r0 ? ~ %pred0
	ct %ctpr3 ? ~ %pred0
}
SYM_FUNC_END_SIZED(cbpf_jit_ld_b_abs_pos_k)

SYM_FUNC_START_SIZED(cbpf_jit_ld_w_ind)
BPF_TEMPL_LABEL(BPF_JIT_K_LABEL(cbpf_jit_ld_w_ind))
BPF_TEMPL_LABEL(BPF_JIT_FUNC_LABEL(cbpf_jit_ld_w_ind, skb_copy_bits))
{
	adds,0 %r_X, _f32s,_lts0 0x0, %r_TMP1
	disp %ctpr1, $cbpf_jit_ld_w_ind
}
BPF_TEMPL_LABEL(BPF_JIT_FUNC_LABEL(cbpf_jit_ld_w_ind, bpf_internal_load_pointer_neg_helper))
{
	nop 1
	cmplsb,0 %r_TMP1, 0x0, %pred0
	addd,1 0x0, %dr0, %db[0]
	adds,2 0x0, %r_TMP1, %b[1]
	disp %ctpr2, $cbpf_jit_ld_w_ind
}
{
	nop 1
	addd,0 0x0, %dr_TMP2, %db[2] ? ~ %pred0
	adds,1 0x0, 0x4, %b[3] ? ~ %pred0
	adds,2 0x0, 0x4, %b[2] ? %pred0
}
BPF_TEMPL_LABEL(BPF_JIT_WBS_LABEL(cbpf_jit_ld_w_ind, skb_copy_bits))
{
	call %ctpr1, wbs = 0x0 ? ~ %pred0
}
BPF_TEMPL_LABEL(BPF_JIT_WBS_LABEL(cbpf_jit_ld_w_ind, bpf_internal_load_pointer_neg_helper))
{
	sxt,0 0x6, %b[0], %db[0] ? ~ %pred0
	call %ctpr2, wbs = 0x0 ? %pred0
}
{
	cmpedb %db[0], 0x0, %pred1
	return %ctpr3
}
ALTERNATIVE_1_ALTINSTR
	{
		pass %pred0, @p0
		pass %pred1, @p1
		andp @p0, ~@p1, @p4
		andp @p0, @p1, @p5
		andp ~@p0, ~@p1, @p6
		pass @p4, %pred2
		pass @p5, %pred4
		pass @p6, %pred3
	}
	{
		nop 3
		ldw,0 [ 0x0 + %dr_TMP2 ], %r_A ? ~ %pred2
		ldw,2 [ 0x0 + %db[0] ], %r_A ? %pred2
		pass %pred3, @p0
		pass %pred4, @p1
		andp ~@p0, ~@p1, @p4
		pass @p4, %pred5
	}
ALTERNATIVE_2_OLDINSTR
	{
		nop 1
		pass %pred0, @p0
		pass %pred1, @p1
		andp @p0, ~@p1, @p4
		andp @p0, @p1, @p5
		andp ~@p0, ~@p1, @p6
		pass @p4, %pred2
		pass @p5, %pred4
		pass @p6, %pred3
	}
	{
		nop 1
		ldw,0 [ 0x0 + %dr_TMP2 ], %r_A ? ~ %pred2
		ldw,2 [ 0x0 + %db[0] ], %r_A ? %pred2
		pass %pred3, @p0
		pass %pred4, @p1
		andp ~@p0, ~@p1, @p4
		pass @p4, %pred5
	}
ALTERNATIVE_3_FEATURE(CPU_FEAT_ISET_V6)
{
	adds,0 0x0, 0x0, %r0 ? ~ %pred5
	ct %ctpr3 ? ~ %pred5
}
/* swap bytes from BE to LE */
{
	addd,0 0x0, _f64,_lts0 0x8080808000010203, %dr_TMP1
	sxt,1 0x6, %r_A, %dr_A ? ~ %pred0
}
{
	nop 3
	pshufb,0 %dr_A, %dr_A, %dr_TMP1, %dr_A ? ~ %pred0
}
SYM_FUNC_END_SIZED(cbpf_jit_ld_w_ind)

SYM_FUNC_START_SIZED(cbpf_jit_ld_h_ind)
BPF_TEMPL_LABEL(BPF_JIT_K_LABEL(cbpf_jit_ld_h_ind))
BPF_TEMPL_LABEL(BPF_JIT_FUNC_LABEL(cbpf_jit_ld_h_ind, skb_copy_bits))
{
	adds,0 %r_X, _f32s,_lts0 0x0, %r_TMP1
	disp %ctpr1, $cbpf_jit_ld_h_ind
}
BPF_TEMPL_LABEL(BPF_JIT_FUNC_LABEL(cbpf_jit_ld_h_ind, bpf_internal_load_pointer_neg_helper))
{
	nop 1
	cmplsb,0 %r_TMP1, 0x0, %pred0
	addd,1 0x0, %dr0, %db[0]
	adds,2 0x0, %r_TMP1, %b[1]
	disp %ctpr2, $cbpf_jit_ld_h_ind
}
{
	nop 1
	addd,0 0x0, %dr_TMP2, %db[2] ? ~ %pred0
	adds,1 0x0, 0x2, %b[3] ? ~ %pred0
	adds,2 0x0, 0x2, %b[2] ? %pred0
}
BPF_TEMPL_LABEL(BPF_JIT_WBS_LABEL(cbpf_jit_ld_h_ind, skb_copy_bits))
{
	call %ctpr1, wbs = 0x0 ? ~ %pred0
}
BPF_TEMPL_LABEL(BPF_JIT_WBS_LABEL(cbpf_jit_ld_h_ind, bpf_internal_load_pointer_neg_helper))
{
	sxt,0 0x6, %b[0], %db[0] ? ~ %pred0
	call %ctpr2, wbs = 0x0 ? %pred0
}
{
	cmpedb %db[0], 0x0, %pred1
	return %ctpr3
}
ALTERNATIVE_1_ALTINSTR
	{
		pass %pred0, @p0
		pass %pred1, @p1
		andp @p0, ~@p1, @p4
		andp @p0, @p1, @p5
		andp ~@p0, ~@p1, @p6
		pass @p4, %pred2
		pass @p5, %pred4
		pass @p6, %pred3
	}
	{
		nop 3
		ldh,0 [ 0x0 + %dr_TMP2 ], %r_A ? ~ %pred2
		ldh,2 [ 0x0 + %db[0] ], %r_A ? %pred2
		pass %pred3, @p0
		pass %pred4, @p1
		andp ~@p0, ~@p1, @p4
		pass @p4, %pred5
	}
ALTERNATIVE_2_OLDINSTR
	{
		nop 1
		pass %pred0, @p0
		pass %pred1, @p1
		andp @p0, ~@p1, @p4
		andp @p0, @p1, @p5
		andp ~@p0, ~@p1, @p6
		pass @p4, %pred2
		pass @p5, %pred4
		pass @p6, %pred3
	}
	{
		nop 1
		ldh,0 [ 0x0 + %dr_TMP2 ], %r_A ? ~ %pred2
		ldh,2 [ 0x0 + %db[0] ], %r_A ? %pred2
		pass %pred3, @p0
		pass %pred4, @p1
		andp ~@p0, ~@p1, @p4
		pass @p4, %pred5
	}
ALTERNATIVE_3_FEATURE(CPU_FEAT_ISET_V6)
{
	adds,0 0x0, 0x0, %r0 ? ~ %pred5
	ct %ctpr3 ? ~ %pred5
}
/* swap bytes from BE to LE */
{
	addd,0 0x0, _f64,_lts0 0x8080808080800001, %dr_TMP1
	sxt,1 0x6, %r_A, %dr_A ? ~ %pred0
}
{
	nop 3
	pshufb,0 %dr_A, %dr_A, %dr_TMP1, %dr_A ? ~ %pred0
}
SYM_FUNC_END_SIZED(cbpf_jit_ld_h_ind)

SYM_FUNC_START_SIZED(cbpf_jit_ld_b_ind)
BPF_TEMPL_LABEL(BPF_JIT_K_LABEL(cbpf_jit_ld_b_ind))
BPF_TEMPL_LABEL(BPF_JIT_FUNC_LABEL(cbpf_jit_ld_b_ind, skb_copy_bits))
{
	adds,0 %r_X, _f32s,_lts0 0x0, %r_TMP1
	disp %ctpr1, $cbpf_jit_ld_b_ind
}
BPF_TEMPL_LABEL(BPF_JIT_FUNC_LABEL(cbpf_jit_ld_b_ind, bpf_internal_load_pointer_neg_helper))
{
	nop 1
	cmplsb,0 %r_TMP1, 0x0, %pred0
	addd,1 0x0, %dr0, %db[0]
	adds,2 0x0, %r_TMP1, %b[1]
	disp %ctpr2, $cbpf_jit_ld_b_ind
}
{
	nop 1
	addd,0 0x0, %dr_TMP2, %db[2] ? ~ %pred0
	adds,1 0x0, 0x1, %b[3] ? ~ %pred0
	adds,2 0x0, 0x1, %b[2] ? %pred0
}
BPF_TEMPL_LABEL(BPF_JIT_WBS_LABEL(cbpf_jit_ld_b_ind, skb_copy_bits))
{
	call %ctpr1, wbs = 0x0 ? ~ %pred0
}
BPF_TEMPL_LABEL(BPF_JIT_WBS_LABEL(cbpf_jit_ld_b_ind, bpf_internal_load_pointer_neg_helper))
{
	sxt,0 0x6, %b[0], %db[0] ? ~ %pred0
	call %ctpr2, wbs = 0x0 ? %pred0
}
{
	cmpedb %db[0], 0x0, %pred1
	return %ctpr3
}
ALTERNATIVE_1_ALTINSTR
	{
		pass %pred0, @p0
		pass %pred1, @p1
		andp @p0, ~@p1, @p4
		andp @p0, @p1, @p5
		andp ~@p0, ~@p1, @p6
		pass @p4, %pred2
		pass @p5, %pred4
		pass @p6, %pred3
	}
	{
		nop 3
		ldb,0 [ 0x0 + %dr_TMP2 ], %r_A ? ~ %pred2
		ldb,2 [ 0x0 + %db[0] ], %r_A ? %pred2
		pass %pred3, @p0
		pass %pred4, @p1
		andp ~@p0, ~@p1, @p4
		pass @p4, %pred5
	}
ALTERNATIVE_2_OLDINSTR
	{
		nop 1
		pass %pred0, @p0
		pass %pred1, @p1
		andp @p0, ~@p1, @p4
		andp @p0, @p1, @p5
		andp ~@p0, ~@p1, @p6
		pass @p4, %pred2
		pass @p5, %pred4
		pass @p6, %pred3
	}
	{
		nop 1
		ldb,0 [ 0x0 + %dr_TMP2 ], %r_A ? ~ %pred2
		ldb,2 [ 0x0 + %db[0] ], %r_A ? %pred2
		pass %pred3, @p0
		pass %pred4, @p1
		andp ~@p0, ~@p1, @p4
		pass @p4, %pred5
	}
ALTERNATIVE_3_FEATURE(CPU_FEAT_ISET_V6)
{
	adds,0 0x0, 0x0, %r0 ? ~ %pred5
	ct %ctpr3 ? ~ %pred5
}
SYM_FUNC_END_SIZED(cbpf_jit_ld_b_ind)


/* Templates for jump commands */
SYM_FUNC_START_SIZED(cbpf_jit_jmp_ja)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(cbpf_jit_jmp_ja, ja))
{
	nop 4
	disp %ctpr1, cbpf_jit_jmp_ja
}
{
	ct %ctpr1
}
SYM_FUNC_END_SIZED(cbpf_jit_jmp_ja)

SYM_FUNC_START_SIZED(cbpf_jit_jmp_jgt_x)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(cbpf_jit_jmp_jgt_x, jt))
{
	cmpbsb,0 %r_X, %r_A, %pred0
	disp %ctpr1, cbpf_jit_jmp_jgt_x
}
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(cbpf_jit_jmp_jgt_x, jf))
{
	nop 3
	disp %ctpr2, cbpf_jit_jmp_jgt_x
}
{
	ct %ctpr1 ? %pred0
}
{
	ct %ctpr2
}
SYM_FUNC_END_SIZED(cbpf_jit_jmp_jgt_x)

SYM_FUNC_START_SIZED(cbpf_jit_jmp_jgt_k)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(cbpf_jit_jmp_jgt_k, jt))
BPF_TEMPL_LABEL(BPF_JIT_K_LABEL(cbpf_jit_jmp_jgt_k))
{
	cmpbesb,0 %r_A, _f32s,_lts0 0x0, %pred0
	disp %ctpr1, cbpf_jit_jmp_jgt_k
}
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(cbpf_jit_jmp_jgt_k, jf))
{
	nop 3
	disp %ctpr2, cbpf_jit_jmp_jgt_k
}
{
	ct %ctpr1 ? ~ %pred0
}
{
	ct %ctpr2
}
SYM_FUNC_END_SIZED(cbpf_jit_jmp_jgt_k)

SYM_FUNC_START_SIZED(cbpf_jit_jmp_jge_x)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(cbpf_jit_jmp_jge_x, jt))
{
	cmpbesb,0 %r_X, %r_A, %pred0
	disp %ctpr1, cbpf_jit_jmp_jge_x
}
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(cbpf_jit_jmp_jge_x, jf))
{
	nop 3
	disp %ctpr2, cbpf_jit_jmp_jge_x
}
{
	ct %ctpr1 ? %pred0
}
{
	ct %ctpr2
}
SYM_FUNC_END_SIZED(cbpf_jit_jmp_jge_x)

SYM_FUNC_START_SIZED(cbpf_jit_jmp_jge_k)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(cbpf_jit_jmp_jge_k, jt))
BPF_TEMPL_LABEL(BPF_JIT_K_LABEL(cbpf_jit_jmp_jge_k))
{
	cmpbsb,0 %r_A, _f32s,_lts0 0x0, %pred0
	disp %ctpr1, cbpf_jit_jmp_jge_k
}
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(cbpf_jit_jmp_jge_k, jf))
{
	nop 3
	disp %ctpr2, cbpf_jit_jmp_jge_k
}
{
	ct %ctpr1 ? ~ %pred0
}
{
	ct %ctpr2
}
SYM_FUNC_END_SIZED(cbpf_jit_jmp_jge_k)

SYM_FUNC_START_SIZED(cbpf_jit_jmp_jeq_x)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(cbpf_jit_jmp_jeq_x, jt))
{
	cmpesb,0 %r_A, %r_X, %pred0
	disp %ctpr1, cbpf_jit_jmp_jeq_x
}
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(cbpf_jit_jmp_jeq_x, jf))
{
	nop 3
	disp %ctpr2, cbpf_jit_jmp_jeq_x
}
{
	ct %ctpr1 ? %pred0
}
{
	ct %ctpr2
}
SYM_FUNC_END_SIZED(cbpf_jit_jmp_jeq_x)

SYM_FUNC_START_SIZED(cbpf_jit_jmp_jeq_k)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(cbpf_jit_jmp_jeq_k, jt))
BPF_TEMPL_LABEL(BPF_JIT_K_LABEL(cbpf_jit_jmp_jeq_k))
{
	cmpesb,0 %r_A, _f32s,_lts0 0x0, %pred0
	disp %ctpr1, cbpf_jit_jmp_jeq_k
}
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(cbpf_jit_jmp_jeq_k, jf))
{
	nop 3
	disp %ctpr2, cbpf_jit_jmp_jeq_k
}
{
	ct %ctpr1 ? %pred0
}
{
	ct %ctpr2
}
SYM_FUNC_END_SIZED(cbpf_jit_jmp_jeq_k)

SYM_FUNC_START_SIZED(cbpf_jit_jmp_jset_x)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(cbpf_jit_jmp_jset_x, jt))
{
	ands,0 %r_A, %r_X, %r_TMP1
	disp %ctpr1, cbpf_jit_jmp_jset_x
}
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(cbpf_jit_jmp_jset_x, jf))
{
	nop 3
	cmpesb,0 %r_TMP1, 0x0, %pred0
	disp %ctpr2, cbpf_jit_jmp_jset_x
}
{
	ct %ctpr1 ? ~ %pred0
}
{
	ct %ctpr2
}
SYM_FUNC_END_SIZED(cbpf_jit_jmp_jset_x)

SYM_FUNC_START_SIZED(cbpf_jit_jmp_jset_k)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(cbpf_jit_jmp_jset_k, jt))
BPF_TEMPL_LABEL(BPF_JIT_K_LABEL(cbpf_jit_jmp_jset_k))
{
	ands,0 %r_A, _f32s,_lts0 0x0, %r_TMP1
	disp %ctpr1, cbpf_jit_jmp_jset_k
}
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(cbpf_jit_jmp_jset_k, jf))
{
	nop 3
	cmpesb,0 %r_TMP1, 0x0, %pred0
	disp %ctpr2, cbpf_jit_jmp_jset_k
}
{
	ct %ctpr1 ? ~ %pred0
}
{
	ct %ctpr2
}
SYM_FUNC_END_SIZED(cbpf_jit_jmp_jset_k)


/* Templates for BPF ancillary commands */
SYM_FUNC_START_SIZED(cbpf_jit_anc_mark)
ALTERNATIVE_1_ALTINSTR
	{
		nop 4
		ldw,0 [ %dr0 + _f32s,_lts0 SKB_MARK ], %r_A
	}
ALTERNATIVE_2_OLDINSTR
	{
		nop 2
		ldw,0 [ %dr0 + _f32s,_lts0 SKB_MARK ], %r_A
	}
ALTERNATIVE_3_FEATURE(CPU_FEAT_ISET_V6)
SYM_FUNC_END_SIZED(cbpf_jit_anc_mark)

SYM_FUNC_START_SIZED(cbpf_jit_anc_rxhash)
ALTERNATIVE_1_ALTINSTR
	{
		nop 4
		ldw,0 [ %dr0 + _f32s,_lts0 SKB_HASH ], %r_A
	}
ALTERNATIVE_2_OLDINSTR
	{
		nop 2
		ldw,0 [ %dr0 + _f32s,_lts0 SKB_HASH ], %r_A
	}
ALTERNATIVE_3_FEATURE(CPU_FEAT_ISET_V6)
SYM_FUNC_END_SIZED(cbpf_jit_anc_rxhash)

SYM_FUNC_START_SIZED(cbpf_jit_anc_vlan_tag)
ALTERNATIVE_1_ALTINSTR
	{
		nop 4
		ldh,0 [ %dr0 + _f32s,_lts0 SKB_VLAN_TCI ], %r_A
	}
ALTERNATIVE_2_OLDINSTR
	{
		nop 2
		ldh,0 [ %dr0 + _f32s,_lts0 SKB_VLAN_TCI ], %r_A
	}
ALTERNATIVE_3_FEATURE(CPU_FEAT_ISET_V6)
SYM_FUNC_END_SIZED(cbpf_jit_anc_vlan_tag)

SYM_FUNC_START_SIZED(cbpf_jit_anc_queue)
ALTERNATIVE_1_ALTINSTR
	{
		nop 4
		ldh,0 [ %dr0 + _f32s,_lts0 SKB_QUEUE_MAPPING ], %r_A
	}
ALTERNATIVE_2_OLDINSTR
	{
		nop 2
		ldh,0 [ %dr0 + _f32s,_lts0 SKB_QUEUE_MAPPING ], %r_A
	}
ALTERNATIVE_3_FEATURE(CPU_FEAT_ISET_V6)
SYM_FUNC_END_SIZED(cbpf_jit_anc_queue)

SYM_FUNC_START_SIZED(cbpf_jit_anc_cpu)
{
	adds,0 GCPUID_PREEMPT, 0x0, %r_A
}
SYM_FUNC_END_SIZED(cbpf_jit_anc_cpu)

SYM_FUNC_START_SIZED(cbpf_jit_anc_protocol)
ALTERNATIVE_1_ALTINSTR
	{
		nop 4
		ldh,0 [ %dr0 + _f32s,_lts0 SKB_PROTOCOL ], mas = 0x8, %r_A
	}
ALTERNATIVE_2_OLDINSTR
	{
		nop 2
		ldh,0 [ %dr0 + _f32s,_lts0 SKB_PROTOCOL ], mas = 0x8, %r_A
	}
ALTERNATIVE_3_FEATURE(CPU_FEAT_ISET_V6)
SYM_FUNC_END_SIZED(cbpf_jit_anc_protocol)

SYM_FUNC_START_SIZED(cbpf_jit_anc_pkttype)
ALTERNATIVE_1_ALTINSTR
	{
		nop 4
		ldb,0 [ %dr0 + _f32s,_lts0 PKT_TYPE_OFFSET ], %r_A
	}
ALTERNATIVE_2_OLDINSTR
	{
		nop 2
		ldb,0 [ %dr0 + _f32s,_lts0 PKT_TYPE_OFFSET ], %r_A
	}
ALTERNATIVE_3_FEATURE(CPU_FEAT_ISET_V6)
{
	ands,0 %r_A, _f32s,_lts0 PKT_TYPE_MAX, %r_A
}
SYM_FUNC_END_SIZED(cbpf_jit_anc_pkttype)

SYM_FUNC_START_SIZED(cbpf_jit_anc_vlan_tag_present)
ALTERNATIVE_1_ALTINSTR
	{
		nop 4
		ldb,0 [ %dr0 + _f32s,_lts0 PKT_VLAN_PRESENT_OFFSET ], %r_A
	}
ALTERNATIVE_2_OLDINSTR
	{
		nop 2
		ldb,0 [ %dr0 + _f32s,_lts0 PKT_VLAN_PRESENT_OFFSET ], %r_A
	}
ALTERNATIVE_3_FEATURE(CPU_FEAT_ISET_V6)
{
	ands,0 %r_A, _f32s,_lts0 PKT_VLAN_PRESENT_BIT, %r_A
}
SYM_FUNC_END_SIZED(cbpf_jit_anc_vlan_tag_present)

SYM_FUNC_START_SIZED(cbpf_jit_anc_ifindex)
ALTERNATIVE_1_ALTINSTR
	{
		nop 4
		ldd,0 [ %dr0 + _f32s,_lts0 SKB_DEV ], %dr_TMP1
		return %ctpr3
	}
	{
		cmpedb,0 %dr_TMP1, 0x0, %pred0
	}
	{
		nop 2
		ldw,0 [ %dr_TMP1 + _f32s,_lts0 NETDEV_IFINDEX ], %r_A ? ~ %pred0
	}
	{
		nop 1
		adds,1 0x0, 0x0, %r0 ? %pred0
		ct %ctpr3 ? %pred0
	}
ALTERNATIVE_2_OLDINSTR
	{
		nop 2
		ldd,0 [ %dr0 + _f32s,_lts0 SKB_DEV ], %dr_TMP1
		return %ctpr3
	}
	{
		nop 1
		cmpedb,0 %dr_TMP1, 0x0, %pred0
	}
	{
		ldw,0 [ %dr_TMP1 + _f32s,_lts0 NETDEV_IFINDEX ], %r_A ? ~ %pred0
	}
	{
		nop 1
		adds,1 0x0, 0x0, %r0 ? %pred0
		ct %ctpr3 ? %pred0
	}
ALTERNATIVE_3_FEATURE(CPU_FEAT_ISET_V6)
SYM_FUNC_END_SIZED(cbpf_jit_anc_ifindex)

SYM_FUNC_START_SIZED(cbpf_jit_anc_hatype)
ALTERNATIVE_1_ALTINSTR
	{
		nop 4
		ldd,0 [ %dr0 + _f32s,_lts0 SKB_DEV ], %dr_TMP1
		return %ctpr3
	}
	{
		cmpedb,0 %dr_TMP1, 0x0, %pred0
	}
	{
		nop 2
		ldh,0 [ %dr_TMP1 + _f32s,_lts0 NETDEV_TYPE ], %r_A ? ~ %pred0
	}
	{
		nop 1
		adds,1 0x0, 0x0, %r0 ? %pred0
		ct %ctpr3 ? %pred0
	}
ALTERNATIVE_2_OLDINSTR
	{
		nop 2
		ldd,0 [ %dr0 + _f32s,_lts0 SKB_DEV ], %dr_TMP1
		return %ctpr3
	}
	{
		nop 1
		cmpedb,0 %dr_TMP1, 0x0, %pred0
	}
	{
		ldh,0 [ %dr_TMP1 + _f32s,_lts0 NETDEV_TYPE ], %r_A ? ~ %pred0
	}
	{
		nop 1
		adds,1 0x0, 0x0, %r0 ? %pred0
		ct %ctpr3 ? %pred0
	}
ALTERNATIVE_3_FEATURE(CPU_FEAT_ISET_V6)
SYM_FUNC_END_SIZED(cbpf_jit_anc_hatype)

SYM_FUNC_START_SIZED(cbpf_jit_anc_pay_offset)
BPF_TEMPL_LABEL(BPF_JIT_FUNC_LABEL(cbpf_jit_anc_pay_offset, skb_get_poff))
{
	nop 4
	addd,0 %dr0, 0x0, %db[0]
	disp %ctpr1, $cbpf_jit_anc_pay_offset
}
BPF_TEMPL_LABEL(BPF_JIT_WBS_LABEL(cbpf_jit_anc_pay_offset, skb_get_poff))
{
	call %ctpr1, wbs = 0x0
}
{
	nop 1
	cmpesb,0 %b[0], 0x0, %pred0
	return %ctpr3
}
{
	adds,0 %b[0], 0x0, %r_A ? ~ %pred0
	adds,1 0x0, 0x0, %r0 ? %pred0
	ct %ctpr3 ? %pred0
}
SYM_FUNC_END_SIZED(cbpf_jit_anc_pay_offset)

SYM_FUNC_START_SIZED(cbpf_jit_anc_vlan_tpid)
ALTERNATIVE_1_ALTINSTR
	{
		nop 4
		ldh,0 [ %dr0 + _f32s,_lts0 SKB_VLAN_PROTO ], mas = 0x8, %r_A
	}
ALTERNATIVE_2_OLDINSTR
	{
		nop 2
		ldh,0 [ %dr0 + _f32s,_lts0 SKB_VLAN_PROTO ], mas = 0x8, %r_A
	}
ALTERNATIVE_3_FEATURE(CPU_FEAT_ISET_V6)
SYM_FUNC_END_SIZED(cbpf_jit_anc_vlan_tpid)

/* Template for seccomp BPF */
SYM_FUNC_START_SIZED(cbpf_jit_ldx_w_abs)
BPF_TEMPL_LABEL(BPF_JIT_K_LABEL(cbpf_jit_ldx_w_abs))
ALTERNATIVE_1_ALTINSTR
	{
		nop 4
		ldw,0 [ %dr0 + _f32s,_lts0 0x0 ], %r_A
	}
ALTERNATIVE_2_OLDINSTR
	{
		nop 2
		ldw,0 [ %dr0 + _f32s,_lts0 0x0 ], %r_A
	}
ALTERNATIVE_3_FEATURE(CPU_FEAT_ISET_V6)
SYM_FUNC_END_SIZED(cbpf_jit_ldx_w_abs)

