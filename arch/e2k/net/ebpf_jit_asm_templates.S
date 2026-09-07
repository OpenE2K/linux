/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Templates for eBPF JIT compiler.
 */

#include <asm/asm-offsets.h>
#include <asm/alternative-asm.h>
#include <asm/trap_table.S.h>

#include "ebpf_jit.h"

/*
 * This file contains templates for eBPF JIT compiler.
 *
 * Refer to common assembler header for description what the templates are.
 */

/*
 *  Register assignment for eBPF jited program:
 *
 * ---------------------------------------------------------------
 *  HW registers |       Macro       |        What for
 * ---------------------------------------------------------------
 *      r0       |        R0         | Maps into eBPF register R0
 *      r1       |        R1         | Maps into eBPF register R1
 *      r2       |        R2         | Maps into eBPF register R2
 *      r3       |        R3         | Maps into eBPF register R3
 *      r4       |        R4         | Maps into eBPF register R4
 *      r5       |        R5         | Maps into eBPF register R5
 *      r6       |        --         | Maps into eBPF register R6
 *      r7       |        --         | Maps into eBPF register R7
 *      r8       |        --         | Maps into eBPF register R8
 *      r9       |        --         | Maps into eBPF register R9
 *      r10      |       R10         | Maps into eBPF register R10
 *      r11      |        --         | Maps into eBPF auxiliary register BPF_REG_AX
 *      r12      |      r_TMP1       | Internal JIT usage
 *      r13      |      r_TMP2       | Internal JIT usage
 *      r14      |        --         | Unused, needed for register window alignment
 *      r15      | r_TAIL_CALL_COUNT | Tail call counter
 *      r16      |      db_R1        | 1st call argument
 *      r17      |      db_R2        | 2nd call argument
 *      r18      |      db_R3        | 3rd call argument
 *      r19      |      db_R4        | 4th call argument
 *      r20      |      db_R5        | 5th call argument
 *      r21      |        --         | 6th call argument
 *      r22      |        --         | 7th call argument
 *      r23      |        --         | 8th call argument
 * ---------------------------------------------------------------
 *
 * Note: last 8 registers are allocated only if JIT ensures that
 *       eBPF program has a function call. Otherwise, register window
 *       contains of 16 registers (r0-r15).
 */

#define R0 dr0
#define R1 dr1
#define R2 dr2
#define R3 dr3
#define R4 dr4
#define R5 dr5
#define R10 dr10

#define r_TMP1 r12
#define dr_TMP1 dr12
#define r_TMP2 r13
#define dr_TMP2 dr13
#define r_TAIL_CALL_CNT r15

/*
 * First argument of bpf-to-bpf calls is placed to db[0]. From the callee
 * point of view, db[0] is dr0, which is mapped to R0 by eBPF JIT. However,
 * in the prologue template dr0 is always moved to dr1 (aka R1), to work
 * seamlessly with e2k calling convention. So, first argument of bpf-to-bpf
 * calls is placed to db[0] assuming the jited subprogram will move it
 * to the correct register in prologue. Other arguments are passed directly
 * to the corresponding registers of the subprogram: second argument to
 * db[2] (which is callee's dr2 aka R2), third to db[3] (callee's dr3 aka
 * R3), and so on.
 */
#define db_R1 db[0]
#define db_R2 db[2]
#define db_R3 db[3]
#define db_R4 db[4]
#define db_R5 db[5]

#define __BPF_JIT_CONCAT(a, b) a ## b
#define BPF_JIT_CONCATENATE(a, b) __BPF_JIT_CONCAT(a, b)

#define r_SRC		BPF_JIT_CONCATENATE(r, EBPF_JIT_SRC_REG)
#define dr_SRC		BPF_JIT_CONCATENATE(dr, EBPF_JIT_SRC_REG)
#define r_DST		BPF_JIT_CONCATENATE(r, EBPF_JIT_DST_REG)
#define dr_DST		BPF_JIT_CONCATENATE(dr, EBPF_JIT_DST_REG)

/*
 * Here is an example of how eBPF JIT will preserve tail call counter across
 * bpf-to-bpf calls. The example is a tricky eBPF program that consists of main
 * entry (entry_prog) and three subprograms (subprog1, subprog2 and subprog3).
 *
 *      entry_prog()
 *      {
 *              ...
 *              call subprog1;    // bpf-to-bpf call
 *              ...
 *              return ...;
 *      }
 *
 *      subprog1
 *      {
 *              ...
 *              call subprog2;    // bpf-to-bpf call
 *              ...
 *              return ...;
 *      }
 *
 *      subprog2 ()
 *      {
 *              ...
 *              return subprog3;  // tail call
 *      }
 *
 *      subprog3 ()
 *      {
 *              ...
 *              return ...;
 *      }
 *
 * Four images for this program will look like (arrows on the right show calls,
 * tail calls and returns during the execution of this jited program):
 *
 *                --------------------------------
 *                |  x (because entry prog)      |
 * entry_prog --> --------------------------------
 *              ^ |  prologue_zero_cnt:          |
 *             x| |                              |
 *              v |  0 -> r7                     |
 *                --------------------------------
 *                |  prologue:                   |
 *                |            ...               |
 *                |  r7 -> r_TAIL_CALL_COUNT     |
 *                --------------------------------
 *                |      <program body>          |
 *                |            ...               |
 *                --------------------------------
 *                |  bpf-to-bpf call:            |
 *                |            ...               |
 *                |  r_TAIL_CALL_COUNT -> b[7]   |
 *                |  call subprog1               | -----
 *                |  b[7] -> r_TAIL_CALL_COUNT   | <---+---------
 *                |            ...               |     |        |
 *                --------------------------------     |        |
 *                |      <program body>          |     |        |
 *                |            ...               |     |        |
 *                --------------------------------     |        |
 *                |  exit:                       |     |        |
 *                |            ...               |     |        |
 *                |  r_TAIL_CALL_COUNT -> r7     |     |        |
 *                |  return                      |     |        |
 *                --------------------------------     |        |
 *                                                     |        |
 *                                                     |        |
 *                --------------------------------     |        |
 *                |  0 (because subprog)         |     |        |
 *   subprog1 --> --------------------------------     |        |
 *                |  prologue:                   | <----        |
 *                |            ...               |              |
 *                |  r7 -> r_TAIL_CALL_COUNT     |              |
 *                --------------------------------              |
 *                |      <program body>          |              |
 *                |            ...               |              |
 *                --------------------------------              |
 *                |  bpf-to-bpf call:            |              |
 *                |            ...               |              |
 *                |  r_TAIL_CALL_COUNT -> b[7]   |              |
 *                |  call subprog2               | -----        |
 *                |  b[7] -> r_TAIL_CALL_COUNT   | <---+-----   |
 *                |            ...               |     |    |   |
 *                --------------------------------     |    |   |
 *                |      <program body>          |     |    |   |
 *                |            ...               |     |    |   |
 *                --------------------------------     |    |   |
 *                |  exit:                       |     |    |   |
 *                |            ...               |     |    |   |
 *                |  r_TAIL_CALL_COUNT -> r7     |     |    |   |
 *                |  return                      | ----+----+----
 *                --------------------------------     |    |
 *                                                     |    |
 *                                                     |    |
 *                --------------------------------     |    |
 *                |  0 (because subprog)         |     |    |
 *   subprog2 --> --------------------------------     |    |
 *                |  prologue:                   | <----    |
 *                |            ...               |          |
 *                |  r7 -> r_TAIL_CALL_COUNT     |          |
 *                --------------------------------          |
 *                |      <program body>          |          |
 *                |            ...               |          |
 *                --------------------------------          |
 *                |  tail call:                  |          |
 *                |            ...               |          |
 *                |  r_TAIL_CALL_COUNT -> b[7]   |          |
 *                |  load [subprog3 - 8], %rtmp  |          |
 *                |  jump subprog3 + %rtmp       | -----    |
 *                --------------------------------     |    |
 *                |   <tail call error path >    |     |    |
 *                |            ...               |     |    |
 *                --------------------------------     |    |
 *                |  exit:                       |     |    |
 *                |            ...               |     |    |
 *                |  r_TAIL_CALL_COUNT -> r7     |     |    |
 *                |  return                      |     |    |
 *                --------------------------------     |    |
 *                                                     |    |
 *                                                     |    |
 *                --------------------------------     |    |
 *                |  0 (because subprog)         |     |    |
 *   subprog3 --> --------------------------------     |    |
 *                |  prologue:                   | <----    |
 *                |            ...               |          |
 *                |  r7 -> r_TAIL_CALL_COUNT     |          |
 *                --------------------------------          |
 *                |      <program body>          |          |
 *                |            ...               |          |
 *                --------------------------------          |
 *                |  exit:                       |          |
 *                |            ...               |          |
 *                |  r_TAIL_CALL_COUNT -> r7     |          |
 *                |  return                      | ----------
 *                --------------------------------
 *
 * A number 8 in load operation in subprog2 is tail call offset.
 */

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

/* Template for tail call counter zeroing */
SYM_FUNC_START_SIZED(ebpf_jit_prologue_zero_cnt)
{
	adds,0 0x0, 0x0, %r7
}
SYM_FUNC_END_SIZED(ebpf_jit_prologue_zero_cnt)

/* Prologue template */
SYM_FUNC_START_SIZED(ebpf_jit_prologue)
BPF_TEMPL_LABEL(BPF_JIT_WSZ_LABEL(ebpf_jit_prologue))
BPF_TEMPL_LABEL(BPF_JIT_RBS_LABEL(ebpf_jit_prologue))
BPF_TEMPL_LABEL(BPF_JIT_STACK_SIZE_LABEL(ebpf_jit_prologue))
{
	getsp,0 _f32s,_lts1 0x0, %r_TMP1
	setwd wsz = 0x7, nfx = 0x1
	setbn rsz = 0x3, rbs = 0x4, rcur = 0x0
	/*
	 * Save tail call counter to the special register, where it would reside
	 * during the jited eBPF program execution. The previous tail call counter
	 * value in register r7 was put there either by the special zeroing part
	 * of program placed by JIT before this template, or by tail call template
	 * of the eBPF program that made the tail call.
	 */
	adds,1 0x0, %r7, %r_TAIL_CALL_CNT
	/*
	 * Just save to a temporary register the number of bytes we allocated
	 * on stack.
	 */
	addd,2 0x0, _f32s,_lts1 0x0, %r_TMP2
}
{
	/*
	 * e2k stack grows toward numerically lower addresses, so getsp returns
	 * the lowest address of allocated stack frame. However, in eBPF programs
	 * frame pointer (R10) is assumed to point to the highest address of stack
	 * frame. Here, we initialize frame pointer accordingly to eBPF conception.
	 */
	subd,0 %r_TMP1, %r_TMP2, %R10
	/*
	 * According to e2k calling convention, the only argument of eBPF program,
	 * pointer to context, resides in dr0 after jited eBPF program was invoked.
	 * Move it from dr0 to R1 to satisfy eBPF calling convention, in which the
	 * first argument should reside in R1.
	 */
	addd,1 %dr0, 0x0, %R1
}
SYM_FUNC_END_SIZED(ebpf_jit_prologue)

/* Template for exit from eBPF program */
SYM_FUNC_START_SIZED(ebpf_jit_jmp_exit)
{
	nop 5
	/*
	 * Move tail call counter to r7. If this is eBPF subprogram, caller
	 * eBPF program will update its tail call counter using the value in r7.
	 */
	adds,0 0x0, %r_TAIL_CALL_CNT, %r7
	return %ctpr3
}
{
	ct %ctpr3
}
SYM_FUNC_END_SIZED(ebpf_jit_jmp_exit)

/* Templates for arithmetic and logic operations */
SYM_FUNC_START_SIZED(ebpf_jit_alu_mov_x)
{
	addd,0 0x0, 0x0, %dr_DST
	adds,1 0x0, %r_SRC, %r_DST
}
SYM_FUNC_END_SIZED(ebpf_jit_alu_mov_x)

SYM_FUNC_START_SIZED(ebpf_jit_alu64_mov_x)
{
	addd,0 0x0, %dr_SRC, %dr_DST
}
SYM_FUNC_END_SIZED(ebpf_jit_alu64_mov_x)

SYM_FUNC_START_SIZED(ebpf_jit_alu_mov_k)
BPF_TEMPL_LABEL(BPF_JIT_IMM_LABEL(ebpf_jit_alu_mov_k))
{
	addd,0 0x0, 0x0, %dr_DST
	adds,1 0x0, _f32s,_lts0 0x0, %r_DST
}
SYM_FUNC_END_SIZED(ebpf_jit_alu_mov_k)

SYM_FUNC_START_SIZED(ebpf_jit_alu64_mov_k)
BPF_TEMPL_LABEL(BPF_JIT_IMM_LABEL(ebpf_jit_alu64_mov_k))
{
	addd,0 0x0, _f32s,_lts0 0x0, %dr_DST
}
SYM_FUNC_END_SIZED(ebpf_jit_alu64_mov_k)

SYM_FUNC_START_SIZED(ebpf_jit_alu_add_x)
{
	addd,0 0x0, 0x0, %dr_DST
	adds,1 %r_DST, %r_SRC, %r_DST
}
SYM_FUNC_END_SIZED(ebpf_jit_alu_add_x)

SYM_FUNC_START_SIZED(ebpf_jit_alu64_add_x)
{
	addd,0 %dr_DST, %dr_SRC, %dr_DST
}
SYM_FUNC_END_SIZED(ebpf_jit_alu64_add_x)

SYM_FUNC_START_SIZED(ebpf_jit_alu_sub_x)
{
	addd,0 0x0, 0x0, %dr_DST
	subs,1 %r_DST, %r_SRC, %r_DST
}
SYM_FUNC_END_SIZED(ebpf_jit_alu_sub_x)

SYM_FUNC_START_SIZED(ebpf_jit_alu64_sub_x)
{
	subd,0 %dr_DST, %dr_SRC, %dr_DST
}
SYM_FUNC_END_SIZED(ebpf_jit_alu64_sub_x)

SYM_FUNC_START_SIZED(ebpf_jit_alu_and_x)
{
	addd,0 0x0, 0x0, %dr_DST
	ands,1 %r_DST, %r_SRC, %r_DST
}
SYM_FUNC_END_SIZED(ebpf_jit_alu_and_x)

SYM_FUNC_START_SIZED(ebpf_jit_alu64_and_x)
{
	andd,0 %dr_DST, %dr_SRC, %dr_DST
}
SYM_FUNC_END_SIZED(ebpf_jit_alu64_and_x)

SYM_FUNC_START_SIZED(ebpf_jit_alu_or_x)
{
	addd,0 0x0, 0x0, %dr_DST
	ors,1 %r_DST, %r_SRC, %r_DST
}
SYM_FUNC_END_SIZED(ebpf_jit_alu_or_x)

SYM_FUNC_START_SIZED(ebpf_jit_alu64_or_x)
{
	ord,0 %dr_DST, %dr_SRC, %dr_DST
}
SYM_FUNC_END_SIZED(ebpf_jit_alu64_or_x)

SYM_FUNC_START_SIZED(ebpf_jit_alu_xor_x)
{
	addd,0 0x0, 0x0, %dr_DST
	xors,1 %r_DST, %r_SRC, %r_DST
}
SYM_FUNC_END_SIZED(ebpf_jit_alu_xor_x)

SYM_FUNC_START_SIZED(ebpf_jit_alu64_xor_x)
{
	xord,0 %dr_DST, %dr_SRC, %dr_DST
}
SYM_FUNC_END_SIZED(ebpf_jit_alu64_xor_x)

SYM_FUNC_START_SIZED(ebpf_jit_alu_lsh_x)
{
	addd,0 0x0, 0x0, %dr_DST
	shls,1 %r_DST, %r_SRC, %r_DST
}
SYM_FUNC_END_SIZED(ebpf_jit_alu_lsh_x)

SYM_FUNC_START_SIZED(ebpf_jit_alu64_lsh_x)
{
	shld,0 %dr_DST, %dr_SRC, %dr_DST
}
SYM_FUNC_END_SIZED(ebpf_jit_alu64_lsh_x)

SYM_FUNC_START_SIZED(ebpf_jit_alu_rsh_x)
{
	addd,0 0x0, 0x0, %dr_DST
	shrs,1 %r_DST, %r_SRC, %r_DST
}
SYM_FUNC_END_SIZED(ebpf_jit_alu_rsh_x)

SYM_FUNC_START_SIZED(ebpf_jit_alu64_rsh_x)
{
	shrd,0 %dr_DST, %dr_SRC, %dr_DST
}
SYM_FUNC_END_SIZED(ebpf_jit_alu64_rsh_x)

SYM_FUNC_START_SIZED(ebpf_jit_alu_arsh_x)
{
	addd,0 0x0, 0x0, %dr_DST
	sars,1 %r_DST, %r_SRC, %r_DST
}
SYM_FUNC_END_SIZED(ebpf_jit_alu_arsh_x)

SYM_FUNC_START_SIZED(ebpf_jit_alu64_arsh_x)
{
	sard,0 %dr_DST, %dr_SRC, %dr_DST
}
SYM_FUNC_END_SIZED(ebpf_jit_alu64_arsh_x)

SYM_FUNC_START_SIZED(ebpf_jit_alu_mul_x)
{
	addd,0 0x0, 0x0, %dr_DST
	/* let hardware control muls -> ... scheduling */
	muls,1 %r_DST, %r_SRC, %r_DST
}
SYM_FUNC_END_SIZED(ebpf_jit_alu_mul_x)

SYM_FUNC_START_SIZED(ebpf_jit_alu64_mul_x)
{
	/* let hardware control muld -> ... scheduling */
	muld,0 %dr_DST, %dr_SRC, %dr_DST
}
SYM_FUNC_END_SIZED(ebpf_jit_alu64_mul_x)

SYM_FUNC_START_SIZED(ebpf_jit_alu_div_x)
ALTERNATIVE_1_ALTINSTR
	{
		cmpesb,0 %r_SRC, 0x0, %pred0
	}
ALTERNATIVE_2_OLDINSTR
	{
		nop 1
		cmpesb,0 %r_SRC, 0x0, %pred0
	}
ALTERNATIVE_3_FEATURE(CPU_FEAT_ISET_V6)
{
	/* set dst to 0 in case of zero division */
	addd,0 0x0, 0x0, %dr_DST
	/* let hardware control udivs -> ... scheduling */
	udivs,5 %r_DST, %r_SRC, %r_DST ? ~ %pred0
}
SYM_FUNC_END_SIZED(ebpf_jit_alu_div_x)

SYM_FUNC_START_SIZED(ebpf_jit_alu64_div_x)
ALTERNATIVE_1_ALTINSTR
	{
		cmpedb,0 %dr_SRC, 0x0, %pred0
	}
ALTERNATIVE_2_OLDINSTR
	{
		nop 1
		cmpedb,0 %dr_SRC, 0x0, %pred0
	}
ALTERNATIVE_3_FEATURE(CPU_FEAT_ISET_V6)
{
	/*
	 * Always set to zero 32 most significant bits and
	 * set dst to 0 in case of zero division.
	 */
	addd,0 0x0, 0x0, %dr_DST
	/* let hardware control udivd -> ... scheduling */
	udivd,5 %dr_DST, %dr_SRC, %dr_DST ? ~ %pred0
}
SYM_FUNC_END_SIZED(ebpf_jit_alu64_div_x)

SYM_FUNC_START_SIZED(ebpf_jit_alu_mod_x)
ALTERNATIVE_1_ALTINSTR
	{
		cmpesb,0 %r_SRC, 0x0, %pred0
	}
ALTERNATIVE_2_OLDINSTR
	{
		nop 1
		cmpesb,0 %r_SRC, 0x0, %pred0
	}
ALTERNATIVE_3_FEATURE(CPU_FEAT_ISET_V6)
{
	sxt,5 0x6, %r_DST, %dr_TMP1 ? ~ %pred0
}
{
	/* always zero 32 most significant bits */
	addd,0 0x0, 0x0, %dr_DST
	/* save 32 least significant bits in case of modulo by zero */
	adds,1 %r_DST, 0x0, %r_DST ? %pred0
	/* let hardware control umodx -> ... scheduling */
	umodx,5 %dr_TMP1, %r_SRC, %r_DST ? ~ %pred0
}
SYM_FUNC_END_SIZED(ebpf_jit_alu_mod_x)

SYM_FUNC_START_SIZED(ebpf_jit_alu64_mod_x)
ALTERNATIVE_1_ALTINSTR
	{
		cmpedb,0 %dr_SRC, 0x0, %pred0
	}
ALTERNATIVE_2_OLDINSTR
	{
		nop 1
		cmpedb,0 %dr_SRC, 0x0, %pred0
	}
ALTERNATIVE_3_FEATURE(CPU_FEAT_ISET_V6)
{
	/* let hardware control udivd -> muld scheduling */
	udivd,5 %dr_DST, %dr_SRC, %dr_TMP1 ? ~ %pred0
}
{
	nop 5
	muld,3 %dr_TMP1, %dr_SRC, %dr_TMP1 ? ~ %pred0
}
{
	subd,3 %dr_DST, %dr_TMP1, %dr_DST ? ~ %pred0
}
SYM_FUNC_END_SIZED(ebpf_jit_alu64_mod_x)

SYM_FUNC_START_SIZED(ebpf_jit_alu_add_k)
BPF_TEMPL_LABEL(BPF_JIT_IMM_LABEL(ebpf_jit_alu_add_k))
{
	addd,0 0x0, 0x0, %dr_DST
	adds,1 %r_DST, _f32s,_lts0 0x0, %r_DST
}
SYM_FUNC_END_SIZED(ebpf_jit_alu_add_k)

SYM_FUNC_START_SIZED(ebpf_jit_alu64_add_k)
BPF_TEMPL_LABEL(BPF_JIT_IMM_LABEL(ebpf_jit_alu64_add_k))
{
	addd,0 %dr_DST, _f32s,_lts0 0x0, %dr_DST
}
SYM_FUNC_END_SIZED(ebpf_jit_alu64_add_k)

SYM_FUNC_START_SIZED(ebpf_jit_alu_sub_k)
BPF_TEMPL_LABEL(BPF_JIT_IMM_LABEL(ebpf_jit_alu_sub_k))
{
	addd,0 0x0, 0x0, %dr_DST
	subs,1 %r_DST, _f32s,_lts0 0x0, %r_DST
}
SYM_FUNC_END_SIZED(ebpf_jit_alu_sub_k)

SYM_FUNC_START_SIZED(ebpf_jit_alu64_sub_k)
BPF_TEMPL_LABEL(BPF_JIT_IMM_LABEL(ebpf_jit_alu64_sub_k))
{
	subd,0 %dr_DST, _f32s,_lts0 0x0, %dr_DST
}
SYM_FUNC_END_SIZED(ebpf_jit_alu64_sub_k)

SYM_FUNC_START_SIZED(ebpf_jit_alu_and_k)
BPF_TEMPL_LABEL(BPF_JIT_IMM_LABEL(ebpf_jit_alu_and_k))
{
	addd,0 0x0, 0x0, %dr_DST
	ands,1 %r_DST, _f32s,_lts0 0x0, %r_DST
}
SYM_FUNC_END_SIZED(ebpf_jit_alu_and_k)

SYM_FUNC_START_SIZED(ebpf_jit_alu64_and_k)
BPF_TEMPL_LABEL(BPF_JIT_IMM_LABEL(ebpf_jit_alu64_and_k))
{
	andd,0 %dr_DST, _f32s,_lts0 0x0, %dr_DST
}
SYM_FUNC_END_SIZED(ebpf_jit_alu64_and_k)

SYM_FUNC_START_SIZED(ebpf_jit_alu_or_k)
BPF_TEMPL_LABEL(BPF_JIT_IMM_LABEL(ebpf_jit_alu_or_k))
{
	addd,0 0x0, 0x0, %dr_DST
	ors,1 %r_DST, _f32s,_lts0 0x0, %r_DST
}
SYM_FUNC_END_SIZED(ebpf_jit_alu_or_k)

SYM_FUNC_START_SIZED(ebpf_jit_alu64_or_k)
BPF_TEMPL_LABEL(BPF_JIT_IMM_LABEL(ebpf_jit_alu64_or_k))
{
	ord,0 %dr_DST, _f32s,_lts0 0x0, %dr_DST
}
SYM_FUNC_END_SIZED(ebpf_jit_alu64_or_k)

SYM_FUNC_START_SIZED(ebpf_jit_alu_xor_k)
BPF_TEMPL_LABEL(BPF_JIT_IMM_LABEL(ebpf_jit_alu_xor_k))
{
	addd,0 0x0, 0x0, %dr_DST
	xors,1 %r_DST, _f32s,_lts0 0x0, %r_DST
}
SYM_FUNC_END_SIZED(ebpf_jit_alu_xor_k)

SYM_FUNC_START_SIZED(ebpf_jit_alu64_xor_k)
BPF_TEMPL_LABEL(BPF_JIT_IMM_LABEL(ebpf_jit_alu64_xor_k))
{
	xord,0 %dr_DST, _f32s,_lts0 0x0, %dr_DST
}
SYM_FUNC_END_SIZED(ebpf_jit_alu64_xor_k)

SYM_FUNC_START_SIZED(ebpf_jit_alu_lsh_k)
BPF_TEMPL_LABEL(BPF_JIT_IMM_LABEL(ebpf_jit_alu_lsh_k))
{
	addd,0 0x0, 0x0, %dr_DST
	shls,1 %r_DST, _f32s,_lts0 0x0, %r_DST
}
SYM_FUNC_END_SIZED(ebpf_jit_alu_lsh_k)

SYM_FUNC_START_SIZED(ebpf_jit_alu64_lsh_k)
BPF_TEMPL_LABEL(BPF_JIT_IMM_LABEL(ebpf_jit_alu64_lsh_k))
{
	shld,0 %dr_DST, _f32s,_lts0 0x0, %dr_DST
}
SYM_FUNC_END_SIZED(ebpf_jit_alu64_lsh_k)

SYM_FUNC_START_SIZED(ebpf_jit_alu_rsh_k)
BPF_TEMPL_LABEL(BPF_JIT_IMM_LABEL(ebpf_jit_alu_rsh_k))
{
	addd,0 0x0, 0x0, %dr_DST
	shrs,1 %r_DST, _f32s,_lts0 0x0, %r_DST
}
SYM_FUNC_END_SIZED(ebpf_jit_alu_rsh_k)

SYM_FUNC_START_SIZED(ebpf_jit_alu64_rsh_k)
BPF_TEMPL_LABEL(BPF_JIT_IMM_LABEL(ebpf_jit_alu64_rsh_k))
{
	shrd,0 %dr_DST, _f32s,_lts0 0x0, %dr_DST
}
SYM_FUNC_END_SIZED(ebpf_jit_alu64_rsh_k)

SYM_FUNC_START_SIZED(ebpf_jit_alu_arsh_k)
BPF_TEMPL_LABEL(BPF_JIT_IMM_LABEL(ebpf_jit_alu_arsh_k))
{
	addd,0 0x0, 0x0, %dr_DST
	sars,1 %r_DST, _f32s,_lts0 0x0, %r_DST
}
SYM_FUNC_END_SIZED(ebpf_jit_alu_arsh_k)

SYM_FUNC_START_SIZED(ebpf_jit_alu64_arsh_k)
BPF_TEMPL_LABEL(BPF_JIT_IMM_LABEL(ebpf_jit_alu64_arsh_k))
{
	sard,0 %dr_DST, _f32s,_lts0 0x0, %dr_DST
}
SYM_FUNC_END_SIZED(ebpf_jit_alu64_arsh_k)

SYM_FUNC_START_SIZED(ebpf_jit_alu_mul_k)
BPF_TEMPL_LABEL(BPF_JIT_IMM_LABEL(ebpf_jit_alu_mul_k))
{
	addd,0 0x0, 0x0, %dr_DST
	/* let hardware control muls -> ... scheduling */
	muls,1 %r_DST, _f32s,_lts0 0x0, %r_DST
}
SYM_FUNC_END_SIZED(ebpf_jit_alu_mul_k)

SYM_FUNC_START_SIZED(ebpf_jit_alu64_mul_k)
BPF_TEMPL_LABEL(BPF_JIT_IMM_LABEL(ebpf_jit_alu64_mul_k))
{
	/* let hardware control muld -> ... scheduling */
	muld,0 %dr_DST, _f32s,_lts0 0x0, %dr_DST
}
SYM_FUNC_END_SIZED(ebpf_jit_alu64_mul_k)

SYM_FUNC_START_SIZED(ebpf_jit_alu_div_k)
BPF_TEMPL_LABEL(BPF_JIT_IMM_LABEL(ebpf_jit_alu_div_k))
{
	addd,0 0x0, 0x0, %dr_DST
	/* let hardware control udivs -> ... scheduling */
	udivs,5 %r_DST, _f32s,_lts0 0x0, %r_DST
}
SYM_FUNC_END_SIZED(ebpf_jit_alu_div_k)

SYM_FUNC_START_SIZED(ebpf_jit_alu64_div_k)
BPF_TEMPL_LABEL(BPF_JIT_IMM_LABEL(ebpf_jit_alu64_div_k))
{
	/* let hardware control udivd -> ... scheduling */
	udivd,5 %dr_DST, _f32s,_lts0 0x0, %dr_DST
}
SYM_FUNC_END_SIZED(ebpf_jit_alu64_div_k)

SYM_FUNC_START_SIZED(ebpf_jit_alu_mod_k)
{
	sxt,5 0x6, %r_DST, %dr_TMP1
}
BPF_TEMPL_LABEL(BPF_JIT_IMM_LABEL(ebpf_jit_alu_mod_k))
{
	addd,0 0x0, 0x0, %dr_DST
	/* let hardware control umodx -> ... scheduling */
	umodx,5 %dr_TMP1, _f32s,_lts0 0x0, %r_DST
}
SYM_FUNC_END_SIZED(ebpf_jit_alu_mod_k)

SYM_FUNC_START_SIZED(ebpf_jit_alu64_mod_k)
BPF_TEMPL_LABEL(BPF_JIT_IMM_LABEL(ebpf_jit_alu64_mod_k))
{
	addd,3 0x0, _f32s,_lts0 0x0, %dr_TMP2
	/* let hardware control udivd -> muld scheduling */
	udivd,5 %dr_DST, _f32s,_lts0 0x0, %dr_TMP1
}
{
	nop 5
	muld,3 %dr_TMP1, %dr_TMP2, %dr_TMP1
}
{
	subd,3 %dr_DST, %dr_TMP1, %dr_DST
}
SYM_FUNC_END_SIZED(ebpf_jit_alu64_mod_k)

SYM_FUNC_START_SIZED(ebpf_jit_alu_neg)
{
	addd,0 0x0, 0x0, %dr_DST
	subs,1 0x0, %r_DST, %r_DST
}
SYM_FUNC_END_SIZED(ebpf_jit_alu_neg)

SYM_FUNC_START_SIZED(ebpf_jit_alu64_neg)
{
	subd,0 0x0, %dr_DST, %dr_DST
}
SYM_FUNC_END_SIZED(ebpf_jit_alu64_neg)

SYM_FUNC_START_SIZED(ebpf_jit_alu_end_le16)
{
	andd,0 %dr_DST, _f64,_lts0 0xffff, %dr_DST
}
SYM_FUNC_END_SIZED(ebpf_jit_alu_end_le16)

SYM_FUNC_START_SIZED(ebpf_jit_alu_end_le32)
{
	andd,0 %dr_DST, _f64,_lts0 0xffffffff, %dr_DST
}
SYM_FUNC_END_SIZED(ebpf_jit_alu_end_le32)

SYM_FUNC_START_SIZED(ebpf_jit_alu_end_be16)
{
	addd,0 0x0, _f64,_lts0 0x8080808080800001, %dr_TMP1
	sxt,1 0x6, %r_DST, %dr_TMP2
}
{
	nop 3
	pshufb,0 %dr_TMP2, %dr_TMP2, %dr_TMP1, %dr_DST
}
SYM_FUNC_END_SIZED(ebpf_jit_alu_end_be16)

SYM_FUNC_START_SIZED(ebpf_jit_alu_end_be32)
{
	addd,0 0x0, _f64,_lts0 0x8080808000010203, %dr_TMP1
	sxt,1 0x6, %r_DST, %dr_TMP2
}
{
	nop 3
	pshufb,0 %dr_TMP2, %dr_TMP2, %dr_TMP1, %dr_DST
}
SYM_FUNC_END_SIZED(ebpf_jit_alu_end_be32)

SYM_FUNC_START_SIZED(ebpf_jit_alu_end_be64)
{
	addd,0 0x0, _f64,_lts0 0x0001020304050607, %dr_TMP1
}
{
	nop 3
	pshufb,0 %dr_DST, %dr_DST, %dr_TMP1, %dr_DST
}
SYM_FUNC_END_SIZED(ebpf_jit_alu_end_be64)

/* Template for loading 64-bit value from eBPF instruction to a register */
SYM_FUNC_START_SIZED(ebpf_jit_ld_imm_dw)
BPF_TEMPL_LABEL(BPF_JIT_IMM_LABEL(ebpf_jit_ld_imm_dw))
{
	addd,0 0x0, _f64,_lts0 0x0, %dr_DST
}
SYM_FUNC_END_SIZED(ebpf_jit_ld_imm_dw)

/* Templates for jump operations */
SYM_FUNC_START_SIZED(ebpf_jit_jmp_ja)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(ebpf_jit_jmp_ja))
{
	/* let hardware control disp -> ct scheduling */
	disp %ctpr1, ebpf_jit_jmp_ja
}
{
	ct %ctpr1
}
SYM_FUNC_END_SIZED(ebpf_jit_jmp_ja)

SYM_FUNC_START_SIZED(ebpf_jit_jmp_jeq_x)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(ebpf_jit_jmp_jeq_x))
{
	/* let hardware control cmp -> ct and disp -> ct scheduling */
	cmpedb,0 %dr_DST, %dr_SRC, %pred0
	disp %ctpr1, ebpf_jit_jmp_jeq_x
}
{
	ct %ctpr1 ? %pred0
}
SYM_FUNC_END_SIZED(ebpf_jit_jmp_jeq_x)

SYM_FUNC_START_SIZED(ebpf_jit_jmp32_jeq_x)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(ebpf_jit_jmp32_jeq_x))
{
	/* let hardware control cmp -> ct and disp -> ct scheduling */
	cmpesb,0 %r_DST, %r_SRC, %pred0
	disp %ctpr1, ebpf_jit_jmp32_jeq_x
}
{
	ct %ctpr1 ? %pred0
}
SYM_FUNC_END_SIZED(ebpf_jit_jmp32_jeq_x)

SYM_FUNC_START_SIZED(ebpf_jit_jmp_jne_x)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(ebpf_jit_jmp_jne_x))
{
	/* let hardware control cmp -> ct and disp -> ct scheduling */
	cmpedb,0 %dr_DST, %dr_SRC, %pred0
	disp %ctpr1, ebpf_jit_jmp_jne_x
}
{
	ct %ctpr1 ? ~ %pred0
}
SYM_FUNC_END_SIZED(ebpf_jit_jmp_jne_x)

SYM_FUNC_START_SIZED(ebpf_jit_jmp32_jne_x)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(ebpf_jit_jmp32_jne_x))
{
	/* let hardware control cmp -> ct and disp -> ct scheduling */
	cmpesb,0 %r_DST, %r_SRC, %pred0
	disp %ctpr1, ebpf_jit_jmp32_jne_x
}
{
	ct %ctpr1 ? ~ %pred0
}
SYM_FUNC_END_SIZED(ebpf_jit_jmp32_jne_x)

SYM_FUNC_START_SIZED(ebpf_jit_jmp_jgt_x)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(ebpf_jit_jmp_jgt_x))
{
	/* let hardware control cmp -> ct and disp -> ct scheduling */
	cmpbedb,0 %dr_DST, %dr_SRC, %pred0
	disp %ctpr1, ebpf_jit_jmp_jgt_x
}
{
	ct %ctpr1 ? ~ %pred0
}
SYM_FUNC_END_SIZED(ebpf_jit_jmp_jgt_x)

SYM_FUNC_START_SIZED(ebpf_jit_jmp32_jgt_x)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(ebpf_jit_jmp32_jgt_x))
{
	/* let hardware control cmp -> ct and disp -> ct scheduling */
	cmpbesb,0 %r_DST, %r_SRC, %pred0
	disp %ctpr1, ebpf_jit_jmp32_jgt_x
}
{
	ct %ctpr1 ? ~ %pred0
}
SYM_FUNC_END_SIZED(ebpf_jit_jmp32_jgt_x)

SYM_FUNC_START_SIZED(ebpf_jit_jmp_jge_x)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(ebpf_jit_jmp_jge_x))
{
	/* let hardware control cmp -> ct and disp -> ct scheduling */
	cmpbdb,0 %dr_DST, %dr_SRC, %pred0
	disp %ctpr1, ebpf_jit_jmp_jge_x
}
{
	ct %ctpr1 ? ~ %pred0
}
SYM_FUNC_END_SIZED(ebpf_jit_jmp_jge_x)

SYM_FUNC_START_SIZED(ebpf_jit_jmp32_jge_x)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(ebpf_jit_jmp32_jge_x))
{
	/* let hardware control cmp -> ct and disp -> ct scheduling */
	cmpbsb,0 %r_DST, %r_SRC, %pred0
	disp %ctpr1, ebpf_jit_jmp32_jge_x
}
{
	ct %ctpr1 ? ~ %pred0
}
SYM_FUNC_END_SIZED(ebpf_jit_jmp32_jge_x)

SYM_FUNC_START_SIZED(ebpf_jit_jmp_jlt_x)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(ebpf_jit_jmp_jlt_x))
{
	/* let hardware control cmp -> ct and disp -> ct scheduling */
	cmpbdb,0 %dr_DST, %dr_SRC, %pred0
	disp %ctpr1, ebpf_jit_jmp_jlt_x
}
{
	ct %ctpr1 ? %pred0
}
SYM_FUNC_END_SIZED(ebpf_jit_jmp_jlt_x)

SYM_FUNC_START_SIZED(ebpf_jit_jmp32_jlt_x)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(ebpf_jit_jmp32_jlt_x))
{
	/* let hardware control cmp -> ct and disp -> ct scheduling */
	cmpbsb,0 %r_DST, %r_SRC, %pred0
	disp %ctpr1, ebpf_jit_jmp32_jlt_x
}
{
	ct %ctpr1 ? %pred0
}
SYM_FUNC_END_SIZED(ebpf_jit_jmp32_jlt_x)

SYM_FUNC_START_SIZED(ebpf_jit_jmp_jle_x)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(ebpf_jit_jmp_jle_x))
{
	/* let hardware control cmp -> ct and disp -> ct scheduling */
	cmpbedb,0 %dr_DST, %dr_SRC, %pred0
	disp %ctpr1, ebpf_jit_jmp_jle_x
}
{
	ct %ctpr1 ? %pred0
}
SYM_FUNC_END_SIZED(ebpf_jit_jmp_jle_x)

SYM_FUNC_START_SIZED(ebpf_jit_jmp32_jle_x)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(ebpf_jit_jmp32_jle_x))
{
	/* let hardware control cmp -> ct and disp -> ct scheduling */
	cmpbesb,0 %r_DST, %r_SRC, %pred0
	disp %ctpr1, ebpf_jit_jmp32_jle_x
}
{
	ct %ctpr1 ? %pred0
}
SYM_FUNC_END_SIZED(ebpf_jit_jmp32_jle_x)

SYM_FUNC_START_SIZED(ebpf_jit_jmp_jsgt_x)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(ebpf_jit_jmp_jsgt_x))
{
	/* let hardware control cmp -> ct and disp -> ct scheduling */
	cmpledb,0 %dr_DST, %dr_SRC, %pred0
	disp %ctpr1, ebpf_jit_jmp_jsgt_x
}
{
	ct %ctpr1 ? ~ %pred0
}
SYM_FUNC_END_SIZED(ebpf_jit_jmp_jsgt_x)

SYM_FUNC_START_SIZED(ebpf_jit_jmp32_jsgt_x)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(ebpf_jit_jmp32_jsgt_x))
{
	/* let hardware control cmp -> ct and disp -> ct scheduling */
	cmplesb,0 %r_DST, %r_SRC, %pred0
	disp %ctpr1, ebpf_jit_jmp32_jsgt_x
}
{
	ct %ctpr1 ? ~ %pred0
}
SYM_FUNC_END_SIZED(ebpf_jit_jmp32_jsgt_x)

SYM_FUNC_START_SIZED(ebpf_jit_jmp_jsge_x)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(ebpf_jit_jmp_jsge_x))
{
	/* let hardware control cmp -> ct and disp -> ct scheduling */
	cmpldb,0 %dr_DST, %dr_SRC, %pred0
	disp %ctpr1, ebpf_jit_jmp_jsge_x
}
{
	ct %ctpr1 ? ~ %pred0
}
SYM_FUNC_END_SIZED(ebpf_jit_jmp_jsge_x)

SYM_FUNC_START_SIZED(ebpf_jit_jmp32_jsge_x)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(ebpf_jit_jmp32_jsge_x))
{
	/* let hardware control cmp -> ct and disp -> ct scheduling */
	cmplsb,0 %r_DST, %r_SRC, %pred0
	disp %ctpr1, ebpf_jit_jmp32_jsge_x
}
{
	ct %ctpr1 ? ~ %pred0
}
SYM_FUNC_END_SIZED(ebpf_jit_jmp32_jsge_x)

SYM_FUNC_START_SIZED(ebpf_jit_jmp_jslt_x)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(ebpf_jit_jmp_jslt_x))
{
	/* let hardware control cmp -> ct and disp -> ct scheduling */
	cmpldb,0 %dr_DST, %dr_SRC, %pred0
	disp %ctpr1, ebpf_jit_jmp_jslt_x
}
{
	ct %ctpr1 ? %pred0
}
SYM_FUNC_END_SIZED(ebpf_jit_jmp_jslt_x)

SYM_FUNC_START_SIZED(ebpf_jit_jmp32_jslt_x)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(ebpf_jit_jmp32_jslt_x))
{
	/* let hardware control cmp -> ct and disp -> ct scheduling */
	cmplsb,0 %r_DST, %r_SRC, %pred0
	disp %ctpr1, ebpf_jit_jmp32_jslt_x
}
{
	ct %ctpr1 ? %pred0
}
SYM_FUNC_END_SIZED(ebpf_jit_jmp32_jslt_x)

SYM_FUNC_START_SIZED(ebpf_jit_jmp_jsle_x)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(ebpf_jit_jmp_jsle_x))
{
	/* let hardware control cmp -> ct and disp -> ct scheduling */
	cmpledb,0 %dr_DST, %dr_SRC, %pred0
	disp %ctpr1, ebpf_jit_jmp_jsle_x
}
{
	ct %ctpr1 ? %pred0
}
SYM_FUNC_END_SIZED(ebpf_jit_jmp_jsle_x)

SYM_FUNC_START_SIZED(ebpf_jit_jmp32_jsle_x)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(ebpf_jit_jmp32_jsle_x))
{
	/* let hardware control cmp -> ct and disp -> ct scheduling */
	cmplesb,0 %r_DST, %r_SRC, %pred0
	disp %ctpr1, ebpf_jit_jmp32_jsle_x
}
{
	ct %ctpr1 ? %pred0
}
SYM_FUNC_END_SIZED(ebpf_jit_jmp32_jsle_x)

SYM_FUNC_START_SIZED(ebpf_jit_jmp_jset_x)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(ebpf_jit_jmp_jset_x))
{
	andd,0 %dr_DST, %dr_SRC, %dr_TMP1
	disp %ctpr1, ebpf_jit_jmp_jset_x
}
{
	/* let hardware control cmp -> ct and disp -> ct scheduling */
	cmpedb,0 %dr_TMP1, 0x0, %pred0
}
{
	ct %ctpr1 ? ~ %pred0
}
SYM_FUNC_END_SIZED(ebpf_jit_jmp_jset_x)

SYM_FUNC_START_SIZED(ebpf_jit_jmp32_jset_x)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(ebpf_jit_jmp32_jset_x))
{
	ands,0 %r_DST, %r_SRC, %r_TMP1
	disp %ctpr1, ebpf_jit_jmp32_jset_x
}
{
	/* let hardware control cmp -> ct and disp -> ct scheduling */
	cmpesb,0 %r_TMP1, 0x0, %pred0
}
{
	ct %ctpr1 ? ~ %pred0
}
SYM_FUNC_END_SIZED(ebpf_jit_jmp32_jset_x)

SYM_FUNC_START_SIZED(ebpf_jit_jmp_jeq_k)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(ebpf_jit_jmp_jeq_k))
BPF_TEMPL_LABEL(BPF_JIT_IMM_LABEL(ebpf_jit_jmp_jeq_k))
{
	/* let hardware control cmp -> ct and disp -> ct scheduling */
	cmpedb,0 %dr_DST, _f32s,_lts0 0x0, %pred0
	disp %ctpr1, ebpf_jit_jmp_jeq_k
}
{
	ct %ctpr1 ? %pred0
}
SYM_FUNC_END_SIZED(ebpf_jit_jmp_jeq_k)

SYM_FUNC_START_SIZED(ebpf_jit_jmp32_jeq_k)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(ebpf_jit_jmp32_jeq_k))
BPF_TEMPL_LABEL(BPF_JIT_IMM_LABEL(ebpf_jit_jmp32_jeq_k))
{
	/* let hardware control cmp -> ct and disp -> ct scheduling */
	cmpesb,0 %r_DST, _f32s,_lts0 0x0, %pred0
	disp %ctpr1, ebpf_jit_jmp32_jeq_k
}
{
	ct %ctpr1 ? %pred0
}
SYM_FUNC_END_SIZED(ebpf_jit_jmp32_jeq_k)

SYM_FUNC_START_SIZED(ebpf_jit_jmp_jne_k)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(ebpf_jit_jmp_jne_k))
BPF_TEMPL_LABEL(BPF_JIT_IMM_LABEL(ebpf_jit_jmp_jne_k))
{
	/* let hardware control cmp -> ct and disp -> ct scheduling */
	cmpedb,0 %dr_DST, _f32s,_lts0 0x0, %pred0
	disp %ctpr1, ebpf_jit_jmp_jne_k
}
{
	ct %ctpr1 ? ~ %pred0
}
SYM_FUNC_END_SIZED(ebpf_jit_jmp_jne_k)

SYM_FUNC_START_SIZED(ebpf_jit_jmp32_jne_k)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(ebpf_jit_jmp32_jne_k))
BPF_TEMPL_LABEL(BPF_JIT_IMM_LABEL(ebpf_jit_jmp32_jne_k))
{
	/* let hardware control cmp -> ct and disp -> ct scheduling */
	cmpesb,0 %r_DST, _f32s,_lts0 0x0, %pred0
	disp %ctpr1, ebpf_jit_jmp32_jne_k
}
{
	ct %ctpr1 ? ~ %pred0
}
SYM_FUNC_END_SIZED(ebpf_jit_jmp32_jne_k)

SYM_FUNC_START_SIZED(ebpf_jit_jmp_jgt_k)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(ebpf_jit_jmp_jgt_k))
BPF_TEMPL_LABEL(BPF_JIT_IMM_LABEL(ebpf_jit_jmp_jgt_k))
{
	/* let hardware control cmp -> ct and disp -> ct scheduling */
	cmpbedb,0 %dr_DST, _f32s,_lts0 0x0, %pred0
	disp %ctpr1, ebpf_jit_jmp_jgt_k
}
{
	ct %ctpr1 ? ~ %pred0
}
SYM_FUNC_END_SIZED(ebpf_jit_jmp_jgt_k)

SYM_FUNC_START_SIZED(ebpf_jit_jmp32_jgt_k)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(ebpf_jit_jmp32_jgt_k))
BPF_TEMPL_LABEL(BPF_JIT_IMM_LABEL(ebpf_jit_jmp32_jgt_k))
{
	/* let hardware control cmp -> ct and disp -> ct scheduling */
	cmpbesb,0 %r_DST, _f32s,_lts0 0x0, %pred0
	disp %ctpr1, ebpf_jit_jmp32_jgt_k
}
{
	ct %ctpr1 ? ~ %pred0
}
SYM_FUNC_END_SIZED(ebpf_jit_jmp32_jgt_k)

SYM_FUNC_START_SIZED(ebpf_jit_jmp_jge_k)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(ebpf_jit_jmp_jge_k))
BPF_TEMPL_LABEL(BPF_JIT_IMM_LABEL(ebpf_jit_jmp_jge_k))
{
	/* let hardware control cmp -> ct and disp -> ct scheduling */
	cmpbdb,0 %dr_DST, _f32s,_lts0 0x0, %pred0
	disp %ctpr1, ebpf_jit_jmp_jge_k
}
{
	ct %ctpr1 ? ~ %pred0
}
SYM_FUNC_END_SIZED(ebpf_jit_jmp_jge_k)

SYM_FUNC_START_SIZED(ebpf_jit_jmp32_jge_k)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(ebpf_jit_jmp32_jge_k))
BPF_TEMPL_LABEL(BPF_JIT_IMM_LABEL(ebpf_jit_jmp32_jge_k))
{
	/* let hardware control cmp -> ct and disp -> ct scheduling */
	cmpbsb,0 %r_DST, _f32s,_lts0 0x0, %pred0
	disp %ctpr1, ebpf_jit_jmp32_jge_k
}
{
	ct %ctpr1 ? ~ %pred0
}
SYM_FUNC_END_SIZED(ebpf_jit_jmp32_jge_k)

SYM_FUNC_START_SIZED(ebpf_jit_jmp_jlt_k)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(ebpf_jit_jmp_jlt_k))
BPF_TEMPL_LABEL(BPF_JIT_IMM_LABEL(ebpf_jit_jmp_jlt_k))
{
	/* let hardware control cmp -> ct and disp -> ct scheduling */
	cmpbdb,0 %dr_DST, _f32s,_lts0 0x0, %pred0
	disp %ctpr1, ebpf_jit_jmp_jlt_k
}
{
	ct %ctpr1 ? %pred0
}
SYM_FUNC_END_SIZED(ebpf_jit_jmp_jlt_k)

SYM_FUNC_START_SIZED(ebpf_jit_jmp32_jlt_k)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(ebpf_jit_jmp32_jlt_k))
BPF_TEMPL_LABEL(BPF_JIT_IMM_LABEL(ebpf_jit_jmp32_jlt_k))
{
	/* let hardware control cmp -> ct and disp -> ct scheduling */
	cmpbsb,0 %r_DST, _f32s,_lts0 0x0, %pred0
	disp %ctpr1, ebpf_jit_jmp32_jlt_k
}
{
	ct %ctpr1 ? %pred0
}
SYM_FUNC_END_SIZED(ebpf_jit_jmp32_jlt_k)

SYM_FUNC_START_SIZED(ebpf_jit_jmp_jle_k)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(ebpf_jit_jmp_jle_k))
BPF_TEMPL_LABEL(BPF_JIT_IMM_LABEL(ebpf_jit_jmp_jle_k))
{
	/* let hardware control cmp -> ct and disp -> ct scheduling */
	cmpbedb,0 %dr_DST, _f32s,_lts0 0x0, %pred0
	disp %ctpr1, ebpf_jit_jmp_jle_k
}
{
	ct %ctpr1 ? %pred0
}
SYM_FUNC_END_SIZED(ebpf_jit_jmp_jle_k)

SYM_FUNC_START_SIZED(ebpf_jit_jmp32_jle_k)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(ebpf_jit_jmp32_jle_k))
BPF_TEMPL_LABEL(BPF_JIT_IMM_LABEL(ebpf_jit_jmp32_jle_k))
{
	/* let hardware control cmp -> ct and disp -> ct scheduling */
	cmpbesb,0 %r_DST, _f32s,_lts0 0x0, %pred0
	disp %ctpr1, ebpf_jit_jmp32_jle_k
}
{
	ct %ctpr1 ? %pred0
}
SYM_FUNC_END_SIZED(ebpf_jit_jmp32_jle_k)

SYM_FUNC_START_SIZED(ebpf_jit_jmp_jsgt_k)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(ebpf_jit_jmp_jsgt_k))
BPF_TEMPL_LABEL(BPF_JIT_IMM_LABEL(ebpf_jit_jmp_jsgt_k))
{
	/* let hardware control cmp -> ct and disp -> ct scheduling */
	cmpledb,0 %dr_DST, _f32s,_lts0 0x0, %pred0
	disp %ctpr1, ebpf_jit_jmp_jsgt_k
}
{
	ct %ctpr1 ? ~ %pred0
}
SYM_FUNC_END_SIZED(ebpf_jit_jmp_jsgt_k)

SYM_FUNC_START_SIZED(ebpf_jit_jmp32_jsgt_k)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(ebpf_jit_jmp32_jsgt_k))
BPF_TEMPL_LABEL(BPF_JIT_IMM_LABEL(ebpf_jit_jmp32_jsgt_k))
{
	/* let hardware control cmp -> ct and disp -> ct scheduling */
	cmplesb,0 %r_DST, _f32s,_lts0 0x0, %pred0
	disp %ctpr1, ebpf_jit_jmp32_jsgt_k
}
{
	ct %ctpr1 ? ~ %pred0
}
SYM_FUNC_END_SIZED(ebpf_jit_jmp32_jsgt_k)

SYM_FUNC_START_SIZED(ebpf_jit_jmp_jsge_k)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(ebpf_jit_jmp_jsge_k))
BPF_TEMPL_LABEL(BPF_JIT_IMM_LABEL(ebpf_jit_jmp_jsge_k))
{
	/* let hardware control cmp -> ct and disp -> ct scheduling */
	cmpldb,0 %dr_DST, _f32s,_lts0 0x0, %pred0
	disp %ctpr1, ebpf_jit_jmp_jsge_k
}
{
	ct %ctpr1 ? ~ %pred0
}
SYM_FUNC_END_SIZED(ebpf_jit_jmp_jsge_k)

SYM_FUNC_START_SIZED(ebpf_jit_jmp32_jsge_k)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(ebpf_jit_jmp32_jsge_k))
BPF_TEMPL_LABEL(BPF_JIT_IMM_LABEL(ebpf_jit_jmp32_jsge_k))
{
	/* let hardware control cmp -> ct and disp -> ct scheduling */
	cmplsb,0 %r_DST, _f32s,_lts0 0x0, %pred0
	disp %ctpr1, ebpf_jit_jmp32_jsge_k
}
{
	ct %ctpr1 ? ~ %pred0
}
SYM_FUNC_END_SIZED(ebpf_jit_jmp32_jsge_k)

SYM_FUNC_START_SIZED(ebpf_jit_jmp_jslt_k)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(ebpf_jit_jmp_jslt_k))
BPF_TEMPL_LABEL(BPF_JIT_IMM_LABEL(ebpf_jit_jmp_jslt_k))
{
	/* let hardware control cmp -> ct and disp -> ct scheduling */
	cmpldb,0 %dr_DST, _f32s,_lts0 0x0, %pred0
	disp %ctpr1, ebpf_jit_jmp_jslt_k
}
{
	ct %ctpr1 ? %pred0
}
SYM_FUNC_END_SIZED(ebpf_jit_jmp_jslt_k)

SYM_FUNC_START_SIZED(ebpf_jit_jmp32_jslt_k)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(ebpf_jit_jmp32_jslt_k))
BPF_TEMPL_LABEL(BPF_JIT_IMM_LABEL(ebpf_jit_jmp32_jslt_k))
{
	/* let hardware control cmp -> ct and disp -> ct scheduling */
	cmplsb,0 %r_DST, _f32s,_lts0 0x0, %pred0
	disp %ctpr1, ebpf_jit_jmp32_jslt_k
}
{
	ct %ctpr1 ? %pred0
}
SYM_FUNC_END_SIZED(ebpf_jit_jmp32_jslt_k)

SYM_FUNC_START_SIZED(ebpf_jit_jmp_jsle_k)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(ebpf_jit_jmp_jsle_k))
BPF_TEMPL_LABEL(BPF_JIT_IMM_LABEL(ebpf_jit_jmp_jsle_k))
{
	/* let hardware control cmp -> ct and disp -> ct scheduling */
	cmpledb,0 %dr_DST, _f32s,_lts0 0x0, %pred0
	disp %ctpr1, ebpf_jit_jmp_jsle_k
}
{
	ct %ctpr1 ? %pred0
}
SYM_FUNC_END_SIZED(ebpf_jit_jmp_jsle_k)

SYM_FUNC_START_SIZED(ebpf_jit_jmp32_jsle_k)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(ebpf_jit_jmp32_jsle_k))
BPF_TEMPL_LABEL(BPF_JIT_IMM_LABEL(ebpf_jit_jmp32_jsle_k))
{
	/* let hardware control cmp -> ct and disp -> ct scheduling */
	cmplesb,0 %r_DST, _f32s,_lts0 0x0, %pred0
	disp %ctpr1, ebpf_jit_jmp32_jsle_k
}
{
	ct %ctpr1 ? %pred0
}
SYM_FUNC_END_SIZED(ebpf_jit_jmp32_jsle_k)

SYM_FUNC_START_SIZED(ebpf_jit_jmp_jset_k)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(ebpf_jit_jmp_jset_k))
BPF_TEMPL_LABEL(BPF_JIT_IMM_LABEL(ebpf_jit_jmp_jset_k))
{
	andd,0 %dr_DST, _f32s,_lts0 0x0, %dr_TMP1
	disp %ctpr1, ebpf_jit_jmp32_jset_k
}
{
	/* let hardware control cmp -> ct and disp -> ct scheduling */
	cmpedb,0 %dr_TMP1, 0x0, %pred0
}
{
	ct %ctpr1 ? ~ %pred0
}
SYM_FUNC_END_SIZED(ebpf_jit_jmp_jset_k)

SYM_FUNC_START_SIZED(ebpf_jit_jmp32_jset_k)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(ebpf_jit_jmp32_jset_k))
BPF_TEMPL_LABEL(BPF_JIT_IMM_LABEL(ebpf_jit_jmp32_jset_k))
{
	ands,0 %r_DST, _f32s,_lts0 0x0, %r_TMP1
	disp %ctpr1, ebpf_jit_jmp32_jset_k
}
{
	/* let hardware control cmp -> ct and disp -> ct scheduling */
	cmpesb,0 %r_TMP1, 0x0, %pred0
}
{
	ct %ctpr1 ? ~ %pred0
}
SYM_FUNC_END_SIZED(ebpf_jit_jmp32_jset_k)

/* Template for calling kernel functions */
SYM_FUNC_START_SIZED(ebpf_jit_jmp_call_hlp)
BPF_TEMPL_LABEL(BPF_JIT_FUNC_LABEL(ebpf_jit_jmp_call_hlp))
{
	nop 3
	disp %ctpr1, $ebpf_jit_jmp_call_hlp
}
{
	addd,0,sm %R1, 0x0, %db[0]
	addd,1,sm %R2, 0x0, %db[1]
	addd,2,sm %R3, 0x0, %db[2]
}
BPF_TEMPL_LABEL(BPF_JIT_WBS_LABEL(ebpf_jit_jmp_call_hlp))
{
	addd,0,sm %R4, 0x0, %db[3]
	addd,1,sm %R5, 0x0, %db[4]
	call %ctpr1, wbs = 0x0
}
{
	addd,0 %db[0], 0x0, %R0
}
SYM_FUNC_END_SIZED(ebpf_jit_jmp_call_hlp)

/* Template for calling eBPF subprograms */
SYM_FUNC_START_SIZED(ebpf_jit_jmp_call_bpf)
BPF_TEMPL_LABEL(BPF_JIT_FUNC_LABEL(ebpf_jit_jmp_call_bpf))
{
	nop 3
	disp %ctpr1, $ebpf_jit_jmp_call_bpf
}
{
	addd,0,sm %R1, 0x0, %db_R1
	addd,1,sm %R2, 0x0, %db_R2
	addd,2,sm %R3, 0x0, %db_R3
}
BPF_TEMPL_LABEL(BPF_JIT_WBS_LABEL(ebpf_jit_jmp_call_bpf))
{
	addd,0,sm %R4, 0x0, %db_R4
	addd,1,sm %R5, 0x0, %db_R5
	/* pass tail call counter to subprogram */
	adds,2 %r_TAIL_CALL_CNT, 0x0, %b[7]
	call %ctpr1, wbs = 0x0
}
{
	addd,0 %db[0], 0x0, %R0
	/* restore tail call counter after call */
	adds,1 0x0, %b[7], %r_TAIL_CALL_CNT
}
SYM_FUNC_END_SIZED(ebpf_jit_jmp_call_bpf)

/* Template for tail call to another eBPF program */
SYM_FUNC_START_SIZED(ebpf_jit_jmp_tail_call)
BPF_TEMPL_LABEL(BPF_JIT_JMP_LABEL(ebpf_jit_jmp_tail_call))
{
	cmpbsb,0 %r_TAIL_CALL_CNT, MAX_TAIL_CALL_CNT, %pred0
	muld,1 %R3, SIZEOF_BPF_ARRAY_PTRS, %dr_TMP2
	addd,2 %R2, BPF_ARRAY_MAP, %dr_TMP1
	disp %ctpr1, $out
}
ALTERNATIVE_1_ALTINSTR
	{
		nop 4
		ldw,0 [ %dr_TMP1 + BPF_MAP_MAX_ENTRIES ], %r_TMP1
	}
ALTERNATIVE_2_OLDINSTR
	{
		nop 2
		ldw,0 [ %dr_TMP1 + BPF_MAP_MAX_ENTRIES ], %r_TMP1
	}
ALTERNATIVE_3_FEATURE(CPU_FEAT_ISET_V6)
{
	cmpbsb,0 %R3, %r_TMP1, %pred1
}
{
	/* scheduling clp -> ct is under hardware control */
	pass %pred0, @p0
	pass %pred1, @p1
	andp @p0, @p1, @p4
	pass @p4, %pred2
}
{
	ct %ctpr1 ? ~ %pred2
	adds,0 0x1, %r_TAIL_CALL_CNT, %r_TAIL_CALL_CNT ? %pred2
	adds,1 %r_TMP2, BPF_ARRAY_PTRS, %r_TMP2
}
ALTERNATIVE_1_ALTINSTR
	{
		nop 4
		ldd,0 [ %R2 + %dr_TMP2 ], %dr_TMP2
	}
	{
		/* scheduling clp -> ct is under hardware control */
		cmpedb 0x0, %dr_TMP2, %pred0
	}
	{
		nop 4
		ct %ctpr1 ? %pred0
		ldd,0 %dr_TMP2, BPF_PROG_BPF_FUNC, %dr_TMP1 ? ~ %pred0
	}
	{
		nop 4
		ldw,0 %dr_TMP1, -TAIL_CALL_OFFSET_SIZE, %r_TMP2
	}
ALTERNATIVE_2_OLDINSTR
	{
		nop 2
		ldd,0 [ %R2 + %dr_TMP2 ], %dr_TMP2
	}
	{
		/* scheduling clp -> ct is under hardware control */
		cmpedb 0x0, %dr_TMP2, %pred0
	}
	{
		nop 2
		ct %ctpr1 ? %pred0
		ldd,0 %dr_TMP2, BPF_PROG_BPF_FUNC, %dr_TMP1 ? ~ %pred0
	}
	{
		nop 2
		ldw,0 %dr_TMP1, -TAIL_CALL_OFFSET_SIZE, %r_TMP2
	}
ALTERNATIVE_3_FEATURE(CPU_FEAT_ISET_V6)
{
	addd,0 %dr_TMP1, %dr_TMP2, %dr_TMP1
}
{
	/* scheduling movtd -> ct is under hardware control */
	movtd,0 %dr_TMP1, %ctpr1
}
BPF_TEMPL_LABEL(BPF_JIT_STACK_SIZE_LABEL(ebpf_jit_jmp_tail_call))
{
	getsp,0 _f32s,_lts1 0x0, %R10
	addd,1 0x0, %R1, %dr0
	adds,2 0x0, %r_TAIL_CALL_CNT, %r7
	ct %ctpr1
}
/*
 * Attention: jump to 'out:' must be a jump to the start of next command.
 * When we implement a HW bug 146897 workaround, the address of the end of this
 * template and the start address of the next one may differ. So this template
 * contains an artificial label that allows JIT to insert a proper offset
 * if needed.
 */
out:
SYM_FUNC_END_SIZED(ebpf_jit_jmp_tail_call)

/* Templates for loading an storing data */
SYM_FUNC_START_SIZED(ebpf_jit_stx_mem_b)
BPF_TEMPL_LABEL(BPF_JIT_OFF_LABEL(ebpf_jit_stx_mem_b))
{
	stb,2 %r_SRC, [ %dr_DST + _f32s,_lts0 0x0 ]
}
SYM_FUNC_END_SIZED(ebpf_jit_stx_mem_b)

SYM_FUNC_START_SIZED(ebpf_jit_st_mem_b)
BPF_TEMPL_LABEL(BPF_JIT_IMM_LABEL(ebpf_jit_st_mem_b))
{
	adds,0 0x0, _f32s,_lts0 0x0, %r_TMP1
}
BPF_TEMPL_LABEL(BPF_JIT_OFF_LABEL(ebpf_jit_st_mem_b))
{
	stb,2 %r_TMP1, [ %dr_DST + _f32s,_lts0 0x0 ]
}
SYM_FUNC_END_SIZED(ebpf_jit_st_mem_b)

SYM_FUNC_START_SIZED(ebpf_jit_ldx_mem_b)
BPF_TEMPL_LABEL(BPF_JIT_OFF_LABEL(ebpf_jit_ldx_mem_b))
ALTERNATIVE_1_ALTINSTR
	{
		nop 4
		ldb,0 [ %dr_SRC + _f32s,_lts0 0x0 ], %r_DST
	}
ALTERNATIVE_2_OLDINSTR
	{
		nop 2
		ldb,0 [ %dr_SRC + _f32s,_lts0 0x0 ], %r_DST
	}
ALTERNATIVE_3_FEATURE(CPU_FEAT_ISET_V6)
SYM_FUNC_END_SIZED(ebpf_jit_ldx_mem_b)

SYM_FUNC_START_SIZED(ebpf_jit_stx_mem_h)
BPF_TEMPL_LABEL(BPF_JIT_OFF_LABEL(ebpf_jit_stx_mem_h))
{
	sth,2 %r_SRC, [ %dr_DST + _f32s,_lts0 0x0 ]
}
SYM_FUNC_END_SIZED(ebpf_jit_stx_mem_h)

SYM_FUNC_START_SIZED(ebpf_jit_st_mem_h)
BPF_TEMPL_LABEL(BPF_JIT_IMM_LABEL(ebpf_jit_st_mem_h))
{
	adds,0 0x0, _f32s,_lts0 0x0, %r_TMP1
}
BPF_TEMPL_LABEL(BPF_JIT_OFF_LABEL(ebpf_jit_st_mem_h))
{
	sth,2 %r_TMP1, [ %dr_DST + _f32s,_lts0 0x0 ]
}
SYM_FUNC_END_SIZED(ebpf_jit_st_mem_h)

SYM_FUNC_START_SIZED(ebpf_jit_ldx_mem_h)
BPF_TEMPL_LABEL(BPF_JIT_OFF_LABEL(ebpf_jit_ldx_mem_h))
ALTERNATIVE_1_ALTINSTR
	{
		nop 4
		ldh,0 [ %dr_SRC + _f32s,_lts0 0x0 ], %r_DST
	}
ALTERNATIVE_2_OLDINSTR
	{
		nop 2
		ldh,0 [ %dr_SRC + _f32s,_lts0 0x0 ], %r_DST
	}
ALTERNATIVE_3_FEATURE(CPU_FEAT_ISET_V6)
SYM_FUNC_END_SIZED(ebpf_jit_ldx_mem_h)

SYM_FUNC_START_SIZED(ebpf_jit_stx_mem_w)
BPF_TEMPL_LABEL(BPF_JIT_OFF_LABEL(ebpf_jit_stx_mem_w))
{
	stw,2 %r_SRC, [ %dr_DST + _f32s,_lts0 0x0 ]
}
SYM_FUNC_END_SIZED(ebpf_jit_stx_mem_w)

SYM_FUNC_START_SIZED(ebpf_jit_st_mem_w)
BPF_TEMPL_LABEL(BPF_JIT_IMM_LABEL(ebpf_jit_st_mem_w))
{
	adds,0 0x0, _f32s,_lts0 0x0, %r_TMP1
}
BPF_TEMPL_LABEL(BPF_JIT_OFF_LABEL(ebpf_jit_st_mem_w))
{
	stw,2 %r_TMP1, [ %dr_DST + _f32s,_lts0 0x0 ]
}
SYM_FUNC_END_SIZED(ebpf_jit_st_mem_w)

SYM_FUNC_START_SIZED(ebpf_jit_ldx_mem_w)
BPF_TEMPL_LABEL(BPF_JIT_OFF_LABEL(ebpf_jit_ldx_mem_w))
ALTERNATIVE_1_ALTINSTR
	{
		nop 4
		ldw,0 [ %dr_SRC + _f32s,_lts0 0x0 ], %r_DST
	}
ALTERNATIVE_2_OLDINSTR
	{
		nop 2
		ldw,0 [ %dr_SRC + _f32s,_lts0 0x0 ], %r_DST
	}
ALTERNATIVE_3_FEATURE(CPU_FEAT_ISET_V6)
SYM_FUNC_END_SIZED(ebpf_jit_ldx_mem_w)

SYM_FUNC_START_SIZED(ebpf_jit_stx_mem_dw)
BPF_TEMPL_LABEL(BPF_JIT_OFF_LABEL(ebpf_jit_stx_mem_dw))
{
	std,2 %dr_SRC, [ %dr_DST + _f32s,_lts0 0x0 ]
}
SYM_FUNC_END_SIZED(ebpf_jit_stx_mem_dw)

SYM_FUNC_START_SIZED(ebpf_jit_st_mem_dw)
BPF_TEMPL_LABEL(BPF_JIT_IMM_LABEL(ebpf_jit_st_mem_dw))
{
	addd,0 0x0, _f32s,_lts0 0x0, %dr_TMP1
}
BPF_TEMPL_LABEL(BPF_JIT_OFF_LABEL(ebpf_jit_st_mem_dw))
{
	std,2 %dr_TMP1, [ %dr_DST + _f32s,_lts0 0x0 ]
}
SYM_FUNC_END_SIZED(ebpf_jit_st_mem_dw)

SYM_FUNC_START_SIZED(ebpf_jit_ldx_mem_dw)
BPF_TEMPL_LABEL(BPF_JIT_OFF_LABEL(ebpf_jit_ldx_mem_dw))
ALTERNATIVE_1_ALTINSTR
	{
		nop 4
		ldd,0 [ %dr_SRC + _f32s,_lts0 0x0 ], %dr_DST
	}
ALTERNATIVE_2_OLDINSTR
	{
		nop 2
		ldd,0 [ %dr_SRC + _f32s,_lts0 0x0 ], %dr_DST
	}
ALTERNATIVE_3_FEATURE(CPU_FEAT_ISET_V6)
SYM_FUNC_END_SIZED(ebpf_jit_ldx_mem_dw)

/*
 * Templates for atomic operations. Just call a special helper,
 * defined in the C language.
 */
SYM_FUNC_START_SIZED(ebpf_jit_stx_atomic_w_op)
BPF_TEMPL_LABEL(BPF_JIT_FUNC_LABEL(ebpf_jit_stx_atomic_w_op))
{
	nop 4
	disp %ctpr1, $ebpf_jit_stx_atomic_w_op
}
BPF_TEMPL_LABEL(BPF_JIT_OFF_LABEL(ebpf_jit_stx_atomic_w_op))
BPF_TEMPL_LABEL(BPF_JIT_WBS_LABEL(ebpf_jit_stx_atomic_w_op))
{
	adds,0 0x0, %r_SRC, %b[0]
	addd,1 %dr_DST, _f32s,_lts0 0x0, %db[1]
	call %ctpr1, wbs = 0x0
}
SYM_FUNC_END_SIZED(ebpf_jit_stx_atomic_w_op)

SYM_FUNC_START_SIZED(ebpf_jit_stx_atomic_dw_op)
BPF_TEMPL_LABEL(BPF_JIT_FUNC_LABEL(ebpf_jit_stx_atomic_dw_op))
{
	nop 4
	disp %ctpr1, $ebpf_jit_stx_atomic_dw_op
}
BPF_TEMPL_LABEL(BPF_JIT_OFF_LABEL(ebpf_jit_stx_atomic_dw_op))
BPF_TEMPL_LABEL(BPF_JIT_WBS_LABEL(ebpf_jit_stx_atomic_dw_op))
{
	addd,0 0x0, %r_SRC, %db[0]
	addd,1 %dr_DST, _f32s,_lts0 0x0, %db[1]
	call %ctpr1, wbs = 0x0
}
SYM_FUNC_END_SIZED(ebpf_jit_stx_atomic_dw_op)

SYM_FUNC_START_SIZED(ebpf_jit_stx_atomic_w_fetch_op)
BPF_TEMPL_LABEL(BPF_JIT_FUNC_LABEL(ebpf_jit_stx_atomic_w_fetch_op))
{
	nop 4
	disp %ctpr1, $ebpf_jit_stx_atomic_w_fetch_op
}
BPF_TEMPL_LABEL(BPF_JIT_OFF_LABEL(ebpf_jit_stx_atomic_w_fetch_op))
BPF_TEMPL_LABEL(BPF_JIT_WBS_LABEL(ebpf_jit_stx_atomic_w_fetch_op))
{
	adds,0 0x0, %r_SRC, %b[0]
	addd,1 %dr_DST, _f32s,_lts0 0x0, %db[1]
	call %ctpr1, wbs = 0x0
}
{
	addd,0 0x0, 0x0, %dr_SRC
	adds,1 0x0, %b[0], %r_SRC
}
SYM_FUNC_END_SIZED(ebpf_jit_stx_atomic_w_fetch_op)

SYM_FUNC_START_SIZED(ebpf_jit_stx_atomic_dw_fetch_op)
BPF_TEMPL_LABEL(BPF_JIT_FUNC_LABEL(ebpf_jit_stx_atomic_dw_fetch_op))
{
	nop 4
	disp %ctpr1, $ebpf_jit_stx_atomic_dw_fetch_op
}
BPF_TEMPL_LABEL(BPF_JIT_OFF_LABEL(ebpf_jit_stx_atomic_dw_fetch_op))
BPF_TEMPL_LABEL(BPF_JIT_WBS_LABEL(ebpf_jit_stx_atomic_dw_fetch_op))
{
	addd,0 0x0, %r_SRC, %db[0]
	addd,1 %dr_DST, _f32s,_lts0 0x0, %db[1]
	call %ctpr1, wbs = 0x0
}
{
	addd,0 0x0, %db[0], %dr_SRC
}
SYM_FUNC_END_SIZED(ebpf_jit_stx_atomic_dw_fetch_op)

SYM_FUNC_START_SIZED(ebpf_jit_stx_atomic_w_cmpxchg)
BPF_TEMPL_LABEL(BPF_JIT_FUNC_LABEL(ebpf_jit_stx_atomic_w_cmpxchg))
{
	nop 4
	disp %ctpr1, $ebpf_jit_stx_atomic_w_cmpxchg
}
BPF_TEMPL_LABEL(BPF_JIT_OFF_LABEL(ebpf_jit_stx_atomic_w_cmpxchg))
BPF_TEMPL_LABEL(BPF_JIT_WBS_LABEL(ebpf_jit_stx_atomic_w_cmpxchg))
{
	adds,0 0x0, %r_SRC, %b[0]
	addd,1 %dr_DST, _f32s,_lts0 0x0, %db[1]
	adds,2 0x0, %R0, %b[2]
	call %ctpr1, wbs = 0x0
}
{
	addd,0 0x0, 0x0, %R0
	adds,1 0x0, %b[0], %R0
}
SYM_FUNC_END_SIZED(ebpf_jit_stx_atomic_w_cmpxchg)

SYM_FUNC_START_SIZED(ebpf_jit_stx_atomic_dw_cmpxchg)
BPF_TEMPL_LABEL(BPF_JIT_FUNC_LABEL(ebpf_jit_stx_atomic_dw_cmpxchg))
{
	nop 4
	disp %ctpr1, $ebpf_jit_stx_atomic_dw_cmpxchg
}
BPF_TEMPL_LABEL(BPF_JIT_OFF_LABEL(ebpf_jit_stx_atomic_dw_cmpxchg))
BPF_TEMPL_LABEL(BPF_JIT_WBS_LABEL(ebpf_jit_stx_atomic_dw_cmpxchg))
{
	addd,0 0x0, %r_SRC, %db[0]
	addd,1 %dr_DST, _f32s,_lts0 0x0, %db[1]
	addd,2 0x0, %R0, %db[2]
	call %ctpr1, wbs = 0x0
}
{
	addd,0 0x0, %db[0], %R0
}
SYM_FUNC_END_SIZED(ebpf_jit_stx_atomic_dw_cmpxchg)

