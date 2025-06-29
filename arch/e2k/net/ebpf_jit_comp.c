/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * eBPF JIT compiler.
 */

#include <linux/filter.h>
#include <linux/types.h>
#include <asm/cpu_regs_types.h>
#include <asm/cpu_regs.h>
#include <asm/machdep.h>

#include "ebpf_jit.h"

/*
 * Insert `imm' from eBPF command into template copy.
 */
#define BPF_JIT_INSERT_IMM(template, pointer, imm, cmd_lens) \
		BPF_JIT_INSERT_IMM32(template, pointer, imm, cmd_lens, BPF_JIT_IMM_LABEL)
/*
 * Insert `off' from eBPF command into template copy.
 */
#define BPF_JIT_INSERT_OFF(template, pointer, off, cmd_lens) \
		BPF_JIT_INSERT_IMM32(template, pointer, off, cmd_lens, BPF_JIT_OFF_LABEL)

/*
 * Insert a 64-bit constant into template copy.
 *
 * This macro is a wrapper for insert_imm64(). It is identical to BPF_JIT_INSERT_IMM32()
 * except that it works with a 64-bit constant, thus receives the constant in two parts
 * `imm64_hi' and `imm64_lo'.
 */
#define BPF_JIT_INSERT_IMM64(template, pointer, imm64_hi, imm64_lo, cmd_lens) \
({ \
	unsigned int insert_imm64_offset = \
		BPF_JIT_OFFSET(BPF_JIT_IMM_LABEL(template), template); \
	insert_imm64(template, insert_imm64_offset, pointer, imm64_hi, imm64_lo, cmd_lens); \
})

/*
 * Insert required stack size to be allocated or freed in jited program.
 *
 * This macro is a wrapper for insert_stack_size(). It provides the function
 * with an offset from the start of a given template to a wide command with
 * setwd instruction.
 */
#define BPF_JIT_INSERT_STACK_SIZE(template, pointer, size, cmd_lens) \
({ \
	unsigned int insert_stack_size_offset = \
		BPF_JIT_OFFSET(BPF_JIT_STACK_SIZE_LABEL(template), template); \
	insert_stack_size(template, insert_stack_size_offset, pointer, size, cmd_lens); \
})

/*
 * Insert stack size to be allocated for jited program.
 *
 * Jited programs allocate stack frame in prologue.
 */
#define BPF_JIT_INSERT_STACK_ALLOC(template, pointer, size, cmd_lens) \
		BPF_JIT_INSERT_STACK_SIZE(template, pointer, -size, cmd_lens)

/*
 * Insert stack size to be freed in jited program.
 *
 * As hardware frees the last stack frame automatically upon function exit,
 * the only use for this macro is in tail call preparation.
 */
#define BPF_JIT_INSERT_STACK_FREE(template, pointer, size, cmd_lens) \
		BPF_JIT_INSERT_STACK_SIZE(template, pointer, size, cmd_lens)

/*
 * Declare all eBPF templates.
 */
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_prologue);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_prologue_zero_cnt);

BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu_mov_x);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu64_mov_x);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu_mov_k);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu64_mov_k);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu_add_x);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu64_add_x);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu_sub_x);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu64_sub_x);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu_and_x);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu64_and_x);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu_or_x);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu64_or_x);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu_xor_x);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu64_xor_x);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu_lsh_x);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu64_lsh_x);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu_rsh_x);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu64_rsh_x);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu_arsh_x);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu64_arsh_x);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu_mul_x);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu64_mul_x);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu_div_x);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu64_div_x);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu_mod_x);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu64_mod_x);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu_add_k);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu64_add_k);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu_sub_k);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu64_sub_k);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu_and_k);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu64_and_k);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu_or_k);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu64_or_k);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu_xor_k);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu64_xor_k);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu_lsh_k);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu64_lsh_k);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu_rsh_k);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu64_rsh_k);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu_arsh_k);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu64_arsh_k);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu_mul_k);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu64_mul_k);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu_div_k);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu64_div_k);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu_mod_k);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu64_mod_k);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu_neg);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu64_neg);

BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu_end_le16);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu_end_le32);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu_end_be16);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu_end_be32);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_alu_end_be64);

BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_jmp_exit);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_ld_imm_dw);

BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_jmp_ja);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_jmp_jeq_x);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_jmp32_jeq_x);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_jmp_jne_x);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_jmp32_jne_x);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_jmp_jgt_x);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_jmp32_jgt_x);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_jmp_jge_x);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_jmp32_jge_x);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_jmp_jlt_x);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_jmp32_jlt_x);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_jmp_jle_x);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_jmp32_jle_x);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_jmp_jsgt_x);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_jmp32_jsgt_x);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_jmp_jsge_x);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_jmp32_jsge_x);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_jmp_jslt_x);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_jmp32_jslt_x);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_jmp_jsle_x);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_jmp32_jsle_x);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_jmp_jset_x);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_jmp32_jset_x);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_jmp_jeq_k);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_jmp32_jeq_k);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_jmp_jne_k);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_jmp32_jne_k);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_jmp_jgt_k);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_jmp32_jgt_k);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_jmp_jge_k);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_jmp32_jge_k);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_jmp_jlt_k);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_jmp32_jlt_k);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_jmp_jle_k);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_jmp32_jle_k);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_jmp_jsgt_k);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_jmp32_jsgt_k);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_jmp_jsge_k);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_jmp32_jsge_k);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_jmp_jslt_k);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_jmp32_jslt_k);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_jmp_jsle_k);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_jmp32_jsle_k);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_jmp_jset_k);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_jmp32_jset_k);

BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_jmp_call_hlp);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_jmp_call_bpf);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_jmp_tail_call);

BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_stx_mem_b);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_st_mem_b);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_ldx_mem_b);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_stx_mem_h);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_st_mem_h);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_ldx_mem_h);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_stx_mem_w);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_st_mem_w);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_ldx_mem_w);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_stx_mem_dw);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_st_mem_dw);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_ldx_mem_dw);

BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_stx_atomic_w_op);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_stx_atomic_w_fetch_op);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_stx_atomic_dw_op);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_stx_atomic_dw_fetch_op);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_stx_atomic_w_cmpxchg);
BPF_JIT_EXTERN_TEMPLATE(ebpf_jit_stx_atomic_dw_cmpxchg);

/*
 * Declare labels for inserting different fields and
 * constants into template.
 */
extern char BPF_JIT_WSZ_LABEL(ebpf_jit_prologue)[];
extern char BPF_JIT_RBS_LABEL(ebpf_jit_prologue)[];
extern char BPF_JIT_STACK_SIZE_LABEL(ebpf_jit_prologue)[];

extern char BPF_JIT_STACK_SIZE_LABEL(ebpf_jit_jmp_tail_call)[];

extern char BPF_JIT_IMM_LABEL(ebpf_jit_alu_mov_k)[];
extern char BPF_JIT_IMM_LABEL(ebpf_jit_alu64_mov_k)[];

extern char BPF_JIT_IMM_LABEL(ebpf_jit_alu_add_k)[];
extern char BPF_JIT_IMM_LABEL(ebpf_jit_alu64_add_k)[];
extern char BPF_JIT_IMM_LABEL(ebpf_jit_alu_sub_k)[];
extern char BPF_JIT_IMM_LABEL(ebpf_jit_alu64_sub_k)[];
extern char BPF_JIT_IMM_LABEL(ebpf_jit_alu_and_k)[];
extern char BPF_JIT_IMM_LABEL(ebpf_jit_alu64_and_k)[];
extern char BPF_JIT_IMM_LABEL(ebpf_jit_alu_or_k)[];
extern char BPF_JIT_IMM_LABEL(ebpf_jit_alu64_or_k)[];
extern char BPF_JIT_IMM_LABEL(ebpf_jit_alu_xor_k)[];
extern char BPF_JIT_IMM_LABEL(ebpf_jit_alu64_xor_k)[];
extern char BPF_JIT_IMM_LABEL(ebpf_jit_alu_lsh_k)[];
extern char BPF_JIT_IMM_LABEL(ebpf_jit_alu64_lsh_k)[];
extern char BPF_JIT_IMM_LABEL(ebpf_jit_alu_rsh_k)[];
extern char BPF_JIT_IMM_LABEL(ebpf_jit_alu64_rsh_k)[];
extern char BPF_JIT_IMM_LABEL(ebpf_jit_alu_arsh_k)[];
extern char BPF_JIT_IMM_LABEL(ebpf_jit_alu64_arsh_k)[];
extern char BPF_JIT_IMM_LABEL(ebpf_jit_alu_mul_k)[];
extern char BPF_JIT_IMM_LABEL(ebpf_jit_alu64_mul_k)[];
extern char BPF_JIT_IMM_LABEL(ebpf_jit_alu_div_k)[];
extern char BPF_JIT_IMM_LABEL(ebpf_jit_alu64_div_k)[];
extern char BPF_JIT_IMM_LABEL(ebpf_jit_alu_mod_k)[];
extern char BPF_JIT_IMM_LABEL(ebpf_jit_alu64_mod_k)[];

extern char BPF_JIT_IMM_LABEL(ebpf_jit_jmp_jeq_k)[];
extern char BPF_JIT_IMM_LABEL(ebpf_jit_jmp32_jeq_k)[];
extern char BPF_JIT_IMM_LABEL(ebpf_jit_jmp_jne_k)[];
extern char BPF_JIT_IMM_LABEL(ebpf_jit_jmp32_jne_k)[];
extern char BPF_JIT_IMM_LABEL(ebpf_jit_jmp_jgt_k)[];
extern char BPF_JIT_IMM_LABEL(ebpf_jit_jmp32_jgt_k)[];
extern char BPF_JIT_IMM_LABEL(ebpf_jit_jmp_jge_k)[];
extern char BPF_JIT_IMM_LABEL(ebpf_jit_jmp32_jge_k)[];
extern char BPF_JIT_IMM_LABEL(ebpf_jit_jmp_jlt_k)[];
extern char BPF_JIT_IMM_LABEL(ebpf_jit_jmp32_jlt_k)[];
extern char BPF_JIT_IMM_LABEL(ebpf_jit_jmp_jle_k)[];
extern char BPF_JIT_IMM_LABEL(ebpf_jit_jmp32_jle_k)[];
extern char BPF_JIT_IMM_LABEL(ebpf_jit_jmp_jsgt_k)[];
extern char BPF_JIT_IMM_LABEL(ebpf_jit_jmp32_jsgt_k)[];
extern char BPF_JIT_IMM_LABEL(ebpf_jit_jmp_jsge_k)[];
extern char BPF_JIT_IMM_LABEL(ebpf_jit_jmp32_jsge_k)[];
extern char BPF_JIT_IMM_LABEL(ebpf_jit_jmp_jslt_k)[];
extern char BPF_JIT_IMM_LABEL(ebpf_jit_jmp32_jslt_k)[];
extern char BPF_JIT_IMM_LABEL(ebpf_jit_jmp_jsle_k)[];
extern char BPF_JIT_IMM_LABEL(ebpf_jit_jmp32_jsle_k)[];
extern char BPF_JIT_IMM_LABEL(ebpf_jit_jmp_jset_k)[];
extern char BPF_JIT_IMM_LABEL(ebpf_jit_jmp32_jset_k)[];

extern char BPF_JIT_IMM_LABEL(ebpf_jit_ld_imm_dw)[];

extern char BPF_JIT_IMM_LABEL(ebpf_jit_st_mem_b)[];
extern char BPF_JIT_IMM_LABEL(ebpf_jit_st_mem_h)[];
extern char BPF_JIT_IMM_LABEL(ebpf_jit_st_mem_w)[];
extern char BPF_JIT_IMM_LABEL(ebpf_jit_st_mem_dw)[];

extern char BPF_JIT_OFF_LABEL(ebpf_jit_stx_mem_b)[];
extern char BPF_JIT_OFF_LABEL(ebpf_jit_st_mem_b)[];
extern char BPF_JIT_OFF_LABEL(ebpf_jit_ldx_mem_b)[];
extern char BPF_JIT_OFF_LABEL(ebpf_jit_stx_mem_h)[];
extern char BPF_JIT_OFF_LABEL(ebpf_jit_st_mem_h)[];
extern char BPF_JIT_OFF_LABEL(ebpf_jit_ldx_mem_h)[];
extern char BPF_JIT_OFF_LABEL(ebpf_jit_stx_mem_w)[];
extern char BPF_JIT_OFF_LABEL(ebpf_jit_st_mem_w)[];
extern char BPF_JIT_OFF_LABEL(ebpf_jit_ldx_mem_w)[];
extern char BPF_JIT_OFF_LABEL(ebpf_jit_stx_mem_dw)[];
extern char BPF_JIT_OFF_LABEL(ebpf_jit_st_mem_dw)[];
extern char BPF_JIT_OFF_LABEL(ebpf_jit_ldx_mem_dw)[];

extern char BPF_JIT_OFF_LABEL(ebpf_jit_stx_atomic_w_op)[];
extern char BPF_JIT_OFF_LABEL(ebpf_jit_stx_atomic_w_fetch_op)[];
extern char BPF_JIT_OFF_LABEL(ebpf_jit_stx_atomic_dw_op)[];
extern char BPF_JIT_OFF_LABEL(ebpf_jit_stx_atomic_dw_fetch_op)[];
extern char BPF_JIT_OFF_LABEL(ebpf_jit_stx_atomic_w_cmpxchg)[];
extern char BPF_JIT_OFF_LABEL(ebpf_jit_stx_atomic_dw_cmpxchg)[];

extern char BPF_JIT_JMP_LABEL(ebpf_jit_jmp_ja)[];
extern char BPF_JIT_JMP_LABEL(ebpf_jit_jmp_jeq_x)[];
extern char BPF_JIT_JMP_LABEL(ebpf_jit_jmp32_jeq_x)[];
extern char BPF_JIT_JMP_LABEL(ebpf_jit_jmp_jne_x)[];
extern char BPF_JIT_JMP_LABEL(ebpf_jit_jmp32_jne_x)[];
extern char BPF_JIT_JMP_LABEL(ebpf_jit_jmp_jgt_x)[];
extern char BPF_JIT_JMP_LABEL(ebpf_jit_jmp32_jgt_x)[];
extern char BPF_JIT_JMP_LABEL(ebpf_jit_jmp_jge_x)[];
extern char BPF_JIT_JMP_LABEL(ebpf_jit_jmp32_jge_x)[];
extern char BPF_JIT_JMP_LABEL(ebpf_jit_jmp_jlt_x)[];
extern char BPF_JIT_JMP_LABEL(ebpf_jit_jmp32_jlt_x)[];
extern char BPF_JIT_JMP_LABEL(ebpf_jit_jmp_jle_x)[];
extern char BPF_JIT_JMP_LABEL(ebpf_jit_jmp32_jle_x)[];
extern char BPF_JIT_JMP_LABEL(ebpf_jit_jmp_jsgt_x)[];
extern char BPF_JIT_JMP_LABEL(ebpf_jit_jmp32_jsgt_x)[];
extern char BPF_JIT_JMP_LABEL(ebpf_jit_jmp_jsge_x)[];
extern char BPF_JIT_JMP_LABEL(ebpf_jit_jmp32_jsge_x)[];
extern char BPF_JIT_JMP_LABEL(ebpf_jit_jmp_jslt_x)[];
extern char BPF_JIT_JMP_LABEL(ebpf_jit_jmp32_jslt_x)[];
extern char BPF_JIT_JMP_LABEL(ebpf_jit_jmp_jsle_x)[];
extern char BPF_JIT_JMP_LABEL(ebpf_jit_jmp32_jsle_x)[];
extern char BPF_JIT_JMP_LABEL(ebpf_jit_jmp_jset_x)[];
extern char BPF_JIT_JMP_LABEL(ebpf_jit_jmp32_jset_x)[];
extern char BPF_JIT_JMP_LABEL(ebpf_jit_jmp_jeq_k)[];
extern char BPF_JIT_JMP_LABEL(ebpf_jit_jmp32_jeq_k)[];
extern char BPF_JIT_JMP_LABEL(ebpf_jit_jmp_jne_k)[];
extern char BPF_JIT_JMP_LABEL(ebpf_jit_jmp32_jne_k)[];
extern char BPF_JIT_JMP_LABEL(ebpf_jit_jmp_jgt_k)[];
extern char BPF_JIT_JMP_LABEL(ebpf_jit_jmp32_jgt_k)[];
extern char BPF_JIT_JMP_LABEL(ebpf_jit_jmp_jge_k)[];
extern char BPF_JIT_JMP_LABEL(ebpf_jit_jmp32_jge_k)[];
extern char BPF_JIT_JMP_LABEL(ebpf_jit_jmp_jlt_k)[];
extern char BPF_JIT_JMP_LABEL(ebpf_jit_jmp32_jlt_k)[];
extern char BPF_JIT_JMP_LABEL(ebpf_jit_jmp_jle_k)[];
extern char BPF_JIT_JMP_LABEL(ebpf_jit_jmp32_jle_k)[];
extern char BPF_JIT_JMP_LABEL(ebpf_jit_jmp_jsgt_k)[];
extern char BPF_JIT_JMP_LABEL(ebpf_jit_jmp32_jsgt_k)[];
extern char BPF_JIT_JMP_LABEL(ebpf_jit_jmp_jsge_k)[];
extern char BPF_JIT_JMP_LABEL(ebpf_jit_jmp32_jsge_k)[];
extern char BPF_JIT_JMP_LABEL(ebpf_jit_jmp_jslt_k)[];
extern char BPF_JIT_JMP_LABEL(ebpf_jit_jmp32_jslt_k)[];
extern char BPF_JIT_JMP_LABEL(ebpf_jit_jmp_jsle_k)[];
extern char BPF_JIT_JMP_LABEL(ebpf_jit_jmp32_jsle_k)[];
extern char BPF_JIT_JMP_LABEL(ebpf_jit_jmp_jset_k)[];
extern char BPF_JIT_JMP_LABEL(ebpf_jit_jmp32_jset_k)[];
extern char BPF_JIT_JMP_LABEL(ebpf_jit_jmp_tail_call)[];

extern char BPF_JIT_FUNC_LABEL(ebpf_jit_jmp_call_hlp)[];
extern char BPF_JIT_WBS_LABEL(ebpf_jit_jmp_call_hlp)[];
extern char BPF_JIT_FUNC_LABEL(ebpf_jit_jmp_call_bpf)[];
extern char BPF_JIT_WBS_LABEL(ebpf_jit_jmp_call_bpf)[];
extern char BPF_JIT_FUNC_LABEL(ebpf_jit_stx_atomic_w_op)[];
extern char BPF_JIT_WBS_LABEL(ebpf_jit_stx_atomic_w_op)[];
extern char BPF_JIT_FUNC_LABEL(ebpf_jit_stx_atomic_w_fetch_op)[];
extern char BPF_JIT_WBS_LABEL(ebpf_jit_stx_atomic_w_fetch_op)[];
extern char BPF_JIT_FUNC_LABEL(ebpf_jit_stx_atomic_dw_op)[];
extern char BPF_JIT_WBS_LABEL(ebpf_jit_stx_atomic_dw_op)[];
extern char BPF_JIT_FUNC_LABEL(ebpf_jit_stx_atomic_dw_fetch_op)[];
extern char BPF_JIT_WBS_LABEL(ebpf_jit_stx_atomic_dw_fetch_op)[];
extern char BPF_JIT_FUNC_LABEL(ebpf_jit_stx_atomic_w_cmpxchg)[];
extern char BPF_JIT_WBS_LABEL(ebpf_jit_stx_atomic_w_cmpxchg)[];
extern char BPF_JIT_FUNC_LABEL(ebpf_jit_stx_atomic_dw_cmpxchg)[];
extern char BPF_JIT_WBS_LABEL(ebpf_jit_stx_atomic_dw_cmpxchg)[];

/*
 * In this structure JIT stores all information about eBPF program being jited.
 */
struct ebpf_prog_info {
	struct cmd_len *prologue;	/* info about prologue added by JIT */
	struct cmd_len *body;		/* info about BPF instruction translations */
	unsigned int prologue_len;	/* number of prologues */
	unsigned int body_len;		/* number of BPF instructions in program body */
	const struct bpf_prog *prog;	/* link to bpf_prog structure */
	unsigned int total_regs;	/* total number of registers required for
					 * eBPF program */
	unsigned int callee_reg_start;	/* start of %b registers area, that is used
					 * for passing arguments to functions */
	u32 *addrs;			/* relative instruction addresses for verifier */
	unsigned int stack_size;	/* size of stack required for current eBPF program */
	unsigned int start_offset;	/* length of the nop interval before the very first
					 * instruction of jited program, if any */
	bool seen_func_call;		/* does JIT need to emit a function call */
};

/*
 * eBPF JIT can be invoked two times to compile the same image: first time for
 * the compilation itself, second time for linking with subprograms. All the
 * information about the compilation process is saved via this structure in
 * order to use it during second invocation.
 */
struct e2k_jit_data {
	struct bpf_binary_header *header;
	u8 *image;
	unsigned int image_size;
	struct ebpf_prog_info info;
	int pass;
};

/*
 * During the compilation, check that size for tail call offset value
 * 1) is enough to store integer value;
 * 2) does not change the alignment of e2k wide instructions.
 */
static inline void compile_time_checks(void)
{
	BUILD_BUG_ON(TAIL_CALL_OFFSET_SIZE < sizeof(int));
	BUILD_BUG_ON(TAIL_CALL_OFFSET_SIZE % E2K_INSTR_ALIGNMENT != 0);
}

/* e2k JIT supports mixing bpf-to-bpf and tail calls */
bool bpf_jit_supports_subprog_tailcalls(void)
{
	return true;
}

static inline int max_pass_num(void)
{
	/*
	 * eBPF JIT for e2k operates in three passes:
	 *    #0 - first pass, just get acquainted with eBPF program;
	 *    #1 - code-generation pass, now fill image with e2k code. Note
	 *         that bpf-to-bpf calls in the generated code (if any) are
	 *         not linked yet;
	 *    #2 - extra pass. If there are subprogs, JIT will be awaken
	 *         again to fill the displacement in bpf-to-bpf calls.
	 *
	 *    ***
	 *    *** Note: between #0 and #1 there is an additional hidden pass
	 *    *** to build a HW bug workaround. This pass takes place in
	 *    *** `calculate_hwbug_workaround()' only if there is a need for
	 *    *** the workaround.
	 *    ***
	 */
	return 2;
}

/*
 * Check if eBPF program `prog' requires tail call counter zeroing.
 */
static inline bool need_tail_call_counter_zeroing(const struct bpf_prog *prog)
{
	bool was_classic = bpf_prog_was_classic(prog);
	bool is_subprog = prog->aux->func_idx != 0;
	/*
	 * There are no tail calls in classic BPF, so eBPF programs obtained from cBPF
	 * don't have tail calls, thus need no tail call counter zeroing. eBPF subprograms
	 * also need no tail call counter zeroing, in order to save tail call counter
	 * during bpf-to-bpf calls.
	 */
	return !was_classic && !is_subprog;
}

/*
 * Allocate memory for `e2k_jit_data' and `ebpf_prog_info' structures and addrs array.
 */
static struct e2k_jit_data *alloc_jit_data(const struct bpf_prog *prog)
{
	unsigned int len = prog->len, prologue_num = 0, alloc_size = 0;
	struct e2k_jit_data *jit_data = NULL;
	struct ebpf_prog_info *info = NULL;

	jit_data = kvzalloc(sizeof(*jit_data), GFP_KERNEL);
	if (!jit_data)
		return NULL;

	info = &jit_data->info;

	info->addrs = kvzalloc(sizeof(*info->addrs) * len, GFP_KERNEL);
	if (!info->addrs) {
		kfree(jit_data);
		return NULL;
	}

	/*
	 * Tail call counter zeroing is implemented as an ordinary template,
	 * which is placed before the prologue template and jumped over during
	 * tail calls.
	 * That's why if we need to zero tail call counter, we place two
	 * 'prologue' templates before the body of jited program.
	 */
	prologue_num = need_tail_call_counter_zeroing(prog) ? 2 : 1;
	BUILD_BUG_ON(sizeof(*info->prologue) != sizeof(*info->body));
	alloc_size = sizeof(*info->prologue) * prologue_num +
		     sizeof(*info->body) * len;

	info->prologue = kvzalloc(alloc_size, GFP_KERNEL);
	if (!info->prologue) {
		kfree(info->addrs);
		kfree(jit_data);
		return NULL;
	}
	info->prologue_len = prologue_num;
	info->body = info->prologue + prologue_num;
	info->body_len = len;
	info->prog = prog;
	info->seen_func_call = false;

	/*
	 * If eBPF program calls a C-function in one of its templates, then we
	 * must reserve some stack space for call's parameters that are passed
	 * via registers. There are up to 8 arguments passed via registers, so
	 * we allocate 8 * 8 = 64 bytes in excess of what eBPF program needs.
	 * Actually, allocating extra 64 bytes on stack is costless operation,
	 * and we will do it even if there are no calls to C-functions.
	 */
	info->stack_size = prog->aux->stack_depth + 64;

	return jit_data;
}

/*
 * Calculate the total size of program as sum of template lengths.
 */
static unsigned int templates_lengths_sum(const struct ebpf_prog_info *info)
{
	unsigned int i = 0, counter = 0;

	for (i = 0; i < info->prologue_len; i++)
		counter += info->prologue[i].template_len;
	for (i = 0; i < info->body_len; i++)
		counter += info->body[i].template_len;

	return counter;
}

/*
 * Calculate displacement from the current position to the destination
 * BPF instruction. The displacement consists of several parts:
 *	- `left' bytes from the current wide instruction
 *	  to the end of current BPF instruction translation;
 *	- `jump' BPF instructions to be jumped over;
 *	- in case of HW bug, the destination instruction can have
 *	  a nop interval at the beginning;
 * The sum of these displacements is a result jump displacement in bytes.
 */
static int disp_jump(int jump, unsigned int left, const struct cmd_len cmd_lens[])
{
	int acc = left, i = 0;

	if (!cpu_has(CPU_HWBUG_CODE_PLACEMENT)) {
		if (jump >= 0) {
			for (i = 1; i <= jump; i++)
				acc += cmd_lens[i].template_len;
		} else {
			for (i = 0; i > jump; i--)
				acc -= cmd_lens[i].template_len;
		}
	} else {
		if (jump >= 0) {
			for (i = 1; i <= jump; i++)
				acc += cmd_lens[i].total_len;
		} else {
			for (i = 0; i > jump; i--)
				acc -= cmd_lens[i].total_len;
		}
		acc += real_wide_instr_offset(&cmd_lens[jump + 1], 0);
	}
	/*
	 * Finally, we need to shift the result by 3 bits right because all wide
	 * instructions are 8-bytes aligned, so the disp field of CS0 syllable
	 * does not store the last three bits of displacement value.
	 */
	return acc >> 3;
}

/*
 * This function is identical to insert_imm32() except that it works with 64-bit
 * constant, thus receives the constant in two parts `imm64_hi' and `imm64_lo'
 * and call find_lts_f32s() twice to find both LTS0 and LTS1 syllables.
 */
static inline bool insert_imm64(const void *template, unsigned int offset,
		void *start, u32 imm64_hi, u32 imm64_lo, const struct cmd_len *cmd_lens)
{
	void *wide_instr_ptr = start + real_wide_instr_offset(cmd_lens, offset);
	instr_lts_t *lts0_ptr = find_lts_f32s(wide_instr_ptr, 0);
	instr_lts_t *lts1_ptr = find_lts_f32s(wide_instr_ptr, 1);

	if (lts0_ptr && lts1_ptr) {
		lts0_ptr->word = imm64_lo;
		lts1_ptr->word = imm64_hi;
		return true;
	} else {
		if (!lts0_ptr)
			WARN_ONCE(1, BPF_JIT_WARN "failed to find lts0 syllable");
		if (!lts1_ptr)
			WARN_ONCE(1, BPF_JIT_WARN "failed to find lts1 syllable");
		return false;
	}
}

/*
 * This finction inserts `stack_size' into LTS1 syllable for getsp assembler
 * instruction. LTS1 was chosen because LTS0 is used to store window size for
 * setwd instruction in the same wide command of eBPF prologue. A stack grows
 * down, negative value of `stack_size' means stack allocation, while positive
 * means stack freeing.
 */
static inline bool insert_stack_size(const void *template, unsigned int offset,
		void *start, unsigned int stack_size, const struct cmd_len *cmd_lens)
{
	void *wide_instr_ptr = start + real_wide_instr_offset(cmd_lens, offset);
	instr_lts_t *lts1_ptr = find_lts_f32s(wide_instr_ptr, 1);

	if (lts1_ptr) {
		lts1_ptr->word = stack_size;
		return true;
	} else {
		WARN_ONCE(1, BPF_JIT_WARN "failed to find lts1 syllable");
		return false;
	}
}

/*
 * Check if eBPF instruction is a jump. 'Jump' means that there is
 * a disp assembler instruction in template where JIT should insert
 * correct displacement.
 */
static inline bool is_jump(const struct bpf_insn *instr)
{
	u8 code = instr->code;

	if (BPF_CLASS(code) != BPF_JMP &&
	    BPF_CLASS(code) != BPF_JMP32)
		return false;

	/* call and exit are actually not jumps in this context */
	if (BPF_OP(code) == BPF_CALL ||
	    BPF_OP(code) == BPF_EXIT)
		return false;

	return true;
}

/*
 * Mark BPF instruction that can be jumped to from the current
 * instruction (if any).
 */
static inline void mark_jump_destinations(const struct bpf_insn *instr,
					  struct cmd_len *cmd_lengths)
{
	u8 code = instr->code;
	s16 off = instr->off;

	if (!cpu_has(CPU_HWBUG_CODE_PLACEMENT))
		return;

	/* skip all instructions except jumps */
	if (!is_jump(instr))
		return;

	if (BPF_OP(code) == BPF_TAIL_CALL) {
		/*
		 * Tail call template has a jump to the following instruction.
		 * The jump is taken if the tail call fails.
		 */
		cmd_lengths[1].is_jump_dest = true;
	} else {
		/* that's a jump; mark its destination */
		cmd_lengths[off + 1].is_jump_dest = true;
	}
}

/*
 * There is only one instruction in eBPF that is encoded with 2 sequential
 * `bpf_insn' structures, namely 'load 64-bit imm value to register'. This
 * function returns true if eBPF instruction pointed by `instr' is that double
 * instruction.
 */
static inline bool is_double_instr(const struct bpf_insn *instr)
{
	return instr->code == (BPF_LD | BPF_IMM | BPF_DW);
}

static inline bool is_nreg(const u32 field)
{
	return (field & INSTR_SRC_DST_NREG_MASK) == INSTR_SRC_DST_NREG_VALUE;
}

static inline u32 reg_num(const u32 field)
{
	return field & INSTR_SRC_DST_NREG_NUM_MASK;
}

static inline bool is_src_reg(const u32 field)
{
	return reg_num(field) == EBPF_JIT_SRC_REG;
}

static inline bool is_dst_reg(const u32 field)
{
	return reg_num(field) == EBPF_JIT_DST_REG;
}

static inline u32 form_reg(const u8 n)
{
	return (n & INSTR_SRC_DST_NREG_NUM_MASK) | INSTR_SRC_DST_NREG_VALUE;
}

#define FILL_OPERAND_SRC_DST(ptr, src, dst, field) \
({ \
	if (is_nreg(ptr->alf2.field)) { \
		if (is_src_reg(ptr->alf2.field)) \
			ptr->alf2.field = form_reg(src); \
		if (is_dst_reg(ptr->alf2.field)) \
			ptr->alf2.field = form_reg(dst); \
	} \
})
#define FILL_ALS_SRC_DST(als_num, ptr, src, dest) \
({ \
	instr_als_t *fill_als_src_and_dst_syl_ptr = NULL; \
	if ((fill_als_src_and_dst_syl_ptr = find_als(ptr, als_num)) != NULL) { \
		FILL_OPERAND_SRC_DST(fill_als_src_and_dst_syl_ptr, src, dest, opce); \
		FILL_OPERAND_SRC_DST(fill_als_src_and_dst_syl_ptr, src, dest, src2); \
		FILL_OPERAND_SRC_DST(fill_als_src_and_dst_syl_ptr, src, dest, dst); \
	} \
})

/*
 * In templates, src and dst registers have big serial numbers, which are exactly
 * out of register window bounds. In this function we loop over wide instructions
 * in template copy, find ALS syllables in them, check operand register numbers and,
 * if needed, substitute them with correct numbers from eBPF instruction.
 */
static void fill_src_and_dst(void *ptr, unsigned int len, const struct cmd_len *cmd_info)
{
	unsigned int wide_instr_len = 0;
	u8 src = cmd_info->src, dst = cmd_info->dst;

	while (len > 0) {
		wide_instr_len = E2K_GET_INSTR_SIZE(*(instr_hs_t *)ptr);
		BUG_ON(len < wide_instr_len);

		FILL_ALS_SRC_DST(0, ptr, src, dst);
		FILL_ALS_SRC_DST(1, ptr, src, dst);
		FILL_ALS_SRC_DST(2, ptr, src, dst);
		FILL_ALS_SRC_DST(3, ptr, src, dst);
		FILL_ALS_SRC_DST(4, ptr, src, dst);
		FILL_ALS_SRC_DST(5, ptr, src, dst);

		ptr += wide_instr_len;
		len -= wide_instr_len;
	}
}

/*
 * After memory allocation, we know its first address (referenced
 * by `ptr') and can build an exact workaround of HW bug. Also return
 * the exact size of jited program if the workaround was built.
 */
static unsigned int calculate_hwbug_workaround(void *ptr,
		const struct bpf_insn insns[], struct ebpf_prog_info *info)
{
	unsigned int i = 0;
	unsigned int real_prog_len = 0;

	if (!cpu_has(CPU_HWBUG_CODE_PLACEMENT))
		return 0;

	/*
	 * First of all, mark all instructions that are jump destinations
	 * and/or contain calls.
	 */
	for (i = 0; i < info->prologue_len; i++) {
		/* both tail call counter zeroing and prologue can be jump destinations */
		info->prologue[i].is_jump_dest = true;
	}
	for (i = 0; i < info->body_len; i++)
		mark_jump_destinations(insns + i, info->body + i);

	/*
	 * Now loop over prologues and eBPF instructions translations and
	 * calculate the workaround for all of them.
	 */
	for (i = 0; i < info->prologue_len; i++) {
		real_prog_len += build_workaround_for_instr(ptr + real_prog_len,
							    &info->prologue[i]);
	}
	for (i = 0; i < info->body_len; i++)
		real_prog_len += build_workaround_for_instr(ptr + real_prog_len, &info->body[i]);

	/*
	 * In case of HW bug, we may need to insert nops before the first
	 * instruction to move it out from a 'bad' region. Save the length
	 * of this nop interval so that we can easily access it later.
	 */
	info->start_offset = real_wide_instr_offset(&info->prologue[0], 0);

	return real_prog_len;
}

/*
 * Insert tail call offset before the beginning of image of jited program. Tail
 * call code will firstly get this number and add it to jump destination
 * address to jump over the tail call counter zeroing. If there is no zeroing,
 * the number stored in this function equals 0, so that the destination
 * address remain unchanged.
 */
static inline void store_tail_call_offset(void *image, const struct ebpf_prog_info *info)
{
	int offset = 0;
	void *store_to = image - TAIL_CALL_OFFSET_SIZE;

	if (need_tail_call_counter_zeroing(info->prog)) {
		offset = real_wide_instr_offset_to_end(&info->prologue[0],
				info->prologue[0].template_len) +
					real_wide_instr_offset(&info->prologue[1], 0);
	}

	if (cpu_has(CPU_HWBUG_CODE_PLACEMENT))
		store_to += info->start_offset;

	*(int *)store_to = offset;
}

/*
 * Helpers for eBPF atomic instructions.
 *
 * Since e2k kernel atomic functions have attribute __always_inline, we can not
 * call them directly from templates. So in templates we call these C-helpers
 * which just inline kernel atomic functions.
 */
#define ATOMIC_HELPER(op) \
static void bpf_jit_atomic_##op##_w_helper(u32 src, atomic_t *addr) \
{ \
	atomic_##op(src, addr); \
} \
static void bpf_jit_atomic_##op##_dw_helper(u64 src, atomic64_t *addr) \
{ \
	atomic64_##op(src, addr); \
} \
static u32 bpf_jit_atomic_##op##_w_fetch_helper(u32 src, atomic_t *addr) \
{ \
	return atomic_fetch_##op(src, addr); \
} \
static u64 bpf_jit_atomic_##op##_dw_fetch_helper(u64 src, atomic64_t *addr) \
{ \
	return atomic64_fetch_##op(src, addr); \
}

ATOMIC_HELPER(add)
ATOMIC_HELPER(and)
ATOMIC_HELPER(or)
ATOMIC_HELPER(xor)

static u32 bpf_jit_atomic_xchg_w_helper(u32 src, atomic_t *addr)
{
	return atomic_xchg(addr, src);
}

static u64 bpf_jit_atomic_xchg_dw_helper(u64 src, atomic64_t *addr)
{
	return atomic64_xchg(addr, src);
}

static u32 bpf_jit_atomic_cmpxchg_w_helper(u32 src, atomic_t *addr, u32 r0)
{
	return atomic_cmpxchg(addr, r0, src);
}

static u64 bpf_jit_atomic_cmpxchg_dw_helper(u64 src, atomic64_t *addr, u64 r0)
{
	return atomic64_cmpxchg(addr, r0, src);
}

static int atomic_op(void *ptr, int pass, struct ebpf_prog_info *info,
			struct cmd_len *cur, const struct bpf_insn *instr)
{
	int size = 0;
	const s32 imm = instr->imm;
	const s16 off = instr->off;
	unsigned int reg_start = info->callee_reg_start;
	u64 func_addr = 0;

	/* all atomic operations are implemented via helper calls */
	info->seen_func_call = true;

	switch (instr->code) {
	case BPF_STX | BPF_ATOMIC | BPF_W:
		switch (imm) {
		case BPF_ADD:
			func_addr = (unsigned long) &bpf_jit_atomic_add_w_helper;
			goto atomic_w_op;
		case BPF_AND:
			func_addr = (unsigned long) &bpf_jit_atomic_and_w_helper;
			goto atomic_w_op;
		case BPF_OR:
			func_addr = (unsigned long) &bpf_jit_atomic_or_w_helper;
			goto atomic_w_op;
		case BPF_XOR:
			func_addr = (unsigned long) &bpf_jit_atomic_xor_w_helper;
atomic_w_op:
			size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_stx_atomic_w_op, ptr, pass, cur);
			if (!is_codegen_pass(pass))
				break;
			if (!BPF_JIT_INSERT_OFF(ebpf_jit_stx_atomic_w_op, ptr, off, cur) ||
			    !BPF_JIT_INSERT_DISP_CALL(ebpf_jit_stx_atomic_w_op,
						      ptr, func_addr, cur) ||
			    !BPF_JIT_INSERT_WBS(ebpf_jit_stx_atomic_w_op,
						ptr, reg_start, cur))
				return -EINVAL;
			break;
		case BPF_ADD | BPF_FETCH:
			func_addr = (unsigned long) &bpf_jit_atomic_add_w_fetch_helper;
			goto atomic_w_op_fetch;
		case BPF_AND | BPF_FETCH:
			func_addr = (unsigned long) &bpf_jit_atomic_and_w_fetch_helper;
			goto atomic_w_op_fetch;
		case BPF_OR | BPF_FETCH:
			func_addr = (unsigned long) &bpf_jit_atomic_or_w_fetch_helper;
			goto atomic_w_op_fetch;
		case BPF_XOR | BPF_FETCH:
			func_addr = (unsigned long) &bpf_jit_atomic_xor_w_fetch_helper;
			goto atomic_w_op_fetch;
		case BPF_XCHG:
			func_addr = (unsigned long) &bpf_jit_atomic_xchg_w_helper;
atomic_w_op_fetch:
			size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_stx_atomic_w_fetch_op,
							ptr, pass, cur);
			if (!is_codegen_pass(pass))
				break;
			if (!BPF_JIT_INSERT_OFF(ebpf_jit_stx_atomic_w_fetch_op, ptr, off, cur) ||
			    !BPF_JIT_INSERT_DISP_CALL(ebpf_jit_stx_atomic_w_fetch_op,
						      ptr, func_addr, cur) ||
			    !BPF_JIT_INSERT_WBS(ebpf_jit_stx_atomic_w_fetch_op,
						ptr, reg_start, cur))
				return -EINVAL;
			break;
		case BPF_CMPXCHG:
			func_addr = (unsigned long) &bpf_jit_atomic_cmpxchg_w_helper;
			size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_stx_atomic_w_cmpxchg,
							ptr, pass, cur);
			if (!is_codegen_pass(pass))
				break;
			if (!BPF_JIT_INSERT_OFF(ebpf_jit_stx_atomic_w_cmpxchg, ptr, off, cur) ||
			    !BPF_JIT_INSERT_DISP_CALL(ebpf_jit_stx_atomic_w_cmpxchg,
						      ptr, func_addr, cur) ||
			    !BPF_JIT_INSERT_WBS(ebpf_jit_stx_atomic_w_cmpxchg,
						ptr, reg_start, cur))
				return -EINVAL;
			break;
		}
		break;
	case BPF_STX | BPF_ATOMIC | BPF_DW:
		switch (imm) {
		case BPF_ADD:
			func_addr = (unsigned long) &bpf_jit_atomic_add_dw_helper;
			goto atomic_dw_op;
		case BPF_AND:
			func_addr = (unsigned long) &bpf_jit_atomic_and_dw_helper;
			goto atomic_dw_op;
		case BPF_OR:
			func_addr = (unsigned long) &bpf_jit_atomic_or_dw_helper;
			goto atomic_dw_op;
		case BPF_XOR:
			func_addr = (unsigned long) &bpf_jit_atomic_xor_dw_helper;
atomic_dw_op:
			size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_stx_atomic_dw_op, ptr, pass, cur);
			if (!is_codegen_pass(pass))
				break;
			if (!BPF_JIT_INSERT_OFF(ebpf_jit_stx_atomic_dw_op, ptr, off, cur) ||
			    !BPF_JIT_INSERT_DISP_CALL(ebpf_jit_stx_atomic_dw_op,
						      ptr, func_addr, cur) ||
			    !BPF_JIT_INSERT_WBS(ebpf_jit_stx_atomic_dw_op,
						ptr, reg_start, cur))
				return -EINVAL;
			break;
		case BPF_ADD | BPF_FETCH:
			func_addr = (unsigned long) &bpf_jit_atomic_add_dw_fetch_helper;
			goto atomic_dw_op_fetch;
		case BPF_AND | BPF_FETCH:
			func_addr = (unsigned long) &bpf_jit_atomic_and_dw_fetch_helper;
			goto atomic_dw_op_fetch;
		case BPF_OR | BPF_FETCH:
			func_addr = (unsigned long) &bpf_jit_atomic_or_dw_fetch_helper;
			goto atomic_dw_op_fetch;
		case BPF_XOR | BPF_FETCH:
			func_addr = (unsigned long) &bpf_jit_atomic_xor_dw_fetch_helper;
			goto atomic_dw_op_fetch;
		case BPF_XCHG:
			func_addr = (unsigned long) &bpf_jit_atomic_xchg_dw_helper;
atomic_dw_op_fetch:
			size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_stx_atomic_dw_fetch_op,
							ptr, pass, cur);
			if (!is_codegen_pass(pass))
				break;
			if (!BPF_JIT_INSERT_OFF(ebpf_jit_stx_atomic_dw_fetch_op, ptr, off, cur) ||
			    !BPF_JIT_INSERT_DISP_CALL(ebpf_jit_stx_atomic_dw_fetch_op,
						      ptr, func_addr, cur) ||
			    !BPF_JIT_INSERT_WBS(ebpf_jit_stx_atomic_dw_fetch_op,
						ptr, reg_start, cur))
				return -EINVAL;
			break;
		case BPF_CMPXCHG:
			func_addr = (unsigned long) &bpf_jit_atomic_cmpxchg_dw_helper;
			size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_stx_atomic_dw_cmpxchg,
							ptr, pass, cur);
			if (!is_codegen_pass(pass))
				break;
			if (!BPF_JIT_INSERT_OFF(ebpf_jit_stx_atomic_dw_cmpxchg, ptr, off, cur) ||
			    !BPF_JIT_INSERT_DISP_CALL(ebpf_jit_stx_atomic_dw_cmpxchg,
						      ptr, func_addr, cur) ||
			    !BPF_JIT_INSERT_WBS(ebpf_jit_stx_atomic_dw_cmpxchg,
						ptr, reg_start, cur))
				return -EINVAL;
			break;
		}
		break;
	default:
		/*
		 * This function should be called for atomic instructions only.
		 * Getting here means either the aforementioned requirement is
		 * not met or a new atomic instruction was added to eBPF ISA.
		 */
		WARN_ONCE(1, BPF_JIT_WARN "unknown atomic operation");
		return -EINVAL;
	}

	return size;
}

static int build_call(void *ptr, const int pass, struct ebpf_prog_info *info,
			struct cmd_len *cur, const struct bpf_insn *instr)
{
	int size = 0, ret = 0;
	bool func_addr_fixed;
	u64 func_addr = 0;

	info->seen_func_call = true;

	ret = bpf_jit_get_func_addr(info->prog, instr, is_extra_pass(pass),
				    &func_addr, &func_addr_fixed);
	if (ret < 0)
		BUG_ON(1);
	if (func_addr_fixed) {
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_jmp_call_hlp, ptr, pass, cur);
		if (is_first_pass(pass))
			return size;
		if (!BPF_JIT_INSERT_DISP_CALL(ebpf_jit_jmp_call_hlp, ptr, func_addr, cur) ||
		    !BPF_JIT_INSERT_WBS(ebpf_jit_jmp_call_hlp, ptr, info->callee_reg_start, cur))
			return -EINVAL;
	} else {
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_jmp_call_bpf, ptr, pass, cur);
		if (is_first_pass(pass) || is_codegen_pass(pass))
			return size;
		/* link bpf-to-bpf calls during the extra pass */
		if (!BPF_JIT_INSERT_DISP_CALL(ebpf_jit_jmp_call_bpf, ptr, func_addr, cur) ||
		    !BPF_JIT_INSERT_WBS(ebpf_jit_jmp_call_bpf, ptr, info->callee_reg_start, cur))
			return -EINVAL;
	}
	return size;
}

static int build_tail_call(void *ptr, int pass, const struct ebpf_prog_info *info, unsigned int num)
{
	int size = 0;
	struct cmd_len *cur = info->body + num;

	size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_jmp_tail_call, ptr, pass, cur);
	if (!is_codegen_pass(pass))
		return size;
	/*
	 * Attention: template for this command implements a jump to the end of this
	 * template if some checks failed. In case of HW bug workaround, some nops can be
	 * inserted between this template and the next one. So we introduce a label to
	 * make JIT insert a correct displacement to the beginning of the next template
	 * (the next template has off = 0).
	 *
	 * Attention: in e2k architecture, programmer must get the size of memory
	 * to deallocate to stack by rounding the allocated size up to 16 bytes.
	 * That is because lower 4 bits of size are zeroed by hardware. So, allocating
	 * 16 * n + k bytes from stack (k < 16) will result in a proper allocation
	 * (actually, 16 * (n + 1) bytes would be allocated), while deallocating
	 * 16 * n + k bytes will result in stack memory leak: only 16 * n bytes would
	 * be freed because of lower 4 bits zeroing.
	 */
	if (!BPF_JIT_INSERT_DISP_JUMP(ebpf_jit_jmp_tail_call, ptr, 0, cur) ||
	    !BPF_JIT_INSERT_STACK_FREE(ebpf_jit_jmp_tail_call, ptr,
				round_up(info->stack_size, E2K_ALIGN_USTACK_SIZE), cur))
		return -EINVAL;
	return size;
}

/*
 * This function is a huge switch that matches BPF instrution codes
 * to the corresponding template names. Depending in the value of `pass',
 * it just returns the length of the template or copies the template
 * to the allocated memory with some changes.
 */
static int compile_single_instruction(void *ptr, const int pass,
				      struct ebpf_prog_info *info, const unsigned int num,
				      const struct bpf_insn *instr)
{
	int size = 0;
	u8 dst = instr->dst_reg, src = instr->src_reg;
	const s16 off = instr->off;
	const s32 imm = instr->imm;
	struct cmd_len *cur = info->body + num;

	if (is_first_pass(pass)) {
		/* save source and destination register numbers */
		cur->dst = dst;
		cur->src = src;
	}

	switch (instr->code) {
	case BPF_ALU | BPF_MOV | BPF_X:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu_mov_x, ptr, pass, cur);
		break;
	case BPF_ALU64 | BPF_MOV | BPF_X:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu64_mov_x, ptr, pass, cur);
		break;
	case BPF_ALU | BPF_MOV | BPF_K:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu_mov_k, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_IMM(ebpf_jit_alu_mov_k, ptr, imm, cur))
			return -EINVAL;
		break;
	case BPF_ALU64 | BPF_MOV | BPF_K:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu64_mov_k, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_IMM(ebpf_jit_alu64_mov_k, ptr, imm, cur))
			return -EINVAL;
		break;
	case BPF_JMP | BPF_EXIT:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_jmp_exit, ptr, pass, cur);
		break;
	case BPF_ALU | BPF_ADD | BPF_X:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu_add_x, ptr, pass, cur);
		break;
	case BPF_ALU64 | BPF_ADD | BPF_X:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu64_add_x, ptr, pass, cur);
		break;
	case BPF_ALU | BPF_SUB | BPF_X:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu_sub_x, ptr, pass, cur);
		break;
	case BPF_ALU64 | BPF_SUB | BPF_X:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu64_sub_x, ptr, pass, cur);
		break;
	case BPF_ALU | BPF_AND | BPF_X:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu_and_x, ptr, pass, cur);
		break;
	case BPF_ALU64 | BPF_AND | BPF_X:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu64_and_x, ptr, pass, cur);
		break;
	case BPF_ALU | BPF_OR | BPF_X:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu_or_x, ptr, pass, cur);
		break;
	case BPF_ALU64 | BPF_OR | BPF_X:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu64_or_x, ptr, pass, cur);
		break;
	case BPF_ALU | BPF_XOR | BPF_X:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu_xor_x, ptr, pass, cur);
		break;
	case BPF_ALU64 | BPF_XOR | BPF_X:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu64_xor_x, ptr, pass, cur);
		break;
	case BPF_ALU | BPF_LSH | BPF_X:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu_lsh_x, ptr, pass, cur);
		break;
	case BPF_ALU64 | BPF_LSH | BPF_X:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu64_lsh_x, ptr, pass, cur);
		break;
	case BPF_ALU | BPF_RSH | BPF_X:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu_rsh_x, ptr, pass, cur);
		break;
	case BPF_ALU64 | BPF_RSH | BPF_X:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu64_rsh_x, ptr, pass, cur);
		break;
	case BPF_ALU | BPF_ARSH | BPF_X:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu_arsh_x, ptr, pass, cur);
		break;
	case BPF_ALU64 | BPF_ARSH | BPF_X:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu64_arsh_x, ptr, pass, cur);
		break;
	case BPF_ALU | BPF_MUL | BPF_X:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu_mul_x, ptr, pass, cur);
		break;
	case BPF_ALU64 | BPF_MUL | BPF_X:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu64_mul_x, ptr, pass, cur);
		break;
	case BPF_ALU | BPF_DIV | BPF_X:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu_div_x, ptr, pass, cur);
		break;
	case BPF_ALU64 | BPF_DIV | BPF_X:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu64_div_x, ptr, pass, cur);
		break;
	case BPF_ALU | BPF_MOD | BPF_X:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu_mod_x, ptr, pass, cur);
		break;
	case BPF_ALU64 | BPF_MOD | BPF_X:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu64_mod_x, ptr, pass, cur);
		break;
	case BPF_ALU | BPF_ADD | BPF_K:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu_add_k, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_IMM(ebpf_jit_alu_add_k, ptr, imm, cur))
			return -EINVAL;
		break;
	case BPF_ALU64 | BPF_ADD | BPF_K:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu64_add_k, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_IMM(ebpf_jit_alu64_add_k, ptr, imm, cur))
			return -EINVAL;
		break;
	case BPF_ALU | BPF_SUB | BPF_K:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu_sub_k, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_IMM(ebpf_jit_alu_sub_k, ptr, imm, cur))
			return -EINVAL;
		break;
	case BPF_ALU64 | BPF_SUB | BPF_K:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu64_sub_k, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_IMM(ebpf_jit_alu64_sub_k, ptr, imm, cur))
			return -EINVAL;
		break;
	case BPF_ALU | BPF_AND | BPF_K:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu_and_k, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_IMM(ebpf_jit_alu_and_k, ptr, imm, cur))
			return -EINVAL;
		break;
	case BPF_ALU64 | BPF_AND | BPF_K:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu64_and_k, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_IMM(ebpf_jit_alu64_and_k, ptr, imm, cur))
			return -EINVAL;
		break;
	case BPF_ALU | BPF_OR | BPF_K:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu_or_k, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_IMM(ebpf_jit_alu_or_k, ptr, imm, cur))
			return -EINVAL;
		break;
	case BPF_ALU64 | BPF_OR | BPF_K:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu64_or_k, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_IMM(ebpf_jit_alu64_or_k, ptr, imm, cur))
			return -EINVAL;
		break;
	case BPF_ALU | BPF_XOR | BPF_K:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu_xor_k, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_IMM(ebpf_jit_alu_xor_k, ptr, imm, cur))
			return -EINVAL;
		break;
	case BPF_ALU64 | BPF_XOR | BPF_K:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu64_xor_k, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_IMM(ebpf_jit_alu64_xor_k, ptr, imm, cur))
			return -EINVAL;
		break;
	case BPF_ALU | BPF_LSH | BPF_K:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu_lsh_k, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_IMM(ebpf_jit_alu_lsh_k, ptr, imm, cur))
			return -EINVAL;
		break;
	case BPF_ALU64 | BPF_LSH | BPF_K:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu64_lsh_k, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_IMM(ebpf_jit_alu64_lsh_k, ptr, imm, cur))
			return -EINVAL;
		break;
	case BPF_ALU | BPF_RSH | BPF_K:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu_rsh_k, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_IMM(ebpf_jit_alu_rsh_k, ptr, imm, cur))
			return -EINVAL;
		break;
	case BPF_ALU64 | BPF_RSH | BPF_K:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu64_rsh_k, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_IMM(ebpf_jit_alu64_rsh_k, ptr, imm, cur))
			return -EINVAL;
		break;
	case BPF_ALU | BPF_ARSH | BPF_K:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu_arsh_k, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_IMM(ebpf_jit_alu_arsh_k, ptr, imm, cur))
			return -EINVAL;
		break;
	case BPF_ALU64 | BPF_ARSH | BPF_K:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu64_arsh_k, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_IMM(ebpf_jit_alu64_arsh_k, ptr, imm, cur))
			return -EINVAL;
		break;
	case BPF_ALU | BPF_MUL | BPF_K:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu_mul_k, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_IMM(ebpf_jit_alu_mul_k, ptr, imm, cur))
			return -EINVAL;
		break;
	case BPF_ALU64 | BPF_MUL | BPF_K:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu64_mul_k, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_IMM(ebpf_jit_alu64_mul_k, ptr, imm, cur))
			return -EINVAL;
		break;
	case BPF_ALU | BPF_DIV | BPF_K:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu_div_k, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_IMM(ebpf_jit_alu_div_k, ptr, imm, cur))
			return -EINVAL;
		break;
	case BPF_ALU64 | BPF_DIV | BPF_K:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu64_div_k, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_IMM(ebpf_jit_alu64_div_k, ptr, imm, cur))
			return -EINVAL;
		break;
	case BPF_ALU | BPF_MOD | BPF_K:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu_mod_k, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_IMM(ebpf_jit_alu_mod_k, ptr, imm, cur))
			return -EINVAL;
		break;
	case BPF_ALU64 | BPF_MOD | BPF_K:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu64_mod_k, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_IMM(ebpf_jit_alu64_mod_k, ptr, imm, cur))
			return -EINVAL;
		break;
	case BPF_ALU | BPF_NEG:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu_neg, ptr, pass, cur);
		break;
	case BPF_ALU64 | BPF_NEG:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu64_neg, ptr, pass, cur);
		break;
	case BPF_ALU | BPF_END | BPF_FROM_LE:
		/* all we have to do is zero most significant bytes */
		if (imm == 16)
			size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu_end_le16, ptr, pass, cur);
		else if (imm == 32)
			size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu_end_le32, ptr, pass, cur);
		else
			size = 0;
		break;
	case BPF_ALU | BPF_END | BPF_FROM_BE:
		if (imm == 16)
			size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu_end_be16, ptr, pass, cur);
		else if (imm == 32)
			size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu_end_be32, ptr, pass, cur);
		else
			size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_alu_end_be64, ptr, pass, cur);
		break;
	case BPF_LD | BPF_IMM | BPF_DW:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_ld_imm_dw, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_IMM64(ebpf_jit_ld_imm_dw, ptr, instr[1].imm, imm, cur))
			return -EINVAL;
		break;
	case BPF_JMP | BPF_JA:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_jmp_ja, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_JUMP(ebpf_jit_jmp_ja, ptr, off, cur))
			return -EINVAL;
		break;
	case BPF_JMP | BPF_JEQ | BPF_X:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_jmp_jeq_x, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_JUMP(ebpf_jit_jmp_jeq_x, ptr, off, cur))
			return -EINVAL;
		break;
	case BPF_JMP32 | BPF_JEQ | BPF_X:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_jmp32_jeq_x, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_JUMP(ebpf_jit_jmp32_jeq_x, ptr, off, cur))
			return -EINVAL;
		break;
	case BPF_JMP | BPF_JNE | BPF_X:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_jmp_jne_x, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_JUMP(ebpf_jit_jmp_jne_x, ptr, off, cur))
			return -EINVAL;
		break;
	case BPF_JMP32 | BPF_JNE | BPF_X:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_jmp32_jne_x, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_JUMP(ebpf_jit_jmp32_jne_x, ptr, off, cur))
			return -EINVAL;
		break;
	case BPF_JMP | BPF_JGT | BPF_X:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_jmp_jgt_x, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_JUMP(ebpf_jit_jmp_jgt_x, ptr, off, cur))
			return -EINVAL;
		break;
	case BPF_JMP32 | BPF_JGT | BPF_X:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_jmp32_jgt_x, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_JUMP(ebpf_jit_jmp32_jgt_x, ptr, off, cur))
			return -EINVAL;
		break;
	case BPF_JMP | BPF_JGE | BPF_X:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_jmp_jge_x, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_JUMP(ebpf_jit_jmp_jge_x, ptr, off, cur))
			return -EINVAL;
		break;
	case BPF_JMP32 | BPF_JGE | BPF_X:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_jmp32_jge_x, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_JUMP(ebpf_jit_jmp32_jge_x, ptr, off, cur))
			return -EINVAL;
		break;
	case BPF_JMP | BPF_JLT | BPF_X:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_jmp_jlt_x, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_JUMP(ebpf_jit_jmp_jlt_x, ptr, off, cur))
			return -EINVAL;
		break;
	case BPF_JMP32 | BPF_JLT | BPF_X:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_jmp32_jlt_x, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_JUMP(ebpf_jit_jmp32_jlt_x, ptr, off, cur))
			return -EINVAL;
		break;
	case BPF_JMP | BPF_JLE | BPF_X:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_jmp_jle_x, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_JUMP(ebpf_jit_jmp_jle_x, ptr, off, cur))
			return -EINVAL;
		break;
	case BPF_JMP32 | BPF_JLE | BPF_X:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_jmp32_jle_x, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_JUMP(ebpf_jit_jmp32_jle_x, ptr, off, cur))
			return -EINVAL;
		break;
	case BPF_JMP | BPF_JSGT | BPF_X:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_jmp_jsgt_x, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_JUMP(ebpf_jit_jmp_jsgt_x, ptr, off, cur))
			return -EINVAL;
		break;
	case BPF_JMP32 | BPF_JSGT | BPF_X:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_jmp32_jsgt_x, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_JUMP(ebpf_jit_jmp32_jsgt_x, ptr, off, cur))
			return -EINVAL;
		break;
	case BPF_JMP | BPF_JSGE | BPF_X:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_jmp_jsge_x, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_JUMP(ebpf_jit_jmp_jsge_x, ptr, off, cur))
			return -EINVAL;
		break;
	case BPF_JMP32 | BPF_JSGE | BPF_X:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_jmp32_jsge_x, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_JUMP(ebpf_jit_jmp32_jsge_x, ptr, off, cur))
			return -EINVAL;
		break;
	case BPF_JMP | BPF_JSLT | BPF_X:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_jmp_jslt_x, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_JUMP(ebpf_jit_jmp_jslt_x, ptr, off, cur))
			return -EINVAL;
		break;
	case BPF_JMP32 | BPF_JSLT | BPF_X:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_jmp32_jslt_x, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_JUMP(ebpf_jit_jmp32_jslt_x, ptr, off, cur))
			return -EINVAL;
		break;
	case BPF_JMP | BPF_JSLE | BPF_X:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_jmp_jsle_x, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_JUMP(ebpf_jit_jmp_jsle_x, ptr, off, cur))
			return -EINVAL;
		break;
	case BPF_JMP32 | BPF_JSLE | BPF_X:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_jmp32_jsle_x, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_JUMP(ebpf_jit_jmp32_jsle_x, ptr, off, cur))
			return -EINVAL;
		break;
	case BPF_JMP | BPF_JSET | BPF_X:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_jmp_jset_x, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_JUMP(ebpf_jit_jmp_jset_x, ptr, off, cur))
			return -EINVAL;
		break;
	case BPF_JMP32 | BPF_JSET | BPF_X:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_jmp32_jset_x, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_JUMP(ebpf_jit_jmp32_jset_x, ptr, off, cur))
			return -EINVAL;
		break;
	case BPF_JMP | BPF_JEQ | BPF_K:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_jmp_jeq_k, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_JUMP(ebpf_jit_jmp_jeq_k, ptr, off, cur) ||
		    !BPF_JIT_INSERT_IMM(ebpf_jit_jmp_jeq_k, ptr, imm, cur))
			return -EINVAL;
		break;
	case BPF_JMP32 | BPF_JEQ | BPF_K:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_jmp32_jeq_k, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_JUMP(ebpf_jit_jmp32_jeq_k, ptr, off, cur) ||
		    !BPF_JIT_INSERT_IMM(ebpf_jit_jmp32_jeq_k, ptr, imm, cur))
			return -EINVAL;
		break;
	case BPF_JMP | BPF_JNE | BPF_K:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_jmp_jne_k, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_JUMP(ebpf_jit_jmp_jne_k, ptr, off, cur) ||
		    !BPF_JIT_INSERT_IMM(ebpf_jit_jmp_jne_k, ptr, imm, cur))
			return -EINVAL;
		break;
	case BPF_JMP32 | BPF_JNE | BPF_K:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_jmp32_jne_k, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_JUMP(ebpf_jit_jmp32_jne_k, ptr, off, cur) ||
		    !BPF_JIT_INSERT_IMM(ebpf_jit_jmp32_jne_k, ptr, imm, cur))
			return -EINVAL;
		break;
	case BPF_JMP | BPF_JGT | BPF_K:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_jmp_jgt_k, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_JUMP(ebpf_jit_jmp_jgt_k, ptr, off, cur) ||
		    !BPF_JIT_INSERT_IMM(ebpf_jit_jmp_jgt_k, ptr, imm, cur))
			return -EINVAL;
		break;
	case BPF_JMP32 | BPF_JGT | BPF_K:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_jmp32_jgt_k, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_JUMP(ebpf_jit_jmp32_jgt_k, ptr, off, cur) ||
		    !BPF_JIT_INSERT_IMM(ebpf_jit_jmp32_jgt_k, ptr, imm, cur))
			return -EINVAL;
		break;
	case BPF_JMP | BPF_JGE | BPF_K:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_jmp_jge_k, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_JUMP(ebpf_jit_jmp_jge_k, ptr, off, cur) ||
		    !BPF_JIT_INSERT_IMM(ebpf_jit_jmp_jge_k, ptr, imm, cur))
			return -EINVAL;
		break;
	case BPF_JMP32 | BPF_JGE | BPF_K:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_jmp32_jge_k, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_JUMP(ebpf_jit_jmp32_jge_k, ptr, off, cur) ||
		    !BPF_JIT_INSERT_IMM(ebpf_jit_jmp32_jge_k, ptr, imm, cur))
			return -EINVAL;
		break;
	case BPF_JMP | BPF_JLT | BPF_K:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_jmp_jlt_k, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_JUMP(ebpf_jit_jmp_jlt_k, ptr, off, cur) ||
		    !BPF_JIT_INSERT_IMM(ebpf_jit_jmp_jlt_k, ptr, imm, cur))
			return -EINVAL;
		break;
	case BPF_JMP32 | BPF_JLT | BPF_K:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_jmp32_jlt_k, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_JUMP(ebpf_jit_jmp32_jlt_k, ptr, off, cur) ||
		    !BPF_JIT_INSERT_IMM(ebpf_jit_jmp32_jlt_k, ptr, imm, cur))
			return -EINVAL;
		break;
	case BPF_JMP | BPF_JLE | BPF_K:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_jmp_jle_k, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_JUMP(ebpf_jit_jmp_jle_k, ptr, off, cur) ||
		    !BPF_JIT_INSERT_IMM(ebpf_jit_jmp32_jlt_k, ptr, imm, cur))
			return -EINVAL;
		break;
	case BPF_JMP32 | BPF_JLE | BPF_K:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_jmp32_jle_k, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_JUMP(ebpf_jit_jmp32_jle_k, ptr, off, cur) ||
		    !BPF_JIT_INSERT_IMM(ebpf_jit_jmp32_jle_k, ptr, imm, cur))
			return -EINVAL;
		break;
	case BPF_JMP | BPF_JSGT | BPF_K:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_jmp_jsgt_k, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_JUMP(ebpf_jit_jmp_jsgt_k, ptr, off, cur) ||
		    !BPF_JIT_INSERT_IMM(ebpf_jit_jmp_jsgt_k, ptr, imm, cur))
			return -EINVAL;
		break;
	case BPF_JMP32 | BPF_JSGT | BPF_K:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_jmp32_jsgt_k, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_JUMP(ebpf_jit_jmp32_jsgt_k, ptr, off, cur) ||
		    !BPF_JIT_INSERT_IMM(ebpf_jit_jmp32_jsgt_k, ptr, imm, cur))
			return -EINVAL;
		break;
	case BPF_JMP | BPF_JSGE | BPF_K:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_jmp_jsge_k, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_JUMP(ebpf_jit_jmp_jsge_k, ptr, off, cur) ||
		    !BPF_JIT_INSERT_IMM(ebpf_jit_jmp_jsge_k, ptr, imm, cur))
			return -EINVAL;
		break;
	case BPF_JMP32 | BPF_JSGE | BPF_K:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_jmp32_jsge_k, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_JUMP(ebpf_jit_jmp32_jsge_k, ptr, off, cur) ||
		    !BPF_JIT_INSERT_IMM(ebpf_jit_jmp32_jsge_k, ptr, imm, cur))
			return -EINVAL;
		break;
	case BPF_JMP | BPF_JSLT | BPF_K:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_jmp_jslt_k, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_JUMP(ebpf_jit_jmp_jslt_k, ptr, off, cur) ||
		    !BPF_JIT_INSERT_IMM(ebpf_jit_jmp_jslt_k, ptr, imm, cur))
			return -EINVAL;
		break;
	case BPF_JMP32 | BPF_JSLT | BPF_K:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_jmp32_jslt_k, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_JUMP(ebpf_jit_jmp32_jslt_k, ptr, off, cur) ||
		    !BPF_JIT_INSERT_IMM(ebpf_jit_jmp32_jslt_k, ptr, imm, cur))
			return -EINVAL;
		break;
	case BPF_JMP | BPF_JSLE | BPF_K:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_jmp_jsle_k, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_JUMP(ebpf_jit_jmp_jsle_k, ptr, off, cur) ||
		    !BPF_JIT_INSERT_IMM(ebpf_jit_jmp_jsle_k, ptr, imm, cur))
			return -EINVAL;
		break;
	case BPF_JMP32 | BPF_JSLE | BPF_K:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_jmp32_jsle_k, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_JUMP(ebpf_jit_jmp32_jsle_k, ptr, off, cur) ||
		    !BPF_JIT_INSERT_IMM(ebpf_jit_jmp32_jsle_k, ptr, imm, cur))
			return -EINVAL;
		break;
	case BPF_JMP | BPF_JSET | BPF_K:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_jmp_jset_k, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_JUMP(ebpf_jit_jmp_jset_k, ptr, off, cur) ||
		    !BPF_JIT_INSERT_IMM(ebpf_jit_jmp_jset_k, ptr, imm, cur))
			return -EINVAL;
		break;
	case BPF_JMP32 | BPF_JSET | BPF_K:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_jmp32_jset_k, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_JUMP(ebpf_jit_jmp32_jset_k, ptr, off, cur) ||
		    !BPF_JIT_INSERT_IMM(ebpf_jit_jmp32_jset_k, ptr, imm, cur))
			return -EINVAL;
		break;
	case BPF_JMP | BPF_CALL:
		size = build_call(ptr, pass, info, cur, instr);
		break;
	case BPF_JMP | BPF_TAIL_CALL:
		size = build_tail_call(ptr, pass, info, num);
		break;
	case BPF_STX | BPF_MEM | BPF_B:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_stx_mem_b, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_OFF(ebpf_jit_stx_mem_b, ptr, off, cur))
			return -EINVAL;
		break;
	case BPF_ST | BPF_MEM | BPF_B:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_st_mem_b, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_IMM(ebpf_jit_st_mem_b, ptr, imm, cur) ||
		    !BPF_JIT_INSERT_OFF(ebpf_jit_st_mem_b, ptr, off, cur))
			return -EINVAL;
		break;
	case BPF_LDX | BPF_MEM | BPF_B:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_ldx_mem_b, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_OFF(ebpf_jit_ldx_mem_b, ptr, off, cur))
			return -EINVAL;
		break;
	case BPF_STX | BPF_MEM | BPF_H:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_stx_mem_h, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_OFF(ebpf_jit_stx_mem_h, ptr, off, cur))
			return -EINVAL;
		break;
	case BPF_ST | BPF_MEM | BPF_H:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_st_mem_h, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_IMM(ebpf_jit_st_mem_h, ptr, imm, cur) ||
		    !BPF_JIT_INSERT_OFF(ebpf_jit_st_mem_h, ptr, off, cur))
			return -EINVAL;
		break;
	case BPF_LDX | BPF_MEM | BPF_H:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_ldx_mem_h, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_OFF(ebpf_jit_ldx_mem_h, ptr, off, cur))
			return -EINVAL;
		break;
	case BPF_STX | BPF_MEM | BPF_W:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_stx_mem_w, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_OFF(ebpf_jit_stx_mem_w, ptr, off, cur))
			return -EINVAL;
		break;
	case BPF_ST | BPF_MEM | BPF_W:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_st_mem_w, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_IMM(ebpf_jit_st_mem_w, ptr, imm, cur) ||
		    !BPF_JIT_INSERT_OFF(ebpf_jit_st_mem_w, ptr, off, cur))
			return -EINVAL;
		break;
	case BPF_LDX | BPF_MEM | BPF_W:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_ldx_mem_w, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_OFF(ebpf_jit_ldx_mem_w, ptr, off, cur))
			return -EINVAL;
		break;
	case BPF_STX | BPF_MEM | BPF_DW:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_stx_mem_dw, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_OFF(ebpf_jit_stx_mem_dw, ptr, off, cur))
			return -EINVAL;
		break;
	case BPF_ST | BPF_MEM | BPF_DW:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_st_mem_dw, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_IMM(ebpf_jit_st_mem_dw, ptr, imm, cur) ||
		    !BPF_JIT_INSERT_OFF(ebpf_jit_st_mem_dw, ptr, off, cur))
			return -EINVAL;
		break;
	case BPF_LDX | BPF_MEM | BPF_DW:
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_ldx_mem_dw, ptr, pass, cur);
		if (!is_codegen_pass(pass))
			break;
		if (!BPF_JIT_INSERT_OFF(ebpf_jit_ldx_mem_dw, ptr, off, cur))
			return -EINVAL;
		break;
	case BPF_STX | BPF_ATOMIC | BPF_W:
	case BPF_STX | BPF_ATOMIC | BPF_DW:
		size = atomic_op(ptr, pass, info, cur, instr);
		break;
	default:
		/* not jitable */
		return -EINVAL;
	}
	return size;
}

/*
 * Build jited program prologues.
 *
 * The first prologue implements tail call counter zeroing and is built only
 * if the program is not eBPF subprogram. The second one is the actual prologue
 * with allocating stack frame, register initializing, etc.
 */
static int build_prologue(void **pptr, const int pass, struct ebpf_prog_info *info)
{
	int size = 0;
	struct cmd_len *cur = &info->prologue[0];
	unsigned int reg_start = info->callee_reg_start, stk_size = info->stack_size;
	void *ptr = *pptr;

	/* zero tail call counter for main eBPF program */
	if (need_tail_call_counter_zeroing(info->prog)) {
		size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_prologue_zero_cnt, ptr, pass, cur);
		if (is_first_pass(pass)) {
			cur->template_len = size;
		} else {
			move_pointer(pptr, cur);
			ptr = *pptr;
		}
		cur++;
	}

	/* build prologue */
	size = BPF_JIT_COPY_ON_2ND_PASS(ebpf_jit_prologue, ptr, pass, cur);
	if (is_first_pass(pass)) {
		cur->template_len = size;
	} else {
		if (is_codegen_pass(pass)) {
			if (!BPF_JIT_INSERT_WSZ(ebpf_jit_prologue, ptr, info->total_regs, cur) ||
			    !BPF_JIT_INSERT_RBS(ebpf_jit_prologue, ptr, reg_start, cur) ||
			    !BPF_JIT_INSERT_STACK_ALLOC(ebpf_jit_prologue, ptr, stk_size, cur))
				return -EINVAL;
		}
		move_pointer(pptr, cur);
	}
	return 0;
}

/*
 * Fill `info' with the size of register window and the beginning
 * of %b registers area, considering flags from `info'.
 */
static inline void calc_reg_window(struct ebpf_prog_info *info)
{
	unsigned int total = MAX_BPF_REG + 3; /* JIT uses 3 additional registers */
	unsigned int reg_start = total;
	unsigned int arg_regs_num = 8;

	if (info->seen_func_call) {
		info->callee_reg_start = reg_start;
		total += arg_regs_num;
	}

	info->total_regs = total;
}

/*
 * Save offset of the translation of `num'th eBPF instruction to addrs array.
 * The offset is the distance in bytes between current position (referenced
 * by `ptr') and image (referenced by `image_ptr').
 *
 * addrs[0] is the offset of the second eBPF instruction translation,
 * addrs[1] is the offset of the third and so on.
 */
static inline void save_addrs(int num, const struct bpf_insn *instr,
			      void *ptr, void *image_ptr, struct ebpf_prog_info *info)
{
	u32 cur_off = (u8 *)ptr - (u8 *)image_ptr;
	int next_instr_num = 0;

	if (!cpu_has(CPU_HWBUG_CODE_PLACEMENT)) {
		info->addrs[num] = cur_off;
		return;
	}

	/*
	 * In case of HW bug, start of image and start of jited program
	 * may differ, if there is a nop interval before the prologue.
	 */
	cur_off -= info->start_offset;

	/*
	 * Also, the start of the translation may have a nop interval
	 * in the beginning. Here we take it into account.
	 */
	next_instr_num = num + is_double_instr(instr) ? 2 : 1;
	if (next_instr_num < info->body_len)
		cur_off += real_wide_instr_offset(&info->body[next_instr_num], 0);

	info->addrs[num] = cur_off;
}

/*
 * Get pointer to jited eBPF program.
 */
static inline void *get_bpf_func(u8 *image, const struct ebpf_prog_info *info)
{
	void *bpf_func = image;

	if (cpu_has(CPU_HWBUG_CODE_PLACEMENT))
		bpf_func += info->start_offset;

	return bpf_func;
}

/*
 * Get exact size of jited eBPF program.
 */
static inline u32 get_bpf_func_size(u32 image_size, const struct ebpf_prog_info *info)
{
	if (cpu_has(CPU_HWBUG_CODE_PLACEMENT))
		image_size -= info->start_offset;

	return image_size;
}

struct bpf_prog *bpf_int_jit_compile(struct bpf_prog *prog)
{
	u8 *image_ptr = NULL;
	unsigned int image_size = 0;
	struct bpf_binary_header *image = NULL;
	const struct bpf_insn *insns = prog->insnsi;
	struct ebpf_prog_info *bpf_prog_info;
	int i = 0, pass = 0;
	void *ptr = NULL;
	int template_size = 0;
	struct e2k_jit_data *jit_data = NULL;

	struct bpf_prog *blinded_prog = NULL, *orig_prog = prog;
	bool blinded = false;

	/* do some compiled time checks */
	compile_time_checks();

	if (!prog->jit_requested)
		return orig_prog;

	blinded_prog = bpf_jit_blind_constants(prog);
	if (IS_ERR(blinded_prog))
		return orig_prog;
	if (blinded_prog != prog) {
		blinded = true;
		prog = blinded_prog;
	}

	jit_data = prog->aux->jit_data;
	if (!jit_data) {
		/* We get here if we meet eBPF program `prog' for the first time */
		jit_data = alloc_jit_data(prog);
		if (!jit_data) {
			prog = orig_prog;
			goto exit;
		}
		bpf_prog_info = &jit_data->info;
		prog->aux->jit_data = jit_data;
	} else {
		/*
		 * We get here if we have already compiled the eBPF program `prog',
		 * but not yet linked it with its subprograms
		 */
		pass = jit_data->pass + 1;
		bpf_prog_info = &jit_data->info;
		image = jit_data->header;
		image_ptr = jit_data->image;
		image_size = jit_data->image_size;
		ptr = image_ptr;
	}

	/* for detailed description of passes see comment in max_pass_num() */
	for (; pass <= max_pass_num(); pass++) {
		/* firstly, deal with prologue ... */
		template_size = build_prologue(&ptr, pass, bpf_prog_info);
		if (template_size < 0)
			goto syllable_insertion_err;

		/* ... and then with BPF instructions */
		for (i = 0; i < prog->len; i++) {
			template_size = compile_single_instruction(ptr, pass,
						bpf_prog_info, i, insns + i);
			if (is_first_pass(pass) && template_size < 0)
				goto not_jitable;
			if (!is_first_pass(pass) && template_size < 0)
				goto syllable_insertion_err;

			if (is_first_pass(pass))
				bpf_prog_info->body[i].template_len = template_size;
			else
				move_pointer(&ptr, bpf_prog_info->body + i);

			/* save address of the next instruction */
			if (is_codegen_pass(pass))
				save_addrs(i, insns + i, ptr, image_ptr, bpf_prog_info);

			if (is_jump(insns + i)) {
				/*
				 * eBPF jump instructions need the calculation
				 * of displacement: JIT sums up the sizes of
				 * translations of all eBPF instructions between
				 * jump and its destination. That's why the
				 * compilation of jump instruction may take
				 * a long time and it is sane to call
				 * cond_reshed().
				 */
				cond_resched();
			}

			if (is_double_instr(insns + i))
				i++;
		}

		if (is_first_pass(pass)) {
			/*
			 * At the end of the first pass we know everything about eBPF program,
			 * so we must:
			 * 1) calculate register window;
			 * 2) allocate memory for jited program;
			 * 3) build a HW bug workaround (if needed);
			 */

			calc_reg_window(bpf_prog_info);

			image_size = get_min_hwbug_size(templates_lengths_sum(bpf_prog_info));
			image = bpf_jit_binary_alloc(image_size + TAIL_CALL_OFFSET_SIZE, &image_ptr,
					E2K_INSTR_ALIGNMENT, jit_fill_exc_software_trap);
			if (!image)
				goto image_alloc_err;
			image_ptr += TAIL_CALL_OFFSET_SIZE;
			ptr = (void *) image_ptr;

			if (cpu_has(CPU_HWBUG_CODE_PLACEMENT)) {
				/*
				 * After HW bug workaround calculation we get
				 * the exact size of jited program.
				 */
				image_size = calculate_hwbug_workaround(ptr, insns, bpf_prog_info);
			}
		}
		if (is_codegen_pass(pass) || is_extra_pass(pass))
			break;
	}

	if (bpf_jit_enable > 1)
		bpf_jit_dump(prog->len, image_size, pass, image_ptr);

	if (!prog->is_func || is_extra_pass(pass)) {
		/*
		 * The last small thing: store tail call offset before
		 * the jited program.
		 * See details in a comment in eBPF JIT header file.
		 */
		store_tail_call_offset(image_ptr, bpf_prog_info);

		bpf_jit_binary_lock_ro(image);
	} else {
		/*
		 * Save some information about this eBPF program and the process
		 * of its jitting. We will use this information if we will be
		 * woken up again for linking with subprograms.
		 */
		jit_data->pass = pass;
		jit_data->header = image;
		jit_data->image = image_ptr;
		jit_data->image_size = image_size;
	}

	prog->bpf_func = get_bpf_func(image_ptr, bpf_prog_info);
	prog->jited = 1;
	prog->jited_len = get_bpf_func_size(image_size, bpf_prog_info);

	if (!prog->is_func || is_extra_pass(pass)) {
		bpf_prog_fill_jited_linfo(prog, bpf_prog_info->addrs);
		goto free_and_exit;
	}
	goto exit;

syllable_insertion_err:
	bpf_jit_binary_free(image);
	prog->bpf_func = NULL;
	prog->jited = 0;
	prog->jited_len = 0;
not_jitable:
image_alloc_err:
	prog->aux->jit_data = NULL;
	prog = orig_prog;
free_and_exit:
	kfree(bpf_prog_info->addrs);
	kfree(bpf_prog_info->prologue);
	kfree(jit_data);
exit:
	if (blinded)
		bpf_jit_prog_release_other(prog, prog == orig_prog ?
					   blinded_prog : orig_prog);
	return prog;
}
