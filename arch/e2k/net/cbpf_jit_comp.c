/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * cBPF JIT compiler.
 */

#include <linux/filter.h>
#include <linux/types.h>
#include <asm/cpu_regs.h>
#include <asm/cpu_features.h>

#include "cbpf_jit.h"

#define SEEN_MEM_USAGE		0x1
#define SEEN_FUNC_CALL		0x2

/*
 * Insert constant K into template copy.
 */
#define BPF_JIT_INSERT_K(template, pointer, k, cmd_lens) \
		BPF_JIT_INSERT_IMM32(template, pointer, k, cmd_lens, BPF_JIT_K_LABEL)

/*
 * Insert register number into template after it was copied to allocated memory.
 *
 * cBPF programs can use so-called scratch memory consisting of 16 cells. JIT
 * compiler for e2k places this memory upon registers r8-r23. This macro adds
 * the number of memory cell to the destination/source register from template,
 * so the value is stored/loaded to/from the right scratch memory cell.
 */
#define BPF_JIT_INSERT_REG(template, pointer, reg_num, cmd_lens, name, field) \
({ \
	bool insert_reg_res = false; \
	void *insert_reg_tmp_ptr = pointer + real_wide_instr_offset(cmd_lens, \
			BPF_JIT_OFFSET(BPF_JIT_MEM_LABEL(template, name), template)); \
	instr_als_t *insert_reg_als_ptr = find_als(insert_reg_tmp_ptr, 0); \
	if (insert_reg_als_ptr) { \
		insert_reg_als_ptr->alf2.field += reg_num; \
		insert_reg_res = true; \
	} else { \
		WARN_ONCE(1, BPF_JIT_WARN "failed to find " \
				__stringify(field) " field in als0 syllable"); \
	} \
	insert_reg_res; \
})

#define BPF_JIT_INSERT_SRC_REG(template, pointer, reg_num, cmd_lens) \
		BPF_JIT_INSERT_REG(template, pointer, reg_num, cmd_lens, src2, src2.word)
#define BPF_JIT_INSERT_DST_REG(template, pointer, reg_num, cmd_lens) \
		BPF_JIT_INSERT_REG(template, pointer, reg_num, cmd_lens, dst, dst)

/*
 * Declare all cBPF templates.
 */
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_prologue);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_alu_add_x);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_alu_add_k);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_alu_sub_x);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_alu_sub_k);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_alu_and_x);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_alu_and_k);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_alu_or_x);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_alu_or_k);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_alu_xor_x);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_alu_xor_k);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_alu_shl_x);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_alu_shl_k);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_alu_shr_x);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_alu_shr_k);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_alu_mul_x);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_alu_mul_k);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_alu_div_x);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_alu_div_k);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_alu_mod_x);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_alu_mod_k);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_alu_neg);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_misc_txa);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_misc_tax);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_ret_a);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_ret_k);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_ld_mem);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_ldx_mem);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_st);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_stx);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_ld_imm);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_ldx_imm);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_ld_w_len);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_ldx_w_len);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_ldx_b_msh_neg_k);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_ldx_b_msh_pos_k);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_ld_w_abs_neg_k);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_ld_w_abs_pos_k);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_ld_h_abs_neg_k);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_ld_h_abs_pos_k);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_ld_b_abs_neg_k);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_ld_b_abs_pos_k);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_ld_w_ind);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_ld_h_ind);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_ld_b_ind);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_jmp_ja);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_jmp_jgt_x);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_jmp_jgt_k);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_jmp_jge_x);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_jmp_jge_k);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_jmp_jeq_x);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_jmp_jeq_k);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_jmp_jset_x);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_jmp_jset_k);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_anc_mark);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_anc_rxhash);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_anc_vlan_tag);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_anc_queue);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_anc_cpu);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_anc_protocol);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_anc_pkttype);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_anc_vlan_tag_present);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_anc_ifindex);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_anc_hatype);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_anc_pay_offset);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_anc_vlan_tpid);
BPF_JIT_EXTERN_TEMPLATE(cbpf_jit_ldx_w_abs);

/*
 * Declare labels for inserting different fields and constants into template.
 */
extern char BPF_JIT_WSZ_LABEL(cbpf_jit_prologue)[];
extern char BPF_JIT_RBS_LABEL(cbpf_jit_prologue)[];
extern char BPF_JIT_K_LABEL(cbpf_jit_alu_add_k)[];
extern char BPF_JIT_K_LABEL(cbpf_jit_alu_sub_k)[];
extern char BPF_JIT_K_LABEL(cbpf_jit_alu_and_k)[];
extern char BPF_JIT_K_LABEL(cbpf_jit_alu_or_k)[];
extern char BPF_JIT_K_LABEL(cbpf_jit_alu_xor_k)[];
extern char BPF_JIT_K_LABEL(cbpf_jit_alu_shl_k)[];
extern char BPF_JIT_K_LABEL(cbpf_jit_alu_shr_k)[];
extern char BPF_JIT_K_LABEL(cbpf_jit_alu_mul_k)[];
extern char BPF_JIT_K_LABEL(cbpf_jit_alu_div_k)[];
extern char BPF_JIT_K_LABEL(cbpf_jit_alu_mod_k)[];
extern char BPF_JIT_K_LABEL(cbpf_jit_ret_k)[];
extern char BPF_JIT_K_LABEL(cbpf_jit_jmp_jgt_k)[];
extern char BPF_JIT_K_LABEL(cbpf_jit_jmp_jge_k)[];
extern char BPF_JIT_K_LABEL(cbpf_jit_jmp_jeq_k)[];
extern char BPF_JIT_K_LABEL(cbpf_jit_jmp_jset_k)[];
extern char BPF_JIT_K_LABEL(cbpf_jit_ldx_b_msh_neg_k)[];
extern char BPF_JIT_K_LABEL(cbpf_jit_ldx_b_msh_pos_k)[];
extern char BPF_JIT_K_LABEL(cbpf_jit_ld_w_abs_neg_k)[];
extern char BPF_JIT_K_LABEL(cbpf_jit_ld_h_abs_neg_k)[];
extern char BPF_JIT_K_LABEL(cbpf_jit_ld_b_abs_neg_k)[];
extern char BPF_JIT_K_LABEL(cbpf_jit_ld_w_abs_pos_k)[];
extern char BPF_JIT_K_LABEL(cbpf_jit_ld_h_abs_pos_k)[];
extern char BPF_JIT_K_LABEL(cbpf_jit_ld_b_abs_pos_k)[];
extern char BPF_JIT_K_LABEL(cbpf_jit_ld_w_ind)[];
extern char BPF_JIT_K_LABEL(cbpf_jit_ld_h_ind)[];
extern char BPF_JIT_K_LABEL(cbpf_jit_ld_b_ind)[];
extern char BPF_JIT_K_LABEL(cbpf_jit_ld_imm)[];
extern char BPF_JIT_K_LABEL(cbpf_jit_ldx_imm)[];
extern char BPF_JIT_K_LABEL(cbpf_jit_ldx_w_abs)[];
extern char BPF_JIT_MEM_SRC_LABEL(cbpf_jit_ld_mem)[];
extern char BPF_JIT_MEM_SRC_LABEL(cbpf_jit_ldx_mem)[];
extern char BPF_JIT_MEM_DST_LABEL(cbpf_jit_st)[];
extern char BPF_JIT_MEM_DST_LABEL(cbpf_jit_stx)[];
extern char BPF_JIT_JMP_LABEL(cbpf_jit_jmp_ja, ja)[];
extern char BPF_JIT_JMP_LABEL(cbpf_jit_jmp_jgt_x, jt)[];
extern char BPF_JIT_JMP_LABEL(cbpf_jit_jmp_jgt_x, jf)[];
extern char BPF_JIT_JMP_LABEL(cbpf_jit_jmp_jgt_k, jt)[];
extern char BPF_JIT_JMP_LABEL(cbpf_jit_jmp_jgt_k, jf)[];
extern char BPF_JIT_JMP_LABEL(cbpf_jit_jmp_jge_x, jt)[];
extern char BPF_JIT_JMP_LABEL(cbpf_jit_jmp_jge_x, jf)[];
extern char BPF_JIT_JMP_LABEL(cbpf_jit_jmp_jge_k, jt)[];
extern char BPF_JIT_JMP_LABEL(cbpf_jit_jmp_jge_k, jf)[];
extern char BPF_JIT_JMP_LABEL(cbpf_jit_jmp_jeq_x, jt)[];
extern char BPF_JIT_JMP_LABEL(cbpf_jit_jmp_jeq_x, jf)[];
extern char BPF_JIT_JMP_LABEL(cbpf_jit_jmp_jeq_k, jt)[];
extern char BPF_JIT_JMP_LABEL(cbpf_jit_jmp_jeq_k, jf)[];
extern char BPF_JIT_JMP_LABEL(cbpf_jit_jmp_jset_x, jt)[];
extern char BPF_JIT_JMP_LABEL(cbpf_jit_jmp_jset_x, jf)[];
extern char BPF_JIT_JMP_LABEL(cbpf_jit_jmp_jset_k, jt)[];
extern char BPF_JIT_JMP_LABEL(cbpf_jit_jmp_jset_k, jf)[];
extern char BPF_JIT_FUNC_LABEL(cbpf_jit_ldx_b_msh_neg_k, bpf_internal_load_pointer_neg_helper)[];
extern char BPF_JIT_FUNC_LABEL(cbpf_jit_ldx_b_msh_pos_k, skb_copy_bits)[];
extern char BPF_JIT_FUNC_LABEL(cbpf_jit_ld_w_abs_neg_k, bpf_internal_load_pointer_neg_helper)[];
extern char BPF_JIT_FUNC_LABEL(cbpf_jit_ld_w_abs_pos_k, skb_copy_bits)[];
extern char BPF_JIT_FUNC_LABEL(cbpf_jit_ld_h_abs_neg_k, bpf_internal_load_pointer_neg_helper)[];
extern char BPF_JIT_FUNC_LABEL(cbpf_jit_ld_h_abs_pos_k, skb_copy_bits)[];
extern char BPF_JIT_FUNC_LABEL(cbpf_jit_ld_b_abs_neg_k, bpf_internal_load_pointer_neg_helper)[];
extern char BPF_JIT_FUNC_LABEL(cbpf_jit_ld_b_abs_pos_k, skb_copy_bits)[];
extern char BPF_JIT_FUNC_LABEL(cbpf_jit_ld_w_ind, bpf_internal_load_pointer_neg_helper)[];
extern char BPF_JIT_FUNC_LABEL(cbpf_jit_ld_w_ind, skb_copy_bits)[];
extern char BPF_JIT_FUNC_LABEL(cbpf_jit_ld_h_ind, bpf_internal_load_pointer_neg_helper)[];
extern char BPF_JIT_FUNC_LABEL(cbpf_jit_ld_h_ind, skb_copy_bits)[];
extern char BPF_JIT_FUNC_LABEL(cbpf_jit_ld_b_ind, bpf_internal_load_pointer_neg_helper)[];
extern char BPF_JIT_FUNC_LABEL(cbpf_jit_ld_b_ind, skb_copy_bits)[];
extern char BPF_JIT_FUNC_LABEL(cbpf_jit_anc_pay_offset, skb_get_poff)[];
extern char BPF_JIT_WBS_LABEL(cbpf_jit_ldx_b_msh_neg_k, bpf_internal_load_pointer_neg_helper)[];
extern char BPF_JIT_WBS_LABEL(cbpf_jit_ldx_b_msh_pos_k, skb_copy_bits)[];
extern char BPF_JIT_WBS_LABEL(cbpf_jit_ld_w_abs_neg_k, bpf_internal_load_pointer_neg_helper)[];
extern char BPF_JIT_WBS_LABEL(cbpf_jit_ld_w_abs_pos_k, skb_copy_bits)[];
extern char BPF_JIT_WBS_LABEL(cbpf_jit_ld_h_abs_neg_k, bpf_internal_load_pointer_neg_helper)[];
extern char BPF_JIT_WBS_LABEL(cbpf_jit_ld_h_abs_pos_k, skb_copy_bits)[];
extern char BPF_JIT_WBS_LABEL(cbpf_jit_ld_b_abs_neg_k, bpf_internal_load_pointer_neg_helper)[];
extern char BPF_JIT_WBS_LABEL(cbpf_jit_ld_b_abs_pos_k, skb_copy_bits)[];
extern char BPF_JIT_WBS_LABEL(cbpf_jit_ld_w_ind, bpf_internal_load_pointer_neg_helper)[];
extern char BPF_JIT_WBS_LABEL(cbpf_jit_ld_w_ind, skb_copy_bits)[];
extern char BPF_JIT_WBS_LABEL(cbpf_jit_ld_h_ind, bpf_internal_load_pointer_neg_helper)[];
extern char BPF_JIT_WBS_LABEL(cbpf_jit_ld_h_ind, skb_copy_bits)[];
extern char BPF_JIT_WBS_LABEL(cbpf_jit_ld_b_ind, bpf_internal_load_pointer_neg_helper)[];
extern char BPF_JIT_WBS_LABEL(cbpf_jit_ld_b_ind, skb_copy_bits)[];
extern char BPF_JIT_WBS_LABEL(cbpf_jit_anc_pay_offset, skb_get_poff)[];

/*
 * In this structure JIT stores all information about cBPF program being jited.
 */
struct cbpf_prog_info {
	struct cmd_len prologue;	/* info about prologue added by JIT */
	struct cmd_len *body;		/* info about BPF instruction translations */
	unsigned int len;		/* number of BPF instructions in program body */
	int seen;			/* field to describe special cases */
};

static inline int max_pass_num(void)
{
	/*
	 * cBPF JIT for e2k operates in two passes:
	 *    #0 - first pass, just get acquainted with cBPF program;
	 *    #1 - code-generation pass, now fill image with e2k code. Copy
	 *         templates and insert constants, jump displacements, etc.
	 *         into template copies.
	 *
	 *    ***
	 *    *** Note: between #0 and #1 there is an additional hidden pass
	 *    *** to build a HW bug workaround. This pass takes place in
	 *    *** `calculate_hwbug_workaround()' only if there is a need for
	 *    *** the workaround.
	 *    ***
	 */
	return 1;
}

static inline int init_prog_info(struct cbpf_prog_info *info, unsigned int len)
{
	info->body = kvzalloc(sizeof(*(info->body)) * len, GFP_KERNEL);
	if (!info->body)
		return 1;
	info->len = len;
	info->seen = 0;
	info->prologue.template_len = BPF_JIT_TEMPLATE_SIZE(cbpf_jit_prologue);
	info->prologue.total_len = 0;
	info->prologue.template_ptr = NULL;
	info->prologue.is_jump_dest = true;
	info->prologue.int_num = 0;
	return 0;
}

static inline void free_prog_info(struct cbpf_prog_info *info)
{
	kvfree(info->body);
}

/*
 * Calculate the total size of program as sum of template lengths.
 */
static inline unsigned int templates_lengths_sum(const struct cbpf_prog_info *info)
{
	unsigned int i = 0;
	unsigned int counter = info->prologue.template_len;

	for (i = 0; i < info->len; i++)
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
 *
 * As backward jumps are not allowed in classic BPF, the return value of
 * the function is always positive and thus unsigned.
 */
static unsigned int disp_jump(unsigned int jump, unsigned int left,
			      const struct cmd_len cmd_lens[])
{
	unsigned int acc = left, i = 0;

	if (!cpu_has(CPU_HWBUG_CODE_PLACEMENT)) {
		for (i = 0; i < jump; i++)
			acc += cmd_lens[i + 1].template_len;
	} else {
		for (i = 0; i < jump; i++)
			acc += cmd_lens[i + 1].total_len;

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
 * Mark BPF instructions that can be jumped to from the current
 * instruction (if any).
 */
static inline void mark_jump_destinations(const struct sock_filter *instr,
					  struct cmd_len *cmd_lengths)
{
	u16 code = bpf_anc_helper(instr);

	if (!cpu_has(CPU_HWBUG_CODE_PLACEMENT))
		return;

	if (BPF_CLASS(code) != BPF_JMP)
		return;

	if (BPF_OP(code) == BPF_JA) {
		cmd_lengths[instr->k + 1].is_jump_dest = true;
	} else {
		cmd_lengths[instr->jt + 1].is_jump_dest = true;
		cmd_lengths[instr->jf + 1].is_jump_dest = true;
	}
}

/*
 * Since we allocated memory and know the starting address
 * (referenced by 'ptr'), we can build an exact workaround of HW bug.
 * Also return the exact size of jited program if the workaround
 * was built.
 */
static unsigned int calculate_hwbug_workaround(void *ptr, struct cbpf_prog_info *info)
{
	unsigned int i = 0, real_prog_len = 0, instr_len = 0;

	if (!cpu_has(CPU_HWBUG_CODE_PLACEMENT))
		return 0;

	instr_len = build_workaround_for_instr(ptr, &(info->prologue));
	real_prog_len += instr_len;
	for (i = 0; i < info->len; i++) {
		instr_len = build_workaround_for_instr(ptr + real_prog_len, &info->body[i]);
		real_prog_len += instr_len;
	}

	return real_prog_len;
}

/*
 * This function is a huge switch that matches BPF instrution codes
 * to the corresponding template names. Depending in the value of 'pass',
 * it just returns the length of the template or copies the template
 * to the allocated memory.
 */
static unsigned int compile_single_instruction(void *ptr, const int pass,
					       struct cmd_len lens[],
					       const struct sock_filter *instr,
					       const int reg_start, int *seen)
{
	unsigned int size = 0;

	switch (bpf_anc_helper(instr)) {
	case BPF_ALU | BPF_ADD | BPF_X: /* A += X; */
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_alu_add_x, ptr, pass, lens);
		break;
	case BPF_ALU | BPF_ADD | BPF_K: /* A += K; */
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_alu_add_k, ptr, pass, lens);
		if (is_first_pass(pass))
			break;
		if (!BPF_JIT_INSERT_K(cbpf_jit_alu_add_k, ptr, instr->k, lens))
			return 0;
		break;
	case BPF_ALU | BPF_SUB | BPF_X: /* A -= X; */
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_alu_sub_x, ptr, pass, lens);
		break;
	case BPF_ALU | BPF_SUB | BPF_K: /* A -= K */
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_alu_sub_k, ptr, pass, lens);
		if (is_first_pass(pass))
			break;
		if (!BPF_JIT_INSERT_K(cbpf_jit_alu_sub_k, ptr, instr->k, lens))
			return 0;
		break;
	case BPF_ALU | BPF_AND | BPF_X: /* A &= X */
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_alu_and_x, ptr, pass, lens);
		break;
	case BPF_ALU | BPF_AND | BPF_K: /* A &= K */
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_alu_and_k, ptr, pass, lens);
		if (is_first_pass(pass))
			break;
		if (!BPF_JIT_INSERT_K(cbpf_jit_alu_and_k, ptr, instr->k, lens))
			return 0;
		break;
	case BPF_ALU | BPF_OR | BPF_X: /* A |= X */
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_alu_or_x, ptr, pass, lens);
		break;
	case BPF_ALU | BPF_OR | BPF_K: /* A |= K */
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_alu_or_k, ptr, pass, lens);
		if (is_first_pass(pass))
			break;
		if (!BPF_JIT_INSERT_K(cbpf_jit_alu_or_k, ptr, instr->k, lens))
			return 0;
		break;
	case BPF_ANC | SKF_AD_ALU_XOR_X:
	case BPF_ALU | BPF_XOR | BPF_X: /* A ^= X; */
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_alu_xor_x, ptr, pass, lens);
		break;
	case BPF_ALU | BPF_XOR | BPF_K: /* A ^= K */
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_alu_xor_k, ptr, pass, lens);
		if (is_first_pass(pass))
			break;
		if (!BPF_JIT_INSERT_K(cbpf_jit_alu_xor_k, ptr, instr->k, lens))
			return 0;
		break;
	case BPF_ALU | BPF_LSH | BPF_X: /* A <<= X */
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_alu_shl_x, ptr, pass, lens);
		break;
	case BPF_ALU | BPF_LSH | BPF_K: /* A <<= K */
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_alu_shl_k, ptr, pass, lens);
		if (is_first_pass(pass))
			break;
		if (!BPF_JIT_INSERT_K(cbpf_jit_alu_shl_k, ptr, instr->k, lens))
			return 0;
		break;
	case BPF_ALU | BPF_RSH | BPF_X: /* A >>= X */
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_alu_shr_x, ptr, pass, lens);
		break;
	case BPF_ALU | BPF_RSH | BPF_K: /* A >>= K */
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_alu_shr_k, ptr, pass, lens);
		if (is_first_pass(pass))
			break;
		if (!BPF_JIT_INSERT_K(cbpf_jit_alu_shr_k, ptr, instr->k, lens))
			return 0;
		break;
	case BPF_ALU | BPF_MUL | BPF_X: /* A *= X; */
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_alu_mul_x, ptr, pass, lens);
		break;
	case BPF_ALU | BPF_MUL | BPF_K: /* A *= K */
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_alu_mul_k, ptr, pass, lens);
		if (is_first_pass(pass))
			break;
		if (!BPF_JIT_INSERT_K(cbpf_jit_alu_mul_k, ptr, instr->k, lens))
			return 0;
		break;
	case BPF_ALU | BPF_DIV | BPF_X: /* A /= X */
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_alu_div_x, ptr, pass, lens);
		break;
	case BPF_ALU | BPF_DIV | BPF_K: /* A /= K */
		/* Verifier guarantees that K != 0 */
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_alu_div_k, ptr, pass, lens);
		if (is_first_pass(pass))
			break;
		if (!BPF_JIT_INSERT_K(cbpf_jit_alu_div_k, ptr, instr->k, lens))
			return 0;
		break;
	case BPF_ALU | BPF_MOD | BPF_X: /* A %= X */
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_alu_mod_x, ptr, pass, lens);
		break;
	case BPF_ALU | BPF_MOD | BPF_K: /* A %= K */
		/* Verifier guarantees that K != 0 */
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_alu_mod_k, ptr, pass, lens);
		if (is_first_pass(pass))
			break;
		if (!BPF_JIT_INSERT_K(cbpf_jit_alu_mod_k, ptr, instr->k, lens))
			return 0;
		break;
	case BPF_ALU | BPF_NEG:
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_alu_neg, ptr, pass, lens);
		break;
	case BPF_MISC | BPF_TXA: /* A = X */
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_misc_txa, ptr, pass, lens);
		break;
	case BPF_MISC | BPF_TAX: /* X = A */
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_misc_tax, ptr, pass, lens);
		break;
	case BPF_RET | BPF_A: /* return A */
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_ret_a, ptr, pass, lens);
		break;
	case BPF_RET | BPF_K: /* return K */
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_ret_k, ptr, pass, lens);
		if (is_first_pass(pass))
			break;
		if (!BPF_JIT_INSERT_K(cbpf_jit_ret_k, ptr, instr->k, lens))
			return 0;
		break;
	case BPF_LD | BPF_IMM: /* A = K */
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_ld_imm, ptr, pass, lens);
		if (is_first_pass(pass))
			break;
		if (!BPF_JIT_INSERT_K(cbpf_jit_ld_imm, ptr, instr->k, lens))
			return 0;
		break;
	case BPF_LDX | BPF_IMM: /* X = K */
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_ldx_imm, ptr, pass, lens);
		if (is_first_pass(pass))
			break;
		if (!BPF_JIT_INSERT_K(cbpf_jit_ldx_imm, ptr, instr->k, lens))
			return 0;
		break;
	case BPF_LD | BPF_MEM: /* A = M[K] */
		*seen |= SEEN_MEM_USAGE;
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_ld_mem, ptr, pass, lens);
		if (is_first_pass(pass))
			break;
		if (!BPF_JIT_INSERT_SRC_REG(cbpf_jit_ld_mem, ptr, instr->k, lens))
			return 0;
		break;
	case BPF_LDX | BPF_MEM: /* X = M[K] */
		*seen |= SEEN_MEM_USAGE;
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_ldx_mem, ptr, pass, lens);
		if (is_first_pass(pass))
			break;
		if (!BPF_JIT_INSERT_SRC_REG(cbpf_jit_ldx_mem, ptr, instr->k, lens))
			return 0;
		break;
	case BPF_ST: /* M[K] = A */
		*seen |= SEEN_MEM_USAGE;
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_st, ptr, pass, lens);
		if (is_first_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DST_REG(cbpf_jit_st, ptr, instr->k, lens))
			return 0;
		break;
	case BPF_STX: /* M[K] = X */
		*seen |= SEEN_MEM_USAGE;
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_stx, ptr, pass, lens);
		if (is_first_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DST_REG(cbpf_jit_stx, ptr, instr->k, lens))
			return 0;
		break;
	case BPF_JMP | BPF_JA: /* pc += K */
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_jmp_ja, ptr, pass, lens);
		if (is_first_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_JUMP(cbpf_jit_jmp_ja, ja, ptr, instr->k, lens))
			return 0;
		break;
	case BPF_JMP | BPF_JGT | BPF_X: /* pc += (A > X) ? jt : jf */
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_jmp_jgt_x, ptr, pass, lens);
		if (is_first_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_JUMP(cbpf_jit_jmp_jgt_x, jt, ptr, instr->jt, lens) ||
		    !BPF_JIT_INSERT_DISP_JUMP(cbpf_jit_jmp_jgt_x, jf, ptr, instr->jf, lens))
			return 0;
		break;
	case BPF_JMP | BPF_JGT | BPF_K: /* pc += (A > K) ? jt : jf */
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_jmp_jgt_k, ptr, pass, lens);
		if (is_first_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_JUMP(cbpf_jit_jmp_jgt_k, jt, ptr, instr->jt, lens) ||
		    !BPF_JIT_INSERT_DISP_JUMP(cbpf_jit_jmp_jgt_k, jf, ptr, instr->jf, lens) ||
		    !BPF_JIT_INSERT_K(cbpf_jit_jmp_jgt_k, ptr, instr->k, lens))
			return 0;
		break;
	case BPF_JMP | BPF_JGE | BPF_X: /* pc += (A >= X) ? jt : jf */
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_jmp_jge_x, ptr, pass, lens);
		if (is_first_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_JUMP(cbpf_jit_jmp_jge_x, jt, ptr, instr->jt, lens) ||
		    !BPF_JIT_INSERT_DISP_JUMP(cbpf_jit_jmp_jge_x, jf, ptr, instr->jf, lens))
			return 0;
		break;
	case BPF_JMP | BPF_JGE | BPF_K: /* pc += (A >= K) ? jt : jf */
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_jmp_jge_k, ptr, pass, lens);
		if (is_first_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_JUMP(cbpf_jit_jmp_jge_k, jt, ptr, instr->jt, lens) ||
		    !BPF_JIT_INSERT_DISP_JUMP(cbpf_jit_jmp_jge_k, jf, ptr, instr->jf, lens) ||
		    !BPF_JIT_INSERT_K(cbpf_jit_jmp_jge_k, ptr, instr->k, lens))
			return 0;
		break;
	case BPF_JMP | BPF_JEQ | BPF_X: /* pc += (A == X) ? jt : jf */
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_jmp_jeq_x, ptr, pass, lens);
		if (is_first_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_JUMP(cbpf_jit_jmp_jeq_x, jt, ptr, instr->jt, lens) ||
		    !BPF_JIT_INSERT_DISP_JUMP(cbpf_jit_jmp_jeq_x, jf, ptr, instr->jf, lens))
			return 0;
		break;
	case BPF_JMP | BPF_JEQ | BPF_K: /* pc += (A == K) ? jt : jf */
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_jmp_jeq_k, ptr, pass, lens);
		if (is_first_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_JUMP(cbpf_jit_jmp_jeq_k, jt, ptr, instr->jt, lens) ||
		    !BPF_JIT_INSERT_DISP_JUMP(cbpf_jit_jmp_jeq_k, jf, ptr, instr->jf, lens) ||
		    !BPF_JIT_INSERT_K(cbpf_jit_jmp_jeq_k, ptr, instr->k, lens))
			return 0;
		break;
	case BPF_JMP | BPF_JSET | BPF_X: /* pc += (A & X) ? jt : jf */
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_jmp_jset_x, ptr, pass, lens);
		if (is_first_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_JUMP(cbpf_jit_jmp_jset_x, jt, ptr, instr->jt, lens) ||
		    !BPF_JIT_INSERT_DISP_JUMP(cbpf_jit_jmp_jset_x, jf, ptr, instr->jf, lens))
			return 0;
		break;
	case BPF_JMP | BPF_JSET | BPF_K: /* pc += (A & K) ? jt : jf */
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_jmp_jset_k, ptr, pass, lens);
		if (is_first_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_JUMP(cbpf_jit_jmp_jset_k, jt, ptr, instr->jt, lens) ||
		    !BPF_JIT_INSERT_DISP_JUMP(cbpf_jit_jmp_jset_k, jf, ptr, instr->jf, lens) ||
		    !BPF_JIT_INSERT_K(cbpf_jit_jmp_jset_k, ptr, instr->k, lens))
			return 0;
		break;
	case BPF_LD | BPF_W | BPF_LEN: /* A = skb->len */
		BUILD_BUG_ON(sizeof_field(struct sk_buff, len) != 4);
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_ld_w_len, ptr, pass, lens);
		break;
	case BPF_LDX | BPF_W | BPF_LEN: /* X = skb->len */
		BUILD_BUG_ON(sizeof_field(struct sk_buff, len) != 4);
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_ldx_w_len, ptr, pass, lens);
		break;
	case BPF_LDX | BPF_B | BPF_MSH: /* X = 4*(P[K:K]&0xf) */
		if ((int)instr->k < 0) {
			*seen |= SEEN_FUNC_CALL;
			size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_ldx_b_msh_neg_k, ptr, pass, lens);
			if (is_first_pass(pass))
				break;
			if (!BPF_JIT_INSERT_DISP_CALL(cbpf_jit_ldx_b_msh_neg_k, ptr,
						      bpf_internal_load_pointer_neg_helper, lens) ||
			    !BPF_JIT_INSERT_K(cbpf_jit_ldx_b_msh_neg_k, ptr, instr->k, lens) ||
			    !BPF_JIT_INSERT_WBS(cbpf_jit_ldx_b_msh_neg_k, ptr,
						bpf_internal_load_pointer_neg_helper,
						reg_start, lens))
				return 0;
			break;
		}
		*seen |= SEEN_FUNC_CALL;
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_ldx_b_msh_pos_k, ptr, pass, lens);
		if (is_first_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_CALL(cbpf_jit_ldx_b_msh_pos_k, ptr, skb_copy_bits, lens) ||
		    !BPF_JIT_INSERT_K(cbpf_jit_ldx_b_msh_pos_k, ptr, instr->k, lens) ||
		    !BPF_JIT_INSERT_WBS(cbpf_jit_ldx_b_msh_pos_k, ptr,
					skb_copy_bits, reg_start, lens))
			return 0;
		break;
	case BPF_LD | BPF_W | BPF_ABS: /* A = P[K:K+3] */
		if ((int)instr->k < 0) {
			*seen |= SEEN_FUNC_CALL;
			size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_ld_w_abs_neg_k, ptr, pass, lens);
			if (is_first_pass(pass))
				break;
			if (!BPF_JIT_INSERT_DISP_CALL(cbpf_jit_ld_w_abs_neg_k, ptr,
						bpf_internal_load_pointer_neg_helper, lens) ||
			    !BPF_JIT_INSERT_K(cbpf_jit_ld_w_abs_neg_k, ptr, instr->k, lens) ||
			    !BPF_JIT_INSERT_WBS(cbpf_jit_ld_w_abs_neg_k, ptr,
						bpf_internal_load_pointer_neg_helper,
						reg_start, lens))
				return 0;
			break;
		}
		*seen |= SEEN_FUNC_CALL;
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_ld_w_abs_pos_k, ptr, pass, lens);
		if (is_first_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_CALL(cbpf_jit_ld_w_abs_pos_k, ptr, skb_copy_bits, lens) ||
		    !BPF_JIT_INSERT_K(cbpf_jit_ld_w_abs_pos_k, ptr, instr->k, lens) ||
		    !BPF_JIT_INSERT_WBS(cbpf_jit_ld_w_abs_pos_k, ptr,
					skb_copy_bits, reg_start, lens))
			return 0;
		break;
	case BPF_LD | BPF_H | BPF_ABS: /* A = P[K:K+1] */
		if ((int)instr->k < 0) {
			*seen |= SEEN_FUNC_CALL;
			size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_ld_h_abs_neg_k, ptr, pass, lens);
			if (is_first_pass(pass))
				break;
			if (!BPF_JIT_INSERT_DISP_CALL(cbpf_jit_ld_h_abs_neg_k, ptr,
						      bpf_internal_load_pointer_neg_helper, lens) ||
			    !BPF_JIT_INSERT_K(cbpf_jit_ld_h_abs_neg_k, ptr, instr->k, lens) ||
			    !BPF_JIT_INSERT_WBS(cbpf_jit_ld_h_abs_neg_k, ptr,
						bpf_internal_load_pointer_neg_helper,
						reg_start, lens))
				return 0;
			break;
		}
		*seen |= SEEN_FUNC_CALL;
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_ld_h_abs_pos_k, ptr, pass, lens);
		if (is_first_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_CALL(cbpf_jit_ld_h_abs_pos_k, ptr, skb_copy_bits, lens) ||
		    !BPF_JIT_INSERT_K(cbpf_jit_ld_h_abs_pos_k, ptr, instr->k, lens) ||
		    !BPF_JIT_INSERT_WBS(cbpf_jit_ld_h_abs_pos_k, ptr,
					skb_copy_bits, reg_start, lens))
			return 0;
		break;
	case BPF_LD | BPF_B | BPF_ABS: /* A = P[K:K] */
		if ((int)instr->k < 0) {
			*seen |= SEEN_FUNC_CALL;
			size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_ld_b_abs_neg_k, ptr, pass, lens);
			if (is_first_pass(pass))
				break;
			if (!BPF_JIT_INSERT_DISP_CALL(cbpf_jit_ld_b_abs_neg_k, ptr,
						      bpf_internal_load_pointer_neg_helper, lens) ||
			    !BPF_JIT_INSERT_K(cbpf_jit_ld_b_abs_neg_k, ptr, instr->k, lens) ||
			    !BPF_JIT_INSERT_WBS(cbpf_jit_ld_b_abs_neg_k, ptr,
						bpf_internal_load_pointer_neg_helper,
						reg_start, lens))
				return 0;
			break;
		}
		*seen |= SEEN_FUNC_CALL;
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_ld_b_abs_pos_k, ptr, pass, lens);
		if (is_first_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_CALL(cbpf_jit_ld_b_abs_pos_k, ptr, skb_copy_bits, lens) ||
		    !BPF_JIT_INSERT_K(cbpf_jit_ld_b_abs_pos_k, ptr, instr->k, lens) ||
		    !BPF_JIT_INSERT_WBS(cbpf_jit_ld_b_abs_pos_k, ptr,
					skb_copy_bits, reg_start, lens))
			return 0;
		break;
	case BPF_LD | BPF_W | BPF_IND: /* A = P[X+K:X+K+3] */
		*seen |= SEEN_FUNC_CALL;
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_ld_w_ind, ptr, pass, lens);
		if (is_first_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_CALL(cbpf_jit_ld_w_ind, ptr, skb_copy_bits, lens) ||
		    !BPF_JIT_INSERT_DISP_CALL(cbpf_jit_ld_w_ind, ptr,
					      bpf_internal_load_pointer_neg_helper, lens) ||
		    !BPF_JIT_INSERT_K(cbpf_jit_ld_w_ind, ptr, instr->k, lens) ||
		    !BPF_JIT_INSERT_WBS(cbpf_jit_ld_w_ind, ptr, skb_copy_bits, reg_start, lens) ||
		    !BPF_JIT_INSERT_WBS(cbpf_jit_ld_w_ind, ptr,
					bpf_internal_load_pointer_neg_helper, reg_start, lens))
			return 0;
		break;
	case BPF_LD | BPF_H | BPF_IND: /* A = P[X+K:X+K+1] */
		*seen |= SEEN_FUNC_CALL;
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_ld_h_ind, ptr, pass, lens);
		if (is_first_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_CALL(cbpf_jit_ld_h_ind, ptr, skb_copy_bits, lens) ||
		    !BPF_JIT_INSERT_DISP_CALL(cbpf_jit_ld_h_ind, ptr,
					      bpf_internal_load_pointer_neg_helper, lens) ||
		    !BPF_JIT_INSERT_K(cbpf_jit_ld_h_ind, ptr, instr->k, lens) ||
		    !BPF_JIT_INSERT_WBS(cbpf_jit_ld_h_ind, ptr, skb_copy_bits, reg_start, lens) ||
		    !BPF_JIT_INSERT_WBS(cbpf_jit_ld_h_ind, ptr,
					bpf_internal_load_pointer_neg_helper, reg_start, lens))
			return 0;
		break;
	case BPF_LD | BPF_B | BPF_IND: /* A = P[X+K:X+K] */
		*seen |= SEEN_FUNC_CALL;
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_ld_b_ind, ptr, pass, lens);
		if (is_first_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_CALL(cbpf_jit_ld_b_ind, ptr, skb_copy_bits, lens) ||
		    !BPF_JIT_INSERT_DISP_CALL(cbpf_jit_ld_b_ind, ptr,
					      bpf_internal_load_pointer_neg_helper, lens) ||
		    !BPF_JIT_INSERT_K(cbpf_jit_ld_b_ind, ptr, instr->k, lens) ||
		    !BPF_JIT_INSERT_WBS(cbpf_jit_ld_b_ind, ptr, skb_copy_bits, reg_start, lens) ||
		    !BPF_JIT_INSERT_WBS(cbpf_jit_ld_b_ind, ptr,
					bpf_internal_load_pointer_neg_helper, reg_start, lens))
			return 0;
		break;
	case BPF_LDX | BPF_W | BPF_ABS: /* A = *((u32 *)(seccomp_data + K)) */
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_ldx_w_abs, ptr, pass, lens);
		if (is_first_pass(pass))
			break;
		if (!BPF_JIT_INSERT_K(cbpf_jit_ldx_w_abs, ptr, instr->k, lens))
			return 0;
		break;
	case BPF_ANC | SKF_AD_MARK: /* A = skb->mark */
		BUILD_BUG_ON(sizeof_field(struct sk_buff, mark) != 4);
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_anc_mark, ptr, pass, lens);
		break;
	case BPF_ANC | SKF_AD_RXHASH: /* A = skb->hash */
		BUILD_BUG_ON(sizeof_field(struct sk_buff, hash) != 4);
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_anc_rxhash, ptr, pass, lens);
		break;
	case BPF_ANC | SKF_AD_VLAN_TAG: /* A = skb->vlan_tci */
		BUILD_BUG_ON(sizeof_field(struct sk_buff, vlan_tci) != 2);
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_anc_vlan_tag, ptr, pass, lens);
		break;
	case BPF_ANC | SKF_AD_QUEUE: /* A = skb->queue_mapping */
		BUILD_BUG_ON(sizeof_field(struct sk_buff, queue_mapping) != 2);
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_anc_queue, ptr, pass, lens);
		break;
	case BPF_ANC | SKF_AD_CPU: /* A = current->cpu */
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_anc_cpu, ptr, pass, lens);
		break;
	case BPF_ANC | SKF_AD_PROTOCOL: /* A = skb->protocol */
		BUILD_BUG_ON(sizeof_field(struct sk_buff, protocol) != 2);
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_anc_protocol, ptr, pass, lens);
		break;
	case BPF_ANC | SKF_AD_PKTTYPE: /* A = skb->pkt_type */
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_anc_pkttype, ptr, pass, lens);
		break;
	case BPF_ANC | SKF_AD_VLAN_TAG_PRESENT: /* A = skb->vlan_present */
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_anc_vlan_tag_present, ptr, pass, lens);
		break;
	case BPF_ANC | SKF_AD_IFINDEX: /* A = skb->dev->ifindex */
		BUILD_BUG_ON(sizeof_field(struct sk_buff, dev) != 8);
		BUILD_BUG_ON(sizeof_field(struct net_device, ifindex) != 4);
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_anc_ifindex, ptr, pass, lens);
		break;
	case BPF_ANC | SKF_AD_HATYPE: /* A = skb->dev->type */
		BUILD_BUG_ON(sizeof_field(struct sk_buff, dev) != 8);
		BUILD_BUG_ON(sizeof_field(struct net_device, type) != 2);
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_anc_hatype, ptr, pass, lens);
		break;
	case BPF_ANC | SKF_AD_PAY_OFFSET: /* A = skb_get_poff(skb) */
		*seen |= SEEN_FUNC_CALL;
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_anc_pay_offset, ptr, pass, lens);
		if (is_first_pass(pass))
			break;
		if (!BPF_JIT_INSERT_DISP_CALL(cbpf_jit_anc_pay_offset, ptr, skb_get_poff, lens) ||
		    !BPF_JIT_INSERT_WBS(cbpf_jit_anc_pay_offset, ptr,
					skb_get_poff, reg_start, lens))
			return 0;
		break;
	case BPF_ANC | SKF_AD_VLAN_TPID: /* A = skb->vlan_proto */
		BUILD_BUG_ON(sizeof_field(struct sk_buff, vlan_proto) != 2);
		size = BPF_JIT_COPY_ON_2ND_PASS(cbpf_jit_anc_vlan_tpid, ptr, pass, lens);
		break;
	case BPF_ANC | SKF_AD_NLATTR:
		fallthrough;
	case BPF_ANC | SKF_AD_NLATTR_NEST:
		fallthrough;
	case BPF_ANC | SKF_AD_RANDOM:
		fallthrough;
	default:
		/* not jitable */
		return 0;
	}
	return size;
}


void bpf_jit_compile(struct bpf_prog *prog)
{
	u8 *image_ptr = NULL;
	unsigned int image_size = 0;
	struct bpf_binary_header *image = NULL;
	const struct sock_filter *insns = prog->insns;
	struct cbpf_prog_info bpf_prog_info;
	int i = 0, pass = 0;
	void *ptr = NULL;
	unsigned int template_size = 0;
	unsigned int total_regs = 8, callee_reg_start = 8;

	if (!bpf_jit_enable)
		return;

	if (init_prog_info(&bpf_prog_info, prog->len))
		return;

	/* for detailed description of passes see comment in max_pass_num() */
	for (pass = 0; pass <= max_pass_num(); pass++) {
		if (is_first_pass(pass))
			/* save the pointer to prologue template */
			save_template_ptr(cbpf_jit_prologue, &(bpf_prog_info.prologue));
		if (is_codegen_pass(pass)) {
			/*
			 * cBPF program can call a function or use scratch memory (which
			 * resides in registers), so we need to initialize a register
			 * window and %b registers according to program's requirements.
			 */
			if ((bpf_prog_info.seen & SEEN_MEM_USAGE) &&
			    (bpf_prog_info.seen & SEEN_FUNC_CALL)) {
				callee_reg_start += BPF_MEMWORDS;
				total_regs += BPF_MEMWORDS + 8;
			} else if (bpf_prog_info.seen & SEEN_MEM_USAGE) {
				total_regs += BPF_MEMWORDS;
			} else if (bpf_prog_info.seen & SEEN_FUNC_CALL) {
				total_regs += 8;
			}

			/* insert filter prologue */
			copy_template(ptr, cbpf_jit_prologue, &(bpf_prog_info.prologue));
			if (!BPF_JIT_INSERT_WSZ(cbpf_jit_prologue, ptr,
						total_regs, &bpf_prog_info.prologue) ||
			    !BPF_JIT_INSERT_RBS(cbpf_jit_prologue, ptr,
						callee_reg_start, &bpf_prog_info.prologue))
				goto syllable_insertion_err;
			move_pointer(&ptr, &bpf_prog_info.prologue);
		}
		for (i = 0; i < prog->len; i++) {
			template_size = compile_single_instruction(ptr, pass,
						bpf_prog_info.body + i, insns + i,
							callee_reg_start, &bpf_prog_info.seen);
			if (template_size == 0 && is_first_pass(pass))
				goto not_jitable;
			if (template_size == 0 && is_codegen_pass(pass))
				goto syllable_insertion_err;
			if (is_first_pass(pass)) {
				bpf_prog_info.body[i].template_len = template_size;
				mark_jump_destinations(insns + i, bpf_prog_info.body + i);
			}
			if (is_codegen_pass(pass))
				move_pointer(&ptr, bpf_prog_info.body + i);
		}
		if (is_first_pass(pass)) {
			/* allocate memory for compiled filter */
			image_size = get_min_hwbug_size(templates_lengths_sum(&bpf_prog_info));
			image = bpf_jit_binary_alloc(image_size, &image_ptr, E2K_INSTR_ALIGNMENT,
							jit_fill_exc_software_trap);
			if (!image)
				goto image_alloc_err;
			ptr = (void *) image_ptr;

			if (cpu_has(CPU_HWBUG_CODE_PLACEMENT)) {
				/*
				 * after HW Bug workaround calculation we know
				 * the exact size of jited program
				 */
				image_size = calculate_hwbug_workaround(ptr, &bpf_prog_info);
			}
		}
	}

	if (cpu_has(CPU_HWBUG_CODE_PLACEMENT)) {
		/*
		 * In case of HW bug, nops can be inserted before the first command
		 * to move it out from the 'bad' region. To take these nops into
		 * account we move the pointer to the start of compiled program too.
		 */
		image_ptr += real_wide_instr_offset(&bpf_prog_info.prologue, 0);
	}

	if (bpf_jit_enable > 1)
		bpf_jit_dump(prog->len, image_size, 1, image_ptr);

	bpf_jit_binary_lock_ro(image);

	free_prog_info(&bpf_prog_info);

	prog->bpf_func = (void *)image_ptr;
	prog->jited = 1;
	prog->jited_len = image_size;
	return;

syllable_insertion_err:
	bpf_jit_binary_free(image);
not_jitable:
image_alloc_err:
	free_prog_info(&bpf_prog_info);
}
