/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * This file contains all inline functions for both cBPF and eBPF JIT compilers.
 */

#pragma once

#include <linux/math.h>
#include <asm/cpu_regs.h>
#include <asm/cpu_features.h>

#include "bpf_jit_comp_common.h"

#if defined(E2K_EBPF_JIT) && defined(E2K_CBPF_JIT)
# error "Macros E2K_EBPF_JIT and E2K_CBPF_JIT should not be defined together"
#elif !defined(E2K_EBPF_JIT) && !defined(E2K_CBPF_JIT)
# error "At least one of E2K_EBPF_JIT or E2K_CBPF_JIT should be defined"
#endif

/*
 * Warning message for cBPF and eBPF JIT compilers.
 */
#if defined(E2K_EBPF_JIT)
# define BPF_JIT_WARN "eBPF JIT: "
#else /* defined(E2K_CBPF_JIT) */
# define BPF_JIT_WARN "cBPF JIT: "
#endif

/*
 * Copy the template `templ' to area pointed by `ptr' on the codegen pass.
 * On the first pass, just return the length of template.
 */
#define BPF_JIT_COPY_ON_2ND_PASS(templ, pointer, pass, cmd_info) \
({ \
	if (is_first_pass(pass)) { \
		save_template_ptr(templ, cmd_info); \
	} else if (is_codegen_pass(pass)) { \
		copy_template(pointer, templ, cmd_info); \
	} \
	BPF_JIT_TEMPLATE_SIZE(templ); \
})

/*
 * Insert a 32-bit constant into template copy.
 *
 * This macro is a wrapper for insert_imm32(). It provides the function
 * with an offset from the start of a given template to a wide instruction
 * where the constant should be inserted. Here we use get_label parameter
 * to get the address of this label.
 */
#define BPF_JIT_INSERT_IMM32(templ, pointer, imm32, cmd_lens, get_label) \
({ \
	unsigned int insert_imm32_offset = \
			BPF_JIT_OFFSET(get_label(templ), templ); \
	insert_imm32(templ, insert_imm32_offset, pointer, imm32, cmd_lens); \
})

/*
 * Insert window size into prologue.
 *
 * This macro is a wrapper for insert_wsz(). It provides the function with
 * an offset from the start of a given template to a wide command with setwd
 * instruction.
 */
#define BPF_JIT_INSERT_WSZ(templ, pointer, total_regs, cmd_lens) \
({ \
	unsigned int insert_wsz_offset = \
		BPF_JIT_OFFSET(BPF_JIT_WSZ_LABEL(templ), templ); \
	insert_wsz(templ, insert_wsz_offset, pointer, total_regs, cmd_lens); \
})

/*
 * Insert base of %b registers into prologue.
 *
 * This macro is a wrapper for insert_rbs(). It provides the function with
 * an offset from the start of a given template to a wide command with setbn
 * instruction.
 */
#define BPF_JIT_INSERT_RBS(templ, pointer, reg_start, cmd_lens) \
({ \
	unsigned int insert_rbs_offset = \
		BPF_JIT_OFFSET(BPF_JIT_RBS_LABEL(templ), templ); \
	insert_rbs(templ, insert_rbs_offset, pointer, reg_start, cmd_lens); \
})

/*
 * Insert base of the next register window.
 *
 * This macro is a wrapper for insert_wbs(). It provides the function with
 * an offset from the start of a given template to a wide command with call
 * instruction.
 */
#if defined(E2K_EBPF_JIT)
# define BPF_JIT_INSERT_WBS(templ, pointer, reg_start, cmd_lens) \
({ \
	unsigned int insert_wbs_offset = \
		BPF_JIT_OFFSET(BPF_JIT_WBS_LABEL(templ), templ); \
	insert_wbs(templ, insert_wbs_offset, pointer, reg_start, cmd_lens); \
})
#else /* defined(E2K_CBPF_JIT) */
# define BPF_JIT_INSERT_WBS(templ, pointer, func, reg_start, cmd_lens) \
({ \
	unsigned int insert_wbs_offset = \
		BPF_JIT_OFFSET(BPF_JIT_WBS_LABEL(templ, func), templ); \
	insert_wbs(templ, insert_wbs_offset, pointer, reg_start, cmd_lens); \
})
#endif

/*
 * Insert jump displacement.
 *
 * This macro is a wrapper for insert_disp_jump(). It provides the function with:
 * 1) offset from the start of a given template to a wide command with disp instruction;
 * 2) offset from the wide command with disp instruction to the end of template.
 */
#if defined(E2K_EBPF_JIT)
# define BPF_JIT_INSERT_DISP_JUMP(templ, pointer, value, cmd_lens) \
({ \
	unsigned int insert_disp_jump_offset = \
		BPF_JIT_OFFSET(BPF_JIT_JMP_LABEL(templ), templ); \
	unsigned int insert_disp_jump_offset_to_end = \
		BPF_JIT_OFFSET(BPF_JIT_FUNC_END_LABEL(templ), BPF_JIT_JMP_LABEL(templ)); \
	insert_disp_jump(templ, insert_disp_jump_offset, insert_disp_jump_offset_to_end, \
			 pointer, value, cmd_lens); \
})
#else /* defined(E2K_CBPF_JIT) */
# define BPF_JIT_INSERT_DISP_JUMP(templ, cond, pointer, value, cmd_lens) \
({ \
	unsigned int insert_disp_jump_offset = \
		BPF_JIT_OFFSET(BPF_JIT_JMP_LABEL(templ, cond), templ); \
	unsigned int insert_disp_jump_offset_to_end = \
		BPF_JIT_OFFSET(BPF_JIT_FUNC_END_LABEL(templ), BPF_JIT_JMP_LABEL(templ, cond)); \
	insert_disp_jump(templ, insert_disp_jump_offset, insert_disp_jump_offset_to_end, \
			 pointer, value, cmd_lens); \
})
#endif

/*
 * Insert call displacement.
 *
 * This macro is a wrapper for insert_disp_call(). It provides the function with
 * an offset from the start of a given template to a wide command with disp
 * instruction.
 */
#if defined(E2K_EBPF_JIT)
# define BPF_JIT_INSERT_DISP_CALL(templ, pointer, func_addr, cmd_lens) \
({ \
	unsigned int insert_disp_call_offset = \
		BPF_JIT_OFFSET(BPF_JIT_FUNC_LABEL(templ), templ); \
	insert_disp_call(templ, insert_disp_call_offset, pointer, func_addr, cmd_lens); \
})
#else /* defined(E2K_CBPF_JIT) */
# define BPF_JIT_INSERT_DISP_CALL(templ, pointer, func, cmd_lens) \
({ \
	unsigned int insert_disp_call_offset = \
		BPF_JIT_OFFSET(BPF_JIT_FUNC_LABEL(templ, func), templ); \
	insert_disp_call(templ, insert_disp_call_offset, pointer, (u64) &func, cmd_lens); \
})
#endif

/*
 * Some e2k processors have a hardware bug, described in bugs #77417, #140436
 * and #146897. So cBPF and eBPF JIT compilers must implement a workaround.
 * The workaround is based on comment 58 of bug 146897. Since BPF JIT does not
 * use AAU, only items 1 and 4.2 from comment 58 were implemented. Later, this
 * hardware bug will be referenced as 'HW bug 146897' or simply 'HW bug'.
 */

/*
 * Regions for HW bug workaround. Let's call them 'bad' regions.
 */
#define HWBUG_REGION_1_START	0xdc0
#define HWBUG_REGION_1_END	0xdff
#define HWBUG_REGION_2_START	0xee0
#define HWBUG_REGION_2_END	0xfff
#define HWBUG_REGIONS_MASK	0xfff

/*
 * HW bug workaround implies moving code beyond the end of a 'bad' regions,
 * if this code gets into a bad region and can be reached indirectly (namely
 * via jump or return from call). If a chunk of code need to be moved, the
 * space before it is filled with nops. Lets refer to these nops as a 'nop
 * interval'.
 *
 * The number of nop intervals that can be inserted during template copying
 * consists of:
 * 1) beginning interval if corresponding BPF instruction is a jump destination;
 * 2) up to MAX_CALLS_IN_TEMPLATE intervals if there are calls in template and
 *    they need to be shifted according to workaround scheme.
 */
#if defined(E2K_EBPF_JIT)
# define MAX_CALLS_IN_TEMPLATE		1
#else /* defined(E2K_CBPF_JIT) */
# define MAX_CALLS_IN_TEMPLATE		2
#endif

#define MAX_NUM_OF_NOP_INTERVALS	(MAX_CALLS_IN_TEMPLATE + 1)

struct nop_interval {
	unsigned int start;	/* distance from the beginning */
				/* of template to the beginning */
				/* of nop interval in bytes*/
	unsigned int len;	/* length of nop interval in bytes */
};

struct cmd_len {
	unsigned int template_len;	/* template length in bytes */
#if defined(E2K_EBPF_JIT)
	u8 src;				/* source register number */
	u8 dst;				/* destination register number */
#endif

	/* Fields for workaround */
	bool is_jump_dest;		/* is BPF instruction a */
					/* jump destination or not */
	const void *template_ptr;	/* pointer to template */
	unsigned int total_len;		/* total length with nops inserted */
	unsigned int int_num;		/* number of nop intervals */
	struct nop_interval intervals[MAX_NUM_OF_NOP_INTERVALS];
};

/*
 * During the first pass (which number is actually 0), JIT compiler just gets
 * acquainted with a BPF program it works with. All the information obtained
 * during the first pass is stored in `ebpf_prog_info'/`cbpf_prog_info' and
 * `cmd_len' structures.
 */
static inline bool is_first_pass(int pass)
{
	return pass == 0;
}

/*
 * During the code generation pass (numbered as 1), JIT compiler copies
 * templates to allocated memory (image) and inserts some data to the copies,
 * e.g. constants or jump shifts.
 */
static inline bool is_codegen_pass(int pass)
{
	return pass == 1;
}

#if defined(E2K_EBPF_JIT)
/*
 * During the extra pass (numbered as 2), JIT compiler resolves all bpf-to-bpf
 * calls. This pass is a feature of eBPF JIT, as classic BPF do not support
 * bpf-to-bpf calls.
 */
static inline bool is_extra_pass(int pass)
{
	return pass == 2;
}
#endif

/*
 * To build a HW bug workaround, we need to allocate enough memory
 * even for the worst case, to avoid the dependence from the starting
 * address of allocated memory (which is random).
 */
static inline unsigned int get_min_hwbug_size(unsigned int size)
{
	const unsigned int region_sizes_sum = (HWBUG_REGION_2_END - HWBUG_REGION_2_START + 1)
					    + (HWBUG_REGION_1_END - HWBUG_REGION_1_START + 1);
	const unsigned int round_to = (HWBUG_REGIONS_MASK + 1) - region_sizes_sum;

	if (!cpu_has(CPU_HWBUG_CODE_PLACEMENT))
		return size;

	/* In case of HW bug we need more memory for workaround */
	return size + region_sizes_sum * roundup(size, round_to) / round_to;
}

/*
 * Get the distance from the place pointed by `addr' to the end of
 * 'bad' region. If `addr' is not in a 'bad' region, return 0.
 */
static inline unsigned int bytes_to_hwbug_region_end(void *addr)
{
	const unsigned int offset = (unsigned long) addr & HWBUG_REGIONS_MASK;

	if (!cpu_has(CPU_HWBUG_CODE_PLACEMENT))
		return 0;

	if ((HWBUG_REGION_1_START <= offset) && (offset <= HWBUG_REGION_1_END))
		return HWBUG_REGION_1_END - offset + 1;
	if ((HWBUG_REGION_2_START <= offset) && (offset <= HWBUG_REGION_2_END))
		return HWBUG_REGION_2_END - offset + 1;
	return 0;
}

/*
 * Check if the pointer `addr' points to a 'bad' region
 */
static inline bool addr_in_regions(void *addr)
{
	if (!cpu_has(CPU_HWBUG_CODE_PLACEMENT))
		return false;

	return bytes_to_hwbug_region_end(addr) > 0;
}

/*
 * Fill `len' bytes starting at `ptr' with nops. It is sane to place as much
 * 'long' 64-byte nops as possible, in order to speed up the execution.
 */
static void fill_with_nops(void *ptr, unsigned int len)
{
	unsigned int max_lng = 7;
	unsigned int max_len_in_bytes = 8 * (max_lng + 1);

	if (!cpu_has(CPU_HWBUG_CODE_PLACEMENT))
		return;

	memset(ptr, '\0', len);

	while (len > max_len_in_bytes) {
		*(u32 *) ptr = ((instr_hs_t) { .lng = max_lng }).word;
		len -= max_len_in_bytes;
		ptr += max_len_in_bytes;
	}

	BUG_ON(len % 8 != 0);
	if (len > 8)
		*(u32 *) ptr = ((instr_hs_t) { .lng = (len / 8) - 1 }).word;
}

/*
 * This function calculates the real offset from the beginning of template
 * to a given wide command, considering there can be nop intervals between them.
 */
static unsigned int real_wide_instr_offset(const struct cmd_len *cmd_info,
						  unsigned int offset)
{
	int i = 0;
	unsigned int nops_len = 0;

	if (!cpu_has(CPU_HWBUG_CODE_PLACEMENT))
		return offset;

	for (i = 0; i < cmd_info->int_num && cmd_info->intervals[i].start <= offset; i++)
		nops_len += cmd_info->intervals[i].len;

	return offset + nops_len;
}

/*
 * Similar to the previous function `real_wide_instr_offset()', but calculates
 * the real offset from the given wide command to the end of template.
 */
static unsigned int real_wide_instr_offset_to_end(const struct cmd_len *cmd_info,
							 unsigned int bytes_to_end)
{
	int i = 0;
	unsigned int nops_len = 0;

	if (!cpu_has(CPU_HWBUG_CODE_PLACEMENT))
		return bytes_to_end;

	for (i = cmd_info->int_num - 1;
		i >= 0 && cmd_info->intervals[i].start > cmd_info->template_len - bytes_to_end;
			i--)
		nops_len += cmd_info->intervals[i].len;

	return bytes_to_end + nops_len;
}

static inline unsigned int single_to_quadro_regs(unsigned int nr_num)
{
	return (nr_num + 1) / 2;
}

#if defined(E2K_EBPF_JIT)
static int disp_jump(int jump, unsigned int left, const struct cmd_len cmd_lens[]);
#else /* defined(E2K_CBPF_JIT) */
static unsigned int disp_jump(unsigned int jump, unsigned int left,
			      const struct cmd_len cmd_lens[]);
#endif

/*
 * Get displacement from current point to kernel function.
 *
 * We need to shift the result by 3 bits right because all wide instructions
 * are 8-bytes aligned, so the disp field of CS0 syllable does not store
 * three least significant bits of displacement value.
 */
static inline int disp_call(u64 func_addr, const void *cur_pos)
{
	int fn_disp = (int)((unsigned long)func_addr - (unsigned long)cur_pos);

	return fn_disp >> 3;
}

/*
 * This function inserts a 32-bit constant into template copy. A special label
 * is defined in assembler template to mark the wide instruction with LTS0 syllable,
 * to which the constant should be inserted. This function calculates the offset from
 * the beginning of template to the address of this label, receives the pointer
 * to LTS0 in that wide instruction via find_lts_f32s() and inserts a constant to
 * this syllable.
 */
static bool insert_imm32(const void *template, unsigned int offset,
		void *start, u32 imm32, const struct cmd_len *cmd_lens)
{
	void *wide_instr_ptr = start + real_wide_instr_offset(cmd_lens, offset);
	instr_lts_t *lts0_ptr = find_lts_f32s(wide_instr_ptr, 0);

	if (lts0_ptr) {
		lts0_ptr->word = imm32;
		return true;
	} else {
		WARN_ONCE(1, BPF_JIT_WARN "failed to find lts0 syllable");
		return false;
	}
}

/*
 * This function inserts window size for setwd instruction. Window size is encoded
 * in quadro registers in wsz field of LTS0 syllable.
 */
static bool insert_wsz(const void *template, unsigned int offset,
		void *start, unsigned int regs, const struct cmd_len *cmd_lens)
{
	void *wide_instr_ptr = start + real_wide_instr_offset(cmd_lens, offset);
	instr_lts_t *lts0_ptr = find_lts_f32s(wide_instr_ptr, 0);

	if (lts0_ptr) {
		lts0_ptr->lts0.wsz = single_to_quadro_regs(regs);
		return true;
	} else {
		WARN_ONCE(1, BPF_JIT_WARN "failed to find lts0 syllable");
		return false;
	}
}

/*
 * %b registers are used by compiled BPF program to refer to callee arguments registers.
 * This function changes the rbs field (encoded in quadro registers) of CS1 syllable
 * to define the right base of %b registers.
 *
 * In fact, the base of %b registers in eBPF JIT is constant and equals 8 (jited
 * program's register window contains at least 16 registers). However, eBPF JIT uses
 * this mechanism for consistency with cBPF JIT and for possible need in the future.
 * For cBPF JIT the base of %b registers equals 12 (at least 24 registers in jited
 * program's register window) if the program uses scratch memory and 4 (at least
 * 8 registers in register window) otherwise.
 */
static bool insert_rbs(const void *template, unsigned int offset,
		void *start, unsigned int reg_start, const struct cmd_len *cmd_lens)
{
	void *wide_instr_ptr = start + real_wide_instr_offset(cmd_lens, offset);
	instr_cs1_t *cs1_ptr = find_cs1(wide_instr_ptr);

	if (cs1_ptr) {
		cs1_ptr->rbs = single_to_quadro_regs(reg_start);
		return true;
	} else {
		WARN_ONCE(1, BPF_JIT_WARN "failed to find cs1 syllable");
		return false;
	}
}

/*
 * This function inserts a base of the next register window. When calling a function,
 * BPF program should specify the beginning of the callee's register window, which
 * is called window base. As the base may differ from one program to another, the
 * right window base should be inserted for every function call in a jited program.
 * Window base is encoded in quadro registers in wbs field of CS1 syllable.
 *
 * In fact, the window base in eBPF JIT is constant and equals 8 (jited program's
 * register window contains 16 registers). However, eBPF JIT uses this mechanism
 * for consistency with cBPF JIT and for possible need in the future. cBPF JIT
 * creates functions with different length of register window, which depends on
 * whether cBPF program uses scratch memory or not.
 */
static bool insert_wbs(const void *template, unsigned int offset,
		void *start, unsigned int reg_start, const struct cmd_len *cmd_lens)
{
	void *wide_instr_ptr = start + real_wide_instr_offset(cmd_lens, offset);
	instr_cs1_t *cs1_ptr = find_cs1(wide_instr_ptr);

	if (cs1_ptr) {
		cs1_ptr->wbs = single_to_quadro_regs(reg_start);
		return true;
	} else {
		WARN_ONCE(1, BPF_JIT_WARN "failed to find cs1 syllable");
		return false;
	}
}

/*
 * This function inserts a jump displacement into `disp' field of CS0 syllable.
 * The displacement is calculated via disp_jump().
 */
static bool insert_disp_jump(const void *template, unsigned int offset,
		unsigned int offset_to_end, void *start, int jump,
		const struct cmd_len *cmd_lens)
{
	void *wide_instr_ptr = start + real_wide_instr_offset(cmd_lens, offset);
	instr_cs0_t *cs0_ptr = find_cs0(wide_instr_ptr);

	if (cs0_ptr) {
		int bytes_to_end = real_wide_instr_offset_to_end(cmd_lens, offset_to_end);
		cs0_ptr->cof2.disp = disp_jump(jump, bytes_to_end, cmd_lens);
		return true;
	} else {
		WARN_ONCE(1, BPF_JIT_WARN "failed to find cs0 syllable");
		return false;
	}
}

/*
 * This function inserts a call displacement into `disp' field of CS0 syllable.
 * The displacement is calculated via disp_call().
 */
static bool insert_disp_call(const void *template, unsigned int offset,
		void *start, u64 func_addr, const struct cmd_len *cmd_lens)
{
	void *wide_instr_ptr = start + real_wide_instr_offset(cmd_lens, offset);
	instr_cs0_t *cs0_ptr = find_cs0(wide_instr_ptr);

	if (cs0_ptr) {
		cs0_ptr->cof2.disp = disp_call(func_addr, wide_instr_ptr);
		return true;
	} else {
		WARN_ONCE(1, BPF_JIT_WARN "failed to find cs0 syllable");
		return false;
	}
}

/*
 * Move pointer to which `ptr' points by the length of current template.
 * The length is obtained from `cmd_info'.
 */
static inline void move_pointer(void **ptr, struct cmd_len *cmd_info)
{
	if (!cpu_has(CPU_HWBUG_CODE_PLACEMENT))
		*ptr += cmd_info->template_len;
	else
		*ptr += cmd_info->total_len;
}

/*
 * Save the pointer to template into `cmd_info'. We need it to build
 * a workaround in case of HW bug.
 */
static inline void save_template_ptr(void *template, struct cmd_len *cmd_info)
{
	if (!cpu_has(CPU_HWBUG_CODE_PLACEMENT))
		return;

	cmd_info->template_ptr = template;
}

#if defined(E2K_EBPF_JIT)
static void fill_src_and_dst(void *ptr, unsigned int len, const struct cmd_len *cmd_info);
#else /* defined(E2K_CBPF_JIT) */
static inline void fill_src_and_dst(void *ptr, unsigned int len, const struct cmd_len *cmd_info)
{
}
# endif

/*
 * Copy template to allocated memory.
 *
 * In case of HW bug, this function inserts nop intervals according to the
 * workaround information from `cmd_info' structure.
 */
static void copy_template(void *ptr, const void *template,
			  const struct cmd_len *cmd_info)
{
	unsigned int copied = 0, position = 0,
		     int_cnt = 0, tmp_len = 0;
	unsigned int template_len = cmd_info->template_len,
		     total_len = cmd_info->total_len,
		     int_num = cmd_info->int_num;

	if (!cpu_has(CPU_HWBUG_CODE_PLACEMENT)) {
		memcpy(ptr, template, template_len);
		fill_src_and_dst(ptr, template_len, cmd_info);
		return;
	}

	/* we use `cmd_info' to place NOPs during copying the template */
	while (copied < total_len) {
		if (int_cnt < int_num && position == cmd_info->intervals[int_cnt].start) {
			/* insert NOP interval */
			fill_with_nops(ptr + copied, cmd_info->intervals[int_cnt].len);
			copied += cmd_info->intervals[int_cnt].len;
			int_cnt++;
		} else {
			/* copy next template chunk */
			if (int_cnt >= int_num)
				tmp_len = template_len - position;
			else
				tmp_len = cmd_info->intervals[int_cnt].start - position;
			memcpy(ptr + copied, template + position, tmp_len);
			copied += tmp_len;
			position += tmp_len;
		}
	}
	fill_src_and_dst(ptr, total_len, cmd_info);
}

/*
 * Calculate HW bug workaround for a single BPF instruction translation and
 * thereafter fill `cmd_info' structure.
 */
static unsigned int build_workaround_for_instr(void *ptr, struct cmd_len *cmd_info)
{
	unsigned int len_inc = 0, tmp_len = 0, offt = 0, cur_wc_len = 0;
	unsigned int int_num = 0;
	const instr_hs_t *hs = NULL;
	const instr_cs1_t *cs1 = NULL;

	if (!cpu_has(CPU_HWBUG_CODE_PLACEMENT))
		return cmd_info->template_len;

	/*
	 * Insert nops before template, if it is a destination of jump
	 * and gets into 'bad' region.
	 */
	if (cmd_info->is_jump_dest && addr_in_regions(ptr)) {
		tmp_len = bytes_to_hwbug_region_end(ptr);
		cmd_info->intervals[int_num].start = 0;
		cmd_info->intervals[int_num].len = tmp_len;
		len_inc += tmp_len;
		ptr += tmp_len;
		int_num++;
	}

	/*
	 * A return from call jumps to the instruction after call. If the address
	 * of this instruction is 'bad', insert nops before call to move the next
	 * wide command out of 'bad' region.
	 */
	while (offt < cmd_info->template_len) {
		hs = (const instr_hs_t *) (cmd_info->template_ptr + offt);
		cur_wc_len = E2K_GET_INSTR_SIZE(*hs);
		if ((cs1 = find_cs1((void *)hs)) != NULL &&
		     cs1->opc == CS1_OPC_CALL &&
		     addr_in_regions(ptr + cur_wc_len)) {
			tmp_len = bytes_to_hwbug_region_end(ptr + cur_wc_len);
			BUG_ON(int_num >= MAX_NUM_OF_NOP_INTERVALS);
			cmd_info->intervals[int_num].start = offt;
			cmd_info->intervals[int_num].len = tmp_len;
			len_inc += tmp_len;
			ptr += tmp_len;
			int_num++;
		}
		ptr += cur_wc_len;
		offt += cur_wc_len;
	}

	cmd_info->total_len = cmd_info->template_len + len_inc;
	cmd_info->int_num = int_num;

	return cmd_info->total_len;
}

