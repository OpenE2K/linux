/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024 MCST
 */

#include <asm-generic/errno-base.h>
#include <asm/current.h>
#include <asm/glob_regs.h>
#include <asm/machdep.h>
#include <asm/tags.h>
#include <linux/errno.h>
#include <linux/sysctl.h>
#include <linux/module.h>
#include <linux/kdebug.h>
#include <linux/preempt.h>
#include <linux/uaccess.h>
#include <linux/file.h>
#include <asm/traps.h>
#include <asm/ptrace.h>
#include <asm/cpu_regs_types.h>
#include <asm/e2k_debug.h>
#include <asm/instr_regs_types.h>
#include <asm/processor.h>
#include <asm/process.h>
#include <asm/mmu_fault.h>
#include <asm/cpu_regs.h>
#include <asm/thread_info.h>
#include <asm/protected_mode.h>
#include <asm/protected_syscalls.h>
#include <asm/iset_ver.h>
#include <asm/unsafe_uint64_to_ptr.h>
#include <linux/kmemleak.h>

/* Soft PM config masks (start)*/

/**
 * define PM_SOFT_PRINT_NOTES - Output important notes about soft PM work
 *
 * Notes report prints information about exception handling process
 * and about causes why it can't be corrected (if it can't be).
 *
 * Default: on.
 */
#define PM_SOFT_PRINT_NOTES 0x00001

/**
 * define PM_SOFT_DEBUG_REG - Debug reg addr resolutions, load/stores, etc.
 *
 * For debugging soft pm itself.
 *
 * Default: off.
 */
#define PM_SOFT_DEBUG_REG 0x00002

/**
 * define PM_SOFT_PRINT_CORRECTION - Output correction result.
 *
 * Outputs old and new register values.
 *
 * Default: on.
 */
#define PM_SOFT_PRINT_CORRECTION 0x00004

/**
 * define PM_SOFT_DEBUG_CORRECTION - Debug correction process.
 *
 * For debugging soft pm itself.
 *
 * Default: off.
 */
#define PM_SOFT_DEBUG_CORRECTION 0x00008

/**
 * define PM_SOFT_PRINT_OPERATION - Output information about faulty operation.
 *
 * Prints "preamble": IP of the exception, operation (i.e. add), exception name.
 *
 * Default: on.
 */
#define PM_SOFT_PRINT_OPERATION 0x00010

/**
 * define PM_SOFT_DEBUG_OPERATION - Debug cmd parsing and decoding process.
 *
 * For debugging soft pm itself.
 *
 * Default: off.
 */
#define PM_SOFT_DEBUG_OPERATION 0x00020

/**
 * define PM_SOFT_PRINT_TO_STDERR - Duplicate output from journal to stderr.
 *
 * Only affects _PRINT_. _DEBUG_ will always stay in journal.
 *
 * Default: off.
 */
#define PM_SOFT_PRINT_TO_STDERR 0x00040

/**
 * define PM_SOFT_GLOBAL_ENABLE - SoftPM enable/disable for current session.
 *
 * Default: off.
 */
#define PM_SOFT_GLOBAL_ENABLE 0x00080

/**
 * define PM_SOFT_PRINT_ON_CORR_FAIL_ONLY - \
 *         Output only when correction is impossible.
 *
 * Suppress output about successful correction. Dramatic speedup in case of
 * unsafe memory operations at hot path.
 *
 * Default: off.
 */
#define PM_SOFT_PRINT_ON_CORR_FAIL_ONLY 0x00100

/**
 * define PM_SOFT_PRINT_FULL_CMDLINE - Print full cmdline. Slow.
 *
 * Print full command line. Involves blocking memory allocation.
 * Useful for reproducing the issue, but slow.
 *
 * Default: off.
 */
#define PM_SOFT_PRINT_FULL_CMDLINE 0x00200

/**
 * define PM_SOFT_PRINT_USERFRIENDLY - default output settings.
 *
 * Prints information about exception, ip, operation, applied correction
 * and notes.
 */
#define PM_SOFT_PRINT_USERFRIENDLY                        \
	(PM_SOFT_PRINT_CORRECTION | PM_SOFT_PRINT_NOTES | \
	 PM_SOFT_PRINT_OPERATION)

/**
 * define PM_SOFT_DEBUG_ALL - Just output everything.
 *
 * Enables all debugging flags. For debugging soft pm itself.
 */
#define PM_SOFT_DEBUG_ALL                                                     \
	(PM_SOFT_DEBUG_REG | \
	 PM_SOFT_DEBUG_CORRECTION |                 \
	 PM_SOFT_DEBUG_OPERATION)

/**
 * define PM_SOFT_POLICY_NODEC_UNINIT_DXWORD - \
 *         Start nodec unint correction from dword(v5+)/xword(v3‑v4).
 *
 * Allows to skip trying single word correction when working with generic
 * decoder that does not have information about sizes.
 *
 * When operation is dword (which is rather common) saves one user-kernel switch
 * which improves performance in exchange for bigger granularity: overcorrection
 * may occur.
 *
 * On V3-V4 extended part is not tagged. Consequently, xword should be corrected
 * as whole. Dword-only correction may lead to undetectable corrupted ext part
 * and corrupted results.
 *
 * Default: off.
 */
#define PM_SOFT_POLICY_NODEC_UNINIT_DXWORD 0x00400

/**
 * define PM_SOFT_POLICY_MAX_ARRAY_BOUNDS - \
 *         Increase descriptor size up to the max available one.
 *
 * Allows the descriptor size to grow up to the maximum available bounds,
 * constrained by continuous VMA's union or whole stack. Similar to how
 * unsafe_uint64_to_ptr works.
 *
 * Dramatically improve performance on i.e. arrays, converted from uintptr_t.
 *
 * Default: off.
 */
#define PM_SOFT_POLICY_MAX_ARRAY_BOUNDS 0x00800

/**
 * define PM_SOFT_POLICY_NODEC_MEM_QWORD - \
 *          Use max (qword) format for nodec mem correction.
 *
 * Works similarly to UNINIT_DXWORD but for memory, applying maximum format
 * from the very beginning.
 *
 * Default: off.
 */
#define PM_SOFT_POLICY_NODEC_MEM_QWORD 0x01000

/**
 * define PM_SOFT_CONSTR_MEM_SAME_PAGE - \
 *          Allow descr increase only up to the corresponding page bounds.
 *
 * Restricts descriptor size growth to stay within the same memory page.
 * May be used for safety reasons, forbidding access to foreign pages.
 *
 * Default: off.
 */
#define PM_SOFT_CONSTR_MEM_SAME_PAGE 0x02000

/**
 * define PM_SOFT_CONSTR_UNINIT_DW_AS_EW - \
 *         Allow treating DW as EW. More fine grained than.
 *
 * Allows working with a diagnostic word as with an empty word.
 *
 * VERY DANGEROUS.
 *
 * Diagnostics must be a result of a faulty speculative operation.
 * But (by far) is used instead of empty words in new memory allocations.
 * Also, compiler seems to set format-extender operations speculative,
 * converting EWs to DWs that way.
 *
 * Default: off.
 */
#define PM_SOFT_CONSTR_UNINIT_DW_AS_EW 0x04000

/**
 * define PM_SOFT_CONSTR_ALLOW_DIAG_OPERAND - \
 *         Allow handling diag operand (as illegal).
 *
 * Has same effect as UNINIT_DW_AS_EW, but enables/disables
 * exc_diag_operand completely.
 *
 * For treating diags as illegals both have to be enabled.
 *
 * Default: off.
 */
#define PM_SOFT_CONSTR_ALLOW_DIAG_OPERAND 0x08000

/**
 * define PM_SOFT_CONSTR_TRUST_PARTIALLY_BROKEN_DESCRS - \
 *         Allow trusting descrs with partially broken tags.
 *
 * Trusts descriptors that are partially corrupted: some words
 * still have correct tags, some are reset to numerical.
 * Rather rare and illogical descriptor damage.
 *
 * Example usecase: when saving flags into lower part of base via dirty hacks.
 *
 * Default: off.
 */
#define PM_SOFT_CONSTR_TRUST_PARTIALLY_BROKEN_DESCRS 0x10000

/* Soft PM config masks (end)*/
/* ########################################################################## */
/* arch/code-dependent definitions and constants (start) */

/* ales extension constants */
#define EXT1_ALES_OPC2 0x02
#define NONE_ALES_OPCE 0xc0

/* src registers masks */
#define SRC_B_MASK (0b10000000) /* reg in window i.e. b[0] */
#define SRC_B_CODE (0b00000000)
#define SRC_R_MASK (0b11000000) /* rotating reg i.e.  r0 */
#define SRC_R_CODE (0b10000000)
#define SRC_G_MASK (0b11100000) /* global reg i.e.    g0 */
#define SRC_G_CODE (0b11100000)

/* src immediates masks */
#define SRC2_IMM4_CODE (0b11000000)
#define SRC2_IMM4_MASK (0b11110000)
#define SRC2_IMM16_CODE (0b11010000)
#define SRC2_IMM16_MASK (0b11111000)
#define SRC2_IMM32_CODE (0b11011000)
#define SRC2_IMM32_MASK (0b11111100)
#define SRC2_IMM64_CODE (0b11011100)
#define SRC2_IMM64_MASK (0b11111100)

/* first used by kernel global register */
#define KERNEL_FIRST_GREG_NUM GUEST_VCPU_STATE_GREG

/* data types sizes */
#define E2K_SIZE_BYTE 1
#define E2K_SIZE_HALF 2
#define E2K_SIZE_WORD 4
#define E2K_SIZE_DWORD 8
#define E2K_SIZE_XWORD 10 /* extended 80 bit float */
#define E2K_SIZE_QWORD 16

/* RW internal flags */
#define E2K_AP_RW (0b11)
#define E2K_AP_RO (0b01)
#define E2K_AP_WO (0b10)

/* DW/EW tags */
#define E2K_DWEW_ITAG_MASK (1 << 30)
#define E2K_EW_ITAG_MASKED 0
#define E2K_DW_ITAG_MASKED (1 << 30)

typedef struct {
	union {
		struct {
			u64 word;
			u16 ext;
		};
		struct {
			u64 lo;
			u64 hi;
		};
	};
} __aligned(16) e2k_xreg_t;

/* arch/code-dependent definitions and constants (end) */
/* ########################################################################## */
/* helper functions/macros (start) */

#define SRC_IS_R(src) (((src)&SRC_R_MASK) == SRC_R_CODE)
#define SRC_IS_B(src) (((src)&SRC_B_MASK) == SRC_B_CODE)
#define SRC_IS_G(src) (((src)&SRC_G_MASK) == SRC_G_CODE)
#define SRC_R_ADDR(src) ((src) & (~SRC_R_MASK))
#define SRC_B_ADDR(src) ((src) & (~SRC_B_MASK))
#define SRC_G_ADDR(src) ((src) & (~SRC_G_MASK))

#define SRC2_IS_IMM4(src) (((src)&SRC2_IMM4_MASK) == SRC2_IMM4_CODE)
#define SRC2_IS_IMM16(src) (((src)&SRC2_IMM16_MASK) == SRC2_IMM16_CODE)
#define SRC2_IS_IMM32(src) (((src)&SRC2_IMM32_MASK) == SRC2_IMM32_CODE)
#define SRC2_IS_IMM64(src) (((src)&SRC2_IMM64_MASK) == SRC2_IMM64_CODE)
#define SRC2_IMM4_VAL(src) ((src) & (~SRC2_IMM4_MASK))
#define SRC2_IMM16_LTS_IND(src) (((src) & (~SRC2_IMM16_MASK)) & 0b11)
#define SRC2_IMM16_LTS_OFFSET(src) ((((src) & (~SRC2_IMM16_MASK)) & 0b100) >> 2)
#define SRC2_IMM32_LTS_IND(src) ((src) & (~SRC2_IMM32_MASK))
#define SRC2_IMM64_LTS_IND(src) ((src) & (~SRC2_IMM64_MASK))

/* EW/DW checkers */
#define E2K_IS_EW(word, tag) \
	((tag) == 0b01 && (((word)&E2K_DWEW_ITAG_MASK) == E2K_EW_ITAG_MASKED))
#define E2K_IS_DW(word, tag) \
	((tag) == 0b01 && (((word)&E2K_DWEW_ITAG_MASK) == E2K_DW_ITAG_MASKED))

static inline unsigned long check_soft_pm_debug_feature(unsigned long feature)
{
	return current->mm->context.pm_soft_options_mask & feature;
}

static inline unsigned long check_pm_sc_debug_feature(const int debug_mask)
{
	return current->mm->context.pm_sc_debug_mode & debug_mask;
}

static inline u64 get_stack_top(const struct pt_regs *regs)
{
	u64 sp, stack_size, top;
	calculate_e2k_dstack_parameters(&regs->stacks, &sp, &stack_size, &top);
	return top;
}

#if 0
static inline struct vm_area_struct *va_slice_is_in_current_vma(u64 start_va,
								u64 end_va)
{
	mmap_read_lock(current->mm);
	struct vm_area_struct *vma_start = find_vma(current->mm, start_va);
	struct vm_area_struct *vma_end = find_vma(current->mm, end_va);
	mmap_read_unlock(current->mm);
	if ((vma_start && start_va >= vma_start->vm_start) &&
	    (vma_end && end_va >= vma_end->vm_start) &&
	    (vma_start == vma_end)) {
		return vma_start;
	}
	return NULL;
}
#endif

static inline unsigned long get_trap_als_mask(struct pt_regs *regs)
{
	return regs->trap->TIR.al;
}

/**
 * get_als() - Read als syllable from user ip.
 * @ip: Instruction pointer to user code.
 * @als_ch: Als channel number, 0..5.
 * @als: Where the als syllable is stored.
 *
 * Return: 0 on success, -ESRCH on no als, copy_from_user ret on failure.
 */
static unsigned long get_als(const void *__user ip, int als_ch,
			     instr_als_t *als)
{
	/* why not find_als? it would not work. ip is in user space. */
	instr_hs_t hs;
	unsigned long res = copy_from_user(&hs, ip, sizeof(instr_hs_t));
	if (res)
		return res;
	if (!(hs.al & (1 << als_ch)))
		return -ESRCH;
	int offset = hweight32(hs.al & ((1 << als_ch) - 1)) + 1 + hs.s;
	return copy_from_user(als, (const e2k_reg_t *__user)ip + offset,
			      sizeof(instr_als_t));
}

/**
 * get_maybe_virtual_ales() - Set ales syllable, corresponding to alsN.
 * @ip: Instruction pointer to user code.
 * @n: Channel number, 0..5.
 * @ales: Where the ales half syllable is stored.
 *
 * For channels 2/5 may set virtual ales, as they behave as if there is one
 * while there is no physical ales into the wide instruction.
 * If there is no corresponding ales for this channel, does nothing.
 *
 * Return: 0 on success, !0 on failure.
 */
static unsigned long get_maybe_virtual_ales(const void *__user ip, int n,
					    instr_ales_t *ales)
{
	const instr_ales_t virtual_ales = { .alef2.opce = NONE_ALES_OPCE,
					    .alef2.opc2 = EXT_ALES_OPC2 };
	instr_hs_t hs;
	unsigned long res = copy_from_user(&hs, ip, sizeof(instr_hs_t));
	if (res)
		return res;
	if (!(hs.ale & (1 << n))) {
		/* no (real or virtual) ales, do nothing */
		return 0;
	}
	if (!(hs.al & (1 << n))) {
		/* the state "no als, but ales set" is isa-reserved */
		return -EINVAL;
	}
	int f1_syl_amount = 1 + hs.s + hweight32(hs.al) + hs.c0;
	instr_syl_t ales_pair = 0;
	int pair_ind = 0;
	if (n == 2 || n == 5) {
		if (CURRENT_ISET < E2K_ISET_V4) {
			*ales = virtual_ales;
			return 0;
		} else {
			if (f1_syl_amount + hs.c1 == hs.mdl + 1) {
				/* ales2/5 not included */
				*ales = virtual_ales;
				return 0;
			} else {
				int offset = f1_syl_amount;
				res = copy_from_user(
					&ales_pair,
					(const e2k_reg_t *__user)ip + offset,
					sizeof(instr_syl_t));
				if (res)
					return res;
				/* n is 5 and 2nd ales also exists, otherwize 0 */
				pair_ind = (n == 5) && (hs.ale & 0b100);
				pr_debug("Got ales 2/5 pair = 0x%08x\n",
					 ales_pair);
			}
		}
	} else {
		/* n = 0, 1, 3, 4*/
		/* if we have ales3 only, then it's in fact first ales in instr */
		/* excluding ales2,5 */
		int nth_ales_fact_n =
			hweight32(((1 << n) - 1) & hs.ale & 0b011011);
		int offset = hs.mdl + 1 + (nth_ales_fact_n / 2);
		res = copy_from_user(&ales_pair,
				     (const e2k_reg_t *__user)ip + offset,
				     sizeof(instr_syl_t));
		if (res)
			return res;
		pair_ind = nth_ales_fact_n % 2;
		pr_debug("Got ales 0/1/3/4 pair = 0x%08x\n", ales_pair);
	}
	/* in upper part of the pair syllable there is lower ales.
	   +------+------+------+------+
	   | byte | byte | byte | byte |
	   |  n+3 |  n+2 |  n+1 |  n   |
	   +------+------+------+------+
	   |  halfsyll   |   halfsyll  |
	   |     j       |      j+1    |
	   +-------------+-------------+ */
	pair_ind = pair_ind ^ 1;
	*ales = ((instr_ales_t *)&ales_pair)[pair_ind];
	return 0;
}

/**
 * get_existing_lts - Get LTS syllable, that is guaranteed to exist in WC.
 * @ip: Instruction pointer.
 * @n: Number of LTS syllable.
 * @lts: Pointer, where extracted lts is saved.
 *
 * The caller must guarantee that LTS exist. I.e. when some op has lts
 * as an argument, hardware guarantees this.
 *
 * Return: -EINVAL on wrong n, copy_from_user ret (0 on success).
 */
static unsigned long get_existing_lts(const void *__user ip, int n,
				      instr_lts_t *lts)
{
	/* find_lts_f32 not applicable. is for kernel *ip, not for user one. */
	int instr_size;

	/* There are four possible LTS syllables, numbered from 0 to 3 */
	if (n < 0 || n > 3)
		return -EINVAL;

	instr_hs_t hs;
	unsigned long res = copy_from_user(&hs, ip, sizeof(instr_hs_t));
	if (res)
		return res;
	instr_size = E2K_GET_INSTR_SIZE(hs);

	return copy_from_user(lts,
			      (ip + instr_size - hs.cd * sizeof(instr_cds_t) -
			       hs.pl * sizeof(instr_pls_t) -
			       sizeof(instr_lts_t) * (n + 1)),
			      sizeof(instr_lts_t));
}

/**
 * get_src2_imm - Extract immediate value from src2 coded field.
 * @ip: Instruction pointer.
 * @src2: Coded src2 field from wide cmd.
 * @imm: Extracted immediate value.
 *
 * Return: -EINVAL or copy_from_user ret, 0 on success.
 */
static unsigned long get_src2_imm(const void *__user ip, u8 src2, s64 *imm)
{
	unsigned long res;
	if (SRC2_IS_IMM4(src2)) {
		*imm = (s64)(SRC2_IMM4_VAL(src2));
		return 0;
	} else if (SRC2_IS_IMM16(src2)) {
		u8 lts_ind = SRC2_IMM16_LTS_IND(src2);
		if (lts_ind > 1) /* see ISA, 5 */
			return -EINVAL;
		u8 lts_oft = SRC2_IMM16_LTS_OFFSET(src2);
		instr_lts_t lts;
		if ((res = get_existing_lts(ip, lts_ind, &lts)))
			return res;
		*imm = (s64)(((s16 *)&lts)[lts_oft]);
		return 0;
	} else if (SRC2_IS_IMM32(src2)) {
		u8 lts_ind = SRC2_IMM32_LTS_IND(src2);
		instr_lts_t lts;
		if ((res = get_existing_lts(ip, lts_ind, &lts)))
			return res;
		*imm = (s64)(((s32 *)&lts)[0]);
		return 0;
	} else if (SRC2_IS_IMM64(src2)) {
		u8 lts_ind = SRC2_IMM64_LTS_IND(src2);
		if (lts_ind == 3)
			return -EINVAL;
		instr_lts_t ltss[2];
		if ((res = get_existing_lts(ip, lts_ind, &ltss[0])))
			return res;
		if ((res = get_existing_lts(ip, lts_ind + 1, &ltss[1])))
			return res;
		*imm = ((s64 *)ltss)[0];
		return 0;
	}
	return -EINVAL;
}

/**
 * softpm_suitable() - Check if soft_pm is enabled and task is protected.
 * @regs: Pointer to pt_regs structure.
 *
 * Return: 1 if suitable, 0 otherwise.
 */
static int softpm_suitable(const struct pt_regs *regs)
{
	if (!(TASK_IS_PROTECTED(current) &&
	      check_soft_pm_debug_feature(PM_SOFT_GLOBAL_ENABLE)))
		return 0;
	/* now we are definitely in context of a faulty protected task */

	if (unlikely(get_trap_ip(regs) != instruction_pointer(regs))) {
		pr_err("%s:%d : The interrupt that must be precise is not precise, default action!\n",
		       __FILE__, __LINE__);
		return 0;
	}
	return 1;
}

static inline void load_dvalue_and_tagd_from_psp(const volatile void *psp_addr,
						 e2k_dreg_t *dword, u8 *tags)
{
	load_value_and_tagd(psp_addr, &dword->word, tags);
}

static inline void load_qvalue_and_tagq_from_psp(const volatile void *psp_addr,
						 e2k_qreg_t *qword, u8 *tags)
{
	load_qvalue_and_tagq(psp_addr, qword, tags, machine.qnr1_offset);
}

static inline void load_xvalue_and_tagx_from_psp(const volatile void *psp_addr,
						 e2k_xreg_t *xword, u8 *tags)
{
	u64 ext_offset = (CURRENT_ISET <= 4) ? 16 : 8;
	load_qvalue_and_tagq(psp_addr, (e2k_qreg_t *)xword, tags, ext_offset);
}

static inline void load_qpvalue_and_tagqp_from_psp(const volatile void *psp_addr,
						   e2k_qreg_t *qword, u8 *tags)
{
	BUG_ON(CURRENT_ISET <= 4);
	load_qvalue_and_tagq(psp_addr, qword, tags, 8);
}

static inline void load_dvalue_and_tagd_from_k_gregs(const volatile void *k_greg_addr,
						     e2k_dreg_t *dword,
						     u8 *tags)
{
	load_value_and_tagd(k_greg_addr, &dword->word, tags);
}

static inline void load_qvalue_and_tagq_from_k_gregs(const volatile void *k_greg_addr,
						     e2k_qreg_t *qword,
						     u8 *tags)
{
	/* kernel_gregs is an array of e2k_greg, each representing xNR or qpNR
	   need to read greg[N].lo and greg[N+1].lo => offset 16 */
	load_qvalue_and_tagq(k_greg_addr, qword, tags, sizeof(struct e2k_greg));
}

static inline void load_xvalue_and_tagx_from_k_gregs(const volatile void *k_greg_addr,
						     e2k_xreg_t *xword,
						     u8 *tags)
{
	load_qvalue_and_tagq(k_greg_addr, (e2k_qreg_t *)xword, tags, 8);
}

static inline void load_qpvalue_and_tagqp_from_k_gregs(const volatile void *k_greg_addr,
						       e2k_qreg_t *qword,
						       u8 *tags)
{
	BUG_ON(CURRENT_ISET <= 4);
	load_qvalue_and_tagq(k_greg_addr, qword, tags, 8);
}

static inline void
load_dvalue_and_tagd_from_real_greg(int rnum_d, e2k_dreg_t *dword, u8 *tags)
{
	register u64 val;
	E2K_GET_DGREG_VAL_AND_TAG(rnum_d, val, *tags);
	dword->word = val;
}

static inline void
load_qvalue_and_tagq_from_real_greg(int rnum_d, e2k_qreg_t *qword, u8 *tags)
{
	register u64 val;
	u8 hi_tags;
	E2K_GET_DGREG_VAL_AND_TAG(rnum_d, val, *tags);
	qword->lo = val;
	E2K_GET_DGREG_VAL_AND_TAG(rnum_d + 1, val, hi_tags);
	qword->hi = val;
	*tags = ((*tags & 0b00001111) | (hi_tags << 4));
}

static inline void
load_xvalue_and_tagx_from_real_greg(int rnum_d, e2k_xreg_t *xword, u8 *tags)
{
	volatile e2k_xreg_t qreg_saved;
	NATIVE_SAVE_SINGLE_GREG_VAR(&qreg_saved, rnum_d, CURRENT_ISET);
	load_qvalue_and_tagq(&qreg_saved, (e2k_qreg_t *)xword, tags, 8);
}

static inline void
load_qpvalue_and_tagqp_from_real_greg(int rnum_d, e2k_qreg_t *qword, u8 *tags)
{
	BUG_ON(CURRENT_ISET <= 4);
	volatile e2k_qreg_t qreg_saved;
	NATIVE_SAVE_SINGLE_GREG_VAR(&qreg_saved, rnum_d, CURRENT_ISET);
	load_qvalue_and_tagq(&qreg_saved, qword, tags, 8);
}

static inline void
store_dvalue_and_tagd_to_psp(volatile void *psp_addr, const e2k_dreg_t *dword, u8 tags)
{
	store_tagged_dword(psp_addr, dword->word, tags & 0b1111);
}

static inline void
store_qvalue_and_tagq_to_psp(volatile void *psp_addr, const e2k_qreg_t *qword, u8 tags)
{
	store_tagged_qword(psp_addr, *qword, tags, machine.qnr1_offset);
}

static inline void store_xvalue_and_tagx_to_psp_v3(volatile void *psp_addr,
						   const e2k_xreg_t *xword,
						   u8 tags)
{
	BUG_ON(CURRENT_ISET > 4);
	u64 ext_offset = 16;
	/* on <= V4 ext part is not tagged. On >= V5 it is tagged */
	tags &= 0b1111;
	e2k_qreg_t data = { .lo = xword->word, .hi = xword->ext };
	store_tagged_qword(psp_addr, data, tags, ext_offset);
}

static inline void
store_qpvalue_and_tagqp_to_psp(volatile void *psp_addr, const e2k_qreg_t *qword, u8 tags)
{
	BUG_ON(CURRENT_ISET <= 4);
	store_tagged_qword(psp_addr, *qword, tags, 8);
}

static inline void store_dvalue_and_tagd_to_k_gregs(volatile void *k_greg_addr,
						    const e2k_dreg_t *dword,
						    u8 tags)
{
	store_tagged_dword(k_greg_addr, dword->word, tags & 0b1111);
}

static inline void store_qvalue_and_tagq_to_k_gregs(volatile void *k_greg_addr,
						    const e2k_qreg_t *qword,
						    u8 tags)
{
	/* kernel_gregs is an array of e2k_greg, each representing xNR or qpNR
	   need to read greg[N].lo and greg[N+1].lo => offset 16 */
	store_tagged_qword(k_greg_addr, *qword, tags, 16);
}

static inline void store_xvalue_and_tagx_to_k_gregs_v3(volatile void *k_greg_addr,
						       const e2k_xreg_t *xword,
						       u8 tags)
{
	BUG_ON(CURRENT_ISET > 4);
	/* on <= V4 ext part is not tagged. On >= V5 it is tagged */
	tags &= 0b1111;
	e2k_qreg_t data = { .lo = xword->word, .hi = xword->ext };
	store_tagged_qword(k_greg_addr, data, tags, 8);
}

static inline void store_qpvalue_and_tagqp_to_k_gregs(volatile void *k_greg_addr,
						      const e2k_qreg_t *qword,
						      u8 tags)
{
	BUG_ON(CURRENT_ISET <= 4);
	store_tagged_qword(k_greg_addr, *qword, tags, 8);
}

static inline void
store_dvalue_and_tagd_to_real_greg(int rnum_d, const e2k_dreg_t *dword, u8 tags)
{
	E2K_SET_DGREG_VAL_AND_TAG(rnum_d, dword->word, tags & 0b1111);
}

static inline void
store_qvalue_and_tagq_to_real_greg(int rnum_d, const e2k_qreg_t *qword, u8 tags)
{
	E2K_SET_DGREG_VAL_AND_TAG(rnum_d, qword->lo, tags & 0b1111);
	E2K_SET_DGREG_VAL_AND_TAG(rnum_d + 1, qword->hi, (tags >> 4) & 0b1111);
}

static inline void
store_xvalue_and_tagx_to_real_greg_v3(int rnum_d, const e2k_xreg_t *xword,
				      u8 tags)
{
	BUG_ON(CURRENT_ISET > 4);
	volatile struct e2k_greg tagged_saved_greg;
	/* on <= V4 ext part is not tagged. On >= V5 it is tagged */
	tags &= 0b1111;
	e2k_qreg_t data = { .lo = xword->word, .hi = xword->ext };
	store_tagged_qword(&tagged_saved_greg, data, tags, 8);
	NATIVE_RESTORE_SINGLE_GREG_VAR(&tagged_saved_greg, rnum_d,
				       CURRENT_ISET);
}

static inline void store_qpvalue_and_tagqp_to_real_greg(int rnum_d,
							const e2k_qreg_t *qword,
							u8 tags)
{
	BUG_ON(CURRENT_ISET <= 4);
	volatile struct e2k_greg tagged_saved_greg;
	store_tagged_qword(&tagged_saved_greg, *qword, tags, 8);
	NATIVE_RESTORE_SINGLE_GREG_VAR(&tagged_saved_greg, rnum_d,
				       CURRENT_ISET);
}

/* helper functions/macros (end) */
/* ########################################################################## */
/* Output, debug and report (start) */

#define pr_debug_reg(...)                                        \
	{                                                        \
		check_soft_pm_debug_feature(PM_SOFT_DEBUG_REG) ? \
			pr_info(__VA_ARGS__) :                   \
			0;                                       \
	}

#define pr_debug_operation(...)                                        \
	{                                                              \
		check_soft_pm_debug_feature(PM_SOFT_DEBUG_OPERATION) ? \
			pr_info(__VA_ARGS__) :                         \
			0;                                             \
	}

#define pr_debug_correction(...)                                        \
	{                                                               \
		check_soft_pm_debug_feature(PM_SOFT_DEBUG_CORRECTION) ? \
			pr_info(__VA_ARGS__) :                          \
			0;                                              \
	}

#define FIXED_LEN_BUF_LEN_MAX 512
struct fixed_len_buf {
	char buf[FIXED_LEN_BUF_LEN_MAX];
	ssize_t pos;
};

static struct kmem_cache *fixed_len_buf_slab_alloc;

/*
 * Print to report buffer and advance pos.
 * If no place left, nothing will be printed, no overfill possible.
 */
#define FIXED_LEN_BUF_PRINTF(buffer, ...)                                      \
	{                                                                      \
		if (buffer) {                                                  \
			ssize_t len = FIXED_LEN_BUF_LEN_MAX - (buffer)->pos;   \
			BUG_ON(len < 0);                                       \
			if (likely(len > 0)) {                                 \
				ssize_t ret = snprintf(                        \
					&(buffer)->buf[(buffer)->pos], len,    \
					__VA_ARGS__);                          \
				if (unlikely(ret >= len))                      \
					(buffer)->pos = FIXED_LEN_BUF_LEN_MAX; \
				else                                           \
					(buffer)->pos += ret;                  \
			}                                                      \
		}                                                              \
	}

#define pr_note_debug_reg(notes, ...)                              \
	{                                                          \
		FIXED_LEN_BUF_PRINTF((notes), "\t\t" __VA_ARGS__); \
		check_soft_pm_debug_feature(PM_SOFT_DEBUG_REG) ?   \
			pr_info(__VA_ARGS__) :                     \
			0;                                         \
	}

#define pr_note_debug_operation(notes, ...)                            \
	{                                                              \
		FIXED_LEN_BUF_PRINTF((notes), "\t\t" __VA_ARGS__);     \
		check_soft_pm_debug_feature(PM_SOFT_DEBUG_OPERATION) ? \
			pr_info(__VA_ARGS__) :                         \
			0;                                             \
	}

#define pr_note_debug_correction(notes, ...)                            \
	{                                                               \
		FIXED_LEN_BUF_PRINTF((notes), "\t\t" __VA_ARGS__);      \
		check_soft_pm_debug_feature(PM_SOFT_DEBUG_CORRECTION) ? \
			pr_info(__VA_ARGS__) :                          \
			0;                                              \
	}

static inline void fixed_len_buf_init(struct fixed_len_buf *buf)
{
	if (buf)
		buf->pos = 0;
}

static inline int fixed_len_buf_len(const struct fixed_len_buf *buf)
{
	return buf ? buf->pos : 0;
}

/**
 * fixed_len_buf_overfilled() - Check if output into buf exceedes it's size.
 * @buf: The buffer.
 *
 * In fact, a buffer is never overfilled.
 * But if filled completely, then it is very likely to be in fact overfilled
 * (With truncated contents).
 *
 * Return: 1 if overfilled, 0 otherwise.
 */
static inline int fixed_len_buf_overfilled(const struct fixed_len_buf *buf)
{
	if (!buf)
		return 0;
	return (buf->pos == FIXED_LEN_BUF_LEN_MAX) ? 1 : 0;
}

/**
 * struct report_bufs - Several reports for user.
 * @operation_report: Info about exc place, faulty operation and cause.
 * @correction_report: Info about applied correction.
 * @notes_report: Important non-standard notes about correction process.
 */
struct report_bufs {
	struct fixed_len_buf *operation_report;
	struct fixed_len_buf *correction_report;
	struct fixed_len_buf *notes_report;
};

#define OPERATION_BUF_PRINTF(report_bufs, ...) \
	FIXED_LEN_BUF_PRINTF((report_bufs)->operation_report, __VA_ARGS__)

#define CORRECTION_BUF_PRINTF(report_bufs, ...) \
	FIXED_LEN_BUF_PRINTF((report_bufs)->correction_report, __VA_ARGS__)

#define NOTES_BUF_PRINTF(report_bufs, ...) \
	FIXED_LEN_BUF_PRINTF((report_bufs)->notes_report, __VA_ARGS__)

/**
 * report_bufs_init() - init report_bufs struct.
 * @bufs: report_bufs struct.
 *
 * Allocates memory for buffers via kmem_cache_alloc and sets initial values.
 */
static inline void report_bufs_init(struct report_bufs *bufs)
{
	bufs->operation_report = NULL;
	bufs->correction_report = NULL;
	bufs->notes_report = NULL;
	if (check_soft_pm_debug_feature(PM_SOFT_PRINT_OPERATION))
		bufs->operation_report =
			kmem_cache_alloc(fixed_len_buf_slab_alloc, GFP_KERNEL);
	if (check_soft_pm_debug_feature(PM_SOFT_PRINT_CORRECTION))
		bufs->correction_report =
			kmem_cache_alloc(fixed_len_buf_slab_alloc, GFP_KERNEL);
	if (check_soft_pm_debug_feature(PM_SOFT_PRINT_NOTES))
		bufs->notes_report =
			kmem_cache_alloc(fixed_len_buf_slab_alloc, GFP_KERNEL);
	fixed_len_buf_init(bufs->operation_report);
	fixed_len_buf_init(bufs->correction_report);
	fixed_len_buf_init(bufs->notes_report);
}

/**
 * report_bufs_drop() - Clean (drop) report_bufs.
 * @bufs: Report_bufs struct.
 *
 * De-allocates buffers.
 */
static inline void report_bufs_drop(struct report_bufs *bufs)
{
	if (bufs->operation_report)
		kmem_cache_free(fixed_len_buf_slab_alloc,
				bufs->operation_report);
	if (bufs->correction_report)
		kmem_cache_free(fixed_len_buf_slab_alloc,
				bufs->correction_report);
	if (bufs->notes_report)
		kmem_cache_free(fixed_len_buf_slab_alloc, bufs->notes_report);
}

/**
 * report_preamble - Fill in report preamble to buffers.
 * @bufs: Report_bufs struct.
 * @regs: Pinter to pt_regs structure.
 * @exc_ind: Index of the exception in the exception table.
 * @exc_name: Exception name (from exc name table).
 *
 * Fills in information about place where the exception occured.
 */
static void report_preamble(struct report_bufs *bufs,
			    const struct pt_regs *regs, int exc_ind,
			    const char *exc_name)
{
	const char *cmdline = current->comm;
	/* kstrdup_quotable_cmdline is rather slow (at least 2 kmalloc)
	   => conditional enabled */
	if (check_soft_pm_debug_feature(PM_SOFT_PRINT_FULL_CMDLINE) &&
	    (cmdline = kstrdup_quotable_cmdline(current, GFP_KERNEL)) == NULL) {
		pr_err("%s:%d : kstrdup_quotable_cmdline error.\n", __FILE__,
		       __LINE__);
		cmdline = current->comm;
	}
	OPERATION_BUF_PRINTF(
		bufs,
		"Protected Mode error at ip=0x%lx; PID=%d cmd=\"%s\"\n"
		"Cause: %s\n",
		(unsigned long)instruction_pointer(regs), current->pid, cmdline,
		exc_name);
	if (check_soft_pm_debug_feature(PM_SOFT_PRINT_FULL_CMDLINE))
		kfree(cmdline);
	/*
	 * If any PM excs were handled before on same interrupt.
	 * I.e. when single cmd contais array_bounds and illegs syllables.
	 */
	if (regs->trap->TIRs[0].exc & SOFT_PM_EXCEPTIONS_MASK &
	    ((1 << exc_ind) - 1)) {
		NOTES_BUF_PRINTF(
			bufs,
			"\t\tHandled on same interrupt with the error above.\n");
	}
}

/**
 * print_buf() - Print the buf to stderr or journl, according to env settings.
 * @buf: Text buffer.
 * @len: Buffer length.
 *
 * Return: kernel_write() retval.
 */
static inline int print_buf(const char *buf, unsigned long len)
{
	int ret = pr_info("%s", buf);
	if (check_soft_pm_debug_feature(PM_SOFT_PRINT_TO_STDERR)) {
		ret = protected_mode_write_to_current_stderr(buf, len);
	}
	return ret;
}

static int print_report(const struct report_bufs *bufs)
{
#define OUT_REPORT(report)                                                                    \
	{                                                                                     \
		if (report) {                                                                 \
			if (unlikely(tempret = print_buf((report)->buf,                       \
							 (report)->pos) < 0))                 \
				ret = tempret;                                                \
			if (unlikely(fixed_len_buf_overfilled(report))) {                     \
				pr_err("%s:%d : %s buffer overfilled!\n",                     \
				       __FILE__, __LINE__, (#report));                        \
				/* truncated output in overfilled buf does not end with \n */ \
				print_buf("\n", 1);                                           \
			}                                                                     \
		}                                                                             \
	}

#define OUT_CHARSTR(str) print_buf((str), sizeof(str) / sizeof(char) - 1)

	int ret = 0, tempret;
	if (fixed_len_buf_len(bufs->operation_report))
		OUT_REPORT(bufs->operation_report);
	if (fixed_len_buf_len(bufs->correction_report)) {
		OUT_CHARSTR("Corrected:\n");
		OUT_REPORT(bufs->correction_report);
	}
	if (fixed_len_buf_len(bufs->notes_report)) {
		OUT_CHARSTR("Notes:\n");
		OUT_REPORT(bufs->notes_report);
	}
	return ret;
}

/* Output, debug and report (end) */
/* ########################################################################## */
/* register routines (start) */

/**
 * enum register_type - Mask-based type of registers (register_t).
 * @REG_NONE: No type, not filled register_t.
 * @REG_R: Local register (NR, rN).
 * @REG_G: Global register (gN).
 * @REG_B: Rotating modificator, both for R and G.
 *
 * Register types are masks.
 * Regs can be R, G, RB, GB.
 */
typedef enum {
	REG_NONE = 0x0,
	REG_R = 0b001,
	REG_G = 0b010,
	/* Modificators follow */
	REG_B = 0b100
} register_type;

/**
 * enum register_size - Register sizes from byte to qword for register_t.
 * @REG_SIZE_UNKNOWN: 0, for not filled register_t.
 * @REG_SIZE_BYTE: 1, unused.
 * @REG_SIZE_HALF: 2, unused.
 * @REG_SIZE_WORD: 4, tagged quant, minimal used size.
 * @REG_SIZE_DWORD: 8, longs, doubles.
 * @REG_SIZE_XWORD: 10, long double.
 * @REG_SIZE_QwORD: 16, descriptors.
 *
 * Commands may work with sizes from byte to qword and qpword.
 * PM's atom is a word.
 * We still have dword (or qpword) registers, even if a cmd uses only one byte.
 * Consequently, we can consider only q/d word when loading/storing
 * (as regs are saved/spilled/read in dwords and qwords).
 * And can consider only q/d/w ords when dealing with values.
 * (if byte is a diag, whole word contains garbage.)
 */
typedef enum {
	REG_SIZE_UNKNOWN = 0,
	REG_SIZE_BYTE = E2K_SIZE_BYTE, /* unused, as tagged quant is 32 bit */
	REG_SIZE_HALF = E2K_SIZE_HALF, /* unused, as tagged quant is 32 bit */
	REG_SIZE_WORD = E2K_SIZE_WORD,
	REG_SIZE_DWORD = E2K_SIZE_DWORD,
	REG_SIZE_XWORD = E2K_SIZE_XWORD,
	REG_SIZE_QWORD = E2K_SIZE_QWORD,
} register_size;

typedef enum {
	REG_STAGE_UNINIT = 0,
	REG_STAGE_BASIC_INIT = 1,
	REG_STAGE_TYPE_NUM_SIZE_FILLED = 2,
	REG_STAGE_TYPE_NUM_SIZE_ADDR_FILLED = 3,
	REG_STAGE_FULL_INIT = 4,
} register_stage;

struct register_struct;
typedef struct register_struct register_t;

typedef struct {
	void (*_raw_load)(register_t *);
	void (*_raw_store)(const register_t *);
	void (*_spirnt_val_tag)(const register_t *, char *, bool);
	int (*_fill_addr)(register_t *);
	int (*_load_store)(register_t *, bool);
} register_ops;

#define REG_REPR_MAXLEN 7
#define REG_VAL_MAXLEN 64

/**
 * struct register_struct - An object that represents register-src of a command.
 * @value_s: Original register value, word-sized.
 * @value_d: Original register value, dword-sized.
 * @value_x: Original register value, xword-sized, float80.
 * @value_q: Original register value, qword-sized, qpword.
 * @value_p: Original register value, qword-sized, descriptor.
 * @tags: Original register tags.
 * @new_value_s: New (corrected) register value, word-sized.
 * @new_value_d: New (corrected) register value, dword-sized.
 * @new_value_x: New (corrected) register value, xword-sized, float80.
 * @new_value_q: New (corrected) register value, qword-sized, qpword.
 * @new_value_p: New (corrected) register value, qword-sized, descriptor.
 * @new_tags: New (corrected) register tags.
 * @ops: Register_ops struct with type and size dependent operations.
 * @correction_occured: Flag, set by corrector and reset on syllable iteration.
 *                      Means, the correction occured on this iteration.
 * @corrected: Flag, set by corrector or from history, never reset.
 *             Means, the correction occured on this handler call.
 * @is_qp: Flag to distinguish qword and qpword.
 * @type: Register type.
 * @size: Register size.
 * @mem_addr: Corresponding memory addr where reg is saved, NULL if not saved.
 * @rnum_d: Relative to window or global register num.
 * @bnum_d: Relative to b[0] or g[0] register num.
 * @stage: Register filling pipeline stage.
 * @notes: Notes report buf.
 * @regs: Pinter to pt_regs structure.
 * @repr: String repr for printing.
 *
 * Working with a register is a pipeline:
 * 1) Init
 * 2) Fill info from SRC + Size: size, R/G/B, rnum_d, bnum_d.
 * 3) Determine corresponding address in memory (if exists).
 * 4) Load value - final init stage.
 * 5) Set corrected value to register_struct.
 * 6) Store value.
 * User should have access to:
 * 1) init
 * 2) fill (src, size)
 * 3) set
 * 4) store
 * As We have stages in the pipeline, we will store completed stage and check
 * it in the next one.
 * Methods naming convention:
 * register_...   - public method, available for direct use.
 * _register_...  - private method, pipeline stage check & set
 * __register_... - private internal stage. No checks.
 */
struct register_struct {
	union {
		e2k_reg_t value_s;
		e2k_dreg_t value_d;
		e2k_xreg_t value_x;
		e2k_qreg_t value_q;
		e2k_ptr_t value_p;
	};
	u8 tags;
	union {
		e2k_reg_t new_value_s;
		e2k_dreg_t new_value_d;
		e2k_xreg_t new_value_x;
		e2k_qreg_t new_value_q;
		e2k_ptr_t new_value_p;
	};
	u8 new_tags;
	register_ops ops;
	bool correction_occured;
	bool corrected;
	bool is_qp;
	register_type type;
	register_size size;
	volatile u64 *mem_addr;
	int rnum_d;
	int bnum_d;
	register_stage stage;
	struct fixed_len_buf *notes;
	struct pt_regs *regs;
	char repr[REG_REPR_MAXLEN];
};

static inline void register_init(register_t *reg, struct pt_regs *regs,
				 struct fixed_len_buf *notes)
{
	reg->type = REG_NONE;
	reg->value_q.hi = 0;
	reg->value_q.lo = 0;
	reg->tags = 0;
	reg->new_value_q.hi = 0;
	reg->new_value_q.lo = 0;
	reg->new_tags = 0;
	reg->ops = (register_ops){ NULL, NULL, NULL, NULL, NULL };
	reg->correction_occured = 0;
	reg->corrected = 0;
	reg->is_qp = 0;
	reg->mem_addr = NULL;
	reg->regs = regs;
	reg->notes = notes;
	reg->rnum_d = -1;
	reg->bnum_d = -1;
	reg->size = REG_SIZE_UNKNOWN;
	reg->stage = REG_STAGE_BASIC_INIT;
	reg->repr[0] = '\0';
}

/**
 * register_get_tags() - Get register tags.
 * @reg: Register to ger tags from.
 *
 * We don't have load_value_and_tag for word.
 * So, tags, value, new_value may contain dword info, when dealing with word.
 * Consequently, this function was created to get proper tags.
 *
 * Return: Significant tags. that means, 2bit for word, 4bit for dword,
 *         8bit for qword.
 */
static inline int register_get_tags(const register_t *reg)
{
	if (unlikely(reg->stage < REG_STAGE_FULL_INIT)) {
		pr_err("%s:%d : Tried to get tags from not ready register_t!\n",
		       __FILE__, __LINE__);
		BUG();
	}
	if (unlikely(reg->size == REG_SIZE_QWORD)) {
		return reg->tags;
	} else if (reg->size == REG_SIZE_XWORD) {
		if (CURRENT_ISET <= 4)
			return reg->tags & 0b00001111;
		return reg->tags & 0b00111111;
	} else if (reg->size == REG_SIZE_DWORD) {
		return reg->tags & 0b00001111;
	}
	return reg->tags & 0b00000011;
}

static inline int register_is_filled(const register_t *reg)
{
	return reg->stage >= REG_STAGE_FULL_INIT && reg->type != REG_NONE;
}

static inline int register_is_uninit(const register_t *reg)
{
	BUG_ON(reg->stage < REG_STAGE_FULL_INIT);
	u8 tags = register_get_tags(reg);
	bool has_addr_word = (tags & 0b10101010);
	return has_addr_word ? 0 : (tags & 0b01010101);
}

static inline void register_drop(register_t *reg)
{
	reg->type = REG_NONE;
	reg->stage = REG_STAGE_UNINIT;
	reg->correction_occured = 0;
}

static void _register_sprint_val_dword(const register_t *reg, char *str,
				       bool print_new)
{
	u64 printed_val = print_new ? reg->new_value_d.word : reg->value_d.word;
	u8 printed_tags = print_new ? reg->new_tags : reg->tags;
	snprintf(str, REG_VAL_MAXLEN, "{0x%016llx tag=%d%d}",
		printed_val, (printed_tags & 0b00001100) >> 2, (printed_tags & 0b00000011)
	);
}

static void _register_sprint_val_qword(const register_t *reg, char *str,
				       bool print_new)
{
	e2k_qreg_t printed_val = print_new ? reg->new_value_q : reg->value_q;
	u8 printed_tags = print_new ? reg->new_tags : reg->tags;
	snprintf(str, REG_VAL_MAXLEN, "lo:{0x%016llx tag=%d%d} hi:{0x%016llx tag=%d%d}",
		printed_val.lo, (printed_tags & 0b00001100) >> 2, (printed_tags & 0b00000011),
		printed_val.hi, (printed_tags & 0b11000000) >> 6, (printed_tags & 0b00110000) >> 4
	);
}

static void _register_sprint_val_xword(const register_t *reg, char *str,
				       bool print_new)
{
	e2k_xreg_t printed_val = print_new ? reg->new_value_x : reg->value_x;
	u8 printed_tags = print_new ? reg->new_tags : reg->tags;
	if (CURRENT_ISET <= 4)
		snprintf(str, REG_VAL_MAXLEN, "{0x%04x}{0x%016llx tag=%d%d}",
			printed_val.ext, printed_val.word,
			(printed_tags & 0b00001100) >> 2, (printed_tags & 0b00000011)
		);
	else
		snprintf(str, REG_VAL_MAXLEN, "{0x%04x tag=%d}{0x%016llx tag=%d%d}",
			printed_val.ext, (printed_tags & 0b00110000) >> 4,
			printed_val.word,
			(printed_tags & 0b00001100) >> 2, (printed_tags & 0b00000011)
		);
}

static void _register_sprint_val_qpword(const register_t *reg, char *str,
					bool print_new)
{
	e2k_qreg_t printed_val = print_new ? reg->new_value_q : reg->value_q;
	u8 printed_tags = print_new ? reg->new_tags : reg->tags;
	snprintf(str, REG_VAL_MAXLEN, "d0:{0x%016llx tag=%d%d} d1:{0x%016llx tag=%d%d}",
		printed_val.lo, (printed_tags & 0b00001100) >> 2, (printed_tags & 0b00000011),
		printed_val.hi, (printed_tags & 0b11000000) >> 6, (printed_tags & 0b00110000) >> 4
	);
}

static void _register_raw_load_dword_R(register_t *reg)
{
	load_dvalue_and_tagd_from_psp(reg->mem_addr, &reg->value_d, &reg->tags);
}

static void _register_raw_load_qword_R(register_t *reg)
{
	load_qvalue_and_tagq_from_psp(reg->mem_addr, &reg->value_q, &reg->tags);
}

static void _register_raw_load_xword_R(register_t *reg)
{
	load_xvalue_and_tagx_from_psp(reg->mem_addr, &reg->value_x, &reg->tags);
}

static void _register_raw_load_qpword_R(register_t *reg)
{
	load_qpvalue_and_tagqp_from_psp(reg->mem_addr, &reg->value_q,
					&reg->tags);
}

static void _register_raw_load_dword_G(register_t *reg)
{
	if (unlikely(reg->mem_addr))
		load_dvalue_and_tagd_from_k_gregs(reg->mem_addr, &reg->value_d,
						  &reg->tags);
	else
		load_dvalue_and_tagd_from_real_greg(reg->rnum_d, &reg->value_d,
						    &reg->tags);
}

static void _register_raw_load_qword_G(register_t *reg)
{
	if (unlikely(reg->mem_addr))
		load_qvalue_and_tagq_from_k_gregs(reg->mem_addr, &reg->value_q,
						  &reg->tags);
	else
		load_qvalue_and_tagq_from_real_greg(reg->rnum_d, &reg->value_q,
						    &reg->tags);
}

static void _register_raw_load_xword_G(register_t *reg)
{
	if (unlikely(reg->mem_addr))
		load_xvalue_and_tagx_from_k_gregs(reg->mem_addr, &reg->value_x,
						  &reg->tags);
	else
		load_xvalue_and_tagx_from_real_greg(reg->rnum_d, &reg->value_x,
						    &reg->tags);
}

static void _register_raw_load_qpword_G(register_t *reg)
{
	if (unlikely(reg->mem_addr))
		load_qpvalue_and_tagqp_from_k_gregs(reg->mem_addr,
						    &reg->value_q, &reg->tags);
	else
		load_qpvalue_and_tagqp_from_real_greg(
			reg->rnum_d, &reg->value_q, &reg->tags);
}

static void _register_raw_store_dword_R(const register_t *reg)
{
	store_dvalue_and_tagd_to_psp(reg->mem_addr, &reg->new_value_d,
				     reg->new_tags);
}

static void _register_raw_store_qword_R(const register_t *reg)
{
	store_qvalue_and_tagq_to_psp(reg->mem_addr, &reg->new_value_q,
				     reg->new_tags);
}

static void _register_raw_store_xword_R_v3(const register_t *reg)
{
	store_xvalue_and_tagx_to_psp_v3(reg->mem_addr, &reg->new_value_x,
					reg->new_tags);
}

static void _register_raw_store_qpword_R(const register_t *reg)
{
	store_qpvalue_and_tagqp_to_psp(reg->mem_addr, &reg->new_value_q,
				       reg->new_tags);
}

static void _register_raw_store_dword_G(const register_t *reg)
{
	if (unlikely(reg->mem_addr))
		store_dvalue_and_tagd_to_k_gregs(
			reg->mem_addr, &reg->new_value_d, reg->new_tags);
	else
		store_dvalue_and_tagd_to_real_greg(
			reg->rnum_d, &reg->new_value_d, reg->new_tags);
}

static void _register_raw_store_qword_G(const register_t *reg)
{
	if (unlikely(reg->mem_addr))
		store_qvalue_and_tagq_to_k_gregs(
			reg->mem_addr, &reg->new_value_q, reg->new_tags);
	else
		store_qvalue_and_tagq_to_real_greg(
			reg->rnum_d, &reg->new_value_q, reg->new_tags);
}

static void _register_raw_store_xword_G_v3(const register_t *reg)
{
	if (unlikely(reg->mem_addr))
		store_xvalue_and_tagx_to_k_gregs_v3(
			reg->mem_addr, &reg->new_value_x, reg->new_tags);
	else
		store_xvalue_and_tagx_to_real_greg_v3(
			reg->rnum_d, &reg->new_value_x, reg->new_tags);
}

static void _register_raw_store_qpword_G(const register_t *reg)
{
	if (unlikely(reg->mem_addr))
		store_qpvalue_and_tagqp_to_k_gregs(
			reg->mem_addr, &reg->new_value_q, reg->new_tags);
	else
		store_qpvalue_and_tagqp_to_real_greg(
			reg->rnum_d, &reg->new_value_q, reg->new_tags);
}

static int _register_fill_addr_R(register_t *reg)
{
	/*
	 * Note: variable names in this function:
	 * u_ - user (just before trap)
	 * c_ - kernel current
	 * t_ - kernel just after trap entities
	 * <nothing>, _d, _q - values in bytes, dwords and qwords
	 * _offset meaning: lower_to_upper_offset
	 *
	 * Trap window t_wd (phys addr) is window just after trap.
	 * User's window u_wd is the previous one. with size reg->regs->crs.cr1.wbs
	 * windows are qword aligned, wbs is in qwords.
	 */
	long u_wd_to_t_wd_offset_d = reg->regs->crs.cr1.wbs * 2;

	/* check bounds. */
	/* reg->rnum_d is in fact u_wd_to_reg_offset_d, as it is relative addr. */
	if (unlikely(reg->rnum_d >= u_wd_to_t_wd_offset_d)) {
		/* the reg is in t_wd and later: */
		pr_debug_reg("r%d: Out of window bounds!\n", reg->rnum_d);
		return -EINVAL;
	}

	/* current_thread_info()->k_psp contains psp just after trap enter. */
	/* t_psp_base is in fact t_psp_ptr,
	   as kernel stack must be empty at trap enter */
	u64 *t_psp_base = (u64 *)PSP_BASE(current_thread_info()->k_psp);
	/* how far is first to be spilled in kernel stack from trap wd: */
	long t_pshtp_ind_d = reg->regs->stacks.pshtp.ind / 8;
	long t_pshtp_tind_d = reg->regs->stacks.pshtp.tind / 8;
	pr_debug_reg("Kernel psp_base: 0x%llx\n", (u64)t_psp_base);
	pr_debug_reg("Regs pshtp.ind: %ld, pshtp.tind: %ld (should be equal)\n",
		     t_pshtp_ind_d, t_pshtp_tind_d);

	long first_spilled_to_u_wd_offset_d =
		t_pshtp_tind_d - u_wd_to_t_wd_offset_d;
	if (unlikely(first_spilled_to_u_wd_offset_d < 0)) {
		pr_err("%s:%d : Impossible! reg is already spilled into user stack!\n",
		       __FILE__, __LINE__);
		return -EINVAL;
	}

	long first_spilled_to_reg_addr_offset_d =
		first_spilled_to_u_wd_offset_d + reg->rnum_d;
	pr_debug_reg("first_spilled_to_reg_addr_offset: %ld",
		     first_spilled_to_reg_addr_offset_d);
	/* first spilled corresponds to t_psp_ptr==t_psp_base: */
	u64 *reg_k_psp_addr =
		(u64 *)((u8 *)t_psp_base +
			(first_spilled_to_reg_addr_offset_d / 2) * EXT_4_NR_SZ);
	/* now reg_k_psp_addr points to 32byte saving of a qword. */
	if (first_spilled_to_reg_addr_offset_d % 2) {
		reg_k_psp_addr =
			(u64 *)((u8 *)reg_k_psp_addr + machine.qnr1_offset);
	}
	/* now points to corresponding dword in 32byte chunk. */
	reg->mem_addr = reg_k_psp_addr;

	pr_debug_reg("Addr of r%d (if spilled) is: 0x%llx\n", reg->rnum_d,
		     (u64)reg->mem_addr);
	reg->stage = REG_STAGE_TYPE_NUM_SIZE_ADDR_FILLED;
	return 0;
}

static int _register_fill_addr_G(register_t *reg)
{
	reg->mem_addr = NULL; /* if not saved anywhere, then NULL. */
	if ((reg->rnum_d >= LOCAL_GREGS_START) &&
	    (reg->rnum_d < LOCAL_GREGS_START + LOCAL_GREGS_NUM)) {
		int k_greg_i = reg->rnum_d - LOCAL_GREGS_START;
		volatile struct e2k_greg *pgreg = &(current->thread.u_gregs.g[k_greg_i]);
		reg->mem_addr = &pgreg->base;
		pr_debug_reg("Addr of g%d (saved to k_gregs) is: 0x%llx\n",
			     reg->rnum_d, (u64)reg->mem_addr);
	}
	reg->stage = REG_STAGE_TYPE_NUM_SIZE_ADDR_FILLED;
	return 0;
}

static int _register_load_store_G(register_t *reg, bool is_load)
{
	if (is_load) {
		char reg_repr[REG_VAL_MAXLEN];
		reg->ops._raw_load(reg);
		reg->ops._spirnt_val_tag(reg, reg_repr, 0);
		pr_debug_reg("LoadG: value = %s\n", reg_repr);
	} else {
		reg->ops._raw_store(reg);
	}
	return 0;
}

static int _register_load_store_R(register_t *reg, bool is_load)
{
	/*
	 * When performing load or store operation at psp stack, we must be sure
	 * that the register is really spilled. Spill/Fill are hardware, so
	 * without forbidding all irqs on current cpu, there is a chance, that
	 * after spill operation, an irq will cause fill operation, that will
	 * lead to filling the register.
	 * No irq can interfere in check->spill->load/store chain!
	 */
	unsigned long flags;
	raw_all_irq_save(flags);
	u64 psp_ptr_before_spill = (unsigned long)K_PSP_PTR(read_PSP_reg());
	int spilled_took_place = 0;
	const char *op_repr = "StoreR";
	if (psp_ptr_before_spill <= (u64)reg->mem_addr) { /* not spilled yet */
		E2K_FLUSHR;
		spilled_took_place = 1;
	}
	u64 psp_ptr_after_spill = (unsigned long)K_PSP_PTR(read_PSP_reg());

	/* we can safely do this, as regs are spilled into kernel stack: */
	if (is_load) {
		reg->ops._raw_load(reg);
		op_repr = "LoadR";
	} else {
		reg->ops._raw_store(reg);
	}

	raw_all_irq_restore(flags);

	pr_debug_reg("%s: PSP state before spilling:      ptr=0x%llx\n"
		     "%s: PSP state after spilling==%s:  ptr=0x%llx\n",
		     op_repr, psp_ptr_before_spill, op_repr,
		     spilled_took_place ? "yes" : "no ", psp_ptr_after_spill);
	if (is_load) {
		char reg_repr[REG_VAL_MAXLEN];
		reg->ops._spirnt_val_tag(reg, reg_repr, 0);
		pr_debug_reg("LoadR: value = %s\n", reg_repr);
	}
	return 0;
}

static inline void register_sprint_val(const register_t *reg, char *buf,
				       bool print_new_val)
{
	reg->ops._spirnt_val_tag(reg, buf, print_new_val);
}

static void register_sprint_repr(const register_t *reg, char *buf)
{
	if ((reg->type & REG_B) && (reg->type & REG_R))
		snprintf(buf, REG_REPR_MAXLEN, "b[%d]", reg->bnum_d);
	else if (reg->type & REG_R)
		snprintf(buf, REG_REPR_MAXLEN, "r%d", reg->rnum_d);
	else if ((reg->type & REG_B) && (reg->type & REG_G))
		snprintf(buf, REG_REPR_MAXLEN, "g[%d]", reg->bnum_d);
	else if (reg->type & REG_G)
		snprintf(buf, REG_REPR_MAXLEN, "g%d", reg->rnum_d);
}

/**
 * _register_fill_from_src_size() - Parse src coding and size, fill reg fieslds.
 * @reg: Register to fill in.
 * @src: Coded src field from als/ales.
 * @sz: Register size: word, dword, xword, qword.
 * @is_qp: qpword is qword-sized, but is a different thing.
 *
 * Return: 0 on success, !0 on failure.
*/
static int _register_fill_from_src_size(register_t *reg, int src,
					register_size sz, bool is_qp)
{
	if (unlikely(reg->stage < REG_STAGE_BASIC_INIT)) {
		return -EINVAL;
	}
	pr_debug_reg("Setting register addresses from src=0x%x\n", src);
	BUG_ON(is_qp && sz != REG_SIZE_QWORD);
	if (SRC_IS_R(src)) {
		reg->type = REG_R;
		reg->rnum_d = SRC_R_ADDR(src);
		pr_debug_reg("Register is r%d\n", reg->rnum_d);
	} else if (SRC_IS_B(src)) {
		reg->type = REG_B | REG_R; /* b[#] is also an r# */
		reg->bnum_d = SRC_B_ADDR(src);
		/* ind_d = BR.rbs_d + (BR.rcur_d + rnum_d) mod BR.rsz_full_d; */
		u32 rbs_d = reg->regs->crs.cr1.rbs * 2;
		u32 rsz_full_d = (reg->regs->crs.cr1.rsz + 1) * 2;
		u32 rcur_d = reg->regs->crs.cr1.rcur * 2;
		reg->rnum_d = rbs_d + (rcur_d + reg->bnum_d) % rsz_full_d;
		pr_debug_reg("Register is b[%d] or r%d\n", reg->bnum_d,
			     reg->rnum_d);
	} else if (SRC_IS_G(src)) {
		reg->type = REG_G;
		if (SRC_G_ADDR(src) < (E2K_MAXGR_d - 8)) {
			reg->rnum_d = SRC_G_ADDR(src);
			pr_debug_reg("Register is g%d\n", reg->rnum_d);
		} else {
			reg->type |= REG_B;
			reg->bnum_d = SRC_G_ADDR(src) & 0b111;
			e2k_bgr_t bgr = current->thread.u_gregs.bgr;
			reg->rnum_d = (E2K_MAXGR_d - 8) +
				      ((bgr.cur + reg->bnum_d) & 0b111);
			pr_debug_reg("Register is g[%d] or g%d\n", reg->bnum_d,
				     reg->rnum_d);
		}
	} else {
		reg->type = REG_NONE;
		pr_debug_reg("Src=0x%x is not a register!\n", src);
		return -EINVAL;
	}
	reg->size = sz;
	reg->is_qp = is_qp;
	pr_debug_reg("Register size is %d\n", reg->size);

	if (likely(reg->type & REG_R)) {
		reg->ops._fill_addr = _register_fill_addr_R;
		reg->ops._load_store = _register_load_store_R;
	} else {
		reg->ops._fill_addr = _register_fill_addr_G;
		reg->ops._load_store = _register_load_store_G;
	}

	if (reg->size == REG_SIZE_QWORD) {
		if (likely(reg->type & REG_R)) {
			if (is_qp) {
				reg->ops._spirnt_val_tag =
					_register_sprint_val_qpword;
				reg->ops._raw_load =
					_register_raw_load_qpword_R;
				reg->ops._raw_store =
					_register_raw_store_qpword_R;
			} else {
				reg->ops._spirnt_val_tag =
					_register_sprint_val_qword;
				reg->ops._raw_load = _register_raw_load_qword_R;
				reg->ops._raw_store =
					_register_raw_store_qword_R;
			}
		} else {
			if (is_qp) {
				reg->ops._spirnt_val_tag =
					_register_sprint_val_qpword;
				reg->ops._raw_load =
					_register_raw_load_qpword_G;
				reg->ops._raw_store =
					_register_raw_store_qpword_G;
			} else {
				reg->ops._spirnt_val_tag =
					_register_sprint_val_qword;
				reg->ops._raw_load = _register_raw_load_qword_G;
				reg->ops._raw_store =
					_register_raw_store_qword_G;
			}
		}
	} else if (reg->size == REG_SIZE_XWORD) {
		reg->ops._spirnt_val_tag = _register_sprint_val_xword;
		if (likely(reg->type & REG_R)) {
			if (CURRENT_ISET > 4) {
				reg->ops._raw_load =
					_register_raw_load_qpword_R;
				reg->ops._raw_store =
					_register_raw_store_qpword_R;
			} else {
				reg->ops._raw_load = _register_raw_load_xword_R;
				reg->ops._raw_store =
					_register_raw_store_xword_R_v3;
			}
		} else {
			if (CURRENT_ISET > 4) {
				reg->ops._raw_load =
					_register_raw_load_qpword_G;
				reg->ops._raw_store =
					_register_raw_store_qpword_G;
			} else {
				reg->ops._raw_load = _register_raw_load_xword_G;
				reg->ops._raw_store =
					_register_raw_store_xword_G_v3;
			}
		}
	} else {
		reg->ops._spirnt_val_tag = _register_sprint_val_dword;
		if (likely(reg->type & REG_R)) {
			reg->ops._raw_load = _register_raw_load_dword_R;
			reg->ops._raw_store = _register_raw_store_dword_R;
		} else {
			reg->ops._raw_load = _register_raw_load_dword_G;
			reg->ops._raw_store = _register_raw_store_dword_G;
		}
	}
	BUG_ON(reg->ops._fill_addr == NULL ||
	       reg->ops._spirnt_val_tag == NULL || reg->ops._raw_load == NULL ||
	       reg->ops._raw_store == NULL || reg->ops._load_store == NULL);
	register_sprint_repr(reg, reg->repr);
	reg->stage = REG_STAGE_TYPE_NUM_SIZE_FILLED;
	return 0;
}

static int _register_fill_addr(register_t *reg)
{
	if (unlikely(reg->stage < REG_STAGE_TYPE_NUM_SIZE_FILLED)) {
		return -EINVAL;
	}
	int ret = reg->ops._fill_addr(reg);
	if (!ret) {
		reg->stage = REG_STAGE_TYPE_NUM_SIZE_ADDR_FILLED;
	}
	return ret;
}

static int _register_fill_value_tag(register_t *reg)
{
	if (unlikely(reg->stage < REG_STAGE_TYPE_NUM_SIZE_ADDR_FILLED)) {
		return -EINVAL;
	}
	int ret = reg->ops._load_store(reg, 1);
	if (!ret) {
		reg->stage = REG_STAGE_FULL_INIT;
	}
	return ret;
}

/**
 * register_fill() - Decode src field and load register value into register_t
 * @reg: Register_t struct.
 * @src: Coded src field from wide cmd.
 * @sz: Size of the register.
 * @is_qp: Flag to mark qpword.
 *
 * Return: 0 on success, !0 on failure.
 */
static int register_fill(register_t *reg, int src, register_size sz, bool is_qp)
{
	int ret = 0;
	if (unlikely(ret = _register_fill_from_src_size(reg, src, sz, is_qp)))
		goto fail;
	if (unlikely(ret = _register_fill_addr(reg)))
		goto fail;
	if (unlikely(ret = _register_fill_value_tag(reg)))
		goto fail;
	return 0;
fail:
	register_drop(reg);
	return ret;
}

/**
 * register_set_new_value_q() - Set new value according to register size.
 * @reg: Register_t struct.
 * @new_val: Pointer to new value, extended to qword.
 * @new_tags: New tags for the register.
 */
static inline void register_set_new_value_q(register_t *reg,
					    const e2k_qreg_t *new_val,
					    u8 new_tags)
{
	int size_words = (reg->size + E2K_SIZE_WORD - 1) / E2K_SIZE_WORD;

	u8 new_tags_mask = (1 << (2 * size_words)) - 1;
	/* on <= V4 ext part of xNR is untagged */
	if (reg->size == REG_SIZE_XWORD && CURRENT_ISET <= 4)
		new_tags_mask = 0b00001111;

	u64 new_val_lo_mask = size_words == 1 ? 0xFFFFFFFF : 0xFFFFFFFFFFFFFFFF;
	u64 new_val_hi_mask = size_words <= 2 ? 0x0 :
			      size_words == 3 ? 0xFFFFFFFF :
						0xFFFFFFFFFFFFFFFF;

	reg->new_tags = (new_tags & new_tags_mask) |
			(reg->tags & (~new_tags_mask));
	reg->new_value_q.lo = (new_val->lo & new_val_lo_mask) |
			      (reg->value_q.lo & (~new_val_lo_mask));
	reg->new_value_q.hi = (new_val->hi & new_val_hi_mask) |
			      (reg->value_q.hi & (~new_val_hi_mask));
}

/**
 * register_set_new_value_d() - Set new value according to register size.
 * @reg: Register_t struct.
 * @new_val: New value, extended to dword.
 * @new_tags: New tags for the register.
 */
static inline void register_set_new_value_d(register_t *reg, u64 new_val,
					    u8 new_tags)
{
	e2k_qreg_t qword = { .lo = new_val, .hi = 0 };
	register_set_new_value_q(reg, &qword, new_tags);
}

/**
 * register_store_new_value_tag() - Store reg->new_value and reg->new_tags.
 * @reg: register_t struct.
 *
 * This function does not handle sizes, use register_set_new_value.
 *
 * Return: 0 on success, !0 on failure.
 */
static int register_store_new_value_tag(register_t *reg)
{
	if (unlikely(reg->stage < REG_STAGE_FULL_INIT)) {
		return -EINVAL;
	}
	int ret = 0;
	ret = reg->ops._load_store(reg, 0);
/* TODO: this is unnecessary verification, as store must not fail */
/* (store is literally write to existing mem or reg) */
#if 1
	register_t stored_reg = *reg;
	if ((ret = _register_fill_value_tag(&stored_reg))) {
		pr_err("%s:%d : store reg: failed to load new value\n",
		       __FILE__, __LINE__);
		return ret;
	}
	if (unlikely((stored_reg.value_q.lo != reg->new_value_q.lo) ||
		     (stored_reg.value_q.hi != reg->new_value_q.hi) ||
		     (stored_reg.tags != reg->new_tags))) {
		pr_err("%s:%d : store reg: stored value does not match intended one!\n",
		       __FILE__, __LINE__);
		char reg_val_expected[REG_VAL_MAXLEN];
		char reg_val_got[REG_VAL_MAXLEN];
		_register_sprint_val_qpword(reg, reg_val_expected, 1);
		_register_sprint_val_qpword(&stored_reg, reg_val_got, 0);
		pr_err("%s:%d : store reg: Expected: %s; Got: %s\n",
		       __FILE__, __LINE__, reg_val_expected, reg_val_got);
		ret = -EIO;
	}
#endif
	return ret;
}

/* register routines (end) */
/* ########################################################################## */
/* correction history (start) */

#define CORRHISTORY_MAX_LEN 8

struct corrhistory_entry {
	register_type reg_type;
	u8 reg_num;
};

struct corrhistory_set {
	size_t len;
	struct corrhistory_entry history[CORRHISTORY_MAX_LEN];
};

static inline void corrhistory_init(struct corrhistory_set *set)
{
	set->len = 0;
}

static bool corrhistory_entry_is_in_set(const struct corrhistory_set *set,
					struct corrhistory_entry entry)
{
	for (size_t i = 0; i < set->len; i++) {
		if (set->history[i].reg_num == entry.reg_num &&
		    set->history[i].reg_type == entry.reg_type)
			return 1;
	}
	return 0;
}

static void corrhistory_entry_insert(struct corrhistory_set *set,
				     struct corrhistory_entry new_entry)
{
	if (corrhistory_entry_is_in_set(set, new_entry))
		return;
	if (unlikely(set->len >= CORRHISTORY_MAX_LEN)) {
		pr_err("%s:%d : Chosen history size is too small.", __FILE__,
		       __LINE__);
		return;
	}
	set->history[set->len++] = new_entry;
}

static inline bool
corrhistory_reg_is_already_corr(const struct corrhistory_set *set,
				const register_t *reg)
{
	struct corrhistory_entry entry = { .reg_type = reg->type,
					   .reg_num = reg->rnum_d };
	return corrhistory_entry_is_in_set(set, entry);
}

static inline void corrhistory_reg_insert(struct corrhistory_set *set,
					  const register_t *reg)
{
	struct corrhistory_entry entry = { .reg_type = reg->type,
					   .reg_num = reg->rnum_d };
	corrhistory_entry_insert(set, entry);
}

/* correction history (end) */
/* ########################################################################## */
/* syllable routines (start) */

typedef enum {
	SYL_OP_CLASS_NONE = 0,
	SYL_OP_CLASS_ALU = 1,
	SYL_OP_CLASS_MEM = 2,
	SYL_OP_CLASS_CUSTOM = 3,
} syllable_operation_class;

typedef enum {
	SYL_NONE = 0,
	SYL_HS = 1,
	SYL_ALS = 2,
	SYL_AAS = 3
} syllable_type;

static const char *const syllable_type_reprs[] = { "NONE", "HS", "ALS", "AAS" };

/**
 * typedef struct syllable_t - Syllable object with extra fields.
 * @instr_als: Raw als syllable data.
 * @instr_generic: Raw syllable data, united with instr_als.
 * @instr_ales: Raw ales (corresponding to als) half-syllable data.
 * @type: Syllable type, only SYL_ALS is used (and SYL_NONE for uninit syllable).
 * @op_class: Operaton class: ALU (add, sub), MEM (ld, st) or CUSTOM(getva).
 * @mem_format: How much bytes mem operation operates with, for MEM class.
 * @mem_ext_ind: Extra index, src2, for MEM class.
 * @pos: General position in wide cmd, -1 if undefined.
 * @als_pos: Pos among als syllables, -1 if undefined.
 * @ip: Corresponding wide cmd instruction pointer.
 * @regs: Pointer to pt_regs structure to get srcs.
 * @instr_repr: String representation of opetation for printing.
 * @guessed_size: Operand size, guessed via generic decoder.
 * @guessed_is_qp: Flag to mark qpwords, in addition to guessed_size.
 * @used_no_dec: Flag to mark if generic decoder was used.
 * @exc_cause_num: Exception cause index in exc table.
 * @correction_history: Set of already corrected registers.
 * @reports: Buffers with text report for user.
 * @operands: 4 register_t structs for srcs1..3 and dst.
 *
 * It is not a syllable in sense of instr_*_t, which is a 32bit real syllable.
 * The purpose of this is to gather all information, needed to work with
 * a faulty operation in a single object.
 * Workflow: init_syllable->process->init_next->...
 */
typedef struct {
	union {
		instr_als_t instr_als;
		e2k_reg_t instr_generic;
	};
	instr_ales_t instr_ales;
	syllable_type type;
	syllable_operation_class op_class;
	u8 mem_format;
	s32 mem_ext_ind;
	int pos;
	int als_pos;
	const void *__user ip;
	struct pt_regs *regs;
	const char *instr_repr;
	register_size guessed_size;
	bool guessed_is_qp;
	bool used_no_dec;
	int exc_cause_num;
	struct corrhistory_set correction_history;
	struct report_bufs reports;
	register_t operands[4];
} syllable_t;

static inline void syllable_init_keep_history(syllable_t *syllable,
					      struct pt_regs *regs,
					      int exc_cause_num)
{
	syllable->type = SYL_NONE;
	syllable->op_class = SYL_OP_CLASS_NONE;
	syllable->mem_format = 0;
	syllable->mem_ext_ind = 0;
	syllable->instr_generic.word = 0;
	syllable->instr_ales.word = 0;
	unsigned long ip = instruction_pointer(regs);
	syllable->ip = (const void *__user)ip;
	syllable->regs = regs;
	syllable->pos = -1;
	syllable->als_pos = -1;
	syllable->instr_repr = NULL;
	syllable->guessed_size = REG_SIZE_UNKNOWN;
	syllable->guessed_is_qp = 0;
	syllable->used_no_dec = 0;
	syllable->exc_cause_num = exc_cause_num;
	for (int i = 0; i < 4; i++)
		register_init(&syllable->operands[i], regs,
			      syllable->reports.notes_report);
}

static inline void syllable_init(syllable_t *syllable, struct pt_regs *regs,
				 int exc_cause_num)
{
	corrhistory_init(&syllable->correction_history);
	report_bufs_init(&syllable->reports);
	syllable_init_keep_history(syllable, regs, exc_cause_num);
}

static inline void syllable_drop(syllable_t *syllable)
{
	report_bufs_drop(&syllable->reports);
}

static syllable_t *syllable_fill_next_faulty(syllable_t *syllable,
					     int *prev_als_pos)
{
	syllable->type = SYL_NONE;
	if (unlikely(!syllable->regs || !syllable->ip)) {
		return syllable;
	}

	/* try als */
	unsigned long raw_als_mask = get_trap_als_mask(syllable->regs);
	/* remove already processed (in previos do_smth) syllables */
	unsigned long als_mask =
		raw_als_mask &
		(~((unsigned long)syllable->regs->trap->corrected_als_mask));
	pr_debug_operation(
		"Filling next faulty als. raw_mask = 0x%lx; als_mask=0x%lx\n",
		raw_als_mask, als_mask);
	int als_pos = *prev_als_pos < 0 ? 0 : *prev_als_pos + 1;
	unsigned long als_shifted_mask = als_mask >> als_pos;
	for (; (als_shifted_mask) && !(als_shifted_mask & 1);
	     als_shifted_mask >>= 1, als_pos++)
		;
	if (als_shifted_mask) {
		syllable->als_pos = als_pos;
		*prev_als_pos = als_pos;
		if (get_als(syllable->ip, als_pos, &syllable->instr_als))
			return syllable;
		if (get_maybe_virtual_ales(syllable->ip, als_pos,
					   &syllable->instr_ales))
			return syllable;
		syllable->type = SYL_ALS;
		pr_debug_operation(
			"Found als%d by ip=0x%llx: als=0x%08x; ales=0x%04x\n",
			als_pos, (u64)syllable->ip, syllable->instr_als.word,
			(u32)syllable->instr_ales.word);
	}
	return syllable;
}

static inline bool syllable_is_corrected(const syllable_t *syllable)
{
	return syllable->operands[0].corrected |
	       syllable->operands[1].corrected |
	       syllable->operands[2].corrected |
	       syllable->operands[3].corrected;
}

/**
 * syllable_append_correction_history() - Memorize already processed syllable.
 * @syllable: The syllable to memorize.
 *
 * Memorize corrected registers into syllable->correction_history.
 * Set corrected_als_mask if syllable is corrected. To skip it if
 * another exception occured simultaneously.
 */
static void syllable_append_correction_history(syllable_t *syllable)
{
	for (int i = 0; i < 4; i++) {
		if (syllable->operands[i].correction_occured)
			corrhistory_reg_insert(&syllable->correction_history,
					       &syllable->operands[i]);
	}
	if (syllable_is_corrected(syllable))
		syllable->regs->trap->corrected_als_mask |= 1 << syllable->als_pos;
}

/**
 * syllable_append_report() - Append syllable correction info to reports.
 * @syllable: The syllable to append.
 */
static void syllable_append_report(syllable_t *syllable)
{
	struct report_bufs *bufs = &syllable->reports;
	if (bufs->operation_report) {
		OPERATION_BUF_PRINTF(bufs, "\t\t%s",
				     syllable_type_reprs[(int)syllable->type]);
		if (syllable->type == SYL_ALS) {
			OPERATION_BUF_PRINTF(bufs, "%d:\t", syllable->als_pos);
		} else {
			OPERATION_BUF_PRINTF(bufs, ":\t");
		}
		if (syllable->instr_repr) {
			OPERATION_BUF_PRINTF(bufs, "%s    ",
					     syllable->instr_repr);
		} else if (syllable->type == SYL_ALS) {
			OPERATION_BUF_PRINTF(bufs,
					     "COP=0x%x,ALES.OPC2=0x%x    ",
					     syllable->instr_als.alf2.cop,
					     syllable->instr_ales.alef1.opc2);
		}
		for (int i = 0; i < 4; i++) {
			const register_t *preg = &syllable->operands[i];
			if (preg->type != REG_NONE) {
				if ((preg->type & REG_B) &&
				    (preg->type & REG_R)) {
					OPERATION_BUF_PRINTF(bufs, "b[%d]  ",
							     preg->bnum_d);
				} else if (preg->type & REG_R) {
					OPERATION_BUF_PRINTF(bufs, "r%d  ",
							     preg->rnum_d);
				} else if ((preg->type & REG_B) &&
					   (preg->type & REG_G)) {
					OPERATION_BUF_PRINTF(bufs, "g[%d]  ",
							     preg->bnum_d);
				} else if (preg->type & REG_G) {
					OPERATION_BUF_PRINTF(bufs, "g%d  ",
							     preg->rnum_d);
				} else {
					pr_err("%s:%d : Impossible REG_* combination!\n",
					       __FILE__, __LINE__);
					BUG();
				}
			} else {
				OPERATION_BUF_PRINTF(bufs,
						     (i < 2) ?
							     "src%d  " :
							     "dst/else/src%d  ",
						     i + 1);
			}
		}
		OPERATION_BUF_PRINTF(bufs, "\n");
	}
	if (bufs->correction_report) {
		for (int i = 0; i < 4; i++) {
			const register_t *preg = &syllable->operands[i];
			if (preg->type != REG_NONE &&
			    preg->correction_occured) {
				char reg_val[REG_VAL_MAXLEN];
				CORRECTION_BUF_PRINTF(bufs, "\t\t%s\t",
						      preg->repr);
				register_sprint_val(preg, reg_val, 0);
				CORRECTION_BUF_PRINTF(bufs, "%s -> ", reg_val);
				register_sprint_val(preg, reg_val, 1);
				CORRECTION_BUF_PRINTF(bufs, "%s\n", reg_val);
			}
		}
	}
	if (bufs->notes_report) {
		if (syllable->used_no_dec) {
			NOTES_BUF_PRINTF(
				bufs, "\t\t%s",
				syllable_type_reprs[(int)syllable->type]);
			if (syllable->type == SYL_ALS) {
				NOTES_BUF_PRINTF(bufs, "%d:\t",
						 syllable->als_pos);
			} else {
				NOTES_BUF_PRINTF(bufs, ":\t");
			}
			NOTES_BUF_PRINTF(bufs, "Used NoDec approach.\n");
		}
	}
}

/* syllable routines (end) */
/* ########################################################################## */
/* simple decoder (start) */

struct _dec_als {
	const char *repr;
	u8 srcs_sizes_is_qp[4];
	u8 mem_format;
};

#define _SRC_QP_MASK	(0b100000)
#define _SRC_SIZE_MASK	(0b011111)

#define _DEC_ALS_EMPTY(dec_als) ((dec_als).repr == NULL)
#define _DEC_ALS_SRC_SIZE(dec_als, src_i) \
	((register_size)((dec_als).srcs_sizes_is_qp[(src_i)] & _SRC_SIZE_MASK))
#define _DEC_ALS_HAS_SRC(dec_als, src_i) ((dec_als).srcs_sizes_is_qp[(src_i)])
#define _DEC_ALS_SRC_IS_QP(dec_als, src_i) \
	((dec_als).srcs_sizes_is_qp[(src_i)] & _SRC_QP_MASK)
#define _DEC_ALS_REPR(dec_als) ((dec_als).repr)
#define _DEC_ALS_MEM_FORMAT(dec_als) ((dec_als).mem_format)

static const struct _dec_als _DEC_TBL_ALS_SHORT[0x12][3] = {
	[0x10] = {{"adds", {4, 4, 0, 0}, 0}, {"adds", {4, 4, 0, 0}, 0}, {"adds", {4, 4, 0, 0}, 0},},
	[0x11] = {{"addd", {8, 8, 0, 0}, 0}, {"addd", {8, 8, 0, 0}, 0}, {"addd", {8, 8, 0, 0}, 0},},
};

static const struct _dec_als _DEC_TBL_ALS_EXT[0x53][3] = {
	[0x52] = {{"getva", {16, 4, 0, 0}, 0}, {NULL, {0, 0, 0, 0}, 0}, {NULL, {0, 0, 0, 0}, 0},},
};

/**
 * dec_als() - Fill als syllable fields according to channel, opcode, ales, etc.
 * @syllable: Syllable to decode.
 *
 * This function takes raw values from instr_als, instr_ales fields and
 * decodes them.
 * It does not require specific tables, relies on _DEC_ALS macros.
 *
 * Return: 0 on success, !0 on decoding failure.
 */
static int dec_als(syllable_t *syllable)
{
	int cop = syllable->instr_als.alf3.cop;
	/* 6 als channels are paired 0/3, 1/4, 2/5. */
	int als_eff_ch = syllable->als_pos > 2 ? syllable->als_pos - 3 :
						 syllable->als_pos;
	int ales_opc2 = syllable->instr_ales.alef2.opc2;
	instr_src_t src[4] = { syllable->instr_als.alf3.src1,
		       syllable->instr_als.alf3.src2,
		       syllable->instr_als.alf3.src3,
		       syllable->instr_ales.alef1.src3 };
	pr_debug_operation(
		"DEC: Decoding als%d with cop=0x%x; ales=0x%x; src1/opce/reg#=0x%x; src2=0x%x; src3/dst/reg#=0x%x; ales_src=0x%x\n",
		syllable->als_pos, cop, syllable->instr_ales.word,
		AW(src[0]), AW(src[1]), AW(src[2]), AW(src[3]));
	const struct _dec_als(*dec_tbl)[3] = NULL;
	size_t dec_tbl_size = 0;
	switch (ales_opc2) {
	case 0:
		dec_tbl = _DEC_TBL_ALS_SHORT;
		dec_tbl_size = sizeof(_DEC_TBL_ALS_SHORT);
		break;
	case EXT_ALES_OPC2:
		dec_tbl = _DEC_TBL_ALS_EXT;
		dec_tbl_size = sizeof(_DEC_TBL_ALS_EXT);
		break;
	default:
		return -ESRCH;
	};
	if (!dec_tbl) {
		pr_debug_operation("DEC: Can't determine dec table.\n");
		return -ESRCH;
	}
	if (unlikely(cop * 3 + als_eff_ch >=
		     dec_tbl_size / sizeof(struct _dec_als))) {
		pr_debug_operation("DEC: Unknown cop=%x\n", cop);
		return -ESRCH;
	}
	const struct _dec_als decoded = dec_tbl[cop][als_eff_ch];
	if (unlikely(_DEC_ALS_EMPTY(decoded))) {
		pr_debug_operation("DEC: Unknown cop=%x\n", cop);
		return -ESRCH;
	}
	syllable->instr_repr = _DEC_ALS_REPR(decoded);
	pr_debug_operation(
		"DEC: Decoded: %s srcs_sizes=%d;%d;%d;%d\n",
		syllable->instr_repr ? syllable->instr_repr : "no_repr",
		_DEC_ALS_SRC_SIZE(decoded, 0), _DEC_ALS_SRC_SIZE(decoded, 1),
		_DEC_ALS_SRC_SIZE(decoded, 2), _DEC_ALS_SRC_SIZE(decoded, 3));
	for (int i = 0; i < 4; i++) {
		if (_DEC_ALS_HAS_SRC(decoded, i)) {
			register_fill(&syllable->operands[i], AW(src[i]),
				      _DEC_ALS_SRC_SIZE(decoded, i),
				      _DEC_ALS_SRC_IS_QP(decoded, i));
			if (corrhistory_reg_is_already_corr(
				    &syllable->correction_history,
				    &syllable->operands[i]))
				syllable->operands[i].corrected = 1;
		}
	}
	if (_DEC_ALS_MEM_FORMAT(decoded)) {
		syllable->mem_format = _DEC_ALS_MEM_FORMAT(decoded);
		if (syllable->operands[1].type != REG_NONE)
			syllable->mem_ext_ind =
				(s32)syllable->operands[1].value_s.word;
		else {
			s64 imm;
			int ret;
			if ((ret = get_src2_imm(syllable->ip, AW(src[1]), &imm)))
				return ret;
			syllable->mem_ext_ind = (s32)imm;
		}
	}
	return 0;
}

/**
 * dec_generic_alu() - Try setting operands for indeterminate operation.
 * @syllable: Syllable to decode.
 * @size: Requested size of operands.
 * @is_qp: 1 if qpword is requested.
 *
 * Operation has 4 places for src to be coded: 3 in als, 1 in ales.
 * Assume, all this places contain potential src and fill syllable->operands[].
 * We will definitely take dst for one of srcs, as it is coded same way, but
 * it won't affect correctness, dst is overwritten anyway.
 *
 * Return: 0 on success, !0 on failure.
 */
static int dec_generic_alu(syllable_t *syllable, register_size size, bool is_qp)
{
	instr_src_t src[4] = { syllable->instr_als.alf3.src1,
		       syllable->instr_als.alf3.src2,
		       syllable->instr_als.alf3.src3,
		       syllable->instr_ales.alef1.src3 };
	int cop = syllable->instr_als.alf3.cop;
	pr_debug_operation(
		"NoDEC: \"Decoding\" ALU als%d with cop=0x%x; ales=0x%x; "
		"src1/opce/reg#=0x%x; src2=0x%x; src3/dst/reg#=0x%x; "
		"ales_src=0x%x\n",
		syllable->als_pos, cop, syllable->instr_ales.word,
		AW(src[0]), AW(src[1]), AW(src[2]), AW(src[3]));
	for (int i = 0; i < 4; i++) {
		bool skip = 0;
		for (int j = 0; j < i; j++) {
			if (AW(src[j]) == AW(src[i]))
				skip = 1;
		}
		if (skip)
			continue;
		register_fill(&syllable->operands[i], AW(src[i]), size, is_qp);
		if (corrhistory_reg_is_already_corr(
			    &syllable->correction_history,
			    &syllable->operands[i]))
			syllable->operands[i].corrected = 1;
	}
	syllable->guessed_size = size;
	syllable->guessed_is_qp = is_qp;
	syllable->used_no_dec = true;
	return 0;
}

/**
 * dec_generic_alu_next() - Iterate through sizes via dec_generic_alu().
 * @syllable: Syllable to increase size and decode.
 *
 * Return: 0 on success, 1 on stop iteration, !0 on failure.
 */
static int dec_generic_alu_next(syllable_t *syllable)
{
	register_size size = syllable->guessed_size;
	/* the last one is pure qword (2 dNRs) */
	if (size == REG_SIZE_QWORD && !syllable->guessed_is_qp)
		return 1;

	unsigned long start_with_dxword =
		check_soft_pm_debug_feature(PM_SOFT_POLICY_NODEC_UNINIT_DXWORD);
	if (start_with_dxword && size == REG_SIZE_UNKNOWN) {
		size = REG_SIZE_WORD;
		pr_note_debug_correction(
			syllable->reports.notes_report,
			"ALS%d:\tUsed 'start from dxword' policy.\n",
			syllable->als_pos);
	}

	register_size new_size = REG_SIZE_UNKNOWN;
	bool new_is_qp = 0;
	if (CURRENT_ISET <= E2K_ISET_V4) {
		/* DWORD is missing, due to ext part in xNR is untagged.
		   We must correct whole xword not to get spoiled ext part. */
		new_size = (size == REG_SIZE_UNKNOWN) ? REG_SIZE_WORD :
			   (size == REG_SIZE_WORD)    ? REG_SIZE_XWORD :
			   (size == REG_SIZE_XWORD)   ? REG_SIZE_QWORD :
							REG_SIZE_UNKNOWN;
	} else {
		new_size = (size == REG_SIZE_UNKNOWN) ? REG_SIZE_WORD :
			   (size == REG_SIZE_WORD)    ? REG_SIZE_DWORD :
			   (size == REG_SIZE_DWORD)   ? REG_SIZE_XWORD :
			   (size == REG_SIZE_XWORD)   ? REG_SIZE_QWORD :
							REG_SIZE_QWORD;
		if (size == REG_SIZE_XWORD)
			new_is_qp = 1;
	}
	BUG_ON(new_size == REG_SIZE_UNKNOWN);

	/* Optimization: as we work with dwords from the very start,
	   value and tags are alredy dword, no need to re-read. */
	if (!start_with_dxword && size == REG_SIZE_WORD &&
	    new_size == REG_SIZE_DWORD) {
		for (int i = 0; i < 4; i++) {
			syllable->operands[i].size = new_size;
		}
		syllable->guessed_size = new_size;
		return 0;
	}

	for (int i = 0; i < 4; i++) {
		register_init(&syllable->operands[i], syllable->regs,
			      syllable->reports.notes_report);
	}
	return dec_generic_alu(syllable, new_size, new_is_qp);
}

/**
 * dec_generic_mem() - Try setting operands for indeterminate memory operation.
 * @syllable: Syllable to decode.
 *
 * Return: 0 on success, !0 on failure.
 */
static int dec_generic_mem(syllable_t *syllable, u8 format)
{
	instr_src_t descr_src = syllable->instr_als.alf3.src1;
	instr_src_t offset_src = syllable->instr_als.alf3.src2;
	int cop = syllable->instr_als.alf3.cop;
	pr_debug_operation(
		"NoDEC: \"Decoding\" MEM als%d with cop=0x%x; ales=0x%x; descr_src=0x%x; offset_src=0x%x\n",
		syllable->als_pos, cop, syllable->instr_ales.word,
		AW(descr_src), AW(offset_src));
	register_fill(&syllable->operands[0], AW(descr_src), REG_SIZE_QWORD, 0);
	if (corrhistory_reg_is_already_corr(&syllable->correction_history,
					    &syllable->operands[0]))
		syllable->operands[0].corrected = 1;

	register_fill(&syllable->operands[1], AW(offset_src), REG_SIZE_WORD, 0);
	syllable->mem_format = format;
	if (syllable->operands[1].type != REG_NONE) {
		syllable->mem_ext_ind = (s32)syllable->operands[1].value_s.word;
	} else {
		s64 imm;
		int ret;
		if ((ret = get_src2_imm(syllable->ip, AW(offset_src), &imm)))
			return ret;
		syllable->mem_ext_ind = (s32)imm;
	}
	syllable->used_no_dec = true;
	return 0;
}

/* simple decoder (end) */
/* ########################################################################## */
/* classificator (start) */

typedef struct {
	u8 cop_start;
	u8 cop_end;
	u8 ch_mask; /* bit-mask of channels: 0b1 for ch0/3; 0b100 for ch2/5 */
	syllable_operation_class op_class;
} class_block_t;

static inline int classify_is_in_block(const syllable_t *syllable,
				       const class_block_t *block)
{
	int als_eff_ch = syllable->als_pos > 2 ? syllable->als_pos - 3 :
						 syllable->als_pos;
	u8 syl_ch_mask = 1 << als_eff_ch;
	u8 cop = syllable->instr_als.alf3.cop;
	return (cop >= block->cop_start) && (cop <= block->cop_end) &&
	       (syl_ch_mask & block->ch_mask);
}

static inline int classify_is_last_block(const class_block_t *block)
{
	/* empty block */
	return block->op_class == SYL_OP_CLASS_NONE;
}

static const class_block_t CLASSIFY_SHORT_BLOCKS[] = {
	{ 0, 0, 0, SYL_OP_CLASS_NONE }
};

static const class_block_t CLASSIFY_EXT_BLOCKS[] = {
	/* aptoap(b) are not MEM, they are converting descrs:
	   {0x50, 0x51, 0b011, SYL_OP_CLASS_?}, */
	{ 0x52, 0x52, 0b001,
	  SYL_OP_CLASS_CUSTOM }, /* getva requires custom handling. */
	{ 0x68, 0x6b, 0b101, SYL_OP_CLASS_MEM }, /* loades, ldap* */
	{ 0x7a, 0x7a, 0b101, SYL_OP_CLASS_MEM }, /* loades, ldapq */
	{ 0x28, 0x2b, 0b100, SYL_OP_CLASS_MEM }, /* stores, stap* */
	{ 0x3a, 0x3a, 0b100, SYL_OP_CLASS_MEM }, /* stores, stapq */
	{ 0, 0, 0, SYL_OP_CLASS_NONE }
};

static const class_block_t CLASSIFY_EXT1_BLOCKS[] = { { 0, 0, 0,
							SYL_OP_CLASS_NONE } };

/**
 * classify_als() - Classifies als+ales syllable to alu/mem/etc. Sets op_class.
 * @syllable: Syllable to classify.
 *
 * This functionality is separated from decoder. Separation allows to work
 * with proper or generic decoders.
 * Classifier needs not that much information:
 * constraints for {channel, cop, ales}.
 *
 * Return: 0 on success, !0 on classification error.
 */
static int classify_als(syllable_t *syllable)
{
	/* setting ALU MUST NOT BREAK ANYTHING!!!! */
	const class_block_t *block = NULL;
	switch (syllable->instr_ales.alef1.opc2) {
	case 0:
		block = CLASSIFY_SHORT_BLOCKS;
		break;
	case EXT_ALES_OPC2:
		block = CLASSIFY_EXT_BLOCKS;
		break;
	case EXT1_ALES_OPC2:
		block = CLASSIFY_EXT1_BLOCKS;
		break;
	default:
		syllable->op_class = SYL_OP_CLASS_ALU;
		return 0;
	}
	while (!classify_is_last_block(block)) {
		if (classify_is_in_block(syllable, block)) {
			syllable->op_class = block->op_class;
			return 0;
		}
		block++;
	}
	syllable->op_class = SYL_OP_CLASS_ALU;
	return 0;
}

/* classificator (end) */
/* ########################################################################## */
/* statistics (start) */

struct soft_pm_stats {
	atomic_long_t total_excs;
	atomic_long_t uncorrected;
	atomic_long_t alu_diag;
	atomic_long_t alu_illegal;
	atomic_long_t mem_diag;
	atomic_long_t mem_illegal;
	atomic_long_t mem_fault;
	atomic_long_t ill_instr;
	atomic_long_t custom_diag;
	atomic_long_t custom_illegal;
};

static struct soft_pm_stats global_stats = {};

static inline void stats_inc_stat(atomic_long_t *stat_ptr)
{
	atomic_long_inc(stat_ptr);
}

static ssize_t stats_show(struct kobject *kobj, struct kobj_attribute *attr,
			  char *buf)
{
	return sysfs_emit(buf,
			  "SoftPM stats (write 'reset' to zero):\n"
			  "total exceptions:\t%ld\n"
			  "uncorrected exceptions:\t%ld\n"
			  "alu diag ops:\t%ld\n"
			  "alu illegal ops:\t%ld\n"
			  "mem diag ops:\t%ld\n"
			  "mem illegal ops:\t%ld\n"
			  "custom diag ops:\t%ld\n"
			  "custom illegal ops:\t%ld\n"
			  "array bounds faults:\t%ld\n"
			  "illegal instr addrs:\t%ld\n",
			  atomic_long_read(&global_stats.total_excs),
			  atomic_long_read(&global_stats.uncorrected),
			  atomic_long_read(&global_stats.alu_diag),
			  atomic_long_read(&global_stats.alu_illegal),
			  atomic_long_read(&global_stats.mem_diag),
			  atomic_long_read(&global_stats.mem_illegal),
			  atomic_long_read(&global_stats.custom_diag),
			  atomic_long_read(&global_stats.custom_illegal),
			  atomic_long_read(&global_stats.mem_fault),
			  atomic_long_read(&global_stats.ill_instr));
}

static ssize_t stats_reset(struct kobject *kobj, struct kobj_attribute *attr,
			   const char *buf, size_t count)
{
	if (sysfs_streq(buf, "reset")) {
		pr_info("Software PM: reset global_stats");
		atomic_long_set(&global_stats.total_excs, 0);
		atomic_long_set(&global_stats.uncorrected, 0);
		atomic_long_set(&global_stats.alu_diag, 0);
		atomic_long_set(&global_stats.alu_illegal, 0);
		atomic_long_set(&global_stats.mem_diag, 0);
		atomic_long_set(&global_stats.mem_illegal, 0);
		atomic_long_set(&global_stats.mem_fault, 0);
		atomic_long_set(&global_stats.ill_instr, 0);
	}
	return count;
}

static struct kobj_attribute soft_pm_stats_attr =
	__ATTR(global_stats, 0644, stats_show, stats_reset);

/* statistics (end) */
/* ########################################################################## */
/* faulty register handlers (start) */

/*
 * Faulty register handlers must follow the convention:
 * int correct_abstract(register_t *reg);
 * Returns 0 on success (even when everything is correct)
 * Returns !0 on errors
 * Sets reg->correction_occured on successful correction.
 */

/**
 * correct_uninit() - Correct uninit words of specified register.
 * @reg: Register_t object, containing filled register.
 * @allow_data_corruption: Flag to allow changing not only diagnostics.
 *
 * Allow_data_corruption is needed due to without decoder, we cannot
 * change non diagnostic words (with tags 1). Other tagged words
 * can store some meaningful (and used) data.
 * Luckily, we still can alter diags, as they are definitely not used
 * by a 'good' code. And softpm works in 'good' code assumption.
 *
 * Return: 0 on success, !0 on failure.
 */
static int correct_uninit(register_t *reg, int allow_data_corruption)
{
	/* init <=> tags are 0 for all corresponding words */
	u8 tags = register_get_tags(reg);
	if (!tags)
		return 0; /* all init */
	pr_debug_correction("Correcting uninit %s\n", reg->repr);

	union {
		e2k_qreg_t qword;
		e2k_xreg_t xword;
		e2k_reg_t word[4];
	} new_data;
	new_data.qword = reg->value_q;
	/* Init only words with non-zero tags. */
	for (int i = 0; tags; i++, tags >>= 2) {
		u8 word_tags = tags & 0b11;
		if (unlikely(word_tags & 0b10)) {
			/* TODO: general user-shown report for warnings, etc. */
			pr_note_debug_correction(
				reg->notes,
				"%s:\tCorrecable word%d tag = %d is not EW/DW when processing uninit! May spoil data! %s\n",
				reg->repr, i, word_tags,
				allow_data_corruption ?
					"Correcting!" :
					"Spoiling data forbidden!");
			if (!allow_data_corruption)
				return -EPERM;
			new_data.word[i].word = 0;
			continue;
		}
		if (unlikely(E2K_IS_DW(new_data.word[i].word, word_tags))) {
			if (check_soft_pm_debug_feature(
				    PM_SOFT_CONSTR_UNINIT_DW_AS_EW)) {
				pr_note_debug_correction(
					reg->notes,
					"%s:\tWord%d: DW treared as EW.\n",
					reg->repr, i);
			} else {
				char reg_val[REG_VAL_MAXLEN];
				register_sprint_val(reg, reg_val, 0);
				pr_note_debug_correction(
					reg->notes,
					"%s:\tTreating DW as EW is forbidden. Reg = %s\n",
					reg->repr, reg_val);
				return -EPERM;
			}
		}
		if (likely(word_tags))
			new_data.word[i].word = 0;
	}
	/* on <=V4 ext is untagged. If we are initing xreg, init it also. */
	if (CURRENT_ISET <= 4 && reg->size == REG_SIZE_XWORD)
		new_data.xword.ext = 0;

	register_set_new_value_q(reg, &new_data.qword, 0);

	int ret;
	if ((ret = register_store_new_value_tag(reg)))
		return ret;
	reg->correction_occured = 1;
	reg->corrected = 1;
	return 0;
}

static int _overflow_constr_same_page(u64 one_addr, u64 another_addr)
{
	u64 min_addr, max_addr;
	if (one_addr < another_addr) {
		min_addr = one_addr;
		max_addr = another_addr;
	} else {
		min_addr = another_addr;
		max_addr = one_addr;
	}
	u64 page_start = min_addr & PAGE_MASK;
	if ((max_addr >= page_start) && (max_addr < page_start + PAGE_SIZE))
		return 1;
	return 0;
}

static inline void _overflow_min_bounds(u64 target_addr, s32 extra_ind,
					u8 format, u64 *new_start, u64 *new_end)
{
	s32 req_end_offset = extra_ind < 0 ? -extra_ind : 0;
	s32 req_start_offset = extra_ind > 0 ? extra_ind : 0;
	u64 new_start_max, new_end_min;
	/* min possible to preserve logic:
	   if ap[extra_ind] is ok, then ap[0] is also.
	   In other worlds, base addr is valid. */
	new_start_max = target_addr - req_start_offset;
	new_end_min = target_addr + req_end_offset + format;
	pr_debug_correction("Calculated new_start_max = 0x%016llx, new_end_min = 0x%016llx\n",
			    new_start_max, new_end_min);
	*new_start = new_start_max;
	*new_end = new_end_min;
}

static inline void _overflow_expand_current(u64 cur_start, u64 cur_end,
					    u64 max_start, u64 min_end,
					    u64 *new_start, u64 *new_end)
{
	*new_start = cur_start < max_start ? cur_start : max_start;
	*new_end = cur_end > min_end ? cur_end : min_end;
	pr_debug_correction("Expanded new_start = 0x%016llx, new_end = 0x%016llx\n",
			    (u64)new_start, (u64)new_end);
}

static inline int _overflow_get_ranges(u64 addr, e2k_addr_t *min_base,
				       unsigned long *max_length,
				       struct pt_regs *regs)
{
	bool is_global = false, is_pl = false;
	int ret = 0;
	e2k_pl_t pl;
	ret = get_descriptor_ranges_on_global_or_pl(
		addr, min_base, max_length, &pl, &is_global, &is_pl, regs);
	if (!ret) {
		if (is_pl)
			return -ESRCH; /* overflow is impossible with PL */
		if (is_global)
			return 0;
	}

	ret = get_descriptor_ranges_on_stacks(
		addr, min_base, max_length,
		PM_SC_UNSAFE_UINT64_TO_PTR_WHOLE_STACK_MODE, regs);
	if (!ret)
		return 0;

	/* Looking for boundaries in MM: */
	ret = get_descriptor_ranges_on_mm(addr, min_base, max_length, regs);
	if (!ret)
		return 0;
	return -ESRCH;
}

/**
 * correct_overflow() - Increase descriptor size to bypass overflow.
 * @descr: The valid (with correct tags) descriptor.
 * @extra_ind: Extra index (src2), adds to descr.curptr, in bytes.
 * @format: ld/st operation format: byte to qword.
 *
 * Return: 0 on success, !0 on failure.
 */
static int correct_overflow(register_t *descr, s32 extra_ind, u8 format)
{
	u8 descr_tags = register_get_tags(descr);
	BUG_ON(descr->size != REG_SIZE_QWORD ||
	       descr_tags != ((E2K_AP_HI_ETAG << 4) | E2K_AP_LO_ETAG));
	unsigned long pm_mm_emptying =
		check_pm_sc_debug_feature(PM_MM_EMPTYING_FREED_POINTERS);
	unsigned long pm_mm_zeroing =
		check_pm_sc_debug_feature(PM_MM_ZEROING_FREED_POINTERS);
	unsigned long pm_mm_check =
		check_pm_sc_debug_feature(PM_MM_CHECK_4_DANGLING_POINTERS);
	if (unlikely(pm_mm_emptying || pm_mm_zeroing || pm_mm_check)) {
		pr_note_debug_correction(
			descr->notes,
			"Overflow handling requires all PM_MM_* env vars set to 0!\n");
		pr_note_debug_correction(descr->notes,
					 "PM_MM_ZEROING_FREED_POINTERS=%lu\n",
					 pm_mm_zeroing);
		pr_note_debug_correction(descr->notes,
					 "PM_MM_EMPTYING_FREED_POINTERS=%lu\n",
					 pm_mm_emptying);
		pr_note_debug_correction(
			descr->notes, "PM_MM_CHECK_4_DANGLING_POINTERS=%lu\n",
			pm_mm_check);
		return -EPERM;
	}

	/* TODO: Why AP_IND return u64? IND is signed for all V3-V7! */
	s64 curptr = (CURRENT_ISET < E2K_ISET_V7) ?
			     (s64)(s32)AP_IND(descr->value_p) :
			     (s64)AP_IND(descr->value_p);
	u64 size = AP_SIZE(descr->value_p);
	u64 base = AP_BASE(descr->value_p);

	pr_debug_correction("Correcting overflow %s%d; "
			    "size=%llu, ind=%lld+%d, format=%d\n",
			    descr->type & REG_R ? "r" : "g", descr->rnum_d,
			    size, curptr, extra_ind, (int)format);

	/* determine left or right overflow */
	u64 target_addr = (u64)AP_PTR(descr->value_p) + (s32)extra_ind;
#if 0
	/* hardware perfoms extra u32 conversion and it's target addr
	   differs from real one on left overflow. */
	u64 hw_target_addr = target_addr;
	if (CURRENT_ISET < E2K_ISET_V7)
		hw_target_addr = base + (u32)(curptr + extra_ind);
	if (hw_target_addr != target_addr) {
		pr_err("%s:%d : curptr+ind seem to overflow, aborting\n",
		       __FILE__, __LINE__);
		return -1;
	}
#endif
	u64 cur_end = base + size;
	u64 new_start = 0, new_end = 0;

	unsigned long max_target_length = 0, max_base_length = 0;
	e2k_addr_t min_target_base = 0, min_base_base = 0;
	int target_ret = _overflow_get_ranges(target_addr, &min_target_base,
					      &max_target_length, descr->regs);
	int base_ret = _overflow_get_ranges(base, &min_base_base,
					    &max_base_length, descr->regs);

	bool overflow_ok = true;
	bool curptr_overflow = false;

	if (unlikely(base_ret)) {
		if ((s64)target_addr < 0) {
			curptr_overflow = true;
			/* here we may encountered a strange thing.
			   (char*) NULL + (uintptr_t) stack_addr results in:
			   base = 0; size = 0; curptr < 0.
			   base + curptr < 0 !
			   all we have to do is recover stack addr upper part */
			u64 stack_top = get_stack_top(descr->regs);
			s32 dist_from_top =
				(stack_top & 0xFFFFFFFF) - (s32)target_addr;
			u64 fixed_target_addr = stack_top - dist_from_top;
			pr_note_debug_correction(
				descr->notes,
				"%s:\t(char*) NULL + (uintptr_t) stack_addr pattern detected\n"
				"\t\t\t\traw addr = 0x%016llx, fixed addr = 0x%016llx.\n",
				descr->repr, target_addr, fixed_target_addr);
			if (dist_from_top < 0) {
				pr_note_debug_correction(
					descr->notes,
					"%s:\tCritical! target_addr upper than stack top.\n",
					descr->repr);
				return -EFAULT;
			}
			target_addr = fixed_target_addr;
			target_ret = get_descriptor_ranges_on_stacks(
				target_addr, &min_target_base,
				&max_target_length,
				PM_SC_UNSAFE_UINT64_TO_PTR_WHOLE_STACK_MODE,
				descr->regs);
		} else if (!target_ret) {
			pr_note_debug_correction(
				descr->notes,
				"%s:\t(char*) NULL + (uintptr_t) heap/global_addr pattern detected.\n",
				descr->repr);
		}
		if (target_ret)
			overflow_ok = false;
		/* this cases expantion has no meaning */
		_overflow_min_bounds(target_addr, extra_ind, format, &new_start,
				     &new_end);
	} else {
		bool ranges_same = (min_target_base == min_base_base) &&
				   (max_target_length == max_base_length);
		if (!ranges_same) {
			pr_note_debug_correction(
				descr->notes,
				"%s:\tBase and target addr are from different areas!\n",
				descr->repr);
			overflow_ok = false;
		}
		if (target_addr + format > cur_end) {
			pr_note_debug_correction(
				descr->notes, "%s:\tRight overflow detected.\n",
				descr->repr);
		} else if (target_addr < base) {
			pr_note_debug_correction(
				descr->notes, "%s:\tLeft overflow detected.\n",
				descr->repr);
		} else {
			/* no overflow. Possible when iterating over formats */
			return 0;
		}
		_overflow_min_bounds(target_addr, extra_ind, format, &new_start,
				     &new_end);
		if (1 /* expand current */) {
			_overflow_expand_current(base, cur_end, new_start,
						 new_end, &new_start, &new_end);
		}
	}

	if (!overflow_ok) {
		pr_note_debug_correction(descr->notes,
					 "%s:\tFailed to find bounds for target addr = 0x%016llx.\n",
					 descr->repr, target_addr);
		return -ESRCH;
	}

	if (new_start < min_target_base ||
	    new_end >= min_target_base + max_target_length) {
		pr_note_debug_correction(
			descr->notes,
			"%s:\tRequired bounds are not in a continuous slice: start = 0x%016llx; end = 0x%016llx.\n",
			descr->repr, new_start, new_end);
		return -EFAULT;
	}

	if (check_soft_pm_debug_feature(PM_SOFT_POLICY_MAX_ARRAY_BOUNDS)) {
		/* VMA borders - MAX */
		new_start = (u64)min_target_base;
		new_end = new_start + max_target_length;
		pr_note_debug_correction(
			descr->notes, "%s:\tUsed 'max array bounds' policy.\n",
			descr->repr);
	}

	/* size_diff constraints */
	if (check_soft_pm_debug_feature(PM_SOFT_CONSTR_MEM_SAME_PAGE) &&
	    !_overflow_constr_same_page(new_start, new_end)) {
		pr_note_debug_correction(
			descr->notes,
			"%s:\tFailed same_page constraint: start = 0x%016llx; end = 0x%016llx.\n",
			descr->repr, new_start, new_end);
		return -EFAULT;
	}

	e2k_ptr_t new_val = MAKE_AP_RW(new_start, new_end - new_start,
				   target_addr - new_start - extra_ind,
				   AP_RW(descr->value_p));

	register_set_new_value_q(descr, (e2k_qreg_t *)&new_val, descr->tags);
	BUG_ON(!curptr_overflow &&
	       (AP_PTR(descr->value_p) != AP_PTR(descr->new_value_p)));
	int ret;
	if ((ret = register_store_new_value_tag(descr)))
		return ret;
	descr->correction_occured = 1;
	descr->corrected = 1;
	return 0;
}

/**
 * correct_descr_tags() - Recover descr with bad tags.
 * @descr: The descriptor to recover.
 *
 * Try recovering untagged descriptor.
 * The descriptor must be zero-tagged (otherwize it's a real error).
 * TODO: ro/wo tags when needed, by far rw only.
 *
 * Return: 0 on success, !0 on failure.
 */
static int correct_descr_tags(register_t *descr, s32 extra_ind, u8 format)
{
	u8 tags = register_get_tags(descr);
	u64 size = AP_SIZE(descr->value_p);
	u64 curptr = AP_IND(descr->value_p);
	u64 base = AP_BASE(descr->value_p);
	u8 itag = AP_ITAG(descr->value_p);
	u8 rw = AP_RW(descr->value_p);
	BUG_ON(descr->size != REG_SIZE_QWORD);

	e2k_ptr_t new_val = {};
	u8 new_tags = 0;
	char reg_val[REG_VAL_MAXLEN];

	register_sprint_val(descr, reg_val, 0);
	pr_debug_correction(
		"Correcting descriptor tags %s%d = %s\n",
		descr->type & REG_R ? "r" : "g", descr->rnum_d, reg_val);

	if (tags == ((E2K_AP_HI_ETAG << 4) | E2K_AP_LO_ETAG))
		return 0;
	bool is_broken_ap = 1;
	for (u8 tg = tags; tg != 0; tg >>= 2) {
		u8 word_tag = tg & 0b11;
		is_broken_ap = is_broken_ap &&
			       ((word_tag == 0b00) || (word_tag == 0b11));
	}
	if (!is_broken_ap) {
		pr_note_debug_correction(descr->notes,
					 "%s:\tNot a broken descriptor.\n",
					 descr->repr);
		goto err;
	}
	if (tags && !check_soft_pm_debug_feature(
			    PM_SOFT_CONSTR_TRUST_PARTIALLY_BROKEN_DESCRS)) {
		pr_note_debug_correction(
			descr->notes,
			"%s:\tDescriptor tags are not zero: 0x%x\n",
			descr->repr, tags);
		goto err;
	}

	if (size == 0 && itag == 0 && rw == 0) {
		pr_debug_correction(
			"Size, itag and rw are 0. Seems like convertion from integer.\n"
		);
		new_val = MAKE_AP_RW(base, size, curptr, E2K_AP_RW);
		new_tags = ((E2K_AP_HI_ETAG << 4) | E2K_AP_LO_ETAG);
	} else if (size != 0 && itag == E2K_AP_ITAG && rw != 0) {
		pr_debug_correction(
			"Non-zero size. Seems like lost tags (i.e. due to bytewize copy).\n");
		if (curptr >= size)
			pr_debug_correction(
				"Untagged descriptor is also overfilled.\n");
		new_val = MAKE_AP_RW(base, size, curptr, rw);
		new_tags = ((E2K_AP_HI_ETAG << 4) | E2K_AP_LO_ETAG);
	} else {
		goto err;
	}

	register_set_new_value_q(descr, (e2k_qreg_t *)&new_val, new_tags);
	int ret;
	if ((ret = register_store_new_value_tag(descr)))
		return ret;
	descr->correction_occured = 1;
	descr->corrected = 1;
	if (!size) {
		/* with zero size we will definitely fault then */
		e2k_qreg_t orig_val = descr->value_q;
		u8 orig_tags = descr->tags;
		descr->value_p = descr->new_value_p;
		descr->tags = descr->new_tags;
		/* Ignore return value. Use only for stats inc.
		   We are already successfully done.
		   If there is a problem, fault will be triggered and
		   correct signal generated. */
		int ret = correct_overflow(descr, extra_ind, format);
		if (!ret)
			stats_inc_stat(&global_stats.mem_fault);
		/* recover orig for proper correction report */
		descr->value_q = orig_val;
		descr->tags = orig_tags;
		pr_note_debug_correction(
			descr->notes,
			"%s:\tCorrected fault just after tag recovery of zero-sized descriptor (int to ptr conversion).\n",
			descr->repr);
	}
	return 0;
err:
	register_sprint_val(descr, reg_val, 0);
	pr_note_debug_correction(descr->notes,
				 "%s:\tUnrecoverable descriptor: %s; size == %llu, itag = %d, rw = %d.\n",
				 descr->repr, reg_val, size, itag, rw);
	return -EINVAL;
}

/**
 * correct_cuir() - Apply correction to CU index on call via uintptr_t.
 * @regs: Pointer to pt_regs structure.
 *
 * Return: 0 on success, -ESRCH on failure.
 */
static int correct_cuir(struct pt_regs *regs)
{
	u64 ip = instruction_pointer(regs);
	int cui;
	e2k_cute_t cute;
	int ret;
	if (unlikely((ret = get_cute_cui_by_func_addr(ip, &cute, &cui, regs))))
		return ret;
	e2k_cuir_t new_cuir;
	AW(new_cuir) = regs->crs.cr1.cuir;
	new_cuir.index = cui;
	/* will re-read ind, but we already fixed ind here: */
	/* new_cuir.checkup = 0; */
	regs->crs.cr1.cuir = AW(new_cuir);
	return 0;
}

/* faulty register handlers (end) */
/* ########################################################################## */
/* faulty syllable handlers (start) */

static inline int _illegal_als_apply_alu_correction(syllable_t *syllable)
{
	int ret = 0;
	for (int i = 0; i < 4; i++) {
		if (register_is_filled(&syllable->operands[i])) {
			if (unlikely(ret = correct_uninit(
					     &syllable->operands[i], 0))) {
				/* allow wrong tagged words (dest, fake srcs) */
				if (ret == -EPERM)
					continue;
				return ret;
			}
		}
	}
	return 0;
}

static inline int _illegal_als_apply_mem_correction(syllable_t *syllable)
{
	BUG_ON(syllable->op_class != SYL_OP_CLASS_MEM);
	return correct_descr_tags(&syllable->operands[0], syllable->mem_ext_ind,
				  syllable->mem_format);
}

static inline int _illegal_als_apply_custom_correction(syllable_t *syllable)
{
	int ret = 0;
	BUG_ON(syllable->op_class != SYL_OP_CLASS_CUSTOM);
	switch (syllable->instr_ales.alef1.opc2) {
	case 0:
		break;
	case EXT_ALES_OPC2:
		switch (syllable->instr_als.alf2.cop) {
		case 0x52: /* GETVA */
			ret = 0;
			if (register_is_uninit(&syllable->operands[0])) {
				ret = correct_uninit(&syllable->operands[0], 0);
			} else {
				ret = correct_descr_tags(&syllable->operands[0],
							 syllable->mem_ext_ind,
							 syllable->mem_format);
			}
			return ret;
		default:
			break;
		};
	default:
		break;
	};
	pr_note_debug_correction(
		syllable->reports.notes_report,
		"ALS%d:\tDon't know how how to correct custom operation.\n",
		syllable->als_pos);
	return -EINVAL;
}

static inline int _als_check_diag_stats(syllable_t *syllable)
{
	switch (syllable->op_class) {
	case SYL_OP_CLASS_ALU:
		if (unlikely(syllable->exc_cause_num ==
			     E2K_EXC_DIAG_OPERAND_IND))
			stats_inc_stat(&global_stats.alu_diag);
		else
			stats_inc_stat(&global_stats.alu_illegal);
		break;
	case SYL_OP_CLASS_MEM:
		if (unlikely(syllable->exc_cause_num ==
			     E2K_EXC_DIAG_OPERAND_IND))
			stats_inc_stat(&global_stats.mem_diag);
		else
			stats_inc_stat(&global_stats.mem_illegal);
		break;
	case SYL_OP_CLASS_CUSTOM:
		if (unlikely(syllable->exc_cause_num ==
			     E2K_EXC_DIAG_OPERAND_IND))
			stats_inc_stat(&global_stats.custom_diag);
		else
			stats_inc_stat(&global_stats.custom_illegal);
		break;
	default:
		BUG();
		break;
	}
	if (unlikely(syllable->exc_cause_num == E2K_EXC_DIAG_OPERAND_IND &&
		     !check_soft_pm_debug_feature(
			     PM_SOFT_CONSTR_ALLOW_DIAG_OPERAND))) {
		pr_note_debug_operation(syllable->reports.notes_report,
					"Handling diag operand not allowed.\n");
		return -EPERM;
	}
	return 0;
}

static int handle_illegal_diag_als(syllable_t *syllable)
{
	int ret = 0;
	if ((ret = classify_als(syllable)))
		return ret;

	if ((ret = _als_check_diag_stats(syllable)))
		return ret;

	if (!dec_als(syllable)) {
		switch (syllable->op_class) {
		case SYL_OP_CLASS_ALU:
			return _illegal_als_apply_alu_correction(syllable);
			break;
		case SYL_OP_CLASS_MEM:
			return _illegal_als_apply_mem_correction(syllable);
			break;
		case SYL_OP_CLASS_CUSTOM:
			return _illegal_als_apply_custom_correction(syllable);
		default:
			BUG();
		}
	}
	pr_debug_correction("Trying no-dec correction.\n");
	switch (syllable->op_class) {
	case SYL_OP_CLASS_ALU:
		while (!dec_generic_alu_next(syllable)) {
			pr_debug_correction(
				"No-dec ALU correction of size %d\n",
				syllable->guessed_size);
			if ((ret = _illegal_als_apply_alu_correction(syllable)))
				return ret;
			/* check if correction really occured.
			   yes? great! returning (maybe fail later)
			   no? continue with bigger size. */
			if (syllable_is_corrected(syllable))
				return 0;
		}
		break;
	case SYL_OP_CLASS_MEM:
		if ((ret = dec_generic_mem(syllable, E2K_SIZE_BYTE)))
			return ret;
		return _illegal_als_apply_mem_correction(syllable);
	default:
		BUG();
	}
	return -EIO;
}

static int handle_fault_als(syllable_t *syllable)
{
	int ret = 0;
	if ((ret = classify_als(syllable)))
		return ret;
	if (syllable->op_class != SYL_OP_CLASS_MEM) {
		pr_debug_operation(
			"Fault handler called for non-memory operation. Cop=0x%x, ch=%d, ales_opc2=0x%x not classified or another exc triggered besides array_bounds.\n",
			syllable->instr_als.alf2.cop, syllable->als_pos,
			syllable->instr_ales.alef1.opc2);
		return -EINVAL;
	}
	stats_inc_stat(&global_stats.mem_fault);
	if (!dec_als(syllable)) {
		/* decoder takes responsibility for the operands */
		return correct_overflow(&syllable->operands[0],
					syllable->mem_ext_ind,
					syllable->mem_format);
	}
	pr_debug_correction("Trying no-dec correction.\n");

	u8 all_formats[] = { E2K_SIZE_BYTE,  E2K_SIZE_HALF,  E2K_SIZE_WORD,
			     E2K_SIZE_DWORD, E2K_SIZE_QWORD, 0 };
	u8 qword_formats[] = { E2K_SIZE_QWORD, 0 };
	const u8 *formats = all_formats;
	if (check_soft_pm_debug_feature(PM_SOFT_POLICY_NODEC_MEM_QWORD) &&
	    !check_soft_pm_debug_feature(PM_SOFT_POLICY_MAX_ARRAY_BOUNDS)) {
		/* MEM_QWORD has no effect when MAX_BOUNDS is enabled.
		   Suppress note. */
		formats = qword_formats;
		pr_note_debug_correction(syllable->reports.notes_report,
					 "ALS%d:\tUsed 'mem qword' policy.\n",
					 syllable->als_pos);
	}
	if ((ret = dec_generic_mem(syllable, formats[0])))
		return ret;
	for (int i = 0; formats[i] != 0; i++) {
		syllable->mem_format = formats[i];
		pr_debug_correction("No-dec MEM correction of format %d\n",
				    syllable->mem_format);
		if ((ret = correct_overflow(&syllable->operands[0],
					    syllable->mem_ext_ind,
					    syllable->mem_format)))
			return ret;
		if (syllable_is_corrected(syllable))
			return 0;
	}

	return -EIO;
}

/* faulty syllable handlers (end) */
/* ########################################################################## */
/* custom exception handlers (start) */

static int handler_launcher(struct pt_regs *regs, int exc_ind,
			    const char *exc_name, int (*handler)(syllable_t *))
{
	if (!softpm_suitable(regs))
		return -ENOTSUPP;
	stats_inc_stat(&global_stats.total_excs);
	/* ignore fault/illegal(diag)_op/ when illegal_instr */
	if (regs->trap->TIRs[0].exc & (1 << E2K_EXC_ILLEGAL_INSTR_ADDR_IND)) {
		return 0;
	}

	int corrected = 0;
	unsigned long print_on_fail_only =
		check_soft_pm_debug_feature(PM_SOFT_PRINT_ON_CORR_FAIL_ONLY);

	syllable_t current_syllable;
	syllable_init(&current_syllable, regs, exc_ind);
	report_preamble(&current_syllable.reports, regs, exc_ind, exc_name);

	int prev_als_pos = -1;
	while (syllable_fill_next_faulty(&current_syllable, &prev_als_pos)
		       ->type != SYL_NONE) {
		switch (current_syllable.type) {
		case SYL_ALS:
			pr_debug_operation("Found ALS%d faulty syllable.\n",
					   current_syllable.als_pos);
			if (!handler(&current_syllable)) {
				if (syllable_is_corrected(&current_syllable))
					corrected++;
			}
			break;
		default:
			pr_err("%s:%d : By far unsupported faulty syllable type: %s\n",
			       __FILE__, __LINE__,
			       syllable_type_reprs[(int)current_syllable.type]);
			break;
		}
		if (!print_on_fail_only || (print_on_fail_only && !corrected)) {
			syllable_append_report(&current_syllable);
		}
		syllable_append_correction_history(&current_syllable);
		syllable_init_keep_history(&current_syllable, regs, exc_ind);
	}
	if (!print_on_fail_only || (print_on_fail_only && !corrected))
		print_report(&current_syllable.reports);
	syllable_drop(&current_syllable);
	if (corrected) {
		return 0;
	}
	stats_inc_stat(&global_stats.uncorrected);
	return -EIO;
}

static int diag_operand_soft_pm(struct pt_regs *regs, const char *exc_name)
{
	/* diag seems to be impossible for pm no spec.
	   DT is a result of spec. uninit/no tag will be illegal_operand.\
	   However, compiler sets extend operations to spec.
	   Resulting in uinint small -> diad big. In this case diag can be
	   treated as uninit. This is configurable. */
	return handler_launcher(regs, E2K_EXC_DIAG_OPERAND_IND, exc_name,
				handle_illegal_diag_als);
}

static int illegal_operand_soft_pm(struct pt_regs *regs, const char *exc_name)
{
	return handler_launcher(regs, E2K_EXC_ILLEGAL_OPERAND_IND, exc_name,
				handle_illegal_diag_als);
}

static int array_bounds_soft_pm(struct pt_regs *regs, const char *exc_name)
{
	return handler_launcher(regs, E2K_EXC_ARRAY_BOUNDS_IND, exc_name,
				handle_fault_als);
}

static int illegal_instr_addr_soft_pm(struct pt_regs *regs,
				      const char *exc_name)
{
	int ret = 0;
	if (!softpm_suitable(regs)) {
		return -ENOTSUPP;
	}
	stats_inc_stat(&global_stats.total_excs);
	stats_inc_stat(&global_stats.ill_instr);
	struct report_bufs reports;
	report_bufs_init(&reports);
	report_preamble(&reports, regs, E2K_EXC_ILLEGAL_INSTR_ADDR_IND,
			exc_name);
	e2k_cuir_t cuir, new_cuir;
	AW(cuir) = regs->crs.cr1.cuir;
	pr_debug_correction("CUIR = 0x%x\n", AW(cuir));
	ret = correct_cuir(regs);
	AW(new_cuir) = regs->crs.cr1.cuir;
	pr_debug_correction("new CUIR = 0x%x\n", AW(new_cuir));
	if (ret || AW(new_cuir) == AW(cuir)) {
		pr_note_debug_correction(reports.notes_report,
					 "Can't correct cuir.ind = 0x%x\n",
					 cuir.index);
		if (!ret)
			ret = -1;
		goto fin;
	}
	CORRECTION_BUF_PRINTF(&reports,
			      "\t\tcuir: {ind = 0x%x, ic = 0x%x} -> {ind = 0x%x, ic = 0x%x}\n",
			      cuir.index, cuir.checkup, new_cuir.index,
			      new_cuir.checkup);
fin:
	print_report(&reports);
	report_bufs_drop(&reports);
	return ret;
}

/* custom exception handlers (end) */
/* ########################################################################## */
/* sysctl configuration (start)*/

/**
 * struct soft_pm_controls - Underlying struct for sysctl.d/e2k_soft_pm.conf.
 * @admin_allowed_mask: Mask of ENV controlled allowed options.
 * @admin_forced_mask: Mask of ENV controlled forced options.
 * @default_mask: Allows to override settings for SoftPM.
 *
 * The contents of the /etc/sysctl.d/e2k_soft_pm.conf file may look like this:
 *
 * #############################################################################
 * # Controls of the "Soft PM" Secure (Protected) Computing interrupts handler.
 * # Normally Soft PM is configures through env variables PM_SOFT_...
 * # There are three masks here, allowing to set constraints on Soft PM
 * # capabilities globally:
 * # - admin_allowed_mask: Mask of ENV controlled allowed options.
 * #                       If an option not set here, it will be disabled
 * #                       notwithstanding ENV, default and forced settings.
 * # - admin_forced_mask: Mask of options that are forced notwithstanding ENV.
 * # - default_mask: Sets default options set. Must be set to desired value
 * #                 (default 0xD) when using sysctl.d.
 * #
 * # How to set mask:
 * #     PM_SOFT_PRINT_NOTES 0x00001
 * #     PM_SOFT_DEBUG_REG 0x00002
 * #     PM_SOFT_PRINT_CORRECTION 0x00004
 * #     PM_SOFT_DEBUG_CORRECTION 0x00008
 * #     PM_SOFT_PRINT_OPERATION 0x00010
 * #     PM_SOFT_DEBUG_OPERATION 0x00020
 * #     PM_SOFT_PRINT_TO_STDERR 0x00040
 * #     PM_SOFT_GLOBAL_ENABLE 0x00080
 * #     PM_SOFT_PRINT_ON_CORR_FAIL_ONLY 0x00100
 * #     PM_SOFT_PRINT_FULL_CMDLINE 0x00200
 * #     PM_SOFT_POLICY_NODEC_UNINIT_DXWORD 0x00400
 * #     PM_SOFT_POLICY_MAX_ARRAY_BOUNDS 0x00800
 * #     PM_SOFT_POLICY_NODEC_MEM_QWORD 0x01000
 * #     PM_SOFT_CONSTR_MEM_SAME_PAGE 0x02000
 * #     PM_SOFT_CONSTR_UNINIT_DW_AS_EW 0x04000
 * #     PM_SOFT_CONSTR_ALLOW_DIAG_OPERAND 0x08000
 * #     PM_SOFT_CONSTR_TRUST_PARTIALLY_BROKEN_DESCRS 0x10000
 * ##############################################################################
 *
 * kernel.e2k.soft_pm.admin_allowed_mask = 0xFFFFF
 * kernel.e2k.soft_pm.admin_forced_mask = 0x00000
 * kernel.e2k.soft_pm.default_mask = 0x0000D
 *
 * ##############################################################################
 *
 * To apply sysctl config on the module load, create udev rule with following
 * contents:
 * ACTION=="add", SUBSYSTEM=="module", KERNEL=="soft_pm",
 *     RUN+="/usr/sbin/sysctl -p /etc/sysctl.d/e2k_soft_pm.conf"
 */
struct soft_pm_controls_struct {
	int admin_allowed_mask;
	int admin_forced_mask;
	int default_mask;
};

struct soft_pm_controls_struct soft_pm_controls;

static inline int get_sysctld_soft_pm_admin_allowed_mask(void)
{
	return soft_pm_controls.admin_allowed_mask;
}

static inline int get_sysctld_soft_pm_admin_forced_mask(void)
{
	return soft_pm_controls.admin_forced_mask;
}

static inline int get_sysctld_soft_pm_default_mask(void)
{
	return soft_pm_controls.default_mask;
}

static inline int e2k_sysctld_soft_pm_controls_enabled(void)
{
	return soft_pm_controls.admin_allowed_mask != 0 ||
	       soft_pm_controls.admin_forced_mask != 0 ||
	       soft_pm_controls.default_mask != 0;
}

static struct ctl_table e2k_soft_pm_table[] = {
	{
		.procname   = "admin_allowed_mask",
		.data       = &soft_pm_controls.admin_allowed_mask,
		.maxlen     = sizeof(soft_pm_controls.admin_allowed_mask),
		.mode       = 0644,
		.proc_handler = proc_douintvec_minmax,
	},
	{
		.procname   = "admin_forced_mask",
		.data       = &soft_pm_controls.admin_forced_mask,
		.maxlen     = sizeof(soft_pm_controls.admin_forced_mask),
		.mode       = 0644,
		.proc_handler = proc_douintvec_minmax,
	},
	{
		.procname   = "default_mask",
		.data       = &soft_pm_controls.default_mask,
		.maxlen     = sizeof(soft_pm_controls.default_mask),
		.mode       = 0644,
		.proc_handler = proc_douintvec_minmax,
	},
	{ }
};

static struct ctl_path e2k_soft_pm_sysctl_path[] = {
	{ .procname = "kernel", },
	{ .procname = "e2k", },
	{ .procname = "soft_pm", },
	{ }
};

static struct ctl_table_header *e2k_soft_pm_table_hdr = NULL;

static int __init e2k_soft_pm_init_sysctl(void)
{
	e2k_soft_pm_table_hdr = register_sysctl_paths(e2k_soft_pm_sysctl_path,
						      e2k_soft_pm_table);
	if (!e2k_soft_pm_table_hdr)
		return -EFAULT;
	else
		kmemleak_not_leak(e2k_soft_pm_table_hdr);

	return 0;
}

static int __exit e2k_soft_pm_remove_sysctl(void)
{
	if (e2k_soft_pm_table_hdr)
		unregister_sysctl_table(e2k_soft_pm_table_hdr);
	return 0;
}

void print_sysctld_soft_pm_controls(void)
{
	printk(KERN_INFO "E2K/SCM Soft‑PM controls setup:\n");
	printk(KERN_INFO "\tadmin_allowed_mask    = %u\n",
	       soft_pm_controls.admin_allowed_mask);
	printk(KERN_INFO "\tadmin_forced_mask     = %u\n",
	       soft_pm_controls.admin_forced_mask);
	printk(KERN_INFO "\tdefault_mask    = %u\n",
	       soft_pm_controls.default_mask);
}

#define PRINT_TO_STDERR(str) \
	protected_mode_write_to_current_stderr((str), strlen(str))

#define CHECK_SOFT_PM_MASK(mask_name) \
do { \
	mask = protected_mode_check_env_debug_mask(#mask_name, 48, mask_name); \
	if (mask) { \
		if (mask & mask_name) { /* positive mask */ \
			if (mask & allowed_mask) \
				context->pm_soft_options_mask |= mask; \
			else \
				PRINT_TO_STDERR("[SoftPM] enabling " #mask_name \
						" forbidden via sysctl.\n"); \
		} else { /* negative mask */ \
			if (~mask & forced_mask) \
				PRINT_TO_STDERR("[SoftPM] disabling " #mask_name \
						" forbidden via sysctl.\n"); \
			else \
				context->pm_soft_options_mask &= mask; \
		} \
	} \
} while (0)

/* Fix due to libc fault RM#18187 */
#define CHECK_DEBUG_MASK(mask_name) \
do { \
	mask = protected_mode_check_env_debug_mask(#mask_name, 48, mask_name); \
	if (mask) { \
		if (mask & mask_name) /* positive mask */ \
			context->pm_sc_debug_mode |= mask; \
		else /* negative mask */ \
			context->pm_sc_debug_mode &= mask; \
	} \
} while (0)

/* Fix due to libc fault RM#18187 */
static inline
void reset_PM_MM_default_setup(mm_context_t *context, int save_flag)
{
	if (context->pm_sc_debug_mode & PM_MM_CHECK_4_DANGLING_POINTERS
			&& save_flag != PM_MM_CHECK_4_DANGLING_POINTERS)
		context->pm_sc_debug_mode &= ~PM_MM_CHECK_4_DANGLING_POINTERS;
	if (context->pm_sc_debug_mode & PM_MM_ZEROING_FREED_POINTERS
			&& save_flag != PM_MM_ZEROING_FREED_POINTERS)
		context->pm_sc_debug_mode &= ~PM_MM_ZEROING_FREED_POINTERS;
	if (context->pm_sc_debug_mode & PM_MM_EMPTYING_FREED_POINTERS
			&& save_flag != PM_MM_EMPTYING_FREED_POINTERS)
		context->pm_sc_debug_mode &= ~PM_MM_EMPTYING_FREED_POINTERS;
}

static void arch_init_soft_pm_mode(void *context_ptr)
{
	mm_context_t *context = (mm_context_t *)context_ptr;
	if (!context)
		context = &current->mm->context;
	unsigned long mask = 0;
	unsigned int allowed_mask = get_sysctld_soft_pm_admin_allowed_mask();
	unsigned int forced_mask = get_sysctld_soft_pm_admin_forced_mask();
	unsigned int default_mask = get_sysctld_soft_pm_default_mask();
	if (!e2k_sysctld_soft_pm_controls_enabled()) {
		/* allow everything when no sysctl.d config */
		PRINT_TO_STDERR("[SoftPM] No sysctl config found.\n");
	}
	if (~allowed_mask & default_mask)
		PRINT_TO_STDERR("[SoftPM] Allow mask overrides default one.\n");
	context->pm_soft_options_mask = default_mask & allowed_mask;
	if (allowed_mask & forced_mask)
		PRINT_TO_STDERR("[SoftPM] Allow mask overrides force one.\n");
	context->pm_soft_options_mask |= forced_mask & allowed_mask;
	CHECK_SOFT_PM_MASK(PM_SOFT_DEBUG_ALL);
	CHECK_SOFT_PM_MASK(PM_SOFT_PRINT_USERFRIENDLY);
	CHECK_SOFT_PM_MASK(PM_SOFT_PRINT_NOTES);
	CHECK_SOFT_PM_MASK(PM_SOFT_DEBUG_REG);
	CHECK_SOFT_PM_MASK(PM_SOFT_PRINT_CORRECTION);
	CHECK_SOFT_PM_MASK(PM_SOFT_DEBUG_CORRECTION);
	CHECK_SOFT_PM_MASK(PM_SOFT_PRINT_OPERATION);
	CHECK_SOFT_PM_MASK(PM_SOFT_DEBUG_OPERATION);
	CHECK_SOFT_PM_MASK(PM_SOFT_PRINT_TO_STDERR);
	CHECK_SOFT_PM_MASK(PM_SOFT_GLOBAL_ENABLE);
	CHECK_SOFT_PM_MASK(PM_SOFT_POLICY_MAX_ARRAY_BOUNDS);
	CHECK_SOFT_PM_MASK(PM_SOFT_POLICY_NODEC_MEM_QWORD);
	CHECK_SOFT_PM_MASK(PM_SOFT_POLICY_NODEC_UNINIT_DXWORD);
	CHECK_SOFT_PM_MASK(PM_SOFT_PRINT_ON_CORR_FAIL_ONLY);
	CHECK_SOFT_PM_MASK(PM_SOFT_PRINT_FULL_CMDLINE);
	CHECK_SOFT_PM_MASK(PM_SOFT_CONSTR_MEM_SAME_PAGE);
	CHECK_SOFT_PM_MASK(PM_SOFT_CONSTR_UNINIT_DW_AS_EW);
	CHECK_SOFT_PM_MASK(PM_SOFT_CONSTR_ALLOW_DIAG_OPERAND);
	CHECK_SOFT_PM_MASK(PM_SOFT_CONSTR_TRUST_PARTIALLY_BROKEN_DESCRS);

	/* Fix due to libc fault RM#18187 */
	/* SoftPM may need all PM_MM_* set to 0. But currently it shall be */
	/* forbidden due to libc bug. */
	int reset_PM_MM_default = 1;
	CHECK_DEBUG_MASK(PM_MM_CHECK_4_DANGLING_POINTERS);
	if (mask) {
		reset_PM_MM_default_setup(context, PM_MM_CHECK_4_DANGLING_POINTERS);
		reset_PM_MM_default = 0;
	}
	CHECK_DEBUG_MASK(PM_MM_ZEROING_FREED_POINTERS);
	if (mask && reset_PM_MM_default) {
		reset_PM_MM_default_setup(context, PM_MM_ZEROING_FREED_POINTERS);
		reset_PM_MM_default = 0;
	}
	CHECK_DEBUG_MASK(PM_MM_EMPTYING_FREED_POINTERS);
	if (mask && reset_PM_MM_default) {
		reset_PM_MM_default_setup(context, PM_MM_EMPTYING_FREED_POINTERS);
		reset_PM_MM_default = 0;
	}
	if ((context->pm_sc_debug_mode & PM_MM_FREE_PTR_MODE_MASK) == 0) {
		if (check_soft_pm_debug_feature(PM_SOFT_GLOBAL_ENABLE)) {
			PRINT_TO_STDERR(
				"[SoftPM] Erasing of freed memory is blocked in this run.\n"
			);
		} else {
			context->pm_sc_debug_mode |= PM_MM_DEFAULT_FREE_PTR_MODE; /* RM-18187 */
		}
	}
}

/* sysctl configuration (end) */
/* ########################################################################## */
/* module init/exit (start) */

static struct kobject *soft_pm_sysfs_dir;

static int soft_pm_init(void)
{
	if (CURRENT_ISET >= 7) {
		pr_err("[SoftPM] not yet ported on V7+.");
		return -ENODEV;
	}
	fixed_len_buf_slab_alloc =
		kmem_cache_create("fixed_len_bufs_allocator",
				  sizeof(struct fixed_len_buf), 0, 0, NULL);
	if (!fixed_len_buf_slab_alloc) {
		pr_err("%s:%d : Error creating slab allocator", __FILE__,
		       __LINE__);
		return -ENOMEM;
	}
	soft_pm_sysfs_dir = kobject_create_and_add("soft_pm", kernel_kobj);
	if (!soft_pm_sysfs_dir) {
		pr_err("%s:%d : Error creating sysfs dir", __FILE__, __LINE__);
		return -ENOMEM;
	}
	if (sysfs_create_file(soft_pm_sysfs_dir, &soft_pm_stats_attr.attr)) {
		pr_err("%s:%d : Error creating sysfs fils", __FILE__, __LINE__);
		return -ENOMEM;
	}

	pr_info("Software PM init: setting handlers...");
	int ret;
	if ((ret = e2k_soft_pm_init_sysctl())) {
		pr_err("%s:%d : Error setuping sysctl config for soft_pm",
		       __FILE__, __LINE__);
		return ret;
	}
	init_arch_init_soft_pm_mode(arch_init_soft_pm_mode);
	soft_pm_init_handlers(illegal_operand_soft_pm, diag_operand_soft_pm,
			      array_bounds_soft_pm, illegal_instr_addr_soft_pm);
	pr_info("Software PM init: setting handlers done.");
	return 0;
}

static void soft_pm_exit(void)
{
	pr_info("Software PM exit: resetting handlers...");
	soft_pm_remove_handlers();
	remove_arch_init_soft_pm_mode();
	e2k_soft_pm_remove_sysctl();
	pr_info("Software PM exit: resetting handlers done.");
	sysfs_remove_file(soft_pm_sysfs_dir, &soft_pm_stats_attr.attr);
	kobject_put(soft_pm_sysfs_dir);
	kmem_cache_destroy(fixed_len_buf_slab_alloc);
}

module_init(soft_pm_init);
module_exit(soft_pm_exit);

/* module init/exit (end) */

MODULE_AUTHOR("MCST");
MODULE_DESCRIPTION("Software corrector for PM incompatibilities");
MODULE_LICENSE("GPL v2");
MODULE_VERSION("0.1.0");
