/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * KVM guest kernel processes support
 */

#ifndef _E2K_KVM_GUEST_COPY_HW_STACKS_H
#define _E2K_KVM_GUEST_COPY_HW_STACKS_H

#include <asm/kvm/hypercall.h>
#include <asm/cpu_regs_types.h>
#include <asm/stacks.h>

#include <asm/kvm/guest/trace-hw-stacks.h>
#include <asm/kvm/guest/trace-tlb-state.h>

extern bool debug_ustacks;
#undef	DEBUG_USER_STACKS_MODE
#undef	DebugUST
#define	DEBUG_USER_STACKS_MODE	0	/* guest user stacks debug mode */
#define	DebugUST(fmt, args...)						\
({									\
	if (debug_ustacks)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

static inline unsigned long
kvm_kernel_hw_stack_frames_copy(u64 *dst, const u64 *src, unsigned long size,
				bool chain_stack)
{
	unsigned long copied;
	ldst_rec_op_t strd_opcode = (ldst_rec_op_t) { .fmt = LDST_QWORD_FMT };
	ldst_rec_op_t ldrd_opcode = (ldst_rec_op_t) { .fmt = LDST_QWORD_FMT,
			.mas = MAS_FILL_OPERATION | MAS_BYPASS_L1_CACHE };

	if (chain_stack) {
		NATIVE_FLUSHC;
	} else {
		NATIVE_FLUSHR;
	}
	copied = kvm_fast_tagged_memory_copy(dst, src, size, strd_opcode, ldrd_opcode, true);
	if (likely(copied >= 0))
		return size - copied;
	return copied;
}

static inline unsigned long
kvm_kernel_hw_stack_frames_copy_user(u64 *dst, const u64 *src, unsigned long size,
					bool chain_stack)
{
	unsigned long copied;
	ldst_rec_op_t strd_opcode = (ldst_rec_op_t) { .fmt = LDST_QWORD_FMT,
			.mas = MAS_BYPASS_L1_CACHE, .prot = 1 };
	ldst_rec_op_t ldrd_opcode = (ldst_rec_op_t) { .fmt = LDST_QWORD_FMT,
			.mas = MAS_FILL_OPERATION | MAS_BYPASS_L1_CACHE, .prot = 1 };

	if (chain_stack) {
		NATIVE_FLUSHC;
	} else {
		NATIVE_FLUSHR;
	}
	copied = kvm_fast_tagged_memory_copy_user(dst, src, size, NULL,
			strd_opcode, ldrd_opcode, true);
	if (likely(copied >= 0))
		return size - copied;
	return copied;
}

static __always_inline void kvm_check_last_user_frame_loss(e2k_stacks_t *stacks)
{
	/*
	 * See comment in user_hw_stacks_copy_full(), but in guest case
	 * the last frame can be as host trampoline,
	 * so user frame can be one (pcshtp == SZ_OF_CR) or absent (pcshtp == 0)
	 */
	BUG_ON(PCSHTP_SIGN_EXTEND(stacks->pcshtp) > SZ_OF_CR);
}

static __always_inline void
kvm_collapse_kernel_ps(pt_regs_t *regs, u64 *dst, const u64 *src, u64 spilled_size)
{
	e2k_psp_hi_t k_psp_hi;
	u64 ps_ind, ps_size;
	u64 size;

	DebugUST("current host procedure stack index 0x%x, PSHTP 0x%x\n",
		NATIVE_NV_READ_PSP_HI_REG().PSP_hi_ind,
		NATIVE_NV_READ_PSHTP_REG().PSHTP_ind);

	KVM_COPY_STACKS_TO_MEMORY();
	ATOMIC_GET_HW_PS_SIZES(ps_ind, ps_size);

	size = ps_ind - spilled_size;
	BUG_ON(!IS_ALIGNED(size, ALIGN_PSTACK_TOP_SIZE) || (s64) size < 0);

	fast_tagged_memory_copy(dst, src, size, true);

	k_psp_hi = NATIVE_NV_READ_PSP_HI_REG();
	k_psp_hi.PSP_hi_ind = size;
	HYPERVISOR_update_psp_hi(k_psp_hi.PSP_hi_half);
	BUG_ON(regs->copyed.ps_size < spilled_size);
	regs->copyed.ps_size -= spilled_size;

	DebugUST("move spilled procedure part from host top %px to "
		"bottom %px, size 0x%llx\n",
		src, dst, size);
	DebugUST("host kernel procedure stack index is now 0x%x, "
		"guest user PSHTP 0x%llx\n",
		k_psp_hi.PSP_hi_ind, spilled_size);
}

static __always_inline void
kvm_collapse_kernel_pcs(pt_regs_t *regs, u64 *dst, const u64 *src, u64 spilled_size)
{
	e2k_pcsp_hi_t k_pcsp_hi;
	u64 pcs_ind, pcs_size;
	u64 size;

	DebugUST("current host chain stack index 0x%x, PCSHTP 0x%llx\n",
		NATIVE_NV_READ_PCSP_HI_REG().PCSP_hi_ind,
		NATIVE_READ_PCSHTP_REG_SVALUE());

	KVM_COPY_STACKS_TO_MEMORY();
	ATOMIC_GET_HW_PCS_SIZES(pcs_ind, pcs_size);

	size = pcs_ind - spilled_size;
	BUG_ON(!IS_ALIGNED(size, ALIGN_PCSTACK_TOP_SIZE) || (s64) size < 0);

	fast_tagged_memory_copy(dst, src, size, true);

	k_pcsp_hi = NATIVE_NV_READ_PCSP_HI_REG();
	k_pcsp_hi.PCSP_hi_ind = size;
	HYPERVISOR_update_pcsp_hi(k_pcsp_hi.PCSP_hi_half);
	BUG_ON(regs->copyed.pcs_size < spilled_size);
	regs->copyed.pcs_size -= spilled_size;

	DebugUST("move spilled chain part from host top %px to "
		"bottom %px, size 0x%llx\n",
		src, dst, size);
	DebugUST("host kernel chain stack index is now 0x%x, "
		"guest user PCSHTP 0x%llx\n",
		k_pcsp_hi.PCSP_hi_ind, spilled_size);
}

static __always_inline int
copy_stack_page_from_kernel(void __user *dst, void *src, e2k_size_t to_copy,
				bool is_chain)
{
	return kvm_kernel_hw_stack_frames_copy(dst, src, to_copy, is_chain);
}

static inline struct page *get_user_addr_to_kernel_page(unsigned long addr)
{
	struct page *page = NULL;
	mm_segment_t seg;
	unsigned long ts_flag;
	int npages;

	seg = get_fs();
	set_fs(K_USER_DS);
	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	npages = get_user_pages_fast(addr, 1, FOLL_WRITE, &page);
	clear_ts_flag(ts_flag);
	set_fs(seg);
	if (npages != 1)
		return ERR_PTR(npages);

	return page;
}

static inline void put_user_addr_to_kernel_page(struct page *page)
{
	if (likely(!IS_ERR_OR_NULL(page)))
		put_page(page);
}

static __always_inline int
copy_stack_page_to_user(void __user *dst, void *src, e2k_size_t to_copy,
			bool is_chain)
{
	struct page *page;
	unsigned long addr = (unsigned long)dst;
	void *k_dst;
	e2k_size_t offset;
	int ret;

	if (to_copy == 0)
		return 0;

	DebugUST("started to copy %s stack from kernel stack %px to user %px "
		"size 0x%lx\n",
		(is_chain) ? "chain" : "procedure",
		src, dst, to_copy);

	page = get_user_addr_to_kernel_page(addr);
	if (unlikely(IS_ERR_OR_NULL(page))) {
		ret = (IS_ERR(page)) ? PTR_ERR(page) : -EINVAL;
		goto failed;
	}

	offset = addr & ~PAGE_MASK;
	k_dst = page_address(page) + offset;
	DebugUST("copy stack frames from kernel %px to user %px, size 0x%lx\n",
		src, k_dst, to_copy);
	ret = copy_stack_page_from_kernel(k_dst, src, to_copy, is_chain);
	if (ret != 0) {
		pr_err("%s(): copy %s stack to user %px from kernel %px, "
			"size 0x%lx failed, error %d\n",
			__func__, (is_chain) ? "chain" : "procedure",
			src, k_dst, to_copy, ret);
		goto failed_copy;
	}

failed_copy:
	put_user_addr_to_kernel_page(page);
failed:
	return ret;
}

static __always_inline int
kvm_copy_user_stack_from_kernel(void __user *dst, void *src,
				e2k_size_t to_copy, bool is_chain)
{
	e2k_size_t offset, len, copied = 0;
	int ret;

	if (to_copy == 0)
		return 0;

	DebugUST("started to copy %s stack from kernel stack %px to user %px "
		"size 0x%lx\n",
		(is_chain) ? "chain" : "procedure",
		src, dst, to_copy);

	if (trace_guest_copy_hw_stack_enabled())
		trace_guest_copy_hw_stack(dst, src, to_copy, is_chain);

	do {
		offset = (unsigned long)dst & ~PAGE_MASK;
		len = min(to_copy, PAGE_SIZE - offset);
		ret = copy_stack_page_to_user(dst, src, len, is_chain);
		if (ret != 0)
			goto failed;
		dst += len;
		src += len;
		to_copy -= len;
		copied += len;
	} while (to_copy > 0);

	if (!is_chain && trace_guest_proc_stack_frame_enabled()) {
		if (trace_guest_va_tlb_state_enabled()) {
			trace_guest_va_tlb_state((e2k_addr_t)dst);
		}
		src -= copied;
		trace_proc_stack_frames((kernel_mem_ps_t *)(src),
					(kernel_mem_ps_t *)(src), copied,
					trace_guest_proc_stack_frame);
		dst -= copied;
		to_copy = copied;
		do {
			struct page *page;
			void *k_dst;

			offset = (unsigned long)dst & ~PAGE_MASK;
			len = min(to_copy, PAGE_SIZE - offset);
			page = get_user_addr_to_kernel_page((unsigned long)dst);
			if (unlikely(IS_ERR_OR_NULL(page))) {
				ret = (IS_ERR(page)) ? PTR_ERR(page) : -EINVAL;
				goto failed;
			}
			k_dst = page_address(page) + offset;
			trace_proc_stack_frames((kernel_mem_ps_t *)(k_dst),
					(kernel_mem_ps_t *)(k_dst), len,
					trace_guest_proc_stack_frame);
			dst += len;
			to_copy -= len;
		} while (to_copy > 0);
	}
	if (is_chain && trace_guest_chain_stack_frame_enabled()) {
		if (trace_guest_va_tlb_state_enabled()) {
			trace_guest_va_tlb_state((e2k_addr_t)dst);
		}
		src -= copied;
		trace_chain_stack_frames((e2k_mem_crs_t *)(src),
					(e2k_mem_crs_t *)(src), copied,
					trace_guest_chain_stack_frame);
		dst -= copied;
		to_copy = copied;
		do {
			struct page *page;
			void *k_dst;

			offset = (unsigned long)dst & ~PAGE_MASK;
			len = min(to_copy, PAGE_SIZE - offset);
			page = get_user_addr_to_kernel_page((unsigned long)dst);
			if (unlikely(IS_ERR_OR_NULL(page))) {
				ret = (IS_ERR(page)) ? PTR_ERR(page) : -EINVAL;
				goto failed;
			}
			k_dst = page_address(page) + offset;
			trace_chain_stack_frames((e2k_mem_crs_t *)(k_dst),
					(e2k_mem_crs_t *)(k_dst), len,
					trace_guest_chain_stack_frame);
			dst += len;
			to_copy -= len;
		} while (to_copy > 0);
	}

	return 0;

failed:
	if (likely(ret == -ERESTARTSYS && fatal_signal_pending(current))) {
		/* there is fatal signal to kill the process */
		;
	} else {
		pr_err("%s(): failed, error %d\n", __func__, ret);
	}
	return ret;
}

static __always_inline int
kvm_dup_chain_stack_frame_to_user(e2k_mem_crs_t *crs, e2k_stacks_t *stacks)
{
	e2k_mem_crs_t *u_crs;

	u_crs = (e2k_mem_crs_t *)(stacks->pcsp_lo.PCSP_lo_base +
				  stacks->pcsp_hi.PCSP_hi_ind);
	return kvm_copy_user_stack_from_kernel(u_crs, crs, SZ_OF_CR, true);
}

static __always_inline int
kvm_user_hw_stacks_copy(pt_regs_t *regs)
{
	e2k_psp_lo_t psp_lo;
	e2k_psp_hi_t psp_hi;
	e2k_pshtp_t  pshtp;
	e2k_pcsp_lo_t pcsp_lo;
	e2k_pcsp_hi_t pcsp_hi;
	e2k_pcshtp_t  pcshtp;
	e2k_stacks_t *stacks;
	void __user *dst;
	void *src;
	long copyed_ps_size, copyed_pcs_size, to_copy, from, there_are;
	int ret;

	if (unlikely(irqs_disabled())) {
		pr_err("%s() called with IRQs disabled PSP: 0x%lx UPSR: 0x%lx "
			"under UPSR %d\n",
			__func__, KVM_READ_PSR_REG_VALUE(),
			KVM_READ_UPSR_REG_VALUE(),
			kvm_get_vcpu_state()->irqs_under_upsr);
		local_irq_enable();
		WARN_ON(true);
	}

	stacks = &regs->stacks;
	copyed_ps_size = regs->copyed.ps_size;
	copyed_pcs_size = regs->copyed.pcs_size;
	if (unlikely(copyed_ps_size)) {
		/* stacks have been already copyed */
		if (copyed_ps_size != GET_PSHTP_MEM_INDEX(stacks->pshtp) &&
				GET_PSHTP_MEM_INDEX(stacks->pshtp) != 0) {
			pr_err("%s(): copyed_ps_size 0x%lx != pshtp 0x%llx or "
				"pshtp 0x%llx != 0\n",
				__func__,
				copyed_ps_size, GET_PSHTP_MEM_INDEX(stacks->pshtp),
				GET_PSHTP_MEM_INDEX(stacks->pshtp));
			WARN_ON(true);
		}
	}
	if (unlikely(copyed_pcs_size)) {
		/* stacks have been already copyed */
		if (copyed_pcs_size != PCSHTP_SIGN_EXTEND(stacks->pcshtp) &&
				PCSHTP_SIGN_EXTEND(stacks->pcshtp) != SZ_OF_CR) {
			pr_err("%s(): copyed_pcs_size 0x%lx != pcshtp 0x%llx or "
				"pcshtp 0x%llx != 0x%lx\n",
				__func__,
				copyed_pcs_size, PCSHTP_SIGN_EXTEND(stacks->pcshtp),
				PCSHTP_SIGN_EXTEND(stacks->pcshtp), SZ_OF_CR);
			WARN_ON(true);
		}
	}
	if (unlikely(copyed_ps_size && copyed_pcs_size))
		/* both stacks have been already copyed */
		return 0;

	ret = HYPERVISOR_copy_stacks_to_memory();
	if (ret != 0) {
		pr_err("%s(): flush of kernel stacks failed, error %d\n",
			__func__, ret);
		goto failed;
	}

	/* copy user part of procedure stack from kernel back to user */
	ATOMIC_READ_HW_STACKS_REGS(psp_lo.PSP_lo_half, psp_hi.PSP_hi_half,
				   pshtp.PSHTP_reg,
				   pcsp_lo.PCSP_lo_half, pcsp_hi.PCSP_hi_half,
				   pcshtp);

	if (unlikely(copyed_ps_size))
		goto copy_chain_stack;

	src = (void *)psp_lo.PSP_lo_base;
	DebugUST("procedure stack at kernel from %px, size 0x%x, ind 0x%x, "
		"pshtp 0x%llx\n",
		src, psp_hi.PSP_hi_size, psp_hi.PSP_hi_ind, pshtp.PSHTP_reg);
	BUG_ON(psp_hi.PSP_hi_ind > psp_hi.PSP_hi_size);

	if (stacks->psp_hi.PSP_hi_ind >= stacks->psp_hi.PSP_hi_size) {
		/* procedure stack overflow, need expand */
		ret = handle_proc_stack_bounds(stacks, regs->trap);
		if (unlikely(ret)) {
			pr_err("%s(): could not handle process %s (%d) "
				"procedure stack overflow, error %d\n",
				__func__, current->comm, current->pid, ret);
			goto failed;
		}
	}
	to_copy = GET_PSHTP_MEM_INDEX(stacks->pshtp);
	BUG_ON(to_copy < 0);
	from = stacks->psp_hi.PSP_hi_ind - to_copy;
	BUG_ON(from < 0);
	dst = (void __user *)stacks->psp_lo.PSP_lo_base + from;
	DebugUST("procedure stack at user from %px, ind 0x%x, "
		"pshtp size to copy 0x%lx\n",
		dst, stacks->psp_hi.PSP_hi_ind, to_copy);
	there_are = stacks->psp_hi.PSP_hi_size - from;
	if (there_are < to_copy) {
		pr_err("%s(): user procedure stack overflow, there are 0x%lx "
			"to copy need 0x%lx, not yet implemented\n",
			__func__, there_are, to_copy);
		BUG_ON(true);
	}
	if (to_copy > 0) {
		ret = kvm_copy_user_stack_from_kernel(dst, src, to_copy, false);
		if (unlikely(ret != 0)) {
			if (likely(ret == -ERESTARTSYS &&
					fatal_signal_pending(current))) {
				/* there is fatal signal to kill the process */
				;
			} else {
				E2K_LMS_HALT_OK;
				pr_err("%s(): procedure stack copying from "
					"kernel %px to user %px, size 0x%lx "
					"failed, error %d\n",
					__func__, src, dst, to_copy, ret);
			}
			goto failed;
		}
		regs->copyed.ps_size = to_copy;
	}

copy_chain_stack:

	if (unlikely(copyed_pcs_size))
		goto complete_copy;

	/* copy user part of chain stack from kernel back to user */
	src = (void *)pcsp_lo.PCSP_lo_base;
	DebugUST("chain stack at kernel from %px, size 0x%x, ind 0x%x, "
		"pcshtp 0x%x\n",
		src, pcsp_hi.PCSP_hi_size, pcsp_hi.PCSP_hi_ind, pcshtp);
	BUG_ON(pcsp_hi.PCSP_hi_ind + PCSHTP_SIGN_EXTEND(pcshtp) >
							pcsp_hi.PCSP_hi_size);
	if (stacks->pcsp_hi.PCSP_hi_ind >= stacks->pcsp_hi.PCSP_hi_size) {
		/* chain stack overflow, need expand */
		ret = handle_chain_stack_bounds(stacks, regs->trap);
		if (unlikely(ret)) {
			pr_err("%s(): could not handle process %s (%d) "
				"chain stack overflow, error %d\n",
				__func__, current->comm, current->pid, ret);
			goto failed;
		}
	}
	to_copy = PCSHTP_SIGN_EXTEND(stacks->pcshtp);
	BUG_ON(to_copy < 0);
	from = stacks->pcsp_hi.PCSP_hi_ind - to_copy;
	BUG_ON(from < 0);
	dst = (void *)stacks->pcsp_lo.PCSP_lo_base + from;
	BUG_ON(to_copy > pcsp_hi.PCSP_hi_ind + PCSHTP_SIGN_EXTEND(pcshtp));
	DebugUST("chain stack at user from %px, ind 0x%x, "
		"pcshtp size to copy 0x%lx\n",
		dst, stacks->pcsp_hi.PCSP_hi_ind, to_copy);
	there_are = stacks->pcsp_hi.PCSP_hi_size - from;
	if (there_are < to_copy) {
		pr_err("%s(): user chain stack overflow, there are 0x%lx "
			"to copy need 0x%lx, not yet implemented\n",
			__func__, there_are, to_copy);
		BUG_ON(true);
	}
	if (to_copy > 0) {
		ret = kvm_copy_user_stack_from_kernel(dst, src, to_copy, true);
		if (unlikely(ret != 0)) {
			if (likely(ret == -ERESTARTSYS &&
					fatal_signal_pending(current))) {
				/* there is fatal signal to kill the process */
				;
			} else {
				pr_err("%s(): chain stack copying from kernel %px "
					"to user %px, size 0x%lx failed, error %d\n",
					__func__, src, dst, to_copy, ret);
			}
			goto failed;
		}
		regs->copyed.pcs_size = to_copy;
	}

complete_copy:
failed:
	if (DEBUG_USER_STACKS_MODE)
		debug_ustacks = false;
	return ret;
}

/*
 * Copy additional frames injected to the guest kernel stack, but these frames
 * are for guest user stack and should be copyed from kernel back to the top
 * of user.
 */
static __always_inline int
kvm_copy_injected_pcs_frames_to_user(pt_regs_t *regs, int frames_num)
{
	e2k_size_t pcs_ind, pcs_size;
	e2k_addr_t pcs_base;
	int  pcsh_top;
	e2k_stacks_t *stacks;
	void __user *dst;
	void *src;
	long to_copy, from, there_are, frames_size;
	int ret;

	BUG_ON(irqs_disabled());

	frames_size = frames_num * SZ_OF_CR;
	if (unlikely(regs->copyed.pcs_injected_frames_size >= frames_size)) {
		/* all frames have been already copied */
		return 0;
	}

	/* copied only part of frames - not implemented case */
	BUG_ON(regs->copyed.pcs_injected_frames_size != 0);

	stacks = &regs->stacks;
	ATOMIC_GET_HW_PCS_SIZES_BASE_TOP(pcs_ind, pcs_size, pcs_base, pcsh_top);

	/* guest user stacks part spilled to kernel should be already copied */
	BUG_ON(regs->copyed.pcs_size != stacks->pcshtp && stacks->pcshtp != SZ_OF_CR);

	src = (void *)(pcs_base + regs->copyed.pcs_size);
	DebugUST("chain stack at kernel from %px, size 0x%lx + 0x%lx, "
		"ind 0x%lx, pcsh top 0x%x\n",
		src, pcs_size, frames_size, pcs_ind, pcsh_top);
	BUG_ON(regs->copyed.pcs_size + frames_size > pcs_ind + pcsh_top);
	if (unlikely(stacks->pcsp_hi.PCSP_hi_ind + frames_size >
						stacks->pcsp_hi.PCSP_hi_size)) {
		/* user chain stack can overflow, need expand */
		ret = handle_chain_stack_bounds(stacks, regs->trap);
		if (unlikely(ret)) {
			pr_err("%s(): could not handle process %s (%d) "
				"chain stack overflow, error %d\n",
				__func__, current->comm, current->pid, ret);
			goto failed;
		}
	}
	to_copy = frames_size;
	BUG_ON(to_copy < 0);
	from = stacks->pcsp_hi.PCSP_hi_ind;
	BUG_ON(from < regs->copyed.pcs_size);
	dst = (void *)stacks->pcsp_lo.PCSP_lo_base + from;
	DebugUST("chain stack at user from %px, ind 0x%x, "
		"frames size to copy 0x%lx\n",
		dst, stacks->pcsp_hi.PCSP_hi_ind, to_copy);
	there_are = stacks->pcsp_hi.PCSP_hi_size - from;
	if (there_are < to_copy) {
		pr_err("%s(): user chain stack overflow, there are 0x%lx "
			"to copy need 0x%lx, not yet implemented\n",
			__func__, there_are, to_copy);
		BUG_ON(true);
	}
	if (likely(to_copy > 0)) {
		ret = kvm_copy_user_stack_from_kernel(dst, src, to_copy, true);
		if (unlikely(ret != 0)) {
			if (likely(ret == -ERESTARTSYS &&
					fatal_signal_pending(current))) {
				/* there is fatal signal to kill the process */
				;
			} else {
				pr_err("%s(): chain stack copying from kernel %px "
					"to user %px, size 0x%lx failed, error %d\n",
					__func__, src, dst, to_copy, ret);
			}
			goto failed;
		}
		regs->copyed.pcs_injected_frames_size = to_copy;
		/* increment chain stack pointer */
		stacks->pcsp_hi.PCSP_hi_ind += to_copy;
	} else {
		BUG_ON(true);
		ret = 0;
	}

failed:
	if (DEBUG_USER_STACKS_MODE)
		debug_ustacks = false;
	return ret;
}

/*
 * See comment before native_user_hw_stacks_prepare()
 */
static __always_inline int kvm_user_hw_stacks_prepare(
		struct e2k_stacks *stacks, pt_regs_t *regs,
		u64 cur_window_q, enum restore_caller from, int syscall)
{
	e2k_pcshtp_t u_pcshtp = stacks->pcshtp;
	int ret;

	BUG_ON(!kvm_trap_user_mode(regs));

	BUG_ON(from & FROM_PV_VCPU_MODE);

	/*
	 * 1) Make sure there is free space in kernel chain stack to return to
	 */
	if (!syscall && u_pcshtp == 0) {
		DebugUST("%s(): PCSHTP is empty\n", __func__);
	}

	/*
	 * 2) User data copying will be done some later at
	 *    kvm_prepare_user_hv_stacks()
	 */
	ret = kvm_user_hw_stacks_copy(regs);
	if (unlikely(ret != 0)) {
		if (likely(ret == -ERESTARTSYS)) {
			/* there is fatal signal to kill the process */
			;
		} else {
			pr_err("%s(): copying of hardware stacks failed, error %d\n",
				__func__, ret);
		}
		user_exit();
		do_exit(SIGKILL);
	}
	return ret;
}

static inline int
kvm_ret_from_fork_prepare_hv_stacks(struct pt_regs *regs)
{
	return kvm_user_hw_stacks_copy(regs);
}

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* native guest kernel */

static __always_inline void check_last_user_frame_loss(e2k_stacks_t *stacks)
{
	kvm_check_last_user_frame_loss(stacks);
}

static __always_inline void
collapse_kernel_ps(pt_regs_t *regs, u64 *dst, const u64 *src, u64 spilled_size)
{
	kvm_collapse_kernel_ps(regs, dst, src, spilled_size);
}

static __always_inline void
collapse_kernel_pcs(pt_regs_t *regs, u64 *dst, const u64 *src, u64 spilled_size)
{
	kvm_collapse_kernel_pcs(regs, dst, src, spilled_size);
}

static __always_inline int
dup_chain_stack_frame_to_user(e2k_mem_crs_t *crs, e2k_stacks_t *stacks)
{
	return kvm_dup_chain_stack_frame_to_user(crs, stacks);
}

static __always_inline int
user_hw_stacks_copy(struct e2k_stacks *stacks,
		pt_regs_t *regs, u64 cur_window_q, bool copy_full)
{
	return kvm_user_hw_stacks_copy(regs);
}

static __always_inline void host_user_hw_stacks_prepare(
		struct e2k_stacks *stacks, pt_regs_t *regs,
		u64 cur_window_q, enum restore_caller from, int syscall)
{
	if (unlikely(from_syscall(regs) && regs->sys_num == __NR_e2k_longjmp2)) {
		/* hardware stacks already are prepared */
		return;
	}
	kvm_user_hw_stacks_prepare(stacks, regs, cur_window_q,
					from, syscall);
}

static inline int
ret_from_fork_prepare_hv_stacks(struct pt_regs *regs)
{
	return kvm_ret_from_fork_prepare_hv_stacks(regs);
}

#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif /* !(_E2K_KVM_GUEST_COPY_HW_STACKS_H) */
