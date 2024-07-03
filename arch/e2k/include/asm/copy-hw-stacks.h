/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _E2K_COPY_HW_STACKS_H
#define _E2K_COPY_HW_STACKS_H

#include <linux/types.h>

#include <asm/mman.h>
#include <asm/pv_info.h>
#include <asm/process.h>

#include <asm/kvm/trace-hw-stacks.h>

#undef	DEBUG_PV_UST_MODE
#undef	DebugUST
#define	DEBUG_PV_UST_MODE	0	/* guest user stacks debug */
#define	DebugUST(fmt, args...)						\
({									\
	if (debug_guest_ust)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_PV_SYSCALL_MODE
#define	DEBUG_PV_SYSCALL_MODE	0	/* syscall injection debugging */

#if	DEBUG_PV_UST_MODE || DEBUG_PV_SYSCALL_MODE
extern bool debug_guest_ust;
#else
#define	debug_guest_ust	false
#endif	/* DEBUG_PV_UST_MODE || DEBUG_PV_SYSCALL_MODE */

#ifndef	CONFIG_VIRTUALIZATION
/* it native kernel without virtualization support */
#else	/* CONFIG_VIRTUALIZATION */
/* It is native host kernel with virtualization support */
/* or virtualized guest kernel
 #include <asm/kvm/process.h>
 */
#endif	/* ! CONFIG_VIRTUALIZATION */

typedef void (*trace_ps_frame_func_t)(kernel_mem_ps_t *base, kernel_mem_ps_t *frame);
typedef void (*trace_pcs_frame_func_t)(e2k_mem_crs_t *base, e2k_mem_crs_t *frame);

static inline void trace_proc_stack_frames(kernel_mem_ps_t *dst_ps_base,
				kernel_mem_ps_t *src_ps_base, u64 ps_size,
				trace_ps_frame_func_t trace_func)
{
	int qreg, qreg_num;
	kernel_mem_ps_t *dst_ps_frame, *src_ps_frame;
	kernel_mem_ps_t rw;

	qreg_num = ps_size / EXT_4_NR_SZ;
	for (qreg = qreg_num - 1; qreg >= 0; qreg--) {
		dst_ps_frame = &dst_ps_base[qreg];
		src_ps_frame = &src_ps_base[qreg];
		rw.word_lo = src_ps_frame->word_lo;
		if (machine.native_iset_ver < E2K_ISET_V5) {
			rw.word_hi = src_ps_frame->word_hi;
			rw.ext_lo = src_ps_frame->ext_lo;
			rw.ext_hi = src_ps_frame->ext_hi;
		} else {
			rw.word_hi = src_ps_frame->ext_lo;
			rw.ext_lo = src_ps_frame->word_hi;
			rw.ext_hi = src_ps_frame->ext_hi;
		}

		trace_func(dst_ps_frame, &rw);
	}
}

static inline void trace_chain_stack_frames(e2k_mem_crs_t *dst_pcs_base,
				e2k_mem_crs_t *src_pcs_base, u64 pcs_size,
				trace_pcs_frame_func_t trace_func)
{
	int crs_no, crs_num;
	e2k_mem_crs_t *dst_pcs_frame, *src_pcs_frame;
	e2k_mem_crs_t crs;
	unsigned long flags;

	crs_num = pcs_size / sizeof(crs);
	raw_all_irq_save(flags);
	for (crs_no = crs_num - 1; crs_no >= 0; crs_no--) {
		dst_pcs_frame = &dst_pcs_base[crs_no];
		src_pcs_frame = &src_pcs_base[crs_no];
		crs = *src_pcs_frame;

		trace_func(dst_pcs_frame, &crs);
	}
	raw_all_irq_restore(flags);
}

static inline void trace_host_hva_area(u64 *hva_base, u64 hva_size)
{
	int line_no, line_num;
	u64 *dst_hva_line;
	unsigned long flags;

	line_num = hva_size / (sizeof(u64) * 4);
	raw_all_irq_save(flags);
	for (line_no = line_num - 1; line_no >= 0; line_no--) {
		dst_hva_line = &hva_base[line_no * 4];
		trace_host_hva_area_line(dst_hva_line, (sizeof(u64) * 4));
	}
	if (line_num * (sizeof(u64) * 4) < hva_size) {
		dst_hva_line = &hva_base[line_no * 4];
		trace_host_hva_area_line(dst_hva_line,
				hva_size - line_num * (sizeof(u64) * 4));
	}
	raw_all_irq_restore(flags);
}

static __always_inline void native_check_last_user_frame_loss(e2k_stacks_t *stacks)
{
	/* See comment in user_hw_stacks_copy_full() */
	BUG_ON(PCSHTP_SIGN_EXTEND(stacks->pcshtp) != SZ_OF_CR);
}

static __always_inline void
native_collapse_kernel_pcs(u64 *dst, const u64 *src, u64 spilled_size)
{
	e2k_pcsp_hi_t k_pcsp_hi;
	u64 size;
	int i;

	DebugUST("current host chain stack index 0x%x, PCSHTP 0x%llx\n",
		NATIVE_NV_READ_PCSP_HI_REG().PCSP_hi_ind,
		NATIVE_READ_PCSHTP_REG_SVALUE());

	NATIVE_FLUSHC;
	k_pcsp_hi = NATIVE_NV_READ_PCSP_HI_REG();

	size = k_pcsp_hi.PCSP_hi_ind - spilled_size;
	BUG_ON(!IS_ALIGNED(size, ALIGN_PCSTACK_TOP_SIZE) || (s64) size < 0);
#pragma loop count (2)
	for (i = 0; i < size / 32; i++) {
		u64 v0, v1, v2, v3;

		v0 = src[4 * i];
		v1 = src[4 * i + 1];
		v2 = src[4 * i + 2];
		v3 = src[4 * i + 3];
		dst[4 * i] = v0;
		dst[4 * i + 1] = v1;
		dst[4 * i + 2] = v2;
		dst[4 * i + 3] = v3;
	}

	k_pcsp_hi.PCSP_hi_ind -= spilled_size;
	NATIVE_NV_NOIRQ_WRITE_PCSP_HI_REG(k_pcsp_hi);

	DebugUST("move spilled chain part from host top %px to "
		"bottom %px, size 0x%llx\n",
		src, dst, size);
	DebugUST("host kernel chain stack index is now 0x%x, "
		"guest user PCSHTP 0x%llx\n",
		k_pcsp_hi.PCSP_hi_ind, spilled_size);
}

static __always_inline void
native_collapse_kernel_ps(u64 *dst, const u64 *src, u64 spilled_size)
{
	e2k_psp_hi_t k_psp_hi;
	u64 size;

	DebugUST("current host procedure stack index 0x%x, PSHTP 0x%x\n",
		NATIVE_NV_READ_PSP_HI_REG().PSP_hi_ind,
		NATIVE_NV_READ_PSHTP_REG().PSHTP_ind);

	NATIVE_FLUSHR;
	k_psp_hi = NATIVE_NV_READ_PSP_HI_REG();

	size = k_psp_hi.PSP_hi_ind - spilled_size;
	BUG_ON(!IS_ALIGNED(size, ALIGN_PSTACK_TOP_SIZE) || (s64) size < 0);

	fast_tagged_memory_copy(dst, src, size, true);

	k_psp_hi.PSP_hi_ind -= spilled_size;
	NATIVE_NV_NOIRQ_WRITE_PSP_HI_REG(k_psp_hi);

	DebugUST("move spilled procedure part from host top %px to "
		"bottom %px, size 0x%llx\n",
		src, dst, size);
	DebugUST("host kernel procedure stack index is now 0x%x, "
		"guest user PSHTP 0x%llx\n",
		k_psp_hi.PSP_hi_ind, spilled_size);
}

static __always_inline int
native_dup_chain_stack_frame_to_user(e2k_mem_crs_t *crs, e2k_stacks_t *stacks)
{
	/* not needed for host */
	return 0;
}

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* It is virtualized guest kernel */
#include <asm/kvm/guest/copy-hw-stacks.h>
#elif	!defined(CONFIG_VIRTUALIZATION) || defined(CONFIG_KVM_HOST_MODE)
/* native kernel with virtualization support */
/* native kernel without virtualization support */

static __always_inline void check_last_user_frame_loss(e2k_stacks_t *stacks)
{
	native_check_last_user_frame_loss(stacks);
}

static __always_inline void
collapse_kernel_pcs(pt_regs_t *regs, u64 *dst, const u64 *src, u64 spilled_size)
{
	native_collapse_kernel_pcs(dst, src, spilled_size);
}
static __always_inline void
collapse_kernel_ps(pt_regs_t *regs, u64 *dst, const u64 *src, u64 spilled_size)
{
	native_collapse_kernel_ps(dst, src, spilled_size);
}

static __always_inline int
dup_chain_stack_frame_to_user(e2k_mem_crs_t *crs, e2k_stacks_t *stacks)
{
	native_dup_chain_stack_frame_to_user(crs, stacks);
	return 0;
}

#else	/* ??? */
 #error "Undefined virtualization mode"
#endif	/* CONFIG_KVM_GUEST_KERNEL */

static __always_inline u64 get_wsz(enum restore_caller from)
{
	return NATIVE_READ_WD_REG().size >> 4;
}

static __always_inline u64 get_ps_clear_size(u64 cur_window_q,
		e2k_pshtp_t pshtp)
{
	s64 u_pshtp_size_q;

	u_pshtp_size_q = GET_PSHTP_Q_INDEX(pshtp);
	if (u_pshtp_size_q > E2K_MAXSR - cur_window_q)
		u_pshtp_size_q = E2K_MAXSR - cur_window_q;

	return E2K_MAXSR - (cur_window_q + u_pshtp_size_q);
}

static __always_inline s64 get_ps_copy_size(u64 cur_window_q, s64 u_pshtp_size)
{
	return u_pshtp_size - (E2K_MAXSR - cur_window_q) * EXT_4_NR_SZ;
}

extern int cf_max_fill_return;
#define E2K_CF_MAX_FILL (cpu_has(CPU_FEAT_FILLC) ? \
	(E2K_CF_MAX_FILL_FILLC_q * 0x10) : cf_max_fill_return)

static __always_inline s64 get_pcs_copy_size(s64 u_pcshtp_size)
{
	/* Before v6 it was possible to fill no more than 16 registers.
	 * Since E2K_MAXCR_q is much bigger than 16 we can be sure that
	 * there is enough space in CF for the FILL, so there is no
	 * need to take into account space taken by current window. */
	return u_pcshtp_size - E2K_CF_MAX_FILL;
}

/*
 * Copy hardware stack from user to *current* kernel stack.
 * One has to be careful to avoid hardware FILL of this stack.
 */
static inline int copy_user_to_current_hw_stack(void *dst, void __user *src,
			unsigned long size, const pt_regs_t *regs, bool chain)
{
	u64 counter;

	if (likely(!host_test_intc_emul_mode(regs))) {
		if (!__range_ok((unsigned long __force) src, size,
				PAGE_OFFSET))
			return -EFAULT;
	}

	/*
	 * Every interrupt and exception here has a chance of FILL'ing
	 * the frame that is being copied, in which case we repeat the copy.
	 */
	do {
		unsigned long ts_flag;
		size_t copied;

		counter = READ_ONCE(current->thread.traps_count);

		if (chain)
			NATIVE_FLUSHC;
		else
			NATIVE_FLUSHR;

		ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
		copied = fast_tagged_memory_copy_from_user_gva(dst, src, size,
				regs, true);
		clear_ts_flag(ts_flag);
		if (unlikely(copied != size))
			return -EFAULT;
	} while (unlikely(counter != READ_ONCE(current->thread.traps_count)));

	return 0;
}


static inline int copy_e2k_stack_from_user(void *dst, void __user *src,
					unsigned long size, pt_regs_t *regs)
{
	unsigned long ts_flag;
	int ret;

	if (likely(!host_test_intc_emul_mode(regs))) {
		if (!__range_ok((unsigned long __force) src, size, PAGE_OFFSET))
			return -EFAULT;
	}

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	ret = host_copy_from_user_with_tags(dst, src, size, regs);
	clear_ts_flag(ts_flag);

	return (ret) ? -EFAULT : 0;
}

static inline int copy_e2k_stack_to_user(void __user *dst, void *src,
					 unsigned long size, pt_regs_t *regs)
{
	unsigned long ts_flag;
	int ret;

	if (likely(!host_test_intc_emul_mode(regs))) {
		if (!__range_ok((unsigned long __force) dst, size, PAGE_OFFSET))
			return -EFAULT;
	}

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	ret = host_copy_to_user_with_tags(dst, src, size, regs);
	clear_ts_flag(ts_flag);

	return (ret) ? -EFAULT : 0;
}

static __always_inline int
user_hw_stack_frames_copy(void __user *dst, void *src, long copy_size,
		const pt_regs_t *regs, long hw_stack_ind, bool is_pcsp)
{
	unsigned long ts_flag, copied;

	if (unlikely(hw_stack_ind < copy_size)) {
		unsigned long flags;
		raw_all_irq_save(flags);
		if (is_pcsp) {
			NATIVE_FLUSHC;
		} else {
			NATIVE_FLUSHR;
		}
		raw_all_irq_restore(flags);
	}

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	copied = fast_tagged_memory_copy_to_user_gva(dst, src, copy_size, regs, true);
	clear_ts_flag(ts_flag);

	if (unlikely(copied != copy_size)) {
		pr_err("process %s (%d) %s stack could not be copied "
			"from %px to %px size 0x%lx (out of memory?)\n",
			current->comm, current->pid,
			(is_pcsp) ? "chain" : "procedure",
			src, dst, copy_size);
		return -EFAULT;
	}
	DebugUST("copying guest %s stack spilled to host from %px "
		"to guest kernel stack from %px, size 0x%lx\n",
		(is_pcsp) ? "chain" : "procedure", src, dst, copy_size);

	return 0;
}

static __always_inline int
user_crs_frames_copy(e2k_mem_crs_t __user *u_frame, pt_regs_t *regs,
			e2k_mem_crs_t *crs)
{
	unsigned long ts_flag;
	int ret;

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	ret = host_copy_to_user(u_frame, crs, sizeof(*crs), regs);
	clear_ts_flag(ts_flag);
	if (unlikely(ret))
		return -EFAULT;

	return 0;
}

static __always_inline int user_psp_stack_copy(e2k_psp_lo_t u_psp_lo,
		e2k_psp_hi_t u_psp_hi, s64 u_pshtp_size,
		e2k_psp_lo_t k_psp_lo, e2k_psp_hi_t k_psp_hi,
		unsigned long copy_size, const pt_regs_t *regs)
{
	void __user *dst;
	void *src;
	int ret;

	dst = (void __user *) (AS(u_psp_lo).base + AS(u_psp_hi).ind -
					u_pshtp_size);
	src = (void *) AS(k_psp_lo).base;

	if (host_test_intc_emul_mode(regs) && trace_host_copy_hw_stack_enabled())
		trace_host_copy_hw_stack(dst, src, copy_size, false);

	ret = user_hw_stack_frames_copy(dst, src, copy_size,
				regs, k_psp_hi.PSP_hi_ind, false);

	if (host_test_intc_emul_mode(regs) && trace_host_proc_stack_frame_enabled())
		trace_proc_stack_frames((kernel_mem_ps_t *)dst,
			(kernel_mem_ps_t *)src, copy_size,
			trace_host_proc_stack_frame);

	return ret;

}

static __always_inline int user_pcsp_stack_copy(e2k_pcsp_lo_t u_pcsp_lo,
		e2k_pcsp_hi_t u_pcsp_hi, s64 u_pcshtp_size,
		e2k_pcsp_lo_t k_pcsp_lo, e2k_pcsp_hi_t k_pcsp_hi,
		unsigned long copy_size, const pt_regs_t *regs)
{
	void __user *dst;
	void *src;
	int ret;

	dst = (void __user *)(AS(u_pcsp_lo).base + AS(u_pcsp_hi).ind -
					u_pcshtp_size);
	src = (void *) AS(k_pcsp_lo).base;

	if (host_test_intc_emul_mode(regs) && trace_host_copy_hw_stack_enabled())
		trace_host_copy_hw_stack(dst, src, copy_size, true);

	ret = user_hw_stack_frames_copy(dst, src, copy_size,
				regs, k_pcsp_hi.PCSP_hi_ind, true);

	if (host_test_intc_emul_mode(regs) && trace_host_chain_stack_frame_enabled())
		trace_chain_stack_frames((e2k_mem_crs_t *)dst,
			(e2k_mem_crs_t *)src, copy_size,
			trace_host_chain_stack_frame);

	return ret;
}

/**
 * user_hw_stacks_copy - copy user hardware stacks that have been
 *			 SPILLed to kernel back to user space
 * @stacks - saved user stack registers
 * @cur_window_q - size of current window in procedure stack,
 *		   needed only if @copy_full is not set
 * @copy_full - set if want to copy _all_ of SPILLed stacks
 *
 * This does not update stacks->pshtp and stacks->pcshtp. Main reason is
 * signals: if a signal arrives after copying then it must see a coherent
 * state where saved stacks->pshtp and stacks->pcshtp values show how much
 * data from user space is spilled to kernel space.
 */
static __always_inline int
native_user_hw_stacks_copy(struct e2k_stacks *stacks,
		pt_regs_t *regs, u64 cur_window_q, bool copy_full)
{
	trap_pt_regs_t *trap = regs->trap;
	e2k_psp_lo_t u_psp_lo = stacks->psp_lo,
		     k_psp_lo = current_thread_info()->k_psp_lo;
	e2k_psp_hi_t u_psp_hi = stacks->psp_hi;
	e2k_pcsp_lo_t u_pcsp_lo = stacks->pcsp_lo,
		      k_pcsp_lo = current_thread_info()->k_pcsp_lo;
	e2k_pcsp_hi_t u_pcsp_hi = stacks->pcsp_hi;
	s64 u_pshtp_size, u_pcshtp_size, ps_copy_size, pcs_copy_size;
	int ret;

	u_pshtp_size = GET_PSHTP_MEM_INDEX(stacks->pshtp);
	u_pcshtp_size = PCSHTP_SIGN_EXTEND(stacks->pcshtp);

	/*
	 * Copy user's part from kernel stacks into user stacks
	 * Update user's stack registers
	 */
	if (copy_full) {
		pcs_copy_size = u_pcshtp_size;
		ps_copy_size = u_pshtp_size;
	} else {
		pcs_copy_size = get_pcs_copy_size(u_pcshtp_size);
		ps_copy_size = get_ps_copy_size(cur_window_q, u_pshtp_size);

		/* Make sure there is enough space in CF for the FILL */
		BUG_ON((E2K_MAXCR_q - 4) * 16 < E2K_CF_MAX_FILL);
	}

	if (!copy_full) {
		/* Fast path when there is nothing to copy */
		if (likely(pcs_copy_size <= 0 && ps_copy_size <= 0))
			return 0;
	}

	if (pcs_copy_size > 0) {
		e2k_pcsp_hi_t k_pcsp_hi = NATIVE_NV_READ_PCSP_HI_REG();

		/* Since not all user data has been SPILL'ed it is possible
		 * that we have already overflown user's hardware stack. */
		if (unlikely(AS(u_pcsp_hi).ind > AS(u_pcsp_hi).size)) {
			ret = handle_chain_stack_bounds(stacks, trap);
			if (unlikely(ret)) {
				pr_warn("process %s (%d) chain stack overflow (out of memory?)\n",
						current->comm, current->pid);
				return ret;
			}

			u_pcsp_lo = stacks->pcsp_lo;
			u_pcsp_hi = stacks->pcsp_hi;
		}

		ret = user_pcsp_stack_copy(u_pcsp_lo, u_pcsp_hi, u_pcshtp_size,
				     k_pcsp_lo, k_pcsp_hi, pcs_copy_size, regs);
		if (ret)
			return ret;
	}

	if (ps_copy_size > 0) {
		e2k_psp_hi_t k_psp_hi = NATIVE_NV_READ_PSP_HI_REG();

		/* Since not all user data has been SPILL'ed it is possible
		 * that we have already overflowed user's hardware stack. */
		if (unlikely(AS(u_psp_hi).ind > AS(u_psp_hi).size)) {
			ret = handle_proc_stack_bounds(stacks, trap);
			if (unlikely(ret)) {
				pr_warn("process %s (%d) procedure stack overflow (out of memory?)\n",
						current->comm, current->pid);
				return ret;
			}

			u_psp_lo = stacks->psp_lo;
			u_psp_hi = stacks->psp_hi;
		}

		ret = user_psp_stack_copy(u_psp_lo, u_psp_hi, u_pshtp_size,
				    k_psp_lo, k_psp_hi, ps_copy_size, regs);
		if (ret)
			return ret;
	}

	return 0;
}

static inline void collapse_kernel_hw_stacks(pt_regs_t *regs, e2k_stacks_t *stacks)
{
	e2k_pcsp_lo_t k_pcsp_lo = current_thread_info()->k_pcsp_lo;
	e2k_psp_lo_t k_psp_lo = current_thread_info()->k_psp_lo;
	unsigned long flags, spilled_pc_size, spilled_p_size;
	e2k_pshtp_t pshtp = stacks->pshtp;
	u64 *dst;
	const u64 *src;

	spilled_pc_size = PCSHTP_SIGN_EXTEND(stacks->pcshtp);
	spilled_p_size = GET_PSHTP_MEM_INDEX(pshtp);
	DebugUST("guest user spilled to host kernel stack part: chain 0x%lx, procedure 0x%lx\n",
		spilled_pc_size, spilled_p_size);
	/* When user tries to return from the last user frame
	 * we will have pcshtp = pcsp_hi.ind = 0. But situation
	 * with pcsp_hi.ind != 0 and pcshtp = 0 is impossible. */
	if (WARN_ON_ONCE(spilled_pc_size < SZ_OF_CR &&
			 AS(stacks->pcsp_hi).ind != 0 && !paravirt_enabled()))
		do_exit(SIGKILL);

	/* Keep the last user frame (see user_hw_stacks_copy_full()) */
	if (spilled_pc_size >= SZ_OF_CR) {
		spilled_pc_size -= SZ_OF_CR;
		DebugUST("Keep the prev user chain frame, so spilled chain "
			"size is now 0x%lx\n",
			spilled_pc_size);
	}

	raw_all_irq_save(flags);

	if (spilled_pc_size) {
		dst = (u64 *) AS(k_pcsp_lo).base;
		src = (u64 *) (AS(k_pcsp_lo).base + spilled_pc_size);
		collapse_kernel_pcs(regs, dst, src, spilled_pc_size);

		stacks->pcshtp = SZ_OF_CR;

		apply_graph_tracer_delta(-spilled_pc_size);
	}

	if (spilled_p_size) {
		dst = (u64 *) AS(k_psp_lo).base;
		src = (u64 *) (AS(k_psp_lo).base + spilled_p_size);
		collapse_kernel_ps(regs, dst, src, spilled_p_size);

		AS(pshtp).ind = 0;
		stacks->pshtp = pshtp;
	}

	raw_all_irq_restore(flags);
}

/**
 * user_hw_stacks_prepare - prepare user hardware stacks that have been
 *			 SPILLed to kernel back to user space
 * @stacks - saved user stack registers
 * @cur_window_q - size of current window in procedure stack,
 *		   needed only if @copy_full is not set
 * @syscall - true if called upon direct system call exit (no signal handlers)
 *
 * This does two things:
 *
 * 1) It is possible that upon kernel entry pcshtp == 0 in some cases:
 *   - user signal handler had pcshtp==0x20 before return to sigreturn()
 *   - user context had pcshtp==0x20 before return to makecontext_trampoline()
 *   - chain stack underflow happened
 * So it is possible in sigreturn() and traps, but not in system calls.
 * If we are using the trick with return to FILL user hardware stacks than
 * we must have frame in chain stack to return to. So in this case kernel's
 * chain stack is moved up by one frame (0x20 bytes).
 * We also fill the new frame with actual user data and update stacks->pcshtp,
 * this is needed to keep the coherent state where saved stacks->pcshtp values
 * shows how much data from user space has been spilled to kernel space.
 *
 * 2) It is not possible to always FILL all of user data that have been
 * SPILLed to kernel stacks. So we manually copy the leftovers that can
 * not be FILLed to user space.
 * This copy does not update stacks->pshtp and stacks->pcshtp. Main reason
 * is signals: if a signal arrives after copying then it must see a coherent
 * state where saved stacks->pshtp and stacks->pcshtp values show how much
 * data from user space has been spilled to kernel space.
 */
static __always_inline void native_user_hw_stacks_prepare(
		struct e2k_stacks *stacks, pt_regs_t *regs,
		u64 cur_window_q, enum restore_caller from, int syscall)
{
	e2k_pcshtp_t u_pcshtp = stacks->pcshtp;
	int ret;

	BUG_ON(from & FROM_PV_VCPU_MODE);

	/*
	 * 1) Make sure there is free space in kernel chain stack to return to
	 */
	if (!syscall && u_pcshtp == 0) {
		unsigned long flags;
		e2k_pcsp_lo_t u_pcsp_lo = stacks->pcsp_lo,
			      k_pcsp_lo = current_thread_info()->k_pcsp_lo;
		e2k_pcsp_hi_t u_pcsp_hi = stacks->pcsp_hi, k_pcsp_hi;
		e2k_mem_crs_t __user *u_cframe;
		e2k_mem_crs_t *k_crs;
		u64 u_cbase;
		int ret = -EINVAL;

		raw_all_irq_save(flags);
		NATIVE_FLUSHC;
		k_pcsp_hi = READ_PCSP_HI_REG();
		BUG_ON(AS(k_pcsp_hi).ind);
		AS(k_pcsp_hi).ind += SZ_OF_CR;
		WRITE_PCSP_HI_REG(k_pcsp_hi);

		k_crs = (e2k_mem_crs_t *) AS(k_pcsp_lo).base;
		u_cframe = (e2k_mem_crs_t __user *) (AS(u_pcsp_lo).base +
						     AS(u_pcsp_hi).ind);
		u_cbase = ((from & FROM_RETURN_PV_VCPU_TRAP) ||
				host_test_intc_emul_mode(regs)) ?
					u_pcsp_lo.PCSP_lo_base :
						(u64) CURRENT_PCS_BASE();
		if ((u64) u_cframe > u_cbase) {
			ret = copy_user_to_current_hw_stack(k_crs, u_cframe - 1,
					sizeof(*k_crs), regs, true);
		}
		raw_all_irq_restore(flags);

		/* Can happen if application returns until runs out of
		 * chain stack or there is no free memory for stacks.
		 * There is no user stack to return to - die. */
		if (ret) {
			SIGDEBUG_PRINT("SIGKILL. %s\n",
				(ret == -EINVAL) ? "tried to return to kernel" :
				       "ran into Out-of-Memory on user stacks");
			force_sig(SIGKILL);
			return;
		}

		if (AS(u_pcsp_hi).ind < SZ_OF_CR) {
			update_pcsp_regs(AS(u_pcsp_lo).base,
					 &u_pcsp_lo, &u_pcsp_hi);
			stacks->pcsp_lo = u_pcsp_lo;
			stacks->pcsp_hi = u_pcsp_hi;
			BUG_ON(AS(u_pcsp_hi).ind < SZ_OF_CR);
		}

		u_pcshtp = SZ_OF_CR;
		stacks->pcshtp = u_pcshtp;
	}

	/*
	 * 2) Copy user data that cannot be FILLed
	 */
	ret = native_user_hw_stacks_copy(stacks, regs, cur_window_q, false);
	if (unlikely(ret))
		do_exit(SIGKILL);
}

#ifndef	CONFIG_VIRTUALIZATION
/* native kernel without virtualization support */
static __always_inline int
user_hw_stacks_copy(struct e2k_stacks *stacks,
		pt_regs_t *regs, u64 cur_window_q, bool copy_full)
{
	return native_user_hw_stacks_copy(stacks, regs, cur_window_q, copy_full);
}

static __always_inline void
host_user_hw_stacks_prepare(struct e2k_stacks *stacks, pt_regs_t *regs,
		u64 cur_window_q, enum restore_caller from, int syscall)
{
	native_user_hw_stacks_prepare(stacks, regs, cur_window_q,
					from, syscall);
}
#elif	defined(CONFIG_KVM_GUEST_KERNEL)
/* It is virtualized guest kernel */
#include <asm/kvm/guest/copy-hw-stacks.h>
#elif	defined(CONFIG_KVM_HOST_MODE)
/* It is host kernel with virtualization support */
#include <asm/kvm/copy-hw-stacks.h>
#else	/* unknow mode */
#error	"unknown virtualization mode"
#endif	/* !CONFIG_VIRTUALIZATION */

/**
 * user_hw_stacks_copy_full - copy part of user stacks that was SPILLed
 *	into kernel back to user stacks.
 * @stacks - saved user stack registers
 * @regs - pt_regs pointer
 * @crs - last frame to copy
 *
 * If @crs is not NULL then the frame pointed to by it will also be copied
 * to userspace.  Note that 'stacks->pcsp_hi.ind' is _not_ updated after
 * copying since it would leave stack in inconsistent state (with two
 * copies of the same @crs frame), this is left to the caller. *
 *
 * Inlining this reduces the amount of memory to copy in
 * collapse_kernel_hw_stacks().
 */
static inline int do_user_hw_stacks_copy_full(struct e2k_stacks *stacks,
					pt_regs_t *regs, e2k_mem_crs_t *crs)
{
	int ret;

	/*
	 * Copy part of user stacks that were SPILLed into kernel stacks
	 */
	ret = user_hw_stacks_copy(stacks, regs, 0, true);
	if (unlikely(ret))
		return ret;

	/*
	 * Nothing to FILL so remove the resulting hole from kernel stacks.
	 *
	 * IMPORTANT: there is always at least one user frame at the top of
	 * kernel stack - the one that issued a system call (in case of an
	 * exception we uphold this rule manually, see user_hw_stacks_prepare())
	 * We keep this ABI and _always_ leave space for one user frame,
	 * this way we can later FILL using return trick (otherwise there
	 * would be no space in chain stack for the trick).
	 */
	collapse_kernel_hw_stacks(regs, stacks);

	/*
	 * Copy saved %cr registers
	 *
	 * Caller must take care of filling of resulting hole
	 * (last user frame from pcshtp == SZ_OF_CR).
	 */
	if (crs) {
		e2k_mem_crs_t __user *u_frame;
		int ret;

		/*
		 * Make sure there is enough space in user chain stack
		 * before copying
		 */
		if (unlikely(AS(stacks->pcsp_hi).ind + sizeof(regs->crs) >
				AS(stacks->pcsp_hi).size)) {
			AS(stacks->pcsp_hi).ind += sizeof(regs->crs);
			ret = handle_chain_stack_bounds(stacks, regs->trap);
			AS(stacks->pcsp_hi).ind -= sizeof(regs->crs);
			if (ret)
				return ret;
		}

		u_frame = (void __user *) (AS(stacks->pcsp_lo).base +
					   AS(stacks->pcsp_hi).ind);
		ret = user_crs_frames_copy(u_frame, regs, &regs->crs);
		if (unlikely(ret))
			return ret;
	}

	return 0;
}

#endif /* _E2K_COPY_HW_STACKS_H */

