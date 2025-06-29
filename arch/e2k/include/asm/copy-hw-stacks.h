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
#endif /* DEBUG_PV_UST_MODE || DEBUG_PV_SYSCALL_MODE */

#ifndef	CONFIG_VIRTUALIZATION
/* it native kernel without virtualization support */
#else /* CONFIG_VIRTUALIZATION */
/* It is native host kernel with virtualization support */
/* or virtualized guest kernel
 #include <asm/kvm/process.h>
 */
#endif /* ! CONFIG_VIRTUALIZATION */

typedef void (*trace_ps_frame_func_t)(kernel_mem_ps_t __user *base, kernel_mem_ps_t *frame);
typedef void (*trace_pcs_frame_func_t)(e2k_mem_crs_t __user *base, e2k_mem_crs_t *frame);

static inline void trace_proc_stack_frames(kernel_mem_ps_t __user *dst_ps_base,
				kernel_mem_ps_t *src_ps_base, u64 ps_size,
				trace_ps_frame_func_t trace_func)
{
	int qreg, qreg_num;
	kernel_mem_ps_t __user *dst_ps_frame;
	kernel_mem_ps_t *src_ps_frame;
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

static inline void trace_chain_stack_frames(e2k_mem_crs_t __user *dst_pcs_base,
				e2k_mem_crs_t *src_pcs_base, u64 pcs_size,
				trace_pcs_frame_func_t trace_func)
{
	int crs_no, crs_num;
	e2k_mem_crs_t __user *dst_pcs_frame;
	e2k_mem_crs_t *src_pcs_frame;
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

static inline void trace_host_hva_area(u64 __user *hva_base, u64 hva_size)
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
	BUG_ON(stacks->pcshtp.ind != SZ_OF_CR);
}

static __always_inline void
native_collapse_kernel_pcs(u64 *dst, const u64 *src, u64 spilled_size)
{
	e2k_pcsp_t k_pcsp;
	u64 size;
	int i;
	long flags = 0;

	DebugUST("current host chain stack index 0x%llx, PCSHTP 0x%x\n",
		PCSP_IND(native_read_PCSP_reg()),
		native_read_PCSHTP_reg().ind);

	raw_all_v7_irq_save(flags);
	NATIVE_FLUSHC;
	k_pcsp = native_read_PCSP_reg();
	size = PCSP_IND(k_pcsp) - spilled_size;
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

	k_pcsp = set_pcsp_ind(k_pcsp, size);
	native_write_PCSP_reg(k_pcsp);
	raw_all_v7_irq_restore(flags);

	DebugUST("move spilled chain part from host top %px to\n"
		 "bottom %px, size 0x%llx\n", src, dst, size);
	DebugUST("host kernel chain stack index is now 0x%llx,\n"
		 "guest user PCSHTP 0x%llx\n", PCSP_IND(k_pcsp), spilled_size);
}

static __always_inline void
native_collapse_kernel_ps(u64 *dst, const u64 *src, u64 spilled_size)
{
	e2k_psp_t k_psp;
	u64 size;

	BUG_ON(!raw_all_irqs_disabled());

	DebugUST("current host procedure stack index 0x%llx, PSHTP 0x%x\n",
		 PSP_IND(native_read_PSP_reg()), native_read_PSHTP_reg().ind);

	NATIVE_FLUSHR;
	k_psp = native_read_PSP_reg();

	size = PSP_IND(k_psp) - spilled_size;
	BUG_ON(!IS_ALIGNED(size, ALIGN_PSTACK_TOP_SIZE) || (s64) size < 0);

	fast_tagged_memory_copy(dst, src, size, true);

	k_psp = set_psp_ind(k_psp, size);
	native_write_PSP_reg(k_psp);

	DebugUST("move spilled procedure part from host top %px to\n"
		 "bottom %px, size 0x%llx\n", src, dst, size);
	DebugUST("host kernel procedure stack index is now 0x%llx,\n"
		 "guest user PSHTP 0x%llx\n", PSP_IND(k_psp), spilled_size);
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

#else /* ??? */
# error "Undefined virtualization mode"
#endif /* CONFIG_KVM_GUEST_KERNEL */

static __always_inline u64 get_wsz(void)
{
	return native_read_WD_reg().size >> 4;
}

static __always_inline u64 get_ps_clear_size(u64 cur_window_q, e2k_pshtp_t pshtp)
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
static inline int copy_user_to_current_hw_stack(void *dst, const void __user *src,
			unsigned long size, const pt_regs_t *regs, bool chain)
{
	u64 counter;
	if (likely(!host_test_intc_emul_mode(regs)) && !access_ok(src, size))
		return -EFAULT;

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
		copied = fast_tagged_memory_copy_from_user_gva(dst, src, size, regs, true);
		clear_ts_flag(ts_flag);
		if (unlikely(copied != size))
			return -EFAULT;
	} while (unlikely(counter != READ_ONCE(current->thread.traps_count)));

	return 0;
}

static inline int copy_priv_to_current_hw_stack(void *dst, const void __priv *src,
			unsigned long size, const pt_regs_t *regs, bool chain)
{
	u64 counter;
	if (likely(!host_test_intc_emul_mode(regs)) && !access_priv_ok(src, size))
		return -EFAULT;

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
		copied = fast_tagged_memory_copy_from_user_gva(dst,
				(const void __user __force *) src, size, regs, true);
		clear_ts_flag(ts_flag);
		if (unlikely(copied != size))
			return -EFAULT;
	} while (unlikely(counter != READ_ONCE(current->thread.traps_count)));

	return 0;
}

/*
 * Copy hardware stack from kernel buffer to *current* kernel stack.
 * One has to be careful to avoid hardware FILL of this stack.
 */
static inline void copy_to_current_hw_stack(void *dst, void *src,
		unsigned long size, bool chain)
{
	unsigned long flags;

	raw_all_irq_save(flags);
	if (chain)
		NATIVE_FLUSHC;
	else
		NATIVE_FLUSHR;
	memcpy(dst, src, size);
	raw_all_irq_restore(flags);
}

static inline int copy_e2k_stack_from_user(void *dst, void __priv *src,
					   unsigned long size, pt_regs_t *regs)
{
	unsigned long ts_flag;
	int ret;

	if (likely(!host_test_intc_emul_mode(regs)) && !access_priv_ok(src, size))
		return -EFAULT;

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	ret = host_copy_from_user_with_tags(dst,
			(void __user __force *) src, size, regs);
	clear_ts_flag(ts_flag);

	return (ret) ? -EFAULT : 0;
}

static inline int copy_e2k_stack_to_user(void __user *dst, void *src,
					 unsigned long size, pt_regs_t *regs)
{
	unsigned long ts_flag;
	int ret;

	if (likely(!host_test_intc_emul_mode(regs)) && !access_priv_ok(dst, size)) {
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
		pr_err("process %s (%d) %s stack could not be copied\n"
		       "from %px to %px size 0x%lx (out of memory?)\n",
		       current->comm, current->pid,
		       (is_pcsp) ? "chain" : "procedure", src, dst, copy_size);
		return -EFAULT;
	}
	DebugUST("copying guest %s stack spilled to host from %px\n"
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

static __always_inline int user_psp_stack_copy(e2k_psp_t u_psp, s64 u_pshtp_size,
		e2k_psp_t k_psp, unsigned long copy_size, const pt_regs_t *regs)
{
	void __user *dst;
	void *src;
	int ret;

	dst = (void __user *) (PSP_PTR(u_psp) - u_pshtp_size);
	src = (void *) PSP_BASE(k_psp);

	if (host_test_intc_emul_mode(regs) && trace_host_copy_hw_stack_enabled())
		trace_host_copy_hw_stack(dst, src, copy_size, false);

	ret = user_hw_stack_frames_copy(dst, src, copy_size,
					regs, PSP_IND(k_psp), false);

	if (host_test_intc_emul_mode(regs) && trace_host_proc_stack_frame_enabled())
		trace_proc_stack_frames((kernel_mem_ps_t __user *) dst,
					(kernel_mem_ps_t *) src, copy_size,
					trace_host_proc_stack_frame);

	return ret;

}

static __always_inline int user_pcsp_stack_copy(e2k_pcsp_t u_pcsp, s64 u_pcshtp_size,
		e2k_pcsp_t k_pcsp, unsigned long copy_size, const pt_regs_t *regs)
{
	void __user *dst;
	void *src;
	int ret;

	dst = (void __user *)(PCSP_PTR(u_pcsp) - u_pcshtp_size);
	src = (void *)PCSP_BASE(k_pcsp);

	if (host_test_intc_emul_mode(regs) && trace_host_copy_hw_stack_enabled())
		trace_host_copy_hw_stack(dst, src, copy_size, true);
	ret = user_hw_stack_frames_copy(dst, src, copy_size,
					regs, PCSP_IND(k_pcsp), true);

	if (host_test_intc_emul_mode(regs) && trace_host_chain_stack_frame_enabled())
		trace_chain_stack_frames((e2k_mem_crs_t __user *) dst,
					 (e2k_mem_crs_t *) src, copy_size,
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
	e2k_psp_t u_psp = stacks->psp;
	e2k_pcsp_t u_pcsp = stacks->pcsp;
	s64 u_pshtp_size, u_pcshtp_size, ps_copy_size, pcs_copy_size;
	int ret;

	u_pcshtp_size = stacks->pcshtp.ind;
	u_pshtp_size = PSHTP_MEM_INDEX(stacks->pshtp);

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
		raw_all_v7_irq_disable();
		e2k_pcsp_t k_pcsp = native_read_PCSP_reg();
		raw_all_v7_irq_enable();

		/* Since not all user data has been SPILL'ed it is possible
		 * that we have already overflown user's hardware stack. */
		if (unlikely(PCSP_IND(u_pcsp) > PCSP_SIZE(u_pcsp))) {
			ret = handle_chain_stack_bounds(stacks, trap);
			if (unlikely(ret)) {
				pr_warn("process %s (%d) chain stack overflow (out of memory?)\n",
					current->comm, current->pid);
				return ret;
			}

			u_pcsp = stacks->pcsp;
		}

		ret = user_pcsp_stack_copy(u_pcsp, u_pcshtp_size,
					   k_pcsp, pcs_copy_size, regs);
		if (ret)
			return ret;
	}

	if (ps_copy_size > 0) {
		raw_all_v7_irq_disable();
		e2k_psp_t k_psp = native_read_PSP_reg();
		raw_all_v7_irq_enable();

		/* Since not all user data has been SPILL'ed it is possible
		 * that we have already overflowed user's hardware stack. */
		if (unlikely(PSP_IND(u_psp) > PSP_SIZE(u_psp))) {
			ret = handle_proc_stack_bounds(stacks, trap);
			if (unlikely(ret)) {
				pr_warn("process %s (%d) procedure stack overflow (out of memory?)\n",
					current->comm, current->pid);
				return ret;
			}

			u_psp = stacks->psp;
		}

		ret = user_psp_stack_copy(u_psp, u_pshtp_size,
					  k_psp, ps_copy_size, regs);
		if (ret)
			return ret;
	}

	return 0;
}

static inline void collapse_kernel_hw_stacks(pt_regs_t *regs, e2k_stacks_t *stacks)
{
	e2k_pcsp_t k_pcsp = current_thread_info()->k_pcsp;
	e2k_psp_t k_psp = current_thread_info()->k_psp;
	unsigned long flags, spilled_pc_size, spilled_p_size;
	e2k_pshtp_t pshtp = stacks->pshtp;
	u64 *dst;
	const u64 *src;

	spilled_pc_size = stacks->pcshtp.ind;
	spilled_p_size = PSHTP_MEM_INDEX(pshtp);
	DebugUST("guest user spilled to host kernel stack part: chain 0x%lx, procedure 0x%lx\n",
		spilled_pc_size, spilled_p_size);
	/* When user tries to return from the last user frame
	 * we will have pcshtp = pcsp_hi.ind = 0. But situation
	 * with pcsp_hi.ind != 0 and pcshtp = 0 is impossible. */
	if (WARN_ON_ONCE(spilled_pc_size < SZ_OF_CR && PCSP_IND(stacks->pcsp) != 0 &&
			!(current->flags & PF_EXITING) && !paravirt_enabled()))
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
		dst = (u64 *) PCSP_BASE(k_pcsp);
		src = (u64 *) (PCSP_BASE(k_pcsp) + spilled_pc_size);
		collapse_kernel_pcs(regs, dst, src, spilled_pc_size);

		stacks->pcshtp.ind = SZ_OF_CR;

		apply_graph_tracer_delta(-spilled_pc_size);
	}

	if (spilled_p_size) {
		dst = (u64 *) PSP_BASE(k_psp);
		src = (u64 *) (PSP_BASE(k_psp) + spilled_p_size);
		collapse_kernel_ps(regs, dst, src, spilled_p_size);

		pshtp.ind = 0;
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
static __always_inline void native_user_hw_stacks_prepare(struct e2k_stacks *stacks,
		pt_regs_t *regs, u64 cur_window_q, enum restore_caller from, int syscall)
{
	e2k_pcshtp_t u_pcshtp = stacks->pcshtp;
	int ret;

	BUG_ON(from & FROM_PV_VCPU_MODE);

	/*
	 * 1) Make sure there is free space in kernel chain stack to return to
	 */
	if (!syscall && u_pcshtp.ind == 0) {
		unsigned long flags;
		e2k_pcsp_t u_pcsp = stacks->pcsp;
		e2k_pcsp_t k_pcsp;
		e2k_mem_crs_t __priv *u_cframe;
		e2k_mem_crs_t *k_crs;
		u64 u_cbase;
		int ret = -EINVAL;

		raw_all_irq_save(flags);
		NATIVE_FLUSHC;
		k_pcsp = read_PCSP_reg();
		BUG_ON(PCSP_IND(k_pcsp));
		k_pcsp = set_pcsp_ind(k_pcsp, SZ_OF_CR);
		write_PCSP_reg(k_pcsp);

		k_crs = (e2k_mem_crs_t *) PCSP_BASE(current_thread_info()->k_pcsp);
		u_cframe = (e2k_mem_crs_t __priv *) PCSP_PTR(u_pcsp);
		u_cbase = ((from & FROM_RETURN_PV_VCPU_TRAP) ||
				host_test_intc_emul_mode(regs)) ?
					PCSP_BASE(u_pcsp) :
					(unsigned long) CURRENT_PCS_BASE();
		if ((unsigned long) u_cframe > u_cbase) {
			ret = copy_priv_to_current_hw_stack(k_crs, u_cframe - 1,
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

		if (PCSP_IND(u_pcsp) < SZ_OF_CR) {
			update_pcsp_regs(PCSP_BASE(u_pcsp), &u_pcsp);
			stacks->pcsp = u_pcsp;
			BUG_ON(PCSP_IND(u_pcsp) < SZ_OF_CR);
		}

		u_pcshtp.ind = SZ_OF_CR;
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
	native_user_hw_stacks_prepare(stacks, regs, cur_window_q, from, syscall);
}
#elif	defined(CONFIG_KVM_GUEST_KERNEL)
/* It is virtualized guest kernel */
#include <asm/kvm/guest/copy-hw-stacks.h>
#elif	defined(CONFIG_KVM_HOST_MODE)
/* It is host kernel with virtualization support */
#include <asm/kvm/copy-hw-stacks.h>
#else /* unknow mode */
#error	"unknown virtualization mode"
#endif /* !CONFIG_VIRTUALIZATION */

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
	 * exception we uphold this rule manually, see native_user_hw_stacks_prepare())
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
		if (unlikely(PCSP_IND(stacks->pcsp) + SZ_OF_CR > PCSP_SIZE(stacks->pcsp))) {
			stacks->pcsp = incr_pcsp_ind(stacks->pcsp, SZ_OF_CR);
			ret = handle_chain_stack_bounds(stacks, regs->trap);
			stacks->pcsp = decr_pcsp_ind(stacks->pcsp, SZ_OF_CR);
			if (ret)
				return ret;
		}

		u_frame = (void __user *) PCSP_PTR(stacks->pcsp);
		ret = user_crs_frames_copy(u_frame, regs, &regs->crs);
		if (unlikely(ret))
			return ret;
	}

	return 0;
}

#endif /* _E2K_COPY_HW_STACKS_H */

