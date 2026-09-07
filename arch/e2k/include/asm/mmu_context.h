/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * asm-e2k/mmu_context.h
 */

#ifndef _E2K_MMU_CONTEXT_H_
#define _E2K_MMU_CONTEXT_H_

#include <linux/bitmap.h>
#include <linux/bitops.h>
#include <linux/mutex.h>

#include <asm/alternative.h>
#include <asm/mmu_regs.h>
#include <asm/page.h>
#include <asm/tlbflush.h>
#include <asm/cacheflush.h>
#include <asm/secondary_space.h>
#include <asm/mmu_regs_access.h>
#include <asm/mm_hooks.h>
#include <asm/pgtable.h>

/*
 * The high bits of the "context_cache" (and the "mm->context") are the
 * CONTEXT _version_ code. A version of 0 is always considered invalid,
 * so to invalidate another process only need to do "p->mm->context = 0".
 *
 * If more CONTEXT's than the processor has is needed, it invalidates all
 * TLB's ('flush_tlb_all()') and starts a new CONTEXT version.
 * That will automatically force a new CONTEXT for any other processes
 * the next time they want to run.
 *
 * last_mmu_context(cpuid):
 * 63                                                 0
 * +-------------------------------+------------------+
 * | ctx version of this processor | hardware CONTEXT |
 * +-------------------------------+------------------+
 */

#define	CTX_HARDWARE_BITS	12
#define	CTX_HARDWARE_MASK	((1ULL << CTX_HARDWARE_BITS) - 1)
#define	CTX_HARDWARE_MAX	CTX_HARDWARE_MASK
#define CTX_VERSION_SHIFT	CTX_HARDWARE_BITS
#define CTX_VERSION_SIZE	(1ULL << CTX_VERSION_SHIFT)
#define CTX_VERSION_MASK	(~(CTX_VERSION_SIZE - 1))
#define	CTX_FIRST_VERSION_NUM	1ULL
#define	CTX_FIRST_VERSION	(CTX_FIRST_VERSION_NUM << CTX_VERSION_SHIFT)

#define	CTX_HARDWARE(ctx)	((ctx) & CTX_HARDWARE_MASK)
#define	CTX_VERSION(ctx)	((ctx) & CTX_VERSION_MASK)
#define	CTX_VERSION_NO(ctx)	(CTX_VERSION(ctx) >> CTX_VERSION_SHIFT)

DECLARE_PER_CPU(u64, last_mmu_context);
/* This is the current context value - i.e. the value that
 * should go into %pid before trying to access userspace. */
register u64 current_mmu_context ASM_GREG(CURRENT_MMU_CONTEXT_GREG);
/* User PT base cached for fast retrieval in uaccess_enable() */
register u64 u_root_ptb ASM_GREG(U_ROOT_PTB_GREG);

extern u64 get_new_mmu_pid_irqs_off(mm_context_t *context);

/*
 * Force a context reload. This is needed when context is changed
 */
enum reload_pid_mode {
	/* Force calculation of a new %pid value */
	MMU_PID_RELOAD_FORCED,
	/* Get a new %pid on flush (i.e. ctx == 0) or version mismatch
	 * (can happen if the task hasn't been executing for some time
	 * and other tasks exhausted all 10 bits of %pid register). */
	MMU_PID_RELOAD_CHECK,
	/* *__NO_UPDATE versions do _not_ update the cached value in
	 * current_mmu_context.  This is useful when we want to switch
	 * to guest's %pid value but keep the qemu's cached pid value
	 * intact in 'per_cpu(last_mmu_context)' (i.e. always when we
	 * work with gmm_context and are not inside light hypercall). */
	MMU_PID_RELOAD_FORCED__NO_UPDATE,
	MMU_PID_RELOAD_CHECK__NO_UPDATE,
};

static __always_inline u64 get_mmu_pid_irqs_off_impl(mm_context_t *context,
		enum reload_pid_mode mode, u64 ctx, u64 last_ctx)
{
	bool get_new_context;

	BUILD_BUG_ON(mode != MMU_PID_RELOAD_FORCED &&
		     mode != MMU_PID_RELOAD_FORCED__NO_UPDATE &&
		     mode != MMU_PID_RELOAD_CHECK &&
		     mode != MMU_PID_RELOAD_CHECK__NO_UPDATE);

	/* Interrupts should be disabled to not bother about
	 * async-safety (calls to this function from the same
	 * CPU after it was interrupted). */
	VM_BUG_ON(!psr_and_upsr_all_irqs_disabled());

	if (mode == MMU_PID_RELOAD_FORCED ||
			mode == MMU_PID_RELOAD_FORCED__NO_UPDATE) {
		get_new_context = true;
	} else if (mode == MMU_PID_RELOAD_CHECK ||
			mode == MMU_PID_RELOAD_CHECK__NO_UPDATE) {
		get_new_context = (CTX_VERSION(ctx) != CTX_VERSION(last_ctx));
	} else {
		BUILD_BUG();
	}

	if (unlikely(get_new_context))
		ctx = get_new_mmu_pid_irqs_off(context);

	if (mode != MMU_PID_RELOAD_CHECK__NO_UPDATE &&
			mode != MMU_PID_RELOAD_FORCED__NO_UPDATE)
		current_mmu_context = ctx;

	return ctx;
}

/**
 * get_mmu_pid_irqs_off - update %pid register value in @context structure
 * @context: mm_context_t that holds current PID/CONT
 * @mode: whether to force allocation of a new pid, or try to
 *	  use the previous one
 */
static __always_inline u64 get_mmu_pid_irqs_off(mm_context_t *context,
		enum reload_pid_mode mode)
{
	u64 ctx = context->cpumsk[smp_processor_id()];
	u64 last_ctx = raw_cpu_read(last_mmu_context);

	return get_mmu_pid_irqs_off_impl(context, mode, ctx, last_ctx);
}

/* Same as get_mmu_pid_irqs_off() but without CONFIG_PREEMPT debugging
 * since it won't work in kernel entry code. */
static __always_inline u64 raw_get_mmu_pid_irqs_off(mm_context_t *context,
	enum reload_pid_mode mode)
{
	u64 ctx = context->cpumsk[raw_smp_processor_id()];
	u64 last_ctx = raw_cpu_read(last_mmu_context);

	return get_mmu_pid_irqs_off_impl(context, mode, ctx, last_ctx);
}

/**
 * flush_mmu_pid - drop current %pid register value for @context
 * @context: mm_context_t that holds current PID/CONT
 *
 * This function drops currently used %pid value which is useful
 * for doing a full TLB flush of the passed context.  The next
 * %pid value to use will be allocated when we actually switch
 * to user's VM space - i.e. in get_user/etc or when returning
 * from kernel to user.
 */
static inline void flush_mmu_pid(mm_context_t *context)
{
	unsigned long flags;

	raw_all_irq_save(flags);
	get_mmu_pid_irqs_off(context, MMU_PID_RELOAD_FORCED);
	if (cpu_has(CPU_FEAT_SVSC)) {
		WRITE_UACCESS_REGS_CACHED();
	}
	raw_all_irq_restore(flags);

	/* We are currently executing with E2K_KERNEL_CONTEXT and the
	 * new %pid value will be written only when actually needed
	 * (when !CPU_FEAT_SVSC). */
	VM_BUG_ON((READ_MMU_PID() != E2K_KERNEL_CONTEXT) == !cpu_has(CPU_FEAT_SVSC));
}

/**
 * reload_root_pgd - change the active pgd for current guest's task.
 * @pgd: page table root to switch to
 *
 * IMPORTANT: for usage in light hypercalls only as this switches %u_root_ptb
 */
static inline void reload_root_pgd(const pgd_t *pgd)
{
	/* Kernel executes with user pgd loaded to register but
	 * disabled through OS_VAB, so we can just update the register. */
	WRITE_MMU_U_PPTB(__pa(pgd));
}

/*
 * Please ignore the name of this function.  It should be called
 * switch_to_kernel_thread().
 *
 * enter_lazy_tlb() is a hint from the scheduler that we are entering a
 * kernel thread or other context without an mm.  Acceptable implementations
 * include doing nothing whatsoever, switching to init_mm, or various clever
 * lazy tricks to try to minimize TLB flushes.
 *
 * The scheduler reserves the right to call enter_lazy_tlb() several times
 * in a row.  It will notify us that we're going back to a real mm by
 * calling switch_mm_irqs_off().
 */
static inline void enter_lazy_tlb(struct mm_struct *prev_mm,
		struct task_struct *tsk)
{
	pgd_t *os_page_table = mm_node_pgd(&init_mm, numa_node_id());

	VM_BUG_ON(!oops_in_progress && !cpu_has(CPU_FEAT_SVSC) &&
		  READ_MMU_PID() != E2K_KERNEL_CONTEXT);

	/* Make sure that kernel threads execute with kernel page tables */
	u_root_ptb = __pa(os_page_table);
	current_mmu_context = E2K_KERNEL_CONTEXT;

	if (cpu_has(CPU_FEAT_SVSC)) {
		WRITE_UACCESS_REGS_CACHED();
	}
}

extern int __init_new_context(struct task_struct *p, struct mm_struct *mm,
		mm_context_t *context);
static inline int init_new_context(struct task_struct *p, struct mm_struct *mm)
{
	return __init_new_context(p, mm, &mm->context);
}
extern void destroy_cached_stacks(mm_context_t *context);
extern void destroy_context(struct mm_struct *mm);

extern e2k_mmu_cr_t svsc_save(void);
extern void svsc_restore(e2k_mmu_cr_t mmu_cr);

struct uaccess_regs {
	u64 u_root_ptb;
	u64 ctx;
};

/*
 * For specific use case in light hypercalls: if we are executing with
 * guest user's values for uac_regs and do not want to corrupt them,
 * instead of uaccess_enable() + uaccess_disable() pair one should use:
 *
 *   struct uaccess_regs regs;
 *   native_uaccess_save(&regs);
 *   < ... >
 *   native_uaccess_restore(&regs);
 */
static inline void native_uaccess_save(struct uaccess_regs *ua_regs)
{
	if (cpu_has(CPU_FEAT_SVSC))
		return;

	ua_regs->u_root_ptb = NATIVE_READ_MMU_U_PPTB_REG();
	ua_regs->ctx = READ_MMU_PID();
}

static inline void native_uaccess_restore(const struct uaccess_regs *ua_regs)
{
	if (cpu_has(CPU_FEAT_SVSC))
		return;

	WRITE_UACCESS_REGS(ua_regs->ctx, ua_regs->u_root_ptb);
}

/*
 * uaccess_enable()/uaccess_disable() are for use
 * in get_user()/put_user()/return to user/etc
 */
static inline void native_uaccess_enable(void)
{
	if (cpu_has(CPU_FEAT_SVSC)) {
		/*
		 * UACCESS_FN_CALL() API assumes that all page faults happen
		 * in the called function.  This means that compiler must not
		 * move semi-spec. load at a potentially bad address inside
		 * the uaccess_{en/dis}able() critical section.
		 *
		 * To achieve it uaccess_{en/dis}able() themselves must be
		 * compiler barriers, and for that *every* path in them must
		 * contain such a barrier.
		 */
		barrier();
		return;
	}

	/* Sometimes functions that access user memory are called
	 * from kernel threads without mm, for example:
	 *     devtmpfsd -> ksys_mount -> strndup_user
	 * So check `current_mmu_context` value only under (mm != NULL) condition. */
	VM_BUG_ON(!oops_in_progress &&
		  (READ_MMU_PID() != E2K_KERNEL_CONTEXT ||
		   u_root_ptb == ULL(-1) ||
		   current->mm && CTX_HARDWARE(current_mmu_context) == E2K_KERNEL_CONTEXT));

	WRITE_UACCESS_REGS_CACHED();
}

static inline void native_uaccess_disable(void)
{
	u64 k_root_ptb;

	if (cpu_has(CPU_FEAT_SVSC)) {
		/* See comment in uaccess_enable() */
		barrier();
		return;
	}

	VM_BUG_ON(current->mm && READ_MMU_PID() == E2K_KERNEL_CONTEXT);
#ifndef CONFIG_MMU_SEP_VIRT_SPACE_ONLY
	k_root_ptb = MMU_IS_SEPARATE_PT() ? NATIVE_READ_MMU_OS_PPTB_REG()
					      : current->thread.regs.k_root_ptb;
#else
	k_root_ptb = NATIVE_READ_MMU_OS_PPTB_REG();
#endif
	VM_BUG_ON(k_root_ptb == ULL(-1));
	WRITE_UACCESS_REGS(E2K_KERNEL_CONTEXT, k_root_ptb);
}

/*
 * Kernel trap handler could have been entered from inside of get/put_user(),
 * in which case we must enable user page tables before exiting handler.
 */
static inline void uaccess_enable_in_kernel_trap(const struct pt_regs *regs)
{
	if (cpu_has(CPU_FEAT_SVSC))
		return;

	u64 ctx = regs->uaccess.cont;
	u64 root_ptb = regs->uaccess.u_root_ptb;

	if (unlikely(ctx != E2K_KERNEL_CONTEXT)) {
		/* User context could have changed while we were
		 * executing with kernel context, update it. */
		ctx = current_mmu_context;
		VM_BUG_ON(CTX_HARDWARE(ctx) == E2K_KERNEL_CONTEXT);
	}
	WRITE_UACCESS_REGS(ctx, root_ptb);
}

/*
 * Force the kernel root page table pointer reload.
 */
static inline void
set_root_pt(pgd_t *root_pt)
{
	WRITE_MMU_U_PPTB(__pa(root_pt));
	if (MMU_IS_SEPARATE_PT())
		WRITE_MMU_OS_PPTB(__pa(root_pt));
}

/*
 * Switch a root page table pointer and context.
 *
 * This also flushes TLB so is more suitable for cases when
 * we switch to a context that might overlap with the previous
 * one (e.g. hibernation)
 */
static inline void reload_thread(struct mm_struct *mm)
{
	unsigned long flags;

	raw_all_irq_save(flags);

	/* %root_ptb/%cont are switched on kernel entry
	 * and exit, so there is nothing to do here. */
	(void) get_mmu_pid_irqs_off(&mm->context, MMU_PID_RELOAD_FORCED);
	if (cpu_has(CPU_FEAT_SVSC)) {
		WRITE_UACCESS_REGS_CACHED();
	}

	/* Normally this is not needed when switching contexts
	 * but hibernation is a special case. */
	local_flush_tlb_all();

	raw_all_irq_restore(flags);
}

/* Virtualization support */

extern void native_deactivate_mm(struct task_struct *dead_task,
				 struct mm_struct *mm);

#include <asm/kvm/mmu_context.h>

/*
 * Switch from address space PREV to address space NEXT.
 * interrupt was disabled by caller
 */
static inline void switch_mm(struct mm_struct *prev_mm,
		struct mm_struct *next_mm, struct task_struct *next)
{
	unsigned long flags;
	int cpu, node;
	pgd_t *pgd;

	raw_all_irq_save(flags);
	node = numa_node_id();
	cpu = raw_smp_processor_id();
	pgd = mm_node_pgd(next_mm, node);

	if (prev_mm == next_mm) {
		/* Switching between threads.
		 * We can get here after several enter_lazy_tlb() calls,
		 * so just reload values that are cleared there:
		 *  - get_mmu_pid_irqs_off() reloads current_mmu_context;
		 *  - u_root_ptb can be loaded from mm. */
		goto skip_mm_cpumask;
	}

#ifdef CONFIG_SMP
	/* Start receiving flush ipis for the next mm */
	cpumask_set_cpu(cpu, mm_cpumask(next_mm));

	/* Without a memory barrier, a following race can happen
	 * (CPU0 executes switch_mm, CPU1 executes flush_tlb):
	 *
	 * -----------------------------+-----------------------
	 * 		CPU0		|	CPU1
	 * -----------------------------+-----------------------
	 * read next_mm->context	|
	 * for CPU0			|
	 *				| set next_mm->context
	 *				| for CPU0 to 0
	 * the loaded value has older	|
	 * context version -> update it	|
	 * with get_new_mmu_pid()	|
	 * -> 0 in next_mm->context	| execute memory barrier
	 * is rewritten			|
	 *				| CPU0 is not set in
	 *				| mm_cpumask(next_mm),
	 *				| so ipi's not send
	 * set CPU0 bit in		|
	 * mm_cpumask(next_mm)		|
	 * -----------------------------+-----------------------
	 *
	 * To avoid the races both CPU1 and CPU0 execute memory
	 * barriers:
	 * -----------------------------+-----------------------
	 * 		CPU0		|	CPU1
	 * -----------------------------+-----------------------
	 * set CPU0 bit in		| set next_mm->context
	 * mm_cpumask(next_mm)		| for CPU0 to 0
	 *				|
	 * execute memory barrier	| execute memory barrier
	 *				|
	 * read next_mm->context	| CPU0 is not set in
	 * for CPU0			| mm_cpumask(next_mm),
	 *				| so ipi's not send
	 * -----------------------------+-----------------------
	 * This way either CPU0 will see 0 in next_mm or
	 * CPU1 will send the flush ipi to CPU0, or both.
	 *
	 * This barrier could be smp_mb__after_atomic(), but
	 * the membarrier syscall requires a full memory
	 * barrier after storing to rq->curr, before going
	 * back to user-space.
	 */
	smp_mb();

	/* Stop flush ipis for the previous mm */
	if (prev_mm)
		cpumask_clear_cpu(cpu, mm_cpumask(prev_mm));
#endif

skip_mm_cpumask:
	/* Switch context */
	get_mmu_pid_irqs_off(&next_mm->context, MMU_PID_RELOAD_CHECK);
	u_root_ptb = __pa(pgd);
	if (cpu_has(CPU_FEAT_SVSC)) {
		WRITE_UACCESS_REGS_CACHED();
	}

	raw_all_irq_restore(flags);
}

/*
 * Activate a new MM instance for the current task.
 */
static inline void
native_activate_mm(struct mm_struct *active_mm, struct mm_struct *mm)
{
	switch_mm(active_mm, mm, current);
}

/*
 * Set kernel MMU state
 */
static inline void
set_kernel_MMU_state(void)
{
	e2k_addr_t root_base = __pa_symbol(swapper_pg_dir);

	E2K_WAIT_ALL;
	if (MMU_IS_SEPARATE_PT()) {
		BUILD_BUG_ON(MMU_SEPARATE_KERNEL_VAB != PAGE_OFFSET);
		WRITE_MMU_OS_VPTB(MMU_SEPARATE_KERNEL_VPTB);
		WRITE_MMU_OS_PPTB(root_base);
		WRITE_MMU_OS_VAB(MMU_SEPARATE_KERNEL_VAB);
		WRITE_MMU_CONT(MMU_KERNEL_CONTEXT);
	} else {
		WRITE_MMU_U_VPTB(MMU_UNITED_KERNEL_VPTB);
		WRITE_MMU_U_PPTB(root_base);
		WRITE_MMU_CONT(MMU_KERNEL_CONTEXT);
	}
	E2K_WAIT_ALL;
}

#ifdef	CONFIG_SECONDARY_SPACE_SUPPORT
static inline void set_secondary_space_MMU_state(void)
{
	e2k_mmu_cr_t mmu_cr = get_MMU_CR();
	mmu_cr.upt = 1;
	if (machine.native_iset_ver >= E2K_ISET_V5) {
		mmu_cr.snxe = 1;
	}
	set_MMU_CR(mmu_cr);
}
#else	/* ! CONFIG_SECONDARY_SPACE_SUPPORT */
#define	set_secondary_space_MMU_state()
#endif	/* CONFIG_SECONDARY_SPACE_SUPPORT */

#endif	/* _E2K_MMU_CONTEXT_H_ */
