/*
 * asm-e2k/mmu_context.h
 */

#ifndef _E2K_MMU_CONTEXT_H_
#define _E2K_MMU_CONTEXT_H_

#include <linux/bitmap.h>
#include <linux/bitops.h>
#include <linux/mutex.h>

#include <asm/mmu_regs.h>
#include <asm/page.h>
#include <asm/tlbflush.h>
#include <asm/cacheflush.h>
#include <asm/secondary_space.h>
#include <asm/mmu_regs_access.h>
#include <asm/mm_hooks.h>

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
 * cpu_last_context(cpuid):
 * 63                                                 0
 * +-------------------------------+------------------+
 * | asn version of this processor | hardware CONTEXT |
 * +-------------------------------+------------------+
 */

#define	CTX_HARDWARE_BITS	12
#define	CTX_HARDWARE_MASK	((1UL << CTX_HARDWARE_BITS) - 1)
#define	CTX_HARDWARE_MAX	CTX_HARDWARE_MASK
#define CTX_VERSION_SHIFT	CTX_HARDWARE_BITS
#define CTX_VERSION_SIZE	(1UL << CTX_VERSION_SHIFT)
#define CTX_VERSION_MASK	(~(CTX_VERSION_SIZE - 1))
#define	CTX_FIRST_VERSION_NUM	1UL
#define	CTX_FIRST_VERSION	(CTX_FIRST_VERSION_NUM << CTX_VERSION_SHIFT)

#define	CTX_HARDWARE(ctx)	((ctx) & CTX_HARDWARE_MASK)
#define	CTX_VERSION(ctx)	((ctx) & CTX_VERSION_MASK)

#ifdef CONFIG_SMP
#include <asm/smp.h>
//spin_lock is needed: #define cpu_last_context(cpuid)	(cpu_data[cpuid].mmu_last_context)
#define my_cpu_last_context()	(my_cpu_data.mmu_last_context)
#define my_cpu_last_context1(num_cpu)	(my_cpu_data1(num_cpu).mmu_last_context)
#else
extern unsigned long		mmu_last_context;
//#define cpu_last_context(cpuid)	mmu_last_context
#define my_cpu_last_context()	mmu_last_context
#define my_cpu_last_context1(num_cpu)	mmu_last_context
#endif /* CONFIG_SMP */

extern int arch_dup_mmap(struct mm_struct *oldmm, struct mm_struct *mm);
extern void arch_exit_mmap(struct mm_struct *mm);

static inline void
reload_context_mask(unsigned long mask)
{
	set_MMU_CONT(CTX_HARDWARE(mask));
}

/*
 * Get process new MMU context. This is needed when the page table
 * pointer is changed or when the CONTEXT of the current process is updated
 * This proc is called under closed interrupts or preempt_disable()
 */

static inline unsigned long
get_new_mmu_pid(mm_context_t *context, int num_cpu)
{
	unsigned long ctx;
	unsigned long next;

	/* Interrupts should be disabled to not bother about
	 * async-safety (calls to this function from the same
	 * CPU after it was interrupted). */

	WARN_ON_ONCE(!__raw_all_irqs_disabled());

        ctx = my_cpu_last_context1(num_cpu);
	next = ctx + 1;
	if (CTX_HARDWARE(next) == E2K_KERNEL_CONTEXT)
		next ++;
	if (CTX_VERSION(ctx) != CTX_VERSION(next)) {
		flush_TLB_all();
		flush_ICACHE_all();
		if (CTX_VERSION(next) < CTX_FIRST_VERSION) {
			next = CTX_FIRST_VERSION;
			if (CTX_HARDWARE(next) == E2K_KERNEL_CONTEXT)
				next ++;
		}
	}

	/* Another CPU might have written 0 to our cpu's mm context
	 * while we were getting the next context. But it is OK since
	 * we are changing the context anyway, and if this happens we
	 * will just rewrite that 0 with the new context. */
	context->cpumsk[num_cpu] = next;
	my_cpu_last_context1(num_cpu) = next;

        return next;
}

static inline unsigned long
get_new_mmu_context(struct mm_struct *mm, int num_cpu)
{
	return get_new_mmu_pid(&mm->context, num_cpu);
}

/*
 * Get the process current MMU context.
 */
static inline unsigned long
get_mmu_pid(mm_context_t *context, int cpu)
{
	unsigned long next;

	/* check if our CPU MASK is of an older generation and thus invalid: */
	next = context->cpumsk[cpu];
	if (unlikely(next == 0 || CTX_VERSION(my_cpu_last_context1(cpu))
			!= CTX_VERSION(next)))
		next = get_new_mmu_pid(context, cpu);

        return next;
}

static inline unsigned long
get_mmu_context(struct mm_struct *mm, int cpu)
{
	return get_mmu_pid(&mm->context, cpu);
}

/*
 * Get the process current MMU context.
 */
static inline void
copy_mmu_pid(mm_context_t *pid_to, mm_context_t *pid_from)
{
	*pid_to = *pid_from;
}

static inline void
reload_mmu_context(struct mm_struct *mm)
{
	unsigned long ctx, flags;
	int cpu;

	raw_all_irq_save(flags);
	cpu = smp_processor_id();
	ctx = get_new_mmu_context(mm, cpu);
	reload_context_mask(ctx);
	raw_all_irq_restore(flags);
}
static inline void
invalidate_mmu_context(struct mm_struct *mm)
{
	int cpu = raw_smp_processor_id();
#ifdef CONFIG_SMP
	/*
	 * Remove this cpu from mm_cpumask. This might be
	 * needed, for example, after sys_io_setup() if the
	 * kernel thread which was using this mm received
	 * flush ipi (unuse_mm() does not clear mm_cpumask).
	 * And maybe there are other such places where
	 * a kernel thread uses user mm.
	 */
	cpumask_clear_cpu(cpu, mm_cpumask(mm));
#endif
	mm->context.cpumsk[cpu] = 0;
}

extern	inline void
enter_lazy_tlb (struct mm_struct *mm, struct task_struct *tsk)
{
}

/*
 * Initialize a new mmu context.  This is invoked when a new
 * address space instance (unique or shared) is instantiated.
 * This just needs to set mm->context[] to an invalid context.
 */
static inline int
__init_new_context(struct task_struct *p, struct mm_struct *mm,
		mm_context_t *context)
{
	bool is_fork = p && (p != current);
	int ret;

	memset(&context->cpumsk, 0, nr_cpu_ids * sizeof(context->cpumsk[0]));

	if (is_fork) {
		/*
		 * Copy data on user fork
		 */
		mm_context_t *curr_context = &current->mm->context;

		/*
		 * Copy cut mask from the context of parent process
		 * to the context of new process
		 */
		mutex_lock(&curr_context->cut_mask_lock);
		bitmap_copy((unsigned long *) &context->cut_mask,
				(unsigned long *) &curr_context->cut_mask,
				USER_CUT_AREA_SIZE/sizeof(e2k_cute_t));
		mutex_unlock(&curr_context->cut_mask_lock);
	} else {
		/*
		 * Initialize by zero cut_mask of new process
		 */
		mutex_init(&context->cut_mask_lock);
		bitmap_zero((unsigned long *) &context->cut_mask,
				USER_CUT_AREA_SIZE/sizeof(e2k_cute_t));
	}

	atomic_set(&context->tstart, 1);

	init_rwsem(&context->sival_ptr_list_sem);
	INIT_LIST_HEAD(&context->sival_ptr_list_head);

	INIT_LIST_HEAD(&context->delay_free_stacks);
	init_rwsem(&context->core_lock);

	INIT_LIST_HEAD(&context->cached_stacks);
	spin_lock_init(&context->cached_stacks_lock);
	context->cached_stacks_size = 0;

	if (mm == NULL)
		return 0;

	ret = hw_contexts_init(p, context, is_fork);
	return ret;
}

static inline int
init_new_context(struct task_struct *p, struct mm_struct *mm)
{
	return __init_new_context(p, mm, &mm->context);
}

static inline int
init_new_mmu_pid(mm_context_t *context)
{
	return __init_new_context(NULL, NULL, context);
}

extern void destroy_cached_stacks(mm_context_t *context);

/*
 * Destroy a dead context.  This occurs when mmput drops the
 * mm_users count to zero, the mmaps have been released, and
 * all the page tables have been flushed.  The function job
 * is to destroy any remaining processor-specific state.
 */
static inline void destroy_context(struct mm_struct *mm)
{
	destroy_cached_stacks(&mm->context);
}


/*
 * Force a context reload. This is needed when context is changed
 */
static inline void
reload_mmu_pid(mm_context_t *context, int num_cpu)
{
	unsigned long ctx = context->cpumsk[num_cpu];

	if (!ctx)
		ctx = get_new_mmu_pid(context, num_cpu);
	set_MMU_CONT(CTX_HARDWARE(ctx));
}
static inline void
reload_context(struct mm_struct *mm, int num_cpu)
{
	reload_mmu_pid(&mm->context, num_cpu);
}

/*
 * Force a root page table pointer reload.
 */
static inline void
reload_root_pgd(pgd_t *pgd)
{
	if (MMU_IS_SEPARATE_PT()) {
		set_MMU_U_PPTB(__pa(pgd));
	} else {
#ifdef	CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT
		if (!THERE_IS_DUP_KERNEL) {
			set_MMU_U_PPTB(__pa(pgd));
		}
#else	/* ! CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */
		set_MMU_U_PPTB(__pa(pgd));
#endif	/* CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */
	}
}
extern	inline void
reload_root_pt(struct mm_struct *mm)
{
	pgd_t *pgd;

	if (mm == &init_mm) {
		pgd = cpu_kernel_root_pt;
		if ((unsigned long) pgd >= KERNEL_BASE)
			pgd = __va(kernel_va_to_pa(pgd));
	} else {
		pgd = mm->pgd;
	}
	reload_root_pgd(pgd);
}
/*
 * Force the kernel root page table pointer reload.
 */
static inline void
set_root_pt(pgd_t *root_pt)
{
	BUG_ON(MMU_IS_SEPARATE_PT());
	set_MMU_U_PPTB(__pa(root_pt));
}

/*
 * Switch a root page table pointer and context.
 */
static inline void
reload_thread(struct mm_struct *mm)
{
	unsigned long flags;
	int num_cpu;

	preempt_disable();
	num_cpu = raw_smp_processor_id();
	if (!MMU_IS_SEPARATE_PT()) {
#ifdef	CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT
		if (THERE_IS_DUP_KERNEL) {
			spin_lock(&mm->page_table_lock);
			copy_user_pgd_to_kernel_root_pt(mm->pgd);
			spin_unlock(&mm->page_table_lock);
		}
#endif	/* CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */
	}
	raw_all_irq_save(flags);
	reload_root_pt(mm);
	reload_context(mm, num_cpu);
	raw_all_irq_restore(flags);
	preempt_enable();
}

static inline void
do_switch_mm(struct mm_struct *prev_mm, struct mm_struct *next_mm,
		struct task_struct *next, int switch_pgd);

/*
 * Activate a new MM instance for the current task.
 */
static inline void
native_activate_mm(struct mm_struct *active_mm, struct mm_struct *mm)
{
	do_switch_mm(active_mm, mm, NULL, false);
}

static inline void call_switch_mm(struct mm_struct *prev_mm,
		struct mm_struct *next_mm, struct task_struct *next,
		int switch_pgd, int switch_mm)
{
	if (switch_mm || switch_pgd)
		do_switch_mm(prev_mm, next_mm, next, switch_pgd);
}

/* Virtualization support */

extern void native_deactivate_mm(struct task_struct *dead_task,
				 struct mm_struct *mm);

#include <asm/kvm/mmu_context.h>

/*
 * Switch from address space PREV to address space NEXT.
 * interrupt was disabled by caller
 */
static inline void
do_switch_mm(struct mm_struct *prev_mm, struct mm_struct *next_mm,
		struct task_struct *next, int switch_pgd)
{
	int cpu = raw_smp_processor_id();
	unsigned long flags, mask;

	if (likely(prev_mm != next_mm)) {
		raw_all_irq_save(flags);

		if (likely(next_mm)) {
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
			 * with get_new_mmu_context()	|
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
#endif

#ifdef	CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT
			/* Load user page table */
			if (!MMU_IS_SEPARATE_PT() && THERE_IS_DUP_KERNEL) {
				copy_user_pgd_to_kernel_root_pt(next_mm->pgd);
			}
#endif	/* CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */

			/* Switch context */
			reload_root_pt(next_mm);
			mask = get_mmu_context(next_mm, cpu);
			reload_context_mask(mask);
		}

#ifdef CONFIG_SMP
		/* Stop flush ipis for the previous mm */
		if (likely(prev_mm))
			cpumask_clear_cpu(cpu, mm_cpumask(prev_mm));
#endif
		raw_all_irq_restore(flags);
	} else {
		/* Switching between threads, nothing to do here */
	}
}

static inline void need_switch_mm(struct task_struct *prev,
		struct task_struct *next, struct mm_struct *oldmm,
		struct mm_struct *mm, int *switch_pgd, int *switch_mm)
{
	*switch_pgd = false;
	*switch_mm = mm != NULL;
}

/*
 * Switch from address space PREV to address space NEXT.
 */
static inline void
switch_mm(struct mm_struct *prev_mm, struct mm_struct *next_mm,
	      struct task_struct *next)
{
	int switch_pgd, switch_mm;

	need_switch_mm(current, next, prev_mm, next_mm,
			&switch_pgd, &switch_mm);
	BUG_ON(switch_mm && switch_pgd);

	call_switch_mm(prev_mm, next_mm, next, switch_pgd, switch_mm);
}

/*
 * Set kernel MMU state
 */
static inline void
set_kernel_MMU_state(void)
{
	e2k_addr_t root_base = kernel_va_to_pa(cpu_kernel_root_pt);

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
extern	inline void
set_secondary_space_MMU_state(void)
{
	unsigned long mmu_cr;

	mmu_cr = get_MMU_CR();
	mmu_cr |= _MMU_CR_UPT_EN;
	if (machine.native_iset_ver >= E2K_ISET_V5)
		mmu_cr |= _MMU_CR_SNXE;
	set_MMU_CR(mmu_cr);
}
#else	/* ! CONFIG_SECONDARY_SPACE_SUPPORT */
#define	set_secondary_space_MMU_state()
#endif	/* CONFIG_SECONDARY_SPACE_SUPPORT */

extern void makecontext_trampoline_switched(void);

#endif	/* _E2K_MMU_CONTEXT_H_ */
