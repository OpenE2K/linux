/*
 * asm-e2k/mmu_context.h
 */
#ifndef _E2K_MMU_CONTEXT_H_
#define _E2K_MMU_CONTEXT_H_

#include <asm/mmu_regs.h>
#include <asm/page.h>
#include <asm/pgalloc.h>
#include <asm/tlbflush.h>
#include <asm/cacheflush.h>
#include <asm/secondary_space.h>
#include <asm/mmu_regs_access.h>

#undef	DEBUG_SS_MODE
#undef	DebugSS
#define	DEBUG_SS_MODE		0	/* secondary space enable */
#define DebugSS(...)		DebugPrint(DEBUG_SS_MODE ,##__VA_ARGS__)

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

#ifdef	CONFIG_SECONDARY_SPACE_SUPPORT

/*
 * Flush secondary virtual addresses in TLB & L1
 * if primary context was updated
 */
extern	inline void
flush_secondary_context(struct mm_struct *mm)
{
	if (IS_UPT_E3S) {
		/*
		 * E3S machine supports context for secondary
		 * virtual space and it is same as primary context when
		 * UPT_SUPPORT is on, so flush of primary context is 
		 * flash of both spaces
		 */
		return;
	}
	if (mm->sec_pgd == empty_sec_pg_dir) {
		/*
		 * Current proces does not use secondary space,
		 * so we have not to flush empty secondary TLB & L1
		 */
		return;
	}
	flush_TLB_all();	/* E3M arch does not flush TLB & L1 */
				/* while write to CR3 register as it */
				/* does Intel arch. Flush of all TLB do */
				/* flush of L1 */
}
#else	/* ! CONFIG_SECONDARY_SPACE_SUPPORT */
#define	flush_secondary_context(mm)	/* Nothing to do */
#endif	/* CONFIG_SECONDARY_SPACE_SUPPORT */

/*
 * Get process new MMU context. This is needed when the page table
 * pointer is changed or when the CONTEXT of the current process is updated
 * This proc is called under closed interrupts or preempt_disable()
 */

static inline unsigned long
get_new_mmu_context(struct mm_struct *mm, int num_cpu)
{
	unsigned long ctx;
	unsigned long next;

	/* Interrupts should be disabled to not bother about
	 * async-safety (calls to this function from the same
	 * CPU after it was interrupted). */

	WARN_ON_ONCE(!raw_all_irqs_disabled());

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
	} else {
		flush_secondary_context(mm);	/* flush secondary TLB */
						/* if context not used */
	}

	/* Another CPU might have written 0 to our cpu's mm context
	 * while we were getting the next context. But it is OK since
	 * we are changing the context anyway, and if this happens we
	 * will just rewrite that 0 with the new context. */
	mm->context.cpumsk[num_cpu] = next;
	my_cpu_last_context1(num_cpu) = next;

        return next;
}

/*
 * Get the process current MMU context.
 */
static inline unsigned long
get_mmu_context(struct mm_struct *mm, int cpu)
{
	unsigned long next;

	/* check if our CPU MASK is of an older generation and thus invalid: */
	next = mm->context.cpumsk[cpu];
	if (unlikely(next == 0 || CTX_VERSION(my_cpu_last_context1(cpu))
			!= CTX_VERSION(next)))
		next = get_new_mmu_context(mm, cpu);

        return next;
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
extern	inline int
init_new_context(struct task_struct *p, struct mm_struct *mm)
{
	int first_user_cui, cpu, i;

	for_each_online_cpu(cpu)
		mm->context.cpumsk[cpu] = 0;

#ifdef	CONFIG_KERNEL_CODE_CONTEXT
	first_user_cui = USER_CODES_32_INDEX;
#else	/* ! CONFIG_KERNEL_CODE_CONTEXT */
	first_user_cui = 1;
#endif	/* CONFIG_KERNEL_CODE_CONTEXT */
	atomic_set(&mm->context.cur_cui, first_user_cui);

	mm->context.mmap_position = TASK32_SIZE;
        atomic_set(&mm->context.tstart,1);
#ifdef	CONFIG_SECONDARY_SPACE_SUPPORT
	if (!IS_UPT_E3S && (p == current)) {
		/*
		 * Function is called by exec() so set secondary space
		 * page tables to initial empty state
		 */
		mm->sec_pgd = init_mm.sec_pgd;
	}
#endif	/* CONFIG_SECONDARY_SPACE_SUPPORT */

	spin_lock_init(&mm->context.hw_context_lock);
	for (i = 0; i < (1 << HW_CONTEXT_HASHBITS); i++)
		INIT_LIST_HEAD(&mm->context.hw_contexts[i]);

	atomic64_set(&mm->context.hw_context_last, 0);
	set_context_ti_key(task_thread_info(p), alloc_context_key(mm));

	return 0;
}

/*
 * Destroy a dead context.  This occurs when mmput drops the
 * mm_users count to zero, the mmaps have been released, and
 * all the page tables have been flushed.  The function job
 * is to destroy any remaining processor-specific state.
 */
extern	inline void
destroy_context(struct mm_struct *mm)
{
	/* Nothing to do.  */
}


/*
 * Force a context reload. This is needed when context is changed
 */
extern	inline void
reload_context(struct mm_struct *mm, int num_cpu)
{
	unsigned long ctx = mm->context.cpumsk[num_cpu];

	if (!ctx)
		ctx = get_new_mmu_context(mm, num_cpu);
	set_MMU_CONT(CTX_HARDWARE(ctx));
}
extern	inline void
reload_context_mask(unsigned long mask)
{
	set_MMU_CONT(CTX_HARDWARE(mask));
}
#ifdef	CONFIG_SECONDARY_SPACE_SUPPORT
/*
 * E3S supports context mechanism for secondary space,
 * so do not any flush.
 * E3M secondary space support does not use context mechanism, so
 * it needs to flush all TLB & L1 (L1 based on virtual addressing)
 * while switch from:
 *  - the process with secondary space to other process with other
 * secondary space;
 *  - the process with secondary space to the process without
 * secondary space access. In this case flushing of TLB & L1 should
 * be done only to provide interprocess virtual space protection
 */
extern	inline void
reload_secondary_context(struct mm_struct *mm)
{
	i386_pgd_t *old_dir;
	i386_pgd_t *new_dir;

	old_dir = (i386_pgd_t *)__va(get_MMU_CR3_RG());
	new_dir = mm->sec_pgd;
	if (old_dir == empty_sec_pg_dir) {
		/*
		 * Current proces does not use secondary space,
		 * so we have not to flush empty secondary TLB & L1
		 */
		return;
	}
	if (old_dir == new_dir) {
		/*
		 * New secondary space is same as current
		 * so we have not to flush the secondary TLB & L1
		 */
		return;
	}
	flush_TLB_all();	/* E3M arch does not flush TLB & L1 */
				/* while write to CR3 register as it */
				/* does Intel arch. Flush of all TLB do */
				/* flush of L1 */
}

extern	inline void
reload_secondary_page_dir(struct mm_struct *mm)
{
	i386_pgd_t *old_dir = (i386_pgd_t *)__va(get_MMU_CR3_RG());
	i386_pgd_t *new_dir = mm->sec_pgd;

	if (IS_UPT_E3S)
		/*
		 * E3S machine supports context for secondary
		 * virtual space and it is same as primary context
		 * when UPT_SUPPORT is on.
		 */
		return;

	if (old_dir == new_dir) {
		/*
		 * New secondary space is same as current
		 * so we have not to reload secondary space
		 */
		return;
	}
	reload_secondary_context(mm);
	set_MMU_CR3_RG(MMU_CR3_KERNEL(__pa(mm->sec_pgd)));
}
#else	/* ! CONFIG_SECONDARY_SPACE_SUPPORT */
#define	reload_secondary_page_dir(mm)	/* Nothing to do */
#endif	/* CONFIG_SECONDARY_SPACE_SUPPORT */

/*
 * Force a root page table pointer reload.
 */
extern	inline void
reload_root_pt(struct mm_struct *mm)
{
#ifdef	CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT
	if (!THERE_IS_DUP_KERNEL) {
		set_MMU_ROOT_PTB(__pa(mm->pgd));
	}
#else	/* ! CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */
	set_MMU_ROOT_PTB(__pa(mm->pgd));
#endif	/* CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */
	reload_secondary_page_dir(mm);
}

/*
 * Switch a root page table pointer and context.
 */
extern	inline void
reload_thread(struct mm_struct *mm)
{
	unsigned long flags;
        int num_cpu;

	preempt_disable();
        num_cpu = raw_smp_processor_id();
#ifdef	CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT
	if (THERE_IS_DUP_KERNEL) {
		spin_lock(&mm->page_table_lock);
		copy_user_pgd_to_kernel_root_pt(mm->pgd);
		spin_unlock(&mm->page_table_lock);
	}
#endif	/* CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */
	raw_all_irq_save(flags);
	reload_root_pt(mm);
	reload_context(mm, num_cpu);
	raw_all_irq_restore(flags);
	preempt_enable();
}

/*
 * Switch from address space PREV to address space NEXT.
 * interrupt was disabled by caller
 */
static inline void
do_switch_mm(struct mm_struct *prev_mm, struct mm_struct *next_mm, int cpu)
{
	unsigned long mask;

	if (likely(prev_mm != next_mm)) {
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
			 * CPU1 will send the flush ipi to CPU0, or both. */
			smp_mb__after_set_bit();
#endif

#ifdef	CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT
			/* Load user page table */
			if (THERE_IS_DUP_KERNEL) {
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
	} else {
		/* Switching between threads, nothing to do here */
	}
}

/*
 * Activate a new MM instance for the current task.
 */
static inline void activate_mm(struct mm_struct *active_mm,
		struct mm_struct *mm)
{
	unsigned long flags;

	raw_all_irq_save(flags);
	do_switch_mm(active_mm, mm, raw_smp_processor_id());
	raw_all_irq_restore(flags);
}

/*
 * Switch from address space PREV to address space NEXT.
 */
extern	inline void
switch_mm(struct mm_struct *prev_mm, struct mm_struct *next_mm,
	      struct task_struct *next)
{
	/*
	 * Switching from user process to user process is executed
	 * on common hardware stacks, so previous stacks should be
	 * flushing on mm context of previous process, then switching to the
	 * new mm context of next process and setting registers context of
	 * next process and filling hardware stacks frames from new process
	 * stacks on the new mm context.
	 * So do_switch_mm() is called by change_stk()
	 * WARNING: switch_mm() is used by sched.c function idle_task_exit()
	 * which now unused by e2k arch. If this function will be used, then
	 * switch_mm() will need to implement some other way.
	 */
}

extern void deactivate_mm(struct task_struct *dead_task, struct mm_struct *mm);
#define deactivate_mm	deactivate_mm

/*
 * Set kernel MMU state
 */
extern	inline void
set_kernel_MMU_state(void)
{
	E2K_WAIT_ALL;
	WRITE_MMU_ELB_PTB(MMU_KERNEL_ELB_PTB);
	WRITE_MMU_ROOT_PTB(kernel_va_to_pa(cpu_kernel_root_pt));
	WRITE_MMU_CONT(MMU_KERNEL_CONTEXT);
	E2K_WAIT_ALL;
}

extern	inline void
boot_set_kernel_MMU_state(void)
{
	E2K_WAIT_ALL;
	WRITE_MMU_ELB_PTB(MMU_KERNEL_ELB_PTB);
	WRITE_MMU_ROOT_PTB(MMU_KERNEL_ROOT_PTB);
	WRITE_MMU_CONT(MMU_KERNEL_CONTEXT);
	E2K_WAIT_ALL;
}

extern e2k_addr_t	pci_low_bound;
extern e2k_addr_t	phys_hi_bound_intel;
extern e2k_addr_t	phys_mpt_base;
extern e2k_addr_t	*MPT;

#ifdef	CONFIG_SECONDARY_SPACE_SUPPORT
extern i386_pgd_t	*empty_sec_pg_dir;

/*
 * Set MMU state to support secondary space
 */
extern	inline void
set_secondary_space_page_dir(struct mm_struct *mm, i386_pgd_t *page_dir)
{
	if (IS_UPT_E3S)
		return;

	if (!page_dir)
		printk("set_secondary_space_page_dir() page_dir == NULL\n");
	mm->sec_pgd = page_dir;
}
extern	inline void
reset_secondary_space_page_dir(struct mm_struct *mm)
{
	if (mm != NULL) {
		set_secondary_space_page_dir(mm, init_mm.sec_pgd);
	}
	reload_secondary_page_dir(&init_mm);
}

extern	inline void
set_upt_enable_flag(void) {

	unsigned long mmu_cr;

	mmu_cr = get_MMU_CR();
	/* Enable UPT on E3S machine */
	mmu_cr |= _MMU_CR_UPT_EN;
	set_MMU_CR(mmu_cr);
}

extern	inline void
set_secondary_space_MMU_state(struct mm_struct *mm, i386_pgd_t *page_dir)
{
	int bff_sz;
	int i;

	DebugSS("started for page dir 0x%p\n",
		page_dir);
	if (IS_UPT_E3S) {
		set_upt_enable_flag();
		return;
	}

#ifndef CONFIG_UPT_SUPPORT
	if (WARN(machine.iset_ver != ELBRUS_ISET,
			"WARNING CONFIG_UPT_SUPPORT must be set for this hardware\n"))
		return;
#endif

	if (page_dir != NULL) {
		DebugSS("will set page dir "
			"0x%p\n", page_dir);
		set_secondary_space_page_dir(mm, page_dir);
	}
	DebugSS("will reload page dir "
		"0x%p\n", page_dir);
	reload_secondary_page_dir(mm);

	DebugSS("will set PCI_L_B register "
		"to 0x%lx\n", pci_low_bound);
	set_MMU_PCI_L_B(pci_low_bound);
	DebugSS("will set PH_H_B register "
		"to 0x%lx\n", phys_hi_bound_intel);
	set_MMU_PH_H_B(phys_hi_bound_intel);

	/* Enable secondary virtual space translations */
	DebugSS("will enable secondary VS\n");
	set_MMU_CR(_MMU_CR_KERNEL | _MMU_CR_SEC_SPACE_EN);

	/* Allocate and fill MPT (Memory Protection Table) */
	if (!MPT) {
		MPT = (e2k_addr_t* )__get_free_pages(GFP_KERNEL | __GFP_ZERO,
							get_order(MPT_SIZE));
		if (!MPT) {
			printk("Can not get MPT (Memory Protection Table)\n");
			return;
		}
		bff_sz = MPT_SIZE;
		/*User INTEL pages are available*/
		memset((void *)MPT, 0xff, bff_sz);
		printk("MPT (Memory Protection Table) allocated\n");
	} else {
		printk("Using formerly allocated MPT\n");
	}
	phys_mpt_base = __pa(MPT);
	set_MMU_MPT_B(phys_mpt_base);
	printk("MPT base:0x%lx\n", phys_mpt_base);
	
	/* Zeroing 8 pairs of mtrr registers (from mtrr0 to mtrr15) */
	for (i = _MMU_MTRR_START_NO; i <= _MMU_MTRR_PAIRS_END_NO; i++)
		set_MMU_MTRR_REG(i, 0);

	/* MTRR (Memory Type Range Registers) initialization */
	set_MMU_MTRR_REG(_MMU_MTRR_END_NO, MTRR_LAST_DEFAULT);
	printk("MTRR#0x%x set to:0x%x\n",_MMU_MTRR_END_NO, MTRR_LAST_DEFAULT);
}

#else	/* ! CONFIG_SECONDARY_SPACE_SUPPORT */
#define	set_secondary_space_MMU_state(mm, page_dir)	/* Nothing to do */
#endif	/* CONFIG_SECONDARY_SPACE_SUPPORT */

extern unsigned long mremap_to(unsigned long addr, unsigned long old_len,
		unsigned long new_addr, unsigned long new_len, bool *locked);

static inline void arch_dup_mmap(struct mm_struct *oldmm,
				 struct mm_struct *mm)
{
}

extern void free_hw_contexts(struct mm_struct *mm);

static inline void arch_exit_mmap(struct mm_struct *mm)
{
	free_hw_contexts(mm);
}


#endif	/* _E2K_MMU_CONTEXT_H_ */
