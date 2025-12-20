/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * MMU menegement (Instruction and Data caches, TLB, registers)
 *
 * Derived heavily from Linus's Alpha/AXP ASN code...
 */

#include <linux/debugfs.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/pgtable.h>
#include <linux/ratelimit.h>
#include <linux/sizes.h>
#include <linux/slab.h>

#include <asm/types.h>
#include <asm/mmu_regs.h>
#include <asm/page.h>
#include <asm/pgalloc.h>
#include <asm/process.h>
#include <asm/mmu_context.h>
#include <asm/process.h>
#include <asm/secondary_space.h>
#include <asm/sic_regs.h>
#include <asm/p2v/boot_map.h>
#include <asm/secondary_space.h>

#define CREATE_TRACE_POINTS
#include "trace-tlb-flush.h"
#include <asm/trace-tlb-flush.h>

#undef	DEBUG_IC_MODE
#undef	DebugIC
#define	DEBUG_IC_MODE		0	/* Instruction Caches */
#define DebugIC(...)		DebugPrint(DEBUG_IC_MODE ,##__VA_ARGS__)

#undef	DEBUG_PT_MODE
#undef	DebugPT
#define	DEBUG_PT_MODE		0	/* Data Caches */
#define DebugPT(...)		DebugPrint(DEBUG_PT_MODE ,##__VA_ARGS__)

u64 kernel_voffset __ro_after_init;
EXPORT_SYMBOL(kernel_voffset);

/*
 * Hardware MMUs page tables have some differences from one ISET to other
 * moreover each MMU supports a few different page tables:
 *	native (primary)
 *	secondary page tables for sevral modes (VA32, VA48, PA32, PA48 ...)
 * The follow structure presents native page table structure
 *
 * Warning .boot_*() entries should be updated dinamicaly to point to
 * physical addresses of functions for arch/e2k/p2v/
 */
pt_struct_t __ro_after_init pgtable_struct = {
	.type		= E2K_PT_TYPE,
	.pt_v6		= false,	/* as default for compatibility */
	.pfn_mask	= _PAGE_PFN_V3,
	.accessed_mask	= _PAGE_A_V3,
	.dirty_mask	= _PAGE_D_V3,
	.present_mask	= _PAGE_P_V3,
	.user_mask	= 0ULL,
	.priv_mask	= _PAGE_PV_V3,
	.non_exec_mask	= _PAGE_NON_EX_V3,
	.exec_mask	= 0ULL,
	.huge_mask	= _PAGE_HUGE_V3,
	.protnone_mask	= _PAGE_PROTNONE_V3,
	.sw_bit1_mask	= _PAGE_AVAIL_BIT_V3,
	.sw_bit2_mask	= _PAGE_SW2_V3,
	.levels_num	= E2K_PT_LEVELS_NUM,
	.levels		= {
		[E2K_PAGES_LEVEL_NUM] = {
			.id		= E2K_PAGES_LEVEL_NUM,
			.page_size	= PAGE_SIZE,
		},
		[E2K_PTE_LEVEL_NUM] = {
			.id		= E2K_PTE_LEVEL_NUM,
			.pt_size	= PTE_SIZE,
			.page_size	= PAGE_SIZE,
			.pt_shift	= PTE_SHIFT,
			.page_shift	= PTE_SHIFT,
			.pt_mask	= PTE_MASK & _PAGE_PFN_V3,
			.pt_offset	= ~PTE_MASK & _PAGE_PFN_V3,
			.pt_index_mask	= PTE_MASK ^ PMD_MASK,
			.page_mask	= PTE_MASK,
			.page_offset	= ~PTE_MASK,
			.ptrs_per_pt	= PTRS_PER_PTE,
			.is_pte		= true,
			.is_huge	= false,
			.dtlb_type	= COMMON_DTLB_TYPE,
		},
		[E2K_PMD_LEVEL_NUM] = {
			.id		= E2K_PMD_LEVEL_NUM,
			.pt_size	= PMD_SIZE,
			.pt_shift	= PMD_SHIFT,
			.pt_mask	= PMD_MASK & _PAGE_PFN_V3,
			.pt_offset	= ~PMD_MASK & _PAGE_PFN_V3,
			.pt_index_mask	= PMD_MASK ^ PUD_MASK,
			.ptrs_per_pt	= PTRS_PER_PMD,
#if	CONFIG_CPU_ISET_MIN >= 3
			.page_size	= E2K_2M_PAGE_SIZE,
			.page_shift	= PMD_SHIFT,
			.page_offset	= ~PMD_MASK,
#elif	!defined CONFIG_E2K_MACHINE
			/* page size and functions should be set dinamicaly */
			.page_size	= -1,
#else
# warning "Undefined CPU ISET VERSION #, PAGE SIZE not defined"
			.page_size	= -1,
#endif
			.is_pte		= false,
			.is_huge	= true,
			.dtlb_type	= COMMON_DTLB_TYPE,
		},
		[E2K_PUD_LEVEL_NUM] = {
			.id		= E2K_PUD_LEVEL_NUM,
			.pt_size	= PUD_SIZE,
			.page_size	= PAGE_PUD_SIZE,
			.pt_shift	= PUD_SHIFT,
			.page_shift	= PUD_SHIFT,
			.pt_mask	= PUD_MASK & _PAGE_PFN_V3,
			.pt_offset	= ~PUD_MASK & _PAGE_PFN_V3,
			.pt_index_mask	= PUD_MASK ^ PGDIR_MASK,
			.page_mask	= PUD_MASK,
			.page_offset	= ~PUD_MASK,
			.ptrs_per_pt	= PTRS_PER_PUD,
			.is_pte		= false,
#if	CONFIG_CPU_ISET_MIN >= 5
			.is_huge	= true,
			.dtlb_type	= FULL_ASSOCIATIVE_DTLB_TYPE,
#elif	CONFIG_CPU_ISET_MIN >= 3 && defined CONFIG_E2K_MACHINE
			.is_huge	= false,
#elif	!defined CONFIG_E2K_MACHINE
			/* huge page enable should be set dinamicaly */
			.is_huge	= false,
#else	/* CONFIG_CPU_ISET_MIN undefined or negative */
# warning "Undefined CPU ISET VERSION #, huge page enable not defined"
			.is_huge	= false,
#endif

		},
		[E2K_PGD_LEVEL_NUM] = {
			.id		= E2K_PGD_LEVEL_NUM,
			.pt_size	= PGDIR_SIZE,
			.page_size	= PAGE_PGD_SIZE,
			.pt_shift	= PGDIR_SHIFT,
			.page_shift	= PGDIR_SHIFT,
			.pt_mask	= PGDIR_MASK & E2K_VA_MASK,
			.pt_offset	= ~PGDIR_MASK & E2K_VA_MASK,
			.pt_index_mask	= PGDIR_MASK & E2K_VA_MASK,
			.page_mask	= PGDIR_MASK,
			.page_offset	= ~PGDIR_MASK,
			.ptrs_per_pt	= PTRS_PER_PGD,
			.is_pte		= false,
			.is_huge	= false,
		},
	},
};
EXPORT_SYMBOL(pgtable_struct);


/*
 * CACHES flushing:
 */

static void __write_back_cache_L3(void)
{
	unsigned long flags;
	l3_ctrl_t l3_ctrl;
	int node;

	raw_all_irq_save(flags);
	node = numa_node_id();

	/* Set bit of L3 control register to flush L3 */
	AW(l3_ctrl) = sic_read_node_nbsr_reg(node, SIC_l3_ctrl);
	AS(l3_ctrl).fl = 1;
	sic_write_node_nbsr_reg(node, SIC_l3_ctrl, AW(l3_ctrl));

	/* Wait for flush completion */
	if (cpu_has(CPU_FEAT_ISET_V5)) {
		do {
			AW(l3_ctrl) = sic_read_node_nbsr_reg(node, SIC_l3_ctrl);
		} while (AS(l3_ctrl).fl);
	} else {
		l3_reg_t l3_diag;

		l3_diag = sic_read_node_nbsr_reg(node, SIC_l3_b0_diag_dw);
		l3_diag = sic_read_node_nbsr_reg(node, SIC_l3_b1_diag_dw);
		l3_diag = sic_read_node_nbsr_reg(node, SIC_l3_b2_diag_dw);
		l3_diag = sic_read_node_nbsr_reg(node, SIC_l3_b3_diag_dw);
		l3_diag = sic_read_node_nbsr_reg(node, SIC_l3_b4_diag_dw);
		l3_diag = sic_read_node_nbsr_reg(node, SIC_l3_b5_diag_dw);
		l3_diag = sic_read_node_nbsr_reg(node, SIC_l3_b6_diag_dw);
		l3_diag = sic_read_node_nbsr_reg(node, SIC_l3_b7_diag_dw);

		__E2K_WAIT_ALL;
	}

	raw_all_irq_restore(flags);
}

static void write_back_cache_all_ipi(void *unused)
{
	int cpu, node;

	write_back_CACHE_L12();

	cpu = smp_processor_id();
	node = numa_node_id();
	if (machine.L3_enable && cpu == cpumask_first(cpumask_of_node(node)))
		__write_back_cache_L3();
}

/*
 * Write Back and Invalidate all caches in the system
 */
void write_back_cache_all(void)
{
	/*
	 * This is rather low-level function
	 * so do not use on_each_cpu() here.
	 */
	nmi_on_each_cpu(write_back_cache_all_ipi, NULL, 1, 0);
}
EXPORT_SYMBOL(write_back_cache_all);

void write_back_cache_range(unsigned long start, size_t size)
{
	/* Some arbitrary condition */
	if (size < SZ_64K)
		flush_DCACHE_range((void *) start, size);
	else
		write_back_cache_all();
}


/*
 * Write Back and Invalidate all caches for current cpu
 */
void local_write_back_cache_all(void)
{
	migrate_disable();
	write_back_CACHE_L12();
	if (machine.L3_enable) {
		__write_back_cache_L3();
	}
	migrate_enable();
}

void local_write_back_cache_range(unsigned long start, size_t size)
{
	/* Some arbitrary condition */
	if (size < SZ_64K)
		flush_DCACHE_range((void *) start, size);
	else
		local_write_back_cache_all();
}

/*
 *  Invalidate all ICACHES of the host processor
 */
void native_flush_icache_all(void)
{
	DebugIC("started flush_icache_all()\n");
	flush_ICACHE_all();
}

/*
 * Flush a specified range of addresses of specified context
 * from ICACHE of the processor
 */
void
flush_icache_other_range(e2k_addr_t start, e2k_addr_t end,
	unsigned long context)
{
	e2k_addr_t addr;

	preempt_disable();
	DebugIC("started: start 0x%lx end 0x%lx context 0x%lx\n",
		start, end, context);

	/*
	 * It is better to flush_ICACHE_all() if flush range is very big.
	 */
	if ((end - start) / E2K_ICACHE_SET_SIZE > E2K_ICACHE_LINES_NUM) {
		DebugIC("will flush_ICACHE_all()\n");
		flush_ICACHE_all();
		preempt_enable();
		return;
	}

	flush_ICACHE_line_begin();
	for (addr = round_down(start, E2K_ICACHE_SET_SIZE);
			addr < round_up(end, E2K_ICACHE_SET_SIZE);
			addr += E2K_ICACHE_SET_SIZE) {
		DebugIC("will flush_ICACHE_line_sys() 0x%lx\n",
			addr);
		__flush_ICACHE_line_sys(addr, CTX_HARDWARE(context));
	}
	flush_ICACHE_line_end();

	DebugIC("finished: start 0x%lx end 0x%lx context 0x%lx\n",
		start, end, context);
	preempt_enable();
}

/*
 * Flush a specified range of addresses of kernel from ICACHE
 * of the processor
 *
 * When function tracing is patched in/out for this function
 * then patched instruction will execute before flushing
 * icache (obviously); the behaviour is correct in this case
 * since code edit is atomic but it causes spurious warnings
 * from simulator, so add `notrace`.
 */
notrace
void native_flush_icache_range(e2k_addr_t start, e2k_addr_t end)
{
	e2k_addr_t addr;

	DebugIC("started: start 0x%lx end 0x%lx\n", start, end);

	start = round_down(start, E2K_ICACHE_SET_SIZE);
	end = round_up(end, E2K_ICACHE_SET_SIZE);

	flush_DCACHE_line_begin();
	for (addr = start; addr < end; addr += E2K_ICACHE_SET_SIZE) {
		DebugIC("will flush_DCACHE_line() 0x%lx\n", addr);
		__flush_DCACHE_line(addr);
	}
	flush_DCACHE_line_end();
	E2K_FLUSH_PIPELINE();

	DebugIC("finished: start 0x%lx end 0x%lx\n", start, end);
}
EXPORT_SYMBOL(native_flush_icache_range);

/*
 * Flush an array of a specified range of addresses of specified context from
 * ICACHE of the processor
 */

void native_flush_icache_range_array(icache_range_array_t *icache_range_arr)
{
	int i;
	unsigned long context;
	int cpu = smp_processor_id();

	context = icache_range_arr->mm->context.cpumsk[cpu];

	DebugIC("started: icache_range_arr 0x%lx\n", icache_range_arr);
	if (context) {
		for (i = 0; i < icache_range_arr->count; i++) {
			icache_range_t icache_range =
				icache_range_arr->ranges[i];
			flush_icache_other_range(
					icache_range.start,
					icache_range.end,
					context);
		}
	} else if (icache_range_arr->mm == current->active_mm) {
		flush_mmu_pid(&icache_range_arr->mm->context);
		E2K_FLUSH_PIPELINE();
	}
	DebugIC("finished: icache_range_arr 0x%lx\n", icache_range_arr);
}

/*
 * Flush just one specified page from ICACHE of all processors
 */
void native_flush_icache_page(struct vm_area_struct *vma, struct page *page)
{
	unsigned long start = (e2k_addr_t) page_address(page);

	BUILD_BUG_ON(PAGE_SIZE != 16 * E2K_ICACHE_SET_SIZE);

	flush_DCACHE_line_begin();
	__flush_DCACHE_line(start);
	__flush_DCACHE_line_offset(start, E2K_ICACHE_SET_SIZE);
	__flush_DCACHE_line_offset(start, 2 * E2K_ICACHE_SET_SIZE);
	__flush_DCACHE_line_offset(start, 3 * E2K_ICACHE_SET_SIZE);
	__flush_DCACHE_line_offset(start, 4 * E2K_ICACHE_SET_SIZE);
	__flush_DCACHE_line_offset(start, 5 * E2K_ICACHE_SET_SIZE);
	__flush_DCACHE_line_offset(start, 6 * E2K_ICACHE_SET_SIZE);
	__flush_DCACHE_line_offset(start, 7 * E2K_ICACHE_SET_SIZE);
	__flush_DCACHE_line_offset(start, 8 * E2K_ICACHE_SET_SIZE);
	__flush_DCACHE_line_offset(start, 9 * E2K_ICACHE_SET_SIZE);
	__flush_DCACHE_line_offset(start, 10 * E2K_ICACHE_SET_SIZE);
	__flush_DCACHE_line_offset(start, 11 * E2K_ICACHE_SET_SIZE);
	__flush_DCACHE_line_offset(start, 12 * E2K_ICACHE_SET_SIZE);
	__flush_DCACHE_line_offset(start, 13 * E2K_ICACHE_SET_SIZE);
	__flush_DCACHE_line_offset(start, 14 * E2K_ICACHE_SET_SIZE);
	__flush_DCACHE_line_offset(start, 15 * E2K_ICACHE_SET_SIZE);
	flush_DCACHE_line_end();
	E2K_FLUSH_PIPELINE();
}

int arch_dup_mmap(struct mm_struct *oldmm, struct mm_struct *mm)
{
	mm_context_t *mmu, *oldmmu;
	struct cached_stacks_entry *new_cached, *old_cached;
#ifdef CONFIG_MAKE_ALL_PAGES_VALID
	struct vm_area_struct *vma;

	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if (!(vma->vm_flags & VM_PAGESVALID))
			continue;

		/* No need to flush TLB since there is
		 * no user for the new mm yet. */
		int ret = make_all_vma_pages_valid(vma, 0);
		if (ret)
			return ret;
	}
#endif

	oldmmu = &oldmm->context;
	mmu = &mm->context;

	/* Copy cached hardware stacks */
	spin_lock(&oldmmu->cached_stacks_lock);

	list_for_each_entry(old_cached, &oldmmu->cached_stacks, list_entry) {
		new_cached = kmalloc(sizeof(*new_cached), GFP_ATOMIC);
		if (!new_cached) {
			spin_unlock(&oldmmu->cached_stacks_lock);
			return -ENOMEM;
		}

		memcpy(&new_cached->stack, &old_cached->stack,
			sizeof(hw_stack_t));

		list_add(&new_cached->list_entry, &mmu->cached_stacks);
	}

	mmu->cached_stacks_size = oldmmu->cached_stacks_size;

	spin_unlock(&oldmmu->cached_stacks_lock);

#ifdef CONFIG_PROTECTED_MODE
	mmu->pm_sc_debug_mode = oldmmu->pm_sc_debug_mode;
#endif

	return 0;
}

void arch_exit_mmap(struct mm_struct *mm)
{
	if (mm == NULL)
		return;

	/* Release hw_contexts */
	hw_contexts_destroy(&mm->context);

#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	free_bin_comp_info(&mm->context.bincomp_info);
#endif
}

#ifdef CONFIG_NUMA
static void free_node_pgds(struct mm_struct *mm)
{
	mm_context_t *context = &mm->context;
	int node;

	if (MMU_IS_SEPARATE_PT())
		return;

	for_each_node_mask(node, context->pgds_nodemask) {
		if (node == context->mm_pgd_node)
			continue;

		pgd_free(mm, context->node_pgds[node]);
		context->node_pgds[node] = NULL;
	}
	nodes_clear(context->pgds_nodemask);
}

static int alloc_node_pgds(struct mm_struct *mm)
{
	mm_context_t *context = &mm->context;
	int node;

	memset(context->node_pgds, 0, sizeof(context->node_pgds));
	nodes_clear(context->pgds_nodemask);
	context->mm_pgd_node = NUMA_NO_NODE;

	if (MMU_IS_SEPARATE_PT())
		return 0;

	/* Reuse already allocated mm->pgd on corresponding node */
	BUG_ON(!mm->pgd);
	node = page_to_nid(virt_to_page(mm->pgd));

	context->node_pgds[node] = mm->pgd;
	context->mm_pgd_node = node;
	node_set(node, context->pgds_nodemask);

	/* On nodes with memory allocate a new pgd,
	 * nodes w/o memory will reuse mm->pgd. */
	for_each_node(node) {
		if (node == context->mm_pgd_node)
			continue;

		if (node_state(node, N_MEMORY))
			context->node_pgds[node] = pgd_alloc_node(mm, node);

		if (context->node_pgds[node])
			node_set(node, context->pgds_nodemask);
		else
			context->node_pgds[node] = mm->pgd;
	}

	return 0;
}
#else
static void free_node_pgds(struct mm_struct *mm) { }
static int alloc_node_pgds(struct mm_struct *mm)
{
	return 0;
}
#endif

/*
 * Initialize a new mmu context.  This is invoked when a new
 * address space instance (unique or shared) is instantiated.
 * This just needs to set mm->context[] to an invalid context.
 */
int __init_new_context(struct task_struct *p, struct mm_struct *mm,
		mm_context_t *context)
{
	bool is_fork = p && (p != current);
	mm_context_t *curr_context = &current->mm->context;
	int ret;

	memset(&context->cpumsk, 0, nr_cpu_ids * sizeof(context->cpumsk[0]));

	mutex_init(&context->cut_mask_lock);

	if (is_fork) {
		/*
		 * Copy data on user fork:
		 *
		 * copy cut mask from the context of parent process
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
		bitmap_zero((unsigned long *) &context->cut_mask,
				USER_CUT_AREA_SIZE/sizeof(e2k_cute_t));
	}

	atomic_set(&context->tstart, 1);
	INIT_LIST_HEAD(&context->delay_free_stacks);
	init_rwsem(&context->core_lock);

	INIT_LIST_HEAD(&context->cached_stacks);
	spin_lock_init(&context->cached_stacks_lock);
	context->cached_stacks_size = 0;

	if (!mm)
		return 0;

#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	rwlock_init(&context->bincomp_info.lock);

	if (current->mm) {
		bin_comp_info_t *oldbi	= &curr_context->bincomp_info;
		bin_comp_info_t *bi	= &mm->context.bincomp_info;

		ret = copy_bin_comp_info(oldbi, bi);
		if (ret)
			return ret;
	}
#endif

	ret = alloc_node_pgds(mm);
	if (ret)
		return ret;

	ret = hw_contexts_init(p, context, is_fork);
	if (ret)
		goto fail_free_pgds;

	return 0;

fail_free_pgds:
	free_node_pgds(mm);

	return ret;
}

/*
 * Destroy a dead context.  This occurs when mmput drops the
 * mm_users count to zero, the mmaps have been released, and
 * all the page tables have been flushed.  The function job
 * is to destroy any remaining processor-specific state.
 */
void destroy_context(struct mm_struct *mm)
{
	free_node_pgds(mm);

	destroy_cached_stacks(&mm->context);
}

bool arch_vma_access_permitted(struct vm_area_struct *vma,
		bool write, bool execute, bool foreign)
{
	if (vma->vm_flags & VM_PRIVILEGED) {
		/* We have only hardware and signal
		 * stacks in VM_PRIVILEGED area */
		if (execute)
			return false;

		if (write && !test_ts_flag(TS_KERNEL_SYSCALL))
			return false;
	}

	return true;
}

#ifdef CONFIG_HALF_SPEC_LOADS_INJECTION
#include <asm/trace-defs.h>
#include <linux/moduleparam.h>
static unsigned long hs_inject_address, hs_inject_size,
		     hs_inject_step = 0x1000;
static bool hs_inject_default = true;
core_param(hs_inject_address, hs_inject_address, ulong, 0644);
core_param(hs_inject_size, hs_inject_size, ulong, 0644);
core_param(hs_inject_step, hs_inject_step, ulong, 0644);
core_param(hs_inject_default, hs_inject_default, bool, 0644);

static bool differs_pt_dtlb(u64 pte, u64 dtlb)
{
	bool pt_successfull = (_PAGE_TEST_PRESENT(pte) && _PAGE_TEST_VALID(pte));
	bool dtlb_successfull = (cpu_has(CPU_FEAT_ISET_V6))
			? !!(dtlb & DTLB_ENTRY_SUCCESSFUL_V6)
			: !(dtlb & DTLB_ENTRY_ERROR_MASK_V3);

	if (pt_successfull != dtlb_successfull)
		return true;

	if (!dtlb_successfull)
		return false;

	if (cpu_has(CPU_FEAT_ISET_V6)) {
		return _PAGE_TEST_WRITEABLE(pte) != !!(dtlb & DTLB_ENTRY_W_V6) ||
			_PAGE_TEST_PRIV(pte) != !!(dtlb & DTLB_ENTRY_PV_or_U_S_V6) ||
			_PAGE_TEST_VALID(pte) != !!(dtlb & DTLB_ENTRY_VVA_V6) ||
			_PAGE_TEST(pte, UNI_PAGE_PROTECT) != !!(dtlb & DTLB_ENTRY_INT_PR_V6) ||
			_PAGE_TEST(pte, UNI_PAGE_GLOBAL) != !!(dtlb & DTLB_ENTRY_G_V6) ||
			_PAGE_TEST_NOT_EXEC(pte) != !!(dtlb & DTLB_ENTRY_NON_EX_V6) ||
			_PAGE_MT_GET_VAL(pte) != DTLB_ENTRY_MT_GET_VAL(dtlb & DTLB_ENTRY_MT_V6) ||
			_PAGE_PFN_TO_PADDR(pte) != DTLB_ENTRY_PHA_TO_PA_V6(dtlb);
	} else {
		return _PAGE_TEST_WRITEABLE(pte) != !!(dtlb & DTLB_ENTRY_WR_V3) ||
			_PAGE_TEST_PRIV(pte) != !!(dtlb & DTLB_ENTRY_PV_V3) ||
			_PAGE_TEST_VALID(pte) != !!(dtlb & DTLB_ENTRY_VVA_V3) ||
			_PAGE_TEST(pte, UNI_PAGE_PROTECT) != !!(dtlb & DTLB_ENTRY_INT_PR_NON_EX_V3) ||
			_PAGE_TEST(pte, UNI_PAGE_GLOBAL) != !!(dtlb & DTLB_ENTRY_G_V3) ||
			_PAGE_TEST_NOT_EXEC(pte) != !!(dtlb & DTLB_ENTRY_NON_EX_U_S_V3) ||
			_PAGE_PFN_TO_PADDR(pte) != DTLB_ENTRY_PHA_TO_PA_V3(dtlb);
	}
}

static void check_single_addr(unsigned long address)
{
	u64 dtlb_entry, dtlb_pud, dtlb_pmd, dtlb_pte;
	pgdval_t pgd;
	pudval_t pud;
	pmdval_t pmd;
	pteval_t pte;
	int pt_level;
	bool pgd_differs, pud_differs, pmd_differs, pte_differs;

	if (!current->mm)
		return;

	trace_get_va_translation(current->mm, address, &pgd, &pud, &pmd, &pte,
			&pt_level, NULL, PT_DTLB_TRANSLATION_AUTO);
	trace_get_dtlb_translation(current->mm, address, &dtlb_entry, &dtlb_pud,
			&dtlb_pmd, &dtlb_pte, pt_level, PT_DTLB_TRANSLATION_AUTO);

	pgd_differs = (pt_level <= E2K_PUD_LEVEL_NUM && differs_pt_dtlb(pgd, dtlb_pud));
	pud_differs = (pt_level <= E2K_PMD_LEVEL_NUM && differs_pt_dtlb(pud, dtlb_pmd));
	pmd_differs = (pt_level <= E2K_PTE_LEVEL_NUM && differs_pt_dtlb(pmd, dtlb_pte));
	pte_differs = (pt_level <= E2K_PAGES_LEVEL_NUM && differs_pt_dtlb(pte, dtlb_entry));

	if (likely(!pgd_differs && !pud_differs && !pmd_differs && !pte_differs))
		return;

	trace_printk("DTLB contents for address 0x%lx do not match page table, disabling tracing\n"
		"Page table (all f's if entry hasn't been read)\n"
		"  pgd 0x%lx\n"
		"  pud 0x%lx\n"
		"  pmd 0x%lx\n"
		"  pte 0x%lx\n"
		"Probed DTLB entries:\n"
		"  pud 0x%llx (%s)\n"
		"  pmd 0x%llx (%s)\n"
		"  pte 0x%llx (%s)\n"
		" addr 0x%llx (%s)\n",
		address,
		(pt_level <= E2K_PGD_LEVEL_NUM) ? pgd : -1UL,
		(pt_level <= E2K_PUD_LEVEL_NUM) ? pud : -1UL,
		(pt_level <= E2K_PMD_LEVEL_NUM) ? pmd : -1UL,
		(pt_level <= E2K_PTE_LEVEL_NUM) ? pte : -1UL,
		(pt_level <= E2K_PUD_LEVEL_NUM) ? dtlb_pud : -1ULL,
		pgd_differs ? "differs" : "same",
		(pt_level <= E2K_PMD_LEVEL_NUM) ? dtlb_pmd : -1ULL,
		pud_differs ? "differs" : "same",
		(pt_level <= E2K_PTE_LEVEL_NUM) ? dtlb_pte : -1ULL,
		pmd_differs ? "differs" : "same",
		dtlb_entry,
		pte_differs ? "differs" : "same"
		);
	tracing_off();
}

void debug_inject_half_spec_loads(bool check)
{
	static atomic_t ratelimit = ATOMIC_INIT(0);
	unsigned long addr;

	/* A simple ratelimited (cannot use proper timed ratelimit since
	 * this function is called deep in scheduler and kernel entry/exit) */
	if (atomic_inc_return_relaxed(&ratelimit) < 100)
		return;
	atomic_set(&ratelimit, 0);

	if (hs_inject_size) {
		for (addr = hs_inject_address;
				addr < hs_inject_address + hs_inject_size;
				addr += hs_inject_step) {
			E2K_HALF_SPEC_LOAD(addr);
		}

		if (check) {
			for (addr = hs_inject_address;
					addr < hs_inject_address + hs_inject_size;
					addr += hs_inject_step) {
				check_single_addr(addr);
			}
		}
	}

	if (hs_inject_default) {
		for (addr = 0; addr < ULL(0x80000); addr += 4 * PAGE_SIZE) {
			E2K_HALF_SPEC_LOAD(addr);
			if (check)
				check_single_addr(addr);
		}

		for (addr = KERNEL_VPTB_BASE_ADDR; addr < ULL(0x1000000000000);
				addr += 1UL << 36) {
			E2K_HALF_SPEC_LOAD(addr);
			if (check)
				check_single_addr(addr);
		}

		E2K_HALF_SPEC_LOAD(0xffffc0000000UL);
		if (check)
			check_single_addr(0xffffc0000000UL);
		E2K_HALF_SPEC_LOAD(0xffffffe00000UL);
		if (check)
			check_single_addr(0xffffffe00000UL);
		E2K_HALF_SPEC_LOAD(0xfffffffff000UL);
		if (check)
			check_single_addr(0xfffffffff000UL);
	}
}

static int test_half_spec_mode(void)
{
	debug_inject_half_spec_loads(false);
	return 0;
}
late_initcall(test_half_spec_mode);
#endif /* CONFIG_HALF_SPEC_LOADS_INJECTION */


/* Since CTX_FIRST_VERSION > 0 and after that last_mmu_context
 * only increases, we know that this variable is never 0.  And
 * if some TLB flush sets mm->context.cpumsk to 0, then version
 * check will automatically fail (in other words, we can just
 * compare contexts versions without comparing the context with 0
 * in get_mmu_pid_irqs_off()). */
DEFINE_PER_CPU(u64, last_mmu_context) = CTX_FIRST_VERSION;
/* This is the current context value - i.e. the value that
 * should go into %pid before trying to access userspace. */
DEFINE_PER_CPU(u64, current_mmu_context) = E2K_KERNEL_CONTEXT;
EXPORT_PER_CPU_SYMBOL(current_mmu_context);
/* User PT base cached for fast retrieval in uaccess_enable() */
DEFINE_PER_CPU(u64, u_root_ptb) = ULL(-1);
EXPORT_PER_CPU_SYMBOL(u_root_ptb);

/*
 * Get process new MMU context. This is needed when the page table
 * pointer is changed or when the CONTEXT of the current process is updated
 * This function is called under closed interrupts (including NMIs).
 */
u64 get_new_mmu_pid_irqs_off(mm_context_t *context, int cpu)
{
	u64 ctx, next;

	debug_inject_half_spec_loads(false);

	/* Otherwise there is a possibility that a half.-speculative load
	 * between flush_TLB_all() and later set_MMU_CONT() will create
	 * an invalid DTLB entry for current context. */
	VM_BUG_ON(READ_MMU_PID() != E2K_KERNEL_CONTEXT);

	ctx = raw_cpu_read(last_mmu_context);
	next = ctx + 1;

	if (unlikely(CTX_HARDWARE(next) == E2K_KERNEL_CONTEXT)) {
		++next;
		flush_TLB_all();
		flush_ICACHE_all();
		if (unlikely(CTX_VERSION(next) < CTX_FIRST_VERSION)) {
			next = CTX_FIRST_VERSION;
			if (CTX_HARDWARE(next) == E2K_KERNEL_CONTEXT)
				++next;
		}
	}

	/* Another CPU might have written 0 to our cpu's mm context
	 * while we were getting the next context. But it is OK since
	 * we are changing the context anyway, and if this happens we
	 * will just rewrite that 0 with the new context. */
	context->cpumsk[cpu] = next;
	raw_cpu_write(last_mmu_context, next);

	return next;
}


#ifdef CONFIG_DEBUG_FS
static void tlb_contents_show_entry(struct seq_file *seq, u64 line, u64 set)
{
	u64 vfn;
	dtlb_tag_t tag;
	dtlb_entry_t entry;
	dtlb_reg_op_t dtlb_reg_op = {
		.type = tlb_addr_tag_access,
		.setN = set,
		.lineN_small = line,
		.lineN_huge = line,
	};
	bool huge = (set == 1 && MMU_CR_KERNEL.set1 ||
		     set == 2 && MMU_CR_KERNEL.set2 ||
		     set == 3 && MMU_CR_KERNEL.set3);

	tag.word = READ_DTLB_REG(dtlb_reg_op.word);

	/* Do not print inactive entries */
	if (!cpu_has(CPU_FEAT_ISET_V6) && !tag.v3.val ||
	    cpu_has(CPU_FEAT_ISET_V6) && !tag.v6.val) {
		seq_printf(seq, "Line %3lld set %lld: empty\n\n\n", line, set);
		return;
	}

	dtlb_reg_op.type = tlb_addr_entry_access;
	entry.word = READ_DTLB_REG(dtlb_reg_op.word);

	if (!cpu_has(CPU_FEAT_ISET_V6)) {
		vfn = ((u64) tag.v3.va_tag << 8);
		if (!huge)
			vfn |= line;

		seq_printf(seq, "Line %3lld set %lld:\n"
			"  tag:   %016llx%s%s|context %x|va_tag %x|vfn %llx\n"
			"  entry: %016llx%s%s%s%s%s%s%s%s%s%s%s%s|pha %x\n",
			line, set,
			tag.word,
			(tag.v3.g) ? "|global" : "",
			(tag.v3.root) ? "|root" : "",
			tag.v3.context,
			tag.v3.va_tag,
			vfn,
			entry.word,
			(entry.v3.wr) ? "|writable" : "",
			(entry.v3.non_ex) ? "|non_ex" : "",
			(entry.v3.pwt) ? "|PWT" : "",
			(entry.v3.pcd1) ? "|CD1" : "",
			(entry.v3.pcd2) ? "|CD2" : "",
			(entry.v3.d) ? "|dirty" : "",
			(entry.v3.g) ? "|global" : "",
			(entry.v3.nwa) ? "|NWA" : "",
			(entry.v3.vva) ? "|valid" : "",
			(entry.v3.pv) ? "|priv" : "",
			(entry.v3.int_pr) ? "|int_pr" : "",
			(entry.v3.uc) ? "|UC" : "",
			entry.v3.pha);
	} else { /* iset v6 */
		vfn = ((u64) tag.v6.addr_tag << 8);
		if (!huge)
			vfn |= line;

		seq_printf(seq, "Line %3lld set %lld:\n"
			"  tag:   %016llx%s%s%s|pid %x|gid %x|addr_tag %x|vfn %llx\n"
			"  entry: %016llx%s%s%s%s%s%s%s%s%s|mt_ma %x|mt_exc %x|pha %llx\n",
			line, set,
			tag.word,
			(tag.v6.g) ? "|global" : "",
			(tag.v6.root) ? "|root" : "",
			(tag.v6.virt) ? "|virt" : "",
			tag.v6.pid,
			tag.v6.gid,
			tag.v6.addr_tag,
			vfn,
			entry.word,
			(entry.v6.wr_exc) ? "|wr_exc" : "",
			(entry.v6.wr_int) ? "|wr_int" : "",
			(entry.v6.pv) ? "|priv" : "",
			(entry.v6.vva) ? "|valid" : "",
			(entry.v6.int_pr) ? "|int_pr" : "",
			(entry.v6.d) ? "|dirty" : "",
			(entry.v6.g) ? "|global" : "",
			(entry.v6.nwa) ? "|NWA" : "",
			(entry.v6.non_ex) ? "|non_ex" : "",
			entry.v6.mt_ma,
			entry.v6.mt_exc,
			entry.v6.pha);
	}
}

static void tlb_contents_show_ipi(void *arg)
{
	struct seq_file *seq = arg;
	u64 line, set;

	for (line = 0; line < NATIVE_TLB_LINES_NUM; line++) {
		for (set = 0; set < NATIVE_TLB_SETS_NUM; set++) {
			tlb_contents_show_entry(seq, line, set);
		}
	}
}

static int tlb_contents_show(struct seq_file *seq, void *unused)
{
	int cpu;

	for_each_online_cpu(cpu) {
		seq_printf(seq, "CPU%d:\n", cpu);
		smp_call_function_single(cpu, tlb_contents_show_ipi, seq, true);
	}

	return 0;
}

static int tlb_contents_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, tlb_contents_show, NULL);
}

static const struct file_operations tlb_contents_fops = {
	.open    = tlb_contents_seq_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = single_release,
};

static int __init tlb_contents_create(void)
{
	debugfs_create_file("tlb_contents", S_IRUSR,
			    arch_debugfs_dir, NULL, &tlb_contents_fops);
	return 0;
}
late_initcall(tlb_contents_create);
#endif /* CONFIG_DEBUG_FS */
