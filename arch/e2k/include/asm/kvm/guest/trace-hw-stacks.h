#if !defined(_KVM_GUEST_TRACE_COPY_HW_STACKS_H) || defined(TRACE_HEADER_MULTI_READ)
#define _KVM_GUEST_TRACE_COPY_HW_STACKS_H

#include <linux/tracepoint.h>
#include <linux/hugetlb.h>

#include <asm/trace-defs.h>
#include <asm/trace_pgtable-v3.h>
#include <asm/trace_pgtable-v6.h>
#include <asm/pgtable_def.h>
#include <asm/kvm/guest/trace-defs.h>

#undef TRACE_SYSTEM
#define TRACE_SYSTEM guest

TRACE_EVENT(
	guest_copy_hw_stack,

	TP_PROTO(void *dst, void *src, unsigned long size, bool is_chain),

	TP_ARGS(dst, src, size, is_chain),

	TP_STRUCT__entry(
		__field(	void *,		dst		)
		__field(	void *,		src		)
		__field(	u64,		size		)
		__field(	bool,		is_chain	)
		__field(	pgdval_t,	dst_pgd		)
		__field(	pudval_t,	dst_pud		)
		__field(	pmdval_t,	dst_pmd		)
		__field(	pteval_t,	dst_pte		)
		__field(	int,		dst_pt_level	)
		__field(	pgdval_t,	src_pgd		)
		__field(	pudval_t,	src_pud		)
		__field(	pmdval_t,	src_pmd		)
		__field(	pteval_t,	src_pte		)
		__field(	int,		src_pt_level	)
		__field(	pgdval_t,	dst_spt_pgd	)
		__field(	pudval_t,	dst_spt_pud	)
		__field(	pmdval_t,	dst_spt_pmd	)
		__field(	pteval_t,	dst_spt_pte	)
		__field(	int,		dst_spt_level	)
		__field(	pgdval_t,	src_spt_pgd	)
		__field(	pudval_t,	src_spt_pud	)
		__field(	pmdval_t,	src_spt_pmd	)
		__field(	pteval_t,	src_spt_pte	)
		__field(	int,		src_spt_level	)
	),

	TP_fast_assign(
		__entry->dst	= dst;
		__entry->src	= src;
		__entry->size	= size;
		__entry->is_chain = is_chain;

		trace_get_va_translation(current->mm, (e2k_addr_t)dst,
			&__entry->dst_pgd, &__entry->dst_pud, &__entry->dst_pmd,
			&__entry->dst_pte, &__entry->dst_pt_level,
			PT_DTLB_TRANSLATION_AUTO);
		trace_kvm_get_gva_spt_translation((e2k_addr_t)dst,
			&__entry->dst_spt_pgd, &__entry->dst_spt_pud,
			&__entry->dst_spt_pmd, &__entry->dst_spt_pte,
			&__entry->dst_spt_level);

		trace_get_va_translation(current->mm, (e2k_addr_t)src,
			&__entry->src_pgd, &__entry->src_pud, &__entry->src_pmd,
			&__entry->src_pte, &__entry->src_pt_level,
			PT_DTLB_TRANSLATION_AUTO);
		trace_kvm_get_gva_spt_translation((e2k_addr_t)src,
			&__entry->src_spt_pgd, &__entry->src_spt_pud,
			&__entry->src_spt_pmd, &__entry->src_spt_pte,
			&__entry->src_spt_level);
	),

	TP_printk("copy %s stack guest user <- guest kernel: dst %px "
		"src %px size %llx\n"
		"  user guest dst %px :\n"
		"    pgd 0x%016lx : %s%s\n"
		"    pud 0x%016lx : %s%s\n"
		"    pmd 0x%016lx : %s%s\n"
		"    pte 0x%016lx : %s%s\n"
		"  user guest dst spt %px :\n"
		"    pgd 0x%016lx : %s%s\n"
		"    pud 0x%016lx : %s%s\n"
		"    pmd 0x%016lx : %s%s\n"
		"    pte 0x%016lx : %s%s\n"
		"  kernel guest src %px :\n"
		"    pgd 0x%016lx : %s%s\n"
		"    pud 0x%016lx : %s%s\n"
		"    pmd 0x%016lx : %s%s\n"
		"    pte 0x%016lx : %s%s\n"
		"  kernel guest src spt %px :\n"
		"    pgd 0x%016lx : %s%s\n"
		"    pud 0x%016lx : %s%s\n"
		"    pmd 0x%016lx : %s%s\n"
		"    pte 0x%016lx : %s%s\n",
		(__entry->is_chain) ? "chain" : "procedure",
		__entry->dst,
		__entry->src,
		__entry->size,
		__entry->dst,
		(__entry->dst_pt_level <= E2K_PGD_LEVEL_NUM) ?
						__entry->dst_pgd : -1UL,
		E2K_TRACE_PRINT_PT_FLAGS(__entry->dst_pgd,
				__entry->dst_pt_level <= E2K_PGD_LEVEL_NUM),
		(__entry->dst_pt_level <= E2K_PUD_LEVEL_NUM) ?
						__entry->dst_pud : -1UL,
		E2K_TRACE_PRINT_PT_FLAGS(__entry->dst_pud,
				__entry->dst_pt_level <= E2K_PUD_LEVEL_NUM),
		(__entry->dst_pt_level <= E2K_PMD_LEVEL_NUM) ?
						__entry->dst_pmd : -1UL,
		E2K_TRACE_PRINT_PT_FLAGS(__entry->dst_pmd,
				__entry->dst_pt_level <= E2K_PMD_LEVEL_NUM),
		(__entry->dst_pt_level <= E2K_PTE_LEVEL_NUM) ?
						__entry->dst_pte : -1UL,
		E2K_TRACE_PRINT_PT_FLAGS(__entry->dst_pte,
				__entry->dst_pt_level <= E2K_PTE_LEVEL_NUM),
		__entry->dst,
		(__entry->dst_spt_level <= E2K_PGD_LEVEL_NUM) ?
						__entry->dst_spt_pgd : -1UL,
		E2K_TRACE_PRINT_PT_FLAGS(__entry->dst_spt_pgd,
				__entry->dst_spt_level <= E2K_PGD_LEVEL_NUM),
		(__entry->dst_spt_level <= E2K_PUD_LEVEL_NUM) ?
						__entry->dst_spt_pud : -1UL,
		E2K_TRACE_PRINT_PT_FLAGS(__entry->dst_spt_pud,
				__entry->dst_spt_level <= E2K_PUD_LEVEL_NUM),
		(__entry->dst_spt_level <= E2K_PMD_LEVEL_NUM) ?
						__entry->dst_spt_pmd : -1UL,
		E2K_TRACE_PRINT_PT_FLAGS(__entry->dst_spt_pmd,
				__entry->dst_spt_level <= E2K_PMD_LEVEL_NUM),
		(__entry->dst_spt_level <= E2K_PTE_LEVEL_NUM) ?
						__entry->dst_spt_pte : -1UL,
		E2K_TRACE_PRINT_PT_FLAGS(__entry->dst_spt_pte,
				__entry->dst_spt_level <= E2K_PTE_LEVEL_NUM),
		__entry->src,
		(__entry->src_pt_level <= E2K_PGD_LEVEL_NUM) ?
						__entry->src_pgd : -1UL,
		E2K_TRACE_PRINT_PT_FLAGS(__entry->src_pgd,
				__entry->src_pt_level <= E2K_PGD_LEVEL_NUM),
		(__entry->src_pt_level <= E2K_PUD_LEVEL_NUM) ?
						__entry->src_pud : -1UL,
		E2K_TRACE_PRINT_PT_FLAGS(__entry->src_pud,
				__entry->src_pt_level <= E2K_PUD_LEVEL_NUM),
		(__entry->src_pt_level <= E2K_PMD_LEVEL_NUM) ?
						__entry->src_pmd : -1UL,
		E2K_TRACE_PRINT_PT_FLAGS(__entry->src_pmd,
				__entry->src_pt_level <= E2K_PMD_LEVEL_NUM),
		(__entry->src_pt_level <= E2K_PTE_LEVEL_NUM) ?
						__entry->src_pte : -1UL,
		E2K_TRACE_PRINT_PT_FLAGS(__entry->src_pte,
				__entry->src_pt_level <= E2K_PTE_LEVEL_NUM),
		__entry->src,
		(__entry->src_spt_level <= E2K_PGD_LEVEL_NUM) ?
						__entry->src_spt_pgd : -1UL,
		E2K_TRACE_PRINT_PT_FLAGS(__entry->src_spt_pgd,
				__entry->src_spt_level <= E2K_PGD_LEVEL_NUM),
		(__entry->src_spt_level <= E2K_PUD_LEVEL_NUM) ?
						__entry->src_spt_pud : -1UL,
		E2K_TRACE_PRINT_PT_FLAGS(__entry->src_spt_pud,
				__entry->src_spt_level <= E2K_PUD_LEVEL_NUM),
		(__entry->src_spt_level <= E2K_PMD_LEVEL_NUM) ?
						__entry->src_spt_pmd : -1UL,
		E2K_TRACE_PRINT_PT_FLAGS(__entry->src_spt_pmd,
				__entry->src_spt_level <= E2K_PMD_LEVEL_NUM),
		(__entry->src_spt_level <= E2K_PTE_LEVEL_NUM) ?
						__entry->src_spt_pte : -1UL,
		E2K_TRACE_PRINT_PT_FLAGS(__entry->src_spt_pte,
				__entry->src_spt_level <= E2K_PTE_LEVEL_NUM)
	)
);

TRACE_EVENT(
	guest_proc_stack_frame,

	TP_PROTO(kernel_mem_ps_t *ps_base, kernel_mem_ps_t *ps_frame),

	TP_ARGS(ps_base, ps_frame),

	TP_STRUCT__entry(
		__field(	kernel_mem_ps_t *,	ps_base		)
		__field_struct(	kernel_mem_ps_t,	ps_frame	)
		__field(	pgprotval_t,		dtlb_entry	)
	),

	TP_fast_assign(
		__entry->ps_base	= ps_base;
		__entry->ps_frame	= *ps_frame;
		__entry->dtlb_entry = HYPERVISOR_mmu_probe((e2k_addr_t)ps_base,
							KVM_MMU_PROBE_ENTRY);
	),

	TP_printk("   %px (dtlb 0x%016lx) : 0x%016lx   0x%016lx",
		__entry->ps_base, __entry->dtlb_entry,
		__entry->ps_frame.word_lo,
		__entry->ps_frame.word_hi)
);

TRACE_EVENT(
	guest_chain_stack_frame,

	TP_PROTO(e2k_mem_crs_t *pcs_base, e2k_mem_crs_t *pcs_frame),

	TP_ARGS(pcs_base, pcs_frame),

	TP_STRUCT__entry(
		__field(	e2k_mem_crs_t *,	pcs_base	)
		__field_struct(	e2k_mem_crs_t,		pcs_frame	)
		__field(	pgprotval_t,		dtlb_entry	)
	),

	TP_fast_assign(
		__entry->pcs_base = pcs_base;
		__entry->pcs_frame = *pcs_frame;
		__entry->dtlb_entry = HYPERVISOR_mmu_probe((e2k_addr_t)pcs_base,
							KVM_MMU_PROBE_ENTRY);
	),

	TP_printk("   %px (dtlb 0x%016lx) : 0x%016llx   0x%016llx   "
		"0x%016llx   0x%016llx",
		__entry->pcs_base, __entry->dtlb_entry,
		__entry->pcs_frame.cr0_lo.CR0_lo_half,
		__entry->pcs_frame.cr0_hi.CR0_hi_half,
		__entry->pcs_frame.cr1_lo.CR1_lo_half,
		__entry->pcs_frame.cr1_hi.CR1_hi_half)
);

#include <asm/kvm/guest/trace-tlb-state.h>

#endif /* _KVM_GUEST_TRACE_COPY_HW_STACKS_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH ../../arch/e2k/include/asm/kvm/guest
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE trace-hw-stacks

/* This part must be outside protection */
#include <trace/define_trace.h>
