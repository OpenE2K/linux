#if !defined(_KVM_TRACE_COPY_HW_STACKS_H) || defined(TRACE_HEADER_MULTI_READ)
#define _KVM_TRACE_COPY_HW_STACKS_H

#include <linux/tracepoint.h>
#include <linux/hugetlb.h>

#include <asm/trace-defs.h>
#include <asm/trace_pgtable-v2.h>
#include <asm/trace_pgtable-v6.h>
#include <asm/pgtable_def.h>
#include <asm/kvm/trace-defs.h>

#undef TRACE_SYSTEM
#define TRACE_SYSTEM host

#ifdef	CONFIG_KVM_HOST_MODE

TRACE_EVENT(
	host_copy_hw_stack,

	TP_PROTO(void *dst, void *src, unsigned long size, bool is_chain),

	TP_ARGS(dst, src, size, is_chain),

	TP_STRUCT__entry(
		__field_struct(struct kvm_vcpu *, vcpu		)
		__field(	void *,		dst		)
		__field(	void *,		src		)
		__field(	u64,		size		)
		__field(	bool,		is_chain	)
		__field(	pgdval_t,	dst_pgd		)
		__field(	pudval_t,	dst_pud		)
		__field(	pmdval_t,	dst_pmd		)
		__field(	pteval_t,	dst_pte		)
		__field(	int,		dst_pt_level	)
		__field(	pgdval_t,	hva_pgd		)
		__field(	pudval_t,	hva_pud		)
		__field(	pmdval_t,	hva_pmd		)
		__field(	pteval_t,	hva_pte		)
		__field(	int,		hva_pt_level	)
		__field(	unsigned long,	hva		)
	),

	TP_fast_assign(
		unsigned long hva;

		__entry->vcpu	= current_thread_info()->vcpu;
		__entry->dst	= dst;
		__entry->src	= src;
		__entry->size	= size;
		__entry->is_chain = is_chain;

		trace_kvm_get_va_translation(__entry->vcpu, (e2k_addr_t)dst,
			&__entry->dst_pgd, &__entry->dst_pud, &__entry->dst_pmd,
			&__entry->dst_pte, &__entry->dst_pt_level);

		hva = trace_kvm_get_gva_to_hva(__entry->vcpu, (gva_t)dst);
		__entry->hva = hva;

		trace_get_va_translation(current->mm, (e2k_addr_t)hva,
			&__entry->hva_pgd, &__entry->hva_pud, &__entry->hva_pmd,
			&__entry->hva_pte, &__entry->hva_pt_level);
	),

	TP_printk("VCPU #%d copy %s stack kernel guest <- kernel host: dst %px "
		"src %px size %llx\n"
		"   kernel guest dst GVA %px : pgd 0x%016lx : %s\n"
		"        Access mode: %s%s\n"
		"                          pud 0x%016lx : %s\n"
		"        Access mode: %s%s\n"
		"                          pmd 0x%016lx : %s\n"
		"        Access mode: %s%s\n"
		"                          pte 0x%016lx : %s\n"
		"        Access mode: %s%s\n"
		"   kernel host  dst HVA %px : pgd 0x%016lx : %s\n"
		"        Access mode: %s%s\n"
		"                          pud 0x%016lx : %s\n"
		"        Access mode: %s%s\n"
		"                          pmd 0x%016lx : %s\n"
		"        Access mode: %s%s\n"
		"                          pte 0x%016lx : %s\n"
		"        Access mode: %s%s",
		__entry->vcpu->vcpu_id,
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
		(void *)__entry->hva,
		(__entry->hva_pt_level <= E2K_PGD_LEVEL_NUM) ?
						__entry->hva_pgd : -1UL,
		E2K_TRACE_PRINT_PT_FLAGS(__entry->hva_pgd,
				__entry->hva_pt_level <= E2K_PGD_LEVEL_NUM),
		(__entry->hva_pt_level <= E2K_PUD_LEVEL_NUM) ?
						__entry->hva_pud : -1UL,
		E2K_TRACE_PRINT_PT_FLAGS(__entry->hva_pud,
				__entry->hva_pt_level <= E2K_PUD_LEVEL_NUM),
		(__entry->hva_pt_level <= E2K_PMD_LEVEL_NUM) ?
						__entry->hva_pmd : -1UL,
		E2K_TRACE_PRINT_PT_FLAGS(__entry->hva_pmd,
				__entry->hva_pt_level <= E2K_PMD_LEVEL_NUM),
		(__entry->hva_pt_level <= E2K_PTE_LEVEL_NUM) ?
						__entry->hva_pte : -1UL,
		E2K_TRACE_PRINT_PT_FLAGS(__entry->hva_pte,
				__entry->hva_pt_level <= E2K_PTE_LEVEL_NUM)
	)
);

TRACE_EVENT(
	host_proc_stack_frame,

	TP_PROTO(kernel_mem_ps_t *ps_base, kernel_mem_ps_t *ps_frame),

	TP_ARGS(ps_base, ps_frame),

	TP_STRUCT__entry(
		__field(	kernel_mem_ps_t *,	ps_base		)
		__field_struct(	kernel_mem_ps_t,	ps_frame	)
		__field(	pgprotval_t,		dtlb_entry	)
	),

	TP_fast_assign(
		__entry->ps_base = ps_base;
		__entry->ps_frame = *ps_frame;
		__entry->dtlb_entry = get_MMU_DTLB_ENTRY((e2k_addr_t)ps_base);
	),

	TP_printk("   %px (dtlb 0x%016lx) : 0x%016lx   0x%016lx",
		__entry->ps_base, __entry->dtlb_entry,
		__entry->ps_frame.word_lo, __entry->ps_frame.word_hi)
);

TRACE_EVENT(
	host_chain_stack_frame,

	TP_PROTO(e2k_mem_crs_t *pcs_base, e2k_mem_crs_t *pcs_frame),

	TP_ARGS(pcs_base, pcs_frame),

	TP_STRUCT__entry(
		__field(	e2k_mem_crs_t *,	pcs_base	)
		__field_struct(	e2k_mem_crs_t,		pcs_frame	)
		__field(	pgprotval_t,		dtlb_entry	)
	),

	TP_fast_assign(
		__entry->pcs_base	= pcs_base;
		__entry->pcs_frame	= *pcs_frame;
		__entry->dtlb_entry = get_MMU_DTLB_ENTRY((e2k_addr_t)pcs_base);
	),

	TP_printk("   %px (dtlb 0x%016lx) : 0x%016llx   0x%016llx   "
		"0x%016llx   0x%016llx",
		__entry->pcs_base, __entry->dtlb_entry,
		__entry->pcs_frame.cr0_lo.CR0_lo_half,
		__entry->pcs_frame.cr0_hi.CR0_hi_half,
		__entry->pcs_frame.cr1_lo.CR1_lo_half,
		__entry->pcs_frame.cr1_hi.CR1_hi_half)
);

TRACE_EVENT(
	host_copy_hva_area,

	TP_PROTO(void *dst, void *src, unsigned long size),

	TP_ARGS(dst, src, size),

	TP_STRUCT__entry(
		__field(	void *,		dst		)
		__field(	void *,		src		)
		__field(	u64,		size		)
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
	),

	TP_fast_assign(
		__entry->dst	= dst;
		__entry->src	= src;
		__entry->size	= size;

		trace_get_va_translation(current->mm, (e2k_addr_t)dst,
			&__entry->dst_pgd, &__entry->dst_pud, &__entry->dst_pmd,
			&__entry->dst_pte, &__entry->dst_pt_level);
		trace_get_va_translation(current->mm, (e2k_addr_t)src,
			&__entry->src_pgd, &__entry->src_pud, &__entry->src_pmd,
			&__entry->src_pte, &__entry->src_pt_level);
	),

	TP_printk("copy area user guest <- kernel guest: dst %px "
		"src %px size %llx\n"
		"   kernel guest dst HVA %px : pgd 0x%016lx : %s\n"
		"        Access mode: %s%s\n"
		"                          pud 0x%016lx : %s\n"
		"        Access mode: %s%s\n"
		"                          pmd 0x%016lx : %s\n"
		"        Access mode: %s%s\n"
		"                          pte 0x%016lx : %s\n"
		"        Access mode: %s%s\n"
		"   kernel guest  dst HVA %px : pgd 0x%016lx : %s\n"
		"        Access mode: %s%s\n"
		"                          pud 0x%016lx : %s\n"
		"        Access mode: %s%s\n"
		"                          pmd 0x%016lx : %s\n"
		"        Access mode: %s%s\n"
		"                          pte 0x%016lx : %s\n"
		"        Access mode: %s%s",
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
				__entry->src_pt_level <= E2K_PTE_LEVEL_NUM)
	)
);

TRACE_EVENT(
	host_hva_area_line,

	TP_PROTO(u64 *hva_base, u64 size),

	TP_ARGS(hva_base, size),

	TP_STRUCT__entry(
		__field(	u64 *,		hva_base		)
		__array(	u64,		hva_line,	4	)
		__field(	u64,		size			)
		__field(	pgprotval_t,	dtlb_entry		)
	),

	TP_fast_assign(
		__entry->hva_base = hva_base;
		__entry->hva_line[0] =
			(size >= 1 * sizeof(u64)) ? hva_base[0] : -1;
		__entry->hva_line[1] =
			(size >= 2 * sizeof(u64)) ? hva_base[1] : -1;
		__entry->hva_line[2] =
			(size >= 3 * sizeof(u64)) ? hva_base[2] : -1;
		__entry->hva_line[3] =
			(size >= 4 * sizeof(u64)) ? hva_base[3] : -1;
		__entry->size		= size;
		__entry->dtlb_entry = get_MMU_DTLB_ENTRY((e2k_addr_t)hva_base);
	),

	TP_printk("   %px (dtlb 0x%016lx) : 0x%016llx   0x%016llx   "
		"0x%016llx   0x%016llx",
		__entry->hva_base, __entry->dtlb_entry,
		__entry->hva_line[0],
		__entry->hva_line[1],
		__entry->hva_line[2],
		__entry->hva_line[3]
	)
);
#else	/* !CONFIG_KVM_HOST_MODE */

static inline bool trace_host_copy_hw_stack_enabled(void)
{
	return false;
}
static inline void
trace_host_copy_hw_stack(void *dst, void *src, unsigned long size, bool is_chain)
{
}

static inline bool trace_host_proc_stack_frame_enabled(void)
{
	return false;
}
static inline void
trace_host_proc_stack_frame(kernel_mem_ps_t *ps_base, kernel_mem_ps_t *ps_frame)
{
}

static inline bool trace_host_chain_stack_frame_enabled(void)
{
	return false;
}
static inline void
trace_host_chain_stack_frame(e2k_mem_crs_t *pcs_base, e2k_mem_crs_t *pcs_frame)
{
}

static inline bool trace_host_copy_hva_area_enabled(void)
{
	return false;
}
static inline void
trace_host_copy_hva_area(void *dst, void *src, unsigned long size)
{
}

static inline bool trace_host_hva_area_line_enabled(void)
{
	return false;
}
static inline void
trace_host_hva_area_line(u64 *hva_base, u64 size)
{
}

#endif	/* CONFIG_KVM_HOST_MODE */

#endif /* _KVM_TRACE_COPY_HW_STACKS_H */

#ifdef	CONFIG_KVM_HOST_MODE
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH ../../arch/e2k/include/asm/kvm
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE trace-hw-stacks

/* This part must be outside protection */
#include <trace/define_trace.h>
#endif	/* CONFIG_KVM_HOST_MODE */
