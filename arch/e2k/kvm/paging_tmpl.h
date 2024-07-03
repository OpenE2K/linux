/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Kernel-based Virtual Machine driver for Linux
 *
 * This module enables machines with e2k hardware virtualization extensions
 * to run virtual machines without emulation or binary translation.
 *
 * Based on x86 MMU virtualization ideas and sources:
 *	arch/x86/kvm/mmu.c
 *	arch/x86/kvm/mmu.h
 *	arch/x86/kvm/paging_tmpl.h
 */

/*
 * We need the mmu code to access both 32-bit and 64-bit guest ptes,
 * so the code in this file is compiled twice, once per pte size.
 */

/*
 * This is used to catch non optimized PT_GUEST_(DIRTY|ACCESS)_SHIFT macro
 * uses for EPT without A/D paging type.
 */
extern u64 __pure __using_nonexistent_pte_bit(void)
	__compiletime_error("wrong use of PT_GUEST_(DIRTY|ACCESS)_SHIFT");

#define guest_walker		guest_walker_e2k
#define FNAME(name)		e2k_##name
#define PT_GUEST_ACCESSED_MASK	PT_ACCESSED_MASK
#define PT_GUEST_DIRTY_MASK	PT_DIRTY_MASK
#define PT_MAX_FULL_LEVELS	E2K_PT_LEVELS_NUM
#define CMPXCHG			cmpxchg64

#define	CHECK_GPTE_CHANGED
#define	DO_PTE_PREFETCH

/*
 * The guest_walker structure emulates the behavior of the hardware page
 * table walker.
 */
typedef struct guest_walker {
	int level;
	unsigned max_level;
	const pt_struct_t *pt_struct;
	const pt_level_t *pt_level;
	unsigned pt_access;
	unsigned pte_access;
	u64 pte_cui;
	gfn_t gfn;
	gva_t gva;
	kvm_arch_exception_t fault;
} guest_walker_t;

typedef struct gpt_entry {
	gpa_t		gpt_base;
	gpa_t		gpa;
	hva_t		hva;
	pgprotval_t	gpte;
	pgprotval_t	*gpt_page;
	pgprotval_t	*gpt_page_atomic;
	int		start_index;
	int		ptrs_num;
	int		level;
	bool		writable;
} gpt_entry_t;

typedef struct gpt_walker {
	int		max_level;
	int		min_level;
	gpa_t		gpt_root;
	gpt_entry_t	gptes[PT_MAX_FULL_LEVELS];
} gpt_walker_t;

#define	MAX_GPT_WALK_RETRY_NUM	5

typedef enum gpte_state {
	same_gpte_state = 0,	/* gpte stays unchanged */
	other_gpte_state,	/* gpte was changed */
	level_out_gpte_state,	/* the PT level of gpte is outside of walk table */
	other_gpa_gpte_state,	/* the gpa of gpte is not the same */
	other_hva_gpte_state,	/* the hva of gpte is not the same */
} gpte_state_t;

static int kvm_vcpu_read_guest_pte(struct kvm_vcpu *vcpu, gpa_t gpa, void *dst,
					int len, hva_t *hvap, bool *writable);
static int sync_shadow_pt_gva(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
				gpt_walker_t *gpt_walker, gva_t gva);
static pf_res_t map_huge_page_to_spte(struct kvm_vcpu *vcpu,
			gmm_struct_t *gmm, gpt_walker_t *gpt_walker,
			pgprotval_t gpte, gva_t gva, gfn_t gfn,
			int level, int to_level, pgprot_t *sptep);
static pf_res_t allocate_shadow_level(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
			gfn_t table_gfn, gva_t gva, int level, unsigned pt_access,
			pgprot_t *spt_pte_hva, bool is_direct, gpa_t guest_pt_gpa);

static inline gpt_entry_t *
get_walk_addr_gpte_level(gpt_walker_t *gpt_walker, int level)
{
	E2K_KVM_BUG_ON(level < gpt_walker->min_level || level > gpt_walker->max_level);
	return &gpt_walker->gptes[level - 1];
}

static inline gpt_entry_t *
get_walk_page_table_level(gpt_walker_t *gpt_walker)
{
	return &gpt_walker->gptes[PT_PAGE_TABLE_LEVEL - 1];
}

static inline void
alloc_addr_range_gpt(struct kvm_vcpu *vcpu, gpt_walker_t *gpt_walker)
{
}

static void alloc_pt_pages_gpt_walker(struct kvm_vcpu *vcpu,
				      gpt_walker_t *gpt_walker)
{
	pgprotval_t *gpt_page;
	gpt_entry_t *gpt_entry;

	gpt_entry = get_walk_page_table_level(gpt_walker);
	gpt_page = mmu_memory_cache_alloc(&vcpu->arch.mmu_page_cache);
	gpt_entry->gpt_page = gpt_page;
	gpt_page = mmu_memory_cache_alloc(&vcpu->arch.mmu_page_cache);
	gpt_entry->gpt_page_atomic = gpt_page;
}

static void free_pt_pages_gpt_walker(gpt_walker_t *gpt_walker)
{
	gpt_entry_t *gpt_entry;

	gpt_entry = get_walk_page_table_level(gpt_walker);
	free_page((unsigned long)gpt_entry->gpt_page);
	gpt_entry->gpt_page = NULL;
	free_page((unsigned long)gpt_entry->gpt_page_atomic);
	gpt_entry->gpt_page_atomic = NULL;
}

static void init_addr_gpt_walker(struct kvm_vcpu *vcpu,
				gva_t gpt_root, gpt_walker_t *gpt_walker,
				bool reinit)
{
#ifndef	DO_PTE_PREFETCH
	gpt_entry_t *gpt_entry;
#endif	/* !DO_PTE_PREFETCH */

	gpt_walker->max_level = vcpu->arch.mmu.root_level;
	gpt_walker->min_level = vcpu->arch.mmu.root_level;
	gpt_walker->gpt_root = gpt_root;

	if (unlikely(reinit))
		return;

#ifndef	DO_PTE_PREFETCH
	gpt_entry = get_walk_page_table_level(gpt_walker);
	gpt_entry->gpt_page = NULL;
	gpt_entry->gpt_page_atomic = NULL;
#else	/* DO_PTE_PREFETCH */
	alloc_pt_pages_gpt_walker(vcpu, gpt_walker);
#endif	/* !DO_PTE_PREFETCH */
}

static void init_addr_range_gpt_walker(struct kvm_vcpu *vcpu,
				gva_t gpt_root, gpt_walker_t *gpt_walker,
				bool reinit)
{
	gpt_entry_t *gpt_entry;

	init_addr_gpt_walker(vcpu, gpt_root, gpt_walker, reinit);

	gpt_entry = get_walk_page_table_level(gpt_walker);
	if (likely(!reinit)) {
#ifndef	DO_PTE_PREFETCH
		alloc_pt_pages_gpt_walker(vcpu, gpt_walker);
#endif	/* !DO_PTE_PREFETCH */
	} else {
		E2K_KVM_BUG_ON(gpt_entry->gpt_page == NULL ||
				gpt_entry->gpt_page_atomic == NULL);
	}
}

static void free_addr_gpt_walker(gpt_walker_t *gpt_walker)
{
#ifdef	DO_PTE_PREFETCH
	free_pt_pages_gpt_walker(gpt_walker);
#else	/* !DO_PTE_PREFETCH */
	E2K_KVM_BUG_ON(gpt_entry->gpt_page != NULL ||
				gpt_entry->gpt_page_atomic != NULL);
#endif	/* DO_PTE_PREFETCH */
}

static void free_addr_range_gpt_walker(gpt_walker_t *gpt_walker)
{
	free_pt_pages_gpt_walker(gpt_walker);
}

static inline int walk_addr_gpte_level(struct kvm_vcpu *vcpu, gva_t addr,
				gpa_t gpt_base, gpt_entry_t *gpt_entry,
				const pt_level_t *pt_level, int level)
{
	pgprotval_t gpte;
	unsigned long index, offset;
	gpa_t gpte_gpa;
	pgprotval_t __user *ptep_user;
	int ret;

	gpt_entry->level = level;
	index = get_pt_level_addr_index(addr, pt_level);
	offset = index * sizeof(pgprotval_t);
	gpte_gpa = gpt_base + offset;
	E2K_KVM_BUG_ON(arch_is_error_gpa(gpte_gpa));
	gpt_entry->gpa = gpte_gpa;
	DebugWGPT("guest PT level #%d addr 0x%lx index 0x%lx offset 0x%lx "
		"gpte: gpa 0x%llx\n",
		level, addr, index, offset, gpte_gpa);

	ret = kvm_vcpu_get_guest_pte(vcpu, gpte_gpa, gpte, ptep_user,
				     &gpt_entry->writable);
	if (unlikely(ret != 0)) {
		DebugWGPT("get gpte from gpa 0x%llx failed, error %d\n",
			gpte_gpa, ret);
		return ret;
	}
	gpt_entry->gpte = gpte;
	gpt_entry->hva = (hva_t)ptep_user;
	gpt_entry->gpt_base = gpt_base;
	gpt_entry->start_index = index;
	gpt_entry->ptrs_num = 1;
	DebugWGPT("guest PT level #%d addr 0x%lx gpte from hva %px : 0x%lx\n",
		level, addr, ptep_user, gpte);
	trace_kvm_mmu_paging_element(__pgprot(gpte), level);

	return 0;
}

static inline int walk_addr_range_gpte_level(struct kvm_vcpu *vcpu,
				gva_t start, gva_t end,
				gpa_t gpt_base, gpt_entry_t *gpt_entry,
				const pt_level_t *pt_level, int level)
{
	unsigned long index, start_index, end_index, offset, start_offset;
	gva_t end_addr, start_page, end_page;
	long pages_num;
	gpa_t gpte_gpa;
	pgprotval_t *gpt_page;
	unsigned long mask;
	size_t len;
	int ret;

	gpt_entry->level = level;

	gpt_page = gpt_entry->gpt_page;
	E2K_KVM_BUG_ON(gpt_page == NULL);

	if (start == end) {
		pages_num = 1;
	} else {
		end_addr = end - 1;
		start_page = start & get_pt_level_page_mask(pt_level);
		end_page = end_addr & get_pt_level_page_mask(pt_level);
		pages_num = ((end_page - start_page) >>
				get_pt_level_page_shift(pt_level)) + 1;
	}
	index = get_pt_level_addr_index(start, pt_level);
	start_index = index;
	end_index = start_index + pages_num;
	mask = PTE_PREFETCH_NUM - 1;
	start_index &= ~mask;
	pages_num = end_index - start_index;
	if (pages_num < PTE_PREFETCH_NUM) {
		pages_num = PTE_PREFETCH_NUM;
		end_index = start_index + pages_num;
	}
	if (end_index > get_ptrs_per_pt_level(pt_level)) {
		end_index = get_ptrs_per_pt_level(pt_level);
		pages_num = end_index - start_index;
	}
	E2K_KVM_BUG_ON(pages_num < PTE_PREFETCH_NUM);

	offset = start_index * sizeof(pgprotval_t);
	start_offset = (index - start_index) * sizeof(pgprotval_t);
	gpte_gpa = gpt_base + offset;
	E2K_KVM_BUG_ON(arch_is_error_gpa(gpte_gpa));
	gpt_entry->gpa = gpte_gpa + start_offset;
	gpt_entry->gpt_base = gpt_base;
	gpt_entry->start_index = start_index;
	gpt_entry->ptrs_num = pages_num;
	len = pages_num * sizeof(pgprotval_t);
	DebugRGPT("guest PT level #%d range 0x%lx - 0x%lx index start 0x%lx "
		"end 0x%lx copy gptes from gpa 0x%llx size 0x%lx\n",
		level, start, end, start_index, end_index, gpte_gpa, len);

	ret = kvm_vcpu_read_guest_pte(vcpu, gpte_gpa, gpt_page + start_index,
				      len, &gpt_entry->hva, &gpt_entry->writable);
	if (unlikely(ret != 0)) {
		pr_err("%s(): copy gpte from gpa 0x%llx size 0x%lx failed, "
			"error %d\n",
			__func__, gpte_gpa, len, ret);
		return ret;
	}
	gpt_entry->gpte = gpt_page[index];
	gpt_entry->hva += start_offset;
	DebugRGPT("guest PT level #%d range 0x%lx - 0x%lx gpte "
		"from hva 0x%lx : 0x%lx\n",
		level, start, end, gpt_entry->hva, gpt_entry->gpte);
	trace_kvm_mmu_paging_element(__pgprot(gpt_entry->gpte), level);

	return 0;
}

static inline int walk_next_addr_gpte_level(struct kvm_vcpu *vcpu, gva_t addr,
				gpa_t gpt_base, gpt_entry_t *gpt_entry,
				const pt_level_t *pt_level, int start_level)
{
	pgprotval_t gpte;
	unsigned long index, offset;
	gpa_t gpte_gpa;
	pgprotval_t __user *ptep_user;
	int cur_level, ret;
	bool to_update;

	cur_level = gpt_entry->level;
	to_update = (cur_level <= start_level);
	index = get_pt_level_addr_index(addr, pt_level);
	offset = index * sizeof(pgprotval_t);
	gpte_gpa = gpt_base + offset;
	E2K_KVM_BUG_ON(arch_is_error_gpa(gpte_gpa));
	if (!to_update) {
		if (gpte_gpa != gpt_entry->gpa) {
			DebugNGPT("guest addr 0x%lx PT level %d/%d gpte: "
				"gpa 0x%llx is changed from 0x%llx\n",
				addr, cur_level, start_level, gpte_gpa,
				gpt_entry->gpa);
			E2K_KVM_BUG_ON(true);
		}
	} else {
		DebugNGPT("guest PT level %d/%d addr 0x%lx offset 0x%lx "
			"gpte: gpa 0x%llx\n",
			cur_level, start_level, addr, offset, gpte_gpa);
		E2K_KVM_BUG_ON(gpte_gpa != gpt_entry->gpa);
	}

	ret = kvm_vcpu_get_guest_pte(vcpu, gpte_gpa, gpte, ptep_user,
				     &gpt_entry->writable);
	if (unlikely(ret != 0)) {
		DebugWGPT("get gpte from gpa 0x%llx failed, error %d\n",
			gpte_gpa, ret);
		return ret;
	}
	if (!to_update) {
		if (unlikely((hva_t)ptep_user != gpt_entry->hva)) {
			DebugNGPT("guest addr 0x%lx gpte: gpa 0x%llx level %d/%d "
				"hva is changed from 0x%lx to 0x%lx\n",
				addr, gpte_gpa, cur_level, start_level,
				gpt_entry->hva, (hva_t)ptep_user);
			E2K_KVM_BUG_ON(true);
		}
		if (gpte != gpt_entry->gpte) {
			DebugNGPT("guest addr 0x%lx gpte: gpa 0x%llx level %d/%d "
				"is changed from 0x%lx to 0x%lx\n",
				addr, gpte_gpa, cur_level, start_level,
				gpt_entry->gpte, gpte);
			return other_gpte_state;
		}
	} else {
		DebugNGPT("guest addr 0x%lx gpte: level %d/%d from "
			"hva %px : 0x%lx\n",
			addr, cur_level, start_level, ptep_user, gpte);
		E2K_KVM_BUG_ON((hva_t)ptep_user != gpt_entry->hva);
		gpt_entry->gpte = gpte;
	}
	trace_kvm_mmu_paging_element(__pgprot(gpte), cur_level);

	return 0;
}

static inline int walk_next_addr_range_gpte_level(struct kvm_vcpu *vcpu,
				gva_t start, gva_t end,
				gpa_t gpt_base, gpt_entry_t *gpt_entry,
				const pt_level_t *pt_level, int start_level)
{
	unsigned long index, start_index, end_index, offset;
	gva_t end_addr, start_page, end_page;
	long pages_num;
	gpa_t gpte_gpa;
	pgprotval_t *gpt_page;
	unsigned long mask;
	size_t len;
	int cur_level, ret;

	cur_level = gpt_entry->level;
	E2K_KVM_BUG_ON(start_level < cur_level);

	gpt_page = gpt_entry->gpt_page;
	E2K_KVM_BUG_ON(gpt_page == NULL);

	end_addr = end - 1;
	start_page = start & get_pt_level_page_mask(pt_level);
	end_page = end_addr & get_pt_level_page_mask(pt_level);
	pages_num = ((end_page - start_page) >>
				get_pt_level_page_shift(pt_level)) + 1;
	index = get_pt_level_addr_index(start, pt_level);
	start_index = index;
	end_index = start_index + pages_num;
	mask = PTE_PREFETCH_NUM - 1;
	start_index &= ~mask;
	pages_num = end_index - start_index;
	if (pages_num < PTE_PREFETCH_NUM) {
		pages_num = PTE_PREFETCH_NUM;
		end_index = start_index + pages_num;
	}
	if (end_index > get_ptrs_per_pt_level(pt_level)) {
		end_index = get_ptrs_per_pt_level(pt_level);
		pages_num = end_index - start_index;
	}

	offset = start_index * sizeof(pgprotval_t);
	gpte_gpa = gpt_base + offset;
	E2K_KVM_BUG_ON(arch_is_error_gpa(gpte_gpa));
	gpt_entry->gpa = gpte_gpa;
	gpt_entry->gpt_base = gpt_base;
	gpt_entry->start_index = start_index;
	gpt_entry->ptrs_num = pages_num;
	len = pages_num * sizeof(pgprotval_t);
	DebugNGPT("guest PT level %d/%d range 0x%lx - 0x%lx index start 0x%lx "
		"end 0x%lx copy gptes from gpa 0x%llx size 0x%lx\n",
		cur_level, start_level, start, end, start_index, end_index,
		gpte_gpa, len);

	ret = kvm_vcpu_read_guest_pte(vcpu, gpte_gpa, gpt_page + start_index,
				      len, &gpt_entry->hva, &gpt_entry->writable);
	if (unlikely(ret != 0)) {
		DebugWGPT("copy gpte from gpa 0x%llx size 0x%lx failed, "
			"error %d\n",
			gpte_gpa, len, ret);
		return ret;
	}
	gpt_entry->gpte = gpt_page[index];
	DebugNGPT("guest PT level %d/%d range 0x%lx - 0x%lx gpte "
		"from hva 0x%lx : 0x%lx\n",
		cur_level, start_level, start, end,
		gpt_entry->hva, gpt_entry->gpte);
	trace_kvm_mmu_paging_element(__pgprot(gpt_entry->gpte), cur_level);

	return 0;
}

static inline int walk_addr_gptes(struct kvm_vcpu *vcpu, gva_t addr,
				  gpt_walker_t *gpt_walker)
{
	const pt_struct_t *pt_struct = GET_VCPU_PT_STRUCT(vcpu);
	gpt_entry_t *gpt_entry;
	const pt_level_t *pt_level;
	gpa_t gpt_base;
	int level, ret;

	level = gpt_walker->max_level;
	gpt_base = gpt_walker->gpt_root;
	gpt_entry = get_walk_addr_gpte_level(gpt_walker, level);
	pt_level = &pt_struct->levels[level];

	do {
		pgprotval_t gpte;

#ifdef	DO_PTE_PREFETCH
		if (likely(level != PT_PAGE_TABLE_LEVEL)) {
			ret = walk_addr_gpte_level(vcpu, addr,
					gpt_base, gpt_entry, pt_level, level);
		} else {
			ret = walk_addr_range_gpte_level(vcpu, addr, addr,
					gpt_base, gpt_entry, pt_level, level);
		}
#else	/* !DO_PTE_PREFETCH */
		ret = walk_addr_gpte_level(vcpu, addr, gpt_base,
					   gpt_entry, pt_level, level);
#endif	/* DO_PTE_PREFETCH */
		if (unlikely(ret != 0)) {
			pr_err("%s(): failed for guest addr 0x%lx on level %d, "
				"error %d\n",
				__func__, addr, level, ret);
			return ret;
		}

		gpte = gpt_entry->gpte;
		if (unlikely(!is_present_gpte(gpte))) {
			DebugWGPT("guest addr 0x%lx : detected not present "
				"gpte 0x%lx on level %d\n",
				addr, gpte, level);
			break;
		}
		if (unlikely(is_last_gpte(&vcpu->arch.mmu, level, gpte))) {
			DebugWGPT("guest addr 0x%lx : detected last "
				"gpte 0x%lx on level %d\n",
				addr, gpte, level);
			break;
		}
		gpt_base = kvm_gpte_gfn_to_phys_addr(vcpu, __pgprot(gpte));

		--level;
		E2K_KVM_BUG_ON(level <= 0);

		--gpt_entry;
		--pt_level;
	} while (true);

	gpt_walker->min_level = level;

	return 0;
}

static inline int walk_addr_range_gptes(struct kvm_vcpu *vcpu,
				gva_t start, gva_t end,
				gpa_t gpt_root, gpt_walker_t *gpt_walker)
{
	const pt_struct_t *pt_struct = GET_VCPU_PT_STRUCT(vcpu);
	gpt_entry_t *gpt_entry;
	const pt_level_t *pt_level;
	gva_t end_addr;
	gpa_t gpt_base;
	int level, ret;

	E2K_KVM_BUG_ON((start & ~PAGE_MASK) != 0 || (end & ~PAGE_MASK) != 0);
	end_addr = end - 1;
	level = gpt_walker->max_level;
	E2K_KVM_BUG_ON(gpt_root != gpt_walker->gpt_root);
	gpt_base = gpt_root;
	gpt_entry = get_walk_addr_gpte_level(gpt_walker, level);
	pt_level = &pt_struct->levels[level];

	do {
		pgprotval_t gpte;

		if (likely(level != PT_PAGE_TABLE_LEVEL)) {
			ret = walk_addr_gpte_level(vcpu, start,
					gpt_base, gpt_entry, pt_level, level);
		} else {
			ret = walk_addr_range_gpte_level(vcpu, start, end,
					gpt_base, gpt_entry, pt_level, level);
		}
		if (unlikely(ret != 0)) {
			pr_err("%s(): failed for guest range 0x%lx - 0x%lx "
				"on level %d, error %d\n",
				__func__, start, end, level, ret);
			return ret;
		}

		if (unlikely(level == PT_PAGE_TABLE_LEVEL))
			break;

		gpte = gpt_entry->gpte;
		if (unlikely(!is_present_gpte(gpte))) {
			DebugWGPT("guest range 0x%lx - 0x%lx : detected "
				"not present gpte 0x%lx on level %d\n",
				start, end, gpte, level);
			break;
		}
		if (unlikely(is_last_gpte(&vcpu->arch.mmu, level, gpte))) {
			E2K_KVM_BUG_ON(!is_huge_gpte(vcpu, gpte));
			DebugWGPT("guest range 0x%lx - 0x%lx : detected last "
				"gpte 0x%lx on level %d\n",
				start, end, gpte, level);
			break;
		}
		gpt_base = kvm_gpte_gfn_to_phys_addr(vcpu, __pgprot(gpte));

		--level;
		E2K_KVM_BUG_ON(level <= 0);

		--gpt_entry;
		--pt_level;
	} while (true);

	gpt_walker->min_level = level;

	return 0;
}

static inline int walk_next_addr_range_gptes(struct kvm_vcpu *vcpu,
				gva_t start, gva_t end,
				gpt_walker_t *gpt_walker, int start_level)
{
	const pt_struct_t *pt_struct = GET_VCPU_PT_STRUCT(vcpu);
	gpt_entry_t *gpt_entry;
	const pt_level_t *pt_level;
	gva_t end_addr;
	gpa_t gpt_base;
	int cur_level, ret;

	E2K_KVM_BUG_ON((start & ~PAGE_MASK) != 0 || (end & ~PAGE_MASK) != 0);
	end_addr = end - 1;
	gpt_base = gpt_walker->gpt_root;
	cur_level = gpt_walker->max_level;
	gpt_entry = get_walk_addr_gpte_level(gpt_walker, cur_level);
	pt_level = &pt_struct->levels[cur_level];

	do {
		pgprotval_t gpte;

		if (likely(cur_level != PT_PAGE_TABLE_LEVEL)) {
			if (cur_level >= start_level) {
				ret = walk_next_addr_gpte_level(vcpu, start,
					gpt_base, gpt_entry, pt_level, start_level);
			} else {
				ret = walk_addr_gpte_level(vcpu, start,
					gpt_base, gpt_entry, pt_level, cur_level);
			}
		} else {
			if (cur_level >= start_level) {
				ret = walk_next_addr_range_gpte_level(vcpu,
						start, end, gpt_base, gpt_entry,
						pt_level, start_level);
			} else {
				ret = walk_addr_range_gpte_level(vcpu,
						start, end, gpt_base, gpt_entry,
						pt_level, cur_level);
			}
		}
		if (unlikely(ret != 0)) {
			if (ret < 0) {
				pr_err("%s(): failed for guest range 0x%lx - 0x%lx "
					"on level %d/%d, error %d\n",
					__func__, start, end,
					cur_level, start_level, ret);
			}
			return ret;
		}

		if (unlikely(cur_level == PT_PAGE_TABLE_LEVEL))
			break;

		gpte = gpt_entry->gpte;
		if (unlikely(!is_present_gpte(gpte))) {
			DebugWGPT("guest range 0x%lx - 0x%lx : detected "
				"not present gpte 0x%lx on level %d/%d\n",
				start, end, gpte, cur_level, start_level);
			E2K_KVM_BUG_ON(cur_level > start_level);
			break;
		}
		if (unlikely(is_last_gpte(&vcpu->arch.mmu, cur_level, gpte))) {
			E2K_KVM_BUG_ON(!is_huge_gpte(vcpu, gpte));
			DebugWGPT("guest range 0x%lx - 0x%lx : detected last "
				"gpte 0x%lx on level %d/%d\n",
				start, end, gpte, cur_level, start_level);
			E2K_KVM_BUG_ON(cur_level > start_level);
			break;
		}
		gpt_base = kvm_gpte_gfn_to_phys_addr(vcpu, __pgprot(gpte));

		--cur_level;
		E2K_KVM_BUG_ON(cur_level <= 0);

		--gpt_entry;
		--pt_level;
	} while (true);

	gpt_walker->min_level = cur_level;

	return 0;
}

static int kvm_vcpu_read_guest_pte(struct kvm_vcpu *vcpu, gpa_t gpa, void *dst,
					int len, hva_t *hvap, bool *writable)
{
	unsigned offset;
	hva_t hva;
	int ret;

	offset = offset_in_page(gpa);

	E2K_KVM_BUG_ON(len + offset > PAGE_SIZE);

	hva = kvm_vcpu_gfn_to_hva_prot(vcpu, gpa_to_gfn(gpa), writable);
	if (unlikely(kvm_is_error_hva(hva))) {
		DebugWGPT("gpa 0x%llx to get hva failed\n",
			gpa);
		return -EFAULT;
	}
	hva += offset;
	if (hvap != NULL)
		*hvap = hva;

	ret = __copy_from_user(dst, (void __user *)hva, len);
	if (unlikely(ret)) {
		DebugWGPT("__copy_from_user() hva 0x%lx failed\n",
			hva);
		return -EFAULT;
	}

	return 0;
}

static inline gpte_state_t
get_addr_gpte_atomic(struct kvm_vcpu *vcpu, gva_t addr, pgprotval_t *gpte_atomic_p,
			gpa_t gpte_gpa, gpt_walker_t *gpt_walker, int level)
{
	gpt_entry_t *gpt_entry;
	pgprotval_t gpte;
	hva_t gpte_hva;
	unsigned offset;
	int ret;

	if (unlikely(level > gpt_walker->max_level ||
					level < gpt_walker->min_level)) {
		DebugAGPT("guest addr 0x%lx gpt level %d is out of walk "
			"pt entries level(s) %d -> %d\n",
			addr, level, gpt_walker->max_level, gpt_walker->min_level);
		return level_out_gpte_state;
	}

	gpt_entry = get_walk_addr_gpte_level(gpt_walker, level);
	if (unlikely(gpte_gpa != gpt_entry->gpa)) {
		DebugAGPT("guest addr 0x%lx gpte: gpa 0x%llx is changed "
			"from 0x%llx\n",
			addr, gpte_gpa, gpt_entry->gpa);
		return other_gpa_gpte_state;
	}

	offset = offset_in_page(gpte_gpa);
	gpte_hva = kvm_vcpu_gfn_to_hva_prot(vcpu, gpa_to_gfn(gpte_gpa), NULL);
	if (unlikely(kvm_is_error_hva(gpte_hva))) {
		DebugAGPT("guest addr 0x%lx gpte: gpa 0x%llx to get hva failed\n",
			addr, gpte_gpa);
		return -EFAULT;
	}
	gpte_hva += offset;
	if (unlikely(gpte_hva != gpt_entry->hva)) {
		DebugAGPT("guest addr 0x%lx gpte: hva 0x%lx is changed "
			"from 0x%lx\n",
			addr, gpte_hva, gpt_entry->hva);
		return other_hva_gpte_state;
	}

	ret = kvm_vcpu_get_gpte_hva_atomic(gpte, gpte_hva);
	if (unlikely(ret != 0)) {
		DebugAGPT("guest addr 0x%lx gpte: gpa 0x%llx, hva 0x%lx failed, "
			"error %d\n",
			addr, gpte_gpa, gpt_entry->hva, ret);
		return ret;
	}

	if (unlikely(gpte != gpt_entry->gpte)) {
		DebugAGPT("guest addr 0x%lx gpte: gpa 0x%llx level %d is changed "
			"from 0x%lx to 0x%lx\n",
			addr, gpte_gpa, level, gpt_entry->gpte, gpte);
		return other_gpte_state;
	}

	if (likely(gpte_atomic_p != NULL))
		*gpte_atomic_p = gpte;

	return same_gpte_state;
}

static inline gpte_state_t
get_addr_range_gpte_atomic(struct kvm_vcpu *vcpu, gva_t addr,
			pgprotval_t *gpte_atomic_p, gpa_t gpte_gpa,
			pgprotval_t *gpt_page, pgprotval_t *gpt_page_atomic,
			gpt_walker_t *gpt_walker,
			const pt_level_t *pt_level, int level)
{
	gpt_entry_t *gpt_entry;
	pgprotval_t gpte, gpte_atomic;
	gpa_t gpa;
	size_t len;
	unsigned long index;

	if (unlikely(level > gpt_walker->max_level ||
					level < gpt_walker->min_level)) {
		DebugAGPT("guest addr 0x%lx gpt level %d is out of walk "
			"pt entries level(s) %d -> %d\n",
			addr, level, gpt_walker->max_level, gpt_walker->min_level);
		return level_out_gpte_state;
	}

	if (unlikely(level != PT_PAGE_TABLE_LEVEL)) {
		return get_addr_gpte_atomic(vcpu, addr, gpte_atomic_p,
					    gpte_gpa, gpt_walker, level);
	}

	gpt_entry = get_walk_addr_gpte_level(gpt_walker, level);
	gpa = gpt_entry->gpa;
	len = gpt_entry->ptrs_num * sizeof(pgprot_t);
	if (unlikely(gpte_gpa < gpa || gpte_gpa >= gpa + len)) {
		DebugNGPT("guest addr 0x%lx gpte: gpa 0x%llx is changed "
			"from 0x%llx\n",
			addr, gpte_gpa, gpa);
		return other_gpa_gpte_state;
	}

	index = get_pt_level_addr_index(addr, pt_level);
	E2K_KVM_BUG_ON(index < gpt_entry->start_index ||
			index >= gpt_entry->start_index + gpt_entry->ptrs_num);
	gpte = gpt_page[index];
	gpte_atomic = gpt_page_atomic[index];
	if (unlikely(gpte_atomic != gpte)) {
		DebugNGPT("guest addr 0x%lx gpte: gpa 0x%llx level %d is changed "
			"from 0x%lx to 0x%lx\n",
			addr, gpte_gpa, level, gpte, gpte_atomic);
		return other_gpte_state;
	}

	if (likely(gpte_atomic_p != NULL))
		*gpte_atomic_p = gpte_atomic;

	return same_gpte_state;
}

static inline gpte_state_t
copy_addr_range_gptes_atomic(struct kvm_vcpu *vcpu, gva_t start, gva_t end,
			     gpa_t gpte_gpa, gpt_walker_t *gpt_walker, int level)
{
	gpt_entry_t *gpt_entry;
	pgprotval_t *gpt_atomic;
	gpa_t gpa;
	hva_t hva;
	size_t len;
	unsigned offset;
	int ret;

	E2K_KVM_BUG_ON(level != PT_PAGE_TABLE_LEVEL);

	if (unlikely(level > gpt_walker->max_level ||
					level < gpt_walker->min_level)) {
		DebugNGPT("guest range 0x%lx - 0x%lx gpt level %d is out of walk "
			"pt entries level(s) %d -> %d\n",
			start, end, level, gpt_walker->max_level,
			gpt_walker->min_level);
		return level_out_gpte_state;
	}

	gpt_entry = get_walk_addr_gpte_level(gpt_walker, level);
	gpa = gpt_entry->gpa;
	len = gpt_entry->ptrs_num * sizeof(pgprot_t);
	if (unlikely(gpa < gpte_gpa || gpa > gpte_gpa + len)) {
		DebugNGPT("guest range 0x%lx - 0x%lx gpte: gpa 0x%llx is changed "
			"from 0x%llx\n",
			start, end, gpte_gpa, gpa);
		return other_gpa_gpte_state;
	}

	offset = offset_in_page(gpte_gpa);
	hva = kvm_vcpu_gfn_to_hva_prot(vcpu, gpa_to_gfn(gpte_gpa), NULL);
	if (unlikely(kvm_is_error_hva(hva))) {
		pr_err("%s(): guest range 0x%lx - 0x%lx gpte: gpa 0x%llx to get "
			"hva failed\n",
			__func__, start, end, gpte_gpa);
		return -EFAULT;
	}
	hva += offset;
	if (unlikely(gpt_entry->hva < hva || gpt_entry->hva > hva + len)) {
		pr_err("%s(): guest range 0x%lx -0x%lx gpte: hva 0x%lx is changed "
			"from 0x%lx\n",
			__func__, start, end, hva, gpt_entry->hva);
		return -EFAULT;
	}

	gpt_atomic = gpt_entry->gpt_page_atomic + gpt_entry->start_index;

	pagefault_disable();
	ret = __copy_from_user_inatomic(gpt_atomic, (void __user *)hva, len);
	pagefault_enable();
	if (unlikely(ret != 0)) {
		DebugNGPT("guest range 0x%lx - 0x%lx gpte: gpa 0x%llx, "
			"hva 0x%lx failed, error %d\n",
			start, end, gpte_gpa, hva, ret);
		return ret;
	}
	DebugNGPT("guest range 0x%lx - 0x%lx copied from %px to %px size 0x%lx\n",
		start, end, (void __user *)hva, gpt_atomic, len);

	return 0;
}

static inline void FNAME(protect_clean_gpte)(unsigned *access, unsigned gpte)
{
	unsigned mask;

	/* dirty bit is not supported, so no need to track it */
	if (!PT_GUEST_DIRTY_MASK)
		return;

	BUILD_BUG_ON(PT_WRITABLE_MASK != ACC_WRITE_MASK);

	mask = (unsigned)~ACC_WRITE_MASK;
	/* Allow write access to dirty gptes */
	if (gpte & PT_GUEST_DIRTY_MASK)
		mask |= ACC_WRITE_MASK;
	*access &= mask;
}

static int FNAME(cmpxchg_gpte)(struct kvm_vcpu *vcpu, struct kvm_mmu *mmu,
			       pgprotval_t __user *ptep_user, unsigned index,
			       pgprotval_t orig_pte, pgprotval_t new_pte)
{
	int npages;
	pgprotval_t ret;
	pgprotval_t *table;
	struct page *page;

	npages = get_user_pages_fast((unsigned long)ptep_user, 1, FOLL_WRITE, &page);
	/* Check if the user is doing something meaningless. */
	if (unlikely(npages != 1))
		return -EFAULT;

	table = kmap_atomic(page);
	ret = CMPXCHG(&table[index], orig_pte, new_pte);
	kunmap_atomic(table);

	kvm_release_page_dirty(page);

	return (ret != orig_pte);
}

static bool FNAME(prefetch_invalid_gpte)(struct kvm_vcpu *vcpu,
				  struct kvm_mmu_page *sp, pgprot_t *sptep,
				  u64 gpte)
{
	if (unlikely(!is_last_spte(*sptep, sp->role.level)))
		return false;

	if (is_rsvd_bits_set(&vcpu->arch.mmu, gpte, PT_PAGE_TABLE_LEVEL))
		goto no_present;

	if (!is_present_gpte(gpte))
		goto no_present;

	/* if accessed bit is not supported prefetch non accessed gpte */
	if (PT_GUEST_ACCESSED_MASK && !(gpte & PT_GUEST_ACCESSED_MASK))
		goto no_present;

	return false;

no_present:
	drop_spte(vcpu->kvm, sptep);
	if (unlikely(is_unmapped_gpte(vcpu, gpte))) {
		clear_spte(vcpu->kvm, sptep);
	} else if (is_only_valid_gpte(vcpu, gpte)) {
		return false;
	}
	return true;
}

/*
 * Here, we repurpose ACC_USER_MASK to signify readability
 * since it isn't used in the EPT case
 */
static inline unsigned
FNAME(gpte_access)(struct kvm_vcpu *vcpu, u64 gpte, gva_t gva)
{
	unsigned access;
	bool priv_access;

	BUILD_BUG_ON(ACC_EXEC_MASK != PT_PRESENT_MASK);
	BUILD_BUG_ON(ACC_EXEC_MASK != 1);
	access = gpte & (PT_WRITABLE_MASK | PT_PRESENT_MASK);
	/* e2k arch can have protection bit 'priv' instead of 'user', */
	/* so it need invert access permition or set in special case */
	priv_access = ((gpte & get_gpte_mode_mask(vcpu)) ? true : false);

	/* Combine NX with P (which is set here) to get ACC_EXEC_MASK.  */
	if (gpte & get_gpte_nx_mask(vcpu))
		access ^= ACC_EXEC_MASK;

	if (likely(get_gpte_priv_mask(vcpu))) {
		if (unlikely(priv_access)) {
			if (likely(vcpu->arch.is_hv)) {
				/* it need keep all protections of the guest */
				;
			} else if (unlikely(is_guest_user_gva(gva))) {
				/* special case: user hardware stacks */
				/* should be privileged */
				access |= (ACC_PRIV_MASK | ACC_USER_MASK);
			} else if (IS_INVALID_GVA(gva)) {
				/* it is guest kernel PT entry */
				;
			} else {
				E2K_KVM_BUG_ON(!is_guest_kernel_gva(gva));
			}
		} else {
			access |= ACC_USER_MASK;
		}
	} else {
		E2K_KVM_BUG_ON(true);
	}

	return access;
}

static inline u64 FNAME(gpte_cui)(u64 gpte)
{
	return !cpu_has(CPU_FEAT_ISET_V6) ?
		_PAGE_INDEX_FROM_CUNIT_V3(gpte) : 0;
}

static int update_accessed_dirty_bits(struct kvm_vcpu *vcpu,
				      struct kvm_mmu *mmu,
				      guest_walker_t *walker,
				      gpt_walker_t *gpt_walker,
				      int write_fault)
{
	gpt_entry_t *gpt_entry;
	unsigned level, index;
	pgprotval_t pte, orig_pte;
	pgprotval_t __user *ptep_user;
	gfn_t table_gfn;
	int ret;

	/* dirty/accessed bits are not supported, so no need to update them */
	if (!PT_GUEST_DIRTY_MASK)
		return 0;

	for (level = walker->max_level; level >= walker->level; --level) {
		gpt_entry = get_walk_addr_gpte_level(gpt_walker, level);
		pte = gpt_entry->gpte;
		orig_pte = pte;
		table_gfn = gpa_to_gfn(gpt_entry->gpt_base);
		ptep_user = (pgprotval_t __user *)gpt_entry->hva;
		index = offset_in_page(ptep_user) / sizeof(pgprotval_t);
		if (!(pte & PT_GUEST_ACCESSED_MASK)) {
			trace_kvm_mmu_set_accessed_bit(table_gfn, index,
							sizeof(pte));
			pte |= PT_GUEST_ACCESSED_MASK;
		}
		if (level == walker->level && write_fault &&
				!(pte & PT_GUEST_DIRTY_MASK)) {
			trace_kvm_mmu_set_dirty_bit(table_gfn, index,
							sizeof(pte));
			pte |= PT_GUEST_DIRTY_MASK;
		}
		if (pte == orig_pte)
			continue;

		/*
		 * If the slot is read-only, simply do not process the accessed
		 * and dirty bits.  This is the correct thing to do if the slot
		 * is ROM, and page tables in read-as-ROM/write-as-MMIO slots
		 * are only supported if the accessed and dirty bits are already
		 * set in the ROM (so that MMIO writes are never needed).
		 *
		 * Note that NPT does not allow this at all and faults, since
		 * it always wants nested page table entries for the guest
		 * page tables to be writable.  And EPT works but will simply
		 * overwrite the read-only memory to set the accessed and dirty
		 * bits.
		 */
		if (unlikely(!gpt_entry->writable))
			continue;

		ret = FNAME(cmpxchg_gpte)(vcpu, mmu, ptep_user, index,
						orig_pte, pte);
		if (ret)
			return ret;

		kvm_vcpu_mark_page_dirty(vcpu, table_gfn);
		gpt_entry->gpte = pte;
	}
	return 0;
}

static inline unsigned FNAME(gpte_pkeys)(struct kvm_vcpu *vcpu, u64 gpte)
{
	return 0;
}

static inline bool trace_kvm_guest_pt_walk_on(u32 access)
{
	if (unlikely(trace_kvm_gva_to_gpa_enabled()))
		return true;
	if (trace_kvm_spt_page_fault_enabled() && (access & PFERR_PT_FAULT_MASK))
		return true;
	return false;
}

/*
 * Fetch a guest pte for a guest virtual address
 */
static int walk_addr_generic(guest_walker_t *walker, gpt_walker_t *gpt_walker,
			     struct kvm_vcpu *vcpu, struct kvm_mmu *mmu,
			     gva_t addr, u32 access)
{
	int ret;
	int level;
	const pt_level_t *pt_level;
	pgprotval_t gpte;
	u64 pte_cui;
	unsigned pt_access, pte_access, accessed_dirty, pte_pkey;
	const int write_fault = access & PFERR_WRITE_MASK;
	const int user_fault  = access & PFERR_USER_MASK;
	const int fetch_fault = access & PFERR_FETCH_MASK;
	const int access_size = PFRES_GET_ACCESS_SIZE(access);
	u16 errcode = 0;
	gfn_t gfn;

	if (trace_kvm_guest_pt_walk_on(access)) {
		trace_kvm_mmu_pagetable_walk(addr, access);
	}
	DebugSPF("address 0x%lx, fault: write %d user %d fetch %d\n",
		addr, write_fault, user_fault, fetch_fault);

retry_walk:

	ret = walk_addr_gptes(vcpu, addr, gpt_walker);
	if (unlikely(ret != 0)) {
		pr_err("%s(): walk through the guest PTs failed for guest "
			"addr 0x%lx, error %d\n",
			__func__, addr, ret);
		return ret;
	}
	walker->level = mmu->root_level;
	walker->pt_struct = GET_VCPU_PT_STRUCT(vcpu);
	walker->pt_level = &walker->pt_struct->levels[mmu->root_level];
	walker->fault.error_code_valid = false;
	walker->fault.error_code = 0;

	walker->max_level = walker->level;

	ASSERT(is_ss(vcpu) && !(is_long_mode(vcpu) && !is_pae(vcpu)));

	accessed_dirty = PT_GUEST_ACCESSED_MASK;

	pt_access = ACC_USER_ALL;
	pte_access = ACC_USER_ALL;

	do {
		gpt_entry_t *gpt_entry;

		level = walker->level;
		pt_level = walker->pt_level;

		/*
		 * protections PT directories entries and page entries are
		 * independent for e2k arch, for example ptds always
		 * privileged and non-executable. ptes do not inherit ptds
		 * protections aoutomaticaly and can have own protection,
		 * for example executable and/or user pages
		 */
		pt_access = pte_access;
		pte_access = ACC_USER_ALL;

		gpt_entry = get_walk_addr_gpte_level(gpt_walker, level);
		gpte = gpt_entry->gpte;
		if (trace_kvm_guest_pt_walk_on(access)) {
			trace_kvm_mmu_paging_element(__pgprot(gpte), level);
		}

		if (unlikely(!is_present_gpte(gpte))) {
			if (is_unmapped_gpte(vcpu, gpte)) {
				errcode |= PFERR_IS_UNMAPPED_MASK;
			} else if (is_only_valid_gpte(vcpu, gpte)) {
				errcode |= PFERR_ONLY_VALID_MASK;
			} else if (is_valid_gpte(vcpu, gpte)) {
				errcode |= PFERR_ONLY_VALID_MASK;
			}
			goto error;
		}

		if (unlikely(is_rsvd_bits_set(mmu, gpte, walker->level))) {
			errcode = PFERR_RSVD_MASK | PFERR_PRESENT_MASK;
			goto error;
		}
		DebugSPF("guest pte is present and has not reserved bits\n");

		accessed_dirty &= gpte;

		pte_cui = FNAME(gpte_cui)(gpte);
		/* protections PT directories entries and page entries are */
		/* independent for e2k arch, see full comment above */
		pte_access &= FNAME(gpte_access)(vcpu, gpte, addr);
		E2K_KVM_BUG_ON((pte_access & ACC_PRIV_MASK) &&
				!(pte_access & ACC_USER_MASK));

		if (is_last_gpte(mmu, level, gpte))
			break;

		--walker->level;
		--walker->pt_level;
	} while (true);

	pte_pkey = FNAME(gpte_pkeys)(vcpu, gpte);
	DebugSPF("pte: access 0x%x, pkey 0x%x, pt access 0x%x, errcode 0x%x\n",
		pte_access, pte_pkey, pt_access, errcode);
	errcode = permission_fault(vcpu, mmu, pte_access, pte_pkey, access);
	if (unlikely(errcode))
		goto error;

	if (!(access & (PFERR_WRITE_MASK | PFERR_WAIT_LOCK_MASK |
			PFERR_INSTR_FAULT_MASK | PFERR_INSTR_PROT_MASK)) &&
			!(access & PFERR_FAPB_MASK) &&
				(access & PFERR_PT_FAULT_MASK) &&
					!(pte_access & ACC_WRITE_MASK)) {
		/*
		 * Try read from write protected page (by gpte).
		 * Probably there is(are) before some write(s) to this page
		 * injected as page fault(s) for guest and it need
		 * to pre-handle this(these) faulted write(s).
		 * Such loads should be injected for guest too
		 */
		if (check_injected_stores_to_addr(vcpu, addr, access_size)) {
			/* there is(are) such store(s) to same load address */
			errcode |= PFERR_READ_PROT_MASK;
			DebugRPROT("found read addr 0x%lx croses previous "
				"store to same page\n",
				addr);
			goto error;
		}
	}

	gfn = gpte_to_gfn_level_address(vcpu, addr, gpte, walker->pt_level);
	walker->gfn = gfn;

	if (!write_fault) {
		FNAME(protect_clean_gpte)(&pte_access, gpte);
		DebugSPF("not write fault, so clean guest pte, "
			"new pte access 0x%x\n",
			pte_access);
	} else {
		/*
		 * On a write fault, fold the dirty bit into accessed_dirty.
		 * For modes without A/D bits support accessed_dirty will be
		 * always clear.
		 */
		if (!(gpte & PT_GUEST_DIRTY_MASK))
			accessed_dirty &= ~PT_GUEST_ACCESSED_MASK;
		DebugSPF("on write fault, accessed dirty 0x%x\n",
			accessed_dirty);
	}

	if (unlikely(!accessed_dirty)) {
		ret = update_accessed_dirty_bits(vcpu, mmu, walker, gpt_walker,
						 write_fault);
		DebugSPF("not accessed dirty, update dirty bits returned %d\n",
			ret);
		if (unlikely(ret < 0))
			goto error;
		else if (ret)
			goto retry_walk;
	}

	walker->pt_access = pt_access;
	walker->pte_access = pte_access;
	walker->pte_cui = pte_cui;
	pgprintk("%s: pte %llx pte_access %x pt_access %x\n",
		 __func__, (u64)gpte, pte_access, pt_access);
	return 1;

error:
	errcode |= write_fault | user_fault;
	if (fetch_fault && (mmu->nx || is_smep(vcpu)))
		errcode |= PFERR_FETCH_MASK;

	walker->fault.error_code_valid = true;
	walker->fault.error_code = errcode;
	walker->fault.address = addr;

	if (trace_kvm_guest_pt_walk_on(access)) {
		trace_kvm_mmu_walker_error(walker->fault.error_code);
	}
	DebugSPF("returns error code 0x%x, for addr 0x%lx\n",
		errcode, addr);
	return 0;
}

static int walk_addr(guest_walker_t *walker, gpt_walker_t *gpt_walker,
		     struct kvm_vcpu *vcpu, gva_t addr, u32 access)
{
	return walk_addr_generic(walker, gpt_walker, vcpu, &vcpu->arch.mmu,
				 addr, access);
}

static bool
FNAME(prefetch_gpte)(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp,
		     pgprot_t *spte, pgprotval_t gpte, bool no_dirty_log)
{
	pgprot_t old_spte;
	unsigned pte_access;
	gfn_t gfn;
	kvm_pfn_t pfn;
#ifdef	KVM_ARCH_WANT_MMU_NOTIFIER
	intc_mu_state_t *mu_state = get_intc_mu_state(vcpu);
#endif	/* KVM_ARCH_WANT_MMU_NOTIFIER */
	bool gfn_only_valid = false;
	u64 pte_cui;
	int ret;

	trace_kvm_prefetch_gpte(vcpu, sp, spte, gpte);

	old_spte = *spte;
	if (FNAME(prefetch_invalid_gpte)(vcpu, sp, spte, gpte)) {
		trace_kvm_sync_spte(spte, old_spte, sp->role.level);
		return false;
	}

	pgprintk("%s: gpte %llx spte %px\n", __func__, (u64)gpte, spte);

	if (is_only_valid_gpte(vcpu, gpte)) {
		gfn_only_valid = true;
		gfn = 0;
		pfn = 0;
		pte_access = 0;
		pte_cui = 0;
		goto write_spte;
	}

	gfn = gpte_to_gfn_level_sp(vcpu, sp, spte, gpte);
	pte_cui = FNAME(gpte_cui)(gpte);
	pte_access = FNAME(gpte_access)(vcpu, gpte, sp->gva);
	FNAME(protect_clean_gpte)(&pte_access, gpte);

#ifdef	KVM_ARCH_WANT_MMU_NOTIFIER
	mu_state->notifier_seq = vcpu->kvm->mmu_notifier_seq;
#endif	/* KVM_ARCH_WANT_MMU_NOTIFIER */

	ret = try_atomic_pf(vcpu, gfn, &pfn,
			no_dirty_log && (pte_access & ACC_WRITE_MASK));

#ifdef	KVM_ARCH_WANT_MMU_NOTIFIER
	if (unlikely(!mmu_notifier_no_retry(vcpu->kvm, mu_state->notifier_seq))) {
		/* MMU notifier is now in progress, and PFN cannot be considered */
		/* as final. Prefetch cannot be retried, therefore it need */
		/* leave the address only valid in order to cause page fault */
		/* on first access and get real PFN */
		DebugRETRY("VCPU #%d notifier retry gfn 0x%llx pfn 0x%llx "
			"gpte 0x%llx spte %px == 0x%lx\n",
			vcpu->vcpu_id, gfn, pfn, (u64)gpte, spte,
			pgprot_val(*spte));
		kvm_release_pfn_clean(pfn);
		ret = TRY_PF_ONLY_VALID_ERR;
	}
#endif	/* KVM_ARCH_WANT_MMU_NOTIFIER */

	if (likely(ret == TRY_PF_NO_ERR)) {
		/* valid guest gfn rmapped to pfn */
	} else if (ret == TRY_PF_ONLY_VALID_ERR) {
		/* gfn with only valid flag */
		gfn_only_valid = true;
		gfn = 0;
		pfn = 0;
		pte_access = 0;
	} else if (ret == TRY_PF_MMIO_ERR) {
		/* gfn is from MMIO space, but not registered on host */
		DebugSYNCV("gfn 0x%llx is from MMIO space, but not "
			"registered on host\n",
			gfn);
	} else if (ret < 0) {
		pr_err("%s(): gfn 0x%llx is inavlid, error %d\n",
			__func__, gfn, ret);
		return false;
	} else {
		E2K_KVM_BUG_ON(true);
	}

write_spte:
	/*
	 * we call mmu_set_spte() with host_writable = true because
	 * pte_prefetch_gfn_to_pfn always gets a writable pfn.
	 */
	old_spte = *spte;
	mmu_set_spte(vcpu, spte, pte_access, 0, sp->role.level, gfn, pfn,
		     true, true, gfn_only_valid, pte_cui);
	if (likely(!gfn_only_valid)) {
		trace_kvm_sync_spte(spte, old_spte, sp->role.level);
	} else {
		trace_kvm_sync_only_valid(spte, sp->role.level);
	}

	return (!gfn_only_valid) ? true : false;
}

static void update_spte(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp,
			pgprot_t *spte, pgprotval_t gpte)
{
	FNAME(prefetch_gpte)(vcpu, sp, spte, gpte, false);
}

#ifdef	DO_PTE_PREFETCH
static void pte_prefetch(struct kvm_vcpu *vcpu, gpt_walker_t *gpt_walker,
			 pgprot_t *sptep)
{
	struct kvm_mmu_page *sp;
	pgprotval_t gpte, gpte_atomic;
	pgprot_t *spte;
	pgprotval_t *gpt_page, *gpt_page_atomic;
	gpt_entry_t *gpt_entry;
	int i, start_index, level;

	sp = page_header(__pa(sptep));
	level = sp->role.level;
	if (sp->role.level > PT_PAGE_TABLE_LEVEL)
		return;

	if (sp->role.direct)
		return __direct_pte_prefetch(vcpu, sp, sptep);

	gpt_entry = get_walk_addr_gpte_level(gpt_walker, level);
	start_index = (sptep - sp->spt) & ~(PTE_PREFETCH_NUM - 1);
	E2K_KVM_BUG_ON(start_index < gpt_entry->start_index ||
			start_index + PTE_PREFETCH_NUM >
				gpt_entry->start_index + gpt_entry->ptrs_num);
	spte = sp->spt + start_index;

	gpt_page = gpt_entry->gpt_page;
	gpt_page_atomic = gpt_entry->gpt_page_atomic;

	for (i = 0; i < PTE_PREFETCH_NUM; i++, spte++) {
		if (spte == sptep)
			continue;

		if (is_shadow_present_pte(vcpu->kvm, *spte))
			continue;

		gpte = gpt_page[start_index + i];
		gpte_atomic = gpt_page_atomic[start_index + i];
		if (unlikely(gpte != gpte_atomic)) {
			pr_err("%s(): guest pte has been changed from 0x%lx "
				"to 0x%lx, no further prefetch is possible\n",
				__func__, gpte, gpte_atomic);
			return;
		}
		if (!FNAME(prefetch_gpte)(vcpu, sp, spte, gpte, true))
			break;
	}
}
#else	/* !DO_PTE_PREFETCH */
static void pte_prefetch(struct kvm_vcpu *vcpu, gpt_walker_t *gpt_walker,
			 pgprot_t *sptep)
{
}
#endif	/* DO_PTE_PREFETCH */

#ifdef	CHECK_GPTE_CHANGED
static gpte_state_t gpte_changed(struct kvm_vcpu *vcpu, gpt_walker_t *gpt_walker,
				 gva_t gva, int level)
{
	pgprotval_t cur_gpte;
	gpt_entry_t *gpt_entry = get_walk_addr_gpte_level(gpt_walker, level);
	gpa_t gpte_gpa = gpt_entry->gpa;
	const pt_struct_t *pt_struct = GET_VCPU_PT_STRUCT(vcpu);
	const pt_level_t *pt_level = &pt_struct->levels[level];
	gpte_state_t r;

	if (level == PT_PAGE_TABLE_LEVEL) {
#ifdef	DO_PTE_PREFETCH
		pgprotval_t *gpt_page, *gpt_page_atomic;
		gpa_t start_gpa;

		start_gpa = gpt_entry->gpt_base +
				gpt_entry->start_index * sizeof(pgprotval_t);
		r = copy_addr_range_gptes_atomic(vcpu, gva, gva, start_gpa,
						 gpt_walker, level);
		if (unlikely(r != 0))
			return r;
		gpt_page = gpt_entry->gpt_page;
		gpt_page_atomic = gpt_entry->gpt_page_atomic;
		r = get_addr_range_gpte_atomic(vcpu, gva, &cur_gpte,
				gpte_gpa, gpt_page, gpt_page_atomic,
				gpt_walker, pt_level, level);
#else	/* !DO_PTE_PREFETCH */
		r = get_addr_gpte_atomic(vcpu, gva, &cur_gpte,
					 gpte_gpa, gpt_walker, level);
#endif	/* DO_PTE_PREFETCH */
	} else {
		r = get_addr_gpte_atomic(vcpu, gva, &cur_gpte,
					 gpte_gpa, gpt_walker, level);
	}
	DebugSPF("level #%d gpte gpa 0x%llx pte cur 0x%lx old 0x%lx\n",
		level, gpte_gpa, cur_gpte, gpt_entry->gpte);

	return r;
}
#else	/* !CHECK_GPTE_CHANGED */
static gpte_state_t gpte_changed(struct kvm_vcpu *vcpu, gpt_walker_t *gpt_walker,
				 gva_t gva, int level)
{
#ifdef	DO_PTE_PREFETCH
	if (level == PT_PAGE_TABLE_LEVEL) {
		gpt_entry_t *gpt_entry;
		gpa_t start_gpa;
		gpte_state_t r;

		gpt_entry = get_walk_addr_gpte_level(gpt_walker, level);
		start_gpa = gpt_entry->gpt_base +
				gpt_entry->start_index * sizeof(pgprotval_t);
		r = copy_addr_range_gptes_atomic(vcpu, gva, gva, start_gpa,
						 gpt_walker, level);
	}
#endif	/* DO_PTE_PREFETCH */
	return same_gpte_state;
}
#endif	/* CHECK_GPTE_CHANGED */

/*
 * Walk a shadow PT levels up to the all present levels in the paging hierarchy.
 */
static int walk_shadow_pts(struct kvm_vcpu *vcpu, gva_t addr,
				kvm_shadow_trans_t *st, hpa_t spt_root)
{
	kvm_shadow_walk_iterator_t it;
	int top_level;
	top_level = vcpu->arch.mmu.root_level;

	E2K_KVM_BUG_ON(!VALID_PAGE(kvm_get_space_addr_spt_root(vcpu, addr)));

	DebugWSPT("started for guest addr 0x%lx\n", addr);

	st->last_level = E2K_PT_LEVELS_NUM + 1;
	st->addr = addr;

	for ((!IS_E2K_INVALID_PAGE(spt_root)) ?
			shadow_pt_walk_init(&it, vcpu, spt_root, addr)
			:
			shadow_walk_init(&it, vcpu, addr);
		shadow_walk_okay(&it);
			shadow_walk_next(&it)) {
		st->pt_entries[it.level].sptep = it.sptep;
		st->pt_entries[it.level].spte = *it.sptep;
		DebugWSPT("shadow PT level #%d addr 0x%llx index 0x%x "
			"sptep %px\n",
			it.level, it.shadow_addr, it.index, it.sptep);
		if (likely(is_shadow_present_pte(vcpu->kvm, *it.sptep))) {
			st->last_level = it.level;
			trace_kvm_sync_spt_level(it.sptep, *it.sptep, it.level);
			continue;
		} else if (is_shadow_valid_pte(vcpu->kvm, *it.sptep)) {
			st->last_level = it.level;
			trace_kvm_sync_only_valid(it.sptep, it.level);
			break;
		}
		if (unlikely(trace_kvm_sync_shadow_gva_enabled())) {
			trace_kvm_sync_spt_level(it.sptep, *it.sptep, it.level);
		}
		break;
	}
	return it.level;
}

/*
 * Fetch a shadow PT levels up to the specified level in the paging hierarchy.
 */
static gpte_state_t fetch_shadow_pts(struct kvm_vcpu *vcpu, gva_t addr,
			kvm_shadow_walk_iterator_t *it,
			gmm_struct_t *gmm, hpa_t spt_root, int down_to_level,
			guest_walker_t *gw, gpt_walker_t *gpt_walker)
{
	struct kvm_mmu_page *sp = NULL;
	int top_level;
	gpte_state_t r;

	top_level = vcpu->arch.mmu.root_level;
	/*
	 * Verify that the top-level gpte is still there.  Since the page
	 * is a root page, it is either write protected (and cannot be
	 * changed from now on) or it is invalid (in which case, we don't
	 * really care if it changes underneath us after this point).
	 */
	if (unlikely(!VALID_PAGE(kvm_get_space_addr_spt_root(vcpu, addr)))) {
		r = other_gpa_gpte_state;
		goto out_gpte_changed;
	}

	DebugSPF("started for guest addr 0x%lx gfn 0x%llx down to level %d\n",
		addr, gw->gfn, down_to_level);

	for ((!IS_E2K_INVALID_PAGE(spt_root)) ?
			shadow_pt_walk_init(it, vcpu, spt_root, addr)
			:
			shadow_walk_init(it, vcpu, addr);
		shadow_walk_okay(it) && it->level > down_to_level;
			shadow_walk_next(it)) {
		gpt_entry_t *gpt_entry;
		pgprot_t old_spte;
		gfn_t table_gfn;
		gpa_t table_gpa;

		DebugSPF("shadow PT level #%d addr 0x%llx index 0x%x "
			"sptep %px\n",
			it->level, it->shadow_addr, it->index, it->sptep);
		clear_sp_write_flooding_count(it->sptep);
		drop_large_spte(vcpu, it->sptep);

		sp = NULL;
		gpt_entry = get_walk_addr_gpte_level(gpt_walker, it->level - 1);
		if (!is_shadow_present_pte(vcpu->kvm, *it->sptep)) {
			table_gfn = gpa_to_gfn(gpt_entry->gpt_base);
			table_gpa = gpt_entry->gpa;
			trace_kvm_sync_spt_level(it->sptep, *it->sptep, it->level);
			sp = kvm_mmu_get_page(vcpu, table_gfn, addr,
				it->level - 1, false, table_gpa, gw->pt_access,
				is_shadow_valid_pte(vcpu->kvm, *it->sptep));
			DebugSPF("allocated shadow page at %px, "
				"guest table gfn 0x%llx\n",
				sp, table_gfn);
		} else {
			trace_kvm_sync_spt_level(it->sptep, *it->sptep, it->level);
		}

		/*
		 * Verify that the gpte in the page we've just write
		 * protected is still there.
		 */
		r = gpte_changed(vcpu, gpt_walker, addr, it->level - 1);
		if (unlikely(r != same_gpte_state))
			goto out_gpte_changed;

		if (sp) {
			old_spte = *it->sptep;
			link_shadow_page(vcpu, gmm, it->sptep, sp);
			DebugSPF("level #%d: linked shadow pte %px == 0x%lx\n",
				it->level, it->sptep, pgprot_val(*it->sptep));
			trace_kvm_sync_spt_level(it->sptep, old_spte, it->level);
		}
	}
	return same_gpte_state;

out_gpte_changed:
	return r;
}

/*
 * Fetch a shadow pte for a specific level in the paging hierarchy.
 * If the guest tries to write a write-protected page, we need to
 * emulate this operation, return 1 to indicate this case.
 */
static pf_res_t fetch(struct kvm_vcpu *vcpu, gva_t addr,
			guest_walker_t *gw, gpt_walker_t *gpt_walker,
			hpa_t spt_root, int error_code, int hlevel,
			kvm_pfn_t pfn, bool map_writable, bool prefault,
			bool only_validate, bool not_prefetch)
{
	struct kvm_mmu_page *sp = NULL;
	pgprot_t old_spte;
	struct kvm_shadow_walk_iterator it;
	gpt_entry_t *gpt_entry;
	unsigned direct_access;
	bool write_fault = !!(error_code & PFERR_WRITE_MASK);
	gmm_struct_t *gmm;
	pf_res_t emulate;
	gpte_state_t r;

	DebugTOVM("started for guest addr 0x%lx pfn 0x%llx level %d\n",
		addr, pfn, hlevel);

	gmm = kvm_get_page_fault_gmm(vcpu, error_code);

	r = fetch_shadow_pts(vcpu, addr, &it, gmm, spt_root,
				gw->level, gw, gpt_walker);
	if (unlikely(r != same_gpte_state))
		goto out_gpte_changed;

	direct_access = gw->pte_access;

	for (;
		shadow_walk_okay(&it) && it.level > hlevel;
			shadow_walk_next(&it)) {
		gfn_t direct_gfn;

		DebugTOVM("shadow PT level #%d addr 0x%llx index 0x%x "
			"sptep %px\n",
			it.level, it.shadow_addr, it.index, it.sptep);
		clear_sp_write_flooding_count(it.sptep);
		old_spte = *it.sptep;
		validate_direct_spte(vcpu, it.sptep, direct_access);

		trace_kvm_sync_spt_level(it.sptep, old_spte, it.level);
		old_spte = *it.sptep;
		if (drop_large_spte(vcpu, it.sptep)) {
			trace_kvm_sync_spt_level(it.sptep, old_spte, it.level);
		}

		DebugTOVM("shadow spte %px == 0x%lx\n",
			it.sptep, pgprot_val(*it.sptep));
		if (is_shadow_present_pte(vcpu->kvm, *it.sptep))
			continue;

		direct_gfn = gw->gfn &
			~(KVM_PT_LEVEL_PAGES_PER_HPAGE(it.pt_level) - 1);

		old_spte = *it.sptep;
		gpt_entry = get_walk_addr_gpte_level(gpt_walker, it.level);
		sp = kvm_mmu_get_page(vcpu, direct_gfn, addr, it.level - 1,
				true, gpt_entry->gpa,
				direct_access,
				is_shadow_valid_pte(vcpu->kvm, *it.sptep));
		link_shadow_page(vcpu, gmm, it.sptep, sp);
		DebugTOVM("allocated shadow page at %px for direct "
			"gfn 0x%llx, direct access %s\n",
			sp, direct_gfn, (direct_access) ? "true" : "false");
		DebugTOVM("level #%d: linked shadow pte %px == 0x%lx\n",
			it.level, it.sptep, pgprot_val(*it.sptep));
		trace_kvm_sync_spt_level(it.sptep, old_spte, it.level);
	}

	clear_sp_write_flooding_count(it.sptep);
	old_spte = *it.sptep;
	emulate = mmu_set_spte(vcpu, it.sptep, gw->pte_access, write_fault,
			       it.level, gw->gfn, pfn, prefault, map_writable,
			       only_validate, gw->pte_cui);
	trace_kvm_sync_spte(it.sptep, old_spte, it.level);
	if (!not_prefetch)
		pte_prefetch(vcpu, gpt_walker, it.sptep);
	DebugTOVM("set shadow spte %px == 0x%lx, emulate %d\n",
		it.sptep, pgprot_val(*it.sptep), emulate);

	return emulate;

out_gpte_changed:
	if (!is_mmio_space_pfn(pfn))
		kvm_release_pfn_clean(pfn);
	return PFRES_RETRY;
}

 /*
 * To see whether the mapped gfn can write its page table in the current
 * mapping.
 *
 * It is the helper function of FNAME(page_fault). When guest uses large page
 * size to map the writable gfn which is used as current page table, we should
 * force kvm to use small page size to map it because new shadow page will be
 * created when kvm establishes shadow page table that stop kvm using large
 * page size. Do it early can avoid unnecessary #PF and emulation.
 *
 * @write_fault_to_shadow_pgtable will return true if the fault gfn is
 * currently used as its page table.
 *
 * Note: the PDPT page table is not checked for PAE-32 bit guest. It is ok
 * since the PDPT is always shadowed, that means, we can not use large page
 * size to map the gfn which is used as PDPT.
 */
#ifndef	CONFIG_KVM_PARAVIRT_TLB_FLUSH
static bool
is_self_change_mapping(struct kvm_vcpu *vcpu, int curr_level,
			gpt_walker_t *gpt_walker, unsigned gpte_access,
			gfn_t gfn, int user_fault,
			bool *write_fault_to_shadow_pgtable)
{
	gfn_t mask = kvm_mmu_hpage_mask(vcpu->kvm, curr_level);
	bool self_changed = false;
	gpt_entry_t *gpt_entry;
	gfn_t pt_gfn;
	int level;

	if (!(gpte_access & ACC_WRITE_MASK ||
			(!is_write_protection(vcpu) && !user_fault)))
		return false;

	for (level = gpt_walker->min_level; level <= gpt_walker->max_level; level++) {
		gpt_entry = get_walk_addr_gpte_level(gpt_walker, level);
		pt_gfn = gfn ^ gpa_to_gfn(gpt_entry->gpt_base);

		self_changed |= !(pt_gfn & mask);
		*write_fault_to_shadow_pgtable |= !pt_gfn;
	}

	return self_changed;
}
#else	/* CONFIG_KVM_PARAVIRT_TLB_FLUSH */
static bool
is_self_change_mapping(struct kvm_vcpu *vcpu, int curr_level,
			gpt_walker_t *gpt_walker, unsigned gpte_access,
			gfn_t gfn, int user_fault,
			bool *write_fault_to_shadow_pgtable)
{
	return false;
}
#endif	/* !CONFIG_KVM_PARAVIRT_TLB_FLUSH */

/*
 * Page fault handler.  There are several causes for a page fault:
 *   - there is no shadow pte for the guest pte
 *   - write access through a shadow pte marked read only so that we can set
 *     the dirty bit
 *   - write access to a shadow pte marked read only so we can update the page
 *     dirty bitmap, when userspace requests it
 *   - mmio access; in this case we will never install a present shadow pte
 *   - normal guest page fault due to the guest pte marked not present, not
 *     writable, or not executable
 *
 *  Returns: 1 if we need to emulate the instruction, 0 otherwise, or
 *           a negative value on error.
 */
static pf_res_t page_fault(struct kvm_vcpu *vcpu, gva_t addr,
				u32 error_code, bool prefault,
				gfn_t *gfnp, kvm_pfn_t *pfnp)
{
	int write_fault = error_code & PFERR_WRITE_MASK;
	int user_fault = error_code & PFERR_USER_MASK;
	bool dont_inject = !!(error_code & PFERR_DONT_INJECT_MASK);
	guest_walker_t walker;
	gpt_walker_t gpt_walker;
	gpa_t gpt_root;
	gmm_struct_t *gmm = NULL;
	pf_res_t r;
	int ret, retry_no;
	kvm_pfn_t pfn;
	int level = PT_PAGE_TABLE_LEVEL;
	bool force_pt_level = false;
	bool map_writable, is_self_change_map;
#ifdef	KVM_ARCH_WANT_MMU_NOTIFIER
	intc_mu_state_t *mu_state = get_intc_mu_state(vcpu);
#endif	/* KVM_ARCH_WANT_MMU_NOTIFIER */

	pgprintk("%s: addr %lx err %x\n", __func__, addr, error_code);

	ret = mmu_topup_memory_caches(vcpu);
	if (ret) {
		r = PFRES_ERR;
		goto out_pf_error;
	}

	gmm = kvm_get_page_fault_gmm(vcpu, error_code);

	trace_kvm_spt_page_fault(vcpu, gmm, addr, error_code);

	gpt_root = kvm_get_space_addr_guest_root(vcpu, addr);
	init_addr_gpt_walker(vcpu, gpt_root, &gpt_walker, false);

	retry_no = 0;

retry_pf_handle:

	retry_no++;
	if (unlikely(retry_no > MAX_GPT_WALK_RETRY_NUM)) {
		pr_err("%s(): too many attempts to get guest ptes in synced state "
			"for guest faulted addr 0x%lx\n",
			__func__, addr);
		r = PFRES_ERR;
		goto out_pf_error;
	}
	if (retry_no > 1) {
		init_addr_gpt_walker(vcpu, gpt_root, &gpt_walker, true);
	}

	/*
	 * If PFEC.RSVD is set, this is a shadow page fault.
	 * The bit needs to be cleared before walking guest page tables.
	 */
	error_code &= ~PFERR_RSVD_MASK;

	/*
	 * Look up the guest pte for the faulting address.
	 */
	ret = walk_addr(&walker, &gpt_walker, vcpu, addr, error_code);

	/*
	 * The page is not mapped by the guest. Let the guest handle it.
	 */
	if (!ret) {
		pgprintk("%s: guest page fault\n", __func__);
		if (likely(!dont_inject)) {
			if (!prefault)
				mmu_pt_inject_page_fault(vcpu, &walker.fault);
			r = PFRES_INJECTED;
		} else {
			r = PFRES_DONT_INJECT;
		}
		if (unlikely(walker.fault.error_code & PFERR_IS_UNMAPPED_MASK)) {
			/*
			 * Faulted gva has been already unmapped
			 * In some case valid bit of pte can be cleared
			 * without TLB flush after gva unmapping.
			 * In such case it need sync shadow PT to clear
			 * valid bit of shadow pte
			 */
			ret = sync_shadow_pt_gva(vcpu, gmm, &gpt_walker, addr);
			if (unlikely(ret != 0)) {
				if (likely(ret == PFRES_RETRY)) {
					goto retry_pf_handle;
				} else if (ret < 0) {
					;
				} else {
					E2K_KVM_BUG_ON(true);
				}
				r = PFRES_ERR;
			}
		}
		goto out_pf_error;
	} else if (unlikely(ret < 0)) {
		r = PFRES_ERR;
		goto out_pf_error;
	}

	if (page_fault_handle_page_track(vcpu, error_code, walker.gfn)) {
		DebugSPF("page fault can not be fixed by handler: guest is "
			"writing the page which is write tracked\n");
		if (pfnp == NULL) {
			r = PFRES_WRITE_TRACK;
			goto out_pf_error;
		}
		is_self_change_map = true;
	} else {
		is_self_change_map = false;
	}

	vcpu->arch.write_fault_to_shadow_pgtable = is_self_change_map;

	is_self_change_map |= is_self_change_mapping(vcpu, walker.level,
					&gpt_walker, walker.pte_access,
					walker.gfn, user_fault,
					&vcpu->arch.write_fault_to_shadow_pgtable);
	DebugSPF("is_self_change_mapping %s\n",
		(is_self_change_map) ? "true" : "false");

	if (walker.level >= PT_DIRECTORY_LEVEL && !is_self_change_map) {
		level = mapping_level(vcpu, walker.gfn, &force_pt_level);
		DebugSPF("mapping level %d force level %d\n",
			level, force_pt_level);
		if (likely(!force_pt_level)) {
			const pt_level_t *pt_level;

			level = min(walker.level, level);
			pt_level = &walker.pt_struct->levels[level];
			walker.gfn = walker.gfn &
				~(KVM_PT_LEVEL_PAGES_PER_HPAGE(pt_level) - 1);
			DebugSPF("level is now %d gfn 0x%llx\n",
				level, walker.gfn);
		}
	} else {
		force_pt_level = true;
	}

#ifdef	KVM_ARCH_WANT_MMU_NOTIFIER
	mu_state->notifier_seq = vcpu->kvm->mmu_notifier_seq;
	smp_rmb();
#endif	/* KVM_ARCH_WANT_MMU_NOTIFIER */

	if (try_async_pf(vcpu, prefault, walker.gfn, addr, &pfn, write_fault,
			 &map_writable)) {
		r = PFRES_NO_ERR;
		goto out_pf_error;
	}
	DebugSPF("try_async_pf returned pfn 0x%llx, writable %d\n",
		pfn, map_writable);

	if (handle_abnormal_pfn(vcpu, addr, walker.gfn, pfn,
					walker.pte_access, &r)) {
		if (pfnp != NULL)
			*pfnp = pfn;
		DebugSPF("returns %d and abnormal pfn 0x%llx\n",
			r, pfn);
		goto out_pf_error;
	}

#ifdef	KVM_ARCH_WANT_MMU_NOTIFIER
	if (r == PFRES_TRY_MMIO) {
		mu_state->may_be_retried = false;
	}
#endif	/* KVM_ARCH_WANT_MMU_NOTIFIER */

	/*
	 * Do not change pte_access if the pfn is a mmio page, otherwise
	 * we will cache the incorrect access into mmio spte.
	 */
	if (write_fault && !(walker.pte_access & ACC_WRITE_MASK) &&
	     !is_write_protection(vcpu) && !user_fault &&
	      !is_noslot_pfn(pfn)) {
		walker.pte_access |= ACC_WRITE_MASK;
		walker.pte_access &= ~ACC_USER_MASK;

		/*
		 * If we converted a user page to a kernel page,
		 * so that the kernel can write to it when cr0.wp=0,
		 * then we should prevent the kernel from executing it
		 * if SMEP is enabled.
		 */
		if (is_smep(vcpu))
			walker.pte_access &= ~ACC_EXEC_MASK;
		DebugSPF("updated pte_access 0x%x\n", walker.pte_access);
	}

	spin_lock(&vcpu->kvm->mmu_lock);
#ifdef	KVM_ARCH_WANT_MMU_NOTIFIER
	if (unlikely(!mmu_notifier_no_retry(vcpu->kvm, mu_state->notifier_seq) &&
			!mu_state->ignore_notifier && r != PFRES_TRY_MMIO)) {
		r = PFRES_RETRY;
		goto out_unlock;
	}
#endif	/* KVM_ARCH_WANT_MMU_NOTIFIER */

	kvm_mmu_audit(vcpu, AUDIT_PRE_PAGE_FAULT);

#ifdef	CHECK_MMU_PAGES_AVAILABLE
	if (unlikely(make_mmu_pages_available(vcpu))) {
		pr_err("%s(): mmu pages limit exceeded to allocate new shadow PTs\n",
			__func__);
		r = PFRES_ENOSPC;
		goto out_unlock;
	}
#endif	/* CHECK_MMU_PAGES_AVAILABLE */

	if (!force_pt_level)
		transparent_hugepage_adjust(vcpu, &walker.gfn, &pfn, &level);

	r = fetch(vcpu, addr, &walker, &gpt_walker,
		  E2K_INVALID_PAGE, error_code,
		  level, pfn, map_writable, prefault, false, false);
	if (unlikely(r == PFRES_RETRY)) {
		spin_unlock(&vcpu->kvm->mmu_lock);
		goto retry_pf_handle;
	}

	++vcpu->stat.pf_fixed;

	check_and_sync_guest_roots(vcpu, gmm);

	kvm_mmu_audit(vcpu, AUDIT_POST_PAGE_FAULT);
	spin_unlock(&vcpu->kvm->mmu_lock);

	if (gfnp != NULL)
		*gfnp = walker.gfn;
	if (pfnp != NULL)
		*pfnp = pfn;
	if (r == PFRES_NO_ERR) {
		/* page fault successfully handled and host shadow PT */
		/* synced with guest PTs */
		if ((error_code & PFERR_USER_MASK) &&
				!(error_code & PFERR_DONT_RECOVER_MASK)) {
			/*
			 * guest user page fault, so the guest kernel should
			 * handle this page fault to reexecute mmu operation
			 * in itself context
			 */
			r = PFRES_INJECTED;
		}
		if (unlikely(walker.pte_access & ACC_PRIV_MASK &&
				!(error_code & PFERR_HW_ACCESS_MASK))) {
			/* guest access to privileged guest user area, */
			/* inject page fault to guest */
			E2K_KVM_BUG_ON(dont_inject);
			r = PFRES_INJECTED;
		}
	}
	DebugSPF("returns %d, pfn 0x%llx\n", r, pfn);
	goto out_pf_error;

#ifdef	KVM_ARCH_WANT_MMU_NOTIFIER
out_unlock:
	spin_unlock(&vcpu->kvm->mmu_lock);
	kvm_release_pfn_clean(pfn);
	E2K_KVM_BUG_ON(!mu_state->may_be_retried);
#endif	/* KVM_ARCH_WANT_MMU_NOTIFIER */

out_pf_error:
	free_addr_gpt_walker(&gpt_walker);

	if (gmm)
		trace_kvm_spt_page_fault_res(vcpu, gmm, addr, r);

	return r;
}

/*
 * Return next gva pointing to next pte on pt_level
 */
static gva_t pt_level_next_gva(gva_t gva, gva_t end_gva,
					const pt_level_t *pt_level)
{
	gva_t boundary = (gva + pt_level->page_size) & pt_level->page_mask;

	return (boundary - 1 < end_gva - 1) ? boundary : end_gva;
}

static gpa_t get_level1_sp_gpa(struct kvm_mmu_page *sp, pgprot_t *sptep)
{
	WARN_ON(sp->role.level != PT_PAGE_TABLE_LEVEL &&
			!sp->role.direct && !is_shadow_huge_pte(*sptep));

	if (likely(!sp->role.direct)) {
		unsigned offset = (sptep - sp->spt) * sizeof(pgprotval_t);
		return gfn_to_gpa(sp->gfn) + offset;
	} else {
		return sp->huge_gpt_gpa;
	}
}

static gpa_t get_ptd_level_sp_gpa(struct kvm_mmu_page *sp, pgprot_t *sptep)
{
	WARN_ON(sp->role.level == PT_PAGE_TABLE_LEVEL);

	if (likely(!sp->role.direct)) {
		unsigned offset = (sptep - sp->spt) * sizeof(pgprotval_t);
		return gfn_to_gpa(sp->gfn) + offset;
	} else {
		return sp->huge_gpt_gpa;
	}
}

static bool is_guest_ptd_updated(struct kvm_vcpu *vcpu, pgprot_t spte,
				pgprotval_t gpte, gva_t gva, int level)
{
	const pt_struct_t *spt_struct;
	const pt_level_t *spt_level;
	pgprot_t *spt_table_hva;
	struct kvm_mmu_page *sp;
	pgprot_t *next_sptep;
	unsigned long next_addr;
	unsigned int pte_index;
	gfn_t gfn;

	spt_struct = GET_HOST_PT_STRUCT(vcpu->kvm);
	spt_level = get_pt_struct_level_on_id(spt_struct, level - 1);
	next_addr = kvm_pte_pfn_to_phys_addr(spte, spt_struct);
	pte_index = get_pt_level_addr_index(gva, spt_level);
	spt_table_hva = (pgprot_t *) __va(next_addr);
	next_sptep = spt_table_hva + pte_index;
	sp = page_header(__pa(next_sptep));
	gfn = gpte_to_gfn_level_sp(vcpu, sp, next_sptep, gpte);
	return gfn != kvm_mmu_sp_get_gfn(sp, pte_index);
}

static pf_res_t sync_shadow_ptd_level_gva(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
				gpt_walker_t *gpt_walker, pgprot_t *sptep,
				gva_t gva, int level)
{
	const pt_struct_t *gpt_struct = GET_VCPU_PT_STRUCT(vcpu);
	const pt_level_t *gpt_level;
	gpt_entry_t *gpt_entry;
	pgprotval_t gpte;
	gfn_t gfn;
	unsigned gpt_access;
	gpte_state_t state;
	pf_res_t res;

	gpt_entry = get_walk_addr_gpte_level(gpt_walker, level);
	state = get_addr_gpte_atomic(vcpu, gva, &gpte, gpt_entry->gpa,
				     gpt_walker, level);
	if (unlikely(state != same_gpte_state)) {
		res = PFRES_RETRY;
		goto out;
	}

	gpt_level = get_pt_struct_level_on_id(gpt_struct, level);
	gfn = gpte_to_gfn_level(vcpu, gpte, gpt_level);
	gpt_access = FNAME(gpte_access)(vcpu, gpte, INVALID_GVA);
	res = allocate_shadow_level(vcpu, gmm, gfn, gva, level - 1,
				    gpt_access, sptep, false, gpt_entry->gpa);

out:
	return res;
}

static pf_res_t sync_shadow_huge_gva(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
				gpt_walker_t *gpt_walker,
				pgprotval_t gpte, pgprot_t *sptep,
				gva_t gva, int level)
{
	const pt_struct_t *gpt_struct = GET_VCPU_PT_STRUCT(vcpu);
	const pt_level_t *gpt_level;
	gfn_t gfn;
	pf_res_t res;

	gpt_level = get_pt_struct_level_on_id(gpt_struct, level);
	gfn = gpte_to_gfn_level(vcpu, gpte, gpt_level);
	res = map_huge_page_to_spte(vcpu, gmm, gpt_walker, gpte,
				    gva, gfn, level, level, sptep);
	return res;
}

static int sync_shadow_ptd(struct kvm_vcpu *vcpu, gmm_struct_t *gmm, gva_t gva,
			pgprot_t *sptep, int level, gpt_entry_t *gpt_entry,
			gpt_walker_t *gpt_walker, struct list_head *invalid_list)
{
	struct kvm *kvm = vcpu->kvm;
	gpa_t gpte_gpa;
	pgprotval_t gpte;
	struct kvm_mmu_page *sp, *child;
	pgprot_t old_spte;
	gpte_state_t state;
	int ret;

	do {
		old_spte = *sptep;
		if (unlikely(!is_shadow_present_pte(kvm, *sptep))) {
			ret = sync_shadow_ptd_level_gva(vcpu, gmm,
					gpt_walker, sptep, gva, level);
			if (unlikely(ret != 0)) {
				spin_unlock(&kvm->mmu_lock);
				return ret;
			}
			trace_kvm_sync_spt_level(sptep, old_spte, level);
		} else {
			gpte_gpa = gpt_entry->gpa;
			state = get_addr_gpte_atomic(vcpu, gva, &gpte,
				 gpte_gpa, gpt_walker, level);
			if (unlikely(state != same_gpte_state)) {
				spin_unlock(&kvm->mmu_lock);
				return PFRES_RETRY;
			}
			trace_kvm_sync_gpte(gva, sptep, gpte_gpa, gpte,
					    level);
			if (is_guest_ptd_updated(vcpu, *sptep, gpte, gva, level)) {
				/* guest changed own pt directory entry */
				sp = page_header(__pa(sptep));
				child = mmu_page_zap_pte(kvm, sp, sptep);
				if (likely(child && child->released)) {
					kvm_mmu_prepare_zap_page(kvm,
						child, invalid_list);
					trace_kvm_sync_spte(sptep, old_spte,
						level);
				}
				continue;
			}
			trace_kvm_sync_spt_level(sptep, old_spte, level);
		}
		break;
	} while (true);

	return 0;
}

static int sync_shadow_pt_gva(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
				gpt_walker_t *gpt_walker, gva_t gva)
{
	struct kvm *kvm = vcpu->kvm;
	kvm_shadow_walk_iterator_t iterator;
	struct kvm_mmu_page *sp, *child;
	gpt_entry_t *gpt_entry;
	hpa_t spt_root;
	pgprot_t *sptep;
	pgprot_t old_spte;
	gpa_t gpte_gpa;
	pgprotval_t gpte;
	LIST_HEAD(invalid_list);
	gpte_state_t state;
	int level, to_level, ret;
	bool is_huge_page;

	to_level = gpt_walker->min_level;

	spin_lock(&kvm->mmu_lock);

	spt_root = gmm->root_hpa;
	if (!VALID_PAGE(spt_root)) {
		/* shadow PT of the gmm has been already released */
		ret = -EFAULT;
		goto out_unlock;
	}

	for_each_shadow_pt_entry(vcpu, spt_root, gva, iterator) {
		level = iterator.level;
		sptep = iterator.sptep;

		if (likely(level > to_level)) {
			gpt_entry = get_walk_addr_gpte_level(gpt_walker, level);
			ret = sync_shadow_ptd(vcpu, gmm, gva, sptep, level,
					gpt_entry, gpt_walker, &invalid_list);
			if (unlikely(ret != 0)) {
				goto out_check_unlock;
			}
			continue;
		}

		/* last gpte level */
		gpt_entry = get_walk_addr_gpte_level(gpt_walker, level);
		gpte = gpt_entry->gpte;
		gpte_gpa = gpt_entry->gpa;

		old_spte = *sptep;
		sp = page_header(__pa(sptep));
		child = mmu_page_zap_pte(kvm, sp, sptep);
		if (unlikely(child && child->released)) {
			kvm_mmu_prepare_zap_page(kvm, child, &invalid_list);
		}
		trace_kvm_sync_spte(sptep, old_spte, level);

		E2K_KVM_BUG_ON(!rmap_can_add(vcpu));

		state = get_addr_gpte_atomic(vcpu, gva, &gpte, gpte_gpa,
					     gpt_walker, level);
		if (unlikely(state != same_gpte_state)) {
			ret = PFRES_RETRY;
			goto out_check_unlock;
		}
		trace_kvm_sync_gpte(gva, sptep, gpte_gpa, gpte, level);

		if (!is_present_gpte(gpte)) {
			if (is_valid_gpte(vcpu, gpte)) {
				/* only validate host pte too */
				validate_spte(kvm, sptep);
			} else {
				/* only clear host pte too */
				clear_spte(kvm, sptep);
			}
			trace_kvm_sync_spte(sptep, old_spte, level);
			ret = 0;
			goto out_check_unlock;
		}

		/* Check if guest pt entry is huge page */
		is_huge_page = is_huge_gpte(vcpu, gpte);
		if (is_huge_page || level != PT_PAGE_TABLE_LEVEL) {
			const pt_struct_t *gpt_struct = GET_VCPU_PT_STRUCT(vcpu);
			const pt_level_t *gpt_level;
			gfn_t gfn;

			gpt_level = get_pt_struct_level_on_id(gpt_struct, level);
			gfn = gpte_to_gfn_level(vcpu, gpte, gpt_level);
			ret = sync_shadow_huge_gva(vcpu, gmm, gpt_walker,
						   gpte, sptep, gva, level);
			goto out_check_unlock;
		}

		update_spte(vcpu, sp, sptep, gpte);
		trace_kvm_sync_spte(sptep, old_spte, level);
	}

	ret = 0;

out_check_unlock:
	check_and_sync_guest_roots(vcpu, gmm);
	kvm_mmu_flush_or_zap(vcpu, &invalid_list, false, false);
out_unlock:
	spin_unlock(&kvm->mmu_lock);

	return ret;
}

static int sync_gva_slow(struct kvm_vcpu *vcpu, gmm_struct_t *gmm, gva_t gva)
{
	gpt_walker_t gpt_walker;
	gpa_t gpt_root;
	int retry_no;
	int ret;

	/*
	 * No need to check return value here, rmap_can_add() can
	 * help us to skip pte prefetch later.
	 */
	mmu_topup_memory_caches(vcpu);

	gpt_root = gmm->u_pptb;
	init_addr_gpt_walker(vcpu, gpt_root, &gpt_walker, false);

	retry_no = 0;

retry_sync_gva:

	retry_no++;
	if (unlikely(retry_no > MAX_GPT_WALK_RETRY_NUM)) {
		pr_err("%s(): too many attempts to get guest ptes in synced state "
			"for guest addr 0x%lx\n",
			__func__, gva);
		ret = -EFAULT;
		goto out_error;
	}
	if (retry_no > 1) {
		init_addr_gpt_walker(vcpu, gpt_root, &gpt_walker, true);
	}

	ret = walk_addr_gptes(vcpu, gva, &gpt_walker);
	if (unlikely(ret != 0)) {
		pr_err("%s(): walk through the guest PTs failed for guest "
			"addr 0x%lx, error %d\n",
			__func__, gva, ret);
		goto out_error;
	}

	ret = sync_shadow_pt_gva(vcpu, gmm, &gpt_walker, gva);
	if (unlikely(ret != 0)) {
		if (likely(ret == PFRES_RETRY)) {
			goto retry_sync_gva;
		} else if (ret < 0) {
			pr_err("%s(): walk through the shadow PTs failed for "
				"guest addr 0x%lx, error %d\n",
				__func__, gva, ret);
		} else {
			E2K_KVM_BUG_ON(true);
		}
		goto out_error;
	}

out_error:
	free_addr_gpt_walker(&gpt_walker);
	return ret;
}

static int sync_gva(struct kvm_vcpu *vcpu, gmm_struct_t *gmm, gva_t gva)
{
	struct kvm *kvm = vcpu->kvm;
	struct kvm_shadow_walk_iterator iterator;
	struct kvm_mmu_page *sp;
	hpa_t spt_root;
	pgprot_t old_spte;
	int level;
	pgprot_t *sptep;
	pgprotval_t gpte;
	gpa_t gpte_gpa;
	pgprotval_t __user *ptep_user;
	bool slow_path = false;
	int ret;

	vcpu_clear_mmio_info(vcpu, gva);

	/*
	 * No need to check return value here, rmap_can_add() can
	 * help us to skip pte prefetch later.
	 */
	mmu_topup_memory_caches(vcpu);

#ifdef CONFIG_KVM_GVA_CACHE
	/* Flush translation in gva->gpa cache */
	gva_cache_flush_addr(gmm->gva_cache, gva);
#endif /* CONFIG_KVM_GVA_CACHE */

retry_sync_gva:

	spin_lock(&kvm->mmu_lock);

	spt_root = gmm->root_hpa;
	if (!VALID_PAGE(spt_root)) {
		/* shadow PT of the gmm has been already released */
		ret = -EFAULT;
		goto out_unlock;
	}

	for_each_shadow_pt_entry(vcpu, spt_root, gva, iterator) {
		level = iterator.level;
		sptep = iterator.sptep;

		sp = page_header(__pa(sptep));
		if (is_last_spte(*sptep, level)) {

#ifndef	CONFIG_KVM_PARAVIRT_TLB_FLUSH
			if (!sp->unsync)
				break;
#endif	/* !CONFIG_KVM_PARAVIRT_TLB_FLUSH */

			gpte_gpa = get_level1_sp_gpa(sp, sptep);

			if (mmu_page_zap_pte(kvm, sp, sptep))
				kvm_flush_remote_tlbs(kvm);

			E2K_KVM_BUG_ON(!rmap_can_add(vcpu));

			if (kvm_vcpu_get_guest_pte_atomic(vcpu, gpte_gpa, gpte)) {

				spin_unlock(&kvm->mmu_lock);

				ret = kvm_vcpu_get_guest_pte(vcpu, gpte_gpa, gpte,
							     ptep_user, NULL);

				if (unlikely(ret != 0)) {
					goto out;
				} else {
					goto retry_sync_gva;
				}
			}
			trace_kvm_sync_gpte(gva, sptep, gpte_gpa, gpte, level);

			old_spte = *sptep;
			if (!is_present_gpte(gpte)) {
				if (is_valid_gpte(vcpu, gpte)) {
					/* only validate host pte too */
					validate_spte(kvm, sptep);
				} else {
					/* only clear host pte too */
					clear_spte(kvm, sptep);
				}
			} else {
				update_spte(vcpu, sp, sptep, gpte);
			}
			trace_kvm_sync_spte(sptep, old_spte, level);
		} else {

			old_spte = *sptep;
			if (!is_shadow_present_pte(kvm, *sptep) ||
						!sp->unsync_children) {
				if (unlikely(trace_kvm_sync_shadow_gva_enabled())) {
					trace_kvm_sync_spt_level(sptep, old_spte,
								 level);
				}
				slow_path = true;
				break;
			}

			gpte_gpa = get_ptd_level_sp_gpa(sp, sptep);
			if (kvm_vcpu_get_guest_pte_atomic(vcpu, gpte_gpa, gpte)) {
				slow_path = true;
				break;
			}

			if (unlikely(!is_present_gpte(gpte))) {
				slow_path = true;
				break;
			}

			if (unlikely(is_guest_ptd_updated(vcpu, *sptep, gpte, gva,
							  level))) {
				/* guest changed own PT directory entry */
				slow_path = true;
				break;
			}
			trace_kvm_sync_spt_level(sptep, old_spte, level);
		}
	}
	ret = 0;

out_unlock:
	spin_unlock(&kvm->mmu_lock);
	if (slow_path) {
		return sync_gva_slow(vcpu, gmm, gva);
	}
out:
	return ret;
}

static int sync_gva_pte_range_slow(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
				   gva_t gva_start, gva_t gva_end,
				   kvm_shadow_walk_iterator_t *spt_walker,
				   gpt_walker_t *gpt_walker, gva_t *retry_gva,
				   struct list_head *invalid_list)
{
	struct kvm *kvm = vcpu->kvm;
	struct kvm_mmu_page *sp, *child;
	int level, to_level;
	const pt_level_t *spt_pt_level;
	unsigned int pte_index;
	gpt_entry_t *gpt_entry;
	pgprot_t *sptep, *spt_table_hva, old_spte;
	gva_t gva, gva_next;
	bool locked_done = false;
	bool gpt_copied = false;
	int ret;

	E2K_KVM_BUG_ON(gva_start > gva_end);

	/* Get descriptors of curr level of shadow page table */
	level = spt_walker->level;
	spt_pt_level = spt_walker->pt_level;
	E2K_KVM_BUG_ON(level < PT_PAGE_TABLE_LEVEL);

	/* Get index in curr level of shadow page table */
	pte_index = get_pt_level_addr_index(gva_start, spt_pt_level);

	/* hva of shadow pt entry in curr level */
	spt_table_hva = (pgprot_t *) __va(spt_walker->shadow_addr);
	sptep = spt_table_hva + pte_index;

	sp = page_header(__pa(sptep));

	gva = gva_start;
	*retry_gva = gva_start;

	if (unlikely(level == gpt_walker->max_level)) {
		E2K_KVM_BUG_ON(level != PT_ROOT_LEVEL);
		ret = walk_addr_range_gptes(vcpu, gva_start, gva_end,
					    gpt_walker->gpt_root, gpt_walker);
		if (unlikely(ret != 0)) {
			pr_err("%s(): walk through the guest PTs failed for guest "
				"range 0x%lx - 0x%lx, error %d\n",
				__func__, gva_start, gva_end, ret);
			return ret;
		}

		/* walk trough shadow PTs should be under lock */
		spin_lock(&kvm->mmu_lock);
		locked_done = true;
	}

	to_level = gpt_walker->min_level;
	gpt_entry = get_walk_addr_gpte_level(gpt_walker, level);

	do {
		const pt_struct_t *pt_struct;
		const pt_level_t *pt_level = NULL;
		pgprotval_t *gpt_page = NULL, *gpt_page_atomic = NULL;
		gpa_t gpte_gpa;
		pgprotval_t gpte;
		gpte_state_t state;
		bool is_huge_page;

		gva_next = pt_level_next_gva(gva, gva_end, spt_pt_level);

		if (likely(level > to_level)) {
			ret = sync_shadow_ptd(vcpu, gmm, gva, sptep, level,
					gpt_entry, gpt_walker, invalid_list);
			if (unlikely(ret != 0)) {
				spin_unlock(&kvm->mmu_lock);
				return ret;
			}

			/* goto next lower level */
			/* hpa of lower level of shadow page table */
			spt_walker->shadow_addr =
				kvm_pte_pfn_to_phys_addr(*sptep,
						spt_walker->pt_struct);

			/* Move iterators to lower level of page tables */
			spt_walker->level--;
			spt_walker->pt_level--;

			ret = sync_gva_pte_range_slow(vcpu, gmm, gva, gva_next,
						      spt_walker, gpt_walker,
						      retry_gva, invalid_list);

			/*
			 * Move iterators back to upper level
			 * of page tables
			 */
			spt_walker->level++;
			spt_walker->pt_level++;

			if (ret != 0) {
				/* unlock should have been made by a function */
				/* that returns error */
				return ret;
			}
			goto next_pte;
		}

		/* last gpte level */
		vcpu_clear_mmio_info(vcpu, gva);

		old_spte = *sptep;
		child = mmu_page_zap_pte(kvm, sp, sptep);
		if (unlikely(child && child->released)) {
			kvm_mmu_prepare_zap_page(kvm, child, invalid_list);
			trace_kvm_sync_spte(sptep, old_spte, level);
			old_spte = *sptep;
		}

		if (unlikely(!rmap_can_add(vcpu))) {
			spin_unlock(&kvm->mmu_lock);
			return PFRES_RETRY_MEM;
		}

			/* Copy gptes atomic from guest table */
		if (unlikely(level == PT_PAGE_TABLE_LEVEL && !gpt_copied)) {
			gpa_t start_gpa;

			pt_struct = GET_VCPU_PT_STRUCT(vcpu);
			pt_level = &pt_struct->levels[level];
			start_gpa = gpt_entry->gpt_base +
					gpt_entry->start_index *
						sizeof(pgprotval_t);
			ret = copy_addr_range_gptes_atomic(vcpu,
					gva_start, gva_end, start_gpa,
					gpt_walker, level);
			if (unlikely(ret != 0)) {
				spin_unlock(&kvm->mmu_lock);
				return ret;
			}
			gpt_copied = true;
			gpt_page = gpt_entry->gpt_page;
			gpt_page_atomic = gpt_entry->gpt_page_atomic;
		}

		gpte_gpa = gpt_entry->gpa;
		state = get_addr_range_gpte_atomic(vcpu, gva, &gpte,
				gpte_gpa, gpt_page, gpt_page_atomic,
				gpt_walker, pt_level, level);
		if (unlikely(state != same_gpte_state)) {
			spin_unlock(&kvm->mmu_lock);
			return PFRES_RETRY;
		}
		trace_kvm_sync_gpte(gva, sptep, gpte_gpa, gpte, level);

		if (!is_present_gpte(gpte)) {
			if (is_valid_gpte(vcpu, gpte)) {
				/* only validate host pte too */
				validate_spte(kvm, sptep);
			} else {
				/* only clear host pte too */
				clear_spte(kvm, sptep);
			}
			trace_kvm_sync_spte(sptep, old_spte, level);
			ret = 0;
			goto next_pte;
		}

		/* Check if guest pt entry is huge page */
		is_huge_page = is_huge_gpte(vcpu, gpte);
		if (is_huge_page || level != PT_PAGE_TABLE_LEVEL) {
			const pt_struct_t *gpt_struct = GET_VCPU_PT_STRUCT(vcpu);
			const pt_level_t *gpt_level;
			gfn_t gfn;

			gpt_level = get_pt_struct_level_on_id(gpt_struct, level);
			gfn = gpte_to_gfn_level(vcpu, gpte, gpt_level);
			ret = sync_shadow_huge_gva(vcpu, gmm, gpt_walker,
						   gpte, sptep, gva, level);
			if (ret != 0) {
				spin_unlock(&kvm->mmu_lock);
				return ret;
			}
			goto next_pte;
		}

		old_spte = *sptep;
		update_spte(vcpu, sp, sptep, gpte);
		trace_kvm_sync_spte(sptep, old_spte, level);

next_pte:
		/* Go to next pt entry on current level */
		sptep++;
		gva = gva_next;
		gpt_entry->gpa += sizeof(pgprotval_t);
		gpt_entry->hva += sizeof(pgprotval_t);
		if (unlikely(gva != gva_end && level > PT_PAGE_TABLE_LEVEL)) {
			/*
			 * Multi-gptes can be only on page tables level #1
			 * For higher levels it need to walk around guest PTs
			 * again for the new incremented guest address
			 * Spin is unlocked to walk through guest PTs in not
			 * atomic mode with enabled page faults, but spin
			 * again locked to continue shadow PTs walk
			 */
			spin_unlock(&kvm->mmu_lock);
			cond_resched();
			if (mmu_need_topup_memory_caches(vcpu)) {
				DebugSYNCV("need fill mmu caches, and run again\n");
				return PFRES_RETRY_MEM;
			}
			ret = walk_next_addr_range_gptes(vcpu, gva, gva_end,
							 gpt_walker, level);
			if (unlikely(ret != 0)) {
				pr_err("%s(): walk through the guest PTs failed "
					"for guest next range 0x%lx - 0x%lx on "
					"level %d, error %d\n",
					__func__, gva, gva_end, level, ret);
				return ret;
			}
			to_level = gpt_walker->min_level;
			/* shadow PTs walk should be continued under lock */
			spin_lock(&kvm->mmu_lock);

		}
	} while (gva != gva_end);

	if (locked_done) {
		check_and_sync_guest_roots(vcpu, gmm);
		/* the lock has been made here, so unlock too here */
		spin_unlock(&kvm->mmu_lock);
	}
	return 0;
}

static long sync_gva_range_slow(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
				gva_t start, gva_t end)
{
	struct kvm *kvm = vcpu->kvm;
	struct kvm_shadow_walk_iterator spt_walker;
	gpt_walker_t gpt_walker;
	hpa_t spt_root;
	gpa_t gpt_root;
	LIST_HEAD(invalid_list);
	long retry_no, retry_max;
	gva_t retry_gva;
	bool gpt_walker_inited = false;
	int ret;

	if (unlikely(mmu_topup_memory_caches(vcpu))) {
		return -ENOMEM;
	}

	/* Get hpa of shadow page table root */
	spt_root = gmm->root_hpa;
	if (!VALID_PAGE(spt_root)) {
		KVM_WARN_ON(true);
		return -EINVAL;
	}
	gpt_root = gmm->u_pptb;

	trace_kvm_sync_shadow_pt_range(vcpu, gmm, spt_root, gpt_root, start, end);

	/*
	 * Use simplified function sync_gva to flush single address
	 * which does not hit into vptb range
	 */
	if (unlikely(start == end)) {
		return sync_gva_slow(vcpu, gmm, start);
	}

	init_addr_range_gpt_walker(vcpu, gpt_root, &gpt_walker, false);
	gpt_walker_inited = true;

	retry_no = 0;
	retry_max = ((end - start) >> PAGE_SHIFT) * MAX_GPT_WALK_RETRY_NUM;

retry_sync_gva_range:

	retry_no++;
	if (unlikely(retry_no > retry_max)) {
		pr_err("%s(): too many attempts %ld to get guest ptes in synced state "
			"for guest range 0x%lx - 0x%lx\n",
			__func__, retry_no, start, end);
		ret = -EFAULT;
		goto out_error;
	} else if (!gpt_walker_inited) {
		init_addr_range_gpt_walker(vcpu, gpt_root, &gpt_walker, true);
		gpt_walker_inited = true;
	}

	shadow_pt_walk_init(&spt_walker, vcpu, spt_root, start);
	ret = sync_gva_pte_range_slow(vcpu, gmm, start, end,
				      &spt_walker, &gpt_walker, &retry_gva,
				      &invalid_list);
	E2K_KVM_BUG_ON(!gpt_walker_inited);
	gpt_walker_inited = false;
	if (likely(ret == 0)) {
		;
	} else if (ret < 0) {
		goto out_error;
	} else  if (ret == PFRES_RETRY) {
		start = retry_gva;
		goto retry_sync_gva_range;
	} else if (ret == PFRES_RETRY_MEM) {
		if (unlikely(mmu_topup_memory_caches(vcpu))) {
			ret = -ENOMEM;
			goto out_error;
		}
		start = retry_gva;
		retry_no--;	/* the attempt not counted */
		goto retry_sync_gva_range;
	} else {
		E2K_KVM_BUG_ON(true);
	}

out_error:
	spin_lock(&kvm->mmu_lock);
	kvm_mmu_flush_or_zap(vcpu, &invalid_list, false, false);
	spin_unlock(&kvm->mmu_lock);
	free_addr_range_gpt_walker(&gpt_walker);
	return ret;
}

static int sync_gva_pte_range(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
				kvm_shadow_walk_iterator_t *spt_walker,
				gva_t gva_start, gva_t gva_end,
				gva_t *retry_gva)
{
	struct kvm *kvm = vcpu->kvm;
	struct kvm_mmu_page *sp;
	int level;
	const pt_level_t *spt_pt_level;
	unsigned int pte_index;
	pgprot_t *sptep, *spt_table_hva, old_spte;
	gva_t gva, gva_next, gva_start_slow, gva_end_slow;
	bool slow_path = false;
	bool slow_path_started = false, slow_path_finished = 0;
	int ret;

	E2K_KVM_BUG_ON(gva_start > gva_end);

	/* Get descriptors of curr level of shadow page table */
	level = spt_walker->level;
	spt_pt_level = spt_walker->pt_level;
	E2K_KVM_BUG_ON(level < PT_PAGE_TABLE_LEVEL);

	/* Get index in curr level of shadow page table */
	pte_index = get_pt_level_addr_index(gva_start, spt_pt_level);

	/* hva of shadow pt entry in curr level */
	spt_table_hva = (pgprot_t *) __va(spt_walker->shadow_addr);
	sptep = spt_table_hva + pte_index;

	sp = page_header(__pa(sptep));

#ifdef CONFIG_KVM_GVA_CACHE
	/* Flush translation in gva->gpa cache */
	gva_cache_flush_addr_range(gmm->gva_cache, gva_start, gva_end);
#endif /* CONFIG_KVM_GVA_CACHE */

	gva = gva_start;
	do {
		pgprotval_t gpte;
		gpa_t gpte_gpa;

		gva_next = pt_level_next_gva(gva, gva_end, spt_pt_level);
		trace_kvm_mmu_spte_element(gmm, sptep, level);

		if (unlikely(is_last_spte(*sptep, level))) {
			/*
			 * This is last level pte (1-st level or large page)
			 */
			pgprotval_t __user *ptep_user;

			if (unlikely(slow_path)) {
				slow_path_finished = true;
				goto sync_slow_path;
			}
			vcpu_clear_mmio_info(vcpu, gva);

#ifndef	CONFIG_KVM_PARAVIRT_TLB_FLUSH
			if (!sp->unsync)
				goto next_pte;
#endif	/* !CONFIG_KVM_PARAVIRT_TLB_FLUSH */

			gpte_gpa = get_level1_sp_gpa(sp, sptep);

			mmu_page_zap_pte(kvm, sp, sptep);

			/* Read pte from guest table */
			if (kvm_vcpu_get_guest_pte_atomic(vcpu, gpte_gpa, gpte)) {
				spin_unlock(&kvm->mmu_lock);
				ret = kvm_vcpu_get_guest_pte(vcpu, gpte_gpa, gpte,
							     ptep_user, NULL);
				if (ret < 0) {
					return ret;
				} else {
					*retry_gva = gva;
					return PFRES_RETRY;
				}
			}
			trace_kvm_sync_gpte(gva, sptep, gpte_gpa, gpte, level);

			if (unlikely(!is_last_gpte(&vcpu->arch.mmu, level, gpte))) {
				/* Guest splitted huge page into smaller ones */
				slow_path = true;
				goto sync_slow_path;
			}

			old_spte = *sptep;
			if (!is_present_gpte(gpte)) {
				if (is_valid_gpte(vcpu, gpte)) {
					/* only validate host pte too */
					validate_spte(kvm, sptep);
				} else {
					/* only clear host pte too */
					clear_spte(kvm, sptep);
				}
			} else {
				update_spte(vcpu, sp, sptep, gpte);
			}
			trace_kvm_sync_spte(sptep, old_spte, level);
		} else {
			old_spte = *sptep;
			if (!is_shadow_present_pte(kvm, *sptep)
#ifndef	CONFIG_KVM_PARAVIRT_TLB_FLUSH
					|| !sp->unsync_children
#endif	/* !CONFIG_KVM_PARAVIRT_TLB_FLUSH */
								) {
				if (unlikely(trace_kvm_sync_shadow_gva_enabled())) {
					trace_kvm_sync_spt_level(sptep, old_spte,
								 level);
				}
				slow_path = true;
				goto sync_slow_path;
			}
			if (unlikely(slow_path)) {
				slow_path_finished = true;
				goto sync_slow_path;
			}

			gpte_gpa = get_ptd_level_sp_gpa(sp, sptep);
			if (kvm_vcpu_get_guest_pte_atomic(vcpu, gpte_gpa, gpte)) {
				slow_path = true;
				goto sync_slow_path;
			}

			if (unlikely(!is_present_gpte(gpte))) {
				slow_path = true;
				goto sync_slow_path;
			}

			if (unlikely(is_guest_ptd_updated(vcpu, *sptep, gpte, gva,
							  level))) {
				/* guest changed own PT directory entry */
				slow_path = true;
				goto sync_slow_path;
			}

			/* hpa of lower level of shadow page table */
			spt_walker->shadow_addr = kvm_pte_pfn_to_phys_addr(*sptep,
							spt_walker->pt_struct);

			/* Move iterators to lower level of page tables */
			spt_walker->level--;
			spt_walker->pt_level--;

			ret = sync_gva_pte_range(vcpu, gmm, spt_walker,
						 gva, gva_next, retry_gva);

			/*
			 * Move iterators back to upper level
			 * of page tables
			 */
			spt_walker->level++;
			spt_walker->pt_level++;

			if (ret != 0) {
				/* unlock should have been made by a function */
				/* that returns error */
				return ret;
			}
		}

sync_slow_path:
		/* Go to next pt entry on curr level */
		if (unlikely(slow_path)) {
			if (!slow_path_started) {
				gva_start_slow = gva;
				slow_path_started = true;
				goto next_pte;
			} else if (!slow_path_finished) {
				goto next_pte;
			}

			/* empty range of spt entries is completed */
			/* goto slow path to sync this range */
			gva_end_slow = gva;
			spin_unlock(&kvm->mmu_lock);
			ret = sync_gva_range_slow(vcpu, gmm,
						  gva_start_slow, gva_end_slow);
			if (ret != 0) {
				/* unlock should have been made by a function */
				/* that returns error */
				return ret;
			}
			spin_lock(&kvm->mmu_lock);
			slow_path = false;
			slow_path_started = false;
			slow_path_finished = false;
			continue;
		}

next_pte:
		sptep++;
		gva = gva_next;
		if (unlikely(slow_path && gva >= gva_end)) {
			/* end of this level spt entries is reached */
			/* complete sync of slow path range */
			slow_path_finished = true;
			goto sync_slow_path;
		}
	} while (gva != gva_end);

	return 0;
}

static long sync_gva_range(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
			gva_t start, gva_t end)
{
	struct kvm *kvm = vcpu->kvm;
	struct kvm_shadow_walk_iterator spt_walker;
	hpa_t spt_root;
	e2k_addr_t vptb_start, vptb_size, vptb_mask, vptb_end;
	gpa_t gpt_root;
	int top_level;
	const pt_struct_t *vcpu_pt = GET_VCPU_PT_STRUCT(vcpu);
	const pt_level_t *pt_level;
	gva_t retry_gva;
	bool sync_range1, sync_range2;
	int ret;

	vptb_start = pv_vcpu_get_init_gmm(vcpu)->u_vptb;

	/* Get top level number for spt */
	top_level = vcpu->arch.mmu.root_level;
	pt_level = get_pt_struct_level_on_id(vcpu_pt, top_level);

	/* Get gva range of page table self-mapping */
	vptb_size = get_pt_level_size(pt_level);
	vptb_mask = get_pt_level_mask(pt_level);
	vptb_start &= vptb_mask;
	vptb_end = vptb_start + vptb_size - 1;

	/*
	 * Use simplified function sync_gva to flush single address
	 * which does not hit into vptb range
	 */
	if ((start == end) && (start < vptb_start || start >= vptb_end)) {
		return sync_gva(vcpu, gmm, start);
	}

	retry_gva = start;

retry_sync_gva_range:

	spin_lock(&kvm->mmu_lock);

	spt_root = gmm->root_hpa;
	if (!VALID_PAGE(spt_root)) {
		/* shadow PT of the gmm has been already released */
		ret = -EFAULT;
		goto out_unlock;
	}
	gpt_root = gmm->u_pptb;

	trace_kvm_sync_shadow_pt_range(vcpu, gmm, spt_root, gpt_root, start, end);

	sync_range1 = true;
	sync_range2 = true;
	if (start < vptb_start && end < vptb_start ||
			start >= vptb_end && end >= vptb_end) {
		/* flushed gva range doesn't overlap vptb range */
		shadow_pt_walk_init(&spt_walker, vcpu, spt_root, start);
		ret = sync_gva_pte_range(vcpu, gmm, &spt_walker,
					 start, end, &retry_gva);
		if (likely(ret == 0)) {
			;
		} else if (ret < 0) {
			goto out_error;
		} else {
			sync_range1 = false;
		}
	} else if (start < vptb_start && end >= vptb_start && end < vptb_end) {
		/* end part of flushed gva range overlaps vptb range */
		shadow_pt_walk_init(&spt_walker, vcpu, spt_root, start);
		ret = sync_gva_pte_range(vcpu, gmm, &spt_walker,
					 start, vptb_start, &retry_gva);
		if (likely(ret == 0)) {
			;
		} else if (ret < 0) {
			goto out_error;
		} else {
			sync_range1 = false;
		}
	} else if (end > vptb_end && start >= vptb_start && start < vptb_end) {
		/* start part of flushed gva range overlaps vptb range */
		shadow_pt_walk_init(&spt_walker, vcpu, spt_root, vptb_end);
		ret = sync_gva_pte_range(vcpu, gmm, &spt_walker,
					 vptb_end, end, &retry_gva);
		if (likely(ret == 0)) {
			;
		} else if (ret < 0) {
			goto out_error;
		} else {
			sync_range1 = false;
		}
	} else if (start < vptb_start && end >= vptb_end) {
		/* flushed gva range contains vptb range */
		shadow_pt_walk_init(&spt_walker, vcpu, spt_root, start);
		ret = sync_gva_pte_range(vcpu, gmm, &spt_walker,
					 start, vptb_start, &retry_gva);
		if (likely(ret == 0)) {
			;
		} else if (ret < 0) {
			goto out_error;
		} else {
			sync_range1 = false;
		}

		if (sync_range1) {
			shadow_pt_walk_init(&spt_walker, vcpu, spt_root,
						vptb_end);
			ret = sync_gva_pte_range(vcpu, gmm, &spt_walker,
						 vptb_end, end, &retry_gva);
			if (likely(ret == 0)) {
				;
			} else if (ret < 0) {
				goto out_error;
			} else {
				sync_range2 = false;
			}
		}
	}
	/* Do nothing if vptb range contains flushed gva range */

	if (!sync_range1 || !sync_range2) {
		start = retry_gva;
		E2K_KVM_BUG_ON(ret != PFRES_RETRY);
		goto retry_sync_gva_range;
	}

	/*
	 * TODO: TLB flush here may be partial similarly to __flush_tlb_*
	 * in host kernel.
	 */

	ret = 0;

out_unlock:
	spin_unlock(&kvm->mmu_lock);
out_error:
	return ret;
}

static gpa_t gva_to_gpa(struct kvm_vcpu *vcpu, gva_t vaddr, u32 access,
			kvm_arch_exception_t *exception, gw_attr_t *gw_res)
{
	guest_walker_t walker;
	gpt_walker_t gpt_walker;
	gpt_entry_t *gpt_entry;
	gpa_t gpa = UNMAPPED_GVA;
	gpa_t gpt_root;
	int r;

	trace_kvm_gva_to_gpa(vcpu, vaddr, access, INVALID_GPA);

	gpt_root = kvm_get_space_addr_guest_root(vcpu, vaddr);
	init_addr_gpt_walker(vcpu, gpt_root, &gpt_walker, false);

	r = walk_addr(&walker, &gpt_walker, vcpu, vaddr, access);

	if (r) {
		gpa = gfn_to_gpa(walker.gfn);
		gpa |= vaddr & ~PAGE_MASK;
	} else if (exception) {
		*exception = walker.fault;
	}

	if (gw_res) {
		gpt_entry = get_walk_addr_gpte_level(&gpt_walker, walker.level);
		gw_res->level = walker.level;
		gw_res->access = FNAME(gpte_access)(vcpu, gpt_entry->gpte, vaddr);
	}

	free_addr_gpt_walker(&gpt_walker);
	trace_kvm_gva_to_gpa(vcpu, vaddr, access, gpa);
	return gpa;
}

/*
 * Using the cached information from sp->gfns is safe because:
 * - The spte has a reference to the struct page, so the pfn for a given gfn
 *   can't change unless all sptes pointing to it are nuked first.
 *
 * Note:
 *   We should flush all tlbs if spte is dropped even though guest is
 *   responsible for it. Since if we don't, kvm_mmu_notifier_invalidate_page
 *   and kvm_mmu_notifier_invalidate_range_start detect the mapping page isn't
 *   used by guest then tlbs are not flushed, so guest is allowed to access the
 *   freed pages.
 *   And we increase kvm->tlbs_dirty to delay tlbs flush in this case.
 */
static int spt_sync_page(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp)
{
	int i, nr_present = 0;
	bool host_writable;
	gpa_t first_pte_gpa;
	u64 pte_cui;

	/* direct kvm_mmu_page can not be unsync. */
	BUG_ON(sp->role.direct);

	trace_kvm_mmu_sync_page(sp);

	first_pte_gpa = get_level1_sp_gpa(sp, sp->spt);

	DebugSPF("sp %px level #%d first_pte_gpa 0x%llx\n",
		sp, sp->role.level, first_pte_gpa);
	for (i = 0; i < PT64_ENT_PER_PAGE; i++) {
		pgprot_t old_spte;
		unsigned pte_access;
		pgprotval_t gpte;
		gpa_t pte_gpa;
		gfn_t gfn;

		if (!pgprot_val(sp->spt[i]))
			continue;

		pte_gpa = first_pte_gpa + i * sizeof(pgprotval_t);

		if (kvm_vcpu_get_guest_pte_atomic(vcpu, pte_gpa, gpte))
			return 0;

		if (unlikely(trace_kvm_sync_shadow_gva_enabled())) {
			trace_kvm_sync_gpte(sp->gva, &sp->spt[i], pte_gpa, gpte,
						sp->role.level);
		}
		if (FNAME(prefetch_invalid_gpte)(vcpu, sp, &sp->spt[i], gpte)) {
			/*
			 * Update spte before increasing tlbs_dirty to make
			 * sure no tlb flush is lost after spte is zapped; see
			 * the comments in kvm_flush_remote_tlbs().
			 */
			smp_wmb();
			vcpu->kvm->tlbs_dirty++;
			continue;
		}
		trace_kvm_sync_gpte(sp->gva, &sp->spt[i], pte_gpa, gpte,
					sp->role.level);
		if (is_only_valid_gpte(vcpu, gpte)) {
			set_spte(vcpu, &sp->spt[i], 0,
				PT_PAGE_TABLE_LEVEL, 0, 0,
				false, false, false,
				true	/* only validate */, 0);
			nr_present++;
			trace_kvm_sync_only_valid(&sp->spt[i], PT_PAGE_TABLE_LEVEL);
			continue;
		}

		gfn = gpte_to_gfn_level_sp(vcpu, sp, &sp->spt[i], gpte);
		pte_cui = FNAME(gpte_cui)(gpte);
		/* protections PT directories entries and page entries are */
		/* independent for e2k arch, see full comment above */
		pte_access = FNAME(gpte_access)(vcpu, gpte, sp->gva);
		FNAME(protect_clean_gpte)(&pte_access, gpte);
		DebugSPF("pte_gpa 0x%llx == 0x%lx, gfn 0x%llx\n",
			pte_gpa, gpte, gfn);

		if (sync_mmio_spte(vcpu, &sp->spt[i], gfn, pte_access,
		      &nr_present))
			continue;

		if (gfn != sp->gfns[i]) {
			old_spte = sp->spt[i];
			drop_spte(vcpu->kvm, &sp->spt[i]);
			/*
			 * The same as above where we are doing
			 * prefetch_invalid_gpte().
			 */
			smp_wmb();
			vcpu->kvm->tlbs_dirty++;
			trace_kvm_sync_spte(&sp->spt[i], old_spte, sp->role.level);
			continue;
		}

		nr_present++;

		host_writable = is_spte_host_writable_mask(vcpu->kvm,
								sp->spt[i]);

		old_spte = sp->spt[i];
		set_spte(vcpu, &sp->spt[i], pte_access,
			 PT_PAGE_TABLE_LEVEL, gfn,
			 spte_to_pfn(vcpu->kvm, sp->spt[i]), true, false,
			 host_writable, false, pte_cui);
		DebugSPF("shadow spte %px == 0x%lx, gfn 0x%llx, pfn 0x%llx\n",
			&sp->spt[i], pgprot_val(sp->spt[i]), gfn,
			spte_to_pfn(vcpu->kvm, sp->spt[i]));
		trace_kvm_sync_spte(&sp->spt[i], old_spte, PT_PAGE_TABLE_LEVEL);
	}

	return nr_present;
}

/*
 * Initialize guest page table iterator
 */
static void guest_pt_walk_init(guest_walker_t *guest_walker,
				struct kvm_vcpu *vcpu,
				pgprotval_t guest_root)
{
	const pt_struct_t *gpt = GET_VCPU_PT_STRUCT(vcpu);

	guest_walker->pt_struct = gpt;
	guest_walker->level = vcpu->arch.mmu.root_level;
	guest_walker->pt_level =
		get_pt_struct_level_on_id(gpt, guest_walker->level);
	guest_walker->gfn = gpte_to_gfn_level(vcpu, guest_root,
						guest_walker->pt_level);
	guest_walker->pt_access = ACC_USER_ALL;
	guest_walker->pte_access = ACC_USER_ALL;
	guest_walker->max_level = guest_walker->level;
}

/*
 * Allocate new spte
 */
static pf_res_t allocate_shadow_level(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
					gfn_t table_gfn,
					gva_t gva, int level,
					unsigned int pt_access,
					pgprot_t *spt_pte_hva,
					bool is_direct,
					gpa_t guest_pt_gpa)
{
	struct kvm_mmu_page *sp = NULL;

	clear_sp_write_flooding_count(spt_pte_hva);
	/* If this spte is the large page, then unmap it */
	drop_large_spte(vcpu, spt_pte_hva);

	/* If spte is not peresent, allocate it */
	if (!is_shadow_present_pte(vcpu->kvm, *spt_pte_hva)) {
		sp = kvm_mmu_get_page(vcpu, table_gfn, gva,
				level, is_direct, guest_pt_gpa,
				pt_access,
				is_shadow_valid_pte(vcpu->kvm, *spt_pte_hva));
		if (!sp) {
			DebugSYNC("Allocation of shadow page for spte 0x%lx"
				" failed\n", spt_pte_hva);
			return PFRES_ERR;
		}

		link_shadow_page(vcpu, gmm, spt_pte_hva, sp);
		DebugSYNC("allocated new shadow page with hpa 0x%llx, guest"
			" table gfn 0x%llx, on level #%d, linked to spte"
			" with hpa 0x%llx, hva 0x%lx on level #%d\n",
			pgprot_val(*spt_pte_hva) & _PAGE_PFN_V3, table_gfn,
			level, __pa(spt_pte_hva), spt_pte_hva, level + 1);
	} else {
		DebugSYNC("present shadow page with hpa 0x%llx, guest table"
			" gfn 0x%llx, on level #%d, linked to spte with"
			" hpa 0x%llx, hva 0x%lx on level #%d\n",
			pgprot_val(*spt_pte_hva) & _PAGE_PFN_V3, table_gfn,
			level, __pa(spt_pte_hva), spt_pte_hva, level + 1);
	}

	return PFRES_NO_ERR;
}

/*
 * Try to convert gfn to pfn. If pfn is allocated on host, return valid pfn.
 * If pfn is not allocated on host, do not fault and wait pfn allocation,
 * set *valid_only = true instead.
 */
static void gfn_atomic_pf(struct kvm_vcpu *vcpu, gfn_t gfn, gva_t gva,
			unsigned int pte_access, kvm_pfn_t *pfn,
			bool *valid_only)
{
	try_pf_err_t res;
	*valid_only = false;

	DebugSYNC("gva 0x%lx -> gfn 0x%llx\n", gva, gfn);

	/* Get pfn for given gfn */
	res = try_atomic_pf(vcpu, gfn, pfn, true);
	if (res == TRY_PF_ONLY_VALID_ERR) {
		/*
		 * gfn is valid (same as hva of gfn on host),
		 * but pfn for gva has not yet been allocated
		 */
		*valid_only = true;
		DebugSYNC("gfn 0x%llx is valid but pfn is not yet allocated"
			" on host\n", gfn);
	} else if (res == TRY_PF_MMIO_ERR) {
		/*
		 * gfn is from MMIO space, but not
		 * registered on host
		 */
		DebugSYNC("gfn 0x%llx is from MMIO space, but not registered "
			"on host\n", gfn);
	} else {
		/*
		 * gfn is valid and pfn is already allocated on host
		 */
		pf_res_t ret_val;

		DebugSYNC("try_atomic_pf returned valid pfn 0x%llx\n", *pfn);
		if (handle_abnormal_pfn(vcpu, gva, gfn, *pfn, pte_access,
					&ret_val)) {
			E2K_KVM_BUG_ON(true);
		}
	}
}

/*
 * Create mapping for guest huge page in shadow page table.
 * Split huge page into smaller shadow pages if needed.
 */
static pf_res_t map_huge_page_to_spte(struct kvm_vcpu *vcpu,
			gmm_struct_t *gmm, gpt_walker_t *gpt_walker,
			pgprotval_t gpte, gva_t gva, gfn_t gfn,
			int level, int split_to_level, pgprot_t *root_pte_hva)
{
	pgprot_t old_spte;
	pf_res_t ret;
	pgprot_t *pte_hva;
	gfn_t table_gfn;
	kvm_pfn_t pfn = 0;
	bool gfn_only_valid, is_guest_pt_area, force_pt_level = false;
	const pt_struct_t *pt_struct = GET_HOST_PT_STRUCT(vcpu->kvm);
	const pt_level_t *pt_level = get_pt_struct_level_on_id(pt_struct, level);
	const pt_struct_t *gpt_struct = GET_VCPU_PT_STRUCT(vcpu);
	gpt_entry_t *gpt_entry;
	unsigned gpte_access, gpt_access;
	/* Get number of sptes, which one spt level contains */
	int sptes_num = PAGE_SIZE / sizeof(pgprotval_t);
	unsigned long split_size;
	int ind, guest_level;

	E2K_KVM_BUG_ON(split_to_level > level);

	gpte_access = FNAME(gpte_access)(vcpu, gpte, gva);
	FNAME(protect_clean_gpte)(&gpte_access, gpte);
	gpt_access = FNAME(gpte_access)(vcpu, gpte, INVALID_GVA);
	guest_level = gpt_walker->min_level;

	/*
	 * If we are already on level #1, then map it
	 */
	if (level == PT_PAGE_TABLE_LEVEL)
		goto map;

	/*
	 * Check if gfn belongs to the area of guest page table, i.e write to
	 * this gfn will change guest page table itself.
	 */
	vcpu->arch.write_fault_to_shadow_pgtable = false;
	is_guest_pt_area = is_self_change_mapping(vcpu, level,
				gpt_walker, gpte_access, gfn, false,
				&vcpu->arch.write_fault_to_shadow_pgtable);

	/*
	 * If gfn belongs to the area of guest page table, then
	 * map it by pages on level 1 in shadow page table
	 */
	if (is_guest_pt_area) {
		split_to_level = PT_PAGE_TABLE_LEVEL;
		force_pt_level = true;
		DebugSYNCV("gva 0x%lx (gfn = 0x%llx) belongs to guest pt "
			"area, split guest page on level #%d into pages "
			"on level #%d\n",
			gva, gfn, gpt_walker->min_level, split_to_level);
	} else {
		/*
		 * Get max mapping level of this gfn in host
		 * page table (hva -> pfn)
		 */
		split_to_level = level;
		DebugSYNCV("can split guest page on level #%d into pages on"
			" level #%d , force = %s\n", level,
			split_to_level, force_pt_level ? "yes" : "no");
	}

	DebugSYNCV("with thp map guest page on level #%d by pages on"
			" level #%d\n", level, split_to_level);

	/*
	 * If we have achived split_to_level, then simply assign pfn to spte.
	 * Otherwise, allocate lower level of spt and map all sptes,
	 * which it contains.
	 */
map:
	gfn_atomic_pf(vcpu, gfn, gva, gpte_access, &pfn, &gfn_only_valid);
	if (likely(!force_pt_level) && (level > PT_PAGE_TABLE_LEVEL)) {
		transparent_hugepage_adjust(vcpu, &gfn, &pfn, &split_to_level);
	}
	if (level == split_to_level) {
		old_spte = *root_pte_hva;
		mmu_set_spte(vcpu, root_pte_hva, gpte_access,
				false, level, gfn, pfn, false,
				true, gfn_only_valid, FNAME(gpte_cui)(gpte));
		trace_kvm_sync_spte(root_pte_hva, old_spte, level);
		return PFRES_NO_ERR;
	}

	kvm_release_pfn_clean(pfn);
	table_gfn = gfn & ~(KVM_PT_LEVEL_PAGES_PER_HPAGE(pt_level) - 1);
	old_spte = *root_pte_hva;
	gpt_entry = get_walk_addr_gpte_level(gpt_walker, level);
	ret = allocate_shadow_level(vcpu, gmm, table_gfn,
					gva, level - 1, gpt_access,
					root_pte_hva, true,
					gpt_entry->gpa);
	if (ret)
		return ret;
	trace_kvm_sync_spt_level(root_pte_hva, old_spte, level);

	/* Get host address of allocated spte */
	pte_hva = __va(kvm_pte_pfn_to_phys_addr(*root_pte_hva, pt_struct));

	DebugSYNC("map guest page with gfn 0x%llx on level #%d to spte with"
		" hpa 0x%llx by pages of level #%d\n",
		gfn, level, __pa(root_pte_hva), split_to_level);

	/*
	 * Walk through all sptes, contained in this spte and
	 * map them.
	 */
	split_size = get_pt_struct_level_page_size(gpt_struct, split_to_level);
	ind = 0;
	do {
		ret = map_huge_page_to_spte(vcpu, gmm, gpt_walker, gpte, gva, gfn,
					    level - 1, split_to_level, pte_hva);
		if (ret)
			return ret;

		gva += split_size;
		gfn += (split_size >> PAGE_SHIFT);
		pte_hva++;
		ind++;
	} while (ind < sptes_num);

	return PFRES_NO_ERR;
}

/*
 * Create mapping for gva range [start_gva, end_gva] in shadow page table
 * in accordance with guest page table maping.
 */
static pf_res_t sync_shadow_pte_range(struct kvm_vcpu *vcpu,
				gmm_struct_t *gmm,
				gva_t start_gva, gva_t end_gva,
				gpt_walker_t *gpt_walker,
				guest_walker_t *guest_walker,
				kvm_shadow_walk_iterator_t *spt_walker,
				gva_t *retry_gva)
{
	struct kvm *kvm = vcpu->kvm;
	struct kvm_mmu *mmu = &vcpu->arch.mmu;
	pf_res_t ret;
	kvm_pfn_t pfn;
	gva_t next_gva, gva;
	gpa_t guest_table_gpa, guest_pte_gpa;
	pgprotval_t *guest_pte_hva;
	hpa_t spt_table_hpa, spt_pte_hpa;
	pgprot_t *spt_table_hva, *spt_pte_hva, old_spte;
	pgprotval_t guest_pte;
	unsigned pte_index, pte_access;
	int level;
	const pt_level_t *guest_pt_level, *spt_pt_level;
	gpt_entry_t *gpt_entry;
	unsigned long level_size;
	bool gfn_only_valid, is_huge_page, is_lowest_level;
	bool locked_done = false;
	bool gpt_copied = false;

	DebugSYNC("called for gva range [0x%lx - 0x%lx]\n", start_gva,
			end_gva);

	E2K_KVM_BUG_ON(start_gva > end_gva);

	/* Get descriptors of curr level of guest and shadow page tables */
	level = guest_walker->level;
	guest_pt_level = guest_walker->pt_level;
	spt_pt_level = spt_walker->pt_level;
	E2K_KVM_BUG_ON(level < PT_PAGE_TABLE_LEVEL);


	/* Get index in curr level of guest and shadow page tables */
	pte_index = get_pt_level_addr_index(start_gva, guest_pt_level);

	/* gpa of curr level of guest page table */
	guest_table_gpa = gfn_to_gpa(guest_walker->gfn);
	/* hva of curr level of guest page table */
	/* gpa of guest pt entry in curr level */
	guest_pte_gpa = guest_table_gpa + pte_index * sizeof(pgprotval_t);

	DebugSYNC("guest level gpa 0x%llx, level #%d, idx %d\n",
		guest_table_gpa, level, pte_index);

	/* hpa of curr level of shadow page table */
	spt_table_hpa = spt_walker->shadow_addr;
	/* hva of curr level of shadow page table */
	spt_table_hva = (pgprot_t *) __va(spt_table_hpa);
	/* hpa of shadow pt entry in curr level */
	spt_pte_hpa = spt_table_hpa + pte_index * sizeof(pgprotval_t);
	/* hva of shadow pt entry in curr level */
	spt_pte_hva = spt_table_hva + pte_index;
	spt_walker->index = pte_index;
	spt_walker->sptep = spt_pte_hva;

	DebugSYNC("shadow level hpa 0x%llx, hva 0x%lx, level #%d, idx %d\n",
		spt_table_hpa, spt_table_hva, level, pte_index);

	gva = start_gva;

	/*
	 * Uses two-phase synchronization with possible recursion
	 * 1. In the first phase, a walk through the guest page table
	 *    is performed without any synchronization, but page faults
	 *    are allowed when reading PTs entries to pin the necessary
	 *    PTs pages.
	 * 2. In the seconde phase, a walk through the host shadow PTs
	 *    is performed under MMU common spinlock. At the same time,
	 *    the PTs entries of the guest table re-read, but atomically
	 *    to avoid page faults.
	 *
	 * Recursion occurs when changes are detected in the guest PTs
	 * or page faults.
	 */

	if (unlikely(level == gpt_walker->max_level)) {
		E2K_KVM_BUG_ON(level != PT_ROOT_LEVEL);
		ret = walk_addr_range_gptes(vcpu, start_gva, end_gva,
					    gpt_walker->gpt_root, gpt_walker);
		if (unlikely(ret != 0)) {
			pr_err("%s(): walk through the guest PTs failed for guest "
				"range 0x%lx - 0x%lx, error %d\n",
				__func__, start_gva, end_gva, ret);
			return ret;
		}

		/* walk trough shadow PTs should be under lock */
		spin_lock(&kvm->mmu_lock);
		locked_done = true;
	}

	gpt_entry = get_walk_addr_gpte_level(gpt_walker, level);

	do {
		pgprotval_t *gpt_page = NULL, *gpt_page_atomic = NULL;
		gpte_state_t r;

		/*
		 * Protections PT directories entries and page entries are
		 * independent for e2k arch.
		 */
		pte_access = ACC_USER_ALL;

		trace_kvm_sync_shadow_gva(gva, level);

		next_gva = pt_level_next_gva(gva, end_gva, guest_pt_level);

		if (unlikely(level == PT_PAGE_TABLE_LEVEL && !gpt_copied)) {
			gpa_t start_gpa;

			/* Copy gptes atomic from guest table */
			start_gpa = gpt_entry->gpt_base +
					gpt_entry->start_index *
						sizeof(pgprotval_t);
			ret = copy_addr_range_gptes_atomic(vcpu,
					gva, end_gva, start_gpa,
					gpt_walker, level);
			if (unlikely(ret != 0)) {
				spin_unlock(&kvm->mmu_lock);
				if (ret < 0) {
					return ret;
				} else {
					pr_err("%s(); failed atomic copy, will run "
						"again with next addr 0x%lx\n",
						__func__, next_gva);
					*retry_gva = next_gva;
					return PFRES_RETRY;
				}
			}
			gpt_copied = true;
			gpt_page = gpt_entry->gpt_page;
			gpt_page_atomic = gpt_entry->gpt_page_atomic;
		}

		r = get_addr_range_gpte_atomic(vcpu, gva, &guest_pte,
				guest_pte_gpa, gpt_page, gpt_page_atomic,
				gpt_walker, guest_pt_level, level);
		if (unlikely(r != same_gpte_state)) {
			spin_unlock(&kvm->mmu_lock);
			if (r < 0) {
				return (int)r;
			} else {
				DebugSYNC("succed retry, but guest pte was "
					"changed, will run again with "
					"same start addr 0x%lx\n", gva);
				*retry_gva = gva;
				return PFRES_RETRY;
			}
		}

		/* Fill guest page table iterator for curr level */
		guest_pte_hva = (pgprotval_t *)gpt_entry->hva;
		guest_walker->gfn = gpte_to_gfn_level(vcpu, guest_pte,
							guest_pt_level);
		guest_walker->gva = gva;

		/*
		 * If gpte is marked as only valid, then
		 * it will be further allocated (during pagefault)
		 * Mark spte as only valid too.
		 */
		if (is_only_valid_gpte(vcpu, guest_pte)) {
			DebugSYNCV("gpte with gpa 0x%llx hva 0x%lx,"
				" gva 0x%lx, level #%d is only valid, mark"
				" it as only valid in shadow page table and"
				" go to next pte on this level\n",
				guest_pte_gpa, guest_pte_hva, gva, level);

			trace_kvm_sync_gpte(gva, spt_pte_hva, guest_pte_gpa,
						guest_pte, level);
			mmu_set_spte(vcpu, spt_pte_hva, pte_access, false,
					level, guest_walker->gfn, 0, false,
					true, true, 0);
			if (level == E2K_PGD_LEVEL_NUM) {
				pv_mmu_spte_make_sync_request(vcpu, spt_pte_hva);
			}
			trace_kvm_sync_only_valid(spt_pte_hva, level);
			goto next_pte;
		}

		if (unlikely(!is_present_gpte(guest_pte))) {
			struct kvm_mmu_page *sp = NULL;

			/* If guest & shadow pt entries are not present, */
			/* then skip it */
			if (likely(is_shadow_unmapped_pte(kvm,
							  *spt_pte_hva))) {
				DebugSYNCV("gpte with gpa 0x%llx hva 0x%lx,"
					" gva 0x%lx, level #%d is not present, go"
					" to next gpte on this level\n",
					guest_pte_gpa, guest_pte_hva, gva, level);
				if (unlikely(trace_kvm_sync_shadow_gva_enabled())) {
					trace_kvm_sync_gpte(gva, spt_pte_hva,
						guest_pte_gpa, guest_pte, level);
				}
				goto next_pte;
			}

			/* shadow pt entry is not empty, clear it */
			sp = page_header(__pa(spt_pte_hva));
			if (mmu_page_zap_pte(kvm, sp, spt_pte_hva))
				kvm_flush_remote_tlbs(kvm);

			old_spte = *spt_pte_hva;
			if (is_valid_gpte(vcpu, guest_pte)) {
				/* only validate host pte too */
				validate_spte(kvm, spt_pte_hva);
			} else {
				/* only clear host pte too */
				clear_spte(kvm, spt_pte_hva);
			}
			trace_kvm_sync_spte(spt_pte_hva, old_spte, level);
			goto next_pte;
		}

		trace_kvm_sync_gpte(gva, spt_pte_hva, guest_pte_gpa,
					guest_pte, level);

		if (unlikely(is_rsvd_bits_set(mmu, guest_pte, level))) {
			DebugSYNCV("guest pt entry gpa 0x%llx hva 0x%lx,"
				" gva 0x%lx, level #%d is reserved, go to"
				" next pte on this level\n",
				guest_pte_gpa, guest_pte_hva, gva, level);
			goto next_pte;
		}

		/* Check if current pt entry is huge page */
		is_huge_page = is_huge_gpte(vcpu, guest_pte);

		/* Check if the lowest possible level achieved */
		is_lowest_level = (level == PT_PAGE_TABLE_LEVEL);

		if (is_huge_page || is_lowest_level) {
			/* Get access rights for guest pt entry */
			pte_access &= FNAME(gpte_access)(vcpu, guest_pte, gva);
		} else {
			/* Get access rights for guest pt directory level */
			pte_access &= FNAME(gpte_access)(vcpu, guest_pte, INVALID_GVA);
		}
		FNAME(protect_clean_gpte)(&pte_access, guest_pte);
		guest_walker->pt_access = guest_walker->pte_access;
		guest_walker->pte_access = pte_access;
		guest_walker->pte_cui = FNAME(gpte_cui)(guest_pte);

		DebugSYNC("correct gpte with gpa 0x%llx hva 0x%lx,"
			" gpte val 0x%lx, gva 0x%lx, level #%d %s\n",
			guest_pte_gpa, guest_pte_hva, guest_pte, gva, level,
			is_huge_page ? "huge page" : "");


		if (is_lowest_level) {
			gfn_only_valid = false;
			gfn_atomic_pf(vcpu, guest_walker->gfn, gva,
					pte_access, &pfn, &gfn_only_valid);
			/* Set pfn in spte */
			old_spte = *spt_pte_hva;
			mmu_set_spte(vcpu, spt_pte_hva, pte_access, false,
				level, guest_walker->gfn, pfn, false,
				true, gfn_only_valid, guest_walker->pte_cui);
			trace_kvm_sync_spte(spt_pte_hva, old_spte, level);
		} else if (is_huge_page) {
			/* Map huge page to spte */
			ret = map_huge_page_to_spte(vcpu, gmm, gpt_walker,
						guest_pte, gva, guest_walker->gfn,
						level, level, spt_pte_hva);

			if (ret) {
				spin_unlock(&kvm->mmu_lock);
				return ret;
			}
			level_size = get_pt_level_page_size(guest_pt_level);
			guest_walker->gfn += (level_size >> PAGE_SHIFT);
			guest_walker->gva += level_size;
			if (mmu_need_topup_memory_caches(vcpu)) {
				DebugSYNCV("need fill mmu caches, run again"
					" with gva 0x%lx\n", gva);
				spin_unlock(&kvm->mmu_lock);
				*retry_gva = gva;
				return PFRES_RETRY_MEM;
			}
		} else {
			/* Allocate lower level in shadow page table */
			old_spte = *spt_pte_hva;
			ret = allocate_shadow_level(vcpu, gmm,
					guest_walker->gfn,
					gva, level - 1, pte_access,
					(pgprot_t *) spt_pte_hva,
					false, gpt_entry->gpa);
			if (ret) {
				spin_unlock(&kvm->mmu_lock);
				if (ret < 0) {
					return ret;
				} else {
					return PFRES_RETRY;
				}
			}

			trace_kvm_sync_spt_level(spt_pte_hva, old_spte, level);

			if (mmu_need_topup_memory_caches(vcpu)) {
				DebugSYNCV("need fill mmu caches, run again"
					" with gva 0x%lx\n", gva);
				spin_unlock(&kvm->mmu_lock);
				*retry_gva = gva;
				return PFRES_RETRY_MEM;
			}

			/* hpa of lower level of shadow page table */
			spt_walker->shadow_addr =
				kvm_pte_pfn_to_phys_addr(*spt_pte_hva,
						spt_walker->pt_struct);

			/* Move iterators to lower level of page tables */
			guest_walker->level--;
			guest_walker->pt_level--;
			spt_walker->level--;
			spt_walker->pt_level--;

			/* Sync lower-level pt range */
			ret = sync_shadow_pte_range(vcpu, gmm,
					gva, next_gva, gpt_walker, guest_walker,
					spt_walker, retry_gva);

			/*
			 * Move iterators back to upper level
			 * of page tables
			 */
			guest_walker->level++;
			guest_walker->pt_level++;
			spt_walker->level++;
			spt_walker->pt_level++;

			if (ret) {
				/* unlock should have been made by a function */
				/* that returns error */
				return ret;
			}
		}

next_pte:
		/* Go to next pt entry on curr level */
		guest_pte_gpa += sizeof(pgprotval_t);
		gpt_entry->gpa += sizeof(pgprotval_t);
		gpt_entry->hva += sizeof(pgprotval_t);
		spt_pte_hpa += sizeof(pgprotval_t);
		spt_pte_hva++;
		gva = next_gva;
		if (unlikely(gva != end_gva && level > PT_PAGE_TABLE_LEVEL)) {
			/*
			 * Multi-gptes can be only on page tables level #1
			 * For higher levels it need to walk around guest PTs
			 * again for the new incremented guest address
			 * Spin is unlocked to walk through guest PTs in not
			 * atomic mode with enabled page faults, but spin
			 * again locked to continue shadow PTs walk
			 */
			spin_unlock(&kvm->mmu_lock);
			cond_resched();
			ret = walk_next_addr_range_gptes(vcpu, gva, end_gva,
							 gpt_walker, level);
			if (unlikely(ret != 0)) {
				pr_err("%s(): walk through the guest PTs failed "
					"for guest next range 0x%lx - 0x%lx on "
					"level %d, error %d\n",
					__func__, gva, end_gva, level, ret);
				return ret;
			}
			/* shadow PTs walk should be continued under lock */
			spin_lock(&kvm->mmu_lock);
		}
	} while (gva != end_gva);

	if (locked_done) {
		check_and_sync_guest_roots(vcpu, gmm);
		/* the lock has been made here, so unlock too here */
		spin_unlock(&kvm->mmu_lock);
	}

	return PFRES_NO_ERR;
}

static int do_sync_shadow_pt_range(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
			hpa_t spt_root, gpa_t guest_root,
			gva_t start, gva_t end)
{
	pf_res_t pfres;
	gpt_walker_t gpt_walker;
	guest_walker_t guest_walker;
	kvm_shadow_walk_iterator_t spt_walker;
#ifdef	KVM_ARCH_WANT_MMU_NOTIFIER
	unsigned long mmu_seq = -1;
#endif	/* KVM_ARCH_WANT_MMU_NOTIFIER */
	gva_t gva_retry, gva_start, gva_end;
	long retry_no, retry_max;
	int ret;

	DebugSYNC("started on VCPU #%d : shadow root at 0x%llx, range"
		" from 0x%lx to 0x%lx\n",
		vcpu->vcpu_id, spt_root, start, end);

	gva_retry = start;
	gva_end = end;

	init_addr_range_gpt_walker(vcpu, guest_root, &gpt_walker, false);
	retry_no = 0;
	retry_max = ((end - start) >> PAGE_SHIFT) * MAX_GPT_WALK_RETRY_NUM;

retry:

#ifdef KVM_ARCH_WANT_MMU_NOTIFIER
	if (unlikely(mmu_seq != -1 &&
			!mmu_notifier_no_retry(vcpu->kvm, mmu_seq))) {
		/*
		 * If modification of shadow page table by another
		 * thread is not completed, than restart synchronization
		 * from the very beginning
		 */
		DebugSYNC("mmu_notifier_retry...\n");
		gva_retry = start;
		kvm_mmu_notifier_wait(vcpu->kvm, mmu_seq);
	}
#endif /* KVM_ARCH_WANT_MMU_NOTIFIER */

	trace_kvm_sync_shadow_pt_range(vcpu, gmm, spt_root, guest_root, start, end);

	if (unlikely(mmu_topup_memory_caches(vcpu))) {
		ret = -ENOMEM;
		goto out_error;
	}

	retry_no++;
	if (unlikely(retry_no > retry_max)) {
		pr_err("%s(): too many attempts %ld to get guest ptes in synced state "
			"for guest range 0x%lx - 0x%lx\n",
			__func__, retry_max, start, end);
		ret = -EFAULT;
		goto out_error;
	} else if (retry_no > 1) {
		init_addr_range_gpt_walker(vcpu, guest_root, &gpt_walker, true);
	}

#ifdef KVM_ARCH_WANT_MMU_NOTIFIER
	mmu_seq = vcpu->kvm->mmu_notifier_seq;
	/* FIXME: Do we really need barrier here? */
	smp_rmb();
#endif /* KVM_ARCH_WANT_MMU_NOTIFIER */

	/* Start with address, which caused retry */
	gva_start = gva_retry;

	DebugSYNC("sync gva range [0x%lx - 0x%lx]\n", gva_start, gva_end);

	/* Initialize iterator to pass through shadow page table */
	shadow_pt_walk_init(&spt_walker, vcpu, spt_root, gva_start);

	/* Initialize iterator to pass through guest page table */
	guest_pt_walk_init(&guest_walker, vcpu, guest_root);

	/* Sync page tables starting from pgd ranges */
	pfres = sync_shadow_pte_range(vcpu, gmm,
				gva_start, gva_end, &gpt_walker, &guest_walker,
				&spt_walker, &gva_retry);
	if (likely(pfres == PFRES_RETRY || pfres == PFRES_RETRY_MEM)) {
		cond_resched();
		if (likely(pfres == PFRES_RETRY_MEM))
			retry_no = 1;
		goto retry;
	} else if (pfres != PFRES_NO_ERR) {
		pr_err("%s(): failed, error #%d\n", __func__, pfres);
		ret = -EFAULT;
		goto out_error;
	}

	DebugSYNC("succed for gva range [0x%lx - 0x%lx]\n", start, end);

	ret = 0;

out_error:
	free_addr_range_gpt_walker(&gpt_walker);
	return ret;
}

static int sync_shadow_pt_range(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
			hpa_t spt_root, gva_t start, gva_t end,
			gpa_t guest_root, gva_t vptb)
{
	const pt_struct_t *vcpu_pt = GET_VCPU_PT_STRUCT(vcpu);
	const pt_level_t *gpt_level;
	e2k_addr_t guest_root_host_addr;
	e2k_addr_t vptb_start, vptb_mask, vptb_size;
	int top_level;
	bool pte_writable;
	gva_t gva_start, gva_end;
	int ret;

	DebugSYNC("started on VCPU #%d : shadow root at 0x%llx, range "
		"from 0x%lx to 0x%lx, vptb = 0x%lx\n", vcpu->vcpu_id,
		spt_root, start, end, vptb);

	E2K_KVM_BUG_ON(gmm == NULL);

	/* Get and check address of guest page table root */
	E2K_KVM_BUG_ON(IS_E2K_INVALID_PAGE(guest_root));

	guest_root_host_addr = kvm_vcpu_gfn_to_hva_prot(vcpu,
					gpa_to_gfn(guest_root),
					&pte_writable);
	if (unlikely(kvm_is_error_hva(guest_root_host_addr))) {
		pr_err("%s(): guest PT base address 0x%lx is invalid\n",
			__func__, guest_root_host_addr);
		return -EINVAL;
	}
	/* Check address of shadow page table root */
	if (!VALID_PAGE(kvm_get_space_addr_spt_root(vcpu, start)))
		return -EINVAL;

	/* Check if top_level has correct value */
	top_level = vcpu->arch.mmu.root_level;
	E2K_KVM_BUG_ON(top_level < PT_DIRECTORY_LEVEL);
	gpt_level = get_pt_struct_level_on_id(vcpu_pt, top_level);

	vptb_start = vptb;
	vptb_mask = get_pt_level_mask(gpt_level);
	vptb_size = get_pt_level_size(gpt_level);
	vptb_start &= vptb_mask;

	gva_start = start;
	gva_end = end;
	if (gva_start >= vptb_start && gva_start < vptb_start + vptb_size)
		gva_start = vptb_start + vptb_size;
	if (gva_end > vptb_start)
		gva_end = vptb_start;
	do {
		/* exclude VPTB page from sync */

		DebugPTSYNC("VCPU #%d : sync range from 0x%lx to 0x%lx\n",
			vcpu->vcpu_id, gva_start, gva_end);
		ret = do_sync_shadow_pt_range(vcpu, gmm, spt_root, guest_root,
						gva_start, gva_end);
		if (ret != 0)
			return ret;

		if (gva_start >= vptb_start + vptb_size)
			break;
		if (gva_end >= end)
			break;
		if (vptb_start + vptb_size >= end)
			break;
		gva_start = vptb_start + vptb_size;
		gva_end = end;

	} while (true);

	mmu_flush_shadow_gmm_tlb(vcpu, gmm);

	return ret;
}

static int
atomic_update_shadow_pt(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
			gpa_t gpa, pgprotval_t old_gpte, pgprotval_t new_gpte,
			unsigned long flags)
{
	gfn_t gfn = gpa_to_gfn(gpa), new_gfn;
	struct kvm_mmu_page *sp;
	pgprot_t *spte;
	int nspte, hspte;

	E2K_KVM_BUG_ON(gmm == NULL || gmm->id < 0);

	if (likely(!flags)) {
		new_gfn = gpte_to_gfn(vcpu, new_gpte);
	} else if (flags & THP_INVALIDATE_WR_TRACK) {
		/* entry is updated by guest to invalidate and free huge page */
		;
	} else {
		/* unknown flag */
		E2K_KVM_BUG_ON(true);
	}

	spin_lock(&vcpu->kvm->mmu_lock);

	nspte = 0;	/* number of spte */
	hspte = 0;	/* number of handled spte */
	for_each_gfn_indirect_valid_sp(vcpu->kvm, sp, gfn) {
		DebugPTE("found SP at %px mapped gva from 0x%lx, gfn 0x%llx\n",
			sp, sp->gva, gfn);

		nspte++;

		if (unlikely(gmm != kvm_get_sp_gmm(sp))) {
			/* it is shadow PT of other gmm, should be ignored */
			pr_err("%s(): other gmm #%d for sp level #%d gfn 0x%llx "
				"gva 0x%lx gmm #%d, gpa 0x%llx\n",
				__func__, gmm->id, sp->role.level, sp->gfn,
				sp->gva, kvm_get_sp_gmm(sp)->id, gpa);
			continue;
		}

#ifdef CONFIG_KVM_GVA_CACHE
		/* Update translation in gva->gpa cache */
		if (sp->role.level == PT_PAGE_TABLE_LEVEL) {
			u32 access = FNAME(gpte_access)(vcpu, new_gpte, sp->gva);
			gva_cache_t *gva_cache = sp->gmm->gva_cache;
			gpa_t page_gpa = gfn_to_gpa(vcpu, new_gfn);
			u64 pte_off = (gpa - gfn_to_gpa(sp->gfn)) /
							sizeof(pgprotval_t);
			gva_t res_gva = sp->gva + pte_off << PAGE_SHIFT;

			DbgGvaCache("cache 0x%lx gentry 0x%lx acc 0x%x\n",
					gva_cache, new_gpte, access);

			if (!is_present_gpte(new_gpte))
				gva_cache_flush_addr(gva_cache, res_gva);
			else
				gva_cache_fetch_addr(gva_cache, res_gva,
							page_gpa, access);
		}
#endif /* CONFIG_KVM_GVA_CACHE */

		if (unlikely(gmm != NULL && gmm != kvm_get_sp_gmm(sp))) {
			/* it is shadow PT of other gmm, should be ignored */
			pr_err("%s(): other gmm #%d for sp level #%d gfn 0x%llx "
				"gva 0x%lx gmm #%d, gpa 0x%llx\n",
				__func__, gmm->nid.nr, sp->role.level, sp->gfn,
				sp->gva, kvm_get_sp_gmm(sp)->nid.nr, gpa);
			continue;
		}
		spte = sp_gpa_to_spte(sp, gpa);

		DebugPTE("GPA 0x%llx mapped by spte %px == 0x%lx\n",
			gpa, spte, pgprot_val(*spte));
		if (unlikely(flags & THP_INVALIDATE_WR_TRACK)) {
			if (has_pt_level_huge_gpte(vcpu, sp->role.level)) {
				/*
				 * pte is updated by guest to invalidate and free
				 * huge page, so release old child SP on host
				 */
				new_gfn = INVALID_GPA;
			}
		}

		mmu_pte_write_new_pte(vcpu, sp, spte, gpa, new_gpte);
		hspte++;
	}
	spin_unlock(&vcpu->kvm->mmu_lock);

	KVM_WARN_ON(nspte != 0 && hspte == 0);
	return 0;
}

#ifndef	CONFIG_KVM_PARAVIRT_TLB_FLUSH
static int shadow_protection_fault(struct kvm_vcpu *vcpu,
				gpa_t addr, kvm_mmu_page_t *sp)
{
	struct gmm_struct *gmm;
	gva_t start_gva, end_gva, vptb;
	hpa_t root_hpa;
	gpa_t guest_root;
	int r;
	unsigned index;
	const pt_struct_t *gpt;
	const pt_level_t *gpt_level;
	int level;

	DebugPTE("SP of protected PT at %px level %d, gfn 0x%llx, "
		"gva 0x%lx, addr 0x%llx\n",
		sp, sp->role.level, sp->gfn, sp->gva, addr);

	level = sp->role.level;
	E2K_KVM_BUG_ON(level <= PT_PAGE_TABLE_LEVEL);
	gpt = GET_VCPU_PT_STRUCT(vcpu);
	gpt_level = &gpt->levels[level];
	index = (addr & ~PAGE_MASK) / sizeof(pgprotval_t);
	start_gva = sp->gva & get_pt_level_mask(gpt_level);
	start_gva = set_pt_level_addr_index(start_gva, index, gpt_level);
	end_gva = start_gva + set_pt_level_addr_index(0, 1, gpt_level);
	DebugPTE("protected PT level #%d gva from 0x%lx to 0x%lx\n",
		level, start_gva, end_gva);

	gmm = kvm_get_sp_gmm(sp);
	root_hpa = gmm->root_hpa;
	E2K_KVM_BUG_ON(!VALID_PAGE(root_hpa));
	guest_root = gmm->u_pptb;
	vptb = pv_vcpu_get_init_gmm(vcpu)->u_vptb;

	trace_spt_ptotection_fault(vcpu, gmm, sp, addr, start_gva, end_gva,
					root_hpa, guest_root);

	r = sync_shadow_pt_range(vcpu, gmm, root_hpa,
			start_gva, end_gva, guest_root, vptb);
	E2K_KVM_BUG_ON(r != 0);
	return r;
}
#else	/* CONFIG_KVM_PARAVIRT_TLB_FLUSH */
static int shadow_protection_fault(struct kvm_vcpu *vcpu,
				gpa_t addr, kvm_mmu_page_t *sp)
{
	E2K_KVM_BUG_ON(true);
	return -ENOSYS;
}
#endif	/* !CONFIG_KVM_PARAVIRT_TLB_FLUSH */

#undef guest_walker
#undef FNAME
#undef PT_MAX_FULL_LEVELS
#undef gpte_to_gfn_level_sp
#undef gpte_to_gfn_level_address
#undef gpte_to_gfn_level
#undef CMPXCHG
#undef PT_GUEST_ACCESSED_MASK
#undef PT_GUEST_DIRTY_MASK
