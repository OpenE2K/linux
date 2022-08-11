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
 *
 * Copyright 2018 MCST.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
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

#if PTTYPE == PTTYPE_E2K
	#define pt_element_t pgprotval_t
	#define guest_walker guest_walker_e2k
	#define FNAME(name) e2k_##name
	#define PT_GUEST_ACCESSED_MASK PT_ACCESSED_MASK
	#define PT_GUEST_DIRTY_MASK PT_DIRTY_MASK
	#define PT_MAX_FULL_LEVELS E2K_PT_LEVELS_NUM
	#define CMPXCHG cmpxchg64
#elif PTTYPE == 64
	#define pt_element_t u64
	#define guest_walker guest_walker64
	#define FNAME(name) paging##64_##name
	#define PT_GUEST_ACCESSED_MASK PT_ACCESSED_MASK
	#define PT_GUEST_DIRTY_MASK PT_DIRTY_MASK
	#ifdef CONFIG_X86_64
	#define PT_MAX_FULL_LEVELS 4
	#define CMPXCHG cmpxchg
	#else
	#define CMPXCHG cmpxchg64
	#define PT_MAX_FULL_LEVELS 2
	#endif
#elif PTTYPE == 32
	#define pt_element_t u32
	#define guest_walker guest_walker32
	#define FNAME(name) paging##32_##name
	#define PT_MAX_FULL_LEVELS 2
	#define PT_GUEST_ACCESSED_MASK PT_ACCESSED_MASK
	#define PT_GUEST_DIRTY_MASK PT_DIRTY_MASK
	#define CMPXCHG cmpxchg
#elif PTTYPE == PTTYPE_EPT
	#define pt_element_t u64
	#define guest_walker guest_walkerEPT
	#define FNAME(name) ept_##name
	#define PT_GUEST_ACCESSED_MASK 0
	#define PT_GUEST_DIRTY_MASK 0
	#define CMPXCHG cmpxchg64
	#define PT_MAX_FULL_LEVELS 4
#else
	#error Invalid PTTYPE value
#endif

#define gpte_to_gfn_level_index		FNAME(gpte_to_gfn_level_index)
#define gpte_to_gfn_level_address	FNAME(gpte_to_gfn_level_address)
#define gpte_to_gfn_ind(_vcpu_, ind, pte, _pts_)	\
		gpte_to_gfn_level_index(_vcpu_, ind, pte, \
			&(_pts_)->levels[PT_PAGE_TABLE_LEVEL])
#define gpte_to_gfn_addr(_vcpu_, addr, pte, _pts_)	\
		gpte_to_gfn_level_address(_vcpu_, addr, pte, \
			&(_pts_)->levels[PT_PAGE_TABLE_LEVEL])

/*
 * The guest_walker structure emulates the behavior of the hardware page
 * table walker.
 */
typedef struct guest_walker {
	int level;
	unsigned max_level;
	const pt_struct_t *pt_struct;
	const pt_level_t *pt_level;
	gfn_t table_gfn[PT_MAX_FULL_LEVELS];
	pt_element_t ptes[PT_MAX_FULL_LEVELS];
	pt_element_t prefetch_ptes[PTE_PREFETCH_NUM];
	gpa_t pte_gpa[PT_MAX_FULL_LEVELS];
	pt_element_t __user *ptep_user[PT_MAX_FULL_LEVELS];
	bool pte_writable[PT_MAX_FULL_LEVELS];
	unsigned pt_access;
	unsigned pte_access;
	u64 pte_cui;
	gfn_t gfn;
	gva_t gva;
	kvm_arch_exception_t fault;
} guest_walker_t;

static gfn_t gpte_to_gfn_level_index(struct kvm_vcpu *vcpu, unsigned index,
				pt_element_t gpte, const pt_level_t *pt_level)
{
	gpa_t gpa;
	unsigned ptes;

	gpa = kvm_gpte_gfn_to_phys_addr(vcpu, __pgprot(gpte));
	gpa &= get_pt_level_mask(pt_level);

	/*
	 * common case: 1 page <-> 1 PT entry,
	 * but there is exclusion:
	 *	e2c+	4 Mb page <-> 2 PT entries
	 */
	ptes = get_pt_level_page_size(pt_level) >> get_pt_level_shift(pt_level);
	gpa += get_pt_level_size(pt_level) * (index & (ptes - 1));
	return gpa_to_gfn(gpa);
}
static gfn_t gpte_to_gfn_level_address(struct kvm_vcpu *vcpu, gva_t address,
				pt_element_t gpte, const pt_level_t *pt_level)
{
	unsigned index;

	index = get_pt_level_addr_index(address, pt_level);
	return gpte_to_gfn_level_index(vcpu, index, gpte, pt_level);
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

static inline bool FNAME(is_present_gpte)(unsigned long pte)
{
#if PTTYPE != PTTYPE_EPT
	return pte & PT_PRESENT_MASK;
#else
	return pte & 7;
#endif
}

static inline bool FNAME(is_unmapped_gpte)(struct kvm_vcpu *vcpu,
							unsigned long pte)
{
	return pte == get_gpte_unmapped_mask(vcpu);
}

static inline bool FNAME(is_only_valid_gpte)(struct kvm_vcpu *vcpu,
							unsigned long pte)
{
	return pte == get_gpte_valid_mask(vcpu);
}

static inline bool FNAME(is_valid_gpte)(struct kvm_vcpu *vcpu,
							unsigned long pte)
{
	return !!(pte & get_gpte_valid_mask(vcpu));
}

static inline bool FNAME(is_present_or_valid_gpte)(struct kvm_vcpu *vcpu,
							unsigned long pte)
{
	return FNAME(is_present_gpte) || FNAME(is_only_valid_gpte);
}

static int FNAME(cmpxchg_gpte)(struct kvm_vcpu *vcpu, struct kvm_mmu *mmu,
			       pt_element_t __user *ptep_user, unsigned index,
			       pt_element_t orig_pte, pt_element_t new_pte)
{
	int npages;
	pt_element_t ret;
	pt_element_t *table;
	struct page *page;

	npages = get_user_pages_fast((unsigned long)ptep_user, 1, 1, &page);
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
				  struct kvm_mmu_page *sp, pgprot_t *spte,
				  u64 gpte)
{
	if (is_rsvd_bits_set(&vcpu->arch.mmu, gpte, PT_PAGE_TABLE_LEVEL))
		goto no_present;

	if (!FNAME(is_present_gpte)(gpte))
		goto no_present;

	/* if accessed bit is not supported prefetch non accessed gpte */
	if (PT_GUEST_ACCESSED_MASK && !(gpte & PT_GUEST_ACCESSED_MASK))
		goto no_present;

	return false;

no_present:
	drop_spte(vcpu->kvm, spte);
	if (FNAME(is_only_valid_gpte(vcpu, gpte)))
		return false;
	return true;
}

/*
 * For PTTYPE_EPT, a page table can be executable but not readable
 * on supported processors. Therefore, set_spte does not automatically
 * set bit 0 if execute only is supported. Here, we repurpose ACC_USER_MASK
 * to signify readability since it isn't used in the EPT case
 */
static inline unsigned FNAME(gpte_access)(struct kvm_vcpu *vcpu, u64 gpte)
{
	unsigned access;
#if PTTYPE == PTTYPE_EPT
	access = ((gpte & VMX_EPT_WRITABLE_MASK) ? ACC_WRITE_MASK : 0) |
		((gpte & VMX_EPT_EXECUTABLE_MASK) ? ACC_EXEC_MASK : 0) |
		((gpte & VMX_EPT_READABLE_MASK) ? ACC_USER_MASK : 0);
#else
	BUILD_BUG_ON(ACC_EXEC_MASK != PT_PRESENT_MASK);
	BUILD_BUG_ON(ACC_EXEC_MASK != 1);
	access = gpte & (PT_WRITABLE_MASK | PT_PRESENT_MASK);
	access |= ((gpte & get_gpte_mode_mask(vcpu)) ? ACC_USER_MASK : 0);

	/* Combine NX with P (which is set here) to get ACC_EXEC_MASK.  */
	if (gpte & get_gpte_nx_mask(vcpu))
		access ^= ACC_EXEC_MASK;

	/* e2k arch can have protection bit 'priv' instead of 'user', */
	/* so it need invert access permition */
	if (get_gpte_priv_mask(vcpu))
		access ^= ACC_USER_MASK;
#endif

	return access;
}

static inline u64 FNAME(gpte_cui)(u64 gpte)
{
	return !cpu_has(CPU_FEAT_ISET_V6) ?
		_PAGE_INDEX_FROM_CUNIT_V2(gpte) : 0;
}

static int FNAME(update_accessed_dirty_bits)(struct kvm_vcpu *vcpu,
					     struct kvm_mmu *mmu,
					     guest_walker_t *walker,
					     int write_fault)
{
	unsigned level, index;
	pt_element_t pte, orig_pte;
	pt_element_t __user *ptep_user;
	gfn_t table_gfn;
	int ret;

	/* dirty/accessed bits are not supported, so no need to update them */
	if (!PT_GUEST_DIRTY_MASK)
		return 0;

	for (level = walker->max_level; level >= walker->level; --level) {
		pte = walker->ptes[level - 1];
		orig_pte = pte;
		table_gfn = walker->table_gfn[level - 1];
		ptep_user = walker->ptep_user[level - 1];
		index = offset_in_page(ptep_user) / sizeof(pt_element_t);
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
		if (unlikely(!walker->pte_writable[level - 1]))
			continue;

		ret = FNAME(cmpxchg_gpte)(vcpu, mmu, ptep_user, index,
						orig_pte, pte);
		if (ret)
			return ret;

		kvm_vcpu_mark_page_dirty(vcpu, table_gfn);
		walker->ptes[level - 1] = pte;
	}
	return 0;
}

static inline unsigned FNAME(gpte_pkeys)(struct kvm_vcpu *vcpu, u64 gpte)
{
	unsigned pkeys = 0;
#if PTTYPE == 64
	pte_t pte = {.pte = gpte};

	pkeys = pte_flags_pkey(pte_flags(pte));
#endif
	return pkeys;
}

/*
 * Fetch a guest pte for a guest virtual address
 */
static int FNAME(walk_addr_generic)(guest_walker_t *walker,
				    struct kvm_vcpu *vcpu, struct kvm_mmu *mmu,
				    gva_t addr, u32 access)
{
	int ret;
	int level;
	const pt_level_t *pt_level;
	pt_element_t pte;
	u64 pte_cui;
	pt_element_t __user *uninitialized_var(ptep_user);
	gfn_t table_gfn;
	unsigned index, pt_access, pte_access, accessed_dirty, pte_pkey;
	gpa_t pte_gpa;
	int offset;
	const int write_fault = access & PFERR_WRITE_MASK;
	const int user_fault  = access & PFERR_USER_MASK;
	const int fetch_fault = access & PFERR_FETCH_MASK;
	const int access_size = PFRES_GET_ACCESS_SIZE(access);
	u16 errcode = 0;
	gpa_t real_gpa;
	gfn_t gfn;

	trace_kvm_mmu_pagetable_walk(addr, access);
	DebugSPF("address 0x%lx, fault: write %d user %d fetch %d\n",
		addr, write_fault, user_fault, fetch_fault);
retry_walk:
	walker->level = mmu->root_level;
	walker->pt_struct = kvm_get_vcpu_pt_struct(vcpu);
	walker->pt_level = &walker->pt_struct->levels[mmu->root_level];
	walker->fault.error_code_valid = false;
	walker->fault.error_code = 0;
	pte = kvm_get_space_addr_guest_root(vcpu, addr);
	DebugSPF("root pte 0x%lx\n", pte);

#if PTTYPE == 64
	if (walker->level == PT32E_ROOT_LEVEL) {
		pte = mmu->get_vcpu_pdpte(vcpu, (addr >> 30) & 3);
		trace_kvm_mmu_paging_element(pte, walker->level);
		if (!FNAME(is_present_gpte)(pte))
			goto error;
		--walker->level;
		--walker->pt_level;
	}
#endif
	walker->max_level = walker->level;

	ASSERT(is_ss(vcpu) && !(is_long_mode(vcpu) && !is_pae(vcpu)));

	accessed_dirty = PT_GUEST_ACCESSED_MASK;

	pt_access = ACC_ALL;
	pte_access = ACC_ALL;

	while (true) {
		gfn_t real_gfn;
		unsigned long host_addr;

		level = walker->level;
		pt_level = walker->pt_level;

#if PTTYPE == PTTYPE_E2K
		/*
		 * protections PT directories entries and page entries are
		 * independent for e2k arch, for example ptds always
		 * privileged and non-executable. ptes do not inherit ptds
		 * protections aoutomaticaly and can have own protection,
		 * for example executable and/or user pages
		 */
		pt_access = pte_access;
		pte_access = ACC_ALL;
#else	/* x86 */
		pt_access &= pte_access;
#endif	/* PTTYPE_E2K */

		index = get_pt_level_addr_index(addr, walker->pt_level);
		table_gfn = gpte_to_gfn_ind(vcpu, 0, pte, walker->pt_struct);
		offset    = index * sizeof(pt_element_t);
		pte_gpa   = gfn_to_gpa(table_gfn) + offset;

		DebugSPF("guest PT level #%d addr 0x%lx index 0x%x "
			"offset 0x%x gpa of pte 0x%llx\n",
			level, addr, index, offset, pte_gpa);

		BUG_ON(level < 1);
		walker->table_gfn[level - 1] = table_gfn;
		walker->pte_gpa[level - 1] = pte_gpa;

		real_gpa = mmu->translate_gpa(vcpu, gfn_to_gpa(table_gfn),
					      PFERR_USER_MASK|PFERR_WRITE_MASK,
					      &walker->fault);
		DebugSPF("table gfn 0x%llx, gpa: table 0x%llx real 0x%llx\n",
			table_gfn, gfn_to_gpa(table_gfn), real_gpa);

		/*
		 * FIXME: This can happen if emulation (for of an INS/OUTS
		 * instruction) triggers a nested page fault.  The exit
		 * qualification / exit info field will incorrectly have
		 * "guest page access" as the nested page fault's cause,
		 * instead of "guest page structure access".  To fix this,
		 * the x86_exception struct should be augmented with enough
		 * information to fix the exit_qualification or exit_info_1
		 * fields.
		 */
		if (unlikely(arch_is_error_gpa(real_gpa)))
			return 0;

		real_gfn = gpa_to_gfn(real_gpa);

		host_addr = kvm_vcpu_gfn_to_hva_prot(vcpu, real_gfn,
				&walker->pte_writable[level - 1]);
		DebugSPF("real gfn 0x%llx, host addr 0x%lx\n",
			real_gfn, host_addr);
		if (unlikely(kvm_is_error_hva(host_addr)))
			goto error;

		ptep_user = (pt_element_t __user *)((void *)host_addr + offset);
		if (unlikely(__copy_from_user(&pte, ptep_user, sizeof(pte))))
			goto error;
		walker->ptep_user[level - 1] = ptep_user;
		DebugSPF("level #%d guest pte %px = 0x%lx\n",
			level, ptep_user, pte);

		trace_kvm_mmu_paging_element(__pgprot(pte), level);

		if (unlikely(!FNAME(is_present_gpte)(pte))) {
			if (FNAME(is_unmapped_gpte(vcpu, pte))) {
				errcode |= PFERR_IS_UNMAPPED_MASK;
			} else if (FNAME(is_only_valid_gpte(vcpu, pte))) {
				errcode |= PFERR_ONLY_VALID_MASK;
			} else if (FNAME(is_valid_gpte(vcpu, pte))) {
				errcode |= PFERR_ONLY_VALID_MASK;
			}
			goto error;
		}

		if (unlikely(is_rsvd_bits_set(mmu, pte, walker->level))) {
			errcode = PFERR_RSVD_MASK | PFERR_PRESENT_MASK;
			goto error;
		}
		DebugSPF("guest pte is present and has not reserved bits\n");

		accessed_dirty &= pte;

		pte_cui = FNAME(gpte_cui)(pte);
#if PTTYPE == PTTYPE_E2K
		/* protections PT directories entries and page entries are */
		/* independent for e2k arch, see full comment above */
		pte_access &= FNAME(gpte_access)(vcpu, pte);
#else	/* x86 */
		pte_access &= pt_access & FNAME(gpte_access)(vcpu, pte);
#endif	/* PTTYPE_E2K */

		walker->ptes[level - 1] = pte;

		if (is_last_gpte(mmu, level, pte))
			break;

		--walker->level;
		--walker->pt_level;
	}

	pte_pkey = FNAME(gpte_pkeys)(vcpu, pte);
	DebugSPF("pte: access 0x%x, pkey 0x%x, pt access 0x%x, errcode 0x%x\n",
		pte_access, pte_pkey, pt_access, errcode);
	errcode = permission_fault(vcpu, mmu, pte_access, pte_pkey, access);
	if (unlikely(errcode))
		goto error;

	if (!(access & (PFERR_WRITE_MASK | PFERR_WAIT_LOCK_MASK |
			PFERR_INSTR_FAULT_MASK | PFERR_INSTR_PROT_MASK)) &&
				!(access & PFERR_FAPB_MASK) &&
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

	gfn = gpte_to_gfn_level_address(vcpu, addr, pte, walker->pt_level);
	gfn += (addr & get_pt_level_offset(walker->pt_level)) >> PAGE_SHIFT;

	real_gpa = mmu->translate_gpa(vcpu, gfn_to_gpa(gfn), access,
					&walker->fault);
	if (arch_is_error_gpa(real_gpa))
		return 0;
	DebugSPF("level #%d gfn from guest pte 0x%llx, gpa 0x%llx "
		"real gpa 0x%llx\n",
		level, gfn, gfn_to_gpa(gfn), real_gpa);

	walker->gfn = real_gpa >> PAGE_SHIFT;

	if (!write_fault) {
		FNAME(protect_clean_gpte)(&pte_access, pte);
		DebugSPF("not write fault, so clean guest pte, "
			"new pte access 0x%x\n",
			pte_access);
	} else {
		/*
		 * On a write fault, fold the dirty bit into accessed_dirty.
		 * For modes without A/D bits support accessed_dirty will be
		 * always clear.
		 */
		if (!(pte & PT_GUEST_DIRTY_MASK))
			accessed_dirty &= ~PT_GUEST_ACCESSED_MASK;
		DebugSPF("on write fault, accessed dirty 0x%x\n",
			accessed_dirty);
	}

	if (unlikely(!accessed_dirty)) {
		ret = FNAME(update_accessed_dirty_bits)(vcpu, mmu, walker,
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
		 __func__, (u64)pte, pte_access, pt_access);
	return 1;

error:
	errcode |= write_fault | user_fault;
	if (fetch_fault && (mmu->nx || is_smep(vcpu)))
		errcode |= PFERR_FETCH_MASK;

	walker->fault.error_code_valid = true;
	walker->fault.error_code = errcode;

#if PTTYPE == PTTYPE_EPT
	/*
	 * Use PFERR_RSVD_MASK in error_code to to tell if EPT
	 * misconfiguration requires to be injected. The detection is
	 * done by is_rsvd_bits_set() above.
	 *
	 * We set up the value of exit_qualification to inject:
	 * [2:0] - Derive from [2:0] of real exit_qualification at EPT violation
	 * [5:3] - Calculated by the page walk of the guest EPT page tables
	 * [7:8] - Derived from [7:8] of real exit_qualification
	 *
	 * The other bits are set to 0.
	 */
	if (!(errcode & PFERR_RSVD_MASK)) {
		vcpu->arch.exit_qualification &= 0x187;
		vcpu->arch.exit_qualification |= ((pt_access & pte) & 0x7) << 3;
	}
#endif
	walker->fault.address = addr;

	trace_kvm_mmu_walker_error(walker->fault.error_code);
	DebugSPF("returns error code 0x%x, for addr 0x%lx\n",
		errcode, addr);
	return 0;
}

static int FNAME(walk_addr)(guest_walker_t *walker,
			    struct kvm_vcpu *vcpu, gva_t addr, u32 access)
{
	return FNAME(walk_addr_generic)(walker, vcpu, &vcpu->arch.mmu, addr,
					access);
}

static bool
FNAME(prefetch_gpte)(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp,
		     pgprot_t *spte, pt_element_t gpte, bool no_dirty_log)
{
	unsigned pte_access;
	gfn_t gfn;
	kvm_pfn_t pfn;
	bool gfn_only_valid = false;
	u64 pte_cui;
	int ret;

	if (FNAME(prefetch_invalid_gpte)(vcpu, sp, spte, gpte))
		return false;

	pgprintk("%s: gpte %llx spte %px\n", __func__, (u64)gpte, spte);

	if (FNAME(is_only_valid_gpte(vcpu, gpte))) {
		gfn_only_valid = true;
		gfn = 0;
		pfn = 0;
		pte_access = 0;
		goto write_spte;
	}

	gfn = gpte_to_gfn_ind(vcpu, 0, gpte, kvm_get_vcpu_pt_struct(vcpu));
	pte_cui = FNAME(gpte_cui)(gpte);
#if PTTYPE == PTTYPE_E2K
	pte_access = FNAME(gpte_access)(vcpu, gpte);
	FNAME(protect_clean_gpte)(&pte_access, gpte);
	ret = try_atomic_pf(vcpu, gfn, &pfn,
			no_dirty_log && (pte_access & ACC_WRITE_MASK));
#else	/* native e2k */
	pte_access = sp->role.access & FNAME(gpte_access)(vcpu, gpte);
	FNAME(protect_clean_gpte)(&pte_access, gpte);
	pfn = pte_prefetch_gfn_to_pfn(vcpu, gfn,
			no_dirty_log && (pte_access & ACC_WRITE_MASK));
#endif	/* CONFIG_X86_HW_VIRTUALIZATION */
	if (likely(ret == TRY_PF_NO_ERR)) {
		/* valid guest gfn rmapped to pfn */
	} else if (ret == TRY_PF_ONLY_VALID_ERR) {
		/* gfn with only valid flag */
		gfn_only_valid = true;
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
		KVM_BUG_ON(true);
	}

write_spte:
	/*
	 * we call mmu_set_spte() with host_writable = true because
	 * pte_prefetch_gfn_to_pfn always gets a writable pfn.
	 */
	mmu_set_spte(vcpu, spte, pte_access, 0, PT_PAGE_TABLE_LEVEL, gfn, pfn,
		     true, true, gfn_only_valid, pte_cui);

	return true;
}

static void FNAME(update_pte)(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp,
			      pgprot_t *spte, const void *pte)
{
	pt_element_t gpte = *(const pt_element_t *)pte;

	FNAME(prefetch_gpte)(vcpu, sp, spte, gpte, false);
}

static bool FNAME(gpte_changed)(struct kvm_vcpu *vcpu,
				guest_walker_t *gw, int level)
{
	pt_element_t curr_pte;
	gpa_t base_gpa, pte_gpa = gw->pte_gpa[level - 1];
	u64 mask;
	int r, index;

	if (level == PT_PAGE_TABLE_LEVEL) {
		mask = PTE_PREFETCH_NUM * sizeof(pt_element_t) - 1;
		base_gpa = pte_gpa & ~mask;
		index = (pte_gpa - base_gpa) / sizeof(pt_element_t);

		r = kvm_vcpu_read_guest_atomic(vcpu, base_gpa,
				gw->prefetch_ptes, sizeof(gw->prefetch_ptes));
		curr_pte = gw->prefetch_ptes[index];
	} else
		r = kvm_vcpu_read_guest_atomic(vcpu, pte_gpa,
				  &curr_pte, sizeof(curr_pte));
	DebugSPF("level #%d gpte gpa 0x%llx pte cur 0x%lx old 0x%lx\n",
		level, pte_gpa, curr_pte, gw->ptes[level - 1]);

	return r || curr_pte != gw->ptes[level - 1];
}

static void FNAME(pte_prefetch)(struct kvm_vcpu *vcpu, guest_walker_t *gw,
				pgprot_t *sptep)
{
	struct kvm_mmu_page *sp;
	pt_element_t *gptep = gw->prefetch_ptes;
	pgprot_t *spte;
	int i;

	sp = page_header(__pa(sptep));

	if (sp->role.level > PT_PAGE_TABLE_LEVEL)
		return;

	if (sp->role.direct)
		return __direct_pte_prefetch(vcpu, sp, sptep);

	i = (sptep - sp->spt) & ~(PTE_PREFETCH_NUM - 1);
	spte = sp->spt + i;

	for (i = 0; i < PTE_PREFETCH_NUM; i++, spte++) {
		if (spte == sptep)
			continue;

		if (is_shadow_present_pte(vcpu->kvm, *spte))
			continue;

		if (!FNAME(prefetch_gpte)(vcpu, sp, spte, gptep[i], true))
			break;
	}
}

/*
 * Walk a shadow PT levels up to the all present levels in the paging hierarchy.
 */
static int e2k_walk_shadow_pts(struct kvm_vcpu *vcpu, gva_t addr,
				kvm_shadow_trans_t *st, hpa_t spt_root)
{
	kvm_shadow_walk_iterator_t it;
	int top_level;
	top_level = vcpu->arch.mmu.root_level;

	KVM_BUG_ON(!VALID_PAGE(kvm_get_space_addr_spt_root(vcpu, addr)));

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
			continue;
		} else if (is_shadow_valid_pte(vcpu->kvm, *it.sptep)) {
			st->last_level = it.level;
			break;
		}
		break;
	}
	return it.level;
}

/*
 * Fetch a shadow PT levels up to the specified level in the paging hierarchy.
 */
static int FNAME(fetch_shadow_pts)(struct kvm_vcpu *vcpu, gva_t addr,
			kvm_shadow_walk_iterator_t *it,
			gmm_struct_t *gmm, hpa_t spt_root,
			int down_to_level, guest_walker_t *gw)
{
	struct kvm_mmu_page *sp = NULL;
	int top_level;

	top_level = vcpu->arch.mmu.root_level;
	if (top_level == PT32E_ROOT_LEVEL)
		top_level = PT32_ROOT_LEVEL;
	/*
	 * Verify that the top-level gpte is still there.  Since the page
	 * is a root page, it is either write protected (and cannot be
	 * changed from now on) or it is invalid (in which case, we don't
	 * really care if it changes underneath us after this point).
	 */
	if (FNAME(gpte_changed)(vcpu, gw, top_level))
		goto out_gpte_changed;

	if (!VALID_PAGE(kvm_get_space_addr_spt_root(vcpu, addr)))
		goto out_gpte_changed;

	DebugSPF("started for guest addr 0x%lx gfn 0x%llx down to level %d\n",
		addr, gw->gfn, down_to_level);

	for ((!IS_E2K_INVALID_PAGE(spt_root)) ?
			shadow_pt_walk_init(it, vcpu, spt_root, addr)
			:
			shadow_walk_init(it, vcpu, addr);
		shadow_walk_okay(it) && it->level > down_to_level;
			shadow_walk_next(it)) {
		gfn_t table_gfn;

		DebugSPF("shadow PT level #%d addr 0x%llx index 0x%x "
			"sptep %px\n",
			it->level, it->shadow_addr, it->index, it->sptep);
		clear_sp_write_flooding_count(it->sptep);
		drop_large_spte(vcpu, it->sptep);

		sp = NULL;
		if (!is_shadow_present_pte(vcpu->kvm, *it->sptep)) {
			table_gfn = gw->table_gfn[it->level - 2];
			sp = kvm_mmu_get_page(vcpu, table_gfn, addr,
				it->level - 1, false, gw->pt_access,
				is_shadow_valid_pte(vcpu->kvm, *it->sptep));
			DebugSPF("allocated shadow page at %px, "
				"guest table gfn 0x%llx\n",
				sp, table_gfn);
		}

		/*
		 * Verify that the gpte in the page we've just write
		 * protected is still there.
		 */
		if (FNAME(gpte_changed)(vcpu, gw, it->level - 1))
			goto out_gpte_changed;

		if (sp) {
			link_shadow_page(vcpu, gmm, it->sptep, sp);
			DebugSPF("level #%d: linked shadow pte %px == 0x%lx\n",
				it->level, it->sptep, pgprot_val(*it->sptep));
		}
	}
	return 0;

out_gpte_changed:
	return 1;
}

/*
 * Fetch a shadow pte for a specific level in the paging hierarchy.
 * If the guest tries to write a write-protected page, we need to
 * emulate this operation, return 1 to indicate this case.
 */
static pf_res_t FNAME(fetch)(struct kvm_vcpu *vcpu, gva_t addr,
			     guest_walker_t *gw, hpa_t spt_root,
			     int error_code, int hlevel,
			     kvm_pfn_t pfn, bool map_writable, bool prefault,
			     bool only_validate, bool not_prefetch)
{
	struct kvm_mmu_page *sp = NULL;
	struct kvm_shadow_walk_iterator it;
	unsigned direct_access;
	bool write_fault = !!(error_code & PFERR_WRITE_MASK);
	gmm_struct_t *gmm;
	pf_res_t emulate;

	DebugTOVM("started for guest addr 0x%lx pfn 0x%llx level %d\n",
		addr, pfn, hlevel);

	gmm = kvm_get_page_fault_gmm(vcpu, error_code);

	if (FNAME(fetch_shadow_pts)(vcpu, addr, &it, gmm, spt_root,
					gw->level, gw))
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
		validate_direct_spte(vcpu, it.sptep, direct_access);

		drop_large_spte(vcpu, it.sptep);

		DebugTOVM("shadow spte %px == 0x%lx\n",
			it.sptep, pgprot_val(*it.sptep));
		if (is_shadow_present_pte(vcpu->kvm, *it.sptep))
			continue;

		direct_gfn = gw->gfn &
			~(KVM_PT_LEVEL_PAGES_PER_HPAGE(it.pt_level) - 1);

		sp = kvm_mmu_get_page(vcpu, direct_gfn, addr, it.level-1,
				true, direct_access,
				is_shadow_valid_pte(vcpu->kvm, *it.sptep));
		link_shadow_page(vcpu, gmm, it.sptep, sp);
		DebugTOVM("allocated shadow page at %px for direct "
			"gfn 0x%llx, direct access %s\n",
			sp, direct_gfn, (direct_access) ? "true" : "false");
		DebugTOVM("level #%d: linked shadow pte %px == 0x%lx\n",
			it.level, it.sptep, pgprot_val(*it.sptep));
	}

	clear_sp_write_flooding_count(it.sptep);
	emulate = mmu_set_spte(vcpu, it.sptep, gw->pte_access, write_fault,
			       it.level, gw->gfn, pfn, prefault, map_writable,
			       only_validate, gw->pte_cui);
	if (!not_prefetch)
		FNAME(pte_prefetch)(vcpu, gw, it.sptep);
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
static bool
FNAME(is_self_change_mapping)(struct kvm_vcpu *vcpu,
			      guest_walker_t *walker, int user_fault,
			      bool *write_fault_to_shadow_pgtable)
{
	int level;
	gfn_t mask = ~(KVM_PT_LEVEL_PAGES_PER_HPAGE(walker->pt_level) - 1);
	bool self_changed = false;

	if (!(walker->pte_access & ACC_WRITE_MASK ||
	      (!is_write_protection(vcpu) && !user_fault)))
		return false;

	for (level = walker->level; level <= walker->max_level; level++) {
		gfn_t gfn = walker->gfn ^ walker->table_gfn[level - 1];

		self_changed |= !(gfn & mask);
		*write_fault_to_shadow_pgtable |= !gfn;
	}

	return self_changed;
}

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
static pf_res_t FNAME(page_fault)(struct kvm_vcpu *vcpu, gva_t addr,
				  u32 error_code, bool prefault,
				  gfn_t *gfnp, kvm_pfn_t *pfnp)
{
	int write_fault = error_code & PFERR_WRITE_MASK;
	int user_fault = error_code & PFERR_USER_MASK;
	guest_walker_t walker;
	pf_res_t r;
	int ret;
	kvm_pfn_t pfn;
	int level = PT_PAGE_TABLE_LEVEL;
	bool force_pt_level = false;
	bool map_writable, is_self_change_mapping;
#ifdef	KVM_ARCH_WANT_MMU_NOTIFIER
	intc_mu_state_t *mu_state = get_intc_mu_state(vcpu);
#endif	/* KVM_ARCH_WANT_MMU_NOTIFIER */

	pgprintk("%s: addr %lx err %x\n", __func__, addr, error_code);

	ret = mmu_topup_memory_caches(vcpu);
	if (ret)
		return PFRES_ERR;

	/*
	 * If PFEC.RSVD is set, this is a shadow page fault.
	 * The bit needs to be cleared before walking guest page tables.
	 */
	error_code &= ~PFERR_RSVD_MASK;

	/*
	 * Look up the guest pte for the faulting address.
	 */
	ret = FNAME(walk_addr)(&walker, vcpu, addr, error_code);

	/*
	 * The page is not mapped by the guest.  Let the guest handle it.
	 */
	if (!ret) {
		pgprintk("%s: guest page fault\n", __func__);
		if (!prefault)
			inject_page_fault(vcpu, &walker.fault);

		return PFRES_INJECTED;
	}

	if (page_fault_handle_page_track(vcpu, error_code, walker.gfn)) {
		shadow_page_table_clear_flood(vcpu, addr);
		DebugSPF("page fault can not be fixed by handler: guest is "
			"writing the page which is write tracked\n");
		if (pfnp == NULL)
			return PFRES_WRITE_TRACK;
		is_self_change_mapping = true;
	} else {
		is_self_change_mapping = false;
	}

	vcpu->arch.write_fault_to_shadow_pgtable = is_self_change_mapping;

	is_self_change_mapping |= FNAME(is_self_change_mapping)(vcpu,
	      &walker, user_fault, &vcpu->arch.write_fault_to_shadow_pgtable);
	DebugSPF("is_self_change_mapping %s\n",
		(is_self_change_mapping) ? "true" : "false");

	if (walker.level >= PT_DIRECTORY_LEVEL && !is_self_change_mapping) {
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
			 &map_writable))
		return PFRES_NO_ERR;
	DebugSPF("try_async_pf returned pfn 0x%llx, writable %d\n",
		pfn, map_writable);

	if (handle_abnormal_pfn(vcpu, addr, walker.gfn, pfn,
					walker.pte_access, &r)) {
		if (pfnp != NULL)
			*pfnp = pfn;
		DebugSPF("returns %d and abnormal pfn 0x%llx\n",
			r, pfn);
		return r;
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
	if (!mu_state->ignore_notifier && r != PFRES_TRY_MMIO &&
			mmu_notifier_retry(vcpu->kvm, mu_state->notifier_seq))
		goto out_unlock;
#endif	/* KVM_ARCH_WANT_MMU_NOTIFIER */

	kvm_mmu_audit(vcpu, AUDIT_PRE_PAGE_FAULT);
	make_mmu_pages_available(vcpu);
	if (!force_pt_level)
		transparent_hugepage_adjust(vcpu, &walker.gfn, &pfn, &level);
	r = FNAME(fetch)(vcpu, addr, &walker, E2K_INVALID_PAGE, error_code,
			 level, pfn, map_writable, prefault, false, false);
	++vcpu->stat.pf_fixed;
	kvm_mmu_audit(vcpu, AUDIT_POST_PAGE_FAULT);
	spin_unlock(&vcpu->kvm->mmu_lock);

	if (gfnp != NULL)
		*gfnp = walker.gfn;
	if (pfnp != NULL)
		*pfnp = pfn;
	DebugSPF("returns %d, pfn 0x%llx\n", r, pfn);
	return r;

#ifdef	KVM_ARCH_WANT_MMU_NOTIFIER
out_unlock:
	spin_unlock(&vcpu->kvm->mmu_lock);
	kvm_release_pfn_clean(pfn);
	KVM_BUG_ON(!mu_state->may_be_retried);
	return PFRES_RETRY;
#endif	/* KVM_ARCH_WANT_MMU_NOTIFIER */
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

static gpa_t FNAME(get_level1_sp_gpa)(struct kvm_mmu_page *sp)
{
	int offset = 0;

	WARN_ON(sp->role.level != PT_PAGE_TABLE_LEVEL);

	if (PTTYPE == 32)
		offset = sp->role.quadrant << PT64_LEVEL_BITS;

	return gfn_to_gpa(sp->gfn) + offset * sizeof(pt_element_t);
}

static void FNAME(sync_gva)(struct kvm_vcpu *vcpu, gva_t gva)
{
	struct kvm_shadow_walk_iterator iterator;
	struct kvm_mmu_page *sp;
	int level;
	pgprot_t *sptep;

	vcpu_clear_mmio_info(vcpu, gva);

	/*
	 * No need to check return value here, rmap_can_add() can
	 * help us to skip pte prefetch later.
	 */
	mmu_topup_memory_caches(vcpu);

	if (!VALID_PAGE(kvm_get_space_addr_spt_root(vcpu, gva))) {
		WARN_ON(1);
		return;
	}

retry_sync_gva:

	spin_lock(&vcpu->kvm->mmu_lock);
	for_each_shadow_entry(vcpu, gva, iterator) {
		level = iterator.level;
		sptep = iterator.sptep;

		sp = page_header(__pa(sptep));
		if (is_last_spte(*sptep, level)) {
			pt_element_t gpte;
			gpa_t pte_gpa;

			if (!sp->unsync)
				break;

			pte_gpa = FNAME(get_level1_sp_gpa)(sp);
			pte_gpa += (sptep - sp->spt) * sizeof(pt_element_t);

			if (mmu_page_zap_pte(vcpu->kvm, sp, sptep))
				kvm_flush_remote_tlbs(vcpu->kvm);

			if (!rmap_can_add(vcpu))
				break;

			if (kvm_vcpu_read_guest_atomic(vcpu, pte_gpa, &gpte,
						sizeof(pt_element_t))) {

				spin_unlock(&vcpu->kvm->mmu_lock);

				if (kvm_vcpu_read_guest(vcpu, pte_gpa, &gpte,
							sizeof(pt_element_t)))
					return;
				else
					goto retry_sync_gva;
			}

			FNAME(update_pte)(vcpu, sp, sptep, &gpte);
		}

		if (!is_shadow_present_pte(vcpu->kvm, *sptep) ||
						!sp->unsync_children)
			break;
	}
	spin_unlock(&vcpu->kvm->mmu_lock);
}

static bool FNAME(sync_gva_pte_range)(struct kvm_vcpu *vcpu,
				struct kvm_shadow_walk_iterator *spt_walker,
				gva_t gva_start, gva_t gva_end,
				gva_t *retry_gva)
{
	struct kvm_mmu_page *sp;
	int level;
	const pt_level_t *spt_pt_level;
	unsigned int pte_index;
	pgprot_t *sptep, *spt_table_hva;
	gva_t gva, gva_next;

	KVM_BUG_ON(gva_start > gva_end);

	/* Get descriptors of curr level of shadow page table */
	level = spt_walker->level;
	spt_pt_level = spt_walker->pt_level;
	KVM_BUG_ON(level < PT_PAGE_TABLE_LEVEL);

	/* Get index in curr level of shadow page table */
	pte_index = get_pt_level_addr_index(gva_start, spt_pt_level);

	/* hva of shadow pt entry in curr level */
	spt_table_hva = (pgprot_t *) __va(spt_walker->shadow_addr);
	sptep = spt_table_hva + pte_index;

	sp = page_header(__pa(sptep));

	gva = gva_start;
	do {
		gva_next = pt_level_next_gva(gva, gva_end, spt_pt_level);

		if (is_last_spte(*sptep, level)) {
			/*
			 * This is last level pte (1-st level or large page)
			 */
			pt_element_t gpte;
			gpa_t pte_gpa;

			vcpu_clear_mmio_info(vcpu, gva);

			if (!sp->unsync)
				goto next_pte;

			pte_gpa = FNAME(get_level1_sp_gpa)(sp);
			pte_gpa += (sptep - sp->spt) * sizeof(pt_element_t);

			mmu_page_zap_pte(vcpu->kvm, sp, sptep);

			/* Read pte from guest table */
			if (kvm_vcpu_read_guest_atomic(vcpu, pte_gpa, &gpte,
						sizeof(pt_element_t))) {

				spin_unlock(&vcpu->kvm->mmu_lock);

				if (kvm_vcpu_read_guest(vcpu, pte_gpa, &gpte,
							sizeof(pt_element_t)))
					*retry_gva = gva_next;
				else
					*retry_gva = gva;

				return false;
			}

			FNAME(update_pte)(vcpu, sp, sptep, &gpte);
		} else {
			bool ret;

			if (!is_shadow_present_pte(vcpu->kvm, *sptep) ||
					!sp->unsync_children)
				goto next_pte;

			/* hpa of lower level of shadow page table */
			spt_walker->shadow_addr =
				kvm_pte_pfn_to_phys_addr(*sptep,
						spt_walker->pt_struct);

			/* Move iterators to lower level of page tables */
			spt_walker->level--;
			spt_walker->pt_level--;

			ret = FNAME(sync_gva_pte_range)(vcpu, spt_walker,
						gva, gva_next, retry_gva);

			/*
			 * Move iterators back to upper level
			 * of page tables
			 */
			spt_walker->level++;
			spt_walker->pt_level++;

			if (!ret)
				return ret;
		}

next_pte:
		/* Go to next pt entry on curr level */
		sptep++;
		gva = gva_next;
	} while (gva != gva_end);

	return true;
}

static void FNAME(sync_gva_range)(struct kvm_vcpu *vcpu,
				gva_t start, gva_t end,
				bool flush_tlb)
{
	struct kvm_shadow_walk_iterator spt_walker;
	hpa_t spt_root;
	e2k_addr_t vptb_start, vptb_size, vptb_mask, vptb_end;
	int top_level;
	const pt_struct_t *vcpu_pt = kvm_get_vcpu_pt_struct(vcpu);
	gva_t retry_gva;
	bool sync_range1, sync_range2;

	/* Get hpa of shadow page table root */
	spt_root = kvm_get_space_addr_spt_root(vcpu, start);
	if (!VALID_PAGE(spt_root)) {
		WARN_ON(1);
		return;
	}

	/* Get top level number for spt */
	top_level = vcpu->arch.mmu.root_level;
	if (top_level == PT32E_ROOT_LEVEL)
		top_level = PT32_ROOT_LEVEL;

	/* Get gva range of page table self-mapping */
	if (is_sep_virt_spaces(vcpu))
		vptb_start = vcpu->arch.mmu.get_vcpu_sh_u_vptb(vcpu);
	else
		vptb_start = vcpu->arch.mmu.get_vcpu_sh_u_vptb(vcpu);

	vptb_size = get_pt_level_size(&vcpu_pt->levels[top_level]);
	vptb_mask = get_pt_level_mask(&vcpu_pt->levels[top_level]);
	vptb_start &= vptb_mask;
	vptb_end = vptb_start + vptb_size - 1;

	/*
	 * Use simplified function sync_gva to flush single address
	 * which does not hit into vptb range
	 */
	if ((start == end) && (start < vptb_start || start >= vptb_end)) {
		FNAME(sync_gva)(vcpu, start);
		goto flush_cpu_tlb;
	}

retry_sync_gva_range:

	sync_range1 = true;
	sync_range2 = true;

	spin_lock(&vcpu->kvm->mmu_lock);
	if (start < vptb_start && end < vptb_start ||
			start >= vptb_end && end >= vptb_end) {
		/* flushed gva range doesn't overlap vptb range */
		shadow_pt_walk_init(&spt_walker, vcpu, spt_root, start);
		sync_range1 = FNAME(sync_gva_pte_range)(vcpu, &spt_walker,
						start, end, &retry_gva);
	} else if (start < vptb_start && end >= vptb_start &&
				end < vptb_end) {
		/* end part of flushed gva range overlaps vptb range */
		shadow_pt_walk_init(&spt_walker, vcpu, spt_root, start);
		sync_range1 = FNAME(sync_gva_pte_range)(vcpu, &spt_walker,
					start, vptb_start, &retry_gva);
	} else if (end > vptb_end && start >= vptb_start &&
				start < vptb_end) {
		/* start part of flushed gva range overlaps vptb range */
		shadow_pt_walk_init(&spt_walker, vcpu, spt_root, vptb_end);
		sync_range1 = FNAME(sync_gva_pte_range)(vcpu, &spt_walker,
						vptb_end, end, &retry_gva);
	} else if (start < vptb_start && end >= vptb_end) {
		/* flushed gva range contains vptb range */
		shadow_pt_walk_init(&spt_walker, vcpu, spt_root, start);
		sync_range1 = FNAME(sync_gva_pte_range)(vcpu, &spt_walker,
					start, vptb_start, &retry_gva);

		if (sync_range1) {
			shadow_pt_walk_init(&spt_walker, vcpu, spt_root,
						vptb_end);
			sync_range2 = FNAME(sync_gva_pte_range)(vcpu,
						&spt_walker, vptb_end,
						end, &retry_gva);
		}
	}
	/* Do nothing if vptb range contains flushed gva range */

	if (!sync_range1 || !sync_range2) {
		start = retry_gva;
		goto retry_sync_gva_range;
	}

	spin_unlock(&vcpu->kvm->mmu_lock);

	/*
	 * TODO: TLB flush here may be partial similarly to __flush_tlb_*
	 * in host kernel.
	 */
flush_cpu_tlb:
	if (flush_tlb) {
		kvm_vcpu_flush_tlb(vcpu);
		kvm_flush_remote_tlbs(vcpu->kvm);
	}
}

gpa_t FNAME(gva_to_gpa)(struct kvm_vcpu *vcpu, gva_t vaddr, u32 access,
			kvm_arch_exception_t *exception)
{
	guest_walker_t walker;
	gpa_t gpa = UNMAPPED_GVA;
	int r;

	r = FNAME(walk_addr)(&walker, vcpu, vaddr, access);

	if (r) {
		gpa = gfn_to_gpa(walker.gfn);
		gpa |= vaddr & ~PAGE_MASK;
	} else if (exception) {
		*exception = walker.fault;
	}
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
static int FNAME(sync_page)(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp)
{
	int i, nr_present = 0;
	bool host_writable;
	gpa_t first_pte_gpa;
	u64 pte_cui;

	/* direct kvm_mmu_page can not be unsync. */
	BUG_ON(sp->role.direct);

	first_pte_gpa = FNAME(get_level1_sp_gpa)(sp);

	DebugSPF("sp %px level #%d first_pte_gpa 0x%llx\n",
		sp, sp->role.level, first_pte_gpa);
	for (i = 0; i < PT64_ENT_PER_PAGE; i++) {
		unsigned pte_access;
		pt_element_t gpte;
		gpa_t pte_gpa;
		gfn_t gfn;

		if (!pgprot_val(sp->spt[i]))
			continue;

		pte_gpa = first_pte_gpa + i * sizeof(pt_element_t);

		if (kvm_vcpu_read_guest_atomic(vcpu, pte_gpa, &gpte,
					       sizeof(pt_element_t)))
			return 0;

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
		if (FNAME(is_only_valid_gpte(vcpu, gpte))) {
			set_spte(vcpu, &sp->spt[i], 0,
				PT_PAGE_TABLE_LEVEL, 0, 0,
				false, false, false,
				true	/* only validate */, 0);
			nr_present++;
			continue;
		}

		gfn = gpte_to_gfn_ind(vcpu, 0, gpte,
					kvm_get_vcpu_pt_struct(vcpu));
		pte_cui = FNAME(gpte_cui)(gpte);
#if PTTYPE == PTTYPE_E2K
		/* protections PT directories entries and page entries are */
		/* independent for e2k arch, see full comment above */
		pte_access = FNAME(gpte_access)(vcpu, gpte);
#else	/* x86 PTs */
		pte_access = sp->role.access;
		pte_access &= FNAME(gpte_access)(vcpu, gpte);
#endif	/* PTTYPE_E2K */
		FNAME(protect_clean_gpte)(&pte_access, gpte);
		DebugSPF("pte_gpa 0x%llx == 0x%lx, gfn 0x%llx\n",
			pte_gpa, gpte, gfn);

		if (sync_mmio_spte(vcpu, &sp->spt[i], gfn, pte_access,
		      &nr_present))
			continue;

		if (gfn != sp->gfns[i]) {
			drop_spte(vcpu->kvm, &sp->spt[i]);
			/*
			 * The same as above where we are doing
			 * prefetch_invalid_gpte().
			 */
			smp_wmb();
			vcpu->kvm->tlbs_dirty++;
			continue;
		}

		nr_present++;

		host_writable = is_spte_host_writable_mask(vcpu->kvm,
								sp->spt[i]);

		set_spte(vcpu, &sp->spt[i], pte_access,
			 PT_PAGE_TABLE_LEVEL, gfn,
			 spte_to_pfn(vcpu->kvm, sp->spt[i]), true, false,
			 host_writable, false, pte_cui);
		DebugSPF("shadow spte %px == 0x%lx, gfn 0x%llx, pfn 0x%llx\n",
			&sp->spt[i], pgprot_val(sp->spt[i]), gfn,
			spte_to_pfn(vcpu->kvm, sp->spt[i]));
	}

	return nr_present;
}

/*
 * Initialize guest page table iterator
 */
static void guest_pt_walk_init(guest_walker_t *guest_walker,
				struct kvm_vcpu *vcpu,
				pt_element_t guest_root)
{
	guest_walker->pt_struct = kvm_get_vcpu_pt_struct(vcpu);
	guest_walker->level = vcpu->arch.mmu.root_level;
	guest_walker->pt_level =
		&guest_walker->pt_struct->levels[guest_walker->level];
	guest_walker->gfn = gpte_to_gfn_ind(vcpu, 0, guest_root,
				guest_walker->pt_struct);
	guest_walker->table_gfn[guest_walker->level] = guest_walker->gfn;
	guest_walker->pt_access = ACC_ALL;
	guest_walker->pte_access = ACC_ALL;
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
					int is_direct)
{
	struct kvm_mmu_page *sp = NULL;

	clear_sp_write_flooding_count(spt_pte_hva);
	/* If this spte is the large page, then unmap it */
	drop_large_spte(vcpu, spt_pte_hva);

	/* If spte is not peresent, allocate it */
	if (!is_shadow_present_pte(vcpu->kvm, *spt_pte_hva)) {
		sp = kvm_mmu_get_page(vcpu, table_gfn, gva,
				level, is_direct, pt_access,
				is_shadow_valid_pte(vcpu->kvm, *spt_pte_hva));
		if (!sp) {
			DebugSYNC("Allocation of shadow page for spte 0x%lx"
				" failed\n", spt_pte_hva);
			return PFRES_ERR;
		}

		link_shadow_page(vcpu, gmm, spt_pte_hva, sp);
		DebugSYNC("allocated new shadow page with hpa 0x%llx, guest"
			" table gfn 0x%llx, on level #%d, linked to spte"
			" with hpa 0x%lx, hva 0x%lx on level #%d\n",
			pgprot_val(*spt_pte_hva) & _PAGE_PFN_V2, table_gfn,
			level, __pa(spt_pte_hva), spt_pte_hva, level + 1);
	} else {
		DebugSYNC("present shadow page with hpa 0x%llx, guest table"
			" gfn 0x%llx, on level #%d, linked to spte with"
			" hpa 0x%lx, hva 0x%lx on level #%d\n",
			pgprot_val(*spt_pte_hva) & _PAGE_PFN_V2, table_gfn,
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
			KVM_BUG_ON(true);
		}
	}
}

/*
 * Create mapping for guest huge page in shadow page table.
 * Split huge page into smaller shadow pages if needed.
 */
static pf_res_t map_huge_page_to_spte(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
			guest_walker_t *guest_walker, int level,
			int split_to_level, pgprot_t *root_pte_hva)
{
	pf_res_t ret;
	pgprot_t *pte_hva;
	gfn_t table_gfn;
	kvm_memory_slot_t *mem_slot;
	kvm_pfn_t pfn = 0;
	bool gfn_only_valid, is_guest_pt_area, force_pt_level = false;

	const pt_level_t *pt_level = &kvm_get_host_pt_struct(vcpu->kvm)->levels[
								level];
	const pt_struct_t *pt_struct = kvm_get_host_pt_struct(vcpu->kvm);

	/* Get number of sptes, which one spt level contains */
	int sptes_num = PAGE_SIZE / sizeof(pt_element_t);
	int ind, split_page_size;

	KVM_BUG_ON(split_to_level > level);

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
	is_guest_pt_area = FNAME(is_self_change_mapping)(vcpu,
			guest_walker, false,
			&vcpu->arch.write_fault_to_shadow_pgtable);

	/*
	 * If gfn belongs to the area of guest page table, then
	 * map it by pages on level 1 in shadow page table
	 */
	split_to_level = PT_PAGE_TABLE_LEVEL;
	if (is_guest_pt_area) {
		force_pt_level = true;
		DebugSYNCV("gva 0x%lx (gfn = 0x%llx) belongs to guest pt "
			"area, split guest page on level #%d into pages "
			"on level #%d\n",
			guest_walker->gva, guest_walker->gfn,
			guest_walker->level, split_to_level);
	} else {
		/*
		 * Get max mapping level of this gfn in host
		 * page table (hva -> pfn)
		 */
		mem_slot = kvm_vcpu_gfn_to_memslot(vcpu, guest_walker->gfn);
		force_pt_level = !memslot_valid_for_gpte(mem_slot, true);
		DebugSYNCV("can split guest page on level #%d into pages on"
			" level #%d , force = %s\n", level,
			split_to_level, force_pt_level ? "yes" : "no");
	}


	if (likely(!force_pt_level) && (level > PT_PAGE_TABLE_LEVEL)) {
		transparent_hugepage_adjust(vcpu, &guest_walker->gfn,
					&pfn, &split_to_level);
	}

	DebugSYNCV("with thp map guest page on level #%d by pages on"
			" level #%d\n", level, split_to_level);

	/*
	 * If we have achived split_to_level, then simply assign pfn to spte.
	 * Otherwise, allocate lower level of spt and map all sptes,
	 * which it contains.
	 */
map:
	split_page_size = pt_struct->levels[split_to_level].page_size;
	if (level == split_to_level) {
		gfn_atomic_pf(vcpu, guest_walker->gfn, guest_walker->gva,
				guest_walker->pte_access, &pfn,
				&gfn_only_valid);
		mmu_set_spte(vcpu, root_pte_hva, guest_walker->pte_access,
				false, level, guest_walker->gfn, pfn, false,
				true, gfn_only_valid, guest_walker->pte_cui);
		guest_walker->gfn += (split_page_size >> PAGE_SHIFT);
		guest_walker->gva += split_page_size;
		return PFRES_NO_ERR;
	} else {
		table_gfn = guest_walker->gfn &
			~(KVM_PT_LEVEL_PAGES_PER_HPAGE(pt_level) - 1);
		ret = allocate_shadow_level(vcpu, gmm, table_gfn,
					guest_walker->gva, level - 1,
					guest_walker->pte_access,
					root_pte_hva, true);
		if (ret)
			return ret;
	}

	/* Get host address of allocated spte */
	pte_hva = __va(kvm_pte_pfn_to_phys_addr(*root_pte_hva, pt_struct));

	DebugSYNC("map guest page with gfn 0x%llx on level #%d to spte with"
		" hpa 0x%lx by pages of level #%d\n",
		guest_walker->gfn, level, __pa(root_pte_hva), split_to_level);

	/*
	 * Walk through all sptes, contained in this spte and
	 * map them.
	 */
	ind = 0;
	do {
		ret = map_huge_page_to_spte(vcpu, gmm, guest_walker, level - 1,
						split_to_level, pte_hva);
		if (ret)
			return ret;

		pte_hva++;
		ind++;
	} while (ind < sptes_num);

	return PFRES_NO_ERR;
}

/*
 * Create mapping for gva range [start_gva, end_gva] in shadow page table
 * in accordance with guest page table maping.
 */
static pf_res_t FNAME(sync_shadow_pte_range)(struct kvm_vcpu *vcpu,
				gmm_struct_t *gmm, struct kvm_mmu *mmu,
				gva_t start_gva, gva_t end_gva,
				guest_walker_t *guest_walker,
				kvm_shadow_walk_iterator_t *spt_walker,
				gva_t *retry_gva)
{
	pf_res_t ret;
	kvm_pfn_t pfn;
	gva_t next_gva, gva;
	gpa_t guest_table_gpa, guest_pte_gpa;
	pt_element_t *guest_table_hva, *guest_pte_hva;
	hpa_t spt_table_hpa, spt_pte_hpa;
	pgprot_t *spt_table_hva, *spt_pte_hva;
	pt_element_t guest_pte;
	unsigned pte_index, pte_access;
	int level;
	const pt_level_t *guest_pt_level, *spt_pt_level;
	bool gfn_only_valid, is_huge_page, is_lowest_level;

	DebugSYNC("called for gva range [0x%lx - 0x%lx]\n", start_gva,
			end_gva);

	KVM_BUG_ON(start_gva >= end_gva);

	/* Get descriptors of curr level of guest and shadow page tables */
	level = guest_walker->level;
	guest_pt_level = guest_walker->pt_level;
	spt_pt_level = spt_walker->pt_level;
	KVM_BUG_ON(level < PT_PAGE_TABLE_LEVEL);


	/* Get index in curr level of guest and shadow page tables */
	pte_index = get_pt_level_addr_index(start_gva, guest_pt_level);

	/* gpa of curr level of guest page table */
	guest_table_gpa = gfn_to_gpa(guest_walker->gfn);
	/* hva of curr level of guest page table */
	guest_table_hva = (pt_element_t *) kvm_vcpu_gfn_to_hva_prot(vcpu,
				gpa_to_gfn(guest_table_gpa),
				&guest_walker->pte_writable[level - 1]);
	/* gpa of guest pt entry in curr level */
	guest_pte_gpa = guest_table_gpa + pte_index * sizeof(pt_element_t);
	/* hva of guest pt entry in curr level */
	guest_pte_hva = guest_table_hva + pte_index;
	/* Save table gfn in guest iterator */
	guest_walker->table_gfn[level - 1] = gpa_to_gfn(guest_table_gpa);

	DebugSYNC("guest level gpa 0x%llx, hva 0x%lx, level #%d, idx %d\n",
		guest_table_gpa, guest_table_hva, level, pte_index);

	if (unlikely(kvm_is_error_hva((unsigned long) guest_table_hva)))
		return PFRES_ERR;

	/* hpa of curr level of shadow page table */
	spt_table_hpa = spt_walker->shadow_addr;
	/* hva of curr level of shadow page table */
	spt_table_hva = (pgprot_t *) __va(spt_table_hpa);
	/* hpa of shadow pt entry in curr level */
	spt_pte_hpa = spt_table_hpa + pte_index * sizeof(pt_element_t);
	/* hva of shadow pt entry in curr level */
	spt_pte_hva = spt_table_hva + pte_index;
	spt_walker->index = pte_index;
	spt_walker->sptep = spt_pte_hva;

	DebugSYNC("shadow level hpa 0x%llx, hva 0x%lx, level #%d, idx %d\n",
		spt_table_hpa, spt_table_hva, level, pte_index);


	gva = start_gva;
	do {
#if PTTYPE == PTTYPE_E2K
		/*
		 * Protections PT directories entries and page entries are
		 * independent for e2k arch.
		 */
		pte_access = ACC_ALL;
#else	/* x86 PTs */
		pte_access = guest_walker->pte_access;
#endif	/* PTTYPE_E2K */

		next_gva = pt_level_next_gva(gva, end_gva, guest_pt_level);

		/*
		 * Read current pt entry from guest page table (user memory).
		 * We need to disable page fault, because we are in spinlock
		 * crictical section.
		 * If user page is mmaped and correct, then no page fault
		 * occures, read is successful, zero is returned.
		 * If user page was swapped out by host, then __copy_from_user
		 * returns non zero. Need to release spinlock, enable page
		 * fault and retry. If retry is successful, remember current
		 * addr and return PFRES_RETRY to run sync_shadow_pte_range
		 * again for address range [*retry_addr, gva_end].
		 * If retry with enabled pagefault failed, then run
		 * sync_shadow_pte_range again for next pt entry on this
		 * level.
		 */
		pagefault_disable();
		if (unlikely(__copy_from_user(&guest_pte,
				guest_pte_hva, sizeof(guest_pte)))) {
			DebugSYNC("gpte with gva 0x%lx gpa 0x%llx"
				" hva 0x%lx failed to read, retry with"
				" enabled pagefault... ", gva, guest_pte_gpa,
				guest_pte_hva);

			spin_unlock(&vcpu->kvm->mmu_lock);
			pagefault_enable();
			if (unlikely(__copy_from_user(&guest_pte,
				guest_pte_hva, sizeof(guest_pte)))) {
				DebugSYNC("failed retry, will run again with"
					" start addr 0x%lx\n", next_gva);
				*retry_gva = next_gva;
			} else {
				DebugSYNC("succed retry, will run again with"
					" start_addr 0x%lx\n", gva);
				*retry_gva = gva;
			}
			return PFRES_RETRY;
		}
		pagefault_enable();

		/* Fullfill guest page table iterator for curr level */
		guest_walker->pte_gpa[level - 1] = guest_pte_gpa;
		guest_walker->ptep_user[level - 1] = guest_pte_hva;
		guest_walker->ptes[level - 1] = guest_pte;
		guest_walker->gfn = gpte_to_gfn_ind(vcpu, 0, guest_pte,
					guest_walker->pt_struct);
		guest_walker->gva = gva;

		/*
		 * If gpte is marked as only valid, then
		 * it will be further allocated (during pagefault)
		 * Mark spte as only valid too.
		 */
		if (FNAME(is_only_valid_gpte)(vcpu, guest_pte)) {
			DebugSYNCV("gpte with gpa 0x%llx hva 0x%lx,"
				" gva 0x%lx, level #%d is only valid, mark"
				" it as only valid in shadow page table and"
				" go to next pte on this level\n",
				guest_pte_gpa, guest_pte_hva, gva, level);
			mmu_set_spte(vcpu, spt_pte_hva, pte_access, false,
					level, guest_walker->gfn, 0, false,
					true, true, 0);
			goto next_pte;
		}

		/* If guest pt entry is not present, then skip it */
		if (unlikely(!FNAME(is_present_gpte)(guest_pte))) {
			DebugSYNCV("gpte with gpa 0x%llx hva 0x%lx,"
				" gva 0x%lx, level #%d is not present, go"
				" to next gpte on this level\n",
				guest_pte_gpa, guest_pte_hva, gva, level);
			goto next_pte;
		}

		if (unlikely(is_rsvd_bits_set(mmu, guest_pte, level))) {
			DebugSYNCV("guest pt entry gpa 0x%llx hva 0x%lx,"
				" gva 0x%lx, level #%d is reserved, go to"
				" next pte on this level\n",
				guest_pte_gpa, guest_pte_hva, gva, level);
			goto next_pte;
		}

		/* Get access rights for guest pt entry */
		pte_access &= FNAME(gpte_access)(vcpu, guest_pte);
		FNAME(protect_clean_gpte)(&pte_access, guest_pte);
		guest_walker->pt_access = guest_walker->pte_access;
		guest_walker->pte_access = pte_access;
		guest_walker->pte_cui = FNAME(gpte_cui)(guest_pte);

		/* Check if current pt entry is huge page */
		is_huge_page = (guest_pte & PT_PAGE_SIZE_MASK) &&
				(level >= PT_DIRECTORY_LEVEL);

		/* Check if the lowest possible level achieved */
		is_lowest_level = (level == PT_PAGE_TABLE_LEVEL);

		DebugSYNC("correct gpte with gpa 0x%llx hva 0x%lx,"
			" gpte val 0x%lx, gva 0x%lx, level #%d %s\n",
			guest_pte_gpa, guest_pte_hva, guest_pte, gva, level,
			is_huge_page ? "huge page" : "");


		if (is_lowest_level) {
			gfn_only_valid = false;
			gfn_atomic_pf(vcpu, guest_walker->gfn, gva,
					pte_access, &pfn, &gfn_only_valid);
			/* Set pfn in spte */
			mmu_set_spte(vcpu, spt_pte_hva, pte_access, false,
				level, guest_walker->gfn, pfn, false,
				true, gfn_only_valid, guest_walker->pte_cui);
		} else if (is_huge_page) {
			/* Map huge page to spte */
			ret = map_huge_page_to_spte(vcpu, gmm, guest_walker,
						level, level, spt_pte_hva);

			if (ret)
				return ret;

			if (mmu_need_topup_memory_caches(vcpu)) {
				DebugSYNCV("need fill mmu caches, run again"
					" with gva 0x%lx\n", gva);
				spin_unlock(&vcpu->kvm->mmu_lock);
				*retry_gva = gva;
				return PFRES_RETRY;
			}
		} else {
			/* Allocate lower level in shadow page table */
			ret = allocate_shadow_level(vcpu, gmm,
					guest_walker->gfn,
					gva, level - 1, pte_access,
					(pgprot_t *) spt_pte_hva, false);
			if (ret)
				return ret;

			if (mmu_need_topup_memory_caches(vcpu)) {
				DebugSYNCV("need fill mmu caches, run again"
					" with gva 0x%lx\n", gva);
				spin_unlock(&vcpu->kvm->mmu_lock);
				*retry_gva = gva;
				return PFRES_RETRY;
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
			ret = FNAME(sync_shadow_pte_range)(vcpu, gmm, mmu,
					gva, next_gva, guest_walker,
					spt_walker, retry_gva);

			/*
			 * Move iterators back to upper level
			 * of page tables
			 */
			guest_walker->level++;
			guest_walker->pt_level++;
			spt_walker->level++;
			spt_walker->pt_level++;

			if (ret)
				return ret;
		}

next_pte:
		/* Go to next pt entry on curr level */
		guest_pte_gpa += sizeof(pt_element_t);
		guest_pte_hva++;
		spt_pte_hpa += sizeof(pt_element_t);
		spt_pte_hva++;
		gva = next_gva;
	} while (gva != end_gva);

	return PFRES_NO_ERR;
}

static int do_sync_shadow_pt_range(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
			hpa_t spt_root, pt_element_t guest_root,
			gva_t start, gva_t end)
{
	pf_res_t pfres;
	guest_walker_t guest_walker;
	kvm_shadow_walk_iterator_t spt_walker;
#ifdef	KVM_ARCH_WANT_MMU_NOTIFIER
	unsigned long mmu_seq;
#endif	/* KVM_ARCH_WANT_MMU_NOTIFIER */
	gva_t gva_retry, gva_start, gva_end;

	DebugSYNC("started on VCPU #%d : shadow root at 0x%llx, range"
		" from 0x%lx to 0x%lx\n",
		vcpu->vcpu_id, spt_root, start, end);

	gva_retry = start;
	gva_end = end;

retry:
	if (mmu_topup_memory_caches(vcpu))
		return -ENOMEM;
#ifdef KVM_ARCH_WANT_MMU_NOTIFIER
	mmu_seq = vcpu->kvm->mmu_notifier_seq;
	/* FIXME: Do we really need barrier here? */
	smp_rmb();
#endif /* KVM_ARCH_WANT_MMU_NOTIFIER */
	/* Acquire mmu_lock to modify shadow page table */
	spin_lock(&vcpu->kvm->mmu_lock);
#ifdef KVM_ARCH_WANT_MMU_NOTIFIER
	if (mmu_notifier_retry(vcpu->kvm, mmu_seq)) {
		/*
		 * ??? If modification of shadow page table by another
		 * thread is not completed, than release mmu_lock and
		 * retry.
		 */
		DebugSYNC("mmu_notifier_retry...\n");
		spin_unlock(&vcpu->kvm->mmu_lock);
		cond_resched();
		goto retry;
	}
#endif /* KVM_ARCH_WANT_MMU_NOTIFIER */

	/* Start with address, which caused retry */
	gva_start = gva_retry;

	DebugSYNC("sync gva range [0x%lx - 0x%lx]\n", gva_start, gva_end);

	/* Initialize iterator to pass through shadow page table */
	shadow_pt_walk_init(&spt_walker, vcpu, spt_root, gva_start);

	/* Initialize iterator to pass through guest page table */
	guest_pt_walk_init(&guest_walker, vcpu, guest_root);

	/* Sync page tables starting from pgd ranges */
	pfres = FNAME(sync_shadow_pte_range)(vcpu, gmm, &vcpu->arch.mmu,
				gva_start, gva_end, &guest_walker,
				&spt_walker, &gva_retry);
	if (pfres == PFRES_RETRY) {
		cond_resched();
		goto retry;
	} else if (pfres != PFRES_NO_ERR) {
		spin_unlock(&vcpu->kvm->mmu_lock);
		pr_err("%s(): failed, error #%d\n", __func__, pfres);
		return -EFAULT;
	}

	spin_unlock(&vcpu->kvm->mmu_lock);

	DebugSYNC("succed for gva range [0x%lx - 0x%lx]\n", start, end);

	return 0;
}

static int FNAME(sync_shadow_pt_range)(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
			hpa_t spt_root, gva_t start, gva_t end,
			gpa_t guest_pptb, gva_t vptb)
{
	const pt_struct_t *host_pt = kvm_get_host_pt_struct(vcpu->kvm);
	const pt_struct_t *vcpu_pt = kvm_get_vcpu_pt_struct(vcpu);
	pt_element_t guest_root;
	e2k_addr_t guest_root_host_addr;
	e2k_addr_t vptb_start, vptb_mask, vptb_size;
	int top_level;
	bool pte_writable;
	gva_t gva_start, gva_end;
	int ret;

	DebugSYNC("started on VCPU #%d : shadow root at 0x%llx, range "
		"from 0x%lx to 0x%lx, vptb = 0x%lx\n", vcpu->vcpu_id,
		spt_root, start, end, vptb);

	/* Get and check address of guest page table root */
	if (likely(!IS_E2K_INVALID_PAGE(guest_pptb)))
		guest_root = guest_pptb;
	else
		guest_root = kvm_get_space_addr_guest_root(vcpu, start);

	guest_root_host_addr = kvm_vcpu_gfn_to_hva_prot(vcpu,
					guest_root >> PAGE_SHIFT,
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
	if (top_level == PT32E_ROOT_LEVEL)
		top_level = PT32_ROOT_LEVEL;
	KVM_BUG_ON(top_level < PT_DIRECTORY_LEVEL);

	vptb_start = vptb;
	vptb_mask = get_pt_level_mask(&vcpu_pt->levels[top_level]);
	vptb_size = get_pt_level_size(&vcpu_pt->levels[top_level]);
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

	return ret;
}

int FNAME(shadow_pt_protection_fault)(struct kvm_vcpu *vcpu,
			struct gmm_struct *gmm, gpa_t addr, kvm_mmu_page_t *sp)
{
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
	KVM_BUG_ON(level <= PT_PAGE_TABLE_LEVEL);
	gpt = kvm_get_vcpu_pt_struct(vcpu);
	gpt_level = &gpt->levels[level];
	index = (addr & ~PAGE_MASK) / sizeof(pt_element_t);
	start_gva = sp->gva & get_pt_level_mask(gpt_level);
	start_gva = set_pt_level_addr_index(start_gva, index, gpt_level);
	end_gva = start_gva + set_pt_level_addr_index(0, 1, gpt_level);
	DebugPTE("protected PT level #%d gva from 0x%lx to 0x%lx\n",
		level, start_gva, end_gva);

	if (end_gva >= GUEST_TASK_SIZE) {
		/* guest kernel address - update init_gmm */
		gmm = pv_vcpu_get_init_gmm(vcpu);
		KVM_BUG_ON(start_gva < GUEST_TASK_SIZE);
	} else if (gmm == NULL) {
		/* can be only current active gmm */
		gmm = pv_vcpu_get_gmm(vcpu);
	}
	root_hpa = gmm->root_hpa;
	KVM_BUG_ON(!VALID_PAGE(root_hpa));
	guest_root = gmm->u_pptb;
	vptb = pv_vcpu_get_init_gmm(vcpu)->u_vptb;

	r = FNAME(sync_shadow_pt_range)(vcpu, gmm, root_hpa,
			start_gva, end_gva, guest_root, vptb);
	KVM_BUG_ON(r != 0);
	return r;
}

#undef pt_element_t
#undef guest_walker
#undef FNAME
#undef PT_MAX_FULL_LEVELS
#undef gpte_to_gfn_ind
#undef gpte_to_gfn_addr
#undef gpte_to_gfn_level_index
#undef gpte_to_gfn_level_address
#undef CMPXCHG
#undef PT_GUEST_ACCESSED_MASK
#undef PT_GUEST_DIRTY_MASK
