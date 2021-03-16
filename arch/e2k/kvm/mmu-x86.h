#ifndef _E2K_KVM_MMU_X86_H_
#define _E2K_KVM_MMU_X86_H_

#include <linux/kvm_host.h>
#include <asm/kvm/pgtable-x86.h>

#define PT_X86_PRESENT_MASK	_PAGE_P_X86
#define PT_X86_WRITABLE_MASK	_PAGE_W_X86
#define PT_X86_USER_MASK	_PAGE_USER_X86
#define PT_X86_PWT_MASK		_PAGE_PWT_X86
#define PT_X86_PCD_MASK		_PAGE_PCD_X86
#define PT_X86_ACCESSED_MASK	_PAGE_A_X86
#define PT_X86_DIRTY_MASK	_PAGE_D_X86
#define PT_X86_PAGE_SIZE_MASK	_PAGE_PSE_X86
#define PT_X86_PAT_MASK		_PAGE_PAT_X86
#define PT_X86_GLOBAL_MASK	_PAGE_G_X86
#define PT_X86_32_NX_MASK	_PAGE_NX_X86_32
#define PT_X86_PAE_NX_MASK	_PAGE_NX_X86_PAE
#define PT_X86_64_NX_MASK	_PAGE_NX_X86_64

#define PT_X86_32_ROOT_LEVEL	X86_32_PGD_LEVEL_NUM	/* pte, pgd */
#define PT_X86_PAE_ROOT_LEVEL	X86_PAE_PGD_LEVEL_NUM	/* pte, pmd, pgd */
#define PT_X86_64_ROOT_LEVEL	X86_64_PGD_LEVEL_NUM	/* pte, pmd, pud, pgd */
#define PT_X86_DIRECTORY_LEVEL	X86_DIRECTORY_LEVEL_NUM	/* pmd */
#define PT_X86_PAGE_TABLE_LEVEL	X86_PTE_LEVEL_NUM	/* pte */
#define PT_X86_MAX_HUGEPAGE_LEVEL MAX_HUGE_PAGES_LEVEL_X86_64	/* pud */

#define	PT_X86_32_ENTRIES_BITS	PT_ENT_BITS_X86_32	/* 10 bits */
#define	PT_X86_64_ENTRIES_BITS	PT_ENT_BITS_X86_64	/*  9 bits */
#define	PT_X86_32_ENT_PER_PAGE	PT_ENT_PER_PAGE_X86_32	/* 1024 entries */
#define	PT_X86_64_ENT_PER_PAGE	PT_ENT_PER_PAGE_X86_64	/*  512 entries */

#ifdef	CONFIG_X86_HW_VIRTUALIZATION
/*
 * Currently, we have two sorts of write-protection, a) the first one
 * write-protects guest page to sync the guest modification, b) another one is
 * used to sync dirty bitmap when we do KVM_GET_DIRTY_LOG. The differences
 * between these two sorts are:
 * 1) the first case clears SPTE_MMU_WRITEABLE bit.
 * 2) the first case requires flushing tlb immediately avoiding corrupting
 *    shadow page table between all vcpus so it should be in the protection of
 *    mmu-lock. And the another case does not need to flush tlb until returning
 *    the dirty bitmap to userspace since it only write-protects the page
 *    logged in the bitmap, that means the page in the dirty bitmap is not
 *    missed, so it can flush tlb out of mmu-lock.
 *
 * So, there is the problem: the first case can meet the corrupted tlb caused
 * by another case which write-protects pages but without flush tlb
 * immediately. In order to making the first case be aware this problem we let
 * it flush tlb if we try to write-protect a spte whose SPTE_MMU_WRITEABLE bit
 * is set, it works since another case never touches SPTE_MMU_WRITEABLE bit.
 *
 * Anyway, whenever a spte is updated (only permission and status bits are
 * changed) we need to check whether the spte with SPTE_MMU_WRITEABLE becomes
 * readonly, if that happens, we need to flush tlb. Fortunately,
 * mmu_spte_update() has already handled it perfectly.
 *
 * The rules to use SPTE_MMU_WRITEABLE and PT_WRITABLE_MASK:
 * - if we want to see if it has writable tlb entry or if the spte can be
 *   writable on the mmu mapping, check SPTE_MMU_WRITEABLE, this is the most
 *   case, otherwise
 * - if we fix page fault on the spte or do write-protection by dirty logging,
 *   check PT_WRITABLE_MASK.
 *
 * TODO: introduce APIs to split these two cases.
 */

static inline bool is_write_protection(struct kvm_vcpu *vcpu)
{
	return kvm_read_cr0_bits(vcpu, X86_CR0_WP);
}

/*
 * Check if a given access (described through the I/D, W/R and U/S bits of a
 * page fault error code pfec) causes a permission fault with the given PTE
 * access rights (in ACC_* format).
 *
 * Return zero if the access does not fault; return the page fault error code
 * if the access faults.
 */
static inline u8 permission_fault(struct kvm_vcpu *vcpu, struct kvm_mmu *mmu,
				  unsigned pte_access, unsigned pte_pkey,
				  unsigned pfec)
{
	int cpl = kvm_x86_ops->get_cpl(vcpu);
	unsigned long rflags = kvm_x86_ops->get_rflags(vcpu);

	/*
	 * If CPL < 3, SMAP prevention are disabled if EFLAGS.AC = 1.
	 *
	 * If CPL = 3, SMAP applies to all supervisor-mode data accesses
	 * (these are implicit supervisor accesses) regardless of the value
	 * of EFLAGS.AC.
	 *
	 * This computes (cpl < 3) && (rflags & X86_EFLAGS_AC), leaving
	 * the result in X86_EFLAGS_AC. We then insert it in place of
	 * the PFERR_RSVD_MASK bit; this bit will always be zero in pfec,
	 * but it will be one in index if SMAP checks are being overridden.
	 * It is important to keep this branchless.
	 */
	unsigned long smap = (cpl - 3) & (rflags & X86_EFLAGS_AC);
	int index = (pfec >> 1) +
		    (smap >> (X86_EFLAGS_AC_BIT - PFERR_RSVD_BIT + 1));
	bool fault = (mmu->permissions[index] >> pte_access) & 1;
	u32 errcode = PFERR_PRESENT_MASK;

	WARN_ON(pfec & (PFERR_PK_MASK | PFERR_RSVD_MASK));
	if (unlikely(mmu->pkru_mask)) {
		u32 pkru_bits, offset;

		/*
		* PKRU defines 32 bits, there are 16 domains and 2
		* attribute bits per domain in pkru.  pte_pkey is the
		* index of the protection domain, so pte_pkey * 2 is
		* is the index of the first bit for the domain.
		*/
		pkru_bits = (kvm_read_pkru(vcpu) >> (pte_pkey * 2)) & 3;

		/* clear present bit, replace PFEC.RSVD with ACC_USER_MASK. */
		offset = (pfec & ~1) +
			((pte_access & PT_USER_MASK) <<
					(PFERR_RSVD_BIT - PT_USER_SHIFT));

		pkru_bits &= mmu->pkru_mask >> offset;
		errcode |= -pkru_bits & PFERR_PK_MASK;
		fault |= (pkru_bits != 0);
	}

	return -(u32)fault & errcode;
}
#endif	/* CONFIG_X86_HW_VIRTUALIZATION */

#endif	/* _E2K_KVM_MMU_X86_H_ */
