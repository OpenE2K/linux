/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef __KVM_E2K_GACCESS_H
#define __KVM_E2K_GACCESS_H

/*
 * Guest virtual and physical memory access to read from/write to
 *
 */

#include <linux/kvm_host.h>
#include <linux/kvm.h>

#include <asm/kvm/gva_cache.h>

#include "mmu.h"

/*
 * The follow defines is expansion of arch-independent GVA->HVA translation
 * error codes (see include/linux/kvm_host.h
 */
#define KVM_HVA_ONLY_VALID	(PAGE_OFFSET + 2 * PAGE_SIZE)
#define KVM_HVA_IS_UNMAPPED	(PAGE_OFFSET + 3 * PAGE_SIZE)
#define KVM_HVA_IS_WRITE_PROT	(PAGE_OFFSET + 4 * PAGE_SIZE)

static inline bool kvm_is_only_valid_hva(unsigned long addr)
{
	return addr == KVM_HVA_ONLY_VALID;
}

static inline bool kvm_is_unmapped_hva(unsigned long addr)
{
	return addr == KVM_HVA_IS_UNMAPPED;
}

static inline bool kvm_is_write_prot_hva(unsigned long addr)
{
	return addr == KVM_HVA_IS_WRITE_PROT;
}

static inline bool
kvm_mmu_gva_is_gpa(struct kvm_vcpu *vcpu, gva_t gva)
{
	gpa_t gpa;
	gfn_t gfn;
	e2k_addr_t hva;

	if (!vcpu->arch.is_pv)
		/* it is unknown in common case */
		return false;
	if (is_paging(vcpu))
		/* can be only virtual addresses */
		return false;
	if (gva >= GUEST_PAGE_OFFSET)
		return false;

	gpa = (gpa_t)gva;
	gfn = gpa_to_gfn(gpa);
	hva = kvm_vcpu_gfn_to_hva(vcpu, gfn);
	if (unlikely(kvm_is_error_hva(hva)))
		return false;

	return true;
}
static inline bool
kvm_mmu_gva_is_gpa_range(struct kvm_vcpu *vcpu, gva_t gva, unsigned int bytes)
{
	gva_t end;

	if (!kvm_mmu_gva_is_gpa(vcpu, gva))
		return false;
	end = gva + bytes - 1;
	if ((end & PAGE_MASK) == (gva & PAGE_MASK))
		return true;
	return kvm_mmu_gva_is_gpa(vcpu, end);
}

static inline gpa_t
kvm_mmu_gvpa_to_gpa(gva_t gvpa)
{
	return (gpa_t)__guest_pa(gvpa);
}

static inline bool
kvm_mmu_gva_is_gvpa(struct kvm_vcpu *vcpu, gva_t gva)
{
	gpa_t gpa;
	gfn_t gfn;
	e2k_addr_t hva;

	if (!vcpu->arch.is_pv)
		/* it is unknown in common case */
		return false;
	if (gva < GUEST_PAGE_OFFSET)
		return false;

	gpa = kvm_mmu_gvpa_to_gpa(gva);
	gfn = gpa_to_gfn(gpa);
	hva = kvm_vcpu_gfn_to_hva(vcpu, gfn);
	if (unlikely(kvm_is_error_hva(hva)))
		return false;

	return true;
}
static inline bool
kvm_mmu_gva_is_gvpa_range(struct kvm_vcpu *vcpu, gva_t gva, unsigned int bytes)
{
	gva_t end;

	if (!kvm_mmu_gva_is_gvpa(vcpu, gva))
		return false;
	end = gva + bytes - 1;
	if ((end & PAGE_MASK) == (gva & PAGE_MASK))
		return true;
	return kvm_mmu_gva_is_gvpa(vcpu, end);
}

static inline gpa_t
kvm_mmu_gva_to_gpa(struct kvm_vcpu *vcpu, gva_t gva, u32 access,
				kvm_arch_exception_t *exception)
{
	gpa_t gpa;
	bool again = false;
#ifdef CONFIG_KVM_GVA_CACHE
	gva_cache_t *gva_cache;
#endif /* CONFIG_KVM_GVA_CACHE */

	if (likely(kvm_mmu_gva_is_gvpa(vcpu, gva)))
		return kvm_mmu_gvpa_to_gpa(gva);

again:

#ifdef CONFIG_KVM_GVA_CACHE
	gva_cache = (gva < GUEST_PAGE_OFFSET) ?
		pv_vcpu_get_gmm(vcpu)->gva_cache :
		pv_vcpu_get_init_gmm(vcpu)->gva_cache;
	gpa = (is_paging(vcpu)) ?
		gva_cache_translate(gva_cache, gva, access, vcpu,
				exception, &mmu_pt_gva_to_gpa) :
		mmu_pt_gva_to_gpa(vcpu, gva, access, exception, NULL);
#else /* !CONFIG_KVM_GVA_CACHE */
	gpa = mmu_pt_gva_to_gpa(vcpu, gva, access, exception, NULL);
#endif /* !CONFIG_KVM_GVA_CACHE */

	if (arch_is_error_gpa(gpa)) {
		/* it's OK to have bad guest virt address and
		 * pass it back to guest even if it's not valid */
	} else if (unlikely(gpa >= HOST_PAGE_OFFSET && !again &&
						vcpu->arch.is_hv)) {
			/* Bug 119772: we may need to switch from nonpaging */
			/* to tdp here */
			is_paging(vcpu);
			again = true;
			goto again;
	}
	gpa |= (gva & ~PAGE_MASK);
	return gpa;
}

static inline gpa_t
kvm_mmu_gva_to_gpa_read(struct kvm_vcpu *vcpu, gva_t gva,
			kvm_arch_exception_t *exception)
{
	u32 access = 0;

	return kvm_mmu_gva_to_gpa(vcpu, gva, access, exception);
}

static inline gpa_t
kvm_mmu_gva_to_gpa_fetch(struct kvm_vcpu *vcpu, gva_t gva,
			kvm_arch_exception_t *exception)
{
	u32 access = 0;

	access |= PFERR_FETCH_MASK;
	return kvm_mmu_gva_to_gpa(vcpu, gva, access, exception);
}

static inline gpa_t
kvm_mmu_gva_to_gpa_write(struct kvm_vcpu *vcpu, gva_t gva,
			kvm_arch_exception_t *exception)
{
	u32 access = 0;

	access |= PFERR_WRITE_MASK;
	return kvm_mmu_gva_to_gpa(vcpu, gva, access, exception);
}

/* uses this to access any guest's mapped memory without checking CPL */
static inline gpa_t
kvm_mmu_gva_to_gpa_system(struct kvm_vcpu *vcpu, gva_t gva,
			kvm_arch_exception_t *exception)
{
	return kvm_mmu_gva_to_gpa(vcpu, gva, 0, exception);
}

static inline hva_t kvm_vcpu_gpa_to_hva(struct kvm_vcpu *vcpu, gpa_t gpa)
{
	gfn_t gfn;
	unsigned long hva;

	gfn = gpa_to_gfn(gpa);

	hva = kvm_vcpu_gfn_to_hva(vcpu, gfn);
	if (kvm_is_error_hva(hva))
		return hva;

	hva |= (gpa & ~PAGE_MASK);
	return hva;
}

static inline hva_t kvm_vcpu_gva_to_hva(struct kvm_vcpu *vcpu, gva_t gva,
				bool is_write, kvm_arch_exception_t *exception)
{
	gpa_t gpa;
	gfn_t gfn;
	unsigned long hva;
	kvm_arch_exception_t gpa_exception;

	gpa = is_write ? kvm_mmu_gva_to_gpa_write(vcpu, gva, &gpa_exception) :
			kvm_mmu_gva_to_gpa_read(vcpu, gva, &gpa_exception);
	if (unlikely(arch_is_error_gpa(gpa))) {
		if (gpa_exception.error_code & PFERR_ONLY_VALID_MASK)
			hva = KVM_HVA_ONLY_VALID;
		else if (gpa_exception.error_code & PFERR_IS_UNMAPPED_MASK)
			hva = KVM_HVA_IS_UNMAPPED;
		else if (is_write &&
				(gpa_exception.error_code & PFERR_WRITE_MASK))
			hva = KVM_HVA_IS_WRITE_PROT;
		else
			hva = KVM_HVA_ERR_BAD;

		if (exception)
			memcpy(exception, &gpa_exception,
					sizeof(gpa_exception));

		return hva;
	}

	gfn = gpa_to_gfn(gpa);

	hva = kvm_vcpu_gfn_to_hva(vcpu, gfn);
	if (kvm_is_error_hva(hva))
		return hva;

	hva |= (gva & ~PAGE_MASK);
	return hva;
}

extern void kvm_vcpu_inject_page_fault(struct kvm_vcpu *vcpu, void *addr,
				   kvm_arch_exception_t *exception);
extern int kvm_vcpu_fetch_guest_virt(struct kvm_vcpu *vcpu,
			gva_t addr, void *val, unsigned int bytes);
extern int kvm_vcpu_read_guest_virt_system(struct kvm_vcpu *vcpu,
			gva_t addr, void *val, unsigned int bytes);
extern int kvm_vcpu_read_guest_system(struct kvm_vcpu *vcpu,
			gva_t addr, void *val, unsigned int bytes);
extern int kvm_vcpu_write_guest_virt_system(struct kvm_vcpu *vcpu,
			gva_t addr, void *val, unsigned int bytes);
extern int kvm_vcpu_write_guest_system(struct kvm_vcpu *vcpu,
			gva_t addr, void *val, unsigned int bytes);
extern int kvm_read_guest_phys_system(struct kvm *kvm, gpa_t addr,
			void *val, unsigned int bytes);
extern int kvm_write_guest_phys_system(struct kvm *kvm, gpa_t addr,
			void *val, unsigned int bytes);
extern long kvm_vcpu_set_guest_virt_system(struct kvm_vcpu *vcpu,
		void *addr, u64 val, u64 tag, size_t size, size_t *cleared,
		u64 strd_opcode);
extern long kvm_vcpu_set_guest_user_virt_system(struct kvm_vcpu *vcpu,
		void *addr, u64 val, u64 tag, size_t size, size_t *cleared,
		u64 strd_opcode);
extern long kvm_vcpu_copy_guest_virt_system(struct kvm_vcpu *vcpu,
		void *dst, const void *src, size_t len, size_t *copied,
		unsigned long strd_opcode, unsigned long ldrd_opcode,
		int prefetch);
extern long kvm_vcpu_copy_guest_virt_system_16(struct kvm_vcpu *vcpu,
		void *dst, const void *src, size_t len,
		unsigned long strd_opcode, unsigned long ldrd_opcode,
		int prefetch);
extern long kvm_vcpu_copy_guest_user_virt_system(struct kvm_vcpu *vcpu,
		void *dst, const void *src, size_t len, size_t *copied,
		unsigned long strd_opcode, unsigned long ldrd_opcode,
		int prefetch);
extern long kvm_vcpu_copy_guest_user_virt_system_16(struct kvm_vcpu *vcpu,
		void *dst, const void *src, size_t len,
		unsigned long strd_opcode, unsigned long ldrd_opcode,
		int prefetch);

static inline unsigned long
kvm_vcpu_copy_from_guest(struct kvm_vcpu *vcpu,
		void *to, const void *from, unsigned long n)
{
	return kvm_vcpu_read_guest_system(vcpu, (gva_t)from, to, n);
}

static inline unsigned long
kvm_vcpu_copy_to_guest(struct kvm_vcpu *vcpu,
		void *to, const void *from, unsigned long n)
{
	return kvm_vcpu_write_guest_system(vcpu, (gva_t)to, (void *)from, n);
}

#endif	/* __KVM_E2K_GACCESS_H */
