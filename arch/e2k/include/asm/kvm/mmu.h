#ifndef __E2K_KVM_HOST_MMU_H
#define __E2K_KVM_HOST_MMU_H

#include <linux/types.h>
#include <linux/mm_types.h>
#include <linux/kvm.h>
#include <asm/kvm/mmu_hv_regs_access.h>
#include <asm/kvm/hypervisor.h>
#include <asm/mmu_fault.h>
#include <asm/kvm/pv-emul.h>

#ifdef	CONFIG_VIRTUALIZATION

static inline bool is_guest_user_gva(gva_t gva)
{
	return gva < GUEST_TASK_SIZE;
}

static inline bool is_guest_kernel_gva(gva_t gva)
{
	return gva >= GUEST_PAGE_OFFSET && gva < HOST_PAGE_OFFSET;
}

static inline bool is_ss(struct kvm_vcpu *vcpu)
{
	return false;
}
static inline bool is_sep_virt_spaces(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.mmu.sep_virt_space;
}
static inline void set_sep_virt_spaces(struct kvm_vcpu *vcpu)
{
	vcpu->arch.mmu.sep_virt_space = true;
}
static inline void reset_sep_virt_spaces(struct kvm_vcpu *vcpu)
{
	vcpu->arch.mmu.sep_virt_space = false;
}
static inline bool is_shadow_paging(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.mmu.shadow_pt_on;
}
static inline void set_shadow_paging(struct kvm_vcpu *vcpu)
{
	vcpu->arch.mmu.shadow_pt_on = true;
	set_bit(KVM_FEAT_MMU_SPT_BIT,
			&vcpu->kvm->arch.kmap_host_info->features);
	clear_bit(KVM_FEAT_MMU_TDP_BIT,
			&vcpu->kvm->arch.kmap_host_info->features);
}
static inline void reset_shadow_paging(struct kvm_vcpu *vcpu)
{
	vcpu->arch.mmu.shadow_pt_on = false;
}
static inline bool is_phys_paging(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.mmu.phys_pt_on;
}
static inline void set_phys_paging(struct kvm_vcpu *vcpu)
{
	vcpu->arch.mmu.phys_pt_on = true;
}
static inline void reset_phys_paging(struct kvm_vcpu *vcpu)
{
	vcpu->arch.mmu.phys_pt_on = false;
}
static inline bool is_tdp_paging(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.mmu.tdp_on;
}
static inline void set_tdp_paging(struct kvm_vcpu *vcpu)
{
	vcpu->arch.mmu.tdp_on = true;
	set_bit(KVM_FEAT_MMU_TDP_BIT,
			&vcpu->kvm->arch.kmap_host_info->features);
	clear_bit(KVM_FEAT_MMU_SPT_BIT,
			&vcpu->kvm->arch.kmap_host_info->features);
}
static inline void reset_tdp_paging(struct kvm_vcpu *vcpu)
{
	vcpu->arch.mmu.tdp_on = false;
}

static inline bool is_paging_flag(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.mmu.paging_on;
}
static inline void set_paging_flag(struct kvm_vcpu *vcpu)
{
	vcpu->arch.mmu.paging_on = true;
}
static inline void reset_paging_flag(struct kvm_vcpu *vcpu)
{
	vcpu->arch.mmu.paging_on = false;
}

static inline bool is_pv_paging(struct kvm_vcpu *vcpu)
{
	return is_paging_flag(vcpu);
}
static inline bool is_spt_paging(struct kvm_vcpu *vcpu)
{
	return is_paging_flag(vcpu);
}
static inline bool is_hv_paging(struct kvm_vcpu *vcpu)
{
#ifdef	CONFIG_VIRTUALIZATION
	if (current_thread_info()->vcpu != vcpu)
		return is_paging_flag(vcpu);
#endif
	if (vcpu->arch.mmu.is_paging == NULL)
		return is_paging_flag(vcpu);

	return vcpu->arch.mmu.is_paging(vcpu);
}

static inline bool is_paging(struct kvm_vcpu *vcpu)
{
	if (is_tdp_paging(vcpu))
		return is_hv_paging(vcpu);
	if (unlikely(vcpu->arch.is_pv))
		return is_pv_paging(vcpu);
	if (unlikely(is_shadow_paging(vcpu)))
		return is_spt_paging(vcpu);

	return is_paging_flag(vcpu);
}

typedef enum sw_to_host_type {
	undefined_sw_to_host,	/* undefined reason to switch */
	syscall_sw_to_host,	/* syscall from guest: return to host */
				/* mode to inject the syscall to guest */
	hypercall_sw_to_host,	/* hypercall from guest */
	to_qemu_sw_to_host,	/* return to qemu to continue guest */
				/* hypercall request */
	trap_sw_to_host,	/* trap on the guest is emulated as */
				/* an intercept */
	trampoline_sw_to_host,	/* guest returned to host trampoline */
				/* after injection completion */
} sw_to_host_type_t;

static inline bool is_spt_gpa_fault(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.mmu.spt_gpa_fault;
}
static inline void set_spt_gpa_fault(struct kvm_vcpu *vcpu)
{
	vcpu->arch.mmu.spt_gpa_fault = true;
}
static inline void reset_spt_gpa_fault(struct kvm_vcpu *vcpu)
{
	vcpu->arch.mmu.spt_gpa_fault = false;
}

static inline unsigned long get_mmu_u_pptb_reg(void)
{
	return NATIVE_READ_MMU_U_PPTB_REG();
}

static inline unsigned long get_mmu_pid_reg(void)
{
	return NATIVE_READ_MMU_PID_REG();
}

static inline hpa_t
kvm_get_gp_phys_root(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.mmu.get_vcpu_gp_pptb(vcpu);
}
static inline void
kvm_set_gp_phys_root(struct kvm_vcpu *vcpu, hpa_t root)
{
	vcpu->arch.mmu.set_vcpu_gp_pptb(vcpu, root);
}

static inline hpa_t
kvm_get_space_type_spt_root(struct kvm_vcpu *vcpu, bool u_root)
{
	return (u_root) ? vcpu->arch.mmu.get_vcpu_sh_u_pptb(vcpu) :
				vcpu->arch.mmu.get_vcpu_sh_os_pptb(vcpu);
}
static inline hpa_t
kvm_get_space_type_spt_os_root(struct kvm_vcpu *vcpu)
{
	return kvm_get_space_type_spt_root(vcpu, false);
}
static inline hpa_t
kvm_get_space_type_spt_u_root(struct kvm_vcpu *vcpu)
{
	return kvm_get_space_type_spt_root(vcpu, true);
}
static inline void
kvm_set_space_type_spt_root(struct kvm_vcpu *vcpu, hpa_t root, bool u_root)
{
	if (u_root) {
		vcpu->arch.mmu.set_vcpu_sh_u_pptb(vcpu, root);
	} else {
		vcpu->arch.mmu.set_vcpu_sh_os_pptb(vcpu, root);
	}
}
static inline void
kvm_set_space_type_spt_os_root(struct kvm_vcpu *vcpu, hpa_t root)
{
	kvm_set_space_type_spt_root(vcpu, root, false);
}
static inline void
kvm_set_space_type_spt_u_root(struct kvm_vcpu *vcpu, hpa_t root)
{
	kvm_set_space_type_spt_root(vcpu, root, true);
}
static inline hpa_t
kvm_get_space_type_spt_gk_root(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.mmu.get_vcpu_sh_gk_pptb(vcpu);
}
static inline void
kvm_set_space_type_spt_gk_root(struct kvm_vcpu *vcpu, hpa_t gk_root)
{
	vcpu->arch.mmu.set_vcpu_sh_gk_pptb(vcpu, gk_root);
}
static inline void
kvm_set_vcpu_spt_u_pptb_context(struct kvm_vcpu *vcpu)
{
	vcpu->arch.mmu.set_vcpu_u_pptb_context(vcpu);
}
static inline hpa_t
kvm_get_space_addr_spt_root(struct kvm_vcpu *vcpu, gva_t gva)
{
	if (likely(is_guest_user_gva(gva))) {
		if (!vcpu->arch.mmu.sep_virt_space) {
			return vcpu->arch.mmu.get_vcpu_sh_u_pptb(vcpu);
		} else if (unlikely(gva >= vcpu->arch.mmu.get_vcpu_os_vab(vcpu))) {
			return vcpu->arch.mmu.get_vcpu_sh_os_pptb(vcpu);
		} else {
			return vcpu->arch.mmu.get_vcpu_sh_u_pptb(vcpu);
		}
	} else {
		return kvm_mmu_get_init_gmm_root_hpa(vcpu->kvm);
	}
}
static inline hpa_t
kvm_get_space_addr_root(struct kvm_vcpu *vcpu, gva_t gva)
{
	if (likely(is_tdp_paging(vcpu) ||
			((!is_paging(vcpu) || is_spt_gpa_fault(vcpu)) &&
						is_phys_paging(vcpu)))) {
		return kvm_get_gp_phys_root(vcpu);
	} else if (is_shadow_paging(vcpu)) {
		return kvm_get_space_addr_spt_root(vcpu, gva);
	} else {
		KVM_BUG_ON(true);
		return (hpa_t)-EINVAL;
	}
}
static inline gpa_t
kvm_get_space_type_guest_root(struct kvm_vcpu *vcpu, bool u_root)
{
	if (!vcpu->arch.mmu.sep_virt_space) {
		KVM_BUG_ON(!u_root);
		return (gpa_t)vcpu->arch.mmu.get_vcpu_u_pptb(vcpu);
	}
	return (u_root) ? (gpa_t)vcpu->arch.mmu.get_vcpu_u_pptb(vcpu) :
				(gpa_t)vcpu->arch.mmu.get_vcpu_os_pptb(vcpu);
}
static inline gpa_t
kvm_get_space_type_guest_os_root(struct kvm_vcpu *vcpu)
{
	return kvm_get_space_type_guest_root(vcpu, false);
}
static inline gpa_t
kvm_get_space_type_guest_u_root(struct kvm_vcpu *vcpu)
{
	return kvm_get_space_type_guest_root(vcpu, true);
}

static inline void
kvm_set_space_type_guest_root(struct kvm_vcpu *vcpu, gpa_t root,
				bool u_root)
{
	if (!vcpu->arch.mmu.sep_virt_space) {
		KVM_BUG_ON(!u_root);
		vcpu->arch.mmu.set_vcpu_u_pptb(vcpu, (pgprotval_t)root);
	} else if (likely(u_root)) {
		vcpu->arch.mmu.set_vcpu_u_pptb(vcpu, (pgprotval_t)root);
	} else {
		vcpu->arch.mmu.set_vcpu_os_pptb(vcpu, (pgprotval_t)root);
	}
}
static inline void
kvm_set_space_type_guest_os_root(struct kvm_vcpu *vcpu, gpa_t root)
{
	kvm_set_space_type_guest_root(vcpu, root, false);
}
static inline void
kvm_set_space_type_guest_u_root(struct kvm_vcpu *vcpu, gpa_t root)
{
	kvm_set_space_type_guest_root(vcpu, root, true);
}
static inline gpa_t
kvm_get_space_addr_guest_root(struct kvm_vcpu *vcpu, gva_t gva)
{
	if (!vcpu->arch.mmu.sep_virt_space) {
		return vcpu->arch.mmu.get_vcpu_u_pptb(vcpu);
	} else if (unlikely(gva >= vcpu->arch.mmu.get_vcpu_os_vab(vcpu))) {
		return vcpu->arch.mmu.get_vcpu_os_pptb(vcpu);
	} else {
		return vcpu->arch.mmu.get_vcpu_u_pptb(vcpu);
	}
}
static inline hpa_t
kvm_get_space_type_spt_vptb(struct kvm_vcpu *vcpu, bool u_root)
{
	if (!vcpu->arch.mmu.sep_virt_space) {
		/* common standard in linux: user and OS share virtual */
		/* space of user */
		KVM_BUG_ON(!u_root);
		return vcpu->arch.mmu.get_vcpu_sh_u_vptb(vcpu);
	} else if (u_root) {
		return vcpu->arch.mmu.get_vcpu_sh_u_vptb(vcpu);
	} else {
		return vcpu->arch.mmu.get_vcpu_sh_os_vptb(vcpu);
	}
}
static inline hpa_t
kvm_get_space_addr_spt_vptb(struct kvm_vcpu *vcpu, gva_t gva)
{
	if (!vcpu->arch.mmu.sep_virt_space) {
		return vcpu->arch.mmu.get_vcpu_sh_u_vptb(vcpu);
	} else if (unlikely(gva >= vcpu->arch.mmu.get_vcpu_os_vab(vcpu))) {
		return vcpu->arch.mmu.get_vcpu_sh_os_vptb(vcpu);
	} else {
		return vcpu->arch.mmu.get_vcpu_sh_u_vptb(vcpu);
	}
}

static inline int do_gmm_put(struct kvm *kvm, gmm_struct_t *gmm)
{
	int count;

	count = atomic_dec_return(&gmm->mm_count);
	KVM_BUG_ON(count < 0);
	return count;
}

static inline void do_gmm_get(gmm_struct_t *gmm)
{
	atomic_inc(&gmm->mm_count);
}

static inline void kvm_gmm_get(struct kvm_vcpu *vcpu, gthread_info_t *gti,
				gmm_struct_t *gmm)
{
	do_gmm_get(gmm);
	if (likely(!pv_vcpu_is_init_gmm(vcpu, gmm))) {
		gti->gmm = gmm;
		gti->gmm_in_release = false;
	} else if (gti->gmm_in_release) {
		/* some thread is converted to as a guest kernel thread */
		KVM_BUG_ON(gti->gmm == NULL);
		KVM_BUG_ON(gmm == gti->gmm);
		do_gmm_put(vcpu->kvm, gti->gmm);
		gti->gmm = NULL;
		gti->gmm_in_release = false;
	}
}

static inline void kvm_init_gmm_get(struct kvm_vcpu *vcpu, gthread_info_t *gti)
{
	gmm_struct_t *init_gmm = pv_vcpu_get_init_gmm(vcpu);
	gmm_struct_t *gmm = gti->gmm;

	KVM_BUG_ON(gmm == NULL);

	do_gmm_put(vcpu->kvm, gti->gmm);
	do_gmm_get(init_gmm);
	gti->gmm = NULL;
}

#define	INVALID_GPA		((gpa_t)E2K_INVALID_PAGE)
#define	IS_INVALID_GPA(gpa)	((gpa) == INVALID_GPA)

#define	INVALID_GVA		((gva_t)E2K_INVALID_PAGE)
#define	IS_INVALID_GVA(gpa)	((gpa) == INVALID_GVA)

static inline struct kvm_mmu_page *page_header(hpa_t shadow_page)
{
	struct page *page = pfn_to_page(shadow_page >> PAGE_SHIFT);

	return (struct kvm_mmu_page *)page_private(page);
}

static inline bool spte_same(pgprot_t pgd_a, pgprot_t pgd_b)
{
	return pgprot_val(pgd_a) == pgprot_val(pgd_b);
}

extern void kvm_get_spt_translation(struct kvm_vcpu *vcpu, e2k_addr_t address,
				    pgdval_t *pgd, pudval_t *pud, pmdval_t *pmd,
				    pteval_t *pte, int *pt_level);
extern unsigned long kvm_get_gva_to_hva(struct kvm_vcpu *vcpu, gva_t gva);

static inline gpa_t kvm_hva_to_gpa(struct kvm *kvm, unsigned long hva)
{
	struct kvm_memslots *slots;
	struct kvm_memory_slot *memslot;
	int i;

	for (i = 0; i < KVM_ADDRESS_SPACE_NUM; i++) {
		slots = __kvm_memslots(kvm, i);
		kvm_for_each_memslot(memslot, slots) {
			unsigned long hva_start, hva_end;
			gfn_t gfn;
			gpa_t gpa;

			hva_start = memslot->userspace_addr;
			hva_end = hva_start + (memslot->npages << PAGE_SHIFT);
			if (hva < hva_start || hva >= hva_end)
				continue;
			gfn = hva_to_gfn_memslot(hva, memslot);
			gpa = (gfn << PAGE_SHIFT) + (hva & ~PAGE_MASK);
			return gpa;
		}
	}

	return INVALID_GPA;
}

static inline gpa_t
kvm_vcpu_hva_to_gpa(struct kvm_vcpu *vcpu, unsigned long hva)
{
	return kvm_hva_to_gpa(vcpu->kvm, hva);
}

static inline void kvm_setup_host_mmu_info(struct kvm_vcpu *vcpu)
{
	if (is_tdp_paging(vcpu)) {
		set_bit(KVM_FEAT_MMU_TDP_BIT,
			&vcpu->kvm->arch.kmap_host_info->features);
		clear_bit(KVM_FEAT_MMU_SPT_BIT,
			&vcpu->kvm->arch.kmap_host_info->features);
	} else if (is_shadow_paging(vcpu)) {
		set_bit(KVM_FEAT_MMU_SPT_BIT,
			&vcpu->kvm->arch.kmap_host_info->features);
		clear_bit(KVM_FEAT_MMU_TDP_BIT,
			&vcpu->kvm->arch.kmap_host_info->features);
	} else {
		KVM_BUG_ON(true);
	}
}

#ifdef	CONFIG_KVM_SHADOW_PT_ENABLE
extern int kvm_pv_mmu_page_fault(struct kvm_vcpu *vcpu, struct pt_regs *regs,
				trap_cellar_t *tcellar, bool user_mode);
extern int kvm_pv_mmu_instr_page_fault(struct kvm_vcpu *vcpu,
				struct pt_regs *regs, tc_fault_type_t ftype,
				const int async_instr);
extern int kvm_pv_mmu_aau_page_fault(struct kvm_vcpu *vcpu,
				struct pt_regs *regs, e2k_addr_t address,
				tc_cond_t cond, unsigned int aa_no);
extern int kvm_mmu_instr_page_fault(struct kvm_vcpu *vcpu, gva_t address,
				bool async_instr, u32 error_code);
#else	/* ! CONFIG_KVM_SHADOW_PT_ENABLE */
static inline int
kvm_pv_mmu_page_fault(struct kvm_vcpu *vcpu, struct pt_regs *regs,
			trap_cellar_t *tcellar, bool user_mode)
{
	/* page fault should be handled by host */
	return -1;
}
static inline long
kvm_hv_mmu_page_fault(struct kvm_vcpu *vcpu, struct pt_regs *regs,
			intc_info_mu_t *intc_info_mu)
{
	/* page fault should be handled by host */
	return -1;
}
static inline int
kvm_pv_mmu_instr_page_fault(struct kvm_vcpu *vcpu,
				struct pt_regs *regs, tc_fault_type_t ftype,
				const int async_instr)
{
	/* page fault should be handled by host */
	return -1;
}
static inline int
kvm_pv_mmu_aau_page_fault(struct kvm_vcpu *vcpu,
				struct pt_regs *regs, e2k_addr_t address,
				tc_cond_t cond, unsigned int aa_no)
{
	/* page fault should be handled by host */
	return -1;
}

static inline int
kvm_mmu_instr_page_fault(struct kvm_vcpu *vcpu, gva_t address,
				bool async_instr, u32 error_code)
{
	/* page fault should be handled by host */
	return -1;
}
#endif	/* CONFIG_KVM_SHADOW_PT_ENABLE */

extern int kvm_guest_addr_to_host(void **addr);
extern void *kvm_guest_ptr_to_host_ptr(void *guest_ptr, bool is_write,
					int size, bool need_inject);

#ifdef	CONFIG_KVM_HOST_MODE
/* it is native host kernel with virtualization support */
static inline int
guest_addr_to_host(void **addr, const pt_regs_t *regs)
{
	if (likely(!host_test_intc_emul_mode(regs))) {
		/* faulted addres is not paravirtualized guest one */
		return native_guest_addr_to_host(addr);
	}

	return kvm_guest_addr_to_host(addr);
}
static inline void *
guest_ptr_to_host(void *ptr, bool is_write, int size, const pt_regs_t *regs)
{
	if (likely(!host_test_intc_emul_mode(regs))) {
		/* faulted addres is not paravirtualized guest one */
		return native_guest_ptr_to_host(ptr, size);
	}

	return kvm_guest_ptr_to_host_ptr(ptr, is_write, size, false);
}
#endif	/* CONFIG_KVM_HOST_MODE */

#else	/* !CONFIG_VIRTUALIZATION */

typedef enum sw_to_host_type {
	undefined_sw_to_host,	/* undefined reason to switch */
} sw_to_host_type_t;

#endif	/* CONFIG_VIRTUALIZATION */

#endif	/* __E2K_KVM_HOST_MMU_H */
