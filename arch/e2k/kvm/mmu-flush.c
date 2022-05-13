/*
 * Guest kernel MMU caches support on KVM host
 * (Instruction and Data caches, TLB)
 *
 * Copyright 2016 Salavat S. Gilyazov (atic@mcst.ru)
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/mm.h>

#include <asm/types.h>
#include <asm/tlbflush.h>
#include <asm/mmu_regs.h>
#include <asm/page.h>
#include <asm/trace-tlb-flush.h>

#include "gaccess.h"

#define CREATE_TRACE_POINTS
#include "trace-tlb-flush.h"

#undef	DEBUG_KVM_FLUSH_SPT_MODE
#undef	DebugFLSPT
#define	DEBUG_KVM_FLUSH_SPT_MODE	0	/* shadow pt levels TLB flushing */
#define	DebugFLSPT(fmt, args...)					\
({									\
	if (DEBUG_KVM_FLUSH_SPT_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})


void host_local_flush_tlb_range_and_pgtables(gmm_struct_t *gmm,
				unsigned long start, unsigned long end)
{
	generic_local_flush_tlb_mm_range(NULL, &gmm->context, gmm_cpumask(gmm),
			start, end, PAGE_SIZE, FLUSH_TLB_LEVELS_ALL,
			trace_host_flush_tlb_enabled());
}

void host_flush_tlb_mm(gmm_struct_t *gmm)
{
	generic_flush_tlb_mm(NULL, &gmm->context, gmm_cpumask(gmm),
			     trace_host_flush_tlb_enabled());
}

void host_flush_tlb_page(gmm_struct_t *gmm, unsigned long addr)
{
	generic_flush_tlb_page(NULL, &gmm->context, gmm_cpumask(gmm), addr,
			       trace_host_flush_tlb_enabled());
}

/* See comment before native_flush_tlb_range() */
void host_flush_tlb_mm_range(gmm_struct_t *gmm,
			  unsigned long start, unsigned long end,
			  unsigned long stride, u32 levels_mask)
{
	generic_flush_tlb_mm_range(NULL, &gmm->context, gmm_cpumask(gmm),
			start, end, stride, levels_mask,
			trace_host_flush_tlb_enabled());
}

/* See comment before native_flush_tlb_range() */
void host_flush_tlb_range(gmm_struct_t *gmm,
			  unsigned long start, unsigned long end)
{
	generic_flush_tlb_mm_range(NULL, &gmm->context, gmm_cpumask(gmm),
			start, end, PAGE_SIZE, FLUSH_TLB_LEVELS_ALL,
			trace_host_flush_tlb_enabled());
}

void host_flush_tlb_kernel_range(gmm_struct_t *gmm,
				 unsigned long start, unsigned long end)
{
	generic_flush_tlb_mm_range(NULL, &gmm->context, gmm_cpumask(gmm),
			start, end, PAGE_SIZE, FLUSH_TLB_LEVELS_ALL,
			trace_host_flush_tlb_enabled());
}

void host_flush_tlb_range_and_pgtables(gmm_struct_t *gmm,
				       unsigned long start, unsigned long end)
{
	generic_flush_tlb_mm_range(NULL, &gmm->context, gmm_cpumask(gmm),
			start, end, PAGE_SIZE, FLUSH_TLB_LEVELS_ALL,
			trace_host_flush_tlb_enabled());
}

void host_flush_pmd_tlb_range(gmm_struct_t *gmm,
			      unsigned long start, unsigned long end)
{
	generic_flush_tlb_mm_range(NULL, &gmm->context, gmm_cpumask(gmm),
			start, end, PMD_SIZE, FLUSH_TLB_LEVELS_LAST,
			trace_host_flush_tlb_enabled());
}

void host_local_flush_tlb_page(mm_context_t *context,
			unsigned long addr, int cpu, bool trace_enabled)
{
	mmu_pid_flush_tlb_page(context, false, NULL, addr, cpu, trace_enabled);
}

void host_local_flush_pmd_tlb_range(mm_context_t *context,
			unsigned long start, unsigned long end, int cpu,
			bool trace_enabled)
{
	mmu_pid_flush_tlb_range(context, false, NULL, start, end,
				PMD_SIZE, FLUSH_TLB_LEVELS_LAST, cpu,
				trace_enabled);
}

void host_local_flush_tlb_range(mm_context_t *context,
			unsigned long start, unsigned long end, int cpu,
			bool trace_enabled)
{
	mmu_pid_flush_tlb_range(context, false, NULL, start, end,
				PAGE_SIZE, FLUSH_TLB_LEVELS_ALL, cpu,
				trace_enabled);
}

#ifdef	CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT
/*
 * Update all user PGD entries of the gmm.
 * PGDs are updated into CPU root page table from main user PGD table
 */
void host_flush_cpu_root_pt_mm(struct kvm_vcpu *vcpu, gmm_struct_t *gmm)
{
	if (unlikely(vcpu->arch.sw_ctxt.no_switch_pt)) {
		pgd_t *gmm_pgd = kvm_mmu_get_gmm_root(gmm);

		KVM_BUG_ON(gmm_pgd == NULL);
		copy_guest_user_pgd_to_kernel_root_pt(gmm_pgd);
		trace_host_flush_cpu_root_pt(vcpu, gmm, gmm_pgd);
	}
}
/*
 * Update all user PGD entries of current active mm.
 * PGDs are updated into CPU root page table from main user PGD table
 */
void host_flush_cpu_root_pt(struct kvm_vcpu *vcpu)
{
	gmm_struct_t *gmm = pv_vcpu_get_gmm(vcpu);

	host_flush_cpu_root_pt_mm(vcpu, gmm);
}
#else	/* !CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */
void host_flush_cpu_root_pt_mm(struct kvm_vcpu *vcpu, gmm_struct_t *gmm)
{
}
void host_flush_cpu_root_pt(struct kvm_vcpu *vcpu)
{
}
#endif	/* CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */

#ifdef	CONFIG_SMP

static void host_flush_init_gmm_tlb_range(struct kvm *kvm, gmm_struct_t *cur_gmm,
					  gva_t start, gva_t end, int level,
					  bool trace_enabled)
{

	gmm_struct_t *gmm;
	struct hlist_node *next;
	int cpu, i;

	/*
	 * init gmm contains guest kernel virtual space mapping
	 * and this mappings are parts of all other guest tasks,
	 * including guest kernel's threads
	 */
	cpu = get_cpu();
	gmmid_table_lock(&kvm->arch.gmmid_table);
	for_each_guest_mm(gmm, i, next, &kvm->arch.gmmid_table) {
		/* it nedd clear context on all CPUs for all gmms, */
		/* excluding the current cpu for current gmm */
		clear_mm_remote_context(&gmm->context,
			(likely(gmm != cur_gmm)) ? -1 : cpu);
	}
	gmmid_table_unlock(&kvm->arch.gmmid_table);

	if (likely(level == E2K_PTE_LEVEL_NUM)) {
		host_local_flush_tlb_page(&cur_gmm->context, start, cpu,
					  trace_enabled);
	} else if (level == E2K_PMD_LEVEL_NUM) {
		host_local_flush_pmd_tlb_range(&cur_gmm->context, start, end, cpu,
					       trace_enabled);
	} else if (level == E2K_PUD_LEVEL_NUM || level == E2K_PGD_LEVEL_NUM) {
		host_local_flush_tlb_range(&cur_gmm->context, start, end, cpu,
					   trace_enabled);
	} else {
		KVM_BUG_ON(true);
	}

	kvm_flush_remote_tlbs(kvm);

	put_cpu();
}

void host_flush_shadow_pt_tlb_range(struct kvm_vcpu *vcpu,
		gva_t start, gva_t end, pgprot_t spte, int level)
{
	bool trace_enabled = trace_host_flush_tlb_enabled();
	gmm_struct_t *cur_gmm = pv_vcpu_get_gmm(vcpu);

	KVM_BUG_ON(start >= NATIVE_TASK_SIZE);

	if (unlikely(start < GUEST_TASK_SIZE)) {
		DebugFLSPT("cpu #%d vcpu #%d gmm id #%d : range from 0x%lx "
			"to 0x%lx, level #%d spte 0x%lx\n",
			raw_smp_processor_id(), vcpu->vcpu_id, cur_gmm->nid.nr,
			start, end, level, pgprot_val(spte));

		KVM_BUG_ON(is_paging(vcpu) &&
				pv_mmu_is_init_gmm(vcpu->kvm, cur_gmm));

		if (level == E2K_PTE_LEVEL_NUM) {
			host_flush_tlb_page(cur_gmm, start);
		} else if (level == E2K_PMD_LEVEL_NUM) {
			host_flush_pmd_tlb_range(cur_gmm, start, end);
		} else if (level == E2K_PUD_LEVEL_NUM ||
					level == E2K_PGD_LEVEL_NUM) {
			host_flush_tlb_range(cur_gmm, start, end);
		} else {
			KVM_BUG_ON(true);
		}
		return;
	}

	host_flush_init_gmm_tlb_range(vcpu->kvm, cur_gmm, start, end, level,
				      trace_enabled);
}

void host_flush_shadow_pt_level_tlb(struct kvm *kvm, gmm_struct_t *gmm, gva_t gva,
			int level, pgprot_t new_spte, pgprot_t old_spte)
{
	bool trace_enabled = trace_host_flush_tlb_enabled();

	KVM_BUG_ON(gva >= NATIVE_TASK_SIZE);

	if (unlikely(gva < GUEST_TASK_SIZE)) {
		DebugFLSPT("cpu #%d gmm id #%d : shadow pt level #%d "
			"gva 0x%lx spte updated from 0x%lx to 0x%lx\n",
			raw_smp_processor_id(), gmm->nid.nr,
			level, gva, pgprot_val(old_spte), pgprot_val(new_spte));

		host_flush_tlb_page(gmm, gva);
		return;
	}

	KVM_BUG_ON(!pv_mmu_is_init_gmm(kvm, gmm));

	host_flush_init_gmm_tlb_range(kvm, gmm, gva, gva, level, trace_enabled);
}

#else	/* !CONFIG_SMP */
void host_flush_shadow_pt_tlb_range(struct kvm_vcpu *vcpu,
		gva_t start, gva_t end, pgprot_t spte, int level)
{
}

void host_flush_shadow_pt_level_tlb(struct kvm *kvm, gmm_struct_t *gmm, gva_t gva,
			int level, pgprot_t new_spte, pgprot_t old_spte)
{
}
#endif	/* CONFIG_SMP */

long kvm_pv_sync_and_flush_tlb(struct kvm_vcpu *vcpu,
				mmu_spt_flush_t __user *flush_user)
{
	mmu_spt_flush_t flush_info;
	mmu_flush_tlb_op_t opc;
	gmm_struct_t *gmm;
	unsigned long start, end, stride;
	unsigned levels_mask;
	long ret;

	if (kvm_vcpu_copy_from_guest(vcpu, &flush_info, flush_user,
					sizeof(flush_info))) {
		pr_err("%s() : copy VCPU #%d flush info from user failed\n",
			__func__, vcpu->vcpu_id);
		return -EFAULT;
	}

	opc = flush_info.opc;
	switch (opc) {
	case flush_all_tlb_op:
		/* such flushing should not be here */
		KVM_WARN_ON(true);
		gmm = NULL;
		return 0;
	case flush_kernel_range_tlb_op:
		gmm = pv_vcpu_get_init_gmm(vcpu);
		break;
	case flush_mm_page_tlb_op:
	case flush_tlb_range_tlb_op:
	case flush_mm_tlb_op:
	case flush_pmd_range_tlb_op:
	case flush_pt_range_tlb_op:
	case flush_mm_range_tlb_op:
		KVM_WARN_ON((int)flush_info.gmm_id < 0);
		gmm = kvm_find_gmmid(&vcpu->kvm->arch.gmmid_table,
					flush_info.gmm_id);
		if (gmm == NULL) {
			pr_err("%s(): could not find gmm #%d\n",
				__func__, flush_info.gmm_id);
			return -EINVAL;
		}
		break;
	default:
		pr_err("%s()^ unknown type of flush TLB operation %d\n",
			__func__, opc);
		return -EINVAL;
	}

	switch (opc) {
	case flush_all_tlb_op:
		/* such flushing should not be here */
		KVM_BUG_ON(true);
		break;
	case flush_mm_tlb_op:
		start = 0;
		end = GUEST_TASK_SIZE;
		break;
	case flush_mm_page_tlb_op:
		start = round_down(flush_info.start, PAGE_SIZE);
		end = start;
		break;
	case flush_tlb_range_tlb_op:
	case flush_pmd_range_tlb_op:
	case flush_pt_range_tlb_op:
	case flush_kernel_range_tlb_op:
		start = round_down(flush_info.start, PAGE_SIZE);
		end = round_up(flush_info.end, PAGE_SIZE);
		if (start > end) {
			pr_err("%s(): start addres of range 0x%lx > 0x%lx end\n",
				__func__, start, end);
			return -EINVAL;
		}
		break;
	case flush_mm_range_tlb_op:
		stride = flush_info.stride;
		levels_mask = flush_info.levels_mask;
		start = round_down(flush_info.start, stride);
		end = round_up(flush_info.end, stride);
		if (start > end) {
			pr_err("%s(): start addres of mm range 0x%lx > 0x%lx end\n",
				__func__, start, end);
			return -EINVAL;
		}
		break;
	default:
		pr_err("%s()^ unknown type of flush TLB operation %d\n",
			__func__, opc);
		return -EINVAL;
	}

	preempt_disable();

	/* sync the specified range of shadow PT */
	trace_host_flush_tlb_range(vcpu, gmm, opc, start, end);

	ret = mmu_pt_sync_gva_range(vcpu, gmm, start, end);

	switch (opc) {
	case flush_all_tlb_op:
		/* such flushing should not be here */
		KVM_BUG_ON(true);
		break;
	case flush_mm_tlb_op:
		host_flush_tlb_mm(gmm);
		break;
	case flush_mm_page_tlb_op:
		host_flush_tlb_page(gmm, start);
		break;
	case flush_tlb_range_tlb_op:
		host_flush_tlb_range(gmm, start, end);
		break;
	case flush_pmd_range_tlb_op:
		host_flush_pmd_tlb_range(gmm, start, end);
		break;
	case flush_pt_range_tlb_op:
		host_flush_tlb_range_and_pgtables(gmm, start, end);
		break;
	case flush_kernel_range_tlb_op:
		host_flush_tlb_kernel_range(gmm, start, end);
		break;
	case flush_mm_range_tlb_op:
		host_flush_tlb_mm_range(gmm, start, end, stride, levels_mask);
		break;
	default:
		pr_err("%s()^ unknown type of flush TLB operation %d\n",
			__func__, opc);
		ret = -EINVAL;
		goto out_failed;
	}

out_failed:
	preempt_enable();
	return ret;
}

long kvm_pv_sync_addr_range(struct kvm_vcpu *vcpu,
			gva_t start_gva, gva_t end_gva)
{
	gmm_struct_t *gmm;

	gmm = pv_vcpu_get_gmm(vcpu);
	if (unlikely(gmm == NULL)) {
		KVM_WARN_ON(true);
		return -EINVAL;
	}
	return mmu_pt_sync_gva_range(vcpu, gmm,
			round_down(start_gva, PAGE_SIZE),
			round_up(end_gva, PAGE_SIZE));
}
