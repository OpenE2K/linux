
/*
 * KVM guest kernel MMU  virtualization
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/kvm_host.h>
#include <linux/kvm.h>
#include <asm/pgtable.h>
#include <asm/mmu_context.h>
#include <asm/mman.h>
#include <asm/mmu_fault.h>
#include <asm/mmu_types.h>

#include <asm/kvm/hypercall.h>

#undef	DEBUG_KVM_PTE_MODE
#undef	DebugKVMPTE
#define	DEBUG_KVM_PTE_MODE	0	/* kernel pte debugging */
#define	DebugKVMPTE(fmt, args...)					\
({									\
	if (DEBUG_KVM_PTE_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_RECOVERY_MODE
#undef	DebugKVMREC
#define	DEBUG_KVM_RECOVERY_MODE	0	/* kernel recovery debugging */
#define	DebugKVMREC(fmt, args...)					\
({									\
	if (DEBUG_KVM_RECOVERY_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_MMU_OP_MODE
#undef	DebugMMUOP
#define	DEBUG_KVM_MMU_OP_MODE	0	/* MUU operations debugging */
#define	DebugMMUOP(fmt, args...)					\
({									\
	if (DEBUG_KVM_MMU_OP_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_ACTIVATE_MM_MODE
#undef	DebugAMM
#define	DEBUG_ACTIVATE_MM_MODE	0	/* activate mm debug */
#define	DebugAMM(fmt, args...)						\
({									\
	if (DEBUG_ACTIVATE_MM_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_MMU_ACCESS_MODE
#undef	DebugKVMMMU
#define	DEBUG_KVM_MMU_ACCESS_MODE	0	/* MUU access debugging */
#define	DebugKVMMMU(fmt, args...)					\
({									\
	if (DEBUG_KVM_MMU_ACCESS_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_MM_NOTIFIER_MODE
#undef	DebugMN
#define	DEBUG_MM_NOTIFIER_MODE	0	/* MM notifier operations debug */
#define	DebugMN(fmt, args...)					\
({									\
	if (DEBUG_MM_NOTIFIER_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

static bool is_simple_ldst_op(u64 ldst_rec_opc, tc_cond_t cond)
{
	ldst_rec_op_t *opc = (ldst_rec_op_t *) &ldst_rec_opc;
	bool is_simple_lock_check_ld = tc_cond_is_check_ld(cond) ||
				tc_cond_is_check_unlock_ld(cond) ||
				tc_cond_is_lock_check_ld(cond) ||
				tc_cond_is_spec_lock_check_ld(cond);

	return (!opc->mas || is_simple_lock_check_ld) &&
		!opc->prot && !opc->root && !opc->mode_h && !opc->fmt_h &&
		(opc->fmt >= LDST_BYTE_FMT) && (opc->fmt <= LDST_DWORD_FMT) &&
		!TASK_IS_PROTECTED(current);
}

static void simple_recovery_faulted_load_to_greg(e2k_addr_t address,
				u32 greg_num_d, u64 ld_rec_opc, tc_cond_t cond)
{
	if (tc_cond_is_lock_check_ld(cond)) {
		SIMPLE_RECOVERY_LOAD_TO_GREG(address, ld_rec_opc, greg_num_d,
						",sm", 0x0);
	} else if (tc_cond_is_spec_lock_check_ld(cond)) {
		SIMPLE_RECOVERY_LOAD_TO_GREG(address, ld_rec_opc, greg_num_d,
						",sm", 0x3);
	} else {
		SIMPLE_RECOVERY_LOAD_TO_GREG(address, ld_rec_opc, greg_num_d,
						"", 0x0);
	}
}

static void simple_recovery_faulted_move(e2k_addr_t addr_from,
			e2k_addr_t addr_to, u64 ldst_rec_opc, u32 first_time,
			tc_cond_t cond)
{
	if (tc_cond_is_lock_check_ld(cond)) {
		SIMPLE_RECOVERY_MOVE(addr_from, addr_to, ldst_rec_opc,
				first_time, ",sm", 0x0);
	} else if (tc_cond_is_spec_lock_check_ld(cond)) {
		SIMPLE_RECOVERY_MOVE(addr_from, addr_to, ldst_rec_opc,
				first_time, ",sm", 0x3);
	} else {
		SIMPLE_RECOVERY_MOVE(addr_from, addr_to, ldst_rec_opc,
				first_time, "", 0x0);
	}
}

static void simple_recovery_faulted_store(e2k_addr_t address, u64 wr_data,
				u64 st_rec_opc)
{
	SIMPLE_RECOVERY_STORE(address, wr_data, st_rec_opc);
}

static probe_entry_t
check_native_mmu_probe(e2k_addr_t virt_addr, unsigned long probe_val)
{
	if (!DTLB_ENTRY_TEST_SUCCESSFUL(probe_val)) {
		DebugMMUOP("virt addr 0x%lx, MMU probe returned 0x%lx : "
			"probe disabled\n",
			virt_addr, probe_val);
	} else if (DTLB_ENTRY_TEST_VVA(probe_val)) {
		DebugMMUOP("virt addr 0x%lx, MMU probe returned 0x%lx : "
			"adrress valid\n",
			virt_addr, probe_val);
	} else {
		DebugMMUOP("virt addr 0x%lx, MMU probe returned 0x%lx\n",
			virt_addr, probe_val);
	}

	/* native MMU probe returns pfn, but guest understand only gfn */
	/* so return always disable result of probe */
	return __probe_entry(ILLEGAL_PAGE_EP_RES);
}
/* Get Entry probe for virtual address */
probe_entry_t
kvm_mmu_entry_probe(e2k_addr_t virt_addr)
{
	unsigned long probe_val;

	probe_val = HYPERVISOR_mmu_probe(virt_addr, KVM_MMU_PROBE_ENTRY);

	return check_native_mmu_probe(virt_addr, probe_val);
}
/* Get physical address for virtual address */
probe_entry_t
kvm_mmu_address_probe(e2k_addr_t virt_addr)
{
	unsigned long probe_val;

	probe_val = HYPERVISOR_mmu_probe(virt_addr, KVM_MMU_PROBE_ADDRESS);

	return check_native_mmu_probe(virt_addr, probe_val);
}

#ifdef	CONFIG_KVM_SHADOW_PT

pgprot_t kvm_pt_atomic_update(struct mm_struct *mm,
			unsigned long addr, pgprot_t *ptp,
			pt_atomic_op_t atomic_op, pgprotval_t prot_mask)
{
	pgprot_t oldptval;
	gpa_t gpa;
	int gmmid_nr;
	int ret;

	DebugKVMPTE("started for address 0x%lx\n", addr);
	/* FIXME: sinchronization on mm should be here */
	oldptval = *ptp;

	switch (atomic_op) {
	case ATOMIC_GET_AND_XCHG:
	case ATOMIC_GET_AND_CLEAR: {
		pte_t pteval = __pte(pgprot_val(oldptval));

		if (pte_none(pteval)) {
			if (!pte_valid(pteval)) {
				DebugKVMPTE("pte 0x%lx is none & not valid "
					"for addr 0x%lx\n",
					pte_val(pteval), addr);
				return __pgprot(pte_val(pteval));
			} else if (atomic_op == ATOMIC_GET_AND_CLEAR) {
				DebugKVMPTE("pte 0x%lx is already now and "
					"should be as valid for addr 0x%lx\n",
					pte_val(pteval), addr);
				return __pgprot(pte_val(pteval));
			} else if (pte_valid(__pte(prot_mask))) {
				DebugKVMPTE("pte 0x%lx is already now and new "
					"value should be as valid for "
					"addr 0x%lx\n",
					pte_val(pteval), addr);
				return __pgprot(pte_val(pteval));
			}
		}
		break;
	}
	case ATOMIC_TEST_AND_CLEAR_YOUNG:
	case ATOMIC_SET_WRPROTECT: {
		pte_t pteval = __pte(pgprot_val(oldptval));

		if (pte_none(pteval)) {
			panic("%s(): pte entry 0x%lx is none and cannot be "
				"update its protections for addr 0x%lx\n",
				__func__, pte_val(pteval), addr);
		}
		break;
	}
	default:
		panic("%s(): invalid type %d of atomic PT update operations\n",
			__func__, atomic_op);
	}

	gpa = __pa(ptp);
	gmmid_nr = mm->gmmid_nr;

	if (mm != &init_mm && mm != current->mm) {
		DebugKVMPTE("mm %px id #%d is not current mm %px id #%d "
			"for addr 0x%lx\n",
			mm, gmmid_nr,
			current->mm,
			(current->mm) ? current->mm->gmmid_nr : 0, addr);
	} else if (mm != &init_mm) {
		DebugKVMPTE("current mm %px id #%d, addr 0x%lx\n",
			mm, gmmid_nr, addr);
	}
	if (addr < PAGE_OFFSET) {
		DebugKVMPTE("address 0x%lx is user address\n", addr);
		if (mm == &init_mm) {
			panic("%s(): current mm %px id #%d, addr 0x%lx\n",
				__func__, mm, gmmid_nr, addr);
		}
	} else if (mm != &init_mm) {
		panic("%s(): current mm %px id #%d is not kernel init_mm "
			"for addr 0x%lx\n",
			__func__, mm, gmmid_nr, addr);
	}

	ret = HYPERVISOR_pt_atomic_update(gmmid_nr, gpa, &oldptval, atomic_op,
						prot_mask);
	if (ret) {
		panic("%s(): could not update guest pte by host, error %d\n",
			__func__, ret);
	}
	return oldptval;
}

pgprot_t kvm_pt_atomic_clear_relaxed(pgprotval_t ptot_mask, pgprot_t *pgprot)
{
	pgprot_t oldptval;
	pte_t pteval;
	gpa_t gpa;
	int ret;

	oldptval = *pgprot;

	pteval = __pte(pgprot_val(oldptval));
	if (pte_none(pteval)) {
		panic("%s(): pte entry 0x%lx is none and cannot update "
			"its protections\n",
			__func__, pte_val(pteval));
	}

	gpa = __pa(pgprot);
	ret = HYPERVISOR_pt_atomic_update(-1, gpa, &oldptval,
				ATOMIC_TEST_AND_CLEAR_RELAXED, ptot_mask);
	if (ret) {
		panic("%s(): could not update guest pte by host, error %d\n",
			__func__, ret);
	}
	return oldptval;
}

#endif	/* CONFIG_KVM_SHADOW_PT */

pte_t kvm_get_pte_for_address(struct vm_area_struct *vma, e2k_addr_t address)
{
	pte_t	*pte;

	pte = get_user_address_pte(vma, address);
	if (pte == NULL) {
		return __pte(0);
	}
	return *pte;
}

static void kvm_mmu_notifier_release(struct mmu_notifier *mn,
				     struct mm_struct *mm)
{
	int gmmid_nr = mm->gmmid_nr;
	int ret;

	DebugMN("%s (%d) started to release mm GMMID #%d at %px (users %d) "
		"notifier at %px (users %d)\n",
		current->comm, current->pid,
		gmmid_nr, mm, atomic_read(&mm->mm_users),
		mn, mn->users);
	if (mm == &init_mm || gmmid_nr < 0) {
		panic("kvm__mmdrop() invalid mm: init_mm or GMMID %d < 0\n",
			gmmid_nr);
	}
	BUG_ON(current->mm == mm);
	if (gmmid_nr > 0) {
		ret = HYPERVISOR_kvm_guest_mm_drop(gmmid_nr);
		if (ret != 0) {
			pr_err("%s(): hypervisor could not drop host gmm #%d\n",
				__func__, gmmid_nr);
		}
	}
	mmu_notifier_put(mn);
	mm->gmmid_nr = -1;
}

static struct mmu_notifier *kvm_alloc_mm_notifier(struct mm_struct *mm)
{
	struct mmu_notifier *mn;

	mn = kzalloc(sizeof(*mn), GFP_KERNEL);
	if (!mn) {
		pr_err("%s(): %s (%d) could not allocate mm notifier, ENOMEM\n",
			__func__, current->comm, current->pid);
		return ERR_PTR(-ENOMEM);
	}
	DebugMN("%s (%d) allocated mm %px notifier at %px\n",
		current->comm, current->pid, mm, mn);

	return mn;
}

static void kvm_free_notifier(struct mmu_notifier *mn)
{
	DebugMN("%s (%d) freeing mm %px notifier at %px\n",
		current->comm, current->pid, mn->mm, mn);
	kfree(mn);
}

static const struct mmu_notifier_ops kvm_mmu_notifier_ops = {
	.release = kvm_mmu_notifier_release,
	.alloc_notifier = kvm_alloc_mm_notifier,
	.free_notifier = kvm_free_notifier,
};

void kvm_get_mm_notifier_locked(struct mm_struct *mm)
{
	struct mmu_notifier *mn;

	/* create mm notifier to trace some events over mm */
	mn = mmu_notifier_get_locked(&kvm_mmu_notifier_ops, mm);
	if (IS_ERR(mn)) {
		panic("%s(): %s (%d) ; could not create mm notifier, "
			"error %ld\n",
			__func__, current->comm, current->pid, PTR_ERR(mn));
	}
	DebugMN("%s (%d) created mm notifier at %px\n users %d\n",
		current->comm, current->pid, mn, mn->users);
}

/*
 * Memory management mman support
 */
void kvm_activate_mm(struct mm_struct *active_mm, struct mm_struct *mm)
{
	int gmmid_nr = 0;
	int ammid_nr;
	e2k_addr_t phys_ptb;
	int ret;

	if (IS_HV_GM())
		return native_activate_mm(active_mm, mm);

	DebugAMM("started on %s (%d) for mm %px\n",
		current->comm, current->pid, mm);
	if (mm == &init_mm) {
		panic("kvm_activate_mm() invalid mm: init_mm\n");
	}
	if (active_mm == NULL) {
		ammid_nr = -1;
		DebugAMM("active mm is NULL\n");
	} else {
		ammid_nr = current_thread_info()->gmmid_nr;
		DebugAMM("active mm %px GMMID %d\n", active_mm, ammid_nr);
	}
	native_activate_mm(active_mm, mm);

	/* FIXME: it need implement separate kernel and user root PTs */
	phys_ptb = __pa(mm->pgd);
	ret = HYPERVISOR_kvm_activate_guest_mm(ammid_nr, gmmid_nr, phys_ptb);
	if (ret < 0) {
		panic("%s(): hypervisor could not activate host agent #%d "
			"of guest mm\n",
			__func__, gmmid_nr);
	}
	current_thread_info()->gmmid_nr = ret;

	/* FIXME: it need delete this field from arch-independent struct */
	mm->gmmid_nr = ret;
}

/*
 * Recovery faulted store operations
 */
void kvm_recovery_faulted_tagged_store(e2k_addr_t address, u64 wr_data,
		u32 data_tag, u64 st_rec_opc, u64 data_ext, u32 data_ext_tag,
		u64 opc_ext, int chan, int qp_store, int atomic_store)
{
	long hret;

	DebugKVMREC("started for address 0x%lx data 0x%llx tag 0x%x, "
		"channel #%d\n", address, wr_data, data_tag, chan);

	if (likely(is_simple_ldst_op(st_rec_opc, (tc_cond_t) {.word = 0})) &&
			!data_tag) {
		simple_recovery_faulted_store(address, wr_data, st_rec_opc);
	} else if (IS_HOST_KERNEL_ADDRESS(address)) {
		hret = HYPERVISOR_recovery_faulted_tagged_guest_store(address,
				wr_data, data_tag, st_rec_opc, data_ext,
				data_ext_tag, opc_ext, chan, qp_store,
				atomic_store);
	} else {
		hret = HYPERVISOR_recovery_faulted_tagged_store(address,
				wr_data, data_tag, st_rec_opc, data_ext,
				data_ext_tag, opc_ext, chan, qp_store,
				atomic_store);
	}

	if (!hret) {
		DebugKVMREC("started for address 0x%lx data 0x%llx tag 0x%x, "
			"channel #%d\n", address, wr_data, data_tag, chan);
	} else {
		DebugKVMREC("started for address 0x%lx data 0x%llx tag 0x%x, "
			"channel #%d will be retried\n", address, wr_data,
			data_tag, chan);
	}
}
void kvm_recovery_faulted_load(e2k_addr_t address, u64 *ld_val, u8 *data_tag,
				u64 ld_rec_opc, int chan, tc_cond_t cond)
{
	long hret;

	DebugKVMREC("started for address 0x%lx, channel #%d\n", address, chan);

	if (likely(is_simple_ldst_op(ld_rec_opc, cond))) {
		simple_recovery_faulted_move(address, (e2k_addr_t) ld_val,
						ld_rec_opc, 1, cond);
		if (data_tag)
			*data_tag = 0;
	} else if (unlikely(IS_HOST_KERNEL_ADDRESS(address) ||
			IS_HOST_KERNEL_ADDRESS((e2k_addr_t)ld_val) ||
			IS_HOST_KERNEL_ADDRESS((e2k_addr_t)data_tag))) {
		hret = HYPERVISOR_recovery_faulted_guest_load(address, ld_val,
					data_tag, ld_rec_opc, chan);
	} else {
		hret = HYPERVISOR_recovery_faulted_load(address, ld_val,
					data_tag, ld_rec_opc, chan);
	}

	if (!hret) {
		DebugKVMREC("loaded data 0x%llx tag 0x%x from address 0x%lx\n",
				*ld_val, *data_tag, address);
	} else {
		DebugKVMREC("loading data 0x%llx tag 0x%x from address 0x%lx "
			"should be retried\n", *ld_val, *data_tag, address);
	}
}
void kvm_recovery_faulted_move(e2k_addr_t addr_from, e2k_addr_t addr_to,
		e2k_addr_t addr_to_hi, int vr, u64 ld_rec_opc,
		int chan, int qp_load, int atomic_load, u32 first_time,
		tc_cond_t cond)
{
	long hret;
	u64 val;
	u8 tag;

	DebugKVMREC("started for address from 0x%lx to addr 0x%lx, "
		"channel #%d\n",
		addr_from, addr_to, chan);
	if (likely(is_simple_ldst_op(ld_rec_opc, cond)) && vr) {
		simple_recovery_faulted_move(addr_from, addr_to, ld_rec_opc,
						first_time, cond);
	} else if (unlikely(IS_HOST_KERNEL_ADDRESS(addr_from) ||
			IS_HOST_KERNEL_ADDRESS(addr_to))) {
		hret = HYPERVISOR_recovery_faulted_guest_move(addr_from,
				addr_to, addr_to_hi, vr, ld_rec_opc, chan,
				qp_load, atomic_load, first_time);
	} else {
		hret = HYPERVISOR_recovery_faulted_move(addr_from, addr_to,
				addr_to_hi, vr, ld_rec_opc, chan,
				qp_load, atomic_load, first_time);
	}

	if (DEBUG_KVM_RECOVERY_MODE)
		load_value_and_tagd((void *) addr_to, &val, &tag);

	DebugKVMREC("moved data 0x%llx tag 0x%x from address 0x%lx %s\n",
		val, tag, addr_from, !hret ? "completed" : "will be retried");
}
void kvm_recovery_faulted_load_to_greg(e2k_addr_t address, u32 greg_num_d,
		int vr, u64 ld_rec_opc, int chan, int qp_load, int atomic_load,
		void *saved_greg_lo, void *saved_greg_hi, tc_cond_t cond)
{
	long hret;
	u64 val;
	u8 tag;

	DebugKVMREC("started for address 0x%lx global reg #%d, channel #%d\n",
		address, greg_num_d, chan);

	if (likely(is_simple_ldst_op(ld_rec_opc, cond))
					&& !saved_greg_lo && vr) {
		simple_recovery_faulted_load_to_greg(address, greg_num_d,
						ld_rec_opc, cond);
	} else if (unlikely(IS_HOST_KERNEL_ADDRESS(address) ||
			IS_HOST_KERNEL_ADDRESS((e2k_addr_t)saved_greg_lo))) {
		hret = HYPERVISOR_recovery_faulted_load_to_guest_greg(address,
			greg_num_d, vr, ld_rec_opc, chan,
			qp_load, atomic_load, saved_greg_lo, saved_greg_hi);
	} else {
		hret = HYPERVISOR_recovery_faulted_load_to_greg(address,
			greg_num_d, vr, ld_rec_opc, chan,
			qp_load, atomic_load, saved_greg_lo, saved_greg_hi);
	}

	if (DEBUG_KVM_RECOVERY_MODE)
		E2K_GET_DGREG_VAL_AND_TAG(greg_num_d, val, tag);

	DebugKVMREC("loaded data 0x%llx tag 0x%x from address 0x%lx %s\n",
		val, tag, address, !hret ? "completed" : "will be retried");
}
static inline void kvm_do_move_tagged_data(int word_size, e2k_addr_t addr_from,
				e2k_addr_t addr_to)
{
	long hret;

	DebugKVMREC("started for address from 0x%lx to addr 0x%lx "
		"data format : %s\n",
		addr_from, addr_to,
		(word_size == sizeof(u32)) ? "word"
			:
			((word_size == sizeof(u64)) ? "double"
				:
				((word_size == sizeof(u64) * 2) ? "quad"
					:
					"???")));
	if (IS_HOST_KERNEL_ADDRESS(addr_from) ||
			IS_HOST_KERNEL_ADDRESS(addr_to)) {
		hret = HYPERVISOR_move_tagged_guest_data(word_size,
							addr_from, addr_to);
	} else {
		hret = HYPERVISOR_move_tagged_data(word_size,
							addr_from, addr_to);
	}

	if (!hret) {
		DebugKVMREC("move from 0x%lx to 0x%lx, size = %d\n",
			addr_from, addr_to, word_size);
	} else {
		DebugKVMREC("move from 0x%lx to 0x%lx, size = %d will "
			"be retried\n", addr_from, addr_to, word_size);
	}
}
void kvm_move_tagged_word(e2k_addr_t addr_from, e2k_addr_t addr_to)
{
	kvm_do_move_tagged_data(sizeof(u32), addr_from, addr_to);
}
void kvm_move_tagged_dword(e2k_addr_t addr_from, e2k_addr_t addr_to)
{
	kvm_do_move_tagged_data(sizeof(u64), addr_from, addr_to);
}
void kvm_move_tagged_qword(e2k_addr_t addr_from, e2k_addr_t addr_to)
{
	kvm_do_move_tagged_data(sizeof(u64) * 2, addr_from, addr_to);
}
mmu_reg_t kvm_read_dtlb_reg(e2k_addr_t virt_addr)
{
	mmu_reg_t reg_value;

	DebugKVMMMU("started for address 0x%lx\n", virt_addr);
	if (IS_HV_GM()) {
		return NATIVE_READ_DTLB_REG(virt_addr);
	}
	reg_value = HYPERVISOR_read_dtlb_reg(virt_addr);
	if ((long)reg_value < 0) {
		pr_err("%s(): hypervisor could not read DTLB entry "
			"for addres 0x%lx, error %ld\n",
			__func__, virt_addr, (long)reg_value);
	}
	return reg_value;
}
void kvm_flush_dcache_line(e2k_addr_t virt_addr)
{
	long ret;

	DebugKVMMMU("started for address 0x%lx\n", virt_addr);
	ret = HYPERVISOR_flush_dcache_line(virt_addr);
	if (ret != 0) {
		pr_err("kvm_flush_dcache_line() hypervisor could not flush "
			"DCACHE line for addres 0x%lx, error %ld\n",
			virt_addr, ret);
	}
}
EXPORT_SYMBOL(kvm_flush_dcache_line);

void kvm_clear_dcache_l1_set(e2k_addr_t virt_addr, unsigned long set)
{
	long ret;

	DebugKVMMMU("started for address 0x%lx, set 0x%lx\n",
		virt_addr, set);
	ret = HYPERVISOR_clear_dcache_l1_set(virt_addr, set);
	if (ret != 0) {
		pr_err("kvm_flush_dcache_range() hypervisor could not clear "
			"DCACHE L1 set 0x%lx for addres 0x%lx, error %ld\n",
			set, virt_addr, ret);
	}
}

void kvm_flush_dcache_range(void *addr, size_t len)
{
	long ret;

	DebugKVMMMU("started for address %px size 0x%lx\n",
		addr, len);
	ret = HYPERVISOR_flush_dcache_range(addr, len);
	if (ret != 0) {
		pr_err("kvm_flush_dcache_range() hypervisor could not flush "
			"DCACHE range from %px, size 0x%lx error %ld\n",
			addr, len, ret);
	}
}
EXPORT_SYMBOL(kvm_flush_dcache_range);

void kvm_clear_dcache_l1_range(void *virt_addr, size_t len)
{
	long ret;

	DebugKVMMMU("started for address %px size 0x%lx\n",
		virt_addr, len);
	ret = HYPERVISOR_clear_dcache_l1_range(virt_addr, len);
	if (ret != 0) {
		pr_err("kvm_flush_dcache_range() hypervisor could not clear "
			"DCACHE L1 range from %px, size 0x%lx error %ld\n",
			virt_addr, len, ret);
	}
}

/*
 * Guest kernel functions can be run on any guest user processes and can have
 * arbitrary MMU contexts to track which on host is not possible, therefore
 * it is necessary to flush all instruction caches
 */
void kvm_flush_icache_all(void)
{
	long ret;

	DebugKVMMMU("started flush_icache_all()\n");
	ret = HYPERVISOR_flush_icache_all();
	if (ret != 0) {
		pr_err("%s(): hypervisor could not flush all ICACHE, "
			"error %ld\n",
			__func__, ret);
	}
}

void kvm_flush_icache_range(e2k_addr_t start, e2k_addr_t end)
{
	kvm_flush_icache_all();
}
EXPORT_SYMBOL(kvm_flush_icache_range);

void kvm_flush_icache_range_array(struct icache_range_array *icache_range_arr)
{
	kvm_flush_icache_all();
}

void kvm_flush_icache_page(struct vm_area_struct *vma, struct page *page)
{
	kvm_flush_icache_all();
}

/*
 * Guest ICACHEs can be localy flushed as user caches
 */
int kvm_flush_local_icache_range(e2k_addr_t start, e2k_addr_t end)
{
	e2k_addr_t addr;

	DebugKVMMMU("started for range from 0x%lx to 0x%lx\n",
		start, end);
	if (IS_HV_GM()) {
		native_flush_icache_range(start, end);
		return 0;
	}

	start = round_down(start, E2K_ICACHE_SET_SIZE);
	end = round_up(end, E2K_ICACHE_SET_SIZE);

	flush_ICACHE_line_begin();
	for (addr = start; addr < end; addr += E2K_ICACHE_SET_SIZE) {
		DebugKVMMMU("will flush_ICACHE_line_user() 0x%lx\n", addr);
		__flush_ICACHE_line_user(addr);
	}
	flush_ICACHE_line_end();
	return 0;
}
EXPORT_SYMBOL(kvm_flush_local_icache_range);

/*
 * Write/read DCACHE L2 registers
 */
void kvm_write_dcache_l2_reg(unsigned long reg_val, int reg_num, int bank_num)
{
	panic("kvm_write_dcache_l2_reg() not implemented\n");
}
unsigned long kvm_read_dcache_l2_reg(int reg_num, int bank_num)
{
	panic("kvm_read_dcache_l2_reg() not implemented\n");
	return -1;
}
