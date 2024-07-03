/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */


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
#include <linux/pgtable.h>

#include <asm/mmu_context.h>
#include <asm/mman.h>
#include <asm/mmu_fault.h>
#include <asm/mmu_types.h>
#include <asm/copy-hw-stacks.h>

#include <asm/kvm/hypercall.h>
#include <asm/kvm/priv-hypercall.h>

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

#undef	DEBUG_KVM_RETRY_MODE
#undef	DebugRETRY
#define	DEBUG_KVM_RETRY_MODE		0	/* memory copy retries debug */
#define	DebugRETRY(fmt, args...)					\
({									\
	if (DEBUG_KVM_RETRY_MODE)					\
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
		!opc->pm && !TASK_IS_PROTECTED(current);
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

unsigned long __kvm_copy_to_priv_user_with_tags(void __user *to,
					const void *from, unsigned long n)
{
	unsigned long _to = (unsigned long)to, _from = (unsigned long)from;
	unsigned long ret, head, mid, tail, k_addr, end_mid;
	struct page *u_page;

	head = (n > PAGE_SIZE - offset_in_page(_to)) ?
				PAGE_SIZE - offset_in_page(_to) : n;
	mid = (n - head > PAGE_SIZE) ?
			((n - head) - offset_in_page(_to + n)) : 0;
	tail = n - head - mid;

	/* Copy head (from "to" to start of next page) */
	if (head) {
		u_page = get_user_addr_to_kernel_page(_to);
		if (IS_ERR_OR_NULL(u_page)) {
			ret = (IS_ERR(u_page)) ? PTR_ERR(u_page) : -EINVAL;
		} else {
			k_addr = ((unsigned long)page_address(u_page)) +
							(_to & ~PAGE_MASK);
			ret = HYPERVISOR_copy_in_user_with_tags((void *)k_addr,
						(const void *)_from, head);
			put_user_addr_to_kernel_page(u_page);
		}

		if (ret)
			return ret;

		_to += head;
		_from += head;
	}

	/* Copy middle (whole pages) */
	if (mid) {
		end_mid = _to + mid;
		for (; _to < end_mid; _to += PAGE_SIZE, _from += PAGE_SIZE) {

			u_page = get_user_addr_to_kernel_page(_to);
			if (IS_ERR_OR_NULL(u_page)) {
				ret = (IS_ERR(u_page)) ? PTR_ERR(u_page) :
							-EINVAL;
			} else {
				k_addr = (unsigned long)page_address(u_page);
				ret = HYPERVISOR_copy_in_user_with_tags(
					(void *)k_addr, (const void *)_from,
					PAGE_SIZE);
				put_user_addr_to_kernel_page(u_page);
			}

			if (ret)
				return ret;
		}
	}

	/* Copy tail (from end of page to "to" + n) */
	if (tail) {
		u_page = get_user_addr_to_kernel_page(_to);
		if (IS_ERR_OR_NULL(u_page)) {
			ret = (IS_ERR(u_page)) ? PTR_ERR(u_page) :
				-EINVAL;
		} else {
			k_addr = ((unsigned long)page_address(u_page)) +
							(_to & ~PAGE_MASK);
			ret = HYPERVISOR_copy_in_user_with_tags((void *)k_addr,
						(const void *)_from, tail);
			put_user_addr_to_kernel_page(u_page);
		}

		if (ret)
			return ret;
	}

	return 0;
}

unsigned long __kvm_copy_from_priv_user_with_tags(void *to,
				const void __user *from, unsigned long n)
{
	unsigned long _to = (unsigned long) to, _from = (unsigned long) from;
	unsigned long ret, head, mid, tail, k_addr, end_mid;
	struct page *u_page;

	head = (n > PAGE_SIZE - offset_in_page(_from)) ?
		PAGE_SIZE - offset_in_page(_from) : n;
	mid = (n - head > PAGE_SIZE) ?
		((n - head) - offset_in_page(_from + n)) : 0;
	tail = n - head - mid;

	/* Copy head (from "from" to start of next page) */
	if (head) {
		u_page = get_user_addr_to_kernel_page(_from);
		if (IS_ERR_OR_NULL(u_page)) {
			ret = (IS_ERR(u_page)) ? PTR_ERR(u_page) : -EINVAL;
		} else {
			k_addr = ((unsigned long)page_address(u_page)) +
							(_from & ~PAGE_MASK);
			ret = HYPERVISOR_copy_in_user_with_tags((void *)_to,
						(const void *)k_addr, head);
			put_user_addr_to_kernel_page(u_page);
		}

		if (ret)
			return ret;

		_to += head;
		_from += head;
	}

	/* Copy middle (whole pages) */
	if (mid) {
		end_mid = _from + mid;
		for (; _from < end_mid; _from += PAGE_SIZE, _to += PAGE_SIZE) {

			u_page = get_user_addr_to_kernel_page(_from);
			if (IS_ERR_OR_NULL(u_page)) {
				ret = (IS_ERR(u_page)) ? PTR_ERR(u_page) :
					-EINVAL;
			} else {
				k_addr = (unsigned long)page_address(u_page);
				ret = HYPERVISOR_copy_in_user_with_tags(
					(void *)_to,
					(const void *)k_addr, PAGE_SIZE);
				put_user_addr_to_kernel_page(u_page);
			}

			if (ret)
				return ret;
		}
	}

	/* Copy tail (from end of page to "from" + n) */
	if (tail) {
		u_page = get_user_addr_to_kernel_page(_from);
		if (IS_ERR_OR_NULL(u_page)) {
			ret = (IS_ERR(u_page)) ? PTR_ERR(u_page) :
				-EINVAL;
		} else {
			k_addr = ((unsigned long)page_address(u_page)) +
							(_from & ~PAGE_MASK);
			ret = HYPERVISOR_copy_in_user_with_tags((void *)_to,
						(const void *)k_addr, tail);
			put_user_addr_to_kernel_page(u_page);
		}

		if (ret)
			return ret;
	}

	return 0;
}

unsigned long __kvm_copy_to_priv_user(void __user *to,
					const void *from, unsigned long n)
{
	return __kvm_copy_to_priv_user_with_tags(to, from, n);
}

unsigned long __kvm_copy_from_priv_user(void *to,
				const void __user *from, unsigned long n)
{
	return __kvm_copy_from_priv_user_with_tags(to, from, n);
}

static probe_entry_t
check_native_mmu_probe(e2k_addr_t virt_addr, unsigned long probe_val)
{
	if (!DTLB_ENTRY_TEST_SUCCESSFUL(probe_val)) {
		DebugMMUOP("virt addr 0x%lx, MMU probe returned 0x%lx : "
			"exception\n",
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
	/* Order is important: first mark mm as being destroyed by clearing
	 * gmmid_nr to stop issuing TLB flushes; then actually do the drop. */
	mm->gmmid_nr = -1;
	if (gmmid_nr > 0) {
		ret = HYPERVISOR_kvm_guest_mm_drop(gmmid_nr);
		if (ret != 0) {
			pr_err("%s(): hypervisor could not drop host gmm #%d\n",
				__func__, gmmid_nr);
		}
	}
	mmu_notifier_put(mn);
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

int kvm_get_mm_notifier_locked(struct mm_struct *mm)
{
	struct mmu_notifier *mn;
	int err;

	/* create mm notifier to trace some events over mm */
	mn = mmu_notifier_get_locked(&kvm_mmu_notifier_ops, mm);
	if (IS_ERR(mn)) {
		err = PTR_ERR(mn);

		pr_warn("%s(): %s (%d) ; could not create mm notifier, "
			"error %d\n",
			__func__, current->comm, current->pid, err);

		return err != -EINTR ? err : -ERESTARTNOINTR;
	}
	DebugMN("%s (%d) created mm notifier at %px\n users %d\n",
		current->comm, current->pid, mn, mn->users);
	return 0;
}

int kvm_get_mm_notifier(struct mm_struct *mm)
{
	int ret;

	mmap_write_lock(mm);
	ret = kvm_get_mm_notifier_locked(mm);
	mmap_write_unlock(mm);
	return ret;
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

#ifdef	CONFIG_PRIV_HYPERCALLS
static long kvm_priv_recovery_faulted_tagged_store(e2k_addr_t addr, u64 wr_data,
			u64 st_rec_opc, u64 data_ext, u64 opc_ext,
			recovery_faulted_arg_t args)
{
	int ret;

	ret = HYPERVISOR_priv_recovery_faulted_store(addr, wr_data,
					st_rec_opc, data_ext, opc_ext, args);
	return ret;
}

static long kvm_priv_recovery_faulted_load(e2k_addr_t addr,
			u64 *ld_val, u8 *data_tag, u64 ld_rec_opc, int chan)
{
	int ret;

	ret = HYPERVISOR_priv_recovery_faulted_load(addr, ld_val, data_tag,
						    ld_rec_opc, chan);
	return ret;
}
static long kvm_priv_recovery_faulted_move(e2k_addr_t addr_from, e2k_addr_t addr_to,
			e2k_addr_t addr_to_hi, u64 ld_rec_opc,
			recovery_faulted_arg_t args, u32 first_time)
{
	int ret;

	ret = HYPERVISOR_priv_recovery_faulted_move(addr_from, addr_to, addr_to_hi,
					ld_rec_opc, args, first_time);
	return ret;
}
static long kvm_priv_recovery_faulted_load_to_greg(e2k_addr_t address,
			u32 greg_num_d, u64 ld_rec_opc, recovery_faulted_arg_t args,
			void *saved_greg_lo, void *saved_greg_hi)
{
	int ret;

	ret = HYPERVISOR_priv_recovery_faulted_load_to_greg(address, greg_num_d,
			ld_rec_opc, args, saved_greg_lo, saved_greg_hi);
	return ret;
}

#else	/* !CONFIG_PRIV_HYPERCALLS */
static long kvm_priv_recovery_faulted_tagged_store(e2k_addr_t addr, u64 wr_data,
			u64 st_rec_opc, u64 data_ext, u64 opc_ext,
			recovery_faulted_arg_t args)
{
	return -ENOSYS;
}

static long kvm_priv_recovery_faulted_load(e2k_addr_t addr,
			u64 *ld_val, u8 *data_tag, u64 ld_rec_opc, int chan)
{
	return -ENOSYS;
}
static long kvm_priv_recovery_faulted_move(e2k_addr_t addr_from, e2k_addr_t addr_to,
			e2k_addr_t addr_to_hi, u64 ld_rec_opc,
			recovery_faulted_arg_t args, u32 first_time)
{
	return -ENOSYS;
}
static long kvm_priv_recovery_faulted_load_to_greg(e2k_addr_t address,
			u32 greg_num_d, u64 ld_rec_opc, recovery_faulted_arg_t args,
			void *saved_greg_lo, void *saved_greg_hi)
{
	return -ENOSYS;
}
#endif	/* CONFIG_PRIV_HYPERCALLS */

long kvm_recovery_faulted_tagged_store(e2k_addr_t address, u64 wr_data,
		u32 data_tag, u64 st_rec_opc, u64 data_ext, u32 data_ext_tag,
		u64 opc_ext, int chan, int qp_store, int atomic_store)
{
	static unsigned long faulted_store_IP = 0UL;
	unsigned long to_save_replaced_IP;
	recovery_faulted_arg_t args = {
		.chan = chan,
		.qp = !!qp_store,
		.atomic = !!atomic_store,
		.tag = data_tag,
		.tag_ext = data_ext_tag
	};
	long hret;

	DebugKVMREC("started for address 0x%lx data 0x%llx tag 0x%x, "
		"channel #%d\n", address, wr_data, data_tag, chan);
	if (unlikely(faulted_store_IP == 0)) {
		hret = 0;
		goto out;
	}

	/* return IP is inverted to tell the host that the return */
	/* should be on the host privileged action handler */
	SAVE_REPLACE_USR_PFAULT(0 - faulted_store_IP, to_save_replaced_IP);

	hret = kvm_priv_recovery_faulted_tagged_store(address, wr_data,
			st_rec_opc, data_ext, opc_ext, args);
	if (likely(hret == 0)) {
		goto restore_out;
	}

	/* restore not inverted IP */
	REPLACE_USR_PFAULT(faulted_store_IP);

	if (hret == -ENOSYS) {
		/* recovery as privileged action is disable */
		;
	} else {
		/* recovery failed */
		goto failed;
	}

again:
	if (likely(is_simple_ldst_op(st_rec_opc, (tc_cond_t) {.word = 0})) &&
			!data_tag) {
		simple_recovery_faulted_store(address, wr_data, st_rec_opc);
		hret = 0;
		goto restore_out;
	} else if (IS_HOST_KERNEL_ADDRESS(address)) {
		hret = HYPERVISOR_recovery_faulted_tagged_guest_store(address,
				wr_data, st_rec_opc, data_ext, opc_ext, args);
	} else {
		hret = HYPERVISOR_recovery_faulted_tagged_store(address,
				wr_data, st_rec_opc, data_ext, opc_ext, args);
	}

failed:
	if (hret == -EAGAIN) {
		DebugKVMREC("%s(): retry store to address 0x%lx data 0x%llx tag 0x%x, "
			"channel #%d\n",
			__func__, address, wr_data, data_tag, chan);
		goto again;
	}

	if (!hret) {
		DebugKVMREC("started for address 0x%lx data 0x%llx tag 0x%x, "
			"channel #%d\n", address, wr_data, data_tag, chan);
	} else {
		pr_err("%s(): failed for address 0x%lx data 0x%llx tag 0x%x, "
			"channel #%d, error %ld\n",
			__func__, address, wr_data, data_tag, chan, hret);
	}

restore_out:
	RESTORE_REPLACED_USR_PFAULT(to_save_replaced_IP);

out:
	E2K_CMD_SEPARATOR;
	faulted_store_IP = NATIVE_READ_IP_REG_VALUE();
	return hret;
}

long kvm_recovery_faulted_load(e2k_addr_t address, u64 *ld_val, u8 *data_tag,
				u64 ld_rec_opc, int chan, tc_cond_t cond)
{
	static unsigned long faulted_load_IP = 0UL;
	unsigned long to_save_replaced_IP;
	long hret;

	DebugKVMREC("started for address 0x%lx, channel #%d\n", address, chan);
	if (unlikely(faulted_load_IP == 0)) {
		hret = 0;
		goto out;
	}

	/* return IP is inverted to tell the host that the return */
	/* should be on the host privileged action handler */
	SAVE_REPLACE_USR_PFAULT(0 - faulted_load_IP, to_save_replaced_IP);

	hret = kvm_priv_recovery_faulted_load(address, ld_val, data_tag,
					      ld_rec_opc, chan);
	if (likely(hret == 0)) {
		goto restore_out;
	}

	/* restore not inverted IP */
	REPLACE_USR_PFAULT(faulted_load_IP);

	if (hret == -ENOSYS) {
		/* recovery as privileged action is disable */
		;
	} else {
		/* recovery failed */
		goto failed;
	}

again:
	if (likely(is_simple_ldst_op(ld_rec_opc, cond))) {
		simple_recovery_faulted_move(address, (e2k_addr_t) ld_val,
						ld_rec_opc, 1, cond);
		if (data_tag)
			*data_tag = 0;
		hret = 0;
		goto restore_out;
	} else if (unlikely(IS_HOST_KERNEL_ADDRESS(address) ||
			IS_HOST_KERNEL_ADDRESS((e2k_addr_t)ld_val) ||
			IS_HOST_KERNEL_ADDRESS((e2k_addr_t)data_tag))) {
		hret = HYPERVISOR_recovery_faulted_guest_load(address, ld_val,
					data_tag, ld_rec_opc, chan);
	} else {
		hret = HYPERVISOR_recovery_faulted_load(address, ld_val,
					data_tag, ld_rec_opc, chan);
	}

failed:
	if (hret == -EAGAIN) {
		DebugKVMREC("%s(): retry ld from address 0x%lx, channel #%d\n",
			__func__, address, chan);
		goto again;
	}

	if (!hret) {
		DebugKVMREC("loaded data 0x%llx tag 0x%x from address 0x%lx\n",
				*ld_val, *data_tag, address);
	} else {
		pr_err("%s(): failed loading data 0x%llx tag 0x%x "
			"from address 0x%lx, error %ld\n",
			__func__, *ld_val, *data_tag, address, hret);
	}

restore_out:
	RESTORE_REPLACED_USR_PFAULT(to_save_replaced_IP);

out:
	E2K_CMD_SEPARATOR;
	faulted_load_IP = NATIVE_READ_IP_REG_VALUE();
	return hret;
}

long kvm_recovery_faulted_move(e2k_addr_t addr_from, e2k_addr_t addr_to,
		e2k_addr_t addr_to_hi, int vr, u64 ld_rec_opc,
		int chan, int qp_load, int atomic_load, u32 first_time,
		tc_cond_t cond)
{
	static unsigned long faulted_move_IP = 0UL;
	unsigned long to_save_replaced_IP;
	recovery_faulted_arg_t args = {
		.chan = chan,
		.qp = !!qp_load,
		.atomic = !!atomic_load,
		.vr = vr,
	};
	long hret;

	DebugKVMREC("started for address from 0x%lx to addr 0x%lx, "
		"channel #%d\n",
		addr_from, addr_to, chan);
	if (unlikely(faulted_move_IP == 0)) {
		hret = 0;
		goto out;
	}

	/* return IP is inverted to tell the host that the return */
	/* should be on the host privileged action handler */
	SAVE_REPLACE_USR_PFAULT(0 - faulted_move_IP, to_save_replaced_IP);

	hret = kvm_priv_recovery_faulted_move(addr_from, addr_to, addr_to_hi,
			ld_rec_opc, args, first_time);
	if (likely(hret == 0)) {
		goto restore_out;
	}

	/* restore not inverted IP */
	REPLACE_USR_PFAULT(faulted_move_IP);

	if (hret == -ENOSYS) {
		/* recovery as privileged action is disable */
		;
	} else {
		/* recovery failed */
		goto failed;
	}

again:
	if (likely(is_simple_ldst_op(ld_rec_opc, cond)) && vr) {
		simple_recovery_faulted_move(addr_from, addr_to, ld_rec_opc,
						first_time, cond);
		hret = 0;
		goto restore_out;
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

failed:
	if (hret == -EAGAIN) {
		DebugKVMREC("%s(): retry move from addr 0x%lx to addr 0x%lx, "
			"channel #%d\n",
			__func__, addr_from, addr_to, chan);
		goto again;
	}

	if (!hret) {
		u64 val;
		u8 tag;

		if (DEBUG_KVM_RECOVERY_MODE)
			load_value_and_tagd((void *) addr_to, &val, &tag);
		DebugKVMREC("moved data 0x%llx tag 0x%x from address 0x%lx\n",
			val, tag, addr_from);
	} else {
		pr_err("%s(): failed moving from addr 0x%lx to addr 0x%lx, "
			"channel #%d, error %ld\n",
			__func__, addr_from, addr_to, chan, hret);
	}

restore_out:
	RESTORE_REPLACED_USR_PFAULT(to_save_replaced_IP);

out:
	E2K_CMD_SEPARATOR;
	faulted_move_IP = NATIVE_READ_IP_REG_VALUE();
	return hret;
}

long kvm_recovery_faulted_load_to_greg(e2k_addr_t address, u32 greg_num_d,
		int vr, u64 ld_rec_opc, int chan, int qp_load, int atomic_load,
		void *saved_greg_lo, void *saved_greg_hi, tc_cond_t cond)
{
	static unsigned long faulted_greg_IP = 0UL;
	unsigned long to_save_replaced_IP;
	recovery_faulted_arg_t args = {
		.chan = chan,
		.qp = !!qp_load,
		.atomic = !!atomic_load,
		.vr = vr,
	};
	long hret;

	DebugKVMREC("started for address 0x%lx global reg #%d, channel #%d\n",
		address, greg_num_d, chan);
	if (unlikely(faulted_greg_IP == 0)) {
		hret = 0;
		goto out;
	}

	/* return IP is inverted to tell the host that the return */
	/* should be on the host privileged action handler */
	SAVE_REPLACE_USR_PFAULT(0 - faulted_greg_IP, to_save_replaced_IP);

	hret = kvm_priv_recovery_faulted_load_to_greg(address, greg_num_d,
			ld_rec_opc, args, saved_greg_lo, saved_greg_hi);
	if (likely(hret == 0)) {
		goto restore_out;
	}

	if (hret == -ENOSYS) {
		/* recovery as privileged action is disable */
		;
	} else {
		/* recovery failed */
		goto failed;
	}

again:
	if (likely(is_simple_ldst_op(ld_rec_opc, cond))
					&& !saved_greg_lo && vr) {
		simple_recovery_faulted_load_to_greg(address, greg_num_d,
						ld_rec_opc, cond);
		hret = 0;
		goto restore_out;
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

failed:
	if (hret == -EAGAIN) {
		DebugKVMREC("%s(): retry load from addr 0x%lx to global reg #%d, "
			"channel #%d\n",
			__func__, address, greg_num_d, chan);
		goto again;
	}

	if (!hret) {
		u64 val;
		u8 tag;

		if (DEBUG_KVM_RECOVERY_MODE)
			E2K_GET_DGREG_VAL_AND_TAG(greg_num_d, val, tag);

		DebugKVMREC("loaded data 0x%llx tag 0x%x from address 0x%lx\n",
			val, tag, address);
	} else {
		pr_err("%s(): loaded data from address 0x%lx to global reg #%d, "
			"channel #%d, error %ld\n",
			__func__, address, greg_num_d, chan, hret);
	}

restore_out:
	RESTORE_REPLACED_USR_PFAULT(to_save_replaced_IP);

out:
	E2K_CMD_SEPARATOR;
	faulted_greg_IP = NATIVE_READ_IP_REG_VALUE();
	return hret;
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
again:
	if (IS_HOST_KERNEL_ADDRESS(addr_from) ||
			IS_HOST_KERNEL_ADDRESS(addr_to)) {
		hret = HYPERVISOR_move_tagged_guest_data(word_size,
							addr_from, addr_to);
	} else {
		hret = HYPERVISOR_move_tagged_data(word_size,
							addr_from, addr_to);
	}

	if (hret == -EAGAIN) {
		pr_warn("%s(): retry tagged move from 0x%lx to 0x%lx, "
			"word size : %d\n",
			__func__, addr_from, addr_to, word_size);
		goto again;
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

u64 kvm_read_dcache_l1_fault_reg(void)
{
	panic("kvm_read_l1_fault_reg() not implemented\n");
}

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
