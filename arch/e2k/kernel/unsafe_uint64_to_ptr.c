/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * This is implementation of system call handlers for E2K protected mode.
 */

#include "asm-generic/errno-base.h"
#include "linux/export.h"
#include <linux/syscalls.h>
#include <asm/e2k_debug.h>

#include <asm/mman.h>

#ifdef CONFIG_PROTECTED_MODE

#include <asm/protected_syscalls.h>
#include <asm/unsafe_uint64_to_ptr.h>

/**
 * get_ranges_cute_on_comp_unit_or_global() - get info about CU/globals, corresponding to addr
 * @addr: address to search for providing it's within stack boundaries
 * @base: pointer to return lower boundary if any
 * @length: pointer to return size of descriptor
 * @pl: pointer to procedure label, corresponding to addr
 * @is_global: pointer to bool, which is set if addr corresponds to globals
 * @is_pl: pointer to bool, which is set if addr is PL
 * @cute: pointer to CUT entry, corresponding to addr
 * @cui: pointer to the cute index
 * @regs: 'pt_regs' structure pointer
 *
 * Return: 0 - address found; -ESRCH - address out of mm ranges.
 */
static inline int get_ranges_cute_on_comp_unit_or_global(
	unsigned long addr, e2k_addr_t *base, unsigned long *length,
	e2k_pl_t *pl, bool *is_global, bool *is_pl, e2k_cute_t *cute, int *cui,
	struct pt_regs *regs)
{
	mm_context_t *context = &current->mm->context;
	struct page *page;
	e2k_cute_t __priv *ucute_p;
	int rval = -ESRCH;
	*is_global = false;
	*is_pl = false;
	int cur_cui;
	down_read(&context->cut_mask_lock);
	for (cur_cui = 0; cur_cui < CUI_SIZE;
	     cur_cui = find_next_bit(&context->cut_mask[0], CUI_SIZE,
				     cur_cui + 1)) {
		ucute_p = get_cut_entry_pointer(cur_cui, &page);
		DbgSCP("(0x%lx) :: cui=0x%x cute_p=0x%lx\n", addr, cur_cui,
		       (unsigned long)ucute_p);
		if (!ucute_p)
			continue;
		rval = copy_from_priv(cute, ucute_p, sizeof(e2k_cute_t));
		if (rval) {
			rval = -ESRCH;
			break;
		}

		DbgSCP("\tcute_p: gd=0x%llx:0x%llx cud=0x%llx:0x%llx\n",
		       cute->gd.lo, cute->gd.hi, cute->cud.lo, cute->cud.hi);
		/* Looking for boundaries in GD: */
		if (addr >= GD_BASE(cute->gd) &&
		    addr < (GD_BASE(cute->gd) + GD_SIZE(cute->gd))) {
			*base = GD_BASE(cute->gd);
			*length = GD_SIZE(cute->gd);
			*is_global = true;
			*cui = cur_cui;
			rval = 0;
			break;
		}
		/* Looking for boundaries in CUD: */
		if (addr >= CUD_BASE(cute->cud) &&
		    addr < (CUD_BASE(cute->cud) + CUD_SIZE(cute->cud))) {
			*pl = new_pl(addr, cur_cui);
			*is_pl = true;
			*cui = cur_cui;
			rval = 0;
			break;
		}
	}
	up_read(&context->cut_mask_lock);
	return rval;
}

/**
 * get_descriptor_ranges_on_stacks() - search for stack boundaries for the given address
 * @addr: address to search for providing it's within stack boundaries
 * @base: pointer to return lower boundary if any
 * @length: pointer to return size of descriptor
 * @options: 3rd argument to the 'unsafe_uint64_to_ptr' syscall
 * @regs: 'pt_regs' structure pointer
 *
 * Return: 0 - address found; -ESRCH - address out of mm ranges.
 */
int get_descriptor_ranges_on_stacks(unsigned long addr, e2k_addr_t *base,
				    unsigned long *length, int options,
				    struct pt_regs *regs)
{
	u64 sp, stack_size, top;

	DbgSCP("(addr=0x%lx) :: top=0x%llx usd=0x%llx:0x%llx\n", addr,
	       regs->stacks.top, regs->stacks.usd.lo, regs->stacks.usd.hi);
	calculate_e2k_dstack_parameters(&regs->stacks, &sp, &stack_size, &top);
	DbgSCP("(addr=0x%lx) :: sp=0x%llx stack_size=0x%llx top=0x%llx\n", addr,
	       sp, stack_size, top);
	if (addr >= sp && addr < top) {
		int mode = options;

		if (!mode)
			mode = current->mm->context
				       .pm_sc_unsafe_uint64_to_ptr_mode;
		*base = sp;
		*length = (mode & PM_SC_UNSAFE_UINT64_TO_PTR_WHOLE_STACK_MODE) ?
				  stack_size :
				  top - sp;
		DbgSCP("(addr=0x%lx) :: base=0x%lx length=%lx\n", addr, *base,
		       *length);
		return 0;
	}

	return -ESRCH;
}

/* used by soft_pm: */
EXPORT_SYMBOL_GPL(get_descriptor_ranges_on_stacks);

/**
 * get_descriptor_ranges_on_mm() - search for boundaries in MM for the given address
 * @addr: address to search for
 * @base: pointer to return lower boundary if any
 * @length: pointer to return size of descriptor
 * @regs: 'pt_regs' structure pointer
 *
 * Return: 0 - address found; -ESRCH - address out of mm ranges.
 */
int get_descriptor_ranges_on_mm(unsigned long addr, e2k_addr_t *base,
				unsigned long *length, struct pt_regs *regs)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	int flags;
	e2k_addr_t start, end; /* boundaries */
	int ret = -ESRCH; /* if ranges not found */

	/*
	 * Parsing mm for the boundaries of the given 'addr':
	 */

	mmap_read_lock(mm);

	vma = vma_lookup(mm, addr);
	if (!vma)
		goto out;

	DbgSCP("(addr=0x%lx) vma: flags=0x%lx start=0x%lx end=0x%lx\n", addr,
	       vma->vm_flags, vma->vm_start, vma->vm_end);

	flags = vma->vm_flags & (VM_READ | VM_WRITE | VM_EXEC);
	if (flags &
	    VM_EXEC) { /* NB> We shouldn't found executable at this point */
		PROTECTED_MODE_WARNING(PMSCWARN_UNALIGNED_PL_IN_ARG,
				       "unsafe_uint64_to_ptr", addr,
				       1 /*argnum*/);
		goto out;
	}
	start = vma->vm_start;
	end = vma->vm_end;
	ret = 0;

	/* Trying to extend lower boundary: */
	for (vma = vma_lookup(mm, start - 1); vma && vma->vm_flags & flags;
	     vma = vma_lookup(mm, start - 1))
		start = vma->vm_start;

	/* Trying to extend higher boundary: */
	for (vma = vma_lookup(mm, end); vma && vma->vm_flags & flags;
	     vma = vma_lookup(mm, end))
		end = vma->vm_end;

out:
	mmap_read_unlock(mm);
	if (!ret) {
		*base = start;
		*length = end - start;
		DbgSCP("(addr=0x%lx) :: base=0x%lx end = 0x%lx length=0x%lx\n",
		       addr, start, end, end - start);
	}

	return ret;
}

/* used by soft_pm: */
EXPORT_SYMBOL_GPL(get_descriptor_ranges_on_mm);

/**
 * get_cui_by_func_addr - get CU index by address of a function
 * @addr: address of a function
 * @cute: pointer to CUT entry, corresponding to addr
 * @cui: pointer to CU index
 *
 * Return: 0 on success, -ESRCH on failure
*/
int get_cute_cui_by_func_addr(unsigned long addr, e2k_cute_t *cute, int *cui,
			      struct pt_regs *regs)
{
	if (unlikely(addr & (E2K_INSTR_ALIGNMENT - 1)))
		return -ESRCH;
	e2k_addr_t base;
	unsigned long len;
	e2k_pl_t pl;
	bool is_global = false, is_pl = false;
	int rval = get_ranges_cute_on_comp_unit_or_global(
		addr, &base, &len, &pl, &is_global, &is_pl, cute, cui, regs);
	if (!rval && is_pl)
		return 0;
	return -ESRCH;
}

/* used by soft_pm: */
EXPORT_SYMBOL_GPL(get_cute_cui_by_func_addr);

/**
 * get_descriptor_ranges_on_global_or_pl() - search for CUD/GD boundaries for the given address
 * @addr: address to search for providing it's within stack boundaries
 * @base: pointer to return lower boundary if any
 * @length: pointer to return size of descriptor
 * @pl: pointer to procedure label, corresponding to addr
 * @is_global: pointer to bool, which is set if addr corresponds to globals
 * @is_pl: pointer to bool, which is set if addr is PL
 * @regs: 'pt_regs' structure pointer
 *
 * Return: 0 - address found; -ESRCH - address out of mm ranges.
 */
int get_descriptor_ranges_on_global_or_pl(unsigned long addr, e2k_addr_t *base,
					  unsigned long *length, e2k_pl_t *pl,
					  bool *is_global, bool *is_pl,
					  struct pt_regs *regs)
{
	e2k_cute_t cute;
	int cui;
	return get_ranges_cute_on_comp_unit_or_global(
		addr, base, length, pl, is_global, is_pl, &cute, &cui, regs);
}

/* used by soft_pm: */
EXPORT_SYMBOL_GPL(get_descriptor_ranges_on_global_or_pl);

notrace __section(".entry.text") long sys_unsafe_uint64_to_ptr(
	unsigned long addr, unsigned long options, const unsigned long unused3,
	const unsigned long unused4, const unsigned long unused5,
	const unsigned long unused6, struct pt_regs *regs)
{
	e2k_addr_t base;
	e2k_ap_t ap;
	e2k_pl_t pl;
	int rv1_tag = E2K_NUMERIC_ETAG, rv2_tag = E2K_NUMERIC_ETAG;
	unsigned long length, offset; /* descriptor attributes */
	long rval = -ESRCH;

	DbgSCP("addr = 0x%lx, options = 0x%lx syscall-enabled=0x%x", addr, options,
	       check_pm_sc_debug_mode(PM_SC_UNSAFE_UINT64_TO_PTR_ENABLED));

	if (check_pm_sc_debug_mode(PM_SC_UNSAFE_UINT64_TO_PTR_ENABLED) == 0) {
		PROTECTED_MODE_WARNING(PMSCERRMSG_SC_NOT_ENABLED,
				       regs->sys_num, sys_call_ID_to_name[regs->sys_num]);
		PM_EXCEPTION_ON_WARNING(SIGABRT, SI_KERNEL, EPERM);
		return sys_ni_syscall();
	}

	if (addr < mmap_min_addr) {
		PROTECTED_MODE_WARNING(PMSCERRMSG_SC_WRONG_ARG_VALUE_LX,
				     sys_call_ID_to_name[regs->sys_num], "addr", addr);
		PM_EXCEPTION_ON_WARNING(SIGABRT, SI_KERNEL, EINVAL);
		goto out_err;
	} else if (!addr ||
	    addr >= user_addr_max()) { /* it doesn't look like valid address */
		PROTECTED_MODE_ALERT(PMSCERRMSG_SC_WRONG_ARG_VALUE_LX,
				     sys_call_ID_to_name[regs->sys_num], "addr", addr);
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		goto out_err;
	}

	if (unlikely(prot_sc_arg_tag(1, regs))) {
		PROTECTED_MODE_ALERT(PMSCERRMSG_UNEXP_ARG_TAG_ID, regs->sys_num,
				     sys_call_ID_to_name[regs->sys_num],
				     prot_sc_arg_tag(1, regs), 1 /*argN*/);
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		goto out_err;
	}

	/* Calculating descriptor boundaries: */
	bool is_global = false, is_pl = false;
	/* Looking for boundaries in globals and code sections: */
	rval = get_descriptor_ranges_on_global_or_pl(addr, &base, &length, &pl,
						     &is_global, &is_pl, regs);
	if (rval)
		goto out_err;
	if (is_pl)
		goto pl_out;
	if (is_global)
		goto boundaries_found;

	/* Looking for boundaries in stacks: */
	rval = get_descriptor_ranges_on_stacks(addr, &base, &length, options,
					       regs);
	if (!rval)
		goto boundaries_found;

	/* Looking for boundaries in MM: */
	rval = get_descriptor_ranges_on_mm(addr, &base, &length, regs);
	if (!rval)
		goto boundaries_found;

	/* Nothing found. Address is illegal. */

	DbgSCP("(0x%lx) :: no ranges found in CUD/CUT/MM\n", addr);

	rval = -ESRCH;
	goto out_err;

boundaries_found: /* for stacks, mm and globals */
	if (!access_ok((void __user *)base, length)) {
		PROTECTED_MODE_ALERT(PMSCERRMSG_SC_WRONG_ARG_VALUE_LX,
				     sys_call_ID_to_name[regs->sys_num], "addr",
				     addr);
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EPERM);
		goto out_err;
	}
	offset = addr - base;
	DbgSCP("(0x%lx) :: base=0x%lx length=0x%lx offset=0x%lx // 1st out byte: 0x%lx\n",
	       addr, base, length, addr - base, base + length);

	ap = new_ap(base, length, offset, RW_ENABLE);
	rv1_tag = E2K_AP_LO_ETAG;
	rv2_tag = E2K_AP_HI_ETAG;

ap_out:
	DbgSCP("(0x%lx) :: rval = %ld (0x%lx) dscr = 0x%llx : 0x%llx.%.8llx  t1/t2=0x%x/0x%x\n",
	       addr, rval, rval, AP_BASE(ap), (u64)AP_SIZE(ap), (u64)AP_IND(ap),
	       rv1_tag, rv2_tag);
	regs->return_desk = 1;
	regs->rval1 = ap.lo;
	regs->rval2 = ap.hi;
	regs->rv1_tag = rv1_tag;
	regs->rv2_tag = rv2_tag;
	return rval;
pl_out:
	regs->return_desk = 1;
	regs->rval1 = pl.lo;
	regs->rval2 = pl.hi;
	regs->rv1_tag = ETAGPL & 0x0f;
	regs->rv2_tag = (ETAGPL & 0xf0) >> 4;
	DbgSCP("(0x%lx) :: rval = %ld (0x%lx) pl = 0x%llx : 0x%llx  t1/t2=0x%x/0x%x\n",
	       addr, rval, rval, pl.lo, pl.hi, regs->rv1_tag, regs->rv2_tag);
	return rval;
out_err:
	ap.lo = 0;
	ap.hi = 0;
	goto ap_out;
}

#endif /* CONFIG_PROTECTED_MODE */
