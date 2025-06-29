/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * This is implementation of system call handlers for E2K protected mode.
 */

#include <linux/syscalls.h>
#include <asm/e2k_debug.h>

#include <asm/mman.h>

#ifdef CONFIG_PROTECTED_MODE

#include <asm/protected_syscalls.h>


/**
 * get_descriptor_ranges_on_stacks() - search for stack boundaries for the given address
 * @addr: address to search for providing it's within stack boundaries
 * @pBase: pointer to return lower boundary if any
 * @pSize: pointer to return size of descriptor
 * @options: 3rd argument to the 'unsafe_uint64_to_ptr' syscall
 * @regs: 'pt_regs' structure pointer
 *
 * Return: 0 - address found; -ESRCH - address out of mm ranges.
 */
static inline
int get_descriptor_ranges_on_stacks(unsigned long addr,
					   e2k_addr_t *pBase, unsigned long *pLength, int options,
					   struct pt_regs *regs)
{
	u64 sp, stack_size, top;

	DbgSCP("(addr=0x%lx) :: top=0x%llx usd=0x%llx:0x%llx\n",
	       addr, regs->stacks.top, regs->stacks.usd.lo, regs->stacks.usd.hi);
	calculate_e2k_dstack_parameters(&regs->stacks, &sp, &stack_size, &top);
	DbgSCP("(addr=0x%lx) :: sp=0x%llx stack_size=0x%llx top=0x%llx\n",
	       addr, sp, stack_size, top);
	if (addr >= sp && addr < top) {
		int mode = options;

		if (!mode)
			mode = current->mm->context.pm_sc_unsafe_uint64_to_ptr_mode;
		*pBase = sp;
		*pLength = (mode & PM_SC_UNSAFE_UINT64_TO_PTR_WHOLE_STACK_MODE) ? stack_size
										: top - sp;
		DbgSCP("(addr=0x%lx) :: base=0x%lx length=%lx\n", addr, *pBase, *pLength);
		return 0;
	}

	return -ESRCH;
}

/**
 * get_descriptor_ranges_on_mm() - search for boundaries in MM for the given address
 * @addr: address to search for
 * @pBase: pointer to return lower boundary if any
 * @pSize: pointer to return size of descriptor
 * @regs: 'pt_regs' structure pointer
 *
 * Return: 0 - address found; -ESRCH - address out of mm ranges.
 */
static int get_descriptor_ranges_on_mm(unsigned long addr,
				       e2k_addr_t *pBase, unsigned long *pLength,
				       struct pt_regs *regs)
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

	flags = vma->vm_flags & (VM_READ | VM_WRITE);
	start = vma->vm_start;
	end = vma->vm_end;
	ret = 0;

	/* Trying to extend lower boundary: */
	for (vma = vma_lookup(mm, start - 1);
	     vma && vma->vm_flags & flags;
	     vma = vma_lookup(mm, start - 1))
		start = vma->vm_start;

	/* Trying to extend higher boundary: */
	for (vma = vma_lookup(mm, end);
	     vma && vma->vm_flags & flags;
	     vma = vma_lookup(mm, end))
		end = vma->vm_end;

out:
	mmap_read_unlock(mm);
	if (!ret) {
		*pBase = start;
		*pLength = end - start;
		DbgSCP("(addr=0x%lx) :: base=0x%lx end = 0x%lx length=0x%lx\n",
		       addr, start, end, end - start);
	}

	return ret;
}

notrace __section(".entry.text")
long sys_unsafe_uint64_to_ptr(unsigned long	addr,
			      unsigned long	options,
				const unsigned long unused3,
				const unsigned long unused4,
				const unsigned long unused5,
				const unsigned long unused6,
				struct pt_regs	*regs)
{
	e2k_addr_t base;
	e2k_ap_t ap;
	e2k_pl_t pl;
	int rv1_tag = E2K_NUMERIC_ETAG, rv2_tag = E2K_NUMERIC_ETAG;
	mm_context_t *context = &current->mm->context;
	int cui;
	e2k_cute_t __priv *ucute_p;
	e2k_cute_t cute_p;
	struct page *page;
	unsigned long length, offset; /* descriptor attributes */
	long rval = -ESRCH;

	DbgSCP("addr = 0x%lx, options = 0x%lx syscall-enabled=0x%x",
	       addr, options, check_pm_sc_debug_mode(PM_SC_UNSAFE_UINT64_TO_PTR_ENABLED));

	if (check_pm_sc_debug_mode(PM_SC_UNSAFE_UINT64_TO_PTR_ENABLED) == 0) {
		PROTECTED_MODE_WARNING(PMSCERRMSG_SC_NOT_AVAILABLE_IN_PM,
				     regs->sys_num, sys_call_ID_to_name[regs->sys_num]);
		return sys_ni_syscall();
	}

	if (!addr || addr >= user_addr_max()) { /* it doesn't look like valid address */
		PROTECTED_MODE_ALERT(PMSCERRMSG_SC_WRONG_ARG_VALUE_LX,
				     sys_call_ID_to_name[regs->sys_num], "addr", addr);
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		goto out_err;
	}

	if (unlikely(prot_sc_arg_tag(1, regs))) {
		PROTECTED_MODE_ALERT(PMSCERRMSG_UNEXP_ARG_TAG_ID,
				     regs->sys_num, sys_call_ID_to_name[regs->sys_num],
				     prot_sc_arg_tag(1, regs), 1/*argN*/);
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		goto out_err;
	}

	/* Calculating descriptor boundaries: */

	down_read(&context->cut_mask_lock);
	for_each_used_cui(cui, context) {
		ucute_p = get_cut_entry_pointer(cui, &page);
		DbgSCP("(0x%lx) :: cui=0x%x cute_p=0x%lx\n", addr, cui, (unsigned long)ucute_p);
		if (!ucute_p)
			continue;
		rval =  copy_from_priv(&cute_p, ucute_p, sizeof(cute_p));
		if (rval) {
			rval = -ESRCH;
			break;
		}

		DbgSCP("\tcute_p: gd=0x%llx:0x%llx cud=0x%llx:0x%llx\n",
		       cute_p.gd.lo, cute_p.gd.hi, cute_p.cud.lo, cute_p.cud.hi);
		/* Looking for boundaries in GD: */
		if (addr >= GD_BASE(cute_p.gd) &&
					addr < (GD_BASE(cute_p.gd) + GD_SIZE(cute_p.gd))) {
			base = GD_BASE(cute_p.gd);
			length = GD_SIZE(cute_p.gd);
			rval = 0;
			up_read(&context->cut_mask_lock);
			goto boundaries_found;
		}
		/* Looking for boundaries in CUD: */
		if (addr >= CUD_BASE(cute_p.cud) &&
					addr < (CUD_BASE(cute_p.cud) + CUD_SIZE(cute_p.cud))) {
			pl = new_pl(addr, cui);
			up_read(&context->cut_mask_lock);
			goto pl_out;
		}
	}
	up_read(&context->cut_mask_lock);
	if (rval)
		goto out_err;

	/* Looking for boundaries in stacks: */
	rval = get_descriptor_ranges_on_stacks(addr, &base, &length, options, regs);
	if (!rval)
		goto boundaries_found;

	/* Looking for boundaries in MM: */
	rval = get_descriptor_ranges_on_mm(addr, &base, &length, regs);
	if (!rval)
		goto boundaries_found;
	else if (rval > 0)
		goto out_err;

	/* Nothing found. Address is illegal. */

	DbgSCP("(0x%lx) :: no ranges found in CUD/CUT/MM\n", addr);

	rval = -ESRCH;

boundaries_found:
	if (!access_ok(base, length)) {
		PROTECTED_MODE_ALERT(PMSCERRMSG_SC_WRONG_ARG_VALUE_LX,
				     sys_call_ID_to_name[regs->sys_num], "addr", addr);
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, ESRCH);
		goto out_err;
	}
	offset = addr - base;
	DbgSCP("(0x%lx) :: base=0x%lx length=0x%lx offset=0x%lx // 1st out byte: 0x%lx\n",
	       addr, base, length, addr - base, base + length);

	ap = new_ap(base, length, offset, RW_ENABLE);
	rv1_tag = E2K_AP_LO_ETAG;
	rv2_tag = E2K_AP_HI_ETAG;

ap_out:
	DbgSCP("(0x%lx) :: rval = %ld (0x%lx) dscr = 0x%llx : 0x%llx.%.llx  t1/t2=0x%x/0x%x\n",
	       addr, rval, rval, AP_BASE(ap), (u64)AP_SIZE(ap), (u64)AP_IND(ap), rv1_tag, rv2_tag);
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
	regs->rv2_tag = ETAGPL & 0xf0;
	DbgSCP("(0x%lx) :: rval = %ld (0x%lx) pl = 0x%llx : 0x%llx.%.llx  t1/t2=0x%x/0x%x\n",
	       addr, rval, rval, pl.lo, pl.hi, (u64)AP_IND(ap), regs->rv1_tag, regs->rv2_tag);
	return rval;
out_err:
	ap.lo = 0;
	ap.hi = 0;
	goto ap_out;
}

#endif /* CONFIG_PROTECTED_MODE */
