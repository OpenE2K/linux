/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Usermode trampolines for returning from signal handlers and coroutines.
 */

#include <linux/elf.h>
#include <linux/mm.h>
#include <linux/err.h>
#include <asm/page.h>
#include <asm/stacks.h>

static vm_fault_t trampolines_fault(const struct vm_special_mapping *sm,
		struct vm_area_struct *vma, struct vm_fault *vmf)
{
	phys_addr_t pa = node_kernel_address_to_phys(numa_node_id(),
			(unsigned long) __trampolines_start + vmf->pgoff * PAGE_SIZE);
	BUG_ON(IS_ERR_VALUE(pa));

	return vmf_insert_pfn(vma, vmf->address, __phys_to_pfn(pa));
}

static int trampolines_mremap(const struct vm_special_mapping *sm,
			      struct vm_area_struct *new_vma)
{
	/* Needed for CRIU to move the trampolines area to its old position */
	current->mm->context.trampolines = new_vma->vm_start;
	return 0;
}

static const struct vm_special_mapping mapping_info = {
	.name = "[trampolines]",
	/* Use page fault instead of static map
	 * to find the duplicate from current node */
	.fault = trampolines_fault,
	.mremap = trampolines_mremap,
};

static int setup_additional_pages(struct mm_struct *mm)
{
	struct vm_area_struct *vma;
	unsigned long base, size;

	base = USER_TRAMPOLINES_BASE;

	BUG_ON(!PAGE_ALIGNED(__trampolines_start) || !PAGE_ALIGNED(__trampolines_end));
	size = (unsigned long) __trampolines_end - (unsigned long) __trampolines_start;

	/* Create the mapping */
	vma = _install_special_mapping(mm, base, size,
			VM_READ | VM_EXEC | VM_MAYREAD | VM_MAYEXEC| VM_PFNMAP,
			&mapping_info);
	if (IS_ERR(vma))
		return PTR_ERR(vma);

	current->mm->context.trampolines = base;

	return 0;
}

int arch_setup_additional_pages(struct linux_binprm *bprm, int uses_interp)
{
	struct mm_struct *mm = current->mm;
	int ret;

	if (mmap_write_lock_killable(mm))
		return -EINTR;

	ret = setup_additional_pages(mm);
	mmap_write_unlock(mm);

	return ret;
}
