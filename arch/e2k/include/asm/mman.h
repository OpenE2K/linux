#ifndef _E2K_MMAN_H_
#define _E2K_MMAN_H_

#include <linux/mm.h>
#include <uapi/asm/mman.h>

/*
 * When MAP_HUGETLB is set bits [26:31] encode the log2 of the huge page size.
 * This gives us 6 bits, which is enough until someone invents 128 bit address
 * spaces.
 *
 * Assume these are all power of twos.
 * When 0 use the default page size.
 */
#define MAP_HUGE_SHIFT	26
#define MAP_HUGE_MASK	0x3f


int e2k_make_pages_valid(unsigned long start_addr, unsigned long end_addr);
int make_all_vma_pages_valid(struct vm_area_struct *vma, int chprot, int flush);
int make_vma_pages_valid(struct vm_area_struct *vma,
	unsigned long start_addr, unsigned long end_addr);
int e2k_set_vmm_cui(struct mm_struct *mm, int cui,
                    unsigned long code_base, unsigned long code_end);

static inline unsigned long arch_calc_vm_prot_bits(unsigned long prot)
{
	unsigned long vm_flags;
	unsigned long cui;

	/* Order of checks is important since
	 * 32BIT flag is set in protected mode */
	if (current->thread.flags & E2K_FLAG_PROTECTED_MODE) {
		cui = GET_CUI_FROM_INT_PROT(prot);
	} else if (current->thread.flags & E2K_FLAG_32BIT) {
		if (prot & PROT_EXEC)
			/*
			 * Dynamically loadable libraries in 32-bit mode
			 * asks to apply CUI on each .text section
			 */
			cui = USER_CODES_32_INDEX;
		else
			cui = GET_CUI_FROM_INT_PROT(prot);
	} else {
		cui = USER_CODES_START_INDEX;
	}

	vm_flags = cui << VM_CUI_SHIFT;

	/*
	 * Check if we are allocating hardware stacks.
	 */
	if (current_thread_info()->status & TS_MMAP_DONTEXPAND) {
		/*
		 * VM_DONTEXPAND makes sure that even if VM_MLOCK
		 * is set, this area won't be populated on mmap().
		 */
		vm_flags |= VM_DONTEXPAND;
	}

	if (current_thread_info()->status & TS_MMAP_PRIVILEGED)
		vm_flags |= VM_PRIVILEGED;

	if (current_thread_info()->status & TS_MMAP_DONTCOPY)
		vm_flags |= VM_DONTCOPY;

	if (current_thread_info()->status & TS_MMAP_DONTMIGRATE)
		vm_flags |= VM_DONTMIGRATE;

	if (current_thread_info()->status & TS_MMAP_PS)
		vm_flags |= VM_HW_STACK_PS;

	if (current_thread_info()->status & TS_MMAP_PCS)
		vm_flags |= VM_HW_STACK_PCS;

	return vm_flags;
}
#define arch_calc_vm_prot_bits(prot) arch_calc_vm_prot_bits(prot)

static inline pgprot_t arch_vm_get_page_prot(unsigned long vm_flags)
{
	unsigned long page_prot;

	page_prot = vm_flags & VM_CUI;

	if (vm_flags & VM_PRIVILEGED)
		page_prot |= _PAGE_PV;

	return __pgprot(page_prot);
}
#define arch_vm_get_page_prot(vm_flags) arch_vm_get_page_prot(vm_flags)

static inline int arch_validate_prot(unsigned long prot)
{
	if (prot & PROT_CUI)
		return 0;
	return 1;
}
#define arch_validate_prot(prot) arch_validate_prot(prot)

static inline int arch_mmap_check(unsigned long addr, unsigned long len,
		unsigned long flags)
{
	if (TASK_IS_BINCO(current) &&
	    (!ADDR_IN_SS(addr) && ADDR_IN_SS(addr + len) ||
	     ADDR_IN_SS(addr) && !ADDR_IN_SS(addr + len)))
		return -EINVAL;

	return 0;
}
#define arch_mmap_check(addr, len, flags) arch_mmap_check(addr, len, flags)

#endif /* _E2K_MMAN_H_ */
