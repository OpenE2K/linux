#ifndef _E2K_MMAN_H_
#define _E2K_MMAN_H_

#include <linux/mm.h>

#include <uapi/asm/mman.h>
#include <asm/head.h>

#define MV_FLUSH	0x00000001

struct vm_area_struct;
struct file;
struct mm_struct;

int make_all_vma_pages_valid(struct vm_area_struct *vma, int flags);
int make_vma_pages_valid(struct vm_area_struct *vma,
	unsigned long start_addr, unsigned long end_addr);

pte_t *get_user_address_pte(struct vm_area_struct *vma, e2k_addr_t address);

int vm_munmap_notkillable(unsigned long start, size_t len);
unsigned long vm_mmap_notkillable(struct file *file, unsigned long addr,
	unsigned long len, unsigned long prot,
	unsigned long flag, unsigned long offset);

typedef enum sma_mode {
	SMA_RO,
	SMA_RW,
	SMA_NX,
	SMA_X,
	SMA_P,
	SMA_NP,
	SMA_WB_MT,
	SMA_WC_MT,
	SMA_UC_MT,
} sma_mode_t;

int e2k_set_vmm_cui(struct mm_struct *mm, int cui,
                    unsigned long code_base, unsigned long code_end);

#define VM_HW_STACK_COMMON_FLAGS (VM_PRIVILEGED | VM_DONTEXPAND)
#define VM_HW_STACK_PS_FLAGS	(VM_HW_STACK_COMMON_FLAGS | VM_HW_STACK_PS)
#define VM_HW_STACK_PCS_FLAGS	(VM_HW_STACK_COMMON_FLAGS | VM_HW_STACK_PCS)

static inline unsigned long arch_calc_vm_prot_bits(unsigned long prot,
						   unsigned long pkey)
{
	unsigned long vm_flags;
	unsigned long cui;

	/* Order of checks is important since
	 * 32BIT flag is set in protected mode */
	if (TASK_IS_PROTECTED(current))
		cui = GET_CUI_FROM_INT_PROT(prot);
	else
		cui = USER_CODES_UNPROT_INDEX(current);

	vm_flags = cui << VM_CUI_SHIFT;

	if (current_thread_info()->status & TS_MMAP_PRIVILEGED)
		vm_flags |= VM_PRIVILEGED;

	if (current_thread_info()->status & TS_MMAP_PS)
		vm_flags |= VM_HW_STACK_PS;

	if (current_thread_info()->status & TS_MMAP_PCS)
		vm_flags |= VM_HW_STACK_PCS;

	if (current_thread_info()->status & TS_MMAP_SIGNAL_STACK)
		vm_flags |= VM_SIGNAL_STACK;

	return vm_flags;
}
#define arch_calc_vm_prot_bits(prot, pkey) arch_calc_vm_prot_bits(prot, pkey)

static inline pgprot_t arch_vm_get_page_prot(unsigned long vm_flags)
{
	unsigned long page_prot;

	page_prot = vm_flags & VM_CUI;

	if (vm_flags & VM_PRIVILEGED)
		page_prot = _PAGE_SET_PRIV(page_prot);

	return __pgprot(page_prot);
}
#define arch_vm_get_page_prot(vm_flags) arch_vm_get_page_prot(vm_flags)

static inline int arch_validate_prot(unsigned long prot, unsigned long addr)
{
	if (prot & PROT_CUI)
		return 0;
	return 1;
}
#define arch_validate_prot(prot, addr) arch_validate_prot(prot, addr)

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

extern int no_writecombine;

/*
 * execute_mmu_operations() return values
 */
enum exec_mmu_ret {
	/* Successfully executed, go to the next trap cellar record */
	EXEC_MMU_SUCCESS = 1,
	/* Stop handling trap cellar and exit */
	EXEC_MMU_STOP,
	/* Trap cellar record should be executed again */
	EXEC_MMU_REPEAT
};
extern enum exec_mmu_ret execute_mmu_operations(trap_cellar_t *tcellar,
		trap_cellar_t *next_tcellar, struct pt_regs *regs,
		int zeroing, e2k_addr_t *addr,
		bool (*is_spill_fill_recovery)(tc_cond_t cond,
					e2k_addr_t address, bool s_f,
					struct pt_regs *regs),
		enum exec_mmu_ret (*calculate_rf_frame)(struct pt_regs *regs,
					tc_cond_t cond, u64 **radr,
					bool *load_to_rf));

#endif /* _E2K_MMAN_H_ */
