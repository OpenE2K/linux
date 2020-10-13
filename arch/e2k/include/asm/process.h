/*
 * include/asm-e2k/process.h
 *
 * Copyright 2001 Salavat S. Guiliazov (atic@mcst.ru)
 */

#ifndef _E2K_PROCESS_H
#define _E2K_PROCESS_H

#include <linux/types.h>
#include <linux/compat.h>
#include <linux/syscalls.h>
#include <linux/rmap.h>

#include <asm/uaccess.h>
#include <asm/cacheflush.h>

#undef	DEBUG_SS_MODE
#undef	DebugSS
#define	DEBUG_SS_MODE		0	/* stack switching */
#define DebugSS(...)		DebugPrint(DEBUG_SS_MODE ,##__VA_ARGS__)

#undef	DEBUG_US_MODE
#undef	DebugUS
#define	DEBUG_US_MODE		0	/* user stacks */
#define DebugUS(...)		DebugPrint(DEBUG_US_MODE ,##__VA_ARGS__)

#undef	DEBUG_HS_MODE
#undef	DebugHS
#define	DEBUG_HS_MODE		0	/* hardware stacks */
#define DebugHS(...)		DebugPrint(DEBUG_HS_MODE ,##__VA_ARGS__)


/*
 * SLAB cache for task_struct structures (tsk)
 */
extern struct kmem_cache __nodedata	*task_cachep;
extern struct kmem_cache __nodedata	*thread_cachep;
#ifdef	CONFIG_NUMA
extern struct kmem_cache __nodedata	*node_policy_cache;

#define	node_task_cachep(nid)						\
		((struct kmem_cache **)__va(node_kernel_va_to_pa(nid,	\
						&task_cachep)))
#define	node_thread_cachep(nid)						\
		((struct kmem_cache **)__va(node_kernel_va_to_pa(nid,	\
						&thread_cachep)))
#define	the_node_policy_cache(nid)					\
		((struct kmem_cache **)__va(node_kernel_va_to_pa(nid,	\
						&node_policy_cache)))
#endif	/* CONFIG_NUMA */

/*
 * User hardware stack mode
 */
extern int uhws_mode;
enum {
	/*
	 * All user hardware stacks are represented by one big continuous area
	 * of user addresses. This area shouldn't come to the end. */
	UHWS_MODE_CONT,
	/*
	 * All user hardware stacks are represented by one continuous area of
	 * user addresses. If this area came to the end, than new area of bigger
	 * size will be allocated and old area will be remapped to new.
	 */
	UHWS_MODE_PSEUDO,
};
#define UHWS_PSEUDO_MODE	(likely(uhws_mode == UHWS_MODE_PSEUDO))

#define	DEBUG_PROCESS_MODE	0	/* processes */
#define DbgP(...)		DebugPrint(DEBUG_PROCESS_MODE ,##__VA_ARGS__)


extern int do_mlock_hw_stack(unsigned long, unsigned long, bool, bool);

static inline int munlock_hw_stack(unsigned long start, unsigned long len)
{
	return do_mlock_hw_stack(start, len, false, false);
}

static inline int mlock_hw_stack(unsigned long start, unsigned long len,
					bool populate)
{
	return do_mlock_hw_stack(start, len, true, populate);
}

static inline int __is_u_hw_stack_range(struct vm_area_struct *vma,
		e2k_addr_t start, e2k_addr_t end)
{
	while (vma && vma->vm_start < end) {
		if (vma->vm_flags & VM_PRIVILEGED)
			return 1;
		vma = vma->vm_next;
	}

	return 0;
}

/*
 * It should be called under closed mmap_sem
 */
static inline int is_u_hw_stack_range(e2k_addr_t start, e2k_addr_t end)
{
	struct vm_area_struct *vma = find_vma(current->mm, start);

	return __is_u_hw_stack_range(vma, start, end);
}

static inline e2k_size_t get_max_hw_stack_size(e2k_size_t user_hw_stack_size,
	e2k_size_t kernel_hw_stack_size, e2k_size_t rlim)
{
	user_hw_stack_size = PAGE_ALIGN_DOWN(user_hw_stack_size);
	kernel_hw_stack_size = PAGE_ALIGN_DOWN(kernel_hw_stack_size);

	rlim = PAGE_ALIGN_DOWN(rlim);
	if (UHWS_PSEUDO_MODE)
		rlim += kernel_hw_stack_size;

	if (rlim >= user_hw_stack_size + kernel_hw_stack_size)
		return user_hw_stack_size;
	if (rlim <= kernel_hw_stack_size)
		return 0;
	return rlim - kernel_hw_stack_size;
}

static inline e2k_size_t get_max_psp_size(e2k_size_t user_psp_size)
{
	return get_max_hw_stack_size(user_psp_size, KERNEL_P_STACK_SIZE,
			current->signal->rlim[RLIM_P_STACK_EXT].rlim_cur);
}

static inline e2k_size_t get_max_pcsp_size(e2k_size_t user_pcsp_size)
{
	return get_max_hw_stack_size(user_pcsp_size, KERNEL_PC_STACK_SIZE,
			current->signal->rlim[RLIM_PC_STACK_EXT].rlim_cur);
}

extern	int do_update_vm_area_flags(e2k_addr_t start, e2k_size_t len,
		vm_flags_t flags_to_set, vm_flags_t flags_to_clear);
extern	int create_cut_entry(int tcount,
			      unsigned long code_base, unsigned  code_sz,
			      unsigned long glob_base, unsigned  glob_sz);

extern struct hw_stack_area *alloc_user_p_stack(size_t stack_area_size,
			 size_t present_offset, size_t present_size);
extern struct hw_stack_area *alloc_user_pc_stack(size_t stack_area_size,
			 size_t present_offset, size_t present_size);

extern void *alloc_kernel_c_stack();
extern void free_kernel_c_stack(void *);

extern void free_user_old_pc_stack_areas(struct list_head *old_u_pcs_list);

extern void switch_to_kernel_hardware_stacks();

/*
 * WARNING: Interrupts should be disabled by caller
 */
extern void inline
switch_to_expanded_p_stack(s64 delta_offset, s64 delta_size)
{
	e2k_psp_lo_t	psp_lo;
	e2k_psp_hi_t 	psp_hi;
	e2k_pshtp_t	pshtp;
	s64		new_ind;

	DebugSS("started for delta: base 0x%llx, size 0x%llx\n",
		delta_offset, delta_size);

	/*
	 * Procedure stack pointers can be changed while stack expansion
	 * or interrupts, so it needs to reread current state of PSP
	 */
	psp_lo = READ_PSP_LO_REG();
	psp_hi = READ_PSP_HI_REG();
	pshtp = READ_PSHTP_REG();
	new_ind = psp_hi.PSP_hi_ind + GET_PSHTP_INDEX(pshtp);
	if (new_ind < delta_offset) {
		panic("switch_to_expanded_p_stack() PSP real index 0x%llx points below the new stack base (< new stack offset 0x%llx)\n",
			new_ind, delta_offset);
	} else if (psp_hi.PSP_hi_ind < delta_offset) {
		/*
		 * New base should be between PSP.ind and PSHTP.ind (inside
		 * procedure registers file). So it needs flush registers
		 * to memory before
		 */
		E2K_FLUSHR;
		psp_hi = READ_PSP_HI_REG();
	}
	psp_lo.PSP_lo_base += delta_offset;
	psp_hi.PSP_hi_size += delta_size;
	psp_hi.PSP_hi_ind -= delta_offset;
	/*
	 * Set PSP pointer registers to new extended stack state
	 */
	WRITE_PSP_REG(psp_hi, psp_lo);

	DebugSS("new PS state: base 0x%llx ind 0x%x size 0x%x, PSHTP.ind 0x%llx\n",
		psp_lo.PSP_lo_base, psp_hi.PSP_hi_ind, psp_hi.PSP_hi_size,
		GET_PSHTP_INDEX(pshtp));
}

/*
 * WARNING: Interrupts should be disabled by caller
 */
extern void inline
switch_to_expanded_pc_stack(s64 delta_offset, s64 delta_size)
{
	e2k_psp_lo_t	pcsp_lo;
	e2k_psp_hi_t 	pcsp_hi;
	e2k_pcshtp_t	pcshtp;
	s64		new_ind;

	DebugSS("started for delta: base 0x%llx, size 0x%llx\n",
		delta_offset, delta_size);

	/*
	 * Chain stack pointers can be changed while stack expansion
	 * or interrupts, so it needs to reread current state of PSP
	 */
	pcsp_lo = READ_PCSP_LO_REG();
	pcsp_hi = READ_PCSP_HI_REG();
	pcshtp = READ_PCSHTP_REG();
	new_ind = pcsp_hi.PCSP_hi_ind + PCSHTP_SIGN_EXTEND(pcshtp);
	if (new_ind < delta_offset) {
		panic("switch_to_expanded_pc_stack() PCSP real index 0x%llx points below the new stack base (< new stack offset 0x%llx)\n",
			new_ind, delta_offset);
	} else if (pcsp_hi.PCSP_hi_ind < delta_offset) {
		/*
		 * New base should be between PCSP.ind and PCSHTP.ind (inside
		 * procedure registers file). So it needs flush registers
		 * to memory before
		 */
		E2K_FLUSHC;
		pcsp_hi = READ_PCSP_HI_REG();
	}
	pcsp_lo.PCSP_lo_base += delta_offset;
	pcsp_hi.PCSP_hi_size += delta_size;
	pcsp_hi.PCSP_hi_ind -= delta_offset;
	/*
	 * Set PCSP pointer registers to new extended stack state
	 */
	WRITE_PCSP_REG(pcsp_hi, pcsp_lo);

	DebugSS("new PCS state: base 0x%llx ind 0x%x size 0x%x, PCSHTP.ind 0x%llx\n",
		pcsp_lo.PCSP_lo_base, pcsp_hi.PCSP_hi_ind, pcsp_hi.PCSP_hi_size,
		PCSHTP_SIGN_EXTEND(pcshtp));
}

int update_vm_area_flags(e2k_addr_t start, e2k_size_t len,
		vm_flags_t flags_to_set, vm_flags_t flags_to_clear);

/*
 * This function is based on move_ptes() function
 */
static inline void copy_user_hard_stack_ptes(
		struct vm_area_struct *vma, pmd_t *old_pmd,
		unsigned long old_addr, unsigned long old_end,
		struct vm_area_struct *new_vma, pmd_t *new_pmd,
		unsigned long new_addr)
{
	struct mm_struct *mm = vma->vm_mm;
	pte_t *old_pte, *new_pte, pte;
	spinlock_t *old_ptl, *new_ptl;

	old_pte = pte_offset_map_lock(mm, old_pmd, old_addr, &old_ptl);
	new_pte = pte_offset_map(new_pmd, new_addr);
	new_ptl = pte_lockptr(mm, new_pmd);
	if (new_ptl != old_ptl)
		spin_lock_nested(new_ptl, SINGLE_DEPTH_NESTING);

	for (; old_addr < old_end; old_pte++, old_addr += PAGE_SIZE,
				   new_pte++, new_addr += PAGE_SIZE) {
		struct page *page;

#ifndef CONFIG_MAKE_ALL_PAGES_VALID
		if (pte_none(*old_pte))
#else	/* CONFIG_MAKE_ALL_PAGES_VALID */
		if (pte_none(*old_pte) && !pte_valid(*old_pte))
#endif	/* ! !CONFIG_MAKE_ALL_PAGES_VALID */
			continue;
		/*
		 * One should increase rss MM_ANONPAGES counter to unmap
		 * correctly old user hardware stack area. But some pages of
		 * new user hardware stack area has already been allocated and
		 * marked as anon during mlock, so rss MM_ANONPAGES counter
		 * should be increased only for not anon pages.
		 */
		if (!PageAnon(pte_page(*new_pte)))
			inc_mm_counter(mm, MM_ANONPAGES);

		pte = *old_pte;
		set_pte_at(mm, new_addr, new_pte, pte);

		/*
		 * One should increase page _count and _mapcount counters to
		 * unmap correctly old user hardware stack area
		 */
		page = pte_page(pte);
		get_page(page);
		atomic_set(&page->_mapcount, page_mapcount(page));
	}

	if (new_ptl != old_ptl)
		spin_unlock(new_ptl);
	pte_unmap(new_pte - 1);
	pte_unmap_unlock(old_pte - 1, old_ptl);
}

/*
 * This function is based on move_page_tables() function
 */
static inline long copy_user_hard_stack_page_tables(struct vm_area_struct *vma,
		unsigned long old_addr, struct vm_area_struct *new_vma,
		unsigned long new_addr, unsigned long len)
{
	unsigned long extent, next, old_end;
	struct mm_struct *mm = vma->vm_mm;
	pmd_t *old_pmd, *new_pmd;
	pud_t *old_pud, *new_pud;
	pgd_t *old_pgd, *new_pgd;

	old_end = old_addr + len;

	for (; old_addr < old_end; old_addr += extent, new_addr += extent) {
		cond_resched();

		next = (old_addr + PMD_SIZE) & PMD_MASK;
		extent = next - old_addr;
		if (extent > old_end - old_addr)
			extent = old_end - old_addr;

		old_pgd = pgd_offset(mm, old_addr);
		if (pgd_none_or_clear_bad(old_pgd))
			break;
		old_pud = pud_offset(old_pgd, old_addr);
		if (pud_none_or_clear_bad(old_pud))
			break;
		old_pmd = pmd_offset(old_pud, old_addr);
		if (pmd_none(*old_pmd))
			break;

		new_pgd = pgd_offset(mm, new_addr);
		new_pud = pud_alloc(mm, new_pgd, new_addr);
		if (!new_pud)
			break;
		new_pmd = pmd_alloc(mm, new_pud, new_addr);
		if (!new_pmd)
			break;
		if (pmd_none(*new_pmd) &&
				__pte_alloc(mm, new_vma, new_pmd, new_addr))
			break;

		next = (new_addr + PMD_SIZE) & PMD_MASK;
		if (extent > next - new_addr)
			extent = next - new_addr;
		if (extent > 64 * PAGE_SIZE)
			extent = 64 * PAGE_SIZE;

		copy_user_hard_stack_ptes(vma, old_pmd, old_addr,
			old_addr + extent, new_vma, new_pmd, new_addr);
	}

	return len + old_addr - old_end;
}

static inline long
remap_user_hard_stack(void *to, void *from, e2k_size_t sz)
{
	struct mm_struct *mm = current->mm;
	e2k_addr_t new_to = (e2k_addr_t)to;
	e2k_addr_t new_from = (e2k_addr_t)from;
	e2k_size_t new_sz = sz;
	e2k_size_t retval = sz;

	down_write(&mm->mmap_sem);

	while (new_sz) {
		struct vm_area_struct *vma_to;
		struct vm_area_struct *vma_from;
		e2k_size_t len;
		e2k_size_t ret;

		vma_to = find_vma(mm, new_to);
		vma_from = find_vma(mm, new_from);
		if (!vma_to || !vma_from) {
			DebugHS("could not find vma to remap from or to\n");
			up_write(&mm->mmap_sem);
			return retval;
		}

		if (anon_vma_prepare(vma_to)) {
			DebugHS("anon_vma_prepare() returned error\n");
			up_write(&mm->mmap_sem);
			return retval;
		}

		len = min(new_sz, vma_to->vm_end - new_to);
		len = min(len, vma_from->vm_end - new_from);

		DebugHS("will remap page table from vma 0x%lx addr 0x%lx to vma 0x%lx addr 0x%lx size 0x%lx\n",
			vma_from, new_from, vma_to, new_to, len);
		ret = copy_user_hard_stack_page_tables(
				vma_from, new_from, vma_to, new_to, len);
		retval -= ret;
		if (ret != len) {
			DebugHS("move_page_tables() returned 0x%lx instead of 0x%lx\n",
				ret, len);
			up_write(&mm->mmap_sem);
			return retval;
		}

		new_to += len;
		new_from += len;
		new_sz -= len;
	};

	up_write(&mm->mmap_sem);

	return 0;
}

extern int switch_to_next_p_stack_area(void);
extern int switch_to_next_pc_stack_area(void);

static	inline int
update_vm_area_flags(e2k_addr_t start, e2k_size_t len,
		vm_flags_t flags_to_set, vm_flags_t flags_to_clear)
{
	int error = 0;

	down_write(&current->mm->mmap_sem);
	len = PAGE_ALIGN(len + (start & ~PAGE_MASK));
	start &= PAGE_MASK;

	error = do_update_vm_area_flags(start, len, flags_to_set,
					flags_to_clear);

	up_write(&current->mm->mmap_sem);
	return error;
}

extern struct task_struct *init_tasks[];

static inline int
get_user_cr0_lo(e2k_cr0_lo_t *cr0_lo, e2k_addr_t base, e2k_addr_t cr_ind)
{
	int ret;
	ret = get_user_nocheck(AS_WORD_P(cr0_lo),
				(u64 __user *)(base + cr_ind + CR0_LO_I));
	return ret;
}

static inline int
get_user_cr0_hi(e2k_cr0_hi_t *cr0_hi, e2k_addr_t base, e2k_addr_t cr_ind)
{
	int ret;
	ret = get_user_nocheck(AS_WORD_P(cr0_hi),
				(u64 __user *)(base + cr_ind + CR0_HI_I));
	return ret;
}

static inline int
get_user_cr1_lo(e2k_cr1_lo_t *cr1_lo, e2k_addr_t base, e2k_addr_t cr_ind)
{
	int ret;
	ret = get_user_nocheck(AS_WORD_P(cr1_lo),
				(u64 __user *)(base + cr_ind + CR1_LO_I));
	return ret;
}

static inline int
get_user_cr1_hi(e2k_cr1_hi_t *cr1_hi, e2k_addr_t base, e2k_addr_t cr_ind)
{
	int ret;
	ret = get_user_nocheck(AS_WORD_P(cr1_hi),
				(u64 __user *)(base + cr_ind + CR1_HI_I));
	return ret;
}

static inline int
put_user_cr1_hi(e2k_cr1_hi_t cr1_hi, e2k_addr_t base, e2k_addr_t cr_ind)
{
	int ret;
	set_ts_flag(TS_KERNEL_SYSCALL);
	ret = __put_user(AS_WORD(cr1_hi),
				(u64 __user *)(base + cr_ind + CR1_HI_I));
	clear_ts_flag(TS_KERNEL_SYSCALL);
	return ret;
}

static inline void
get_kernel_cr0_lo(e2k_cr0_lo_t *cr0_lo, e2k_addr_t base, e2k_addr_t cr_ind)
{
	AS_WORD_P(cr0_lo) = *((u64 *)(base + cr_ind + CR0_LO_I));
}

static inline void
get_kernel_cr0_hi(e2k_cr0_hi_t *cr0_hi, e2k_addr_t base, e2k_addr_t cr_ind)
{
	AS_WORD_P(cr0_hi) = *((u64 *)(base + cr_ind + CR0_HI_I));
}

static inline void
get_kernel_cr1_lo(e2k_cr1_lo_t *cr1_lo, e2k_addr_t base, e2k_addr_t cr_ind)
{
	AS_WORD_P(cr1_lo) = *((u64 *)(base + cr_ind + CR1_LO_I));
}

static inline void
get_kernel_cr1_hi(e2k_cr1_hi_t *cr1_hi, e2k_addr_t base, e2k_addr_t cr_ind)
{
	AS_WORD_P(cr1_hi) = *((u64 *)(base + cr_ind + CR1_HI_I));
}

static inline void
put_kernel_cr0_hi(e2k_cr0_hi_t cr0_hi, e2k_addr_t base, e2k_addr_t cr_ind)
{
	*((u64 *)(base + cr_ind + CR0_HI_I)) = AS_WORD(cr0_hi);
}

static inline void
put_kernel_cr0_lo(e2k_cr0_lo_t cr0_lo, e2k_addr_t base, e2k_addr_t cr_ind)
{
	*((u64 *)(base + cr_ind + CR0_LO_I)) = AS_WORD(cr0_lo);
}

static inline void
put_kernel_cr1_hi(e2k_cr1_hi_t cr1_hi, e2k_addr_t base, e2k_addr_t cr_ind)
{
	*((u64 *)(base + cr_ind + CR1_HI_I)) = AS_WORD(cr1_hi);
}

static inline void
put_kernel_cr1_lo(e2k_cr1_lo_t cr1_lo, e2k_addr_t base, e2k_addr_t cr_ind)
{
	*((u64 *)(base + cr_ind + CR1_LO_I)) = AS_WORD(cr1_lo);
}

static inline int
get_cr1_lo(e2k_cr1_lo_t *cr1_lo, e2k_addr_t base, u64 cr_ind,
		int user_stacks)
{
	int ret = 0;

	if (user_stacks)
		ret = get_user_cr1_lo(cr1_lo, base, cr_ind);
	else
		get_kernel_cr1_lo(cr1_lo, base, cr_ind);
	return ret;
}

static inline int
get_cr1_hi(e2k_cr1_hi_t *cr1_hi, e2k_addr_t base, u64 cr_ind,
		int user_stacks)
{
	int ret = 0;

	if (user_stacks)
		ret = get_user_cr1_hi(cr1_hi, base, cr_ind);
	else
		get_kernel_cr1_hi(cr1_hi, base, cr_ind);
	return ret;
}

static inline int
get_cr0_lo(e2k_cr0_lo_t *cr0_lo, e2k_addr_t base, u64 cr_ind,
		int user_stacks)
{
	int ret = 0;

	if (user_stacks)
		ret = get_user_cr0_lo(cr0_lo, base, cr_ind);
	else
		get_kernel_cr0_lo(cr0_lo, base, cr_ind);
	return ret;
}

static inline int
get_cr0_hi(e2k_cr0_hi_t *cr0_hi, e2k_addr_t base, u64 cr_ind,
		int user_stacks)
{
	int ret = 0;

	if (user_stacks)
		ret = get_user_cr0_hi(cr0_hi, base, cr_ind);
	else
		get_kernel_cr0_hi(cr0_hi, base, cr_ind);
	return ret;
}

static inline int
put_cr1_hi(e2k_cr1_hi_t cr1_hi, e2k_addr_t base, u64 cr_ind,
		int user_stacks)
{
	int ret = 0;

	if (user_stacks)
		ret = put_user_cr1_hi(cr1_hi, base, cr_ind);
	else
		put_kernel_cr1_hi(cr1_hi, base, cr_ind);
	return ret;
}

static inline int
get_user_cr1(e2k_cr1_lo_t *cr1_lo, e2k_cr1_hi_t *cr1_hi,
		e2k_pcsp_lo_t pcsp_lo, u64 cr_ind)
{
	u64 base = AS_STRUCT(pcsp_lo).base;
	int ret = 0;

	ret += get_user_cr1_lo(cr1_lo, base, cr_ind);
	ret += get_user_cr1_hi(cr1_hi, base, cr_ind);
	return ret;
}

static inline int
get_user_cr0(e2k_cr0_lo_t *cr0_lo, e2k_cr0_hi_t *cr0_hi,
		e2k_pcsp_lo_t pcsp_lo, u64 cr_ind)
{
	u64 base = AS_STRUCT(pcsp_lo).base;
	int ret = 0;

	ret += get_user_cr0_lo(cr0_lo, base, cr_ind);
	ret += get_user_cr0_hi(cr0_hi, base, cr_ind);
	return ret;
}

static inline void
get_kernel_cr1(e2k_cr1_lo_t *cr1_lo, e2k_cr1_hi_t *cr1_hi,
		e2k_pcsp_lo_t pcsp_lo, u64 cr_ind)
{
	u64 base = AS_STRUCT(pcsp_lo).base;

	get_kernel_cr1_lo(cr1_lo, base, cr_ind);
	get_kernel_cr1_hi(cr1_hi, base, cr_ind);
}
static inline void
get_kernel_cr0(e2k_cr0_lo_t *cr0_lo, e2k_cr0_hi_t *cr0_hi,
		e2k_pcsp_lo_t pcsp_lo, u64 cr_ind)
{
	u64 base = AS_STRUCT(pcsp_lo).base;

	get_kernel_cr0_lo(cr0_lo, base, cr_ind);
	get_kernel_cr0_hi(cr0_hi, base, cr_ind);
}

static inline int
get_cr1(e2k_cr1_lo_t *cr1_lo, e2k_cr1_hi_t *cr1_hi,
		e2k_pcsp_lo_t pcsp_lo, u64 cr_ind, int user_stacks)
{
	int ret = 0;

	if (user_stacks)
		ret = get_user_cr1(cr1_lo, cr1_hi, pcsp_lo, cr_ind);
	else
		get_kernel_cr1(cr1_lo, cr1_hi, pcsp_lo, cr_ind);
	return ret;
}

static inline int
get_cr0(e2k_cr0_lo_t *cr0_lo, e2k_cr0_hi_t *cr0_hi,
		e2k_pcsp_lo_t pcsp_lo, u64 cr_ind, int user_stacks)
{
	int ret = 0;

	if (user_stacks)
		ret = get_user_cr0(cr0_lo, cr0_hi, pcsp_lo, cr_ind);
	else
		get_kernel_cr0(cr0_lo, cr0_hi, pcsp_lo, cr_ind);
	return ret;
}

static inline int
get_user_crs(e2k_mem_crs_t *crs, e2k_addr_t base, e2k_addr_t cr_ind)
{
	int ret;
	ret = __copy_from_user(crs, (const char __user *)(base + cr_ind),
			sizeof (*crs));
	return ret;
}

static inline int
put_user_crs(e2k_mem_crs_t *crs, e2k_addr_t base, e2k_addr_t cr_ind)
{
	int ret;
	ret = __copy_to_user((char __user *)(base + cr_ind), crs,
			sizeof (*crs));
	return ret;
}

static inline void
get_kernel_crs(e2k_mem_crs_t *crs, e2k_addr_t base, e2k_addr_t cr_ind)
{
	get_kernel_cr0_lo(&crs->cr0_lo, base, cr_ind);
	get_kernel_cr0_hi(&crs->cr0_hi, base, cr_ind);
	get_kernel_cr1_lo(&crs->cr1_lo, base, cr_ind);
	get_kernel_cr1_hi(&crs->cr1_hi, base, cr_ind);
}

static inline void
put_kernel_crs(e2k_mem_crs_t *crs, e2k_addr_t base, e2k_addr_t cr_ind)
{
	put_kernel_cr0_lo(crs->cr0_lo, base, cr_ind);
	put_kernel_cr0_hi(crs->cr0_hi, base, cr_ind);
	put_kernel_cr1_lo(crs->cr1_lo, base, cr_ind);
	put_kernel_cr1_hi(crs->cr1_hi, base, cr_ind);
}

static inline int
get_crs(e2k_mem_crs_t *crs, e2k_addr_t base, e2k_addr_t cr_ind,
	int user_stacks)
{
	int ret = 0;

	if (user_stacks)
		ret = get_user_crs(crs, base, cr_ind);
	else
		get_kernel_crs(crs, base, cr_ind);
	return ret;
}

static inline int
put_crs(e2k_mem_crs_t *crs, e2k_addr_t base, e2k_addr_t cr_ind,
	int user_stacks)
{
	int ret = 0;

	if (user_stacks)
		ret = put_user_crs(crs, base, cr_ind);
	else
		put_kernel_crs(crs, base, cr_ind);
	return ret;
}

extern int fix_all_stack_sz(e2k_addr_t base, long cr_ind,
			e2k_size_t delta_sp, long start_cr_ind,
			int user_stacks, int set_stack_sz);

extern int fix_all_stack_sz_for_gdb(e2k_addr_t base, long cr_ind,
			e2k_size_t delta_sp, long start_cr_ind,
			int user_stacks, int set_stack_sz,
                        struct task_struct *tsk);
extern int fix_all_user_stack_regs(pt_regs_t *regs, e2k_size_t delta_sp);
extern e2k_addr_t get_nested_kernel_IP(pt_regs_t *regs, int n);

#endif /* _E2K_PROCESS_H */

