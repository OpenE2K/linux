/*
 *  arch/e2k/mm/memory.c
 *
 * Memory management utilities
 *
 * Copyright 2001 Salavat S. Guiliazov (atic@mcst.ru)
 */
 
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/hugetlb.h>
#include <linux/blkdev.h>
#include <linux/swap.h>
#include <linux/mman.h>
#include <linux/file.h>
#include <linux/rmap.h>
#include <asm/types.h>
#include <asm/p2v/boot_head.h>
#include <asm/p2v/boot_init.h>
#include <asm/p2v/boot_phys.h>
#include <asm/head.h>
#include <asm/system.h>
#include <asm/mmu_regs.h>
#include <asm/page.h>
#include <asm/pgalloc.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <asm/mmu_context.h>
#include <asm/secondary_space.h>

#include <asm/e2k_debug.h>

#undef	DEBUG_PT_MODE
#undef	DebugPT
#define	DEBUG_PT_MODE		0	/* Page table */
#define DebugPT(...)		DebugPrint(DEBUG_PT_MODE, ##__VA_ARGS__)

#undef	DEBUG_PTE_MODE
#undef	DebugPTE
#define	DEBUG_PTE_MODE		0	/* Page table */
#define DebugPTE(...)		DebugPrint(DEBUG_PTE_MODE, ##__VA_ARGS__)

#undef	DEBUG_PMD_MODE
#undef	DebugPMD
#define	DEBUG_PMD_MODE		0	/* Page table */
#define DebugPMD(...)		DebugPrint(DEBUG_PMD_MODE, ##__VA_ARGS__)

#undef	DEBUG_PTD_MODE
#undef	DebugPTD
#define	DEBUG_PTD_MODE		0	/* Page table */
#define DebugPTD(...)		DebugPrint(DEBUG_PTD_MODE, ##__VA_ARGS__)

#undef	DEBUG_NUMA_MODE
#undef	DebugNUMA
#define	DEBUG_NUMA_MODE		0	/* NUMA supporting */
#define DebugNUMA(...)		DebugPrint(DEBUG_NUMA_MODE, ##__VA_ARGS__)

void print_va_tlb(e2k_addr_t addr, int large_page)
{
	tlb_line_state_t tlb;
	tlb_set_state_t *set;
	int set_no;

	get_va_tlb_state(&tlb, addr, large_page);

	for (set_no = 0; set_no < NATIVE_TLB_SETS_NUM; set_no++) {
		tlb_tag_t tlb_tag;
		pte_t tlb_entry;

		set = &tlb.sets[set_no];
		tlb_tag = set->tlb_tag;
		tlb_entry = set->tlb_entry;
		printk("TLB addr 0x%lx : set #%d tag 0x%016lx entry "
			"0x%016lx\n",
			addr, set_no, tlb_tag_val(tlb_tag), pte_val(tlb_entry));
	}
}

pte_t *node_pte_alloc_kernel(int nid, pmd_t *pmd, e2k_addr_t address)
{
	struct mm_struct *mm = &init_mm;
	pte_t *new;
	struct page *page;

	page = alloc_pages_node(nid, GFP_KERNEL | __GFP_ZERO, 0);
	if (!page)
		return NULL;
	new = page_address(page);

	spin_lock(&mm->page_table_lock);
	if (!pmd_present(*pmd)) {
		pmd_populate_kernel(mm, pmd, new);
		new = NULL;
	}
	spin_unlock(&mm->page_table_lock);
	if (new)
		__free_page(page);
	return pte_offset_kernel(pmd, address);
}

pmd_t *node_pmd_alloc_kernel(int nid, pud_t *pud, e2k_addr_t address)
{
	struct mm_struct *mm  = &init_mm;
	pmd_t *new;
	struct page *page;

	page = alloc_pages_node(nid, GFP_KERNEL | __GFP_ZERO, 0);
	if (!page)
		return NULL;
	new = page_address(page);

	spin_lock(&mm->page_table_lock);
	if (!pud_present(*pud)) {
		pud_populate_kernel(mm, pud, new);
		new = NULL;
	}
	spin_unlock(&mm->page_table_lock);
	if (new)
		__free_page(page);
	return pmd_offset(pud, address);
}

pud_t *node_pud_alloc_kernel(int nid, pgd_t *pgd, e2k_addr_t address)
{
	struct mm_struct *mm = &init_mm;
	pud_t *new;
	struct page *page;

	page = alloc_pages_node(nid, GFP_KERNEL | __GFP_ZERO, 0);
	if (!page)
		return NULL;
	new = page_address(page);

	spin_lock(&mm->page_table_lock);
	if (!pgd_present(*pgd)) {
		node_pgd_populate_kernel(nid, mm, pgd, new);
		new = NULL;
	}
	spin_unlock(&mm->page_table_lock);
	if (new)
		__free_page(page);
	return pud_offset(pgd, address);
}

#ifdef	CONFIG_NUMA
#ifdef	CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT
pgd_t *
node_pgd_offset_kernel(int nid, e2k_addr_t virt_addr)
{
	int node_cpu;

	if (!MMU_IS_SEPARATE_PT()) {
		node_cpu = node_to_first_present_cpu(nid);
		return the_cpu_pg_dir(node_cpu) + pgd_index(virt_addr);
	} else {
		return the_node_kernel_root_pt(nid) + pgd_index(virt_addr);
	}
}

/*
 * Set pgd entry at root PTs of all CPUs of the node
 */
static void node_all_cpus_pgd_set_k(int the_node, int pgd_index, pgd_t pgd)
{
	pgd_t *pgdp;
	cpumask_t node_cpus;
	int cpu;

	node_cpus = node_to_present_cpumask(the_node);
	DebugNUMA("node #%d online cpu mask 0x%lx pgd[0x%x] = 0x%lx\n",
		the_node, node_cpus.bits[0], pgd_index, pgd_val(pgd));

	for_each_cpu_of_node(the_node, cpu, node_cpus) {
		pgdp = the_cpu_pg_dir(cpu);
		DebugNUMA("set the node #%d CPU #%d pgd "
			"entry 0x%px == 0x%lx\n",
			the_node, cpu, &pgdp[pgd_index], pgd_val(pgd));
		if (!pgd_none(pgdp[pgd_index])) {
			pr_err("node_pgd_set_k() pgd %px is not empty 0x%lx\n",
				&pgdp[pgd_index], pgd_val(pgdp[pgd_index]));
			BUG();
		}
		pgdp[pgd_index] = pgd;
	}
}

/*
 * Set specified kernel pgd entry to point to next-level page table PUD
 * Need populate the pgd entry into follow root page tables:
 *	- all CPUs of the specified node;
 *	- all CPUs of other nodes which have not own copy of kernel image
 *	  (DUP KERNEL) and use duplicated kernel of this node
 */
void node_pgd_set_k(int the_node, pgd_t *the_pgdp, pud_t *pudp)
{
	pgd_t pgd = mk_pgd_phys_k(pudp);
	int pgd_index = pgd_to_index(the_pgdp);
	int dup_node;
	nodemask_t node_mask;
	int node;

	if (!THERE_IS_DUP_KERNEL) {
		kernel_root_pt[pgd_index] = pgd;
		DebugNUMA("set kernel root PT pgd "
			"entry 0x%px to pud 0x%px\n",
			&kernel_root_pt[pgd_index], pudp);
		return;
	}

	DebugNUMA("node #%d pgd %px == 0x%lx, pudp at %px\n",
		the_node, the_pgdp, pgd_val(*the_pgdp), pudp);

	dup_node = node_dup_kernel_nid(the_node);
	if (dup_node == the_node) {
		if (MMU_IS_SEPARATE_PT()) {
			the_node_kernel_root_pt(the_node)[pgd_index] = pgd;
		} else {
			/* Set pgd entry at root PTs of all CPUs of the node */
			node_all_cpus_pgd_set_k(the_node, pgd_index, pgd);
		}
	}

	if (DUP_KERNEL_NUM >= phys_nodes_num) {
		DebugNUMA("all %d nodes have duplicated "
			"kernel so own root PT\n",
			DUP_KERNEL_NUM);
		return;
	}

	/*
	 * Root and PTs of the node is on other node
	 * Set pgd entry at root PTs of all CPUs of other node on which
	 * this node has duplicated kernel
	 */
	if (dup_node != the_node) {
		if (MMU_IS_SEPARATE_PT()) {
			the_node_kernel_root_pt(dup_node)[pgd_index] = pgd;
		} else {
			node_all_cpus_pgd_set_k(dup_node, pgd_index, pgd);
		}
	}

	/*
	 * Set pgd entry at root PTs of all CPUs of all other nodes,
	 * which has duplicated kernel on the same node as this node
	 */
	for_each_node_has_not_dup_kernel(node, node_mask) {
		if (node == the_node)
			continue;
		if (node_dup_kernel_nid(node) != dup_node)
			continue;
		if (MMU_IS_SEPARATE_PT()) {
			the_node_kernel_root_pt(node)[pgd_index] = pgd;
		} else {
			node_all_cpus_pgd_set_k(node, pgd_index, pgd);
		}
	}
}
#else	/* ! CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */

pgd_t *
node_pgd_offset_kernel(int nid, e2k_addr_t virt_addr)
{
	BUG_ON(!MMU_IS_SEPARATE_PT());
	return the_node_kernel_root_pt(nid) + pgd_index(virt_addr);
}

/*
 * Set specified kernel pgd entry to point to next-level page table PUD
 * Need populate the pgd entry into follow root page tables:
 *	- PT of the specified node, if the node has duplicated kernel;
 *	- PT of node on which the node is duplicated
 *	- PTs of all other nodes which have not own copy of kernel image
 *	  (DUP KERNEL) and use duplicated kernel of this node or
 *	  are duplicated on the same node as this node
 */
void node_pgd_set_k(int the_node, pgd_t *the_pgdp, pud_t *pudp)
{
	pgd_t pgd = mk_pgd_phys_k(pudp);
	int pgd_index = pgd_to_index(the_pgdp);
	int dup_node;
	nodemask_t node_mask;
	int node;

	BUG_ON(!MMU_IS_SEPARATE_PT());

	if (!THERE_IS_DUP_KERNEL) {
		kernel_root_pt[pgd_index] = pgd;
		DebugNUMA("set kernel root PT pgd entry 0x%px to pud 0x%px\n",
			&kernel_root_pt[pgd_index], pudp);
		return;
	}

	DebugNUMA("node #%d pgd %px == 0x%lx, pudp at %px\n",
		the_node, the_pgdp, pgd_val(*the_pgdp), pudp);

	dup_node = node_dup_kernel_nid(the_node);
	if (dup_node == the_node) {
		the_node_kernel_root_pt(the_node)[pgd_index] = pgd;
	}

	if (DUP_KERNEL_NUM >= phys_nodes_num) {
		DebugNUMA("all %d nodes have duplicated kernel so own PT\n",
			DUP_KERNEL_NUM);
		return;
	}

	/*
	 * Root and PTs of the node is on other node
	 * Set pgd entry at root PTs on other node on which
	 * this node has duplicated kernel
	 */
	if (dup_node != the_node) {
		the_node_kernel_root_pt(dup_node)[pgd_index] = pgd;
	}

	/*
	 * Set pgd entry at root PTs of all CPUs of all other nodes,
	 * which has duplicated kernel on the same node as this node
	 */
	for_each_node_has_not_dup_kernel(node, node_mask) {
		if (node == the_node)
			continue;
		if (node_dup_kernel_nid(node) != dup_node)
			continue;
		the_node_kernel_root_pt(node)[pgd_index] = pgd;
	}
}
#endif	/* CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */
#endif	/* CONFIG_NUMA */

/*
 * Simplistic page force to be valid
 */

static int e2k_make_single_pmd_valid(struct vm_area_struct *vma, pmd_t *pmd,
				     unsigned long address, unsigned long next,
				     int set_invalid, int hpage)
{
	struct mm_struct *mm = vma->vm_mm;
	spinlock_t *ptl;
	pmd_t pmdv;

	DebugPMD("started from 0x%lx for pmd 0x%lx to %s\n",
		 address, pmd, (set_invalid) ? "invalidate" : "validate");

	if (hpage) {
		pte_t *huge_pte = (pte_t *) pmd;

		if (E2K_LARGE_PAGE_SIZE == E2K_4M_PAGE_SIZE) {
			if (huge_pte && pmd_index(address) % 2)
				huge_pte--;
		}

		ptl = huge_pte_lockptr(hstate_vma(vma), mm, huge_pte);
	} else {
		ptl = pmd_lockptr(mm, pmd);
	}

	spin_lock(ptl);

	pmdv = *pmd;

	/* Test pmd again under spinlock */
	if (!hpage && !pmd_trans_huge(pmdv) &&
	    (!pmd_none(pmdv) || next - address != PMD_SIZE)) {
		spin_unlock(ptl);
		return -EAGAIN;
	}

	DebugPMD("sets pmd 0x%px to 0x%lx for address 0x%lx\n",
		 pmd, pmd_val(*pmd), address);

	/*
	 * We just set _PAGE_VALID. Do not use vm_page_prot to make sure
	 * that huge_pte_none()/pmd_none() still returns true for this pte.
	 */
	if (set_invalid)
		pmdv = __pmd(_PAGE_CLEAR_VALID(pmd_val(pmdv)));
	else
		pmdv = __pmd(_PAGE_SET_VALID(pmd_val(pmdv)));

	validate_pmd_at(mm, address, pmd, pmdv);

	spin_unlock(ptl);

	return 0;
}

static int e2k_make_pte_pages_valid(struct mm_struct *mm, pmd_t *pmd,
		e2k_addr_t start_addr, e2k_addr_t end, int set_invalid)
{
	e2k_addr_t	address = start_addr;
	spinlock_t	*ptl;
	pte_t		*pte, *orig_pte;

	DebugPTE("started from 0x%lx to 0x%lx to %s\n", start_addr, end,
			(set_invalid) ? "invalidate" : "validate");

	pte = pte_offset_map_lock(mm, pmd, address, &ptl);
	orig_pte = pte;

#pragma loop count (512)
#pragma unroll (4)
	do {
		pte_t ptev = *pte;

		DebugPTE("sets pte 0x%px to 0x%lx for address 0x%lx\n",
			 pte, pte_val(ptev), address);

#if defined CONFIG_PARAVIRT_GUEST || defined CONFIG_KVM_GUEST_KERNEL
		/* probably pte can be already validated/invalidated,
		 * for example, data stack for sys_execve() is validated
		 * from setup_arg_pages() -> expand_stack()
		 * stack validation is completed at get_user_main_c_stack()
		 *
		 * It is important to avoid such double validation and
		 * invalidation in host's shadow page tables. */
		if ((!set_invalid) && pte_valid(*pte)) {
			DebugPTE("pte 0x%px == 0x%lx is already valid\n",
				pte, pte_val(*pte));
			continue;
		}
		if (set_invalid && (!pte_valid(*pte))) {
			DebugPTE("pte 0x%px == 0x%lx is already invalid\n",
				pte, pte_val(*pte));
			continue;
		}
#endif

		/*
		 * We change _PAGE_VALID only here. Do not use
		 * vm_page_prot to make sure that pte_none()
		 * still returns true for this pte.
		 */
		if (set_invalid)
			ptev = __pte(_PAGE_CLEAR_VALID(pte_val(ptev)));
		else
			ptev = __pte(_PAGE_SET_VALID(pte_val(ptev)));

		validate_pte_at(mm, address, pte, ptev);
	} while (pte++, address += PAGE_SIZE, (address < end));

	pte_unmap_unlock(orig_pte, ptl);

	DebugPTE("finished OK\n");
	return 0;
}

static int
e2k_make_pmd_pages_valid(struct vm_area_struct *vma, pud_t *pud,
		e2k_addr_t start_addr, e2k_addr_t end)
{
	unsigned long	address = start_addr, next;
	pmd_t		*pmd = pmd_offset(pud, address);
	int set_invalid, ret = 0, hpage = is_vm_hugetlb_page(vma);
	struct mm_struct *mm = vma->vm_mm;

	DebugPTD("started from 0x%lx to 0x%lx\n", start_addr, end);

	set_invalid = !_PAGE_TEST_VALID(pgprot_val(vma->vm_page_prot));

	do {
		next = pmd_addr_end(address, end);

again:
		if (!hpage && !pmd_none_or_trans_huge_or_clear_bad(pmd)) {
			/*
			 * pmd is stable and there is the next level
			 */
			ret = e2k_make_pte_pages_valid(mm, pmd, address,
					next, set_invalid);
			if (ret != 0)
				return ret;

			continue;
		}

		if (hpage || pmd_trans_huge(*pmd) || (pmd_none(*pmd) &&
						  next - address == PMD_SIZE)) {
			/*
			 * Set/clear the valid bit on the whole pmd
			 */
			ret = e2k_make_single_pmd_valid(vma, pmd, address, next,
					set_invalid, hpage);
			if (ret == -EAGAIN)
				goto again;
			if (ret)
				return ret;

			continue;
		}

		/*
		 * Use __pte_alloc instead of pte_alloc_map, because we can't
		 * run pte_offset_map on the pmd, if an huge pmd could
		 * materialize from under us from a different thread.
		 */
		DebugPTD("will pte_alloc_map(0x%px) for addr 0x%lx\n",
			 pmd, address);
		if (unlikely(__pte_alloc(vma->vm_mm, pmd))) {
			DebugPTD("could not alloc pte page for addr 0x%lx\n",
				 address);
			return -ENOMEM;
		}

		goto again;
	} while (pmd++, address = next, (address < end));

	DebugPTD("finished OK\n");
	return 0;
}

static int e2k_make_pud_pages_valid(struct vm_area_struct *vma, pgd_t *pgd,
		e2k_addr_t start_addr, e2k_addr_t end)
{
	e2k_addr_t	address = start_addr, next;
	pud_t		*pud = pud_offset(pgd, address);
	bool		make_pmd_valid;
	int		ret = 0, hpage = is_vm_hugetlb_page(vma);

	DebugPTD("started from 0x%lx to 0x%lx\n", start_addr, end);

	do {
		make_pmd_valid = true;

		if (pud_none(*pud)) {
			if (!hpage && (address & PUD_MASK) == address &&
					end >= pud_addr_bound(address)) {
				DebugPTD("will make pud 0x%lx valid & !present for addr 0x%lx\n",
					pud, address);
				make_pmd_valid = false;
				validate_pud_at(vma->vm_mm, address, pud);
			} else {
				DebugPTD("will pmd_alloc(0x%px) for addr 0x%lx\n",
					pud, address);
				if (!pmd_alloc(vma->vm_mm, pud, address)) {
					DebugPTD("could not alloc pmd for addr 0x%lx\n",
						address);
					return -ENOMEM;
				}
			}
		} else if (pud_bad(*pud)) {
			pud_ERROR(*pud);
			BUG();
		}

		next = pud_addr_end(address, end);

		if (make_pmd_valid) {
			DebugPTD("will make pmd range pages valid from address 0x%lx to 0x%lx\n",
				address, next);
			ret = e2k_make_pmd_pages_valid(vma, pud, address, next);
			if (ret)
				return ret;
		}
	} while (pud++, address = next, (address < end));

	DebugPTD("finished OK\n");
	return 0;
}

static int e2k_make_vma_pages_valid(struct vm_area_struct *vma,
		e2k_addr_t start_addr, e2k_addr_t end_addr, int flags)
{
	e2k_addr_t	address = start_addr, next;
	pgd_t		*pgd = pgd_offset(vma->vm_mm, address);
	bool		make_pud_valid;
	int		ret = 0, hpage = is_vm_hugetlb_page(vma);

	DebugPT("started from 0x%lx to 0x%lx\n", start_addr, end_addr);

	do {
		make_pud_valid = true;

		if (pgd_none(*pgd)) {
			if (!hpage && (address & PGDIR_MASK) == address &&
					end_addr >= pgd_addr_bound(address)) {
				DebugPTD("will make pgd 0x%lx valid & !present for addr 0x%lx\n",
					pgd, address);
				make_pud_valid = false;
				pgd_populate_not_present(vma->vm_mm,
							address, pgd);
			} else {
				DebugPTD("will pud_alloc(0x%px) for addr 0x%lx\n",
					pgd, address);
				if (!pud_alloc(vma->vm_mm, pgd, address)) {
					DebugPTD("could not alloc pud for addr 0x%lx\n",
						address);
					return -ENOMEM;
				}
			}
		} else if (pgd_bad(*pgd)) {
			pgd_ERROR(*pgd);
			BUG();
		}

		next = pgd_addr_end(address, end_addr);

		if (make_pud_valid) {
			DebugPTD("will make pud range pages valid from address 0x%lx to 0x%lx\n",
				address, next);
			ret = e2k_make_pud_pages_valid(vma, pgd, address, next);
			if (ret)
				return ret;
		}
	} while (pgd++, address = next, (address < end_addr));
	
	/*
	 * Semispeculative requests can access virtual addresses
	 * from this validated VM area while these addresses were not
	 * yet existed and write invalid TLB entry (valid bit = 0).
	 * So it's need to flush the same TLB entries for all VM areas.
	 *
	 * Invalid TLB entries can be created for any level of page table,
	 * so flush all 4 levels.
	 */
	if (!ret && (flags & MV_FLUSH)) {
		DebugPTD("flush TLB from 0x%lx to 0x%lx\n",
			start_addr, end_addr);
		flush_tlb_range_and_pgtables(vma->vm_mm, start_addr, end_addr);
	}

	DebugPT("finished with %d\n", ret);

	return ret;
}

int
make_vma_pages_valid(struct vm_area_struct *vma,
	unsigned long start_addr, unsigned long end_addr)
{
	int	ret;

	BUG_ON(end_addr < start_addr);

	DebugPT("started for VMA 0x%px from start addr 0x%lx to end addr 0x%lx\n",
		vma, start_addr, end_addr);

	ret = e2k_make_vma_pages_valid(vma, start_addr, end_addr, MV_FLUSH);
	if (ret != 0) {
		DebugPT("finished with error %d\n",
			ret);
		return ret;
	}

	DebugPT("finished OK\n");
	return 0;
}

int
make_all_vma_pages_valid(struct vm_area_struct *vma, int flags)
{
	int	ret;

	DebugPT("started for VMA 0x%px from start addr 0x%lx to end addr 0x%lx\n",
		vma, vma->vm_start, vma->vm_end);

	ret = e2k_make_vma_pages_valid(vma, vma->vm_start, vma->vm_end, flags);
	if (ret != 0) {
		DebugPT("finished with error %d\n",
			ret);
		return ret;
	}

	DebugPT("finished OK\n");
	return 0;
}

int e2k_set_vmm_cui(struct mm_struct *mm, int cui,
		unsigned long code_base, unsigned long code_end)
{
	struct vm_area_struct	*vma, *prev;
	int			ret = -EINVAL;
	unsigned long		vm_flags;
	unsigned long		off = code_base;

	down_write(&mm->mmap_sem);
	while (off < code_end) {
		vma = find_vma_prev(mm, off, &prev);
		if (!vma || (off == code_base && vma->vm_start > off)) {
			pr_err("No vma for 0x%lx : 0x%lx (found vma %lx : %lx)\n",
				off, code_end, vma ? vma->vm_start : 0,
				vma ? vma->vm_end : 0);
			ret = -EINVAL;
			goto out;
		}
		if (off > vma->vm_start)
			prev = vma;
		vm_flags = (vma->vm_flags & ~VM_CUI) |
					((u64) cui << VM_CUI_SHIFT);
		if (ret = mprotect_fixup(vma, &prev,
				vma->vm_start < off ? off : vma->vm_start,
				vma->vm_end > code_end ? code_end : vma->vm_end,
				vm_flags))
			goto out;

		off = vma->vm_end;
	}

out:
	up_write(&mm->mmap_sem);
	return ret;
}
