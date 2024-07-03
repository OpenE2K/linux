/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Memory management utilities
 */
 
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/string.h>
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
#include <linux/pgtable.h>
#include <linux/delay.h>

#include <asm/types.h>
#include <asm/p2v/boot_head.h>
#include <asm/p2v/boot_init.h>
#include <asm/p2v/boot_phys.h>
#include <asm/head.h>
#include <asm/system.h>
#include <asm/mmu_regs.h>
#include <asm/page.h>
#include <asm/pgalloc.h>
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

static inline void
print_va_tlb_line(e2k_addr_t addr, tlb_line_state_t *line,
		  bool huge_page, tlb_line_state_t *huge_line,
		  probe_entry_t probe_pte, const char *msg)
{
	e2k_mmu_cr_t mmu_cr = MMU_CR_KERNEL;
	int line_no, set_no, set_num;

	if (msg != NULL) {
		pr_alert("%s addr %px\n", msg, (void *)addr);
	}
	line_no = VADDR_TO_TLB_LINE_NUM(addr, 0);
	pr_cont("     line[%02x] : ", line_no);
	for (set_no = 0; set_no < NATIVE_TLB_SETS_NUM; set_no++) {
		tlb_set_state_t *set;
		tlb_tag_t tlb_tag;
		pte_t tlb_entry;

		set = &line->sets[set_no];
		tlb_tag = set->tlb_tag;
		tlb_entry = set->tlb_entry;
		if (set_no > 0) {
			pr_cont("              : ");
		}
		pr_cont("set #%d tag 0x%016lx entry 0x%016lx\n",
			set_no, tlb_tag_val(tlb_tag), pte_val(tlb_entry));
	}

	if (!huge_page)
		goto out;

	line_no = VADDR_TO_TLB_LINE_NUM(addr, 1);
	set_num = 0;
	pr_cont("huge line[%02x] : ", line_no);
	for (set_no = 0; set_no < NATIVE_TLB_SETS_NUM; set_no++) {
		tlb_set_state_t *set;
		tlb_tag_t tlb_tag;
		pte_t tlb_entry;

		if (set_no == 0)
			continue;
		if (set_no == 1 && !mmu_cr.set1)
			continue;
		if (set_no == 2 && !mmu_cr.set2)
			continue;
		if (set_no == 3 && !mmu_cr.set3)
			continue;

		set = &huge_line->sets[set_no];
		tlb_tag = set->tlb_tag;
		tlb_entry = set->tlb_entry;
		if (set_num > 0) {
			pr_cont("              : ");
		}
		pr_cont("set #%d tag 0x%016lx entry 0x%016lx\n",
			set_no, tlb_tag_val(tlb_tag), pte_val(tlb_entry));
		set_num++;
	}

out:
	pr_alert("tlb probe     : %016lx %s\n",
		probe_pte,
		DTLB_ENTRY_TEST_SUCCESSFUL(probe_pte) ? "successful" : "invalid");
}

void print_va_tlb(e2k_addr_t addr, bool huge_page)
{
	int cpu;
	tlb_line_state_t line, huge_line;
	mmu_reg_t u_pptb;
	mmu_reg_t os_pptb;
	mmu_reg_t pid;
	probe_entry_t probe_pte;
	struct mm_struct *mm = current->active_mm;
	unsigned long cntx;

	cpu = get_cpu();

	/*
	 * First of all, get TLB to minimally disrupt its current state
	 * because of subsequent printk() actions significantly change
	 * TLB content
	 */
	get_va_tlb_state(&line, addr, 0);
	if (huge_page) {
		get_va_tlb_state(&huge_line, addr, 1);
	}
	probe_pte = get_MMU_DTLB_ENTRY(addr);

	u_pptb = READ_MMU_U_PPTB();
	if (MMU_IS_SEPARATE_PT()) {
		os_pptb = READ_MMU_OS_PPTB();
	}
	pid = READ_MMU_PID();
	cntx = mm->context.cpumsk[cpu];

	pr_alert("======= start CPU #%d DTLB addr %px =======\n",
		cpu, (void *)addr);
	pr_cont("mmu user root at %px", (void *)u_pptb);
	if (MMU_IS_SEPARATE_PT())
		pr_cont(" os root at %px", (void *)os_pptb);
	pr_cont("\n");
	pr_alert("mm  pgd  root at %px\n", mm->pgd);
	pr_alert("mmu pid  %lx\n", (unsigned long)pid);
	pr_alert("mm  pid  %llx version %llx\n",
		CTX_HARDWARE(cntx), CTX_VERSION_NO(cntx));

	print_va_tlb_line(addr, &line, huge_page, &huge_line, probe_pte, NULL);
	pr_alert("=======  end  CPU #%d DTLB addr %px =======\n",
		cpu, (void *)addr);
	put_cpu();
}

void print_va_all_tlb_levels(e2k_addr_t addr, bool huge_page)
{
	int cpu;
	e2k_addr_t pte_addr, pmd_addr, pud_addr;
	tlb_line_state_t line, huge_line;
	tlb_line_state_t pte_line, pte_huge_line;
	tlb_line_state_t pmd_line, pmd_huge_line;
	tlb_line_state_t pud_line, pud_huge_line;
	mmu_reg_t u_pptb;
	mmu_reg_t os_pptb;
	mmu_reg_t pid;
	probe_entry_t probe, pte_probe, pmd_probe, pud_probe;
	struct mm_struct *mm = current->active_mm;
	unsigned long cntx;

	/* Only older CPUs cached intermediate levels of page table in DTLB */
	bool print_intermediate_levels = !cpu_has(CPU_FEAT_ISET_V6);

	cpu = get_cpu();

	/*
	 * First of all, get TLB to minimally disrupt its current state
	 * because of subsequent printk() actions significantly change
	 * TLB content
	 */
	get_va_tlb_state(&line, addr, 0);
	if (huge_page) {
		get_va_tlb_state(&huge_line, addr, 1);
	}
	probe = get_MMU_DTLB_ENTRY(addr);

	if (print_intermediate_levels) {
		pte_addr = pte_virt_offset(round_down(addr, PTE_SIZE));
		pmd_addr = pmd_virt_offset(round_down(addr, PMD_SIZE));
		pud_addr = pud_virt_offset(round_down(addr, PUD_SIZE));
		get_va_tlb_state(&pte_line, pte_addr, 0);
		get_va_tlb_state(&pmd_line, pmd_addr, 0);
		get_va_tlb_state(&pud_line, pud_addr, 0);
		if (huge_page) {
			get_va_tlb_state(&pte_huge_line, pte_addr, 1);
			get_va_tlb_state(&pmd_huge_line, pmd_addr, 1);
			get_va_tlb_state(&pud_huge_line, pud_addr, 1);
		}
		pte_probe = get_MMU_DTLB_ENTRY(pte_addr);
		pmd_probe = get_MMU_DTLB_ENTRY(pmd_addr);
		pud_probe = get_MMU_DTLB_ENTRY(pud_addr);
	}

	u_pptb = READ_MMU_U_PPTB();
	if (MMU_IS_SEPARATE_PT()) {
		os_pptb = READ_MMU_OS_PPTB();
	}
	pid = READ_MMU_PID();
	cntx = mm->context.cpumsk[cpu];

	pr_alert("======= start CPU #%d DTLB addr %px =======\n",
		cpu, (void *)addr);
	pr_cont("mmu user root at %px", (void *)u_pptb);
	if (MMU_IS_SEPARATE_PT())
		pr_cont(" os root at %px", (void *)os_pptb);
	pr_cont("\n");
	pr_alert("mm  pgd  root at %px\n", mm->pgd);
	pr_alert("mmu pid  %lx\n", (unsigned long)pid);
	pr_alert("mm  pid  %llx version %llx\n",
		CTX_HARDWARE(cntx), CTX_VERSION_NO(cntx));

	print_va_tlb_line(addr, &line, huge_page, &huge_line, probe, NULL);

	if (print_intermediate_levels) {
		/* Only older CPUs cached intermediate
		 * levels of page table in DTLB */
		print_va_tlb_line(pte_addr, &pte_line, huge_page, &pte_huge_line,
				pte_probe, "pte level addr");
		print_va_tlb_line(pmd_addr, &pmd_line, huge_page, &pmd_huge_line,
				pmd_probe, "pmd level addr");
		print_va_tlb_line(pud_addr, &pud_line, huge_page, &pud_huge_line,
				pud_probe, "pud level addr");
	}

	pr_alert("=======  end  CPU #%d DTLB addr %px =======\n",
		cpu, (void *)addr);
	put_cpu();
}

static DEFINE_PER_CPU_ALIGNED(tlb_state_t, all_tlb_state);

void native_print_all_tlb(void)
{
	tlb_state_t *tlb;
	int cpu;
	int line_no, set_no;

	cpu = get_cpu();
	tlb = this_cpu_ptr(&all_tlb_state);
	get_all_tlb_state(tlb);

	pr_alert("========== CPU #%d DTLB all lines & sets state ==========\n",
		cpu);
	for (line_no = 0; line_no < NATIVE_TLB_LINES_NUM; line_no++) {
		tlb_line_sets_t *line;

		line = &tlb->lines[line_no];
		pr_cont("line[%02x] : ", line_no);
		for (set_no = 0; set_no < NATIVE_TLB_SETS_NUM; set_no++) {
			tlb_set_state_t *set;
			tlb_tag_t tlb_tag;
			pte_t tlb_entry;

			set = &line->sets[set_no];
			tlb_tag = set->tlb_tag;
			tlb_entry = set->tlb_entry;
			if (set_no > 0) {
				pr_cont("         : ");
			}
			pr_cont("set #%d tag 0x%016lx entry 0x%016lx\n",
				set_no, tlb_tag_val(tlb_tag), pte_val(tlb_entry));
		}
		msleep(10);
	}
	put_cpu();
}

static inline bool pud_is_single(pud_t pudv, bool hpage,
		unsigned long address, unsigned long next)
{
	return hpage || pud_trans_huge(pudv) || (pud_none(pudv) &&
						 next - address == PUD_SIZE);
}

static int e2k_make_single_pud_valid(struct vm_area_struct *vma, pud_t *pud,
				     unsigned long address, unsigned long next,
				     bool set_invalid, bool hpage)
{
	struct mm_struct *mm = vma->vm_mm;
	spinlock_t *ptl;
	pud_t pudv;

	if (hpage) {
		pte_t *huge_pte = (pte_t *) pud;
		ptl = huge_pte_lockptr(hstate_vma(vma), mm, huge_pte);
	} else {
		ptl = pud_lockptr(mm, pud);
	}

	spin_lock(ptl);

	pudv = *pud;

	/* Test pud again under spinlock */
	if (!pud_is_single(pudv, hpage, address, next)) {
		spin_unlock(ptl);
		return -EAGAIN;
	}

	/*
	 * We just set _PAGE_VALID. Do not use vm_page_prot to make sure
	 * that huge_pte_none()/pud_none() still returns true for this pte.
	 */
	pudv = (set_invalid) ? pud_mknotvalid(pudv) : pud_mkvalid(pudv);
	validate_pud_at(mm, address, pud, pudv);

	spin_unlock(ptl);

	return 0;
}

static inline bool pmd_is_single(pmd_t pmdv, bool hpage,
		unsigned long address, unsigned long next)
{
	return hpage || pmd_trans_huge(pmdv) || (pmd_none(pmdv) &&
						 next - address == PMD_SIZE);
}

static int e2k_make_single_pmd_valid(struct vm_area_struct *vma, pmd_t *pmd,
				     unsigned long address, unsigned long next,
				     bool set_invalid, bool hpage)
{
	struct mm_struct *mm = vma->vm_mm;
	spinlock_t *ptl;
	pmd_t pmdv;

	DebugPMD("started from 0x%lx for pmd 0x%lx to %s\n",
		 address, pmd, (set_invalid) ? "invalidate" : "validate");

	if (hpage) {
		pte_t *huge_pte = (pte_t *) pmd;
		ptl = huge_pte_lockptr(hstate_vma(vma), mm, huge_pte);
	} else {
		ptl = pmd_lockptr(mm, pmd);
	}

	spin_lock(ptl);

	pmdv = *pmd;

	/* Test pmd again under spinlock */
	if (!pmd_is_single(pmdv, hpage, address, next)) {
		spin_unlock(ptl);
		return -EAGAIN;
	}

	DebugPMD("sets pmd 0x%px to 0x%lx for address 0x%lx\n",
		 pmd, pmd_val(*pmd), address);

	/*
	 * We just set _PAGE_VALID. Do not use vm_page_prot to make sure
	 * that huge_pte_none()/pmd_none() still returns true for this pte.
	 */
	pmdv = (set_invalid) ? pmd_mknotvalid(pmdv) : pmd_mkvalid(pmdv);
	validate_pmd_at(mm, address, pmd, pmdv);

	spin_unlock(ptl);

	return 0;
}

static void e2k_make_pte_pages_valid(struct mm_struct *mm, pmd_t *pmd,
		e2k_addr_t start_addr, e2k_addr_t end, bool set_invalid)
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

#ifdef	CONFIG_KVM_GUEST_KERNEL
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
#endif	/* CONFIG_KVM_GUEST_KERNEL */

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
}

static int
e2k_make_pmd_pages_valid(struct vm_area_struct *vma, pud_t *pud,
		e2k_addr_t start_addr, e2k_addr_t end, bool set_invalid)
{
	unsigned long address = start_addr, next;
	pmd_t *pmd = pmd_offset(pud, address);
	bool hpage;
	int ret = 0;
	struct mm_struct *mm = vma->vm_mm;

	hpage = is_vm_hugetlb_page(vma);

	DebugPTD("started from 0x%lx to 0x%lx to %s\n", start_addr, end,
			(set_invalid) ? "invalidate" : "validate");

	do {
		next = pmd_addr_end(address, end);

again:
		if (!hpage && !pmd_none_or_trans_huge_or_clear_bad(pmd)) {
			/*
			 * pmd is stable and there is the next level
			 */
			e2k_make_pte_pages_valid(mm, pmd, address,
					next, set_invalid);
			continue;
		}

		if (pmd_is_single(*pmd, hpage, address, next)) {
			/* Set/clear the valid bit on the whole pmd */
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
	e2k_addr_t address = start_addr, next;
	pud_t *pud = pud_offset(pgd, address);
	bool set_invalid, hpage;
	int ret = 0;

	hpage = is_vm_hugetlb_page(vma) &&
		huge_page_size(hstate_vma(vma)) == PUD_SIZE;
	set_invalid = !_PAGE_TEST_VALID(pgprot_val(vma->vm_page_prot));

	DebugPTD("started from 0x%lx to 0x%lx to %s\n", start_addr, end,
			(set_invalid) ? "invalidate" : "validate");

	do {
		next = pud_addr_end(address, end);

again:
		if (!hpage && !pud_trans_huge(*pud) && !pud_none(*pud)) {
			/* There is the next level */
			ret = e2k_make_pmd_pages_valid(vma, pud, address, next, set_invalid);
			if (ret)
				return ret;

			continue;
		}

		if (pud_is_single(*pud, hpage, address, next)) {
			/* Set/clear the valid bit on the whole pud */
			ret = e2k_make_single_pud_valid(vma, pud, address, next,
					set_invalid, hpage);
			if (ret == -EAGAIN)
				goto again;
			if (ret)
				return ret;

			continue;
		}

		if (!pmd_alloc(vma->vm_mm, pud, address)) {
			DebugPTD("could not alloc pud for addr 0x%lx\n", address);
			return -ENOMEM;
		}

		goto again;
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
	int		ret = 0;

	DebugPT("started from 0x%lx to 0x%lx\n", start_addr, end_addr);

	do {
		make_pud_valid = true;

		if (pgd_none(*pgd)) {
			if ((address & PGDIR_MASK) == address &&
					end_addr >= pgd_addr_bound(address)) {
				DebugPTD("will make pgd 0x%lx valid & !present for addr 0x%lx\n",
					pgd, address);
				make_pud_valid = false;
				pgd_populate_user_not_present(vma->vm_mm,
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

	mmap_write_lock(mm);
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
	mmap_write_unlock(mm);
	return ret;
}
