/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PGALLOC_TRACK_H
#define _LINUX_PGALLOC_TRACK_H

#if defined(CONFIG_MMU)
static inline p4d_t *p4d_alloc_track(struct mm_struct *mm, pgd_t *pgd,
				     unsigned long address,
				     pgtbl_mod_mask *mod_mask)
{
	if (unlikely(pgd_none(*pgd))) {
		if (__p4d_alloc(mm, pgd, address))
			return NULL;
		*mod_mask |= PGTBL_PGD_MODIFIED;
	}

	return p4d_offset(pgd, address);
}

# ifdef CONFIG_E2K_MODULES_DUPLICATION
static inline p4d_t *p4d_alloc_track_node(int node, struct mm_struct *mm,
					  pgd_t *pgd, unsigned long address)
{
	if (unlikely(pgd_none(*pgd))) {
		if (__p4d_alloc_node(node, mm, pgd, address))
			return NULL;
	} else {
#ifdef __PAGETABLE_P4D_FOLDED
		/*
		 * While P4D level is not used in e2k, pgd_none(*pgd) always returns 0
		 * and we get to this branch. We can't check here that page pointed by
		 * PGD entry '*pgd' is located on node 'node' - that page may not exist
		 * yet. The appropriate checks will be done at PUD level (see
		 * pud_alloc_track_node()).
		 */
#else
		/*
		 * When P4D level will be supported in e2k, add a check that the page
		 * pointed by PGD entry is on the right node.
		 */
		BUILD_BUG_ON(1);
#endif
	}

	return p4d_offset(pgd, address);
}
# endif /* CONFIG_E2K_MODULES_DUPLICATION */

static inline pud_t *pud_alloc_track(struct mm_struct *mm, p4d_t *p4d,
				     unsigned long address,
				     pgtbl_mod_mask *mod_mask)
{
	if (unlikely(p4d_none(*p4d))) {
		if (__pud_alloc(mm, p4d, address))
			return NULL;
		*mod_mask |= PGTBL_P4D_MODIFIED;
	}

	return pud_offset(p4d, address);
}

# ifdef CONFIG_E2K_MODULES_DUPLICATION
static inline pud_t *pud_alloc_track_node(int node, struct mm_struct *mm,
					  p4d_t *p4d, unsigned long address)
{
	if (unlikely(p4d_none(*p4d))) {
		if (__pud_alloc_node(node, mm, p4d))
			return NULL;
	} else {
		/*
		 * If p4d entry points to existing page, check that
		 * this page is on the right node.
		 */
		BUG_ON(page_to_nid(p4d_page(*p4d)) != node);
	}

	return pud_offset(p4d, address);
}
# endif /* CONFIG_E2K_MODULES_DUPLICATION */

static inline pmd_t *pmd_alloc_track(struct mm_struct *mm, pud_t *pud,
				     unsigned long address,
				     pgtbl_mod_mask *mod_mask)
{
	if (unlikely(pud_none(*pud))) {
		if (__pmd_alloc(mm, pud, address))
			return NULL;
		*mod_mask |= PGTBL_PUD_MODIFIED;
	}

	return pmd_offset(pud, address);
}

# ifdef CONFIG_E2K_MODULES_DUPLICATION
static inline pmd_t *pmd_alloc_track_node(int node, struct mm_struct *mm,
					  pud_t *pud, unsigned long address)
{
	if (unlikely(pud_none(*pud))) {
		if (__pmd_alloc_node(node, mm, pud))
			return NULL;
	} else {
		/*
		 * If pud entry points to existing page, check that
		 * this page is on the right node.
		 */
		BUG_ON(page_to_nid(pud_page(*pud)) != node);
	}

	return pmd_offset(pud, address);
}
# endif /* CONFIG_E2K_MODULES_DUPLICATION */
#endif /* CONFIG_MMU */

#define pte_alloc_kernel_track(pmd, address, mask)			\
	((unlikely(pmd_none(*(pmd))) &&					\
	  (__pte_alloc_kernel(pmd) || ({*(mask)|=PGTBL_PMD_MODIFIED;0;})))?\
		NULL: pte_offset_kernel(pmd, address))

#ifdef CONFIG_E2K_MODULES_DUPLICATION
# define pte_alloc_kernel_track_node pte_alloc_kernel_track_node
static inline pte_t *pte_alloc_kernel_track_node(int node, pmd_t *pmd, unsigned long address)
{
	if (unlikely(pmd_none(*pmd))) {
		if (__pte_alloc_kernel_node(node, pmd))
			return NULL;
	} else {
		/*
		 * If pmd entry points to existing page, check that
		 * this page is on the right node.
		 */
		BUG_ON(page_to_nid(pmd_page(*pmd)) != node);
	}

	return pte_offset_kernel(pmd, address);
}
#endif /* CONFIG_E2K_MODULES_DUPLICATION */

#endif /* _LINUX_PGALLOC_TRACK_H */
