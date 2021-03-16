/*
 * pgtable_def.h: E2K page table common definitions.
 *
 * Copyright 2001 Salavat S. Guiliazov (atic@mcst.ru)
 */

#ifndef _ASM_E2K_PGTABLE_DEF_H
#define _ASM_E2K_PGTABLE_DEF_H

/*
 * This file contains the functions and defines necessary to modify and
 * use the E2K page tables.
 * NOTE: E2K has four levels of page tables.
 */

#include <linux/types.h>
#include <linux/mm_types.h>
#include <asm/mmu_types.h>
#include <asm/pgtable_types.h>
#include <asm/machdep.h>
#include <asm/page.h>
#include <asm/pgtable-v2.h>
#include <asm/pgtable-v6.h>
#include <asm/p2v/boot_v2p.h>

#ifndef __ASSEMBLY__

/* max. number of physical address bits (architected) */
static inline int
mmu_max_phys_addr_bits(bool mmu_pt_v6)
{
	return (mmu_pt_v6) ? E2K_MAX_PHYS_BITS_V6 : E2K_MAX_PHYS_BITS_V2;
}
static inline int
e2k_max_phys_addr_bits(void)
{
	return mmu_max_phys_addr_bits(MMU_IS_PT_V6());
}
#define	E2K_PHYS_BITS_NUM		e2k_max_phys_addr_bits()
#define	E2K_MAX_PHYS_BITS		E2K_MAX_PHYS_BITS_V6

/*
 * Hardware MMUs page tables have some differences from one ISET to other
 * moreover each MMU supports a few different page tables:
 *	native (primary)
 *	secondary page tables for sevral modes (VA32, VA48, PA32, PA48 ...)
 * The follow interface to manage page tables as common item
 */

static inline const pt_level_t *
get_pt_level_on_id(int level_id)
{
	/* now PT level is number of level */
	return get_pt_struct_level_on_id(&pgtable_struct, level_id);
}

static inline bool
is_huge_pmd_level(void)
{
	return is_huge_pt_struct_level(&pgtable_struct, E2K_PMD_LEVEL_NUM);
}

static inline bool
is_huge_pud_level(void)
{
	return is_huge_pt_struct_level(&pgtable_struct, E2K_PUD_LEVEL_NUM);
}

static inline bool
is_huge_pgd_level(void)
{
	return is_huge_pt_struct_level(&pgtable_struct, E2K_PGD_LEVEL_NUM);
}

static inline e2k_size_t
get_e2k_pt_level_size(int level_id)
{
	return get_pt_struct_level_size(&pgtable_struct, level_id);
}
static inline e2k_size_t
get_pgd_level_size(void)
{
	return get_e2k_pt_level_size(E2K_PGD_LEVEL_NUM);
}
static inline e2k_size_t
get_pud_level_size(void)
{
	return get_e2k_pt_level_size(E2K_PUD_LEVEL_NUM);
}
static inline e2k_size_t
get_pmd_level_size(void)
{
	return get_e2k_pt_level_size(E2K_PMD_LEVEL_NUM);
}
static inline e2k_size_t
get_pte_level_size(void)
{
	return get_e2k_pt_level_size(E2K_PTE_LEVEL_NUM);
}

static inline e2k_size_t
get_e2k_pt_level_page_size(int level_id)
{
	return get_pt_struct_level_page_size(&pgtable_struct, level_id);
}
static inline e2k_size_t
get_pgd_level_page_size(void)
{
	return get_e2k_pt_level_page_size(E2K_PGD_LEVEL_NUM);
}
static inline e2k_size_t
get_pud_level_page_size(void)
{
	return get_e2k_pt_level_page_size(E2K_PUD_LEVEL_NUM);
}
static inline e2k_size_t
get_pmd_level_page_size(void)
{
	return get_e2k_pt_level_page_size(E2K_PMD_LEVEL_NUM);
}
static inline e2k_size_t
get_pte_level_page_size(void)
{
	return get_e2k_pt_level_page_size(E2K_PTE_LEVEL_NUM);
}

static inline int
get_e2k_pt_level_huge_ptes_num(int level_id)
{
	return get_pt_struct_level_huge_ptes_num(&pgtable_struct, level_id);
}
static inline int
get_pgd_level_huge_ptes_num(void)
{
	return get_e2k_pt_level_huge_ptes_num(E2K_PGD_LEVEL_NUM);
}
static inline int
get_pud_level_huge_ptes_num(void)
{
	return get_e2k_pt_level_huge_ptes_num(E2K_PUD_LEVEL_NUM);
}
static inline int
get_pmd_level_huge_ptes_num(void)
{
	return get_e2k_pt_level_huge_ptes_num(E2K_PMD_LEVEL_NUM);
}

/*
 * PTE format
 */

static inline pteval_t
mmu_phys_addr_to_pte_pfn(e2k_addr_t phys_addr, bool mmu_pt_v6)
{
	if (mmu_pt_v6)
		return _PAGE_PADDR_TO_PFN_V6(phys_addr);
	else
		return _PAGE_PADDR_TO_PFN_V2(phys_addr);
}
static inline e2k_addr_t
mmu_pte_pfn_to_phys_addr(pteval_t pte_val, bool mmu_pt_v6)
{
	if (mmu_pt_v6)
		return _PAGE_PFN_TO_PADDR_V6(pte_val);
	else
		return _PAGE_PFN_TO_PADDR_V2(pte_val);
}

static inline pteval_t
phys_addr_to_pte_pfn(e2k_addr_t phys_addr)
{
	return mmu_phys_addr_to_pte_pfn(phys_addr, MMU_IS_PT_V6());
}
static inline e2k_addr_t
pte_pfn_to_phys_addr(pteval_t pte_val)
{
	return mmu_pte_pfn_to_phys_addr(pte_val, MMU_IS_PT_V6());
}
#define	_PAGE_PADDR_TO_PFN(phys_addr)	phys_addr_to_pte_pfn(phys_addr)
#define	_PAGE_PFN_TO_PADDR(pte_val)	pte_pfn_to_phys_addr(pte_val)

static inline pteval_t
mmu_kernel_protected_text_pte_val(pteval_t kernel_text_pte_val, e2k_addr_t cui,
					bool mmu_pt_v6)
{
	if (mmu_pt_v6)
		return convert_kernel_text_pte_val_v6_to_protected(
						kernel_text_pte_val);
	else
		return convert_kernel_text_pte_val_v2_to_protected(
						kernel_text_pte_val, cui);
}
static inline pteval_t
kernel_protected_text_pte_val(pteval_t kernel_text_pte_val, e2k_addr_t cui)
{
	return mmu_kernel_protected_text_pte_val(kernel_text_pte_val, cui,
							MMU_IS_PT_V6());
}
#define	_PAGE_KERNEL_PROT_TEXT(kernel_text_pte_val, cui)	\
		kernel_protected_text_pte_val(kernel_text_pte_val, cui)

/* PTE Memory Type */
static inline enum pte_mem_type get_pte_val_memory_type(pteval_t pte_val)
{
	if (MMU_IS_PT_V6())
		return get_pte_val_v6_memory_type(pte_val);
	else
		return get_pte_val_v2_memory_type(pte_val);
}
static inline pteval_t set_pte_val_memory_type(pteval_t pte_val,
		pte_mem_type_t memory_type)
{
	if (MMU_IS_PT_V6())
		return set_pte_val_v6_memory_type(pte_val, memory_type);
	else
		return set_pte_val_v2_memory_type(pte_val, memory_type);
}
#define	_PAGE_GET_MEM_TYPE(pte_val)	\
		get_pte_val_memory_type(pte_val)
#define	_PAGE_SET_MEM_TYPE(pte_val, memory_type)	\
		set_pte_val_memory_type(pte_val, memory_type)

static inline pteval_t
mmu_fill_pte_val_flags(const uni_pteval_t uni_flags, bool mmu_pt_v6)
{
	if (mmu_pt_v6)
		return fill_pte_val_v6_flags(uni_flags);
	else
		return fill_pte_val_v2_flags(uni_flags);
}
static inline pteval_t
mmu_get_pte_val_flags(pteval_t pte_val, const uni_pteval_t uni_flags,
			bool mmu_pt_v6)
{
	if (mmu_pt_v6)
		return get_pte_val_v6_flags(pte_val, uni_flags);
	else
		return get_pte_val_v2_flags(pte_val, uni_flags);
}
static inline bool
mmu_test_pte_val_flags(pteval_t pte_val, const uni_pteval_t uni_flags,
			bool mmu_pt_v6)
{
	return mmu_get_pte_val_flags(pte_val, uni_flags, mmu_pt_v6) != 0;
}
static inline pteval_t
mmu_set_pte_val_flags(pteval_t pte_val, const uni_pteval_t uni_flags,
			bool mmu_pt_v6)
{
	if (mmu_pt_v6)
		return set_pte_val_v6_flags(pte_val, uni_flags);
	else
		return set_pte_val_v2_flags(pte_val, uni_flags);
}
static inline pteval_t
mmu_clear_pte_val_flags(pteval_t pte_val, const uni_pteval_t uni_flags,
			bool mmu_pt_v6)
{
	if (mmu_pt_v6)
		return clear_pte_val_v6_flags(pte_val, uni_flags);
	else
		return clear_pte_val_v2_flags(pte_val, uni_flags);
}
static inline pteval_t
fill_pte_val_flags(const uni_pteval_t uni_flags)
{
	return mmu_fill_pte_val_flags(uni_flags, MMU_IS_PT_V6());
}
static inline pteval_t
get_pte_val_flags(pteval_t pte_val, const uni_pteval_t uni_flags)
{
	return mmu_get_pte_val_flags(pte_val, uni_flags, MMU_IS_PT_V6());
}
static inline bool
test_pte_val_flags(pteval_t pte_val, const uni_pteval_t uni_flags)
{
	return mmu_test_pte_val_flags(pte_val, uni_flags, MMU_IS_PT_V6());
}
static inline pteval_t
set_pte_val_flags(pteval_t pte_val, const uni_pteval_t uni_flags)
{
	return mmu_set_pte_val_flags(pte_val, uni_flags, MMU_IS_PT_V6());
}
static inline pteval_t
clear_pte_val_flags(pteval_t pte_val, const uni_pteval_t uni_flags)
{
	return mmu_clear_pte_val_flags(pte_val, uni_flags, MMU_IS_PT_V6());
}
#define	_PAGE_INIT(uni_flags)		fill_pte_val_flags(uni_flags)
#define	_PAGE_GET(pte_val, uni_flags)	get_pte_val_flags(pte_val, uni_flags)
#define	_PAGE_TEST(pte_val, uni_flags)	test_pte_val_flags(pte_val, uni_flags)
#define	_PAGE_SET(pte_val, uni_flags)	set_pte_val_flags(pte_val, uni_flags)
#define	_PAGE_CLEAR(pte_val, uni_flags)	clear_pte_val_flags(pte_val, uni_flags)

static inline pteval_t
mmu_get_pte_val_changeable_mask(bool mmu_pt_v6)
{
	if (mmu_pt_v6)
		return get_pte_val_v6_changeable_mask();
	else
		return get_pte_val_v2_changeable_mask();
}
static inline pteval_t
mmu_get_huge_pte_val_changeable_mask(bool mmu_pt_v6)
{
	if (mmu_pt_v6)
		return get_huge_pte_val_v6_changeable_mask();
	else
		return get_huge_pte_val_v2_changeable_mask();
}
static inline pteval_t
mmu_get_pte_val_reduceable_mask(bool mmu_pt_v6)
{
	if (mmu_pt_v6)
		return get_pte_val_v6_reduceable_mask();
	else
		return get_pte_val_v2_reduceable_mask();
}
static inline pteval_t
mmu_get_pte_val_restricted_mask(bool mmu_pt_v6)
{
	if (mmu_pt_v6)
		return get_pte_val_v6_restricted_mask();
	else
		return get_pte_val_v2_restricted_mask();
}
static inline pteval_t
get_pte_val_changeable_mask(void)
{
	return mmu_get_pte_val_changeable_mask(MMU_IS_PT_V6());
}
static inline pteval_t
get_huge_pte_val_changeable_mask(void)
{
	return mmu_get_huge_pte_val_changeable_mask(MMU_IS_PT_V6());
}
static inline pteval_t
get_pte_val_reduceable_mask(void)
{
	return mmu_get_pte_val_reduceable_mask(MMU_IS_PT_V6());
}
static inline pteval_t
get_pte_val_restricted_mask(void)
{
	return mmu_get_pte_val_restricted_mask(MMU_IS_PT_V6());
}

#define _PAGE_CHG_MASK		get_pte_val_changeable_mask()
#define _HPAGE_CHG_MASK		get_huge_pte_val_changeable_mask()
#define _PROT_REDUCE_MASK	get_pte_val_reduceable_mask()
#define _PROT_RESTRICT_MASK	get_pte_val_restricted_mask()

/* some the most popular PTEs */
#define	_PAGE_INIT_VALID		_PAGE_INIT(UNI_PAGE_VALID)
#define	_PAGE_GET_VALID(pte_val)	_PAGE_GET(pte_val, UNI_PAGE_VALID)
#define	_PAGE_TEST_VALID(pte_val)	_PAGE_TEST(pte_val, UNI_PAGE_VALID)
#define	_PAGE_SET_VALID(pte_val)	_PAGE_SET(pte_val, UNI_PAGE_VALID)
#define	_PAGE_CLEAR_VALID(pte_val)	_PAGE_CLEAR(pte_val, UNI_PAGE_VALID)

#define	_PAGE_INIT_PRESENT		_PAGE_INIT(UNI_PAGE_PRESENT)
#define	_PAGE_GET_PRESENT(pte_val)	_PAGE_GET(pte_val, UNI_PAGE_PRESENT)
#define	_PAGE_TEST_PRESENT(pte_val)	_PAGE_TEST(pte_val, UNI_PAGE_PRESENT)
#define	_PAGE_SET_PRESENT(pte_val)	_PAGE_SET(pte_val, UNI_PAGE_PRESENT)
#define	_PAGE_CLEAR_PRESENT(pte_val)	_PAGE_CLEAR(pte_val, UNI_PAGE_PRESENT)

#define	_PAGE_INIT_PROTNONE		_PAGE_INIT(UNI_PAGE_PROTNONE)
#define	_PAGE_GET_PROTNONE(pte_val)	_PAGE_GET(pte_val, UNI_PAGE_PROTNONE)
#define	_PAGE_TEST_PROTNONE(pte_val)	_PAGE_TEST(pte_val, UNI_PAGE_PROTNONE)
#define	_PAGE_SET_PROTNONE(pte_val)	_PAGE_SET(pte_val, UNI_PAGE_PROTNONE)
#define	_PAGE_CLEAR_PROTNONE(pte_val)	_PAGE_CLEAR(pte_val, UNI_PAGE_PROTNONE)

#define	_PAGE_INIT_WRITEABLE		_PAGE_INIT(UNI_PAGE_WRITE)
#define	_PAGE_GET_WRITEABLE(pte_val)	_PAGE_GET(pte_val, UNI_PAGE_WRITE)
#define	_PAGE_TEST_WRITEABLE(pte_val)	_PAGE_TEST(pte_val, UNI_PAGE_WRITE)
#define	_PAGE_SET_WRITEABLE(pte_val)	_PAGE_SET(pte_val, UNI_PAGE_WRITE)
#define	_PAGE_CLEAR_WRITEABLE(pte_val)	_PAGE_CLEAR(pte_val, UNI_PAGE_WRITE)

#define	_PAGE_INIT_PRIV			_PAGE_INIT(UNI_PAGE_PRIV)
#define	_PAGE_GET_PRIV(pte_val)		_PAGE_GET(pte_val, UNI_PAGE_PRIV)
#define	_PAGE_TEST_PRIV(pte_val)	_PAGE_TEST(pte_val, UNI_PAGE_PRIV)
#define	_PAGE_SET_PRIV(pte_val)		_PAGE_SET(pte_val, UNI_PAGE_PRIV)
#define	_PAGE_CLEAR_PRIV(pte_val)	_PAGE_CLEAR(pte_val, UNI_PAGE_PRIV)

#define	_PAGE_INIT_ACCESSED		_PAGE_INIT(UNI_PAGE_ACCESSED)
#define	_PAGE_GET_ACCESSED(pte_val)	_PAGE_GET(pte_val, UNI_PAGE_ACCESSED)
#define	_PAGE_TEST_ACCESSED(pte_val)	_PAGE_TEST(pte_val, UNI_PAGE_ACCESSED)
#define	_PAGE_SET_ACCESSED(pte_val)	_PAGE_SET(pte_val, UNI_PAGE_ACCESSED)
#define	_PAGE_CLEAR_ACCESSED(pte_val)	_PAGE_CLEAR(pte_val, UNI_PAGE_ACCESSED)

#define	_PAGE_INIT_DIRTY		_PAGE_INIT(UNI_PAGE_DIRTY)
#define	_PAGE_GET_DIRTY(pte_val)	_PAGE_GET(pte_val, UNI_PAGE_DIRTY)
#define	_PAGE_TEST_DIRTY(pte_val)	_PAGE_TEST(pte_val, UNI_PAGE_DIRTY)
#define	_PAGE_SET_DIRTY(pte_val)	_PAGE_SET(pte_val, UNI_PAGE_DIRTY)
#define	_PAGE_CLEAR_DIRTY(pte_val)	_PAGE_CLEAR(pte_val, UNI_PAGE_DIRTY)

#define	_PAGE_INIT_HUGE			_PAGE_INIT(UNI_PAGE_HUGE)
#define	_PAGE_GET_HUGE(pte_val)		_PAGE_GET(pte_val, UNI_PAGE_HUGE)
#define	_PAGE_TEST_HUGE(pte_val)	_PAGE_TEST(pte_val, UNI_PAGE_HUGE)
#define	_PAGE_SET_HUGE(pte_val)		_PAGE_SET(pte_val, UNI_PAGE_HUGE)
#define	_PAGE_CLEAR_HUGE(pte_val)	_PAGE_CLEAR(pte_val, UNI_PAGE_HUGE)

#define	_PAGE_INIT_NOT_EXEC		_PAGE_INIT(UNI_PAGE_NON_EX)
#define	_PAGE_GET_NOT_EXEC(pte_val)	_PAGE_GET(pte_val, UNI_PAGE_NON_EX)
#define	_PAGE_TEST_NOT_EXEC(pte_val)	_PAGE_TEST(pte_val, UNI_PAGE_NON_EX)
#define	_PAGE_SET_NOT_EXEC(pte_val)	_PAGE_SET(pte_val, UNI_PAGE_NON_EX)
#define	_PAGE_CLEAR_NOT_EXEC(pte_val)	_PAGE_CLEAR(pte_val, UNI_PAGE_NON_EX)

#define	_PAGE_INIT_EXECUTEABLE		((pteval_t)0ULL)
#define	_PAGE_TEST_EXECUTEABLE(pte_val)	(!_PAGE_TEST_NOT_EXEC(pte_val))
#define	_PAGE_SET_EXECUTEABLE(pte_val)	_PAGE_CLEAR_NOT_EXEC(pte_val)
#define	_PAGE_CLEAR_EXECUTEABLE(pte_val) _PAGE_SET_NOT_EXEC(pte_val)

#define	_PAGE_INIT_SPECIAL		_PAGE_INIT(UNI_PAGE_SPECIAL)
#define	_PAGE_GET_SPECIAL(pte_val)	_PAGE_GET(pte_val, UNI_PAGE_SPECIAL)
#define	_PAGE_TEST_SPECIAL(pte_val)	_PAGE_TEST(pte_val, UNI_PAGE_SPECIAL)
#define	_PAGE_SET_SPECIAL(pte_val)	_PAGE_SET(pte_val, UNI_PAGE_SPECIAL)
#define	_PAGE_CLEAR_SPECIAL(pte_val)	_PAGE_CLEAR(pte_val, UNI_PAGE_SPECIAL)

#define	_PAGE_PFN_MASK			_PAGE_INIT(UNI_PAGE_PFN)

#define _PAGE_KERNEL_RX_NOT_GLOB	\
		_PAGE_INIT(UNI_PAGE_PRESENT | UNI_PAGE_VALID | \
				 UNI_PAGE_PRIV | UNI_PAGE_HW_ACCESS)
#define _PAGE_KERNEL_RO_NOT_GLOB	\
		_PAGE_INIT(UNI_PAGE_PRESENT | UNI_PAGE_VALID | \
				UNI_PAGE_PRIV | UNI_PAGE_HW_ACCESS | \
				UNI_PAGE_NON_EX)
#define _PAGE_KERNEL_RWX_NOT_GLOB	\
		_PAGE_SET(_PAGE_KERNEL_RX_NOT_GLOB, \
				UNI_PAGE_WRITE | UNI_PAGE_DIRTY)
#define _PAGE_KERNEL_RW_NOT_GLOB	\
		_PAGE_SET(_PAGE_KERNEL_RWX_NOT_GLOB, UNI_PAGE_NON_EX)
#define _PAGE_KERNEL_HUGE_RW_NOT_GLOB	\
		_PAGE_SET(_PAGE_KERNEL_RW_NOT_GLOB, UNI_PAGE_HUGE)
#ifdef	CONFIG_GLOBAL_CONTEXT
#define _PAGE_KERNEL_RX		\
		_PAGE_SET(_PAGE_KERNEL_RX_NOT_GLOB, UNI_PAGE_GLOBAL)
#define _PAGE_KERNEL_RO		\
		_PAGE_SET(_PAGE_KERNEL_RO_NOT_GLOB, UNI_PAGE_GLOBAL)
#define _PAGE_KERNEL_RWX	\
		_PAGE_SET(_PAGE_KERNEL_RWX_NOT_GLOB, UNI_PAGE_GLOBAL)
#define _PAGE_KERNEL_RW		\
		_PAGE_SET(_PAGE_KERNEL_RW_NOT_GLOB, UNI_PAGE_GLOBAL)
#define _PAGE_KERNEL_HUGE_RW	\
		_PAGE_SET(_PAGE_KERNEL_HUGE_RW_NOT_GLOB, UNI_PAGE_GLOBAL)
#else	/* ! CONFIG_GLOBAL_CONTEXT */
#define _PAGE_KERNEL_RX		_PAGE_KERNEL_RX_NOT_GLOB
#define _PAGE_KERNEL_RO		_PAGE_KERNEL_RO_NOT_GLOB
#define _PAGE_KERNEL_RWX	_PAGE_KERNEL_RWX_NOT_GLOB
#define _PAGE_KERNEL_RW		_PAGE_KERNEL_RW_NOT_GLOB
#define _PAGE_KERNEL_HUGE_RW	_PAGE_KERNEL_HUGE_RW_NOT_GLOB
#endif	/* CONFIG_GLOBAL_CONTEXT */

#define _PAGE_KERNEL		_PAGE_KERNEL_RW
#define _PAGE_KERNEL_HUGE	_PAGE_KERNEL_HUGE_RW
#define _PAGE_KERNEL_IMAGE	_PAGE_KERNEL_RX
#define _PAGE_KERNEL_PT		_PAGE_KERNEL
#define _PAGE_USER_PT		_PAGE_KERNEL_RW_NOT_GLOB
#define _PAGE_KERNEL_PTE	_PAGE_KERNEL_PT
#define _PAGE_KERNEL_PMD	_PAGE_KERNEL_PT
#define _PAGE_KERNEL_PUD	_PAGE_KERNEL_PT
#define _PAGE_USER_PTE		_PAGE_USER_PT
#define _PAGE_USER_PMD		_PAGE_USER_PT
#define _PAGE_USER_PUD		_PAGE_USER_PT

#define _PAGE_IO_MAP_BASE	_PAGE_KERNEL_RW
#define _PAGE_IO_MAP		\
		_PAGE_SET_MEM_TYPE(_PAGE_IO_MAP_BASE, EXT_NON_PREFETCH_MT)
#define _PAGE_IO_PORTS		\
		_PAGE_SET_MEM_TYPE(_PAGE_IO_MAP_BASE, EXT_NON_PREFETCH_MT)

#define _PAGE_KERNEL_SWITCHING_IMAGE	\
		_PAGE_SET_MEM_TYPE(_PAGE_KERNEL_RX_NOT_GLOB, EXT_CONFIG_MT)

#define _PAGE_PROT_MASK		\
		_PAGE_INIT(UNI_PAGE_PRESENT | UNI_PAGE_VALID | \
					UNI_PAGE_WRITE | UNI_PAGE_NON_EX)

#define _PAGE_USER		\
		_PAGE_INIT(UNI_PAGE_PRESENT | UNI_PAGE_VALID | \
			UNI_PAGE_WRITE | UNI_PAGE_DIRTY | UNI_PAGE_NON_EX)
#define _PAGE_USER_RO_ACCESSED	\
		_PAGE_INIT(UNI_PAGE_PRESENT | UNI_PAGE_VALID | \
			UNI_PAGE_HW_ACCESS | UNI_PAGE_NON_EX)

#define PAGE_KERNEL		__pgprot(_PAGE_KERNEL)
#define PAGE_KERNEL_RO		__pgprot(_PAGE_KERNEL_RO)
#define PAGE_KERNEL_EXEC	__pgprot(_PAGE_KERNEL_RWX)
#define	PAGE_KERNEL_LARGE	__pgprot(_PAGE_KERNEL_HUGE)
#define	PAGE_KERNEL_PTE		__pgprot(_PAGE_KERNEL_PTE)
#define	PAGE_KERNEL_PMD		__pgprot(_PAGE_KERNEL_PMD)
#define	PAGE_KERNEL_PUD		__pgprot(_PAGE_KERNEL_PUD)
#define	PAGE_USER_PTE		__pgprot(_PAGE_USER_PTE)
#define	PAGE_USER_PMD		__pgprot(_PAGE_USER_PMD)
#define	PAGE_USER_PUD		__pgprot(_PAGE_USER_PUD)

#define	PAGE_KERNEL_NOCACHE	PAGE_IO_MAP

#define PAGE_USER		__pgprot(_PAGE_USER)
#define PAGE_USER_RO_ACCESSED	__pgprot(_PAGE_USER_RO_ACCESSED)

#define PAGE_KERNEL_TEXT	__pgprot(_PAGE_KERNEL_IMAGE)

#define PAGE_KERNEL_DATA	\
		__pgprot(_PAGE_SET(_PAGE_KERNEL_IMAGE, \
				UNI_PAGE_WRITE | UNI_PAGE_DIRTY | \
					UNI_PAGE_NON_EX))
#define PAGE_KERNEL_STACK	\
		__pgprot(_PAGE_SET(_PAGE_KERNEL, UNI_PAGE_NON_EX))

#define PAGE_USER_HWS		__pgprot(_PAGE_KERNEL_RW_NOT_GLOB)
#define PAGE_USER_PS		PAGE_USER_HWS
#define PAGE_USER_PCS		PAGE_USER_HWS
#define PAGE_USER_STACK		\
		__pgprot(_PAGE_SET(_PAGE_USER, UNI_PAGE_NON_EX))

#define PAGE_TAG_MEMORY		__pgprot(_PAGE_KERNEL_RW_NOT_GLOB)

#define PAGE_BOOTINFO		\
		__pgprot(_PAGE_SET(_PAGE_KERNEL_IMAGE, UNI_PAGE_NON_EX))

#define PAGE_INITRD		\
		__pgprot(_PAGE_SET(_PAGE_KERNEL_IMAGE, UNI_PAGE_NON_EX))

#define PAGE_MPT		\
		__pgprot(_PAGE_SET(_PAGE_KERNEL_IMAGE, UNI_PAGE_NON_EX))

#define PAGE_KERNEL_NAMETAB	\
		__pgprot(_PAGE_SET(_PAGE_KERNEL_IMAGE, UNI_PAGE_NON_EX))

#define PAGE_MAPPED_PHYS_MEM	__pgprot(_PAGE_KERNEL)

#define PAGE_CNTP_MAPPED_MEM	\
		__pgprot(_PAGE_SET(_PAGE_KERNEL_IMAGE, UNI_PAGE_NON_EX))

#define PAGE_X86_IO_PORTS	__pgprot(_PAGE_IO_PORTS)

#define PAGE_IO_MAP		__pgprot(_PAGE_IO_MAP)

#define	PAGE_KERNEL_SWITCHING_TEXT	__pgprot(_PAGE_KERNEL_SWITCHING_IMAGE)
#define	PAGE_KERNEL_SWITCHING_DATA	\
		__pgprot(_PAGE_SET(_PAGE_KERNEL_SWITCHING_IMAGE, \
					UNI_PAGE_WRITE | UNI_PAGE_NON_EX))
#define	PAGE_KERNEL_SWITCHING_US_STACK	\
		__pgprot(_PAGE_SET_MEM_TYPE(_PAGE_KERNEL_RW_NOT_GLOB, \
						 EXT_CONFIG_MT))

#define PAGE_SHARED		\
		__pgprot(_PAGE_INIT(UNI_PAGE_PRESENT | UNI_PAGE_VALID | \
				UNI_PAGE_HW_ACCESS | UNI_PAGE_SW_ACCESS | \
				UNI_PAGE_WRITE | UNI_PAGE_NON_EX))
#define PAGE_SHARED_EX		\
		__pgprot(_PAGE_INIT(UNI_PAGE_PRESENT | UNI_PAGE_VALID | \
				UNI_PAGE_HW_ACCESS | UNI_PAGE_SW_ACCESS | \
				UNI_PAGE_WRITE))
#define	PAGE_COPY_NEX		\
		__pgprot(_PAGE_INIT(UNI_PAGE_PRESENT | UNI_PAGE_VALID | \
				UNI_PAGE_HW_ACCESS | UNI_PAGE_SW_ACCESS | \
				UNI_PAGE_NON_EX))
#define	PAGE_COPY_EX		\
		__pgprot(_PAGE_INIT(UNI_PAGE_PRESENT | UNI_PAGE_VALID | \
				UNI_PAGE_HW_ACCESS | UNI_PAGE_SW_ACCESS))

#define	PAGE_COPY		PAGE_COPY_NEX

#define PAGE_READONLY		\
		__pgprot(_PAGE_INIT(UNI_PAGE_PRESENT | UNI_PAGE_VALID | \
				UNI_PAGE_HW_ACCESS | UNI_PAGE_SW_ACCESS | \
				UNI_PAGE_NON_EX))
#define PAGE_EXECUTABLE		\
		__pgprot(_PAGE_INIT(UNI_PAGE_PRESENT | UNI_PAGE_VALID | \
				UNI_PAGE_HW_ACCESS | UNI_PAGE_SW_ACCESS))

/*
 * PAGE_NONE is used for NUMA hinting faults and should be valid.
 * __P000/__S000 are used for mmap(PROT_NONE) mapping and should be not valid.
 */
#define	PAGE_ENPTY		__pgprot(0ULL)
#define PAGE_NONE		\
		__pgprot(_PAGE_INIT(UNI_PAGE_PROTNONE | UNI_PAGE_HW_ACCESS | \
					UNI_PAGE_VALID))
#define PAGE_NONE_INVALID	\
		__pgprot(_PAGE_INIT(UNI_PAGE_PROTNONE | UNI_PAGE_HW_ACCESS))

#define PAGE_INT_PR		\
		__pgprot(_PAGE_INIT(UNI_PAGE_INT_PR))

/*
 * Next come the mappings that determine how mmap() protection bits
 * (PROT_EXEC, PROT_READ, PROT_WRITE, PROT_NONE) get implemented.  The
 * _P version gets used for a private shared memory segment, the _S
 * version gets used for a shared memory segment with MAP_SHARED on.
 * In a private shared memory segment, we do a copy-on-write if a task
 * attempts to write to the page.
 */
 /* initial boot-time page protections are not used, */
 /* so can be set to empty state */
	/* xwr */
#define __P000	PAGE_ENPTY	/* PAGE_NONE_INVALID */
#define __P001	PAGE_ENPTY	/* PAGE_READONLY */
#define __P010	PAGE_ENPTY	/* PAGE_COPY_NEX */
#define __P011	PAGE_ENPTY	/* PAGE_COPY_NEX */
#define __P100	PAGE_ENPTY	/* PAGE_EXECUTABLE */
#define __P101	PAGE_ENPTY	/* PAGE_EXECUTABLE */
#define __P110	PAGE_ENPTY	/* PAGE_COPY_EX */
#define __P111	PAGE_ENPTY	/* PAGE_COPY_EX */

#define __S000	PAGE_ENPTY	/* PAGE_NONE_INVALID */
#define __S001	PAGE_ENPTY	/* PAGE_READONLY */
#define __S010	PAGE_ENPTY	/* PAGE_SHARED */
#define __S011	PAGE_ENPTY	/* PAGE_SHARED */
#define __S100	PAGE_ENPTY	/* PAGE_EXECUTABLE */
#define __S101	PAGE_ENPTY	/* PAGE_EXECUTABLE */
#define __S110	PAGE_ENPTY	/* PAGE_SHARED_EX */
#define __S111	PAGE_ENPTY	/* PAGE_SHARED_EX */

/* real protection map */
	/* xwr */
#define PROT_MAP_P000	PAGE_NONE_INVALID
#define PROT_MAP_P001	PAGE_READONLY
#define PROT_MAP_P010	PAGE_COPY_NEX
#define PROT_MAP_P011	PAGE_COPY_NEX
#define PROT_MAP_P100	PAGE_EXECUTABLE
#define PROT_MAP_P101	PAGE_EXECUTABLE
#define PROT_MAP_P110	PAGE_COPY_EX
#define PROT_MAP_P111	PAGE_COPY_EX

#define PROT_MAP_S000	PAGE_NONE_INVALID
#define PROT_MAP_S001	PAGE_READONLY
#define PROT_MAP_S010	PAGE_SHARED
#define PROT_MAP_S011	PAGE_SHARED
#define PROT_MAP_S100	PAGE_EXECUTABLE
#define PROT_MAP_S101	PAGE_EXECUTABLE
#define PROT_MAP_S110	PAGE_SHARED_EX
#define PROT_MAP_S111	PAGE_SHARED_EX

static inline void
create_protection_map(pgprot_t prot_map[16])
{
	prot_map[0] = PROT_MAP_P000;
	prot_map[1] = PROT_MAP_P001;
	prot_map[2] = PROT_MAP_P010;
	prot_map[3] = PROT_MAP_P011;
	prot_map[4] = PROT_MAP_P100;
	prot_map[5] = PROT_MAP_P101;
	prot_map[6] = PROT_MAP_P110;
	prot_map[7] = PROT_MAP_P111;

	prot_map[8 + 0] = PROT_MAP_S000;
	prot_map[8 + 1] = PROT_MAP_S001;
	prot_map[8 + 2] = PROT_MAP_S010;
	prot_map[8 + 3] = PROT_MAP_S011;
	prot_map[8 + 4] = PROT_MAP_S100;
	prot_map[8 + 5] = PROT_MAP_S101;
	prot_map[8 + 6] = PROT_MAP_S110;
	prot_map[8 + 7] = PROT_MAP_S111;
}

#define pgd_ERROR(e)						\
	do {							\
		pr_warn("%s:%d: bad pgd 0x%016lx.\n",		\
			__FILE__, __LINE__, pgd_val(e));	\
		dump_stack();					\
	} while (0)
#define pud_ERROR(e)						\
	do {							\
		pr_warn("%s:%d: bad pud 0x%016lx.\n",		\
			__FILE__, __LINE__, pud_val(e));	\
		dump_stack();					\
	} while (0)
#define pmd_ERROR(e)						\
	do {							\
		pr_warn("%s:%d: bad pmd 0x%016lx.\n",		\
			__FILE__, __LINE__, pmd_val(e));	\
		dump_stack();					\
	} while (0)
#define pte_ERROR(e)						\
	do {							\
		pr_warn("%s:%d: bad pte 0x%016lx.\n",		\
			__FILE__, __LINE__, pte_val(e));	\
		dump_stack();					\
	} while (0)

/*
 * This takes a physical page address and protection bits to make
 * pte/pmd/pud/pgd
 */
#define mk_pte_phys(phys_addr, pgprot) \
	(__pte(_PAGE_PADDR_TO_PFN(phys_addr) | pgprot_val(pgprot)))
#define mk_pmd_phys(phys_addr, pgprot) \
	(__pmd(_PAGE_PADDR_TO_PFN(phys_addr) | pgprot_val(pgprot)))
#define mk_pud_phys(phys_addr, pgprot) \
	(__pud(_PAGE_PADDR_TO_PFN(phys_addr) | pgprot_val(pgprot)))
#define mk_pgd_phys(phys_addr, pgprot) \
	(__pgd(_PAGE_PADDR_TO_PFN(phys_addr) | pgprot_val(pgprot)))

#define mk_pmd_addr(virt_addr, pgprot) \
	(__pmd(_PAGE_PADDR_TO_PFN(__pa(virt_addr)) | pgprot_val(pgprot)))
#define mk_pud_addr(virt_addr, pgprot) \
	(__pud(_PAGE_PADDR_TO_PFN(__pa(virt_addr)) | pgprot_val(pgprot)))
#define mk_pgd_addr(virt_addr, pgprot) \
	(__pgd(_PAGE_PADDR_TO_PFN(__pa(virt_addr)) | pgprot_val(pgprot)))

/*
 * Conversion functions: convert page frame number (pfn) and
 * a protection value to a page table entry (pte).
 */
#define pfn_pte(pfn, pgprot)	mk_pte_phys((pfn) << PAGE_SHIFT, pgprot)
#define pfn_pmd(pfn, pgprot)	mk_pmd_phys((pfn) << PAGE_SHIFT, pgprot)

/*
 * Currently all these mappings correlate to what arm64 uses
 * and there must be a good reason to use anything else.
 *
 * Any changes here should take into account set_general_mt()
 * and set_external_mt().
 */
#define pgprot_device(prot) \
	(__pgprot(_PAGE_SET_MEM_TYPE(pgprot_val(prot), EXT_NON_PREFETCH_MT)))
#define pgprot_noncached(prot) \
	(__pgprot(_PAGE_SET_MEM_TYPE(pgprot_val(prot), GEN_NON_CACHE_ORDERED_MT)))
/* pgprot_writecombine() can be used both for RAM and devices, and while
 * "general" memory type can be used for devices using "external" type
 * for RAM is prohibited as it disables cache snooping.  So by default
 * use "general" memory type for it. */
#define pgprot_writecombine(prot) \
	__pgprot(_PAGE_SET_MEM_TYPE(pgprot_val(prot), GEN_NON_CACHE_MT))

#define pgprot_writethrough pgprot_writecombine

/* PTE_PFN_MASK extracts the PFN from a (pte|pmd|pud|pgd)val_t */
#define PTE_PFN_MASK		_PAGE_PFN_MASK

/* PTE_FLAGS_MASK extracts the flags from a (pte|pmd|pud|pgd)val_t */
#define PTE_FLAGS_MASK		(~PTE_PFN_MASK)

/* PTE_PROT_MASK extracts the protection flags from a (pte|pmd|pud|pgd)val_t */
#define	PTE_PROTECTS_MASK	_PAGE_INIT(UNI_PAGE_WRITE | UNI_PAGE_NON_EX)

/* PT_USER_FLAGS_MASK extracts the flags from a user (pgd|pud|pmd)val_t */
#define PMD_USER_FLAGS_MASK	_PAGE_SET(_PAGE_USER_PTE, UNI_PAGE_HUGE)
#define PUD_USER_FLAGS_MASK	(_PAGE_USER_PMD)
#define PGD_USER_FLAGS_MASK	(_PAGE_USER_PUD)

static inline pteval_t pte_flags(pte_t pte)
{
	return pte_val(pte) & PTE_FLAGS_MASK;
}
static inline pteval_t pte_only_flags(pte_t pte)
{
	return pte_flags(pte) & ~PTE_PROTECTS_MASK;
}
static inline pteval_t pte_only_protects(pte_t pte)
{
	return pte_val(pte) & PTE_PROTECTS_MASK;
}

static inline pmdval_t pmd_user_flags(pmd_t pmd)
{
	return pmd_val(pmd) & PMD_USER_FLAGS_MASK;
}

static inline pudval_t pud_user_flags(pud_t pud)
{
	return pud_val(pud) & PUD_USER_FLAGS_MASK;
}

static inline pgdval_t pgd_user_flags(pgd_t pgd)
{
	return pgd_val(pgd) & PGD_USER_FLAGS_MASK;
}

/*
 * Extract pfn from pte.
 */
#define pte_pfn(pte)	(_PAGE_PFN_TO_PADDR(pte_val(pte)) >> PAGE_SHIFT)
#define pmd_pfn(pmd)	(_PAGE_PFN_TO_PADDR(pmd_val(pmd)) >> PAGE_SHIFT)
#define pud_pfn(pud)	(_PAGE_PFN_TO_PADDR(pud_val(pud)) >> PAGE_SHIFT)
#define pgd_pfn(pgd)	(_PAGE_PFN_TO_PADDR(pgd_val(pgd)) >> PAGE_SHIFT)

#define mk_pte(page, pgprot)	pfn_pte(page_to_pfn(page), (pgprot))
#define mk_pmd(page, pgprot)	pfn_pmd(page_to_pfn(page), (pgprot))

#define mk_pfn_pte(pfn, pte)	\
		pfn_pte(pfn, __pgprot(pte_val(pte) & ~_PAGE_PFN_MASK))
#define mk_clone_pte(page, pte)	\
		pfn_pte(page_to_pfn(page), \
				__pgprot(pte_val(pte) & ~_PAGE_PFN_MASK))
#define mk_not_present_pte(pgprot)	\
		__pte(_PAGE_CLEAR_PRESENT(pgprot_val(pgprot)))
#define mk_guest_pfn_prot(pgprot)	\
		__pgprot(_PAGE_SET(pgprot_val(pgprot), UNI_PAGE_GFN))
#define mk_pte_pgprot(pte, pgprot)	\
		__pte(pte_val(pte) | pgprot_val(pgprot))
#define mk_pmd_pgprot(pmd, pgprot)	\
		__pmd(pmd_val(pmd) | pgprot_val(pgprot))
#define page_pte_prot(page, prot)	mk_pte(page, prot)
#define page_pte(page)			page_pte_prot(page, __pgprot(0))

#define pgprot_modify_mask(old_prot, newprot_val, prot_mask) \
		(__pgprot(((pgprot_val(old_prot) & ~(prot_mask)) | \
		((newprot_val) & (prot_mask)))))

#define pgprot_large_size_set(prot) \
		__pgprot(_PAGE_SET_HUGE(pgprot_val(prot)))
#define pgprot_small_size_set(prot) \
		__pgprot(_PAGE_CLEAR_HUGE(pgprot_val(prot)))
#define pgprot_present_flag_set(prot) \
		pgprot_modify_mask(prot, _PAGE_INIT_PRESENT, _PAGE_INIT_PRESENT)
#define pgprot_present_flag_reset(prot) \
		pgprot_modify_mask(prot, 0UL, \
			_PAGE_INIT(UNI_PAGE_PRESENT | UNI_PAGE_PFN))
#define _pgprot_reduce(src_prot_val, reduced_prot_val) \
		(((src_prot_val) & ~(_PROT_REDUCE_MASK)) | \
			(((src_prot_val) & (_PROT_REDUCE_MASK)) | \
			((reduced_prot_val) & (_PROT_REDUCE_MASK))))
#define _pgprot_restrict(src_prot_val, restricted_prot_val) \
		(((src_prot_val) & ~(_PROT_RESTRICT_MASK)) | \
			(((src_prot_val) & (_PROT_RESTRICT_MASK)) & \
			((restricted_prot_val) & (_PROT_RESTRICT_MASK))))
#define pgprot_reduce(src_prot, reduced_prot) \
		(__pgprot(_pgprot_reduce(pgprot_val(src_prot), \
					pgprot_val(reduced_prot))))
#define pgprot_restrict(src_prot, restricted_prot) \
		(__pgprot(_pgprot_restrict(pgprot_val(src_prot), \
					pgprot_val(restricted_prot))))
#define pte_reduce_prot(src_pte, reduced_prot) \
		(__pte(_pgprot_reduce(pte_val(src_pte), \
					pgprot_val(reduced_prot))))
#define pte_restrict_prot(src_pte, restricted_prot) \
		(__pte(_pgprot_restrict(pte_val(src_pte), \
					pgprot_val(restricted_prot))))
#define pgprot_priv(pgprot)		_PAGE_TEST_PRIV(pgprot_val(pgprot))
#define pgprot_present(pgprot)		_PAGE_TEST_PRESENT(pgprot_val(pgprot))
#define pgprot_valid(pgprot)		_PAGE_TEST_VALID(pgprot_val(pgprot))
#define	pgprot_write(pgprot)		_PAGE_TEST_WRITEABLE(pgprot_val(pgprot))
#define	pgprot_huge(pgprot)		_PAGE_TEST_HUGE(pgprot_val(pgprot))
#define	pgprot_special(pgprot)		_PAGE_TEST_SPECIAL(pgprot_val(pgprot))

static inline pte_t pte_modify(pte_t pte, pgprot_t newprot)
{
	pteval_t val = pte_val(pte);

	val &= _PAGE_CHG_MASK;
	val |= pgprot_val(newprot) & ~_PAGE_CHG_MASK;

	return __pte(val);
}

static inline pmd_t pmd_modify(pmd_t pmd, pgprot_t newprot)
{
	pmdval_t val = pmd_val(pmd);

	val &= _HPAGE_CHG_MASK;
	val |= pgprot_val(newprot) & ~_HPAGE_CHG_MASK;

	return __pmd(val);
}

#ifndef	CONFIG_MAKE_ALL_PAGES_VALID
# define pte_none(pte)	(!pte_val(pte))
#else
# define pte_none(pte)	(_PAGE_CLEAR_VALID(pte_val(pte)) == 0)
#endif

#define pte_valid(pte)			_PAGE_TEST_VALID(pte_val(pte))
#define pte_present(pte)		\
		_PAGE_TEST(pte_val(pte), UNI_PAGE_PRESENT | UNI_PAGE_PROTNONE)
#define pte_secondary(pte)		(pte_val(pte) & _PAGE_SEC_MAP)
#define pte_priv(pte)			_PAGE_TEST_PRIV(pte_val(pte))
#define pte_clear_guest(pte)		\
		(__pte(_PAGE_CLEAR(pte_val(pte), \
					UNI_PAGE_PRIV | UNI_PAGE_GLOBAL)))
#define pte_set_priv(pte)		__pte(_PAGE_SET_PRIV(pte_val(pte)))
#define	pte_large_page(pte)		_PAGE_TEST_HUGE(pte_val(pte))
#define	pte_set_small_size(pte)		__pte(_PAGE_CLEAR_HUGE(pte_val(pte)))
#define	pte_set_large_size(pte)		__pte(_PAGE_SET_HUGE(pte_val(pte)))

#define pte_accessible(mm, pte) \
	(mm_tlb_flush_pending(mm) ? pte_present(pte) : \
					_PAGE_TEST_PRESENT(pte_val(pte)))

#ifdef CONFIG_NUMA_BALANCING
/*
 * These return true for PAGE_NONE too but the kernel does not care.
 * See the comment in include/asm-generic/pgtable.h
 */
static inline int pte_protnone(pte_t pte)
{
	return _PAGE_GET(pte_val(pte), UNI_PAGE_PRESENT | UNI_PAGE_PROTNONE) ==
						_PAGE_INIT_PROTNONE;
}
static inline int pmd_protnone(pmd_t pmd)
{
	return _PAGE_GET(pmd_val(pmd), UNI_PAGE_PRESENT | UNI_PAGE_PROTNONE) ==
						_PAGE_INIT_PROTNONE;
}
# define pte_present_and_exec(pte) (pte_present(pte) && pte_exec(pte))
#else	/* ! CONFIG_NUMA_BALANCING */
# define pte_present_and_exec(pte) \
		(_PAGE_GET(pte_val(pte), \
			UNI_PAGE_PRESENT | UNI_PAGE_NON_EX) == \
						_PAGE_INIT_PRESENT)
#endif /* CONFIG_NUMA_BALANCING */

/* Since x86 uses Write Combine both for external devices
 * (meaning optimization if CPU accesses) and for RAM
 * (meaning avoid cache allocation) we do the same here
 * as that is what drivers expect. */
#define is_mt_wb(mt) \
({ \
	u64 __im_mt = (mt); \
	(__im_mt == GEN_CACHE_MT || __im_mt == EXT_CACHE_MT); \
})
#define is_mt_wc(mt) \
({ \
	u64 __im_mt = (mt); \
	(__im_mt == GEN_NON_CACHE_MT || __im_mt == EXT_PREFETCH_MT); \
})
#define is_mt_uc(mt) \
({ \
	u64 __im_mt = (mt); \
	(__im_mt == GEN_NON_CACHE_ORDERED_MT || \
	 __im_mt == EXT_NON_PREFETCH_MT || __im_mt == EXT_CONFIG_MT); \
})
#define is_mt_general(mt) \
({ \
	u64 __im_mt = (mt); \
	(__im_mt == GEN_NON_CACHE_MT || __im_mt == GEN_CACHE_MT); \
})
#define is_mt_external(mt) (!is_mt_general(mt))

static inline pgprot_t set_general_mt(pgprot_t prot)
{
	pte_mem_type_t mt = get_pte_val_memory_type(pgprot_val(prot));

	switch (mt) {
	case EXT_CACHE_MT:
		prot = __pgprot(set_pte_val_memory_type(pgprot_val(prot),
					GEN_CACHE_MT));
		break;
	case EXT_NON_PREFETCH_MT:
		/* pgprot_device() case */
	case EXT_PREFETCH_MT:
	case EXT_CONFIG_MT:
		mt = GEN_NON_CACHE_MT;
		prot = __pgprot(set_pte_val_memory_type(pgprot_val(prot),
					GEN_NON_CACHE_MT));
		break;
	case GEN_NON_CACHE_ORDERED_MT:
		/* pgprot_noncached() case */
	case GEN_NON_CACHE_MT:
		/* pgprot_writecombine() and pgprot_writethrough() case */
	case GEN_CACHE_MT:
		break;
	default:
		WARN_ON_ONCE(1);
		prot = __pgprot(set_pte_val_memory_type(pgprot_val(prot),
					GEN_NON_CACHE_MT));
		break;
	}

	return prot;
}

static inline pgprot_t set_external_mt(pgprot_t prot)
{
	pte_mem_type_t mt = get_pte_val_memory_type(pgprot_val(prot));

	switch (mt) {
	case GEN_CACHE_MT:
		prot = __pgprot(set_pte_val_memory_type(pgprot_val(prot),
					EXT_CACHE_MT));
		break;
	case GEN_NON_CACHE_MT:
		/* pgprot_writecombine() and pgprot_writethrough() case */
		prot = __pgprot(set_pte_val_memory_type(pgprot_val(prot),
					EXT_PREFETCH_MT));
		break;
	case GEN_NON_CACHE_ORDERED_MT:
		/* pgprot_noncached() case */
		prot = __pgprot(set_pte_val_memory_type(pgprot_val(prot),
					EXT_NON_PREFETCH_MT));
		break;
	case EXT_NON_PREFETCH_MT:
		/* pgprot_device() case */
	case EXT_PREFETCH_MT:
	case EXT_CONFIG_MT:
	case EXT_CACHE_MT:
		break;
	default:
		WARN_ON_ONCE(1);
		prot = __pgprot(set_pte_val_memory_type(pgprot_val(prot),
					EXT_CONFIG_MT));
		break;
	}

	return prot;
}

/*
 * See comment in pmd_present() - since _PAGE_HUGE bit stays on at all times
 * (both during split_huge_page and when the _PAGE_PROTNONE bit gets set)
 * we can check only the _PAGE_HUGE bit.
 */
#define pmd_present_and_exec_and_huge(pmd) \
		(_PAGE_GET(pmd_val(pmd), UNI_PAGE_NON_EX |	\
						UNI_PAGE_HUGE) == \
			_PAGE_INIT_HUGE)

#define pud_present_and_exec_and_huge(pud) \
		(_PAGE_GET(pud_val(pud), UNI_PAGE_PRESENT | \
					UNI_PAGE_NON_EX | UNI_PAGE_HUGE) == \
			_PAGE_INIT(UNI_PAGE_PRESENT | UNI_PAGE_HUGE))

/*
 * See comment in pmd_present() - since _PAGE_HUGE bit stays on at all times
 * (both during split_huge_page and when the _PAGE_PROTNONE bit gets set) we
 * should not return "pmd_none() == true" when the _PAGE_HUGE bit is set.
 */
#ifndef	CONFIG_MAKE_ALL_PAGES_VALID
# define pmd_none(pmd)	(pmd_val(pmd) == 0)
#else
# define pmd_none(pmd)	(_PAGE_CLEAR_VALID(pmd_val(pmd)) == 0)
#endif

#define pmd_valid(pmd)	_PAGE_TEST_VALID(pmd_val(pmd))

/* This will return true for huge pages as expected by arch-independent part */
static inline int pmd_bad(pmd_t pmd)
{
	return unlikely(_PAGE_CLEAR(pmd_val(pmd) & PTE_FLAGS_MASK,
				UNI_PAGE_GLOBAL) != _PAGE_USER_PTE);
}

#define	user_pmd_huge(pmd)	_PAGE_TEST_HUGE(pmd_val(pmd))
#define	kernel_pmd_huge(pmd)	\
		(is_huge_pmd_level() && _PAGE_TEST_HUGE(pmd_val(pmd)))

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
#define has_transparent_hugepage has_transparent_hugepage
static inline int has_transparent_hugepage(void)
{
	return cpu_has(CPU_FEAT_ISET_V3);
}

#define pmd_trans_huge(pmd)		user_pmd_huge(pmd)
#endif /* CONFIG_TRANSPARENT_HUGEPAGE */

/*
 * Checking for _PAGE_HUGE is needed too because
 * split_huge_page will temporarily clear the present bit (but
 * the _PAGE_HUGE flag will remain set at all times while the
 * _PAGE_PRESENT bit is clear).
 */
#define pmd_present(pmd)	\
		_PAGE_TEST(pmd_val(pmd), UNI_PAGE_PRESENT | \
			   UNI_PAGE_PROTNONE | UNI_PAGE_HUGE)
#define pmd_write(pmd)		_PAGE_TEST_WRITEABLE(pmd_val(pmd))
#define pmd_exec(pmd)		_PAGE_TEST_EXECUTEABLE(pmd_val(pmd))
#define pmd_dirty(pmd)		_PAGE_TEST_DIRTY(pmd_val(pmd))
#define pmd_young(pmd)		_PAGE_TEST_ACCESSED(pmd_val(pmd))
#define pmd_wb(pmd)		is_mt_wb(_PAGE_GET_MEM_TYPE(pmd_val(pmd)))
#define pmd_wc(pmd)		is_mt_wc(_PAGE_GET_MEM_TYPE(pmd_val(pmd)))
#define pmd_uc(pmd)		is_mt_uc(_PAGE_GET_MEM_TYPE(pmd_val(pmd)))

#define pmd_wrprotect(pmd)	(__pmd(_PAGE_CLEAR_WRITEABLE(pmd_val(pmd))))
#define pmd_mkwrite(pmd)	(__pmd(_PAGE_SET_WRITEABLE(pmd_val(pmd))))
#define pmd_mkexec(pmd)		(__pmd(_PAGE_SET_EXECUTEABLE(pmd_val(pmd))))
#define pmd_mknotexec(pmd)	(__pmd(_PAGE_CLEAR_EXECUTEABLE(pmd_val(pmd))))
#define pmd_mkpresent(pmd)	(__pmd(_PAGE_SET_PRESENT(pmd_val(pmd))))
#define pmd_mk_present_valid(pmd) (__pmd(_PAGE_SET(pmd_val(pmd), \
				   UNI_PAGE_PRESENT | UNI_PAGE_VALID)))
#define pmd_mknotpresent(pmd)	\
		(__pmd(_PAGE_CLEAR(pmd_val(pmd), \
				UNI_PAGE_PRESENT | UNI_PAGE_PROTNONE)))
#define pmd_mknot_present_valid(pmd) (__pmd(_PAGE_CLEAR(pmd_val(pmd), \
		 UNI_PAGE_PRESENT | UNI_PAGE_PROTNONE | UNI_PAGE_VALID)))
#define pmd_mkold(pmd)		(__pmd(_PAGE_CLEAR_ACCESSED(pmd_val(pmd))))
#define pmd_mkyoung(pmd)	(__pmd(_PAGE_SET_ACCESSED(pmd_val(pmd))))
#define pmd_mkclean(pmd)	(__pmd(_PAGE_CLEAR_DIRTY(pmd_val(pmd))))
#define pmd_mkdirty(pmd)	(__pmd(_PAGE_SET_DIRTY(pmd_val(pmd))))
#define pmd_mkhuge(pmd)		(__pmd(_PAGE_SET_HUGE(pmd_val(pmd))))
#define pmd_clear_guest(pmd)	\
		(__pmd(_PAGE_CLEAR(pmd_val(pmd), \
				UNI_PAGE_PRIV | UNI_PAGE_GLOBAL)))
static inline pmd_t pmd_mk_wb(pmd_t pmd)
{
	if (is_mt_external(_PAGE_GET_MEM_TYPE(pmd_val(pmd))))
		return __pmd(_PAGE_SET_MEM_TYPE(pmd_val(pmd), EXT_CACHE_MT));
	else
		return __pmd(_PAGE_SET_MEM_TYPE(pmd_val(pmd), GEN_CACHE_MT));
}
static inline pmd_t pmd_mk_wc(pmd_t pmd)
{
	if (is_mt_external(_PAGE_GET_MEM_TYPE(pmd_val(pmd))))
		return __pmd(_PAGE_SET_MEM_TYPE(pmd_val(pmd), EXT_PREFETCH_MT));
	else
		return __pmd(_PAGE_SET_MEM_TYPE(pmd_val(pmd), GEN_NON_CACHE_MT));
}
static inline pmd_t pmd_mk_uc(pmd_t pmd)
{
	if (is_mt_external(_PAGE_GET_MEM_TYPE(pmd_val(pmd))))
		return __pmd(_PAGE_SET_MEM_TYPE(pmd_val(pmd), EXT_NON_PREFETCH_MT));
	else
		return __pmd(_PAGE_SET_MEM_TYPE(pmd_val(pmd), GEN_NON_CACHE_ORDERED_MT));
}

#ifndef	CONFIG_MAKE_ALL_PAGES_VALID
# define pud_none(pud)	(pud_val(pud) == 0)
#else
# define pud_none(pud)	(_PAGE_CLEAR_VALID(pud_val(pud)) == 0)
#endif

#define pud_valid(pud)	_PAGE_TEST_VALID(pud_val(pud))

/* This will return true for huge pages as expected by arch-independent part */
static inline int pud_bad(pud_t pud)
{
	return unlikely(_PAGE_CLEAR(pud_val(pud) & PTE_FLAGS_MASK,
				UNI_PAGE_GLOBAL) != _PAGE_USER_PMD);
}

#define pud_present(pud)	_PAGE_TEST_PRESENT(pud_val(pud))
#define pud_write(pud)		_PAGE_TEST_WRITEABLE(pud_val(pud))
#define pud_exec(pud)		_PAGE_TEST_EXECUTEABLE(pud_val(pud))
#define	user_pud_huge(pud)	_PAGE_TEST_HUGE(pud_val(pud))
#define	kernel_pud_huge(pud)		\
		(is_huge_pud_level() && _PAGE_TEST_HUGE(pud_val(pud)))
#define pud_wb(pud)		is_mt_wb(_PAGE_GET_MEM_TYPE(pud_val(pud)))
#define pud_wc(pud)		is_mt_wc(_PAGE_GET_MEM_TYPE(pud_val(pud)))
#define pud_uc(pud)		is_mt_uc(_PAGE_GET_MEM_TYPE(pud_val(pud)))

#define pud_clear_guest(pud)		\
		(__pud(_PAGE_CLEAR(pud_val(pud), \
				UNI_PAGE_PRIV | UNI_PAGE_GLOBAL)))
#define pud_wrprotect(pud)	(__pud(_PAGE_CLEAR_WRITEABLE(pud_val(pud))))
#define pud_mkwrite(pud)	(__pud(_PAGE_SET_WRITEABLE(pud_val(pud))))
#define pud_mkexec(pud)		(__pud(_PAGE_SET_EXECUTEABLE(pud_val(pud))))
#define pud_mknotexec(pud)	(__pud(_PAGE_CLEAR_EXECUTEABLE(pud_val(pud))))
#define pud_mkpresent(pud)	(__pud(_PAGE_SET_PRESENT(pud_val(pud))))
#define pud_mk_present_valid(pud) (__pud(_PAGE_SET(pud_val(pud), \
				   UNI_PAGE_PRESENT | UNI_PAGE_VALID)))
#define pud_mknotpresent(pud)	(__pud(_PAGE_CLEAR_PRESENT(pud_val(pud))))
#define pud_mknot_present_valid(pud) (__pud(_PAGE_CLEAR(pud_val(pud), \
					    UNI_PAGE_PRESENT | UNI_PAGE_VALID)))
static inline pud_t pud_mk_wb(pud_t pud)
{
	if (is_mt_external(_PAGE_GET_MEM_TYPE(pud_val(pud))))
		return __pud(_PAGE_SET_MEM_TYPE(pud_val(pud), EXT_CACHE_MT));
	else
		return __pud(_PAGE_SET_MEM_TYPE(pud_val(pud), GEN_CACHE_MT));
}
static inline pud_t pud_mk_wc(pud_t pud)
{
	if (is_mt_external(_PAGE_GET_MEM_TYPE(pud_val(pud))))
		return __pud(_PAGE_SET_MEM_TYPE(pud_val(pud), EXT_PREFETCH_MT));
	else
		return __pud(_PAGE_SET_MEM_TYPE(pud_val(pud), GEN_NON_CACHE_MT));
}
static inline pud_t pud_mk_uc(pud_t pud)
{
	if (is_mt_external(_PAGE_GET_MEM_TYPE(pud_val(pud))))
		return __pud(_PAGE_SET_MEM_TYPE(pud_val(pud), EXT_NON_PREFETCH_MT));
	else
		return __pud(_PAGE_SET_MEM_TYPE(pud_val(pud), GEN_NON_CACHE_ORDERED_MT));
}

#ifndef	CONFIG_MAKE_ALL_PAGES_VALID
#define pgd_none(pgd)		(!pgd_val(pgd))
#else
#define pgd_none(pgd)		(_PAGE_CLEAR_VALID(pgd_val(pgd)) == 0)
#endif
#define pgd_none_full(pgd)	(!pgd_val(pgd))
#define pgd_valid(pgd)		_PAGE_TEST_VALID(pgd_val(pgd))

static inline int pgd_bad(pgd_t pgd)
{
	return unlikely(_PAGE_CLEAR(pgd_val(pgd) & PTE_FLAGS_MASK,
				    UNI_PAGE_GLOBAL) != _PAGE_USER_PUD);
}
#define pgd_present(pgd)	_PAGE_TEST_PRESENT(pgd_val(pgd))
#define	user_pgd_huge(pgd)	_PAGE_TEST_HUGE(pgd_val(pgd))
#define	kernel_pgd_huge(pgd)		\
		(is_huge_pgd_level() && _PAGE_TEST_HUGE(pgd_val(pgd)))
#define pgd_clear_guest(pgd)		\
		(__pgd(_PAGE_CLEAR(pgd_val(pgd), \
				UNI_PAGE_PRIV | UNI_PAGE_GLOBAL)))

/*
 * The following have defined behavior only work if pte_present() is true.
 */
#define pte_read(pte)		(true)
#define pte_write(pte)		_PAGE_TEST_WRITEABLE(pte_val(pte))
#define pte_exec(pte)		_PAGE_TEST_EXECUTEABLE(pte_val(pte))
#define pte_dirty(pte)		_PAGE_TEST_DIRTY(pte_val(pte))
#define pte_young(pte)		_PAGE_TEST_ACCESSED(pte_val(pte))
#define pte_huge(pte)		_PAGE_TEST_HUGE(pte_val(pte))
#define pte_special(pte)	_PAGE_TEST_SPECIAL(pte_val(pte))
#define pte_wb(pte)		is_mt_wb(_PAGE_GET_MEM_TYPE(pte_val(pte)))
#define pte_wc(pte)		is_mt_wc(_PAGE_GET_MEM_TYPE(pte_val(pte)))
#define pte_uc(pte)		is_mt_uc(_PAGE_GET_MEM_TYPE(pte_val(pte)))

#define pte_wrprotect(pte)	(__pte(_PAGE_CLEAR_WRITEABLE(pte_val(pte))))
#define pte_mkwrite(pte)	(__pte(_PAGE_SET_WRITEABLE(pte_val(pte))))
#define pte_mkexec(pte)		(__pte(_PAGE_SET_EXECUTEABLE(pte_val(pte))))
#define pte_mknotexec(pte)	(__pte(_PAGE_CLEAR_EXECUTEABLE(pte_val(pte))))
#define pte_mkpresent(pte)	(__pte(_PAGE_SET_PRESENT(pte_val(pte))))
#define pte_mk_present_valid(pte) (__pte(_PAGE_SET(pte_val(pte), \
				   UNI_PAGE_PRESENT | UNI_PAGE_VALID)))
#define pte_mknotpresent(pte)	\
		(__pte(_PAGE_CLEAR(pte_val(pte), \
				UNI_PAGE_PRESENT | UNI_PAGE_PROTNONE)))
#define pte_mknot_present_valid(pte) (__pte(_PAGE_CLEAR(pte_val(pte), \
		 UNI_PAGE_PRESENT | UNI_PAGE_PROTNONE | UNI_PAGE_VALID)))
#define pte_mkold(pte)		(__pte(_PAGE_CLEAR_ACCESSED(pte_val(pte))))
#define pte_mkyoung(pte)	(__pte(_PAGE_SET_ACCESSED(pte_val(pte))))
#define pte_mkclean(pte)	(__pte(_PAGE_CLEAR_DIRTY(pte_val(pte))))
#define pte_mkdirty(pte)	(__pte(_PAGE_SET_DIRTY(pte_val(pte))))
#define pte_mkvalid(pte)	(__pte(_PAGE_SET_VALID(pte_val(pte))))
#define pte_mkhuge(pte)		\
		(__pte(_PAGE_SET(pte_val(pte), \
				UNI_PAGE_PRESENT | UNI_PAGE_HUGE)))
#define	pte_mkspecial(pte)	(__pte(_PAGE_SET_SPECIAL(pte_val(pte))))
#define pte_mknotvalid(pte)	(__pte(_PAGE_CLEAR_VALID(pte_val(pte))))
static inline pte_t pte_mk_wb(pte_t pte)
{
	if (is_mt_external(_PAGE_GET_MEM_TYPE(pte_val(pte))))
		return __pte(_PAGE_SET_MEM_TYPE(pte_val(pte), EXT_CACHE_MT));
	else
		return __pte(_PAGE_SET_MEM_TYPE(pte_val(pte), GEN_CACHE_MT));
}
static inline pte_t pte_mk_wc(pte_t pte)
{
	if (is_mt_external(_PAGE_GET_MEM_TYPE(pte_val(pte))))
		return __pte(_PAGE_SET_MEM_TYPE(pte_val(pte), EXT_PREFETCH_MT));
	else
		return __pte(_PAGE_SET_MEM_TYPE(pte_val(pte), GEN_NON_CACHE_MT));
}
static inline pte_t pte_mk_uc(pte_t pte)
{
	if (is_mt_external(_PAGE_GET_MEM_TYPE(pte_val(pte))))
		return __pte(_PAGE_SET_MEM_TYPE(pte_val(pte), EXT_NON_PREFETCH_MT));
	else
		return __pte(_PAGE_SET_MEM_TYPE(pte_val(pte), GEN_NON_CACHE_ORDERED_MT));
}

/*
 * The index and offset in the root-level page table directory.
 */
#define	pgd_index(virt_addr)		(((virt_addr) >> PGDIR_SHIFT) & \
					(PTRS_PER_PGD - 1))
#define pgd_offset(mm, virt_addr)	((mm)->pgd + pgd_index(virt_addr))
#define	pgd_to_index(pgdp)		((((unsigned long)(pgdp)) /	\
						(sizeof(pgd_t))) &	\
							(PTRS_PER_PGD - 1))
#define	pgd_to_page(pgdp)		((pgdp) - pgd_to_index(pgdp))
#define	boot_pgd_index(virt_addr)	pgd_index(virt_addr)

#define	VIRT_ADDR_VPTB_BASE(va)		\
		((MMU_IS_SEPARATE_PT()) ?	\
			(((va) >= MMU_SEPARATE_KERNEL_VAB) ?	\
				KERNEL_VPTB_BASE_ADDR : USER_VPTB_BASE_ADDR) \
			:	\
			MMU_UNITED_KERNEL_VPTB)
/*
 * The index and offset in the upper page table directory.
 */
#define	pud_index(virt_addr)		((virt_addr >> PUD_SHIFT) & \
					(PTRS_PER_PUD - 1))
#define	pud_virt_offset(virt_addr)	(VIRT_ADDR_VPTB_BASE(virt_addr) | \
					((pmd_virt_offset(virt_addr) & \
					PTE_MASK) >> \
					(E2K_VA_SIZE - PGDIR_SHIFT)))
#define	boot_pud_index(virt_addr)	pud_index(virt_addr)
#define boot_pud_offset(pgdp, addr)	((pud_t *)boot_pgd_page(*(pgdp)) + \
					boot_pud_index(addr))

/*
 * The index and offset in the middle page table directory
 */
#define	pmd_index(virt_addr)		((virt_addr >> PMD_SHIFT) & \
					(PTRS_PER_PMD - 1))
#define	pmd_virt_offset(virt_addr)	(VIRT_ADDR_VPTB_BASE(virt_addr) | \
					((pte_virt_offset(virt_addr) & \
					PTE_MASK) >> \
					(E2K_VA_SIZE - PGDIR_SHIFT)))
#define	boot_pmd_index(virt_addr)	pmd_index(virt_addr)
#define boot_pmd_offset(pudp, addr)	((pmd_t *)boot_pud_page(*(pudp)) + \
					boot_pmd_index(addr))

/*
 * The index and offset in the third-level page table.
 */
#define	pte_index(virt_addr)		((virt_addr >> PAGE_SHIFT) & \
					(PTRS_PER_PTE - 1))
#define	pte_virt_offset(virt_addr)	(VIRT_ADDR_VPTB_BASE(virt_addr) | \
					(((virt_addr) & PTE_MASK) >> \
					(E2K_VA_SIZE - PGDIR_SHIFT)))

#define	boot_pte_index(virt_addr)	pte_index(virt_addr)
#define boot_pte_offset(pmdp, addr)	((pte_t *)boot_pmd_page(*(pmdp)) + \
						boot_pte_index(addr))

#endif	/* !(__ASSEMBLY__) */

#endif /* !(_ASM_E2K_PGTABLE_DEF_H) */
