/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * E2K page table common definitions.
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

#include <asm-generic/pgtable-nop4d.h>

#include <asm/mmu_types.h>
#include <asm/pgtable_types.h>
#include <asm/machdep.h>
#include <asm/page.h>
#include <asm/pgtable-v3.h>
#include <asm/pgtable-v6.h>

/*
 * Set to 1 to trace user page tables updates.
 * Set to 2 to also trace kernel page tables updates.
 */
#define TRACE_PT_UPDATES 0
#if TRACE_PT_UPDATES
# define trace_pt_update(...) \
do { \
	if (system_state == SYSTEM_RUNNING) \
		trace_printk(__VA_ARGS__); \
} while (0)
#else
# define trace_pt_update(...) do { } while (0)
#endif

#define MAX_POSSIBLE_PHYSMEM_BITS CONFIG_E2K_PA_BITS


/* See comment before PAGE_UNCACHED/PAGE_COHERENT in pgtable.c */
enum page_cache_mode {
	PCM_WB,
	PCM_WC,
	PCM_UC,
	PCM_UNKNOWN
};

/*
 * Returns PTE memory type for RAM pages taking
 * into account PCIe No Snoop supoport.
 */
static inline pte_mem_type_t memtype2pte_mem_type(enum page_cache_mode memtype)
{
	/*
	 * Make sure to use coherent mapping if PCIe No Snoop is not supported
	 * as in that case device memory accesses are always coherent.
	 */
	switch (memtype) {
	case PCM_WB:
	case PCM_UNKNOWN:
		return GEN_CACHE_MT;
	case PCM_WC:
		return GEN_NON_CACHE_MT;
	case PCM_UC:
		return GEN_NON_CACHE_ORDERED_MT;
	default:
		WARN_ONCE(1, "Got an impossible value for enum, some type error in kernel?");
		return GEN_NON_CACHE_MT;
	}
}

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
is_huge_p4d_level(void)
{
	return is_huge_pt_struct_level(&pgtable_struct, E2K_PGD_LEVEL_NUM);
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

/*
 * PTE format
 */

static inline pteval_t
mmu_phys_addr_to_pte_pfn(e2k_addr_t phys_addr, bool mmu_pt_v6)
{
	if (mmu_pt_v6)
		return _PAGE_PADDR_TO_PFN_V6(phys_addr);
	else
		return _PAGE_PADDR_TO_PFN_V3(phys_addr);
}
static inline e2k_addr_t
mmu_pte_pfn_to_phys_addr(pteval_t pte_val, bool mmu_pt_v6)
{
	if (mmu_pt_v6)
		return _PAGE_PFN_TO_PADDR_V6(pte_val);
	else
		return _PAGE_PFN_TO_PADDR_V3(pte_val);
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

/* PTE Memory Type */
static inline enum pte_mem_type get_pte_val_memory_type(pteval_t pte_val)
{
	if (MMU_IS_PT_V6())
		return get_pte_val_v6_memory_type(pte_val);
	else
		return get_pte_val_v3_memory_type(pte_val);
}
static inline pteval_t set_pte_val_memory_type(pteval_t pte_val,
		pte_mem_type_t memory_type)
{
	if (MMU_IS_PT_V6())
		return set_pte_val_v6_memory_type(pte_val, memory_type);
	else
		return set_pte_val_v3_memory_type(pte_val, memory_type);
}
#define	_PAGE_GET_MEM_TYPE(pte_val)	\
		get_pte_val_memory_type(pte_val)
#define	_PAGE_SET_MEM_TYPE(pte_val, memory_type)	\
		set_pte_val_memory_type(pte_val, memory_type)

static inline pteval_t
mmu_fill_pte_val_flags(uni_pteval_t uni_flags, bool mmu_pt_v6)
{
	if (mmu_pt_v6)
		return fill_pte_val_v6_flags(uni_flags);
	else
		return fill_pte_val_v3_flags(uni_flags);
}
static inline pteval_t
mmu_get_pte_val_flags(pteval_t pte_val, uni_pteval_t uni_flags,
			bool mmu_pt_v6)
{
	if (mmu_pt_v6)
		return get_pte_val_v6_flags(pte_val, uni_flags);
	else
		return get_pte_val_v3_flags(pte_val, uni_flags);
}
static inline bool
mmu_test_pte_val_flags(pteval_t pte_val, uni_pteval_t uni_flags,
			bool mmu_pt_v6)
{
	return mmu_get_pte_val_flags(pte_val, uni_flags, mmu_pt_v6) != 0;
}
static inline pteval_t
mmu_set_pte_val_flags(pteval_t pte_val, uni_pteval_t uni_flags,
			bool mmu_pt_v6)
{
	if (mmu_pt_v6)
		return set_pte_val_v6_flags(pte_val, uni_flags);
	else
		return set_pte_val_v3_flags(pte_val, uni_flags);
}
static inline pteval_t
mmu_clear_pte_val_flags(pteval_t pte_val, uni_pteval_t uni_flags,
			bool mmu_pt_v6)
{
	if (mmu_pt_v6)
		return clear_pte_val_v6_flags(pte_val, uni_flags);
	else
		return clear_pte_val_v3_flags(pte_val, uni_flags);
}
static __must_check inline pteval_t
fill_pte_val_flags(uni_pteval_t uni_flags)
{
	return mmu_fill_pte_val_flags(uni_flags, MMU_IS_PT_V6());
}
static __must_check inline pteval_t
get_pte_val_flags(pteval_t pte_val, uni_pteval_t uni_flags)
{
	return mmu_get_pte_val_flags(pte_val, uni_flags, MMU_IS_PT_V6());
}
static __must_check inline bool
test_pte_val_flags(pteval_t pte_val, uni_pteval_t uni_flags)
{
	return mmu_test_pte_val_flags(pte_val, uni_flags, MMU_IS_PT_V6());
}
static __must_check inline pteval_t
set_pte_val_flags(pteval_t pte_val, uni_pteval_t uni_flags)
{
	return mmu_set_pte_val_flags(pte_val, uni_flags, MMU_IS_PT_V6());
}
static __must_check inline pteval_t
clear_pte_val_flags(pteval_t pte_val, uni_pteval_t uni_flags)
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
		return get_pte_val_v3_changeable_mask();
}
static inline pteval_t
mmu_get_huge_pte_val_changeable_mask(bool mmu_pt_v6)
{
	if (mmu_pt_v6)
		return get_huge_pte_val_v6_changeable_mask();
	else
		return get_huge_pte_val_v3_changeable_mask();
}
static inline pteval_t
mmu_get_pte_val_reduceable_mask(bool mmu_pt_v6)
{
	if (mmu_pt_v6)
		return get_pte_val_v6_reduceable_mask();
	else
		return get_pte_val_v3_reduceable_mask();
}
static inline pteval_t
mmu_get_pte_val_restricted_mask(bool mmu_pt_v6)
{
	if (mmu_pt_v6)
		return get_pte_val_v6_restricted_mask();
	else
		return get_pte_val_v3_restricted_mask();
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

#define	_PAGE_INIT_PROTECT		_PAGE_INIT(UNI_PAGE_PROTECT)
#define	_PAGE_GET_PROTECT(pte_val)	_PAGE_GET(pte_val, UNI_PAGE_PROTECT)
#define	_PAGE_TEST_PROTECT(pte_val)	_PAGE_TEST(pte_val, UNI_PAGE_PROTECT)
#define	_PAGE_SET_PROTECT(pte_val)	_PAGE_SET(pte_val, UNI_PAGE_PROTECT)
#define	_PAGE_CLEAR_PROTECT(pte_val)	_PAGE_CLEAR(pte_val, UNI_PAGE_PROTECT)

#define	_PAGE_INIT_NWA			_PAGE_INIT(UNI_PAGE_NWA)
#define	_PAGE_GET_NWA(pte_val)		_PAGE_GET(pte_val, UNI_PAGE_NWA)
#define	_PAGE_TEST_NWA(pte_val)		_PAGE_TEST(pte_val, UNI_PAGE_NWA)
#define	_PAGE_SET_NWA(pte_val)		_PAGE_SET(pte_val, UNI_PAGE_NWA)
#define	_PAGE_CLEAR_NWA(pte_val)	_PAGE_CLEAR(pte_val, UNI_PAGE_NWA)

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

#define	_PAGE_INIT_DEVMAP		_PAGE_INIT(UNI_PAGE_DEVMAP)
#define	_PAGE_GET_DEVMAP(pte_val)	_PAGE_GET(pte_val, UNI_PAGE_DEVMAP)
#define	_PAGE_TEST_DEVMAP(pte_val)	_PAGE_TEST(pte_val, UNI_PAGE_DEVMAP)
#define	_PAGE_SET_DEVMAP(pte_val)	_PAGE_SET(pte_val, UNI_PAGE_DEVMAP)
#define	_PAGE_CLEAR_DEVMAP(pte_val)	_PAGE_CLEAR(pte_val, UNI_PAGE_DEVMAP)

#define	_PAGE_PFN_MASK			_PAGE_INIT(UNI_PAGE_PFN)

#ifdef CONFIG_MARK_KERNEL_PAGE_TABLES
# define KERNEL_PT_MARK _PAGE_INIT(UNI_PAGE_KERNEL_MARK)
#else
# define KERNEL_PT_MARK 0ull
#endif

#define _PAGE_KERNEL_RX_NOT_GLOB	\
		(_PAGE_INIT(UNI_PAGE_PRESENT | UNI_PAGE_VALID | \
				 UNI_PAGE_PRIV | UNI_PAGE_ACCESSED) | KERNEL_PT_MARK)
#define _PAGE_KERNEL_RO_NOT_GLOB	\
		(_PAGE_INIT(UNI_PAGE_PRESENT | UNI_PAGE_VALID | \
				UNI_PAGE_PRIV | UNI_PAGE_ACCESSED | \
				UNI_PAGE_NON_EX) | KERNEL_PT_MARK)
#define _PAGE_KERNEL_RWX_NOT_GLOB	\
		_PAGE_SET(_PAGE_KERNEL_RX_NOT_GLOB, \
				UNI_PAGE_WRITE | UNI_PAGE_DIRTY)
#define _PAGE_KERNEL_RW_NOT_GLOB	\
		_PAGE_SET(_PAGE_KERNEL_RWX_NOT_GLOB, UNI_PAGE_NON_EX)
#define _PAGE_KERNEL_RX		\
		_PAGE_SET(_PAGE_KERNEL_RX_NOT_GLOB, UNI_PAGE_GLOBAL)
#define _PAGE_KERNEL_RO		\
		_PAGE_SET(_PAGE_KERNEL_RO_NOT_GLOB, UNI_PAGE_GLOBAL)
#define _PAGE_KERNEL_RWX	\
		_PAGE_SET(_PAGE_KERNEL_RWX_NOT_GLOB, UNI_PAGE_GLOBAL)
#define _PAGE_KERNEL_RW		\
		_PAGE_SET(_PAGE_KERNEL_RW_NOT_GLOB, UNI_PAGE_GLOBAL)

#define _PAGE_KERNEL		_PAGE_KERNEL_RW
/* For S3 (suspend to RAM) to work kernel code must have accessed bit set
 * to avoid unexpected memory accesses from TLU when entering it. */
#define _PAGE_KERNEL_IMAGE	_PAGE_KERNEL_RX

/* Do not set GLOBAL for intermediate kernel page tables. Otherwise the
 * following is possible:
 * 1) Kernel accesses an address from VMLPT area (0xff8*_****_****) that
 * belongs to user space, and DTLB caches intermediate page tables with
 * GLOBAL attribute set.
 * 2) User accesses address that uses that cached intermediate page table,
 * and DTLB reuses the cached entry from kernel page tables. Then user
 * address ends up being translated through kernel page tables. */
#define _PAGE_KERNEL_PT		_PAGE_KERNEL_RW_NOT_GLOB

#define _PAGE_USER_PT		_PAGE_INIT( \
				 UNI_PAGE_PRESENT | UNI_PAGE_VALID | \
				 UNI_PAGE_PRIV | UNI_PAGE_ACCESSED | \
				 UNI_PAGE_WRITE | UNI_PAGE_DIRTY | UNI_PAGE_NON_EX)
#define _PAGE_KERNEL_PTE	_PAGE_KERNEL_PT
#define _PAGE_KERNEL_PMD	_PAGE_KERNEL_PT
#define _PAGE_KERNEL_PUD	_PAGE_KERNEL_PT
#define _PAGE_KERNEL_P4D	_PAGE_KERNEL_PT
#define _PAGE_USER_PTE		_PAGE_USER_PT
#define _PAGE_USER_PMD		_PAGE_USER_PT
#define _PAGE_USER_PUD		_PAGE_USER_PT

#define _PAGE_IO_MAP_BASE	_PAGE_KERNEL_RW
#define _PAGE_IO_MAP		\
		_PAGE_SET_MEM_TYPE(_PAGE_IO_MAP_BASE, EXT_NON_PREFETCH_MT)
#define _PAGE_IO_MAP_WC		\
		_PAGE_SET_MEM_TYPE(_PAGE_IO_MAP_BASE, EXT_PREFETCH_MT)

#define _PAGE_KERNEL_SWITCHING_IMAGE	\
		_PAGE_SET_MEM_TYPE(_PAGE_KERNEL_RX_NOT_GLOB, EXT_CONFIG_MT)

#define _PAGE_USER_RO_ACCESSED	\
		_PAGE_INIT(UNI_PAGE_PRESENT | UNI_PAGE_VALID | \
			UNI_PAGE_ACCESSED | UNI_PAGE_NON_EX)
#define _PAGE_USER_EXEC	\
		_PAGE_INIT(UNI_PAGE_PRESENT | UNI_PAGE_VALID | UNI_PAGE_ACCESSED)

#define PAGE_KERNEL		__pgprot(_PAGE_KERNEL)
#define PAGE_KERNEL_RO		__pgprot(_PAGE_KERNEL_RO)
#define PAGE_KERNEL_EXEC	__pgprot(_PAGE_KERNEL_RWX)
#define	PAGE_KERNEL_PTE		__pgprot(_PAGE_KERNEL_PTE)
#define	PAGE_KERNEL_PMD		__pgprot(_PAGE_KERNEL_PMD)
#define	PAGE_KERNEL_PUD		__pgprot(_PAGE_KERNEL_PUD)
#define	PAGE_USER_PTE		__pgprot(_PAGE_USER_PTE)
#define	PAGE_USER_PMD		__pgprot(_PAGE_USER_PMD)
#define	PAGE_USER_PUD		__pgprot(_PAGE_USER_PUD)

#define PAGE_USER_RO_ACCESSED	__pgprot(_PAGE_USER_RO_ACCESSED)
#define PAGE_USER_EXEC		__pgprot(_PAGE_USER_EXEC)

#define PAGE_KERNEL_TEXT	__pgprot(_PAGE_KERNEL_IMAGE)

#define PAGE_KERNEL_DATA	\
		__pgprot(_PAGE_SET(_PAGE_KERNEL_IMAGE, \
				UNI_PAGE_WRITE | UNI_PAGE_DIRTY | \
					UNI_PAGE_NON_EX))

#define PAGE_BOOTINFO		\
		__pgprot(_PAGE_SET(_PAGE_KERNEL_IMAGE, UNI_PAGE_NON_EX))

#define PAGE_INITRD		\
		__pgprot(_PAGE_SET(_PAGE_KERNEL_IMAGE, UNI_PAGE_NON_EX))

#define PAGE_MPT		\
		__pgprot(_PAGE_SET(_PAGE_KERNEL_IMAGE, UNI_PAGE_NON_EX))

#define PAGE_KERNEL_NAMETAB	\
		__pgprot(_PAGE_SET(_PAGE_KERNEL_IMAGE, UNI_PAGE_NON_EX))

#define PAGE_MAPPED_PHYS_MEM	__pgprot(_PAGE_KERNEL)

#define PAGE_IO_MAP		__pgprot(_PAGE_IO_MAP)
#define PAGE_IO_MAP_WC		__pgprot(_PAGE_IO_MAP_WC)

#define	PAGE_KERNEL_SWITCHING_TEXT	__pgprot(_PAGE_KERNEL_SWITCHING_IMAGE)
#define	PAGE_KERNEL_SWITCHING_DATA	\
		__pgprot(_PAGE_SET(_PAGE_KERNEL_SWITCHING_IMAGE, \
					UNI_PAGE_WRITE | UNI_PAGE_NON_EX))
#define	PAGE_KERNEL_SWITCHING_US_STACK	\
		__pgprot(_PAGE_SET_MEM_TYPE(_PAGE_KERNEL_RW_NOT_GLOB, \
						 EXT_CONFIG_MT))

#define PAGE_SHARED		\
		__pgprot(_PAGE_INIT(UNI_PAGE_PRESENT | UNI_PAGE_VALID | \
				UNI_PAGE_ACCESSED | UNI_PAGE_WRITE | \
				UNI_PAGE_NON_EX))
#define PAGE_SHARED_EX		\
		__pgprot(_PAGE_INIT(UNI_PAGE_PRESENT | UNI_PAGE_VALID | \
				UNI_PAGE_ACCESSED | UNI_PAGE_WRITE))
#define	PAGE_COPY_NEX		\
		__pgprot(_PAGE_INIT(UNI_PAGE_PRESENT | UNI_PAGE_VALID | \
				UNI_PAGE_ACCESSED | UNI_PAGE_NON_EX))
#define	PAGE_COPY_EX		\
		__pgprot(_PAGE_INIT(UNI_PAGE_PRESENT | UNI_PAGE_VALID | \
				UNI_PAGE_ACCESSED))
#define PAGE_READONLY		\
		__pgprot(_PAGE_INIT(UNI_PAGE_PRESENT | UNI_PAGE_VALID |	\
				UNI_PAGE_ACCESSED | UNI_PAGE_NON_EX))
#define PAGE_EXECUTABLE		\
		__pgprot(_PAGE_INIT(UNI_PAGE_PRESENT | UNI_PAGE_VALID | \
				UNI_PAGE_ACCESSED))

/*
 * PAGE_NONE is used for NUMA hinting faults and should be valid.
 */
#define PAGE_NONE		\
		__pgprot(_PAGE_INIT(UNI_PAGE_PROTNONE | UNI_PAGE_ACCESSED | \
					UNI_PAGE_VALID))
#define PAGE_NONE_INVALID	\
		__pgprot(_PAGE_INIT(UNI_PAGE_PROTNONE | UNI_PAGE_ACCESSED))

#define pgd_ERROR(e)						\
({							\
		pr_warn("%s:%d: bad pgd 0x%016lx.\n",		\
			__FILE__, __LINE__, pgd_val(e));	\
		dump_stack();					\
})
#define pud_ERROR(e)						\
({							\
		pr_warn("%s:%d: bad pud 0x%016lx.\n",		\
			__FILE__, __LINE__, pud_val(e));	\
		dump_stack();					\
})
#define pmd_ERROR(e)						\
({							\
		pr_warn("%s:%d: bad pmd 0x%016lx.\n",		\
			__FILE__, __LINE__, pmd_val(e));	\
		dump_stack();					\
})
#define pte_ERROR(e)						\
({							\
		pr_warn("%s:%d: bad pte 0x%016lx.\n",		\
			__FILE__, __LINE__, pte_val(e));	\
		dump_stack();					\
})

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
#define mk_p4d_phys(phys_addr, pgprot) \
	(__p4d(_PAGE_PADDR_TO_PFN(phys_addr) | pgprot_val(pgprot)))

#define mk_pmd_addr(virt_addr, pgprot) \
	(__pmd(_PAGE_PADDR_TO_PFN(__pa(virt_addr)) | pgprot_val(pgprot)))
#define mk_pud_addr(virt_addr, pgprot) \
	(__pud(_PAGE_PADDR_TO_PFN(__pa(virt_addr)) | pgprot_val(pgprot)))
#define mk_p4d_addr(virt_addr, pgprot) \
	(__p4d(_PAGE_PADDR_TO_PFN(__pa(virt_addr)) | pgprot_val(pgprot)))

/*
 * Conversion functions: convert page frame number (pfn) and
 * a protection value to a page table entry (pte).
 */
#define pfn_pte(pfn, pgprot)	mk_pte_phys((pfn) << PAGE_SHIFT, pgprot)
#define pfn_pmd(pfn, pgprot)	mk_pmd_phys((pfn) << PAGE_SHIFT, pgprot)
#define pfn_pud(pfn, pgprot)	mk_pud_phys((pfn) << PAGE_SHIFT, pgprot)

static inline pgprot_t pgprot_nx(pgprot_t prot)
{
	return __pgprot(_PAGE_CLEAR_EXECUTEABLE(pgprot_val(prot)));
}
#define pgprot_nx pgprot_nx

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

#define pgprot_dmacoherent(prot) \
	__pgprot(_PAGE_SET_MEM_TYPE(pgprot_val(prot), GEN_CACHE_MT))

/* PTE_PFN_MASK extracts the PFN from a (pte|pmd|pud|pgd)val_t */
#define PTE_PFN_MASK		_PAGE_PFN_MASK

/* PTE_FLAGS_MASK extracts the flags from a (pte|pmd|pud|pgd)val_t */
#define PTE_FLAGS_MASK		(~(PTE_PFN_MASK | KERNEL_PT_MARK))

static inline pteval_t pte_flags(pte_t pte)
{
	return pte_val(pte) & PTE_FLAGS_MASK;
}

static inline pteval_t pmd_flags(pmd_t pmd)
{
	return pmd_val(pmd) & PTE_FLAGS_MASK;
}

#define pte_pgprot(x) __pgprot(pte_flags(x))
#define pmd_pgprot(x) __pgprot(pmd_flags(x))

/*
 * Extract pfn from pte.
 */
#define pte_pfn(pte)	(_PAGE_PFN_TO_PADDR(pte_val(pte)) >> PAGE_SHIFT)
#define pmd_pfn(pmd)	(_PAGE_PFN_TO_PADDR(pmd_val(pmd)) >> PAGE_SHIFT)
#define pud_pfn(pud)	(_PAGE_PFN_TO_PADDR(pud_val(pud)) >> PAGE_SHIFT)
#define p4d_pfn(p4d)	(_PAGE_PFN_TO_PADDR(p4d_val(p4d)) >> PAGE_SHIFT)

#define mk_pte(page, pgprot)	pfn_pte(page_to_pfn(page), (pgprot))
#define mk_pmd(page, pgprot)	pfn_pmd(page_to_pfn(page), (pgprot))

#define mk_pfn_pte(pfn, pte)	\
		pfn_pte(pfn, __pgprot(pte_val(pte) & ~_PAGE_PFN_MASK))
#define mk_not_present_pte(pgprot)	\
		__pte(_PAGE_CLEAR_PRESENT(pgprot_val(pgprot)))

#define pgprot_modify_mask(old_prot, newprot_val, prot_mask) \
		(__pgprot(((pgprot_val(old_prot) & ~(prot_mask)) | \
		((newprot_val) & (prot_mask)))))

#define pgprot_large_size_set(prot) \
		__pgprot(_PAGE_SET_HUGE(pgprot_val(prot)))
#define pgprot_small_size_set(prot) \
		__pgprot(_PAGE_CLEAR_HUGE(pgprot_val(prot)))
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
#define pte_reduce_prot(src_pte, reduced_prot) \
		(__pte(_pgprot_reduce(pte_val(src_pte), \
					pgprot_val(reduced_prot))))
#define pte_restrict_prot(src_pte, restricted_prot) \
		(__pte(_pgprot_restrict(pte_val(src_pte), \
					pgprot_val(restricted_prot))))

#define pgprot_present(pgprot)		_PAGE_TEST_PRESENT(pgprot_val(pgprot))
#define pgprot_valid(pgprot)		_PAGE_TEST_VALID(pgprot_val(pgprot))
#define	pgprot_write(pgprot)		_PAGE_TEST_WRITEABLE(pgprot_val(pgprot))
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


#define pmd_pte(pmd)	(pte_t *) pmd
#define pud_pte(pud)	(pte_t *) pud

#ifndef	CONFIG_MAKE_ALL_PAGES_VALID
# define pte_none(pte)	(!pte_val(pte))
#else
# define pte_none(pte)	(_PAGE_CLEAR_VALID(pte_val(pte)) == 0)
#endif

#define pte_valid(pte)			_PAGE_TEST_VALID(pte_val(pte))

#define pte_present(pte)	_PAGE_TEST(pte_val(pte), UNI_PAGE_PRESENT | UNI_PAGE_PROTNONE)
#define pte_present_valid(pte) _PAGE_TEST(pte_val(pte), UNI_PAGE_PRESENT | UNI_PAGE_VALID)
#define pte_present_only(pte)	_PAGE_TEST_PRESENT(pte_val(pte))

#define	pte_large_page(pte)		_PAGE_TEST_HUGE(pte_val(pte))
#define	pte_set_small_size(pte)		__pte(_PAGE_CLEAR_HUGE(pte_val(pte)))
#define	pte_set_large_size(pte)		__pte(_PAGE_SET_HUGE(pte_val(pte)))

#define pte_accessible(mm, pte) \
	(mm_tlb_flush_pending(mm) ? pte_present(pte) : \
				    pte_present_only(pte))

#ifdef CONFIG_ARCH_HAS_PTE_DEVMAP
#define pte_devmap(pte)			_PAGE_TEST_DEVMAP(pte_val(pte))
#endif

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
	(__im_mt == GEN_CACHE_MT); \
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

static inline pgprot_t __must_check set_general_mt(pgprot_t prot)
{
	pte_mem_type_t mt = get_pte_val_memory_type(pgprot_val(prot));

	switch (mt) {
	case EXT_NON_PREFETCH_MT:
		/* pgprot_device() case */
	case EXT_PREFETCH_MT:
	case EXT_CONFIG_MT:
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

static inline pgprot_t __must_check set_external_mt(pgprot_t prot)
{
	pte_mem_type_t mt = get_pte_val_memory_type(pgprot_val(prot));

	switch (mt) {
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

#define pmd_leaf(pmd)		_PAGE_TEST_HUGE(pmd_val(pmd))
#define pud_leaf(pud)		_PAGE_TEST_HUGE(pud_val(pud))


#ifdef CONFIG_TRANSPARENT_HUGEPAGE
# define PMD_THP_INVALIDATE_FLAGS	(UNI_PAGE_PRESENT | UNI_PAGE_PROTNONE)

# define has_transparent_hugepage has_transparent_hugepage
static inline int has_transparent_hugepage(void)
{
	return true;
}

# define pmd_trans_huge(pmd)		user_pmd_huge(pmd)
# ifdef CONFIG_HAVE_ARCH_TRANSPARENT_HUGEPAGE_PUD
#  define pud_trans_huge(pud)		user_pud_huge(pud)
# endif

# ifdef CONFIG_ARCH_HAS_PTE_DEVMAP
#  define pmd_devmap(pmd)		_PAGE_TEST_DEVMAP(pmd_val(pmd))

#  ifdef CONFIG_HAVE_ARCH_TRANSPARENT_HUGEPAGE_PUD
#   define pud_devmap(pmd)		_PAGE_TEST_DEVMAP(pud_val(pmd))
#  else
static inline int pud_devmap(pud_t pud)
{
	return 0;
}
#  endif /* CONFIG_HAVE_ARCH_TRANSPARENT_HUGEPAGE_PUD */

static inline int pgd_devmap(pgd_t pgd)
{
	return 0;
}
# endif /* CONFIG_ARCH_HAS_PTE_DEVMAP */

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
#define pmd_present_valid(pmd) _PAGE_TEST(pmd_val(pmd), UNI_PAGE_PRESENT | UNI_PAGE_VALID)
#define pmd_present_only(pmd)   _PAGE_TEST_PRESENT(pmd_val(pmd))
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
#define pmd_mknotpresent(pmd)	(__pmd(_PAGE_CLEAR_PRESENT(pmd_val(pmd))))
#define pmd_mk_present_valid(pmd) (__pmd(_PAGE_SET(pmd_val(pmd), \
				   UNI_PAGE_PRESENT | UNI_PAGE_VALID)))
#define pmd_mkinvalid(pmd) \
		(__pmd(_PAGE_CLEAR(pmd_val(pmd), PMD_THP_INVALIDATE_FLAGS)))
#define pmd_mknot_present_valid(pmd) (__pmd(_PAGE_CLEAR(pmd_val(pmd), \
		 UNI_PAGE_PRESENT | UNI_PAGE_PROTNONE | UNI_PAGE_VALID)))
#define pmd_mkvalid(pmd)	(__pmd(_PAGE_SET_VALID(pmd_val(pmd))))
#define pmd_mknotvalid(pmd)	(__pmd(_PAGE_CLEAR_VALID(pmd_val(pmd))))
#define pmd_mkold(pmd)		(__pmd(_PAGE_CLEAR_ACCESSED(pmd_val(pmd))))
#define pmd_mkyoung(pmd)	(__pmd(_PAGE_SET_ACCESSED(pmd_val(pmd))))
#define pmd_mkclean(pmd)	(__pmd(_PAGE_CLEAR_DIRTY(pmd_val(pmd))))
#define pmd_mkdirty(pmd)	(__pmd(_PAGE_SET_DIRTY(pmd_val(pmd))))
#define pmd_mkhuge(pmd)		(__pmd(_PAGE_SET_HUGE(pmd_val(pmd))))
#define pmd_mkdevmap(pmd)	__pmd(_PAGE_SET(pmd_val(pmd), UNI_PAGE_DEVMAP))
#define pmd_clear_guest(pmd)	\
		(__pmd(_PAGE_CLEAR(pmd_val(pmd), \
				UNI_PAGE_PRIV | UNI_PAGE_GLOBAL)))
static inline pmd_t pmd_mk_wb(pmd_t pmd)
{
	return __pmd(_PAGE_SET_MEM_TYPE(pmd_val(pmd), GEN_CACHE_MT));
}
static inline pmd_t pmd_mk_wc(pmd_t pmd)
{
	pte_mem_type_t mt;
	if (is_mt_external(_PAGE_GET_MEM_TYPE(pmd_val(pmd)))) {
		mt = EXT_PREFETCH_MT;
	} else {
		mt = memtype2pte_mem_type(PCM_WC);
	}
	return __pmd(_PAGE_SET_MEM_TYPE(pmd_val(pmd), mt));
}
static inline pmd_t pmd_mk_uc(pmd_t pmd)
{
	pte_mem_type_t mt;
	if (is_mt_external(_PAGE_GET_MEM_TYPE(pmd_val(pmd)))) {
		mt = EXT_NON_PREFETCH_MT;
	} else {
		mt = memtype2pte_mem_type(PCM_UC);
	}
	return __pmd(_PAGE_SET_MEM_TYPE(pmd_val(pmd), mt));
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
#define pud_present_valid(pud) _PAGE_TEST(pud_val(pud), UNI_PAGE_PRESENT | UNI_PAGE_VALID)
#define pud_write(pud)		_PAGE_TEST_WRITEABLE(pud_val(pud))
#define pud_exec(pud)		_PAGE_TEST_EXECUTEABLE(pud_val(pud))
#define pud_dirty(pud)		_PAGE_TEST_DIRTY(pud_val(pud))
#define pud_young(pud)		_PAGE_TEST_ACCESSED(pud_val(pud))
#define	user_pud_huge(pud)	_PAGE_TEST_HUGE(pud_val(pud))
#define	kernel_pud_huge(pud)		\
		(is_huge_pud_level() && _PAGE_TEST_HUGE(pud_val(pud)))
#define pud_wb(pud)		is_mt_wb(_PAGE_GET_MEM_TYPE(pud_val(pud)))
#define pud_wc(pud)		is_mt_wc(_PAGE_GET_MEM_TYPE(pud_val(pud)))
#define pud_uc(pud)		is_mt_uc(_PAGE_GET_MEM_TYPE(pud_val(pud)))

#define pud_wrprotect(pud)	(__pud(_PAGE_CLEAR_WRITEABLE(pud_val(pud))))
#define pud_mkwrite(pud)	(__pud(_PAGE_SET_WRITEABLE(pud_val(pud))))
#define pud_mkexec(pud)		(__pud(_PAGE_SET_EXECUTEABLE(pud_val(pud))))
#define pud_mknotexec(pud)	(__pud(_PAGE_CLEAR_EXECUTEABLE(pud_val(pud))))
#define pud_mkpresent(pud)	(__pud(_PAGE_SET_PRESENT(pud_val(pud))))
#define pud_mknotpresent(pud)	(__pud(_PAGE_CLEAR_PRESENT(pud_val(pud))))
#define pud_mk_present_valid(pud) (__pud(_PAGE_SET(pud_val(pud), \
				   UNI_PAGE_PRESENT | UNI_PAGE_VALID)))
#define pud_mkvalid(pud)	(__pud(_PAGE_SET_VALID(pud_val(pud))))
#define pud_mknotpresent(pud)	(__pud(_PAGE_CLEAR_PRESENT(pud_val(pud))))
#define pud_mknot_present_valid(pud) (__pud(_PAGE_CLEAR(pud_val(pud), \
					    UNI_PAGE_PRESENT | UNI_PAGE_VALID)))
#define pud_mknotvalid(pud)	(__pud(_PAGE_CLEAR_VALID(pud_val(pud))))
#define pud_mkold(pud)		(__pud(_PAGE_CLEAR_ACCESSED(pud_val(pud))))
#define pud_mkyoung(pud)	(__pud(_PAGE_SET_ACCESSED(pud_val(pud))))
#define pud_mkclean(pud)	(__pud(_PAGE_CLEAR_DIRTY(pud_val(pud))))
#define pud_mkdirty(pud)	(__pud(_PAGE_SET_DIRTY(pud_val(pud))))
#define pud_mkhuge(pud)		(__pud(_PAGE_SET_HUGE(pud_val(pud))))
#define pud_mkdevmap(pud)	__pud(_PAGE_SET(pud_val(pud), UNI_PAGE_DEVMAP))
static inline pud_t pud_mk_wb(pud_t pud)
{
	return __pud(_PAGE_SET_MEM_TYPE(pud_val(pud), GEN_CACHE_MT));
}
static inline pud_t pud_mk_wc(pud_t pud)
{
	pte_mem_type_t mt;
	if (is_mt_external(_PAGE_GET_MEM_TYPE(pud_val(pud)))) {
		mt = EXT_PREFETCH_MT;
	} else {
		mt = memtype2pte_mem_type(PCM_WC);
	}
	return __pud(_PAGE_SET_MEM_TYPE(pud_val(pud), mt));
}
static inline pud_t pud_mk_uc(pud_t pud)
{
	pte_mem_type_t mt;
	if (is_mt_external(_PAGE_GET_MEM_TYPE(pud_val(pud)))) {
		mt = EXT_NON_PREFETCH_MT;
	} else {
		mt = memtype2pte_mem_type(PCM_UC);
	}
	return __pud(_PAGE_SET_MEM_TYPE(pud_val(pud), mt));
}

#ifndef	CONFIG_MAKE_ALL_PAGES_VALID
#define p4d_none(p4d)		(!p4d_val(p4d))
#else
#define p4d_none(p4d)		(_PAGE_CLEAR_VALID(p4d_val(p4d)) == 0)
#endif
#define p4d_mknotvalid(p4d)	(__p4d(_PAGE_CLEAR_VALID(p4d_val(p4d))))
#define p4d_valid(p4d)		_PAGE_TEST_VALID(p4d_val(p4d))

static inline int p4d_bad(p4d_t p4d)
{
	return unlikely(_PAGE_CLEAR(p4d_val(p4d) & PTE_FLAGS_MASK,
				    UNI_PAGE_GLOBAL) != _PAGE_USER_PUD);
}

#define p4d_present(p4d)	_PAGE_TEST_PRESENT(p4d_val(p4d))

#define	kernel_p4d_huge(p4d)	(is_huge_p4d_level() && _PAGE_TEST_HUGE(p4d_val(p4d)))

#define pgd_valid(pgd)		(1)
#define	kernel_pgd_huge(pgd)	(0)
#define pgd_mknotvalid(pgd)	(__pgd(_PAGE_CLEAR_VALID(pgd_val(pgd))))

/*
 * The following have defined behavior only work if pte_present() is true.
 */
#define pte_write(pte)		_PAGE_TEST_WRITEABLE(pte_val(pte))
#define pte_exec(pte)		_PAGE_TEST_EXECUTEABLE(pte_val(pte))
#define pte_dirty(pte)		_PAGE_TEST_DIRTY(pte_val(pte))
#define pte_young(pte)		_PAGE_TEST_ACCESSED(pte_val(pte))
#define pte_user(pte)		(!_PAGE_TEST_PRIV(pte))
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
#define pte_mkhuge(pte)		\
		(__pte(_PAGE_SET(pte_val(pte), \
				UNI_PAGE_PRESENT | UNI_PAGE_HUGE)))
#define	pte_mkspecial(pte)	(__pte(_PAGE_SET_SPECIAL(pte_val(pte))))
#define pte_mknotvalid(pte)	(__pte(_PAGE_CLEAR_VALID(pte_val(pte))))
#define pte_mkdevmap(pte)	__pte(_PAGE_SET(pte_val(pte), \
						UNI_PAGE_SPECIAL | UNI_PAGE_DEVMAP))



#ifdef CONFIG_PAGE_TABLE_CHECK
static inline bool pte_user_accessible_page(pte_t pte)
{
	return pte_present(pte) && pte_user(pte_val(pte));
}

static inline bool pmd_user_accessible_page(pmd_t pmd)
{
	return pmd_leaf(pmd) && pte_user(pmd_val(pmd));
}

static inline bool pud_user_accessible_page(pud_t pud)
{
	return pud_leaf(pud) && pte_user(pud_val(pud));
}
#endif

static inline pte_t pte_mk_wb(pte_t pte)
{
	return __pte(_PAGE_SET_MEM_TYPE(pte_val(pte), GEN_CACHE_MT));
}
static inline pte_t pte_mk_wc(pte_t pte)
{
	pte_mem_type_t mt;
	if (is_mt_external(_PAGE_GET_MEM_TYPE(pte_val(pte)))) {
		mt = EXT_PREFETCH_MT;
	} else {
		mt = memtype2pte_mem_type(PCM_WC);
	}
	return __pte(_PAGE_SET_MEM_TYPE(pte_val(pte), mt));
}
static inline pte_t pte_mk_uc(pte_t pte)
{
	pte_mem_type_t mt;
	if (is_mt_external(_PAGE_GET_MEM_TYPE(pte_val(pte)))) {
		mt = EXT_NON_PREFETCH_MT;
	} else {
		mt = memtype2pte_mem_type(PCM_UC);
	}
	return __pte(_PAGE_SET_MEM_TYPE(pte_val(pte), mt));
}

#define	VIRT_ADDR_VPTB_BASE(va)		\
		((MMU_IS_SEPARATE_PT()) ?	\
			(((va) >= MMU_SEPARATE_KERNEL_VAB) ?	\
				KERNEL_VPTB_BASE_ADDR : USER_VPTB_BASE_ADDR) \
			:	\
			MMU_UNITED_KERNEL_VPTB)

#define IS_USER_VPTB_ADDR(va) \
	((MMU_IS_SEPARATE_PT()) ? ((va) < MMU_SEPARATE_KERNEL_VAB) \
				: (IS_USER_ADDR(va)))

/*
 * The index and offset in the upper page table directory.
 */
#define	pud_index(virt_addr)		((virt_addr >> PUD_SHIFT) & \
					(PTRS_PER_PUD - 1))
#define	pud_virt_offset(virt_addr)	(VIRT_ADDR_VPTB_BASE(virt_addr) | \
					((pmd_virt_offset(virt_addr) & \
					PTE_MASK) >> \
					(E2K_VA_SIZE - PGDIR_SHIFT)))
#define	pud_virt_offset_k(virt_addr)	(KERNEL_VPTB_BASE_ADDR | \
					((pmd_virt_offset_k(virt_addr) & \
					PTE_MASK) >> \
					(E2K_VA_SIZE - PGDIR_SHIFT)))
#define	pud_virt_offset_u(virt_addr)	(USER_VPTB_BASE_ADDR | \
					((pmd_virt_offset_u(virt_addr) & \
					PTE_MASK) >> \
					(E2K_VA_SIZE - PGDIR_SHIFT)))

/*
 * The index and offset in the middle page table directory
 */
#define	pmd_index(virt_addr)		((virt_addr >> PMD_SHIFT) & \
					(PTRS_PER_PMD - 1))
#define	pmd_virt_offset(virt_addr)	(VIRT_ADDR_VPTB_BASE(virt_addr) | \
					((pte_virt_offset(virt_addr) & \
					PTE_MASK) >> \
					(E2K_VA_SIZE - PGDIR_SHIFT)))
#define	pmd_virt_offset_k(virt_addr)	(KERNEL_VPTB_BASE_ADDR | \
					((pte_virt_offset_k(virt_addr) & \
					PTE_MASK) >> \
					(E2K_VA_SIZE - PGDIR_SHIFT)))
#define	pmd_virt_offset_u(virt_addr)	(USER_VPTB_BASE_ADDR | \
					((pte_virt_offset_u(virt_addr) & \
					PTE_MASK) >> \
					(E2K_VA_SIZE - PGDIR_SHIFT)))

/*
 * The index and offset in the third-level page table.
 */
#define	pte_virt_offset(virt_addr)	(VIRT_ADDR_VPTB_BASE(virt_addr) | \
					(((virt_addr) & PTE_MASK) >> \
					(E2K_VA_SIZE - PGDIR_SHIFT)))
#define	pte_virt_offset_k(virt_addr)	(KERNEL_VPTB_BASE_ADDR | \
					(((virt_addr) & PTE_MASK) >> \
					(E2K_VA_SIZE - PGDIR_SHIFT)))
#define	pte_virt_offset_u(virt_addr)	(USER_VPTB_BASE_ADDR | \
					(((virt_addr) & PTE_MASK) >> \
					(E2K_VA_SIZE - PGDIR_SHIFT)))

#endif /* !(_ASM_E2K_PGTABLE_DEF_H) */
