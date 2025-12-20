/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * MMU management (Instruction and Data caches, TLB, registers)
 *
 * Derived heavily from Linus's Alpha/AXP ASN code...
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/pgtable.h>

#include <asm/types.h>
#include <asm/mmu_regs.h>
#include <asm/page.h>
#include <asm/pgalloc.h>
#include <asm/mmu_context.h>
#include <asm/secondary_space.h>

#include "pgtable-gp.h"
#include "mmu-pt.h"

static unsigned int
mmu_get_pte_val_memory_type_v3(pgprot_t pte)
{
	return mmu_pt_get_pte_val_memory_type_v3(pte);
}
static pgprot_t
mmu_set_pte_val_memory_type_v3(pgprot_t pte, unsigned int mtype)
{
	return mmu_pt_set_pte_val_memory_type_v3(pte, mtype);
}
static unsigned int
mmu_get_pte_val_memory_type_v6(pgprot_t pte)
{
	return mmu_pt_get_pte_val_memory_type_v6(pte);
}
static pgprot_t
mmu_set_pte_val_memory_type_v6(pgprot_t pte, unsigned int mtype)
{
	return mmu_pt_set_pte_val_memory_type_v6(pte, mtype);
}
static unsigned int
mmu_get_pte_val_memory_type_gp(pgprot_t pte)
{
	return mmu_pt_get_pte_val_memory_type_gp(pte);
}
static pgprot_t
mmu_set_pte_val_memory_type_gp(pgprot_t pte, unsigned int mtype)
{
	return mmu_pt_set_pte_val_memory_type_gp(pte, mtype);
}
static unsigned int
mmu_get_pte_val_memory_type_rule_gp(pgprot_t pte)
{
	return mmu_pt_get_pte_val_memory_type_rule_gp(pte);
}
static pgprot_t
mmu_set_pte_val_memory_type_rule_gp(pgprot_t pte, unsigned int mtcr)
{
	return mmu_pt_set_pte_val_memory_type_rule_gp(pte, mtcr);
}

/*
 * Hardware MMUs page tables have some differences from one ISET to other
 * moreover each MMU supports a few different page tables:
 *	native (primary)
 *	secondary page tables for sevral modes (VA32, VA48, PA32, PA48 ...)
 * The follow structures presents all available page table structures
 *
 * Warning .boot_*() entries should be updated dinamicaly to point to
 * physical addresses of functions for arch/e2k/p2v/
 */
const pt_struct_t pgtable_struct_e2k_v3 = {
	.type		= E2K_PT_TYPE,
	.name		= "primary e2k v3",
	.pt_v6		= false,
	.pfn_mask	= _PAGE_PFN_V3,
	.accessed_mask	= _PAGE_A_V3,
	.dirty_mask	= _PAGE_D_V3,
	.present_mask	= _PAGE_P_V3,
	.valid_mask	= _PAGE_VALID_V3,
	.user_mask	= 0ULL,
	.priv_mask	= _PAGE_PV_V3,
	.non_exec_mask	= _PAGE_NON_EX_V3,
	.exec_mask	= 0ULL,
	.huge_mask	= _PAGE_HUGE_V3,
	.protnone_mask	= _PAGE_PROTNONE_V3,
	.sw_bit1_mask	= _PAGE_AVAIL_V3,
	.sw_bit2_mask	= _PAGE_SW2_V3,
	.sw_mmio_mask	= _PAGE_MMIO_SW_V3,
	.ptd_kernel_prot = _PAGE_KERNEL_PT_V3,
	.ptd_user_prot	= _PAGE_USER_PT_V3,
	.levels_num	= E2K_PT_LEVELS_NUM,
	.get_pte_val_memory_type = &mmu_get_pte_val_memory_type_v3,
	.set_pte_val_memory_type = &mmu_set_pte_val_memory_type_v3,
	.get_pte_val_memory_type_rule = NULL,
	.set_pte_val_memory_type_rule = NULL,
	.levels		= {
		[E2K_PAGES_LEVEL_NUM] = {
			.id		= E2K_PAGES_LEVEL_NUM,
			.page_size	= PAGE_SIZE,
		},
		[E2K_PTE_LEVEL_NUM] = {
			.id		= E2K_PTE_LEVEL_NUM,
			.pt_size	= PTE_SIZE,
			.page_size	= PAGE_SIZE,
			.pt_shift	= PTE_SHIFT,
			.page_shift	= PTE_SHIFT,
			.pt_mask	= PTE_MASK & E2K_VA_PAGE_MASK,
			.pt_offset	= ~PTE_MASK & E2K_VA_PAGE_MASK,
			.pt_index_mask	= PTE_MASK ^ PMD_MASK,
			.page_mask	= PTE_MASK,
			.page_offset	= ~PTE_MASK,
			.ptrs_per_pt	= PTRS_PER_PTE,
			.is_pte		= true,
			.is_huge	= false,
			.dtlb_type	= COMMON_DTLB_TYPE,
		},
		[E2K_PMD_LEVEL_NUM] = {
			.id		= E2K_PMD_LEVEL_NUM,
			.pt_size	= PMD_SIZE,
			.pt_shift	= PMD_SHIFT,
			.pt_mask	= PMD_MASK & E2K_VA_PAGE_MASK,
			.pt_offset	= ~PMD_MASK & E2K_VA_PAGE_MASK,
			.pt_index_mask	= PMD_MASK ^ PUD_MASK,
			.page_mask	= PMD_MASK,
			.ptrs_per_pt	= PTRS_PER_PMD,
			.page_size	= E2K_2M_PAGE_SIZE,
			.page_shift	= PMD_SHIFT,
			.page_offset	= ~PMD_MASK,
			.is_pte		= false,
			.is_huge	= true,
			.dtlb_type	= COMMON_DTLB_TYPE,
		},
		[E2K_PUD_LEVEL_NUM] = {
			.id		= E2K_PUD_LEVEL_NUM,
			.pt_size	= PUD_SIZE,
			.page_size	= PAGE_PUD_SIZE,
			.pt_shift	= PUD_SHIFT,
			.page_shift	= PUD_SHIFT,
			.pt_mask	= PUD_MASK & E2K_VA_PAGE_MASK,
			.pt_offset	= ~PUD_MASK & E2K_VA_PAGE_MASK,
			.pt_index_mask	= PUD_MASK ^ PGDIR_MASK,
			.page_mask	= PUD_MASK,
			.page_offset	= ~PUD_MASK,
			.ptrs_per_pt	= PTRS_PER_PUD,
			.is_pte		= false,
			.is_huge	= false,
			.is_huge	= false,
		},
		[E2K_PGD_LEVEL_NUM] = {
			.id		= E2K_PGD_LEVEL_NUM,
			.pt_size	= PGDIR_SIZE,
			.page_size	= PAGE_PGD_SIZE,
			.pt_shift	= PGDIR_SHIFT,
			.page_shift	= PGDIR_SHIFT,
			.pt_mask	= PGDIR_MASK & E2K_VA_PAGE_MASK,
			.pt_offset	= ~PGDIR_MASK & E2K_VA_PAGE_MASK,
			.pt_index_mask	= PGDIR_MASK & E2K_VA_PAGE_MASK,
			.page_mask	= PGDIR_MASK,
			.page_offset	= ~PGDIR_MASK,
			.ptrs_per_pt	= PTRS_PER_PGD,
			.is_pte		= false,
			.is_huge	= false,
		},
	},
};
const pt_struct_t pgtable_struct_e2k_v5 = {
	.type		= E2K_PT_TYPE,
	.name		= "primary e2k v5",
	.pt_v6		= false,
	.pfn_mask	= _PAGE_PFN_V3,
	.accessed_mask	= _PAGE_A_V3,
	.dirty_mask	= _PAGE_D_V3,
	.present_mask	= _PAGE_P_V3,
	.valid_mask	= _PAGE_VALID_V3,
	.user_mask	= 0ULL,
	.priv_mask	= _PAGE_PV_V3,
	.non_exec_mask	= _PAGE_NON_EX_V3,
	.exec_mask	= 0ULL,
	.huge_mask	= _PAGE_HUGE_V3,
	.protnone_mask	= _PAGE_PROTNONE_V3,
	.sw_bit1_mask	= _PAGE_AVAIL_V3,
	.sw_bit2_mask	= _PAGE_SW2_V3,
	.sw_mmio_mask	= _PAGE_MMIO_SW_V3,
	.ptd_kernel_prot = _PAGE_KERNEL_PT_V3,
	.ptd_user_prot	= _PAGE_USER_PT_V3,
	.levels_num	= E2K_PT_LEVELS_NUM,
	.get_pte_val_memory_type = &mmu_get_pte_val_memory_type_v3,
	.set_pte_val_memory_type = &mmu_set_pte_val_memory_type_v3,
	.get_pte_val_memory_type_rule = NULL,
	.set_pte_val_memory_type_rule = NULL,
	.levels		= {
		[E2K_PAGES_LEVEL_NUM] = {
			.id		= E2K_PAGES_LEVEL_NUM,
			.page_size	= PAGE_SIZE,
		},
		[E2K_PTE_LEVEL_NUM] = {
			.id		= E2K_PTE_LEVEL_NUM,
			.pt_size	= PTE_SIZE,
			.page_size	= PAGE_SIZE,
			.pt_shift	= PTE_SHIFT,
			.page_shift	= PTE_SHIFT,
			.pt_mask	= PTE_MASK & E2K_VA_PAGE_MASK,
			.pt_offset	= ~PTE_MASK & E2K_VA_PAGE_MASK,
			.pt_index_mask	= PTE_MASK ^ PMD_MASK,
			.page_mask	= PTE_MASK,
			.page_offset	= ~PTE_MASK,
			.ptrs_per_pt	= PTRS_PER_PTE,
			.is_pte		= true,
			.is_huge	= false,
			.dtlb_type	= COMMON_DTLB_TYPE,
		},
		[E2K_PMD_LEVEL_NUM] = {
			.id		= E2K_PMD_LEVEL_NUM,
			.pt_size	= PMD_SIZE,
			.pt_shift	= PMD_SHIFT,
			.pt_mask	= PMD_MASK & E2K_VA_PAGE_MASK,
			.pt_offset	= ~PMD_MASK & E2K_VA_PAGE_MASK,
			.pt_index_mask	= PMD_MASK ^ PUD_MASK,
			.page_mask	= PMD_MASK,
			.ptrs_per_pt	= PTRS_PER_PMD,
			.page_size	= E2K_2M_PAGE_SIZE,
			.page_shift	= PMD_SHIFT,
			.page_offset	= ~PMD_MASK,
			.is_pte		= false,
			.is_huge	= true,
			.dtlb_type	= COMMON_DTLB_TYPE,
		},
		[E2K_PUD_LEVEL_NUM] = {
			.id		= E2K_PUD_LEVEL_NUM,
			.pt_size	= PUD_SIZE,
			.page_size	= PAGE_PUD_SIZE,
			.pt_shift	= PUD_SHIFT,
			.page_shift	= PUD_SHIFT,
			.pt_mask	= PUD_MASK & E2K_VA_PAGE_MASK,
			.pt_offset	= ~PUD_MASK & E2K_VA_PAGE_MASK,
			.pt_index_mask	= PUD_MASK ^ PGDIR_MASK,
			.page_mask	= PUD_MASK,
			.page_offset	= ~PUD_MASK,
			.ptrs_per_pt	= PTRS_PER_PUD,
			.is_pte		= false,
			.is_huge	= true,
			.dtlb_type	= FULL_ASSOCIATIVE_DTLB_TYPE,
		},
		[E2K_PGD_LEVEL_NUM] = {
			.id		= E2K_PGD_LEVEL_NUM,
			.pt_size	= PGDIR_SIZE,
			.page_size	= PAGE_PGD_SIZE,
			.pt_shift	= PGDIR_SHIFT,
			.page_shift	= PGDIR_SHIFT,
			.pt_mask	= PGDIR_MASK & E2K_VA_PAGE_MASK,
			.pt_offset	= ~PGDIR_MASK & E2K_VA_PAGE_MASK,
			.pt_index_mask	= PGDIR_MASK & E2K_VA_PAGE_MASK,
			.page_mask	= PGDIR_MASK,
			.page_offset	= ~PGDIR_MASK,
			.ptrs_per_pt	= PTRS_PER_PGD,
			.is_pte		= false,
			.is_huge	= false,
		},
	},
};

const pt_struct_t pgtable_struct_e2k_v6_pt_v6 = {
	.type		= E2K_PT_TYPE,
	.name		= "primary e2k v6",
	.pt_v6		= true,
	.pfn_mask	= _PAGE_PFN_V6,
	.accessed_mask	= _PAGE_A_V6,
	.dirty_mask	= _PAGE_D_V6,
	.present_mask	= _PAGE_P_V6,
	.valid_mask	= _PAGE_VALID_V6,
	.user_mask	= 0ULL,
	.priv_mask	= _PAGE_PV_V6,
	.non_exec_mask	= _PAGE_NON_EX_V6,
	.exec_mask	= 0ULL,
	.huge_mask	= _PAGE_HUGE_V6,
	.protnone_mask	= _PAGE_PROTNONE_V6,
	.sw_bit1_mask	= _PAGE_SW1_V6,
	.sw_bit2_mask	= _PAGE_SW2_V6,
	.sw_mmio_mask	= _PAGE_MMIO_SW_V6,
	.ptd_kernel_prot = _PAGE_KERNEL_PT_V6,
	.ptd_user_prot	= _PAGE_USER_PT_V6,
	.levels_num	= E2K_PT_LEVELS_NUM,
	.get_pte_val_memory_type = &mmu_get_pte_val_memory_type_v6,
	.set_pte_val_memory_type = &mmu_set_pte_val_memory_type_v6,
	.get_pte_val_memory_type_rule = NULL,
	.set_pte_val_memory_type_rule = NULL,
	.levels		= {
		[E2K_PAGES_LEVEL_NUM] = {
			.id		= E2K_PAGES_LEVEL_NUM,
			.page_size	= PAGE_SIZE,
		},
		[E2K_PTE_LEVEL_NUM] = {
			.id		= E2K_PTE_LEVEL_NUM,
			.pt_size	= PTE_SIZE,
			.page_size	= PAGE_SIZE,
			.pt_shift	= PTE_SHIFT,
			.page_shift	= PTE_SHIFT,
			.pt_mask	= PTE_MASK & E2K_VA_PAGE_MASK,
			.pt_offset	= ~PTE_MASK & E2K_VA_PAGE_MASK,
			.pt_index_mask	= PTE_MASK ^ PMD_MASK,
			.page_mask	= PTE_MASK,
			.page_offset	= ~PTE_MASK,
			.ptrs_per_pt	= PTRS_PER_PTE,
			.is_pte		= true,
			.is_huge	= false,
			.dtlb_type	= COMMON_DTLB_TYPE,
		},
		[E2K_PMD_LEVEL_NUM] = {
			.id		= E2K_PMD_LEVEL_NUM,
			.pt_size	= PMD_SIZE,
			.pt_shift	= PMD_SHIFT,
			.pt_mask	= PMD_MASK & E2K_VA_PAGE_MASK,
			.pt_offset	= ~PMD_MASK & E2K_VA_PAGE_MASK,
			.pt_index_mask	= PMD_MASK ^ PUD_MASK,
			.page_mask	= PMD_MASK,
			.ptrs_per_pt	= PTRS_PER_PMD,
			.page_size	= E2K_2M_PAGE_SIZE,
			.page_shift	= PMD_SHIFT,
			.page_offset	= ~PMD_MASK,
			.is_pte		= false,
			.is_huge	= true,
			.dtlb_type	= COMMON_DTLB_TYPE,
		},
		[E2K_PUD_LEVEL_NUM] = {
			.id		= E2K_PUD_LEVEL_NUM,
			.pt_size	= PUD_SIZE,
			.page_size	= PAGE_PUD_SIZE,
			.pt_shift	= PUD_SHIFT,
			.page_shift	= PUD_SHIFT,
			.pt_mask	= PUD_MASK & E2K_VA_PAGE_MASK,
			.pt_offset	= ~PUD_MASK & E2K_VA_PAGE_MASK,
			.pt_index_mask	= PUD_MASK ^ PGDIR_MASK,
			.page_mask	= PUD_MASK,
			.page_offset	= ~PUD_MASK,
			.ptrs_per_pt	= PTRS_PER_PUD,
			.is_pte		= false,
			.is_huge	= true,
			.dtlb_type	= FULL_ASSOCIATIVE_DTLB_TYPE,
		},
		[E2K_PGD_LEVEL_NUM] = {
			.id		= E2K_PGD_LEVEL_NUM,
			.pt_size	= PGDIR_SIZE,
			.page_size	= PAGE_PGD_SIZE,
			.pt_shift	= PGDIR_SHIFT,
			.page_shift	= PGDIR_SHIFT,
			.pt_mask	= PGDIR_MASK & E2K_VA_PAGE_MASK,
			.pt_offset	= ~PGDIR_MASK & E2K_VA_PAGE_MASK,
			.pt_index_mask	= PGDIR_MASK & E2K_VA_PAGE_MASK,
			.page_mask	= PGDIR_MASK,
			.page_offset	= ~PGDIR_MASK,
			.ptrs_per_pt	= PTRS_PER_PGD,
			.is_pte		= false,
			.is_huge	= false,
		},
	},
};

const pt_struct_t pgtable_struct_e2k_v6_gp = {
	.type		= E2K_PT_TYPE,
	.name		= "guest physical e2k v6",
	.pt_v6		= true,
	.pfn_mask	= _PAGE_PFN_GP,
	.accessed_mask	= _PAGE_A_GP,
	.dirty_mask	= _PAGE_D_GP,
	.present_mask	= _PAGE_P_GP,
	.valid_mask	= 0ULL,
	.user_mask	= 0ULL,
	.priv_mask	= 0ULL,
	.non_exec_mask	= 0ULL,
	.exec_mask	= 0ULL,
	.huge_mask	= _PAGE_HUGE_GP,
	.protnone_mask	= 0ULL,
	.sw_bit1_mask	= _PAGE_SW1_GP,
	.sw_bit2_mask	= _PAGE_SW2_GP,
	.sw_mmio_mask	= _PAGE_MMIO_SW_GP,
	.ptd_kernel_prot = _PAGE_KERNEL_PT_GP,
	.ptd_user_prot	= _PAGE_KERNEL_PT_GP,
	.levels_num	= E2K_PT_LEVELS_NUM,
	.get_pte_val_memory_type = &mmu_get_pte_val_memory_type_gp,
	.set_pte_val_memory_type = &mmu_set_pte_val_memory_type_gp,
	.get_pte_val_memory_type_rule = &mmu_get_pte_val_memory_type_rule_gp,
	.set_pte_val_memory_type_rule = &mmu_set_pte_val_memory_type_rule_gp,
	.levels		= {
		[E2K_PAGES_LEVEL_NUM] = {
			.id		= E2K_PAGES_LEVEL_NUM,
			.page_size	= PAGE_SIZE,
		},
		[E2K_PTE_LEVEL_NUM] = {
			.id		= E2K_PTE_LEVEL_NUM,
			.pt_size	= PTE_SIZE,
			.page_size	= PAGE_SIZE,
			.pt_shift	= PTE_SHIFT,
			.page_shift	= PTE_SHIFT,
			.pt_mask	= PTE_MASK & E2K_VA_PAGE_MASK,
			.pt_offset	= ~PTE_MASK & E2K_VA_PAGE_MASK,
			.pt_index_mask	= PTE_MASK ^ PMD_MASK,
			.page_mask	= PTE_MASK,
			.page_offset	= ~PTE_MASK,
			.ptrs_per_pt	= PTRS_PER_PTE,
			.is_pte		= true,
			.is_huge	= false,
			.dtlb_type	= COMMON_DTLB_TYPE,
		},
		[E2K_PMD_LEVEL_NUM] = {
			.id		= E2K_PMD_LEVEL_NUM,
			.pt_size	= PMD_SIZE,
			.pt_shift	= PMD_SHIFT,
			.pt_mask	= PMD_MASK & E2K_VA_PAGE_MASK,
			.pt_offset	= ~PMD_MASK & E2K_VA_PAGE_MASK,
			.pt_index_mask	= PMD_MASK ^ PUD_MASK,
			.page_mask	= PMD_MASK,
			.ptrs_per_pt	= PTRS_PER_PMD,
			.page_size	= E2K_2M_PAGE_SIZE,
			.page_shift	= PMD_SHIFT,
			.page_offset	= ~PMD_MASK,
			.is_pte		= false,
			.is_huge	= true,
			.dtlb_type	= COMMON_DTLB_TYPE,
		},
		[E2K_PUD_LEVEL_NUM] = {
			.id		= E2K_PUD_LEVEL_NUM,
			.pt_size	= PUD_SIZE,
			.page_size	= PAGE_PUD_SIZE,
			.pt_shift	= PUD_SHIFT,
			.page_shift	= PUD_SHIFT,
			.pt_mask	= PUD_MASK & E2K_VA_PAGE_MASK,
			.pt_offset	= ~PUD_MASK & E2K_VA_PAGE_MASK,
			.pt_index_mask	= PUD_MASK ^ PGDIR_MASK,
			.page_mask	= PUD_MASK,
			.page_offset	= ~PUD_MASK,
			.ptrs_per_pt	= PTRS_PER_PUD,
			.is_pte		= false,
			.is_huge	= true,
			.dtlb_type	= FULL_ASSOCIATIVE_DTLB_TYPE,
		},
		[E2K_PGD_LEVEL_NUM] = {
			.id		= E2K_PGD_LEVEL_NUM,
			.pt_size	= PGDIR_SIZE,
			.page_size	= PAGE_PGD_SIZE,
			.pt_shift	= PGDIR_SHIFT,
			.page_shift	= PGDIR_SHIFT,
			.pt_mask	= PGDIR_MASK & E2K_VA_PAGE_MASK,
			.pt_offset	= ~PGDIR_MASK & E2K_VA_PAGE_MASK,
			.pt_index_mask	= PGDIR_MASK & E2K_VA_PAGE_MASK,
			.page_mask	= PGDIR_MASK,
			.page_offset	= ~PGDIR_MASK,
			.ptrs_per_pt	= PTRS_PER_PGD,
			.is_pte		= false,
			.is_huge	= false,
		},
	},
};

