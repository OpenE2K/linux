/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _E2K_KVM_MMU_E2K_H_
#define _E2K_KVM_MMU_E2K_H_

#include <linux/kvm_host.h>

#include <asm/mmu_types.h>
#include <asm/pgtable_def.h>

#if	_PAGE_P_V6 == _PAGE_P_V3
# define PT_E2K_PRESENT_MASK	_PAGE_P_V6
#else
# error	"Page table PRESENT bit is different for ISET-V6 vs older ISETs"
#endif
#if	_PAGE_W_V6 == _PAGE_W_V3
# define PT_E2K_WRITABLE_MASK	_PAGE_W_V6
#else
# error	"Page table WRITABLE bit is different for ISET-V6 vs older ISETs"
#endif
#if	_PAGE_A_V6 == _PAGE_A_V3
# define PT_E2K_ACCESSED_MASK	_PAGE_A_V6
#else
# error	"Page table ACCESSED bit is different for ISET-V6 vs older ISETs"
#endif
#if	_PAGE_D_V6 == _PAGE_D_V3
# define PT_E2K_DIRTY_MASK	_PAGE_D_V6
#else
# error	"Page table DIRTY bit is different for ISET-V6 vs older ISETs"
#endif
#if	_PAGE_HUGE_V6 == _PAGE_HUGE_V3
# define PT_E2K_PAGE_SIZE_MASK	_PAGE_HUGE_V6
#else
# error	"Page table PAGE SIZE bit is different for ISET-V6 vs older ISETs"
#endif
#if	_PAGE_G_V6 == _PAGE_G_V3
# define PT_E2K_GLOBAL_MASK	_PAGE_G_V6
#else
# error	"Page table GLOBAL bit is different for ISET-V6 vs older ISETs"
#endif
#if	_PAGE_NON_EX_V6 == _PAGE_NON_EX_V3
# define PT_E2K_NX_MASK		_PAGE_NON_EX_V6
#else
# define PT_E2K_NX_MASK(pt_v6)	((pt_v6) ? _PAGE_NON_EX_V6 : _PAGE_NON_EX_V3)
#endif

#define PT_E2K_ROOT_LEVEL	E2K_PGD_LEVEL_NUM	/* pte, pmd, pud, pgd */
#define PT_E2K_DIRECTORY_LEVEL	E2K_PMD_LEVEL_NUM	/* pmd */
#define PT_E2K_PAGE_TABLE_LEVEL	E2K_PTE_LEVEL_NUM	/* pte */
#define PT_E2K_MAX_HUGEPAGE_LEVEL MAX_HUGE_PAGES_LEVEL	/* pud */

#define	PT_E2K_ENTRIES_BITS	PT_ENTRIES_BITS		/* 9 bits */
#define	PT_E2K_ENT_PER_PAGE	PT_ENTRIES_PER_PAGE	/* 512 entries */

#endif	/* _E2K_KVM_MMU_E2K_H_ */
