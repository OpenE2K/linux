/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#pragma once

#include <asm/pgtable.h>
#include <asm/p2v/boot_v2p.h>

#define	boot_pgd_index(virt_addr)	pgd_index(virt_addr)
#define boot_pgd_offset_k(virt_addr) ((pgd_t *) boot_va_to_pa(swapper_pg_dir) + \
				      boot_pgd_index(virt_addr))

#define boot_mk_pgd_phys_k(pudp)	\
		mk_pgd_phys(boot_vpa_to_pa((e2k_addr_t)(pudp)), PAGE_KERNEL_PUD)
#define boot_mk_pgd_phys_u(pudp)	\
		mk_pgd_phys(boot_vpa_to_pa((e2k_addr_t)(pudp)), PAGE_USER_PUD)
#define boot_pgd_set_k(pgdp, pudp)	(*(pgdp) = boot_mk_pgd_phys_k(pudp))
#define boot_pgd_set_u(pgdp, pudp)	(*(pgdp) = boot_mk_pgd_phys_u(pudp))

#define boot_vmlpt_pgd_set(pgdp, lpt)	(*(pgdp) = boot_mk_pgd_phys_k(	\
							(pud_t *)(lpt)))
#define	boot_pgd_page_vaddr(pgd) \
		(e2k_addr_t)boot_va(_PAGE_PFN_TO_PADDR(pgd_val(pgd)))

#define	boot_pud_index(virt_addr)	pud_index(virt_addr)
#define boot_pud_offset(pgd, addr) ((pud_t *) boot_pgd_page_vaddr(*(pgd)) + \
				    boot_pud_index(addr))
#define boot_pud_set_k(pudp, pmdp) \
		(*(pudp) = mk_pud_phys(boot_vpa_to_pa((e2k_addr_t)(pmdp)), \
							PAGE_KERNEL_PMD))
#define boot_pud_set_u(pudp, pmdp) \
		(*(pudp) = mk_pud_phys(boot_vpa_to_pa((e2k_addr_t)(pmdp)), \
							PAGE_USER_PMD))
#define	boot_pud_page_vaddr(pud) \
		((unsigned long) boot_va(_PAGE_PFN_TO_PADDR(pud_val(pud))))


#define	boot_pmd_index(virt_addr)	pmd_index(virt_addr)
#define boot_pmd_offset(pud, addr) ((pmd_t *) boot_pud_page_vaddr(*(pud)) + \
				    boot_pmd_index(addr))
#define boot_pmd_set_k(pmdp, ptep) \
		(*(pmdp) = mk_pmd_phys(boot_vpa_to_pa((e2k_addr_t)(ptep)), \
							PAGE_KERNEL_PTE))
#define boot_pmd_set_u(pmdp, ptep)	\
		(*(pmdp) = mk_pmd_phys(boot_vpa_to_pa((e2k_addr_t)(ptep)), \
							PAGE_USER_PTE))
#define	boot_pmd_page_vaddr(pmd)		\
		((e2k_addr_t) boot_va(_PAGE_PFN_TO_PADDR(pmd_val(pmd))))


#define	boot_pte_index(virt_addr)	pte_index(virt_addr)
#define boot_pte_offset(pmd, addr) ((pte_t *) boot_pmd_page_vaddr(*(pmd)) + \
				    boot_pte_index(addr))
