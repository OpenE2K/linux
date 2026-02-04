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

#define boot_mk_p4d_phys_k(pudp)	\
		mk_p4d_phys(boot_vpa_to_pa((e2k_addr_t)(pudp)), PAGE_KERNEL_PUD)
#define boot_mk_p4d_phys_u(pudp)	\
		mk_p4d_phys(boot_vpa_to_pa((e2k_addr_t)(pudp)), PAGE_USER_PUD)
#define boot_p4d_offset(pgd, addr)	pgdp_to_p4dp(pgd)
#define boot_p4d_set_k(p4dp, pudp)	(*(p4dp) = boot_mk_p4d_phys_k(pudp))
#define boot_p4d_set_u(p4dp, pudp)	(*(p4dp) = boot_mk_p4d_phys_u(pudp))

#define boot_vmlpt_pgd_set(pgdp, lpt) \
		(*(pgdp) = __pgd(_PAGE_PADDR_TO_PFN(boot_vpa_to_pa((e2k_addr_t)lpt)) | \
				 _PAGE_KERNEL_PT))

#define	boot_p4d_page_vaddr(p4d) \
		(e2k_addr_t)boot_va(_PAGE_PFN_TO_PADDR(p4d_val(p4d)))

#define	boot_pud_index(virt_addr)	pud_index(virt_addr)
#define boot_pud_offset(p4d, addr) ((pud_t *) boot_p4d_page_vaddr(*(p4d)) + \
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
