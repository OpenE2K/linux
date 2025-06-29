/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _ASM_E2K_VMALLOC_H
#define _ASM_E2K_VMALLOC_H

#include <asm/cpu_features.h>

/*
 * vmap for huge pages forbid for debug kernel configuration
 * because in case if you need to split page from vmap area
 * you can get into indirect recursion
 * (set_memory_* -> alloc_page -> set_memory_*)
 */
#define arch_vmap_pud_supported arch_vmap_pud_supported
static inline bool arch_vmap_pud_supported(pgprot_t prot)
{
	return cpu_has(CPU_FEAT_ISET_V5) && !IS_ENABLED(CONFIG_DEBUG_PAGEALLOC);
}

#define arch_vmap_pmd_supported arch_vmap_pmd_supported
static inline bool arch_vmap_pmd_supported(pgprot_t prot)
{
	return !IS_ENABLED(CONFIG_DEBUG_PAGEALLOC);
}


#endif /* _ASM_E2K_VMALLOC_H */
