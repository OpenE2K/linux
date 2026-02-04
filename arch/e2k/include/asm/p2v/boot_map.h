/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/* $Id: boot_map.h,v 1.5 2008/12/19 12:57:15 atic Exp $
 *
 * boot-time mappings physical memory areas to virtual kernel space.
 */
#ifndef _E2K_P2V_BOOT_MAP_H
#define _E2K_P2V_BOOT_MAP_H

#include <linux/init.h>
#include <linux/pgtable.h>

#include <asm/types.h>
#include <asm/page.h>
#include <asm/mmu_regs.h>
#include <asm/p2v/boot_pgtable.h>
#include <asm/p2v/boot_smp.h>

/*
 * Forwards of boot-time functions to map physical areas to kernel virtual space
 */

extern void boot_init_mapping(int bsp);

extern void boot_map_phys_area(const char *name, e2k_addr_t phys_area_addr,
		e2k_size_t phys_area_size, e2k_addr_t area_virt_addr,
		pgprot_t prot_flags, e2k_size_t page_size,
		bool ignore_busy, bool host_map);
extern long boot_do_map_phys_area(e2k_addr_t phys_area_addr,
			e2k_size_t phys_area_size, e2k_addr_t area_virt_addr,
			pgprot_t prot_flags, const pt_level_t *pt_level,
			bool ignore_busy, bool host_map);
extern void boot_map_to_equal_virt_area(const char *name, e2k_addr_t area_addr,
		size_t area_size, pgprot_t prot_flags, size_t max_page_size);
extern void init_unmap_virt_to_equal_phys(bool bsp, int cpus_to_sync);

#endif /* _E2K_P2V_BOOT_MAP_H */
