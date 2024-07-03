/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Boot-time initialization of Virtual RAM support.
 * VRAM is memory areas into physical memory address range, which
 * can be allocated by KVM guest kernel launcher (for example QEMU).
 * These areas can not
 *	intersect with real physical memory addresses range;
 *	be used as physical memory
 * VRAMs are special areas shared by QEMU, host and guest as extensions
 * to support virtual machines
 */

#include <asm/p2v/boot_v2p.h>
#include <asm/p2v/boot_init.h>
#include <asm/p2v/boot_console.h>
#include <asm/mmu_context.h>
#include <asm/p2v/boot_param.h>
#include <asm/p2v/boot_map.h>
#include <asm/errors_hndl.h>

#include "boot.h"

#undef	DEBUG_BOOT_MODE
#undef	boot_printk
#define	DEBUG_BOOT_MODE		1	/* Boot process */
#define	boot_printk(fmt, args...)					\
({									\
	if (DEBUG_BOOT_MODE)						\
		do_boot_printk("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_NUMA_MODE
#undef	DebugNUMA
#define	DEBUG_NUMA_MODE		0	/* NUMA mode debugging */
#define	DebugNUMA(fmt, args...)						\
({									\
	if (DEBUG_NUMA_MODE)						\
		do_boot_printk("%s(): " fmt, __func__, ##args);		\
})

/*
 * The next structure contains list of descriptors of the memory areas
 * used by boot-time initialization.
 * All the used memory areas enumerate in this structure. If a some new
 * area will be used, then it should be added to the list of already known ones.
 */

vram_area_t __initdata vram_areas[KVM_MAX_VRAM_AREAS];
int __initdata vram_areas_num = 0;

#ifdef	CONFIG_NUMA
static int __initdata node_vram_mapped[MAX_NUMNODES] = { 0 };
#define	boot_node_vram_mapped					\
		boot_get_vo_value(node_vram_mapped[boot_numa_node_id()])
#else	/* ! CONFIG_NUMA */
#define	boot_node_vram_mapped	0
#endif	/* CONFIG_NUMA */

static void __init
boot_create_vram_area(vram_area_t *vram_area,
			e2k_addr_t bank_start, e2k_size_t bank_size)
{
	vram_area->base_addr = bank_start;
	vram_area->pages_num = bank_size >> PAGE_SHIFT;
}

int __init
boot_kvm_probe_vram_memory(boot_info_t *bootblock)
{
	bank_info_t	*vram_banks;
	bank_info_t	*bank_info;
	vram_area_t	*vrams;
	int		bank = 0;

	vram_banks = bootblock->bios.banks_ex;
	vrams = boot_vram_areas;

	for (bank = 0; bank < L_MAX_PHYS_BANKS_EX; bank++) {
		e2k_size_t bank_size;
		e2k_addr_t bank_start;
		vram_area_t *vram;

		bank_info = &vram_banks[bank];
		bank_start = bank_info->address;
		bank_size = bank_info->size;

		if (bank_size == 0)
			/* no more VRAM banks */
			break;

		if (bank >= KVM_MAX_VRAM_AREAS) {
			do_boot_printk("Number of VRAM banks too many, only "
				"%d banks is allowed, ignore other\n",
				KVM_MAX_VRAM_AREAS);
			break;
		}

		if ((bank_size & (PAGE_SIZE - 1)) != 0) {
			BOOT_BUG("VRAM bank #%d size 0x%lx is not page aligned",
				bank, bank_size);
			bank_size &= ~(PAGE_SIZE - 1);
		}
		if ((bank_start & (PAGE_SIZE - 1)) != 0) {
			BOOT_BUG("VRAM bank #%d base address 0x%lx is not "
				"page aligned",
				bank, bank_start);
			bank_size += (bank_start & (PAGE_SIZE - 1));
			bank_start &= ~(PAGE_SIZE - 1);
		}

		vram = &vrams[bank];
		boot_create_vram_area(vram, bank_start, bank_size);
		boot_printk("VRAM bank #%d : base 0x%lx, size 0x%lx "
			"(0x%lx pages)\n",
			bank, vram->base_addr, vram->pages_num << PAGE_SHIFT,
			vram->pages_num);
	}
	if (bank > 0) {
		boot_vram_areas_num = bank;
		boot_printk("Created %d VRAM bank(s)\n", bank);
	} else {
		BOOT_BUG("Could not find or create VRAM banks");
	}

	return bank;
}

static void __init boot_map_vram_area(vram_area_t *vram)
{
	e2k_addr_t	area_phys_base;
	e2k_size_t	area_size;
	e2k_addr_t	area_virt_base;

	area_phys_base = boot_pa_to_vpa(vram->base_addr);
	area_size = vram->pages_num << PAGE_SHIFT;
	area_virt_base = (e2k_addr_t)__boot_va(boot_vpa_to_pa(area_phys_base));
	boot_map_phys_area("VRAM", area_phys_base, area_size,
			area_virt_base,
			PAGE_KERNEL, E2K_SMALL_PAGE_SIZE,
			false,	/* do not ignore if data mapping virtual */
				/* area is busy */
			false);	/* populate map on host? */
}

void __init boot_kvm_map_vram_memory(boot_info_t *boot_info)
{
	vram_area_t *vrams = boot_vram_areas;
	int bank;

	/*
	 * Map the available VRAM areas into virtual space to direct
	 * access to the memory using kernel pa <-> va translations
	 * VRAM are mapped to virtual space starting from 'PAGE_OFFSET',
	 * same as physical memory pages
	 */
	for (bank = 0; bank < boot_vram_areas_num; bank++)
		boot_map_vram_area(&vrams[bank]);
}
