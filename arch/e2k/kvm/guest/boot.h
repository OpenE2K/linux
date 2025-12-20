/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * KVM boot-time initialization
 */

#ifndef __E2K_KVM_GUEST_BOOT_H
#define __E2K_KVM_GUEST_BOOT_H

#include <linux/types.h>

#include <uapi/asm/kvm.h>
#include <asm/kvm/guest.h>

typedef struct vram_area {
	e2k_addr_t	base_addr;	/* base physical address of the start */
					/* page of the bank */
	e2k_size_t	pages_num;	/* total number of pages in the bank */
} vram_area_t;

extern vram_area_t	vram_areas[KVM_MAX_VRAM_AREAS];
extern int		vram_areas_num;

#define boot_vram_areas	\
		boot_vp_to_pp((vram_area_t *)vram_areas)
#define boot_vram_areas_num	\
		boot_get_vo_value(vram_areas_num)

extern int __init boot_kvm_probe_vram_memory(boot_info_t *bootblock);
extern void __init boot_kvm_map_vram_memory(boot_info_t *boot_info);

#ifdef	CONFIG_KVM_SHADOW_PT
static inline void __init boot_host_kernel_image(bool bsp)
{
	/* nothing to do */
	return;
}
#define	populate_image_on_host	false
#else	/* ! CONFIG_KVM_SHADOW_PT */
extern void __init boot_host_kernel_image(bool bsp);
#define	populate_image_on_host	true
#endif	/* CONFIG_KVM_SHADOW_PT */

#endif /* __E2K_KVM_GUEST_BOOT_H */
