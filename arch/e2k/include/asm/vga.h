/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _LINUX_ASM_VGA_H_
#define _LINUX_ASM_VGA_H_

#include <asm/e2k_api.h>
#include <asm/io.h>
#include <asm/mas.h>

#define VT_BUF_HAVE_RW

#define VGA_MAP_MEM(x, s) (unsigned long)phys_to_virt(x)

#define	VGA_VRAM_PHYS_BASE	0x00000a0000UL	/* VGA video RAM low memory */
#define	VGA_VRAM_SIZE		0x0000020000UL	/* a0000 - c0000 */

#define native_scr_writew(val, addr) \
do { \
	if (cpu_has(CPU_FEAT_WC_LEGACY_VGA)) { \
		*(addr) = (val); \
	} else { \
		native_writew_relaxed(val, (volatile u16 *) addr); \
	} \
} while (0)

#define native_scr_readw(addr) \
({ \
	u16 __scr_val; \
	if (cpu_has(CPU_FEAT_WC_LEGACY_VGA)) { \
		__scr_val = *(addr); \
	} else { \
		__scr_val = native_readw_relaxed((volatile u16 *) addr); \
	} \
	__scr_val; \
})

static inline void native_vga_writeb(u8 val, u8 *addr)
{
	if (cpu_has(CPU_FEAT_WC_LEGACY_VGA)) {
		*addr = val;
	} else {
		native_writeb_relaxed(val, (volatile u8 *) addr);
	}
}

static inline u8 native_vga_readb(const u8 *addr)
{
	if (cpu_has(CPU_FEAT_WC_LEGACY_VGA)) {
		return *addr;
	} else {
		return native_readb_relaxed((volatile u8 *) addr);
	}
}

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is virtualized guest kernel */
#include <asm/kvm/guest/vga.h>
#else	/* !CONFIG_KVM_GUEST_KERNEL */
/* native host kernel with or whithout visrtualizaton */
# define scr_writew	native_scr_writew
# define scr_readw	native_scr_readw
# define vga_writeb	native_vga_writeb
# define vga_readb	native_vga_readb
#endif	/* CONFIG_KVM_GUEST_KERNEL */

/*
 * Our drivers doens't use VGA legacy resources so
 * we assume we can't have any conflicts
 */
#define __ARCH_HAS_VGA_CONFLICT
struct pci_dev;
static inline int vga_conflicts(struct pci_dev *p1, struct pci_dev *p2)
{
	return 0;
}

#endif
