/*
 *	Access to VGA videoram
 *
 *	(c) 1998 Martin Mares <mj@ucw.cz>
 */

#ifndef _LINUX_ASM_VGA_H_
#define _LINUX_ASM_VGA_H_

#include <asm/e2k_api.h>
#include <asm/mas.h>

/*
 *	On the PC, we can just recalculate addresses and then
 *	access the videoram directly without any black magic.
 */

#define	E2K_VGA_DIRECT_IOMEM

#define VGA_MAP_MEM(x, s) (unsigned long)phys_to_virt(x)

#define	VGA_VRAM_PHYS_BASE	0x00000a0000UL	/* VGA video RAM low memory */
#define	VGA_VRAM_SIZE		0x0000020000UL	/* a0000 - c0000 */

#ifdef E2K_VGA_DIRECT_IOMEM

#define native_scr_writew(val, addr)	(*(addr) = (val))
#define native_scr_readw(addr)		(*(addr))

#define native_vga_readb(addr)		(*(addr))
#define native_vga_writeb(val, addr)	(*(addr) = (val))

#else

#define VT_BUF_HAVE_RW

static inline void native_scr_writew(u16 val, volatile u16 *addr)
{
	native_writew(val, addr);
}
static inline u16 native_scr_readw(volatile const u16 *addr)
{
	return native_readw(addr);
}
static inline void native_vga_writeb(u8 val, volatile u8 *addr)
{
	native_writeb(val, addr);
}

static inline u8 native_vga_readb(volatile const u8 *addr)
{
	return native_readb(addr);
}

#endif	/* E2K_VGA_DIRECT_IOMEM */

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* native guest kernel */
#include <asm/kvm/guest/vga.h>
#elif	defined(CONFIG_PARAVIRT_GUEST)
/* paravirtualized host and guest kernel */
#include <asm/paravirt/vga.h>
#else	/* ! CONFIG_KVM_GUEST_KERNEL && ! CONFIG_PARAVIRT_GUEST */
/* native host kernel with or whithout visrtualizaton */

static inline void scr_writew(u16 val, volatile u16 *addr)
{
	native_scr_writew(val, addr);
}

static inline u16 scr_readw(volatile const u16 *addr)
{
	return native_scr_readw(addr);
}
static inline void vga_writeb(u8 val, volatile u8 *addr)
{
	native_vga_writeb(val, addr);
}

static inline u8 vga_readb(volatile const u8 *addr)
{
	return native_vga_readb(addr);
}
#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif
