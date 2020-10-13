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

#ifdef E2K_VGA_DIRECT_IOMEM

#define vga_readb(x) (*(x))
#define vga_writeb(x,y) (*(y) = (x))

#else

#define VT_BUF_HAVE_RW

extern inline void scr_writew(u16 val, volatile u16 *addr)
{
       E2K_WRITE_MAS_H(addr, val, MAS_IOADDR);
}

extern inline u16 scr_readw(volatile const u16 *addr)
{
        return (u16) E2K_READ_MAS_H(addr, MAS_IOADDR);
}

#define vga_readb(x)	({ E2K_READ_MAS_B(x, MAS_IOADDR); })
#define vga_writeb(x,y)	({ E2K_WRITE_MAS_B(y, x, MAS_IOADDR); })

#endif	/* E2K_VGA_DIRECT_IOMEM */

#endif
