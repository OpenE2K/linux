
#ifndef	_E2K_PARAVIRT_VGA_H_
#define	_E2K_PARAVIRT_VGA_H_

#include <linux/types.h>
#include <asm/paravirt/pv_ops.h>
#include <asm/kvm/guest/vga.h>

/*
 * VGA screen support
 * VGA Video Memory emulated as part of common guest VCPUs virtual memory
 */

static inline void pv_scr_writew(u16 val, volatile u16 *addr)
{
	pv_io_ops.scr_writew(val, addr);
}
static inline u16 pv_scr_readw(volatile const u16 *addr)
{
	return pv_io_ops.scr_readw(addr);
}
static inline void pv_vga_writeb(u8 val, volatile u8 *addr)
{
	pv_io_ops.vga_writeb(val, addr);
}
static inline u8 pv_vga_readb(volatile const u8 *addr)
{
	return pv_io_ops.vga_readb(addr);
}

#ifdef	CONFIG_PARAVIRT_GUEST
static inline void scr_writew(u16 val, volatile u16 *addr)
{
	pv_scr_writew(val, addr);
}

static inline u16 scr_readw(volatile const u16 *addr)
{
	return pv_scr_readw(addr);
}
static inline void vga_writeb(u8 val, volatile u8 *addr)
{
	pv_vga_writeb(val, addr);
}

static inline u8 vga_readb(volatile const u8 *addr)
{
	return pv_vga_readb(addr);
}
#endif	/* CONFIG_PARAVIRT_GUEST */

#endif  /* _E2K_PARAVIRT_VGA_H_ */
