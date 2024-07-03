/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */


#ifndef	_E2K_BOOT_IO_H_
#define	_E2K_BOOT_IO_H_

//#include <asm/e2k_api.h>
//#include <asm/types.h>
#include <asm/head.h>

/*
 * E2K I/O ports for BIOS
 */

#if defined(CONFIG_E2K_FULL_SIC)
#define	PHYS_IO_BASE	E2K_FULL_SIC_IO_AREA_PHYS_BASE
#elif defined(CONFIG_E2K_LEGACY_SIC)
#define	PHYS_IO_BASE	E2K_LEGACY_SIC_IO_AREA_PHYS_BASE
#else
#error "Undefined machine or SIC type"
#endif

extern unsigned char	bios_inb(unsigned short port);
extern unsigned short	bios_inw(unsigned short port);
extern unsigned int	bios_inl(unsigned short port);
extern unsigned long	bios_inll(unsigned short port);
extern void		bios_outb(unsigned char byte, unsigned short port);
extern void		bios_outw(unsigned short byte, unsigned short port);
extern void		bios_outl(unsigned int byte, unsigned short port);
extern void		bios_outll(unsigned long byte, unsigned short port);

#ifdef	CONFIG_E2K_SIC
extern u8 bios_conf_inb(int domain, unsigned char bus, unsigned long port);
extern u16 bios_conf_inw(int domain, unsigned char bus, unsigned long port);
extern u32 bios_conf_inl(int domain, unsigned char bus, unsigned long port);
extern void bios_conf_outb(int domain, unsigned char bus, u8 byte,
			unsigned long port);
extern void bios_conf_outw(int domain, unsigned char bus, u16 halwword,
			unsigned long port);
extern void bios_conf_outl(int domain, unsigned char bus, u32 word,
			unsigned long port);
extern u8 bios_ioh_e2s_inb(int domain, unsigned char bus, unsigned long port);
extern u16 bios_ioh_e2s_inw(int domain, unsigned char bus, unsigned long port);
extern u32 bios_ioh_e2s_inl(int domain, unsigned char bus, unsigned long port);
extern void bios_ioh_e2s_outb(int domain, unsigned char bus, unsigned char byte,
			unsigned long port);
extern void bios_ioh_e2s_outw(int domain, unsigned char bus, u16 halfword,
			unsigned long port);
extern void bios_ioh_e2s_outl(int domain, unsigned char bus, u32 word,
			unsigned long port);

#endif	/* CONFIG_E2K_SIC */

extern void rom_puts(char *s);
extern void rom_printk(char const *fmt, ...);

#endif	/* _E2K_BOOT_IO_H_ */
