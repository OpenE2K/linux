/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include "pci.h"
#include <asm/types.h>
#include <asm/e2k_api.h>
#include <asm/head.h>
#include "boot_io.h"

#undef DEBUG_IO
#undef DebugIO
#define DEBUG_IO        0
#define DebugIO         if (DEBUG_IO) rom_printk

#undef DEBUG_IOH
#undef DebugIOH
#define DEBUG_IOH	0
#define DebugIOH	if (DEBUG_IOH) rom_printk

#define e2s_domain_pci_conf_base(domain) (E2S_PCICFG_AREA_PHYS_BASE + \
		E2S_PCICFG_AREA_SIZE * ((unsigned long) domain))
#define e8c_domain_pci_conf_base(domain) (E8C_PCICFG_AREA_PHYS_BASE + \
		E8C_PCICFG_AREA_SIZE * ((unsigned long) domain))
#define e1cp_domain_pci_conf_base(domain) (E1CP_PCICFG_AREA_PHYS_BASE)
#define e8c2_domain_pci_conf_base(domain) (E8C2_PCICFG_AREA_PHYS_BASE + \
		E8C2_PCICFG_AREA_SIZE * ((unsigned long) domain))
#define e12c_domain_pci_conf_base(domain) (E12C_PCICFG_AREA_PHYS_BASE + \
		E12C_PCICFG_AREA_SIZE * ((unsigned long) domain))
#define e16c_domain_pci_conf_base(domain) (E16C_PCICFG_AREA_PHYS_BASE + \
		E16C_PCICFG_AREA_SIZE * ((unsigned long) domain))
#define e2c3_domain_pci_conf_base(domain) (E2C3_PCICFG_AREA_PHYS_BASE + \
		E2C3_PCICFG_AREA_SIZE * ((unsigned long) domain))
#define e8v7_domain_pci_conf_base(domain) (E8V7_PCICFG_AREA_PHYS_BASE + \
		E8V7_PCICFG_AREA_SIZE * ((unsigned long) domain))

static inline unsigned long bios_get_domain_pci_conf_base(unsigned int domain)
{
	unsigned long conf_base;

#if	defined(CONFIG_E2S)
	conf_base = e2s_domain_pci_conf_base(domain);
#elif	defined(CONFIG_E8C)
	conf_base = e8c_domain_pci_conf_base(domain);
#elif	defined(CONFIG_E1CP)
	conf_base = e1cp_domain_pci_conf_base(domain);
#elif	defined(CONFIG_E8C2)
	conf_base = e8c2_domain_pci_conf_base(domain);
#elif	defined(CONFIG_E12C)
	conf_base = e12c_domain_pci_conf_base(domain);
#elif	defined(CONFIG_E16C)
	conf_base = e16c_domain_pci_conf_base(domain);
#elif	defined(CONFIG_E2C3)
	conf_base = e2c3_domain_pci_conf_base(domain);
#elif	defined(CONFIG_E8V7)
	conf_base = e8v7_domain_pci_conf_base(domain);
#else
	#error	"Invalid e2k machine type"
#endif /* CONFIG_E2S */
	return (conf_base);
}

unsigned char bios_conf_inb(int domain, unsigned char bus, unsigned long port)
{

	unsigned char byte;
	unsigned long conf_base;

	conf_base = bios_get_domain_pci_conf_base(domain);
	port = conf_base + port;
	byte = NATIVE_READ_MAS_B(port, MAS_IO_OPERATION);

	DebugIO("conf_inb(): value %x read from port %x\n",
		(int) byte, (int) port);

	return byte;
}

unsigned char bios_inb(unsigned short port)
{
	unsigned char byte;

	DebugIO("bios_inb entered.\n");

	byte = NATIVE_READ_MAS_B(PHYS_IO_BASE + port, MAS_IO_OPERATION);

	DebugIO("value %x read from port %x\n", (int) byte, (int) port);

	DebugIO("bios_inb exited.\n");

	return byte;
}

void bios_conf_outb(int domain, unsigned char bus, unsigned char byte,
			unsigned long port)
{
	unsigned long conf_base;

	conf_base = bios_get_domain_pci_conf_base(domain);
	port = conf_base + port;
	DebugIO("conf_outb(): port = %x\n", (int) port);
	NATIVE_WRITE_MAS_B(port, byte, MAS_IO_OPERATION);

	DebugIO("conf_outb exited.\n");
}
void bios_ioh_e2s_outb(int domain, unsigned char bus, unsigned char byte,
				unsigned long port)
{
	unsigned long addr;

	addr = IOHUB_SCRB_DOMAIN_START(domain);
	addr += port;
	NATIVE_WRITE_MAS_B(addr, byte, MAS_IO_OPERATION);
	DebugIOH("ioh_e2s_outb write 0x%x to domain %d bus 0x%x, port = 0x%x.\n",
		byte, domain, bus, addr);
}

u8 bios_ioh_e2s_inb(int domain, unsigned char bus, unsigned long port)
{
	unsigned long addr;
	u8 byte;

	addr = IOHUB_SCRB_DOMAIN_START(domain);
	addr += port;
	byte = NATIVE_READ_MAS_B(addr, MAS_IO_OPERATION);
	DebugIOH("bios_ioh_e2s_inb() read 0x%x from domain %d bus 0x%x, "
		"port = 0x%x\n",
		byte, domain, bus, addr);
	return (byte);
}

void bios_outb(unsigned char byte, unsigned short port)
{
	DebugIO("outb entered.\n");

	NATIVE_WRITE_MAS_B(PHYS_IO_BASE + port, byte, MAS_IO_OPERATION);

	DebugIO("outb exited.\n");
}

void bios_conf_outw(int domain, unsigned char bus, u16 halfword,
			unsigned long port)
{
	unsigned long conf_base;

	conf_base = bios_get_domain_pci_conf_base(domain);
	port = conf_base + port;
	DebugIO("conf_outw(): port = %x\n", (int) port);
	NATIVE_WRITE_MAS_H(port, halfword, MAS_IO_OPERATION);

	DebugIO("conf_outw exited.\n");
}

void bios_ioh_e2s_outw(int domain, unsigned char bus, u16 halfword,
			unsigned long port)
{
	unsigned long addr;

	addr = IOHUB_SCRB_DOMAIN_START(domain);
	addr += port;
	NATIVE_WRITE_MAS_H(addr, halfword, MAS_IO_OPERATION);
	DebugIOH("ioh_e2s_outw write 0x%x to domain %d bus 0x%x, port = 0x%x\n",
		halfword, domain, bus, addr);
}

u16 bios_ioh_e2s_inw(int domain, unsigned char bus, unsigned long port)
{
	unsigned long addr;
	u16 halfword;

	addr = IOHUB_SCRB_DOMAIN_START(domain);
	addr += port;
	halfword = NATIVE_READ_MAS_B(addr, MAS_IO_OPERATION);
	DebugIOH("bios_ioh_e2s_inw() read 0x%x from domain %d bus 0x%x, "
		"port = 0x%x\n",
		halfword, domain, bus, addr);
	return (halfword);
}

void bios_outw(u16 halfword, unsigned short port)
{
	DebugIO("outw entered.\n");

	NATIVE_WRITE_MAS_H(PHYS_IO_BASE + port, halfword, MAS_IO_OPERATION);

	DebugIO("outw exited.\n");
}

u16 bios_conf_inw(int domain, unsigned char bus, unsigned long port)
{
	u16 hword;
	unsigned long conf_base;

	conf_base = bios_get_domain_pci_conf_base(domain);
	port = conf_base + port;
	hword = NATIVE_READ_MAS_H(port, MAS_IO_OPERATION);
	DebugIO("conf_inw(): value %x read from port %x\n",hword, (int)port);
	DebugIO("conf_inw exited.\n");

	return hword;
}

u16 bios_inw(unsigned short port)
{
	u16 hword;

	DebugIO("inw entered.\n");

	hword = NATIVE_READ_MAS_H(PHYS_IO_BASE + port, MAS_IO_OPERATION);

	DebugIO("inw exited.\n");

	return hword;
}

/*
 * 'unsigned long' for I/O means 'u32', because IN/OUT ops are IA32-specific
 */
void bios_conf_outl(int domain, unsigned char bus, u32 word, unsigned long port)
{
	unsigned long conf_base;

	conf_base = bios_get_domain_pci_conf_base(domain);
	port = conf_base + port;
	NATIVE_WRITE_MAS_W(port, word, MAS_IO_OPERATION);
	DebugIO("conf_outl exited.\n");
}

u32 bios_conf_inl(int domain, unsigned char bus, unsigned long port)
{
	u32 word;
	unsigned long conf_base;

	conf_base = bios_get_domain_pci_conf_base(domain);
	port = conf_base + port;
	word = NATIVE_READ_MAS_W(port, MAS_IO_OPERATION);
	DebugIO("conf_inl(): value %x read from port %x\n",
		(int) word, (int) port);
	DebugIO("conf_inl exited.\n");
	return word;
}

void bios_ioh_e2s_outl(int domain, unsigned char bus, u32 word,
			unsigned long port)
{
	unsigned long addr;

	addr = IOHUB_SCRB_DOMAIN_START(domain);
	addr += port;
	NATIVE_WRITE_MAS_W(addr, word, MAS_IO_OPERATION);
	DebugIOH("ioh_e2s_outl write 0x%x to domain %d bus 0x%x, port = 0x%x\n",
		word, domain, bus, addr);
}

u32 bios_ioh_e2s_inl(int domain, unsigned char bus, unsigned long port)
{
	unsigned long addr;
	u32 word;

	addr = IOHUB_SCRB_DOMAIN_START(domain);
	addr += port;
	word = NATIVE_READ_MAS_W(addr, MAS_IO_OPERATION);
	DebugIOH("bios_ioh_e2s_inl read 0x%x from domain %d bus 0x%x, "
		"port = 0x%x\n",
		word, domain, bus, addr);
	return (word);
}

void bios_outl(u32 word, unsigned short port)
{
	DebugIO("outl entered.\n");

	NATIVE_WRITE_MAS_W(PHYS_IO_BASE + port, word, MAS_IO_OPERATION);

	DebugIO("outl exited.\n");
}

u32 bios_inl(unsigned short port)
{
	u32 word;
	DebugIO("inl entered.\n");
	word = NATIVE_READ_MAS_W(PHYS_IO_BASE + port, MAS_IO_OPERATION);
	DebugIO("inl(): value %x read from port %x\n", (int) word, (int) port);
	DebugIO("inl exited.\n");

	return word;
}

void bios_outll(unsigned long data, unsigned short port)
{
	DebugIO("outb entered.\n");

	NATIVE_WRITE_MAS_D(PHYS_IO_BASE + port, data, MAS_IO_OPERATION);

	DebugIO("outb exited.\n");
}

unsigned long bios_inll(unsigned short port)
{
	unsigned long dword;
	DebugIO("inl entered.\n");
	dword = NATIVE_READ_MAS_D(PHYS_IO_BASE + port, MAS_IO_OPERATION);
	DebugIO("inl(): value %lx read from port %x\n",
		(unsigned long)dword, (int)port);
	DebugIO("inl exited.\n");

	return dword;
}
