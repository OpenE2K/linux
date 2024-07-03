#include "pci.h"
#include <asm/types.h>
#include <asm/e2k_api.h>
#include <asm/head.h>
#include "../boot_io.h"

#undef DEBUG_IO
#undef DebugIO
#define DEBUG_IO        0
#define DebugIO         if (DEBUG_IO) rom_printk

#undef DEBUG_IOH
#undef DebugIOH
#define DEBUG_IOH	0
#define DebugIOH	if (DEBUG_IOH) rom_printk

#ifdef CONFIG_E2K_SIC

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
#define e48c_domain_pci_conf_base(domain) (E48C_PCICFG_AREA_PHYS_BASE + \
		E48C_PCICFG_AREA_SIZE * ((unsigned long) domain))
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
#elif	defined(CONFIG_E48C)
	conf_base = e48c_domain_pci_conf_base(domain);
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
	byte = NATIVE_READ_MAS_B(port, MAS_IOADDR);

	DebugIO("conf_inb(): value %x read from port %x\n",
		(int) byte, (int) port);

	return byte;
}
#endif

unsigned char bios_inb(unsigned short port)
{
	unsigned char byte;

	DebugIO("bios_inb entered.\n");

	byte = NATIVE_READ_MAS_B(PHYS_IO_BASE + port, MAS_IOADDR);

	DebugIO("value %x read from port %x\n", (int) byte, (int) port);

	DebugIO("bios_inb exited.\n");

	return byte;
}

unsigned char bios_inb_p(unsigned long port)
{

	unsigned char byte;

	DebugIO("bios_inb_p entered.\n");

	byte = NATIVE_READ_MAS_B(PHYS_IO_BASE + port, MAS_IOADDR);

	DebugIO("bios_inb_p exited.\n");

	return byte;
}

void bios_outb_p(unsigned char byte, unsigned long port)
{
	DebugIO("bios_outb_p entered.\n");

	NATIVE_WRITE_MAS_B(PHYS_IO_BASE + port, byte, MAS_IOADDR);

	DebugIO("bios_outb_p exited.\n");
}

#ifdef CONFIG_E2K_SIC
void bios_conf_outb(int domain, unsigned char bus, unsigned char byte,
			unsigned long port)
{
	unsigned long conf_base;

	conf_base = bios_get_domain_pci_conf_base(domain);
	port = conf_base + port;
	DebugIO("conf_outb(): port = %x\n", (int) port);
	NATIVE_WRITE_MAS_B(port, byte, MAS_IOADDR);

	DebugIO("conf_outb exited.\n");
}
void bios_ioh_e2s_outb(int domain, unsigned char bus, unsigned char byte,
				unsigned long port)
{
	unsigned long addr;

	addr = IOHUB_SCRB_DOMAIN_START(domain);
	addr += port;
	NATIVE_WRITE_MAS_B(addr, byte, MAS_IOADDR);
	DebugIOH("ioh_e2s_outb write 0x%x to domain %d bus 0x%x, port = 0x%x.\n",
		byte, domain, bus, addr);
}

u8 bios_ioh_e2s_inb(int domain, unsigned char bus, unsigned long port)
{
	unsigned long addr;
	u8 byte;

	addr = IOHUB_SCRB_DOMAIN_START(domain);
	addr += port;
	byte = NATIVE_READ_MAS_B(addr, MAS_IOADDR);
	DebugIOH("bios_ioh_e2s_inb() read 0x%x from domain %d bus 0x%x, "
		"port = 0x%x\n",
		byte, domain, bus, addr);
	return (byte);
}
#endif

void bios_outb(unsigned char byte, unsigned short port)
{
	DebugIO("outb entered.\n");

	NATIVE_WRITE_MAS_B(PHYS_IO_BASE + port, byte, MAS_IOADDR);

	DebugIO("outb exited.\n");
}

#ifdef CONFIG_E2K_SIC
void bios_conf_outw(int domain, unsigned char bus, u16 halfword,
			unsigned long port)
{
	unsigned long conf_base;

	conf_base = bios_get_domain_pci_conf_base(domain);
	port = conf_base + port;
	DebugIO("conf_outw(): port = %x\n", (int) port);
	NATIVE_WRITE_MAS_H(port, halfword, MAS_IOADDR);

	DebugIO("conf_outw exited.\n");
}

void bios_ioh_e2s_outw(int domain, unsigned char bus, u16 halfword,
			unsigned long port)
{
	unsigned long addr;

	addr = IOHUB_SCRB_DOMAIN_START(domain);
	addr += port;
	NATIVE_WRITE_MAS_H(addr, halfword, MAS_IOADDR);
	DebugIOH("ioh_e2s_outw write 0x%x to domain %d bus 0x%x, port = 0x%x\n",
		halfword, domain, bus, addr);
}

u16 bios_ioh_e2s_inw(int domain, unsigned char bus, unsigned long port)
{
	unsigned long addr;
	u16 halfword;

	addr = IOHUB_SCRB_DOMAIN_START(domain);
	addr += port;
	halfword = NATIVE_READ_MAS_B(addr, MAS_IOADDR);
	DebugIOH("bios_ioh_e2s_inw() read 0x%x from domain %d bus 0x%x, "
		"port = 0x%x\n",
		halfword, domain, bus, addr);
	return (halfword);
}
#endif

void bios_outw(u16 halfword, unsigned short port)
{
	DebugIO("outw entered.\n");

	NATIVE_WRITE_MAS_H(PHYS_IO_BASE + port, halfword, MAS_IOADDR);

	DebugIO("outw exited.\n");
}

void bios_outw_p(u16 halfword, unsigned long port)
{
	DebugIO("outw_p entered.\n");

	NATIVE_WRITE_MAS_H(PHYS_IO_BASE + port, halfword, MAS_IOADDR);

	DebugIO("outw_p exited.\n");
}

#ifdef CONFIG_E2K_SIC
u16 bios_conf_inw(int domain, unsigned char bus, unsigned long port)
{
	u16 hword;
	unsigned long conf_base;

	conf_base = bios_get_domain_pci_conf_base(domain);
	port = conf_base + port;
	hword = NATIVE_READ_MAS_H(port, MAS_IOADDR);
	DebugIO("conf_inw(): value %x read from port %x\n",hword, (int)port);
	DebugIO("conf_inw exited.\n");

	return hword;
}
#endif

u16 bios_inw(unsigned short port)
{
	u16 hword;

	DebugIO("inw entered.\n");

	hword = NATIVE_READ_MAS_H(PHYS_IO_BASE + port, MAS_IOADDR);

	DebugIO("inw exited.\n");

	return hword;
}

u16 bios_inw_p(unsigned long port)
{
	u16 hword;

	DebugIO("inw_p entered.\n");

	hword = NATIVE_READ_MAS_H(PHYS_IO_BASE + port, MAS_IOADDR);

	DebugIO("inw_p exited.\n");

	return hword;
}

/*
 * 'unsigned long' for I/O means 'u32', because IN/OUT ops are IA32-specific
 */
#ifdef CONFIG_E2K_SIC
void bios_conf_outl(int domain, unsigned char bus, u32 word, unsigned long port)
{
	unsigned long conf_base;

	conf_base = bios_get_domain_pci_conf_base(domain);
	port = conf_base + port;
	NATIVE_WRITE_MAS_W(port, word, MAS_IOADDR);
	DebugIO("conf_outl exited.\n");
}

u32 bios_conf_inl(int domain, unsigned char bus, unsigned long port)
{
	u32 word;
	unsigned long conf_base;

	conf_base = bios_get_domain_pci_conf_base(domain);
	port = conf_base + port;
	word = NATIVE_READ_MAS_W(port, MAS_IOADDR);
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
	NATIVE_WRITE_MAS_W(addr, word, MAS_IOADDR);
	DebugIOH("ioh_e2s_outl write 0x%x to domain %d bus 0x%x, port = 0x%x\n",
		word, domain, bus, addr);
}

u32 bios_ioh_e2s_inl(int domain, unsigned char bus, unsigned long port)
{
	unsigned long addr;
	u32 word;

	addr = IOHUB_SCRB_DOMAIN_START(domain);
	addr += port;
	word = NATIVE_READ_MAS_W(addr, MAS_IOADDR);
	DebugIOH("bios_ioh_e2s_inl read 0x%x from domain %d bus 0x%x, "
		"port = 0x%x\n",
		word, domain, bus, addr);
	return (word);
}
#endif

void bios_outl(u32 word, unsigned short port)
{
	DebugIO("outl entered.\n");

	NATIVE_WRITE_MAS_W(PHYS_IO_BASE + port, word, MAS_IOADDR);

	DebugIO("outl exited.\n");
}

u32 bios_inl(unsigned short port)
{
	u32 word;
	DebugIO("inl entered.\n");
	word = NATIVE_READ_MAS_W(PHYS_IO_BASE + port, MAS_IOADDR);
	DebugIO("inl(): value %x read from port %x\n", (int) word, (int) port);
	DebugIO("inl exited.\n");

	return word;
}

void bios_outll(unsigned long data, unsigned short port)
{
	DebugIO("outb entered.\n");

	NATIVE_WRITE_MAS_D(PHYS_IO_BASE + port, data, MAS_IOADDR);

	DebugIO("outb exited.\n");
}

unsigned long bios_inll(unsigned short port)
{
	unsigned long dword;
	DebugIO("inl entered.\n");
	dword = NATIVE_READ_MAS_D(PHYS_IO_BASE + port, MAS_IOADDR);
	DebugIO("inl(): value %lx read from port %x\n",
		(unsigned long)dword, (int)port);
	DebugIO("inl exited.\n");

	return dword;
}

static inline void fast_outw_p(u16 halfword, unsigned long port)
{
	NATIVE_WRITE_MAS_H(PHYS_IO_BASE + port, halfword, MAS_IOADDR);
}

void bios_outsw(unsigned long port, const void *src, unsigned long count)
{
	u16 *hw_p = (u16 *)src;

	DebugIO("outsw entered.\n");

	DebugIO("outsw(): port=%lx src=%px count=%lx\n", port, src, count);

        if (((unsigned long)src) & 0x1) {
                rom_printk("outsw: memory address is not short aligned");
        }
        if (!count)
                return;

	while (count--) {
		fast_outw_p(*hw_p++, port);
	}

	DebugIO("outsw exited.\n");
}

static inline u16 fast_inw_p(unsigned long port)
{
	return NATIVE_READ_MAS_H(PHYS_IO_BASE + port, MAS_IOADDR);
}

void bios_insw(unsigned long port, void *dst, unsigned long count)
{
	u16 *hw_p = (u16 *)dst;

	DebugIO("insw entered.\n");

	DebugIO("insw(): port=%lx dst=%px count=%lx\n",port, dst, count);

        if (((unsigned long)dst) & 0x1) {
                rom_printk("insw: memory address is not short aligned");
        }
        if (!count)
                return;

	while (count--) {
		*hw_p++ = fast_inw_p(port);
	}

	DebugIO("insw exited.\n");
}

/*
 * Read COUNT 32-bit words from port PORT into memory starting at
 * SRC. Now works with any alignment in SRC. Performance is important,
 * but the interfaces seems to be slow: just using the inlined version
 * of the bios_inl() breaks things.
 *
 * The source code was taken from Alpha's lib/io.c
 */
void bios_insl(unsigned long port, void *dst, unsigned long count)
{
	unsigned int l = 0, l2;

	if (!count)
		return;

	switch (((unsigned long) dst) & 0x3)
	{
	 case 0x00:			/* Buffer 32-bit aligned */
		while (count--)
		{
			*(unsigned int *) dst = bios_inl(port);
			dst += 4;
		}
		break;

	/* Assuming little endian in cases 0x01 -- 0x03 ... */

	 case 0x02:			/* Buffer 16-bit aligned */
		--count;

		l = bios_inl(port);
		*(unsigned short *) dst = l;
		dst += 2;

		while (count--)
		{
			l2 = bios_inl(port);
			*(unsigned int *) dst = l >> 16 | l2 << 16;
			dst += 4;
			l = l2;
		}
		*(unsigned short *) dst = l >> 16;
		break;

	 case 0x01:			/* Buffer 8-bit aligned */
		--count;

		l = bios_inl(port);
		*(unsigned char *) dst = l;
		dst += 1;
		*(unsigned short *) dst = l >> 8;
		dst += 2;
		while (count--)
		{
			l2 = bios_inl(port);
			*(unsigned int *) dst = l >> 24 | l2 << 8;
			dst += 4;
			l = l2;
		}
		*(unsigned char *) dst = l >> 24;
		break;

	 case 0x03:			/* Buffer 8-bit aligned */
		--count;

		l = bios_inl(port);
		*(unsigned char *) dst = l;
		dst += 1;
		while (count--)
		{
			l2 = bios_inl(port);
			*(unsigned int *) dst = l << 24 | l2 >> 8;
			dst += 4;
			l = l2;
		}
		*(unsigned short *) dst = l >> 8;
		dst += 2;
		*(unsigned char *) dst = l >> 24;
		break;
	}
}

/*
 * Like insl but in the opposite direction.  This is used by the IDE
 * driver to write disk sectors.  Works with any alignment in SRC.
 *  Performance is important, but the interfaces seems to be slow:
 * just using the inlined version of the outl() breaks things.
 *
 * The source code was taken from Alpha's lib/io.c
 */
void bios_outsl(unsigned long port, const void *src, unsigned long count)
{
	unsigned int l = 0, l2;

	if (!count)
		return;

	switch (((unsigned long) src) & 0x3)
	{
	 case 0x00:			/* Buffer 32-bit aligned */
		while (count--)
		{
			bios_outl(*(unsigned int *) src, port);
			src += 4;
		}
		break;

	 case 0x02:			/* Buffer 16-bit aligned */
		--count;

		l = *(unsigned short *) src << 16;
		src += 2;

		while (count--)
		{
			l2 = *(unsigned int *) src;
			src += 4;
			bios_outl(l >> 16 | l2 << 16, port);
			l = l2;
		}
		l2 = *(unsigned short *) src;
		bios_outl(l >> 16 | l2 << 16, port);
		break;

	 case 0x01:			/* Buffer 8-bit aligned */
		--count;

		l  = *(unsigned char *) src << 8;
		src += 1;
		l |= *(unsigned short *) src << 16;
		src += 2;
		while (count--)
		{
			l2 = *(unsigned int *) src;
			src += 4;
			bios_outl(l >> 8 | l2 << 24, port);
			l = l2;
		}
		l2 = *(unsigned char *) src;
		bios_outl(l >> 8 | l2 << 24, port);
		break;

	 case 0x03:			/* Buffer 8-bit aligned */
		--count;

		l  = *(unsigned char *) src << 24;
		src += 1;
		while (count--)
		{
			l2 = *(unsigned int *) src;
			src += 4;
			bios_outl(l >> 24 | l2 << 8, port);
			l = l2;
		}
		l2  = *(unsigned short *) src;
		src += 2;
		l2 |= *(unsigned char *) src << 16;
		bios_outl(l >> 24 | l2 << 8, port);
		break;
	}
}

/*
 * Read COUNT 8-bit bytes from port PORT into memory starting at
 * SRC.
 *
 * The source code was taken from Alpha's lib/io.c
 */
void bios_insb(unsigned long port, void *dst, unsigned long count)
{
	while (((unsigned long)dst) & 0x3) {
		if (!count)
			return;
		count--;
		*(unsigned char *) dst = bios_inb(port);
		dst += 1;
	}

	while (count >= 4) {
		unsigned int w;
		count -= 4;
		w = bios_inb(port);
		w |= bios_inb(port) << 8;
		w |= bios_inb(port) << 16;
		w |= bios_inb(port) << 24;
		*(unsigned int *) dst = w;
		dst += 4;
	}

	while (count) {
		--count;
		*(unsigned char *) dst = bios_inb(port);
		dst += 1;
	}
}

/*
 * Like insb but in the opposite direction.
 * Don't worry as much about doing aligned memory transfers:
 * doing byte reads the "slow" way isn't nearly as slow as
 * doing byte writes the slow way (no r-m-w cycle).
 *
 * The source code was taken from Alpha's lib/io.c
 */
void bios_outsb(unsigned long port, const void *src, unsigned long count)
{
	while (count) {
		count--;
		bios_outb(*(char *)src, port);
		src += 1;
	}
}
