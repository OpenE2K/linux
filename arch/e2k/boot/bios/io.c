#include "pci.h"
#include <asm/types.h>
#include <asm/e2k_api.h>
#include <asm/e2k.h>
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

static inline unsigned long get_domain_pci_conf_base(unsigned int domain)
{
	unsigned long conf_base;

#ifdef	CONFIG_E3S
	conf_base =e3s_domain_pci_conf_base(domain);
#elif	defined(CONFIG_ES2)
	conf_base = es2_domain_pci_conf_base(domain);
#elif	defined(CONFIG_E2S)
	conf_base = e2s_domain_pci_conf_base(domain);
#elif	defined(CONFIG_E8C)
	conf_base = e8c_domain_pci_conf_base(domain);
#elif	defined(CONFIG_E1CP)
	conf_base = e1cp_domain_pci_conf_base(domain);
#elif	defined(CONFIG_E8C2)
	conf_base = e8c2_domain_pci_conf_base(domain);
#else
	#error	"Invalid e2k machine type"
#endif /* CONFIG_E3S */
	return (conf_base);
}

unsigned char boot_conf_inb(int domain, unsigned char bus, unsigned long port)
{

	unsigned char byte;
	unsigned long conf_base;

	conf_base = get_domain_pci_conf_base(domain);
	port = conf_base + port;
	byte = E2K_READ_MAS_B(port, MAS_IOADDR);

	DebugIO("conf_inb(): value %x read from port %x\n",
		(int) byte, (int) port);

	return byte;
}
#endif

unsigned char inb(unsigned long port)
{
	unsigned char byte;

	DebugIO("inb entered.\n");

	byte = E2K_READ_MAS_B(PHYS_X86_IO_BASE + port, MAS_IOADDR);

	DebugIO("value %x read from port %x\n", (int) byte, (int) port);

	DebugIO("inb exited.\n");

	return byte;
}

unsigned char inb_p(unsigned long port)
{

	unsigned char byte;

	DebugIO("inb_p entered.\n");

	byte = E2K_READ_MAS_B(PHYS_X86_IO_BASE + port, MAS_IOADDR);

	DebugIO("inb_p exited.\n");

	return byte;
}

void outb_p(unsigned char byte, unsigned long port)
{
	DebugIO("outb_p entered.\n");

	E2K_WRITE_MAS_B(PHYS_X86_IO_BASE + port, byte, MAS_IOADDR);

	DebugIO("outb_p exited.\n");
}

#ifdef CONFIG_E2K_SIC
void boot_conf_outb(int domain, unsigned char bus, unsigned char byte,
			unsigned long port)
{
	unsigned long conf_base;

	conf_base = get_domain_pci_conf_base(domain);
	port = conf_base + port;
	DebugIO("conf_outb(): port = %x\n", (int) port);
	E2K_WRITE_MAS_B(port, byte, MAS_IOADDR);

	DebugIO("conf_outb exited.\n");
}
void boot_ioh_e3s_outb(int domain, unsigned char bus, unsigned char byte,
				unsigned long port)
{
	unsigned long addr;

	addr = IOHUB_SCRB_DOMAIN_START(domain);
	addr += port;
	E2K_WRITE_MAS_B(addr, byte, MAS_IOADDR);
	DebugIOH("ioh_e3s_outb write 0x%x to domain %d bus 0x%x, port = 0x%x.\n",
		byte, domain, bus, addr);
}

u8 boot_ioh_e3s_inb(int domain, unsigned char bus, unsigned long port)
{
	unsigned long addr;
	u8 byte;

	addr = IOHUB_SCRB_DOMAIN_START(domain);
	addr += port;
	byte = E2K_READ_MAS_B(addr, MAS_IOADDR);
	DebugIOH("boot_ioh_e3s_inb() read 0x%x from domain %d bus 0x%x, "
		"port = 0x%x\n",
		byte, domain, bus, addr);
	return (byte);
}
#endif

void outb(unsigned char byte, unsigned long port)
{
	DebugIO("outb entered.\n");

	E2K_WRITE_MAS_B(PHYS_X86_IO_BASE + port, byte, MAS_IOADDR);

	DebugIO("outb exited.\n");
}

#ifdef CONFIG_E2K_SIC
void boot_conf_outw(int domain, unsigned char bus, u16 halfword,
			unsigned long port)
{
	unsigned long conf_base;

	conf_base = get_domain_pci_conf_base(domain);
	port = conf_base + port;
	DebugIO("conf_outw(): port = %x\n", (int) port);
	E2K_WRITE_MAS_H(port, halfword, MAS_IOADDR);

	DebugIO("conf_outw exited.\n");
}

void boot_ioh_e3s_outw(int domain, unsigned char bus, u16 halfword,
			unsigned long port)
{
	unsigned long addr;

	addr = IOHUB_SCRB_DOMAIN_START(domain);
	addr += port;
	E2K_WRITE_MAS_H(addr, halfword, MAS_IOADDR);
	DebugIOH("ioh_e3s_outw write 0x%x to domain %d bus 0x%x, port = 0x%x\n",
		halfword, domain, bus, addr);
}

u16 boot_ioh_e3s_inw(int domain, unsigned char bus, unsigned long port)
{
	unsigned long addr;
	u16 halfword;

	addr = IOHUB_SCRB_DOMAIN_START(domain);
	addr += port;
	halfword = E2K_READ_MAS_B(addr, MAS_IOADDR);
	DebugIOH("boot_ioh_e3s_inw() read 0x%x from domain %d bus 0x%x, "
		"port = 0x%x\n",
		halfword, domain, bus, addr);
	return (halfword);
}
#endif

void outw(u16 halfword, unsigned long port)
{
	DebugIO("outw entered.\n");

        E2K_WRITE_MAS_H(PHYS_X86_IO_BASE + port, halfword, MAS_IOADDR);

	DebugIO("outw exited.\n");
}

void outw_p(u16 halfword, unsigned long port)
{
	DebugIO("outw_p entered.\n");

        E2K_WRITE_MAS_H(PHYS_X86_IO_BASE + port, halfword, MAS_IOADDR);

	DebugIO("outw_p exited.\n");
}

#ifdef CONFIG_E2K_SIC
u16 boot_conf_inw(int domain, unsigned char bus, unsigned long port)
{
	u16 hword;
	unsigned long conf_base;

	conf_base = get_domain_pci_conf_base(domain);
	port = conf_base + port;
	hword = E2K_READ_MAS_H(port, MAS_IOADDR);
	DebugIO("conf_inw(): value %x read from port %x\n",hword, (int)port);
	DebugIO("conf_inw exited.\n");

	return hword;
}
#endif

u16 inw(unsigned long port)
{
	u16 hword;

	DebugIO("inw entered.\n");

	hword = E2K_READ_MAS_H(PHYS_X86_IO_BASE + port, MAS_IOADDR);

	DebugIO("inw exited.\n");

	return hword;
}

u16 inw_p(unsigned long port)
{
	u16 hword;

	DebugIO("inw_p entered.\n");

	hword = E2K_READ_MAS_H(PHYS_X86_IO_BASE + port, MAS_IOADDR);

	DebugIO("inw_p exited.\n");

	return hword;
}

/*
 * 'unsigned long' for I/O means 'u32', because IN/OUT ops are IA32-specific
 */
#ifdef CONFIG_E2K_SIC
void boot_conf_outl(int domain, unsigned char bus, u32 word, unsigned long port)
{
	unsigned long conf_base;

	conf_base = get_domain_pci_conf_base(domain);
	port = conf_base + port;
	E2K_WRITE_MAS_W(port, word, MAS_IOADDR);
	DebugIO("conf_outl exited.\n");
}

u32 boot_conf_inl(int domain, unsigned char bus, unsigned long port)
{
	u32 word;
	unsigned long conf_base;

	conf_base = get_domain_pci_conf_base(domain);
	port = conf_base + port;
	word = E2K_READ_MAS_W(port, MAS_IOADDR);
	DebugIO("conf_inl(): value %x read from port %x\n",
		(int) word, (int) port);
	DebugIO("conf_inl exited.\n");
	return word;
}

void boot_ioh_e3s_outl(int domain, unsigned char bus, u32 word,
			unsigned long port)
{
	unsigned long addr;

	addr = IOHUB_SCRB_DOMAIN_START(domain);
	addr += port;
	E2K_WRITE_MAS_W(addr, word, MAS_IOADDR);
	DebugIOH("ioh_e3s_outl write 0x%x to domain %d bus 0x%x, port = 0x%x\n",
		word, domain, bus, addr);
}

u32 boot_ioh_e3s_inl(int domain, unsigned char bus, unsigned long port)
{
	unsigned long addr;
	u32 word;

	addr = IOHUB_SCRB_DOMAIN_START(domain);
	addr += port;
	word = E2K_READ_MAS_W(addr, MAS_IOADDR);
	DebugIOH("boot_ioh_e3s_inl read 0x%x from domain %d bus 0x%x, "
		"port = 0x%x\n",
		word, domain, bus, addr);
	return (word);
}
#endif

void outl(u32 word, unsigned long port)
{
	DebugIO("outl entered.\n");

        E2K_WRITE_MAS_W(PHYS_X86_IO_BASE + port, word, MAS_IOADDR);

	DebugIO("outl exited.\n");
}

u32 inl(unsigned long port)
{
	u32 word;
	DebugIO("inl entered.\n");
	word = E2K_READ_MAS_W(PHYS_X86_IO_BASE + port, MAS_IOADDR);
	DebugIO("inl(): value %x read from port %x\n", (int) word, (int) port);
	DebugIO("inl exited.\n");

	return word;
}


extern inline void fast_outw_p(u16 halfword, unsigned long port)
{
	E2K_WRITE_MAS_H(PHYS_X86_IO_BASE + port, halfword, MAS_IOADDR);
}

void outsw (unsigned long port, const void *src, unsigned long count)
{
	u16 *hw_p = (u16 *)src;

	DebugIO("outsw entered.\n");

	DebugIO("outsw(): port=%lx src=%p count=%lx\n", port, src, count);

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

extern inline u16 fast_inw_p(unsigned long port)
{
	return E2K_READ_MAS_H(PHYS_X86_IO_BASE + port, MAS_IOADDR);
}

void insw (unsigned long port, void *dst, unsigned long count)
{
	u16 *hw_p = (u16 *)dst;

	DebugIO("insw entered.\n");

	DebugIO("insw(): port=%lx dst=%p count=%lx\n",port, dst, count);

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
 * of the inl() breaks things.
 *
 * The source code was taken from Alpha's lib/io.c
 */
void insl (unsigned long port, void *dst, unsigned long count)
{
	unsigned int l = 0, l2;

	if (!count)
		return;

	switch (((unsigned long) dst) & 0x3)
	{
	 case 0x00:			/* Buffer 32-bit aligned */
		while (count--)
		{
			*(unsigned int *) dst = inl(port);
			dst += 4;
		}
		break;

	/* Assuming little endian in cases 0x01 -- 0x03 ... */

	 case 0x02:			/* Buffer 16-bit aligned */
		--count;

		l = inl(port);
		*(unsigned short *) dst = l;
		dst += 2;

		while (count--)
		{
			l2 = inl(port);
			*(unsigned int *) dst = l >> 16 | l2 << 16;
			dst += 4;
			l = l2;
		}
		*(unsigned short *) dst = l >> 16;
		break;

	 case 0x01:			/* Buffer 8-bit aligned */
		--count;

		l = inl(port);
		*(unsigned char *) dst = l;
		dst += 1;
		*(unsigned short *) dst = l >> 8;
		dst += 2;
		while (count--)
		{
			l2 = inl(port);
			*(unsigned int *) dst = l >> 24 | l2 << 8;
			dst += 4;
			l = l2;
		}
		*(unsigned char *) dst = l >> 24;
		break;

	 case 0x03:			/* Buffer 8-bit aligned */
		--count;

		l = inl(port);
		*(unsigned char *) dst = l;
		dst += 1;
		while (count--)
		{
			l2 = inl(port);
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
void outsl (unsigned long port, const void *src, unsigned long count)
{
	unsigned int l = 0, l2;

	if (!count)
		return;

	switch (((unsigned long) src) & 0x3)
	{
	 case 0x00:			/* Buffer 32-bit aligned */
		while (count--)
		{
			outl(*(unsigned int *) src, port);
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
			outl (l >> 16 | l2 << 16, port);
			l = l2;
		}
		l2 = *(unsigned short *) src;
		outl (l >> 16 | l2 << 16, port);
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
			outl (l >> 8 | l2 << 24, port);
			l = l2;
		}
		l2 = *(unsigned char *) src;
		outl (l >> 8 | l2 << 24, port);
		break;

	 case 0x03:			/* Buffer 8-bit aligned */
		--count;

		l  = *(unsigned char *) src << 24;
		src += 1;
		while (count--)
		{
			l2 = *(unsigned int *) src;
			src += 4;
			outl (l >> 24 | l2 << 8, port);
			l = l2;
		}
		l2  = *(unsigned short *) src;
		src += 2;
		l2 |= *(unsigned char *) src << 16;
		outl (l >> 24 | l2 << 8, port);
		break;
	}
}

/*
 * Read COUNT 8-bit bytes from port PORT into memory starting at
 * SRC.
 *
 * The source code was taken from Alpha's lib/io.c
 */
void insb (unsigned long port, void *dst, unsigned long count)
{
	while (((unsigned long)dst) & 0x3) {
		if (!count)
			return;
		count--;
		*(unsigned char *) dst = inb(port);
		dst += 1;
	}

	while (count >= 4) {
		unsigned int w;
		count -= 4;
		w = inb(port);
		w |= inb(port) << 8;
		w |= inb(port) << 16;
		w |= inb(port) << 24;
		*(unsigned int *) dst = w;
		dst += 4;
	}

	while (count) {
		--count;
		*(unsigned char *) dst = inb(port);
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
void outsb(unsigned long port, const void * src, unsigned long count)
{
	while (count) {
		count--;
		outb(*(char *)src, port);
		src += 1;
	}
}
