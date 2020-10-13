
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/init.h>

#include <asm/mas.h>
#include <asm/io.h>
//#include <asm/page.h>
#include <asm/iolinkmask.h>
#include <asm/e2k_sic.h>

#include <asm/e2k_api.h>
#include <asm/e2k_debug.h>

#undef	DEBUG_IO_MODE
#undef	DebugIO
#define	DEBUG_IO_MODE		0	/* input/output functions */
#define DebugIO(...)		DebugPrint(DEBUG_IO_MODE ,##__VA_ARGS__)

#undef	DEBUG_CIO_MODE
#undef	DebugCIO
#define	DEBUG_CIO_MODE		0	/* configuration space  */
					/* input/output functions */
#define DebugCIO(...)		DebugPrint(DEBUG_CIO_MODE ,##__VA_ARGS__)

notrace void
boot_outb(u16 port, u8 byte)
{
	E2K_WRITE_MAS_B(BOOT_X86_IO_AREA_PHYS_BASE + port, byte, MAS_IOADDR);
}

notrace u8
boot_inb(u16 port)
{
	return (u8)E2K_READ_MAS_B(BOOT_X86_IO_AREA_PHYS_BASE + port,
								MAS_IOADDR);
}

notrace u32
boot_inl(u16 port)
{
	return (u32)E2K_READ_MAS_W(BOOT_X86_IO_AREA_PHYS_BASE + port,
								MAS_IOADDR);
}

asmlinkage int sys_ioperm(unsigned long from, unsigned long num, int turn_on)
{
	DebugIO("sys_ioperm entered.\n");
	DebugIO("sys_ioperm exited.\n");

	return 0;
}

void * __io_virt_debug(unsigned long x, const char *file, int line)
{
#if 0
	DebugIO("__io_virt_debug entered.\n");
	DebugIO("__io_virt_debug exited.\n");
#endif

	return (void *)x;
}

unsigned char inb(unsigned long port)
{
	unsigned char byte;

	DebugIO("inb entered.\n");

	byte = E2K_READ_MAS_B(X86_IO_AREA_PHYS_BASE + port, MAS_IOADDR);

	DebugIO("value %x read from port %x\n", (int) byte, (int) port);

	DebugIO("inb exited.\n");

	return byte;
}
EXPORT_SYMBOL(inb);

unsigned char inb_p(unsigned long port)
{
	unsigned char byte;

	DebugIO("inb_p entered.\n");

	byte = E2K_READ_MAS_B(X86_IO_AREA_PHYS_BASE + port, MAS_IOADDR);

	DebugIO("inb_p exited.\n");

	return byte;
}
EXPORT_SYMBOL(inb_p);

void outb(unsigned char byte, unsigned long port)
{
	DebugIO("outb entered.\n");

	E2K_WRITE_MAS_B(X86_IO_AREA_PHYS_BASE + port, byte, MAS_IOADDR);

	DebugIO("outb exited.\n");
}
EXPORT_SYMBOL(outb);

void outb_p(unsigned char byte, unsigned long port)
{
	DebugIO("outb_p entered.\n");

	E2K_WRITE_MAS_B(X86_IO_AREA_PHYS_BASE + port, byte, MAS_IOADDR);

	DebugIO("outb_p exited.\n");
}
EXPORT_SYMBOL(outb_p);

void outw(u16 halfword, unsigned long port)
{
	DebugIO("outw entered.\n");

        E2K_WRITE_MAS_H(X86_IO_AREA_PHYS_BASE + port, halfword, MAS_IOADDR);

	DebugIO("outw exited.\n");
}
EXPORT_SYMBOL(outw);

void outw_p(u16 halfword, unsigned long port)
{
	DebugIO("outw_p entered.\n");

        E2K_WRITE_MAS_H(X86_IO_AREA_PHYS_BASE + port, halfword, MAS_IOADDR);

	DebugIO("outw_p exited.\n");
}

u16 inw(unsigned long port)
{
	u16 hword;

	DebugIO("inw entered.\n");

	hword = E2K_READ_MAS_H(X86_IO_AREA_PHYS_BASE + port, MAS_IOADDR);

	DebugIO("inw exited.\n");

	return hword;
}
EXPORT_SYMBOL(inw);

u16 inw_p(unsigned long port)
{
	u16 hword;

	DebugIO("inw_p entered.\n");

	hword = E2K_READ_MAS_H(X86_IO_AREA_PHYS_BASE + port, MAS_IOADDR);

	DebugIO("inw_p exited.\n");

	return hword;
}

/*
 * 'unsigned long' for I/O means 'u32', because IN/OUT ops are IA32-specific
 */
void outl(u32 word, unsigned long port)
{
	DebugIO("outl entered.\n");

        E2K_WRITE_MAS_W(X86_IO_AREA_PHYS_BASE + port, word, MAS_IOADDR);

	DebugIO("outl exited.\n");
}
EXPORT_SYMBOL(outl);

void outl_p(u32 word, unsigned long port)
{
	DebugIO("outl_p entered.\n");

        E2K_WRITE_MAS_W(X86_IO_AREA_PHYS_BASE + port, word, MAS_IOADDR);

	DebugIO("outl_p exited.\n");
}


u32 inl(unsigned long port)
{
	u32 word;
	DebugIO("inl entered.\n");
	word = E2K_READ_MAS_W(X86_IO_AREA_PHYS_BASE + port, MAS_IOADDR);
	DebugIO("value %x read from port %x\n", (int) word, (int) port);
	DebugIO("inl exited.\n");

	return word;
}
EXPORT_SYMBOL(inl);

u32 inl_p(unsigned long port)
{
	u32 word;
	DebugIO("inl_p entered.\n");
	word = E2K_READ_MAS_W(X86_IO_AREA_PHYS_BASE + port, MAS_IOADDR);
	DebugIO("value %x read from port %x\n", word, (int) port);
	DebugIO("inl_p exited.\n");

	return word;
}


extern inline void fast_outw_p(u16 halfword, unsigned long port)
{
	E2K_WRITE_MAS_H(X86_IO_AREA_PHYS_BASE + port, halfword, MAS_IOADDR);
}

void outsw (unsigned long port, const void *src, unsigned long count)
{
	u16 *hw_p = (u16 *)src;

	DebugIO("outsw entered.\n");

	DebugIO("port=%lx src=%p count=%lx\n", port, src, count);

        if (((unsigned long)src) & 0x1) {
                panic("outsw: memory address is not short aligned");
        }
        if (!count)
                return;

	while (count--) {
		fast_outw_p(*hw_p++, port);
	}

	DebugIO("outsw exited.\n");
}
EXPORT_SYMBOL(outsw);

static inline u16 fast_inw_p(unsigned long port)
{
	return E2K_READ_MAS_H(X86_IO_AREA_PHYS_BASE + port, MAS_IOADDR);
}

void insw (unsigned long port, void *dst, unsigned long count)
{
	u16 *hw_p = (u16 *)dst;

	DebugIO("insw entered.\n");

	DebugIO("port=%lx dst=%p count=%lx\n",port, dst, count);

        if (((unsigned long)dst) & 0x1) {
                panic("insw: memory address is not short aligned");
        }
        if (!count)
                return;

	while (count--) {
		*hw_p++ = fast_inw_p(port);
	}

	DebugIO("insw exited.\n");
}
EXPORT_SYMBOL(insw);

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
EXPORT_SYMBOL(insl);

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
EXPORT_SYMBOL(outsl);

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
EXPORT_SYMBOL(insb);

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
EXPORT_SYMBOL(outsb);

/*
 * E3S/E2C+/E2C/E2S/E8C/E1C+ configuration area access
 */
 
static inline unsigned long get_domain_pci_conf_base(unsigned int domain)
{
	unsigned long conf_base;

	if (!HAS_MACHINE_L_SIC) {
		printk(KERN_ERR "get_domain_pci_conf_base() machine has not "
			"NBSR to calculate PCI CFG base\n");
		return (-1);
	}
	if (!iohub_online(domain)) {
		printk(KERN_ERR "get_domain_pci_conf_base() IOHUB domain "
			"# %d (node %d, link %d) is not online\n",
			domain, iohub_domain_to_node(domain),
			iohub_domain_to_link(domain));
		return (-1);
	}
	conf_base = domain_pci_conf_base(domain);
	if (conf_base == 0) {
		printk(KERN_ERR "get_domain_pci_conf_base() IOHUB domain "
			"# %d (node %d, link %d) PCI CFG base did not set\n",
			domain, iohub_domain_to_node(domain),
			iohub_domain_to_link(domain));
		return (-1);
	}
	return (conf_base);
}

void
conf_inb(unsigned int domain, unsigned int bus, unsigned long port, u8 *byte)
{
	unsigned long conf_base;

	conf_base = get_domain_pci_conf_base(domain);
	port = conf_base + port;
	*byte = E2K_READ_MAS_B(port, MAS_IOADDR);
	DebugCIO("value %x read from port %lx, domain #%d "
		"(node %d, IO link %d)\n",
		(u32) *byte, port, domain,
	iohub_domain_to_node(domain), iohub_domain_to_link(domain));
}

void
conf_inw(unsigned int domain, unsigned int bus, unsigned long port, u16 *hword)
{
	unsigned long conf_base;

	conf_base = get_domain_pci_conf_base(domain);
	port = conf_base + port;
	*hword = E2K_READ_MAS_H(port, MAS_IOADDR);
	DebugCIO("value %x read from port %lx, domain #%d "
		"(node %d, IO link %d)\n",
		(u32) *hword, port, domain,
		iohub_domain_to_node(domain), iohub_domain_to_link(domain));
}

void
conf_inl(unsigned int domain, unsigned int bus, unsigned long port, u32 *word)
{
	unsigned long conf_base;

	conf_base = get_domain_pci_conf_base(domain);
	port = conf_base + port;
	*word = E2K_READ_MAS_W(port, MAS_IOADDR);
	DebugCIO("value %x read from port %lx, domain #%d "
		"(node %d, IO link %d)\n",
		(u32) *word, port, domain,
		iohub_domain_to_node(domain), iohub_domain_to_link(domain));
}

void
conf_outb(unsigned int domain, unsigned int bus, unsigned long port, u8 byte)
{
	unsigned long conf_base;

	conf_base = get_domain_pci_conf_base(domain);
	port = conf_base + port;
	DebugCIO("value %x write to port %lx, domain #%d "
		"(node %d, IO link %d)\n",
		(u32) byte, port, domain,
		iohub_domain_to_node(domain), iohub_domain_to_link(domain));
	E2K_WRITE_MAS_B(port, byte, MAS_IOADDR);
}

void
conf_outw(unsigned int domain, unsigned int bus, unsigned long port, u16 hword)
{
	unsigned long conf_base;

	conf_base = get_domain_pci_conf_base(domain);
	port = conf_base + port;
	DebugCIO("value %x write to port %lx, domain #%d "
		"(node %d, IO link %d)\n",
		(u32) hword, port, domain,
		iohub_domain_to_node(domain), iohub_domain_to_link(domain));
	E2K_WRITE_MAS_H(port, hword, MAS_IOADDR);
}

void
conf_outl(unsigned int domain, unsigned int bus, unsigned long port, u32 word)
{
	unsigned long conf_base;

	conf_base = get_domain_pci_conf_base(domain);
	port = conf_base + port;
	DebugCIO("value %x write to port %lx, domain #%d "
		"(node %d, IO link %d)\n",
		(u32) word, port, domain,
		iohub_domain_to_node(domain), iohub_domain_to_link(domain));
	E2K_WRITE_MAS_W(port, word, MAS_IOADDR);
}
