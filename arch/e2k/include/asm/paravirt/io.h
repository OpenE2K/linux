
#ifndef	_E2K_ASM_PARAVIRT_IO_H_
#define	_E2K_ASM_PARAVIRT_IO_H_

#include <linux/types.h>
#include <asm/paravirt/pv_ops.h>


static inline u8 boot_pv_readb(void __iomem *addr)
{
	return BOOT_PARAVIRT_IO_READ(boot_readb, addr);
}
static inline u16 boot_pv_readw(void __iomem *addr)
{
	return BOOT_PARAVIRT_IO_READ(boot_readw, addr);
}
static inline u32 boot_pv_readl(void __iomem *addr)
{
	return BOOT_PARAVIRT_IO_READ(boot_readl, addr);
}
static inline u64 boot_pv_readll(void __iomem *addr)
{
	return BOOT_PARAVIRT_IO_READ(boot_readll, addr);
}
static inline void boot_pv_writeb(u8 b, void __iomem *addr)
{
	BOOT_PARAVIRT_IO_WRITE(boot_writeb, b, addr);
}
static inline void boot_pv_writew(u16 w, void __iomem *addr)
{
	BOOT_PARAVIRT_IO_WRITE(boot_writew, w, addr);
}
static inline void boot_pv_writel(u32 l, void __iomem *addr)
{
	BOOT_PARAVIRT_IO_WRITE(boot_writel, l, addr);
}
static inline void boot_pv_writell(u64 q, void __iomem *addr)
{
	BOOT_PARAVIRT_IO_WRITE(boot_writell, q, addr);
}

static inline u8 pv_readb(void __iomem *addr)
{
	return pv_io_ops.readb(addr);
}
static inline u16 pv_readw(void __iomem *addr)
{
	return pv_io_ops.readw(addr);
}
static inline u32 pv_readl(void __iomem *addr)
{
	return pv_io_ops.readl(addr);
}
static inline u64 pv_readll(void __iomem *addr)
{
	return pv_io_ops.readll(addr);
}
static inline void pv_writeb(u8 b, void __iomem *addr)
{
	pv_io_ops.writeb(b, addr);
}
static inline void pv_writew(u16 w, void __iomem *addr)
{
	pv_io_ops.writew(w, addr);
}
static inline void pv_writel(u32 l, void __iomem *addr)
{
	pv_io_ops.writel(l, addr);
}
static inline void pv_writeq(u64 q, void __iomem *addr)
{
	pv_io_ops.writell(q, addr);
}

static inline u8 pv_inb(unsigned long port)
{
	return pv_io_ops.inb(port);
}
static inline void pv_outb(unsigned char byte, unsigned long port)
{
	pv_io_ops.outb(byte, port);
}
static inline void pv_outw(u16 halfword, unsigned long port)
{
	pv_io_ops.outw(halfword, port);
}
static inline u16 pv_inw(unsigned long port)
{
	return pv_io_ops.inw(port);
}
static inline void pv_outl(u32 word, unsigned long port)
{
	pv_io_ops.outl(word, port);
}
static inline u32 pv_inl(unsigned long port)
{
	return pv_io_ops.inl(port);
}

static inline void pv_outsb(unsigned long port, const void *src, unsigned long count)
{
	pv_io_ops.outsb(port, src, count);
}
static inline void pv_outsw(unsigned long port, const void *src, unsigned long count)
{
	pv_io_ops.outsw(port, src, count);
}
static inline void pv_outsl(unsigned long port, const void *src, unsigned long count)
{
	pv_io_ops.outsl(port, src, count);
}
static inline void pv_insb(unsigned long port, void *dst, unsigned long count)
{
	pv_io_ops.insb(port, dst, count);
}
static inline void pv_insw(unsigned long port, void *dst, unsigned long count)
{
	pv_io_ops.insw(port, dst, count);
}
static inline void pv_insl(unsigned long port, void *dst, unsigned long count)
{
	pv_io_ops.insl(port, dst, count);
}

static inline void
pv_conf_inb(unsigned int domain, unsigned int bus, unsigned long port, u8 *byte)
{
	pv_io_ops.conf_inb(domain, bus, port, byte);
}
static inline void
pv_conf_inw(unsigned int domain, unsigned int bus, unsigned long port,
		u16 *hword)
{
	pv_io_ops.conf_inw(domain, bus, port, hword);
}
static inline void
pv_conf_inl(unsigned int domain, unsigned int bus, unsigned long port,
		u32 *word)
{
	pv_io_ops.conf_inl(domain, bus, port, word);
}
static inline void
pv_conf_outb(unsigned int domain, unsigned int bus, unsigned long port,
		u8 byte)
{
	pv_io_ops.conf_outb(domain, bus, port, byte);
}
static inline void
pv_conf_outw(unsigned int domain, unsigned int bus, unsigned long port,
		u16 hword)
{
	pv_io_ops.conf_outw(domain, bus, port, hword);
}
static inline void
pv_conf_outl(unsigned int domain, unsigned int bus, unsigned long port,
		u32 word)
{
	pv_io_ops.conf_outl(domain, bus, port, word);
}

static inline void boot_pv_debug_cons_outb(u8 byte, u16 port)
{
	BOOT_PARAVIRT_OUT_OP(boot_debug_cons_outb, byte, port);
}

static inline u8 boot_pv_debug_cons_inb(u16 port)
{
	return BOOT_PARAVIRT_IN_OP(boot_debug_cons_inb, port);
}

static inline u32 boot_pv_debug_cons_inl(u16 port)
{
	return BOOT_PARAVIRT_IN_OP(boot_debug_cons_inl, port);
}

static inline void pv_debug_cons_outb(u8 byte, u16 port)
{
	pv_boot_ops.debug_cons_outb(byte, port);
}

static inline void pv_debug_cons_outb_p(u8 byte, u16 port)
{
	pv_boot_ops.debug_cons_outb(byte, port);
}

static inline u8 pv_debug_cons_inb(u16 port)
{
	return pv_boot_ops.debug_cons_inb(port);
}

static inline u32 pv_debug_cons_inl(u16 port)
{
	return pv_boot_ops.debug_cons_inl(port);
}

static inline int __init pv_arch_pci_init(void)
{
	return pv_io_ops.pci_init();
}

#ifdef	CONFIG_PARAVIRT_GUEST
/* it is paravirtualized host and guest kernel */
static inline void boot_writeb(u8 b, void __iomem *addr)
{
	boot_pv_writeb(b, addr);
}
static inline void boot_writew(u16 w, void __iomem *addr)
{
	boot_pv_writew(w, addr);
}
static inline void boot_writel(u32 l, void __iomem *addr)
{
	boot_pv_writel(l, addr);
}
static inline u8 boot_readb(void __iomem *addr)
{
	return boot_pv_readb(addr);
}
static inline u16 boot_readw(void __iomem *addr)
{
	return boot_pv_readw(addr);
}
static inline u32 boot_readl(void __iomem *addr)
{
	return boot_pv_readl(addr);
}

static inline void
conf_inb(unsigned int domain, unsigned int bus, unsigned long port, u8 *byte)
{
	pv_conf_inb(domain, bus, port, byte);
}
static inline void
conf_inw(unsigned int domain, unsigned int bus, unsigned long port, u16 *hword)
{
	pv_conf_inw(domain, bus, port, hword);
}
static inline void
conf_inl(unsigned int domain, unsigned int bus, unsigned long port, u32 *word)
{
	pv_conf_inl(domain, bus, port, word);
}
static inline void
conf_outb(unsigned int domain, unsigned int bus, unsigned long port, u8 byte)
{
	pv_conf_outb(domain, bus, port, byte);
}
static inline void
conf_outw(unsigned int domain, unsigned int bus, unsigned long port, u16 hword)
{
	pv_conf_outw(domain, bus, port, hword);
}
static inline void
conf_outl(unsigned int domain, unsigned int bus, unsigned long port, u32 word)
{
	pv_conf_outl(domain, bus, port, word);
}

static inline void boot_debug_cons_outb(u8 byte, u16 port)
{
	boot_pv_debug_cons_outb(byte, port);
}
static inline u8 boot_debug_cons_inb(u16 port)
{
	return boot_pv_debug_cons_inb(port);
}
static inline u32 boot_debug_cons_inl(u16 port)
{
	return boot_pv_debug_cons_inl(port);
}
static inline void debug_cons_outb(u8 byte, u16 port)
{
	pv_debug_cons_outb(byte, port);
}
static inline void debug_cons_outb_p(u8 byte, u16 port)
{
	pv_debug_cons_outb(byte, port);
}
static inline u8 debug_cons_inb(u16 port)
{
	return pv_debug_cons_inb(port);
}
static inline u32 debug_cons_inl(u16 port)
{
	return pv_debug_cons_inl(port);
}

static inline int __init arch_pci_init(void)
{
	return pv_arch_pci_init();
}
#endif	/* CONFIG_PARAVIRT_GUEST */

#endif  /* _E2K_ASM_PARAVIRT_IO_H_ */
