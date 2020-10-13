
#ifndef	_E2K_IO_H_
#define	_E2K_IO_H_

#include <linux/cpumask.h>
#include <linux/string.h>
#include <linux/compiler.h>

#include <asm/e2k_api.h>
#include <asm/types.h>
#include <asm/head.h>
#include <asm/page.h>
#include <asm/machdep.h>
#include <asm/boot_head.h>

/*
 * E2K I/O ports, BIOS areas virtual memory mapping
 */
#define	E2K_X86_IO_AREA_BASE	E2K_KERNEL_IO_BIOS_AREAS_BASE
#define	E2K_IO_AREA_BASE	(E2K_X86_IO_AREA_BASE + E2K_X86_IO_AREA_SIZE)
#define	E2K_BIOS_AREA_BASE	(E2K_IO_AREA_BASE + E2K_IO_AREA_SIZE)

/* Size of pages for the IO area */
#define	E2K_X86_IO_PAGE_SIZE (cpu_has(CPU_HWBUG_LARGE_PAGES) ? \
				E2K_SMALL_PAGE_SIZE : E2K_LARGE_PAGE_SIZE)
#define	BOOT_E2K_X86_IO_PAGE_SIZE (boot_cpu_has(CPU_HWBUG_LARGE_PAGES) ? \
				E2K_SMALL_PAGE_SIZE : BOOT_E2K_LARGE_PAGE_SIZE)

#define IO_SPACE_LIMIT 0xffff				/* ????? */

#ifdef	CONFIG_E2K_MACHINE

#if defined(CONFIG_E2K_E3M) || defined(CONFIG_E2K_E3M_SIM) ||	\
	defined(CONFIG_E2K_E3M_IOHUB) || defined(CONFIG_E2K_E3M_IOHUB_SIM)
#define	X86_IO_AREA_PHYS_BASE		E3M_X86_IO_AREA_PHYS_BASE
#define	BOOT_X86_IO_AREA_PHYS_BASE	X86_IO_AREA_PHYS_BASE
#elif defined(CONFIG_E2K_E3S) || defined(CONFIG_E2K_E3S_SIM) ||		\
	defined(CONFIG_E2K_ES2_DSP) || defined(CONFIG_E2K_ES2_DSP_SIM) || \
	defined(CONFIG_E2K_ES2_RU) || defined(CONFIG_E2K_ES2_RU_SIM) || \
	defined(CONFIG_E2K_E2S) || defined(CONFIG_E2K_E2S_SIM) || \
	defined(CONFIG_E2K_E8C) || defined(CONFIG_E2K_E8C_SIM) || \
	defined(CONFIG_E2K_E8C2) || defined(CONFIG_E2K_E8C2_SIM)
#define	X86_IO_AREA_PHYS_BASE		E2K_FULL_SIC_IO_AREA_PHYS_BASE
#define	BOOT_X86_IO_AREA_PHYS_BASE	X86_IO_AREA_PHYS_BASE
#elif defined(CONFIG_E2K_E1CP) || defined(CONFIG_E2K_E1CP_SIM)		\
#define	X86_IO_AREA_PHYS_BASE		E2K_LEGACY_SIC_IO_AREA_PHYS_BASE
#define	BOOT_X86_IO_AREA_PHYS_BASE	X86_IO_AREA_PHYS_BASE
#else
#    error "E2K MACHINE type does not defined"
#endif
#else	/* ! CONFIG_E2K_MACHINE */
#define	X86_IO_AREA_PHYS_BASE		machine.x86_io_area_base
#define	BOOT_X86_IO_AREA_PHYS_BASE	boot_machine.x86_io_area_base
#endif	/* CONFIG_E2K_MACHINE */

/*
 * readX/writeX() are used to access memory mapped devices. On some
 * architectures the memory mapped IO stuff needs to be accessed
 * differently. On the x86 architecture, we just read/write the
 * memory location directly.
 */

#ifndef	CONFIG_HW_BUG_IO_READ
#define __raw_readb(addr) (E2K_READ_B(addr))
#define __raw_readw(addr) (E2K_READ_H(addr))
#define __raw_readl(addr) (E2K_READ_W(addr))
#define __raw_readq(addr) (E2K_READ_D(addr))
#else
#define __raw_readb(addr)		\
({					\
	u8 res = E2K_READ_B(addr);	\
	E2K_WAIT_LD;			\
	res;				\
})
#define __raw_readw(addr)		\
({					\
	u16 res = E2K_READ_H(addr);	\
	E2K_WAIT_LD;			\
	res;				\
})
#define __raw_readl(addr)		\
({					\
	u32 res = E2K_READ_W(addr);	\
	E2K_WAIT_LD;			\
	res;				\
})
#define __raw_readq(addr)		\
({					\
	u64 res = E2K_READ_D(addr);	\
	E2K_WAIT_LD;			\
	res;				\
})
#endif

#define readb __raw_readb
#define readw __raw_readw
#define readl __raw_readl
#define readq __raw_readq

#define readb_relaxed readb
#define readw_relaxed readw
#define readl_relaxed readl
#define readq_relaxed readq

#define __raw_writeb(b,addr) (E2K_WRITE_B(addr, b))
#define __raw_writew(b,addr) (E2K_WRITE_H(addr, b))
#define __raw_writel(b,addr) (E2K_WRITE_W(addr, b))
#define __raw_writeq(b,addr) (E2K_WRITE_D(addr, b))
#define writeb __raw_writeb
#define writew __raw_writew
#define writel __raw_writel
#define writeq __raw_writeq

#define mmiowb()

#define memset_io(dst, c, n) __memset_io(dst, c, n, __alignof(*(dst)))
static inline void __memset_io(volatile void __iomem *dst, int c, size_t n,
		const unsigned long dst_align)
{
	long cc;

	cc = c & 0xff;
	cc = cc | (cc << 8);
	cc = cc | (cc << 16);
	cc = cc | (cc << 32);

	if (__builtin_constant_p(n) && dst_align >= 8 && n < 136) {
		/* Inline small aligned memset's */
		volatile u64 *l_dst = dst;

		if (n >= 8)
			l_dst[0] = cc;
		if (n >= 16)
			l_dst[1] = cc;
		if (n >= 24)
			l_dst[2] = cc;
		if (n >= 32)
			l_dst[3] = cc;
		if (n >= 40)
			l_dst[4] = cc;
		if (n >= 48)
			l_dst[5] = cc;
		if (n >= 56)
			l_dst[6] = cc;
		if (n >= 64)
			l_dst[7] = cc;
		if (n >= 72)
			l_dst[8] = cc;
		if (n >= 80)
			l_dst[9] = cc;
		if (n >= 88)
			l_dst[10] = cc;
		if (n >= 96)
			l_dst[11] = cc;
		if (n >= 104)
			l_dst[12] = cc;
		if (n >= 112)
			l_dst[13] = cc;
		if (n >= 120)
			l_dst[14] = cc;
		if (n >= 128)
			l_dst[15] = cc;

		/* Set the tail */
		if (n & 4)
			*(volatile u32 *) (dst + (n & ~0x7UL)) = cc;
		if (n & 2)
			*(volatile u16 *) (dst + (n & ~0x3UL)) = cc;
		if (n & 1)
			*(volatile u8 *) (dst + (n & ~0x1UL)) = cc;
	} else {
		__memset((void * __force) dst, cc, n);
	}
}

extern void __memcpy_fromio(void *dst, const void *src, size_t n);
extern void __memcpy_toio(void *dst, const void *src, size_t n);
#define memcpy_fromio(a, b, c)	__memcpy_fromio((a), (void * __force) (b), (c))
#define memcpy_toio(a, b, c)	__memcpy_toio((void * __force) (a), (b), (c))


static inline void
boot_writeb(u8 b, void __iomem *addr)
{
       E2K_WRITE_MAS_B((e2k_addr_t)addr, b, MAS_IOADDR);
}

static inline void
boot_writew(u16 w, void __iomem *addr)
{
       E2K_WRITE_MAS_H((e2k_addr_t)addr, w, MAS_IOADDR);
}

static inline void
boot_writel(u32 l, void __iomem *addr)
{
       E2K_WRITE_MAS_W((e2k_addr_t)addr, l, MAS_IOADDR);
}

static inline void
boot_writeq(u64 q, void __iomem *addr)
{
       E2K_WRITE_MAS_D((e2k_addr_t)addr, q, MAS_IOADDR);
}

static inline u8
boot_readb(void __iomem *addr)
{
	return E2K_READ_MAS_B((e2k_addr_t)addr, MAS_IOADDR);
}

static inline u16
boot_readw(void __iomem *addr)
{
	return E2K_READ_MAS_H((e2k_addr_t)addr, MAS_IOADDR);
}

static inline u32
boot_readl(void __iomem *addr)
{
	return E2K_READ_MAS_W((e2k_addr_t)addr, MAS_IOADDR);
}

static inline u64
boot_readq(void __iomem *addr)
{
	return E2K_READ_MAS_D((e2k_addr_t)addr, MAS_IOADDR);
}

#define virt_to_bus virt_to_phys
#define bus_to_virt phys_to_virt

extern void	boot_outb(u16 port, u8 byte);
extern u8	boot_inb(u16 port);
extern u32	boot_inl(u16 port);

unsigned char	inb(unsigned long port);
u16		inw(unsigned long port);
u32		inl(unsigned long port);
void		outb(unsigned char byte, unsigned long port);
void		outw(u16 halfword, unsigned long port);
void		outl(u32 word, unsigned long port);
unsigned char	inb_p(unsigned long port);
u16		inw_p(unsigned long port);
u32		inl_p(unsigned long port);
void		outb_p(unsigned char byte, unsigned long port);
void		outw_p(u16 halfword, unsigned long port);
void		outl_p(u32 word, unsigned long port);


void outsb (unsigned long port, const void * src, unsigned long count);
void outsw (unsigned long port, const void *src, unsigned long count);
void outsl (unsigned long port, const void *src, unsigned long count);
void insb  (unsigned long port, void *dst, unsigned long count);
void insw  (unsigned long port, void *dst, unsigned long count);
void insl  (unsigned long port, void *dst, unsigned long count);

void	conf_inb(unsigned int domain, unsigned int bus, 
					unsigned long port, u8 *byte);
void	conf_inw(unsigned int domain, unsigned int bus, 
					unsigned long port, u16 *hword);
void	conf_inl(unsigned int domain, unsigned int bus, 
					unsigned long port, u32 *word);
void	conf_outb(unsigned int domain, unsigned int bus, 
					unsigned long port, u8 byte);
void	conf_outw(unsigned int domain, unsigned int bus, 
					unsigned long port, u16 hword);
void	conf_outl(unsigned int domain, unsigned int bus, 
					unsigned long port, u32 word);

#ifdef __KERNEL__

/*
 * Map in an area of physical address space, for accessing
 * I/O devices etc.
 */
extern void __iomem *ioremap_nocache(unsigned long address, unsigned long size);
extern void __iomem *ioremap_cache(unsigned long address, unsigned long size);
extern void __iomem *ioremap_wc(unsigned long address, unsigned long size);

static inline void __iomem *ioremap(resource_size_t offset, unsigned long size)
{
	return ioremap_nocache(offset, size);
}

#define ARCH_HAS_IOREMAP_WC

#include <asm-generic/iomap.h>

extern void iounmap(void *addr);

/* Create a virtual mapping cookie for an IO port range */
extern void __iomem *ioport_map(unsigned long port, unsigned int nr);
extern void ioport_unmap(void __iomem *);

/* Create a virtual mapping cookie for a PCI BAR (memory or IO) */
struct pci_dev;
extern void __iomem *pci_iomap(struct pci_dev *dev, int bar, unsigned long max);
extern void pci_iounmap(struct pci_dev *dev, void __iomem *);

static inline void flush_write_buffers(void)
{
	wmb();
}

/*
 * Convert a physical pointer to a virtual kernel pointer for /dev/mem
 * access
 */
#define xlate_dev_mem_ptr(p)	__va(p)

/*
 * Convert a virtual cached pointer to an uncached pointer
 */
#define xlate_dev_kmem_ptr(p)	p


/*
 * ISA I/O bus memory addresses are 1:1 with the physical address.
 */
#define isa_virt_to_bus virt_to_phys


/*
 * E2K does not require mem IO specific function.
 */

#define eth_io_copy_and_sum(a, b, c, d)		\
		eth_copy_and_sum((a), (void *)(b), (c), (d))

#endif /* __KERNEL__ */

#ifdef CONFIG_GENERIC_IOMAP

extern unsigned int ioread8(void __iomem *addr);
extern unsigned int ioread16(void __iomem *addr);
extern unsigned int ioread16be(void __iomem *addr);
extern unsigned int ioread32(void __iomem *addr);
extern unsigned int ioread32be(void __iomem *addr);

extern void iowrite8(u8 val, void __iomem *addr);
extern void iowrite16(u16 val, void __iomem *addr);
extern void iowrite16be(u16 val, void __iomem *addr);
extern void iowrite32(u32 val, void __iomem *addr);
extern void iowrite32be(u32 val, void __iomem *addr);

extern void ioread8_rep(void __iomem *addr, void *dst, unsigned long count);
extern void ioread16_rep(void __iomem *addr, void *dst, unsigned long count);
extern void ioread32_rep(void __iomem *addr, void *dst, unsigned long count);

extern void iowrite8_rep(void __iomem *addr, const void *src, unsigned long count);
extern void iowrite16_rep(void __iomem *addr, const void *src, unsigned long count);
extern void iowrite32_rep(void __iomem *addr, const void *src, unsigned long count);
#else

#define ioread8(X)                      readb(X)
#define ioread16(X)                     readw(X)
#define ioread32(X)                     readl(X)
#define iowrite8(val,X)                 writeb(val,X)
#define iowrite16(val,X)                writew(val,X)
#define iowrite32(val,X)                writel(val,X)

#endif /* CONFIG_GENERIC_IOMAP */

#endif  /* _E2K_IO_H_ */
