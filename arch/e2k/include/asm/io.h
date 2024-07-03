/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

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

#ifndef COFNIG_KVM_GUEST_KERNEL
#include <asm/p2v/io.h>
#endif

extern int __init native_arch_pci_init(void);

#define	E2K_IO_AREA_BASE		E2K_KERNEL_IO_BIOS_AREAS_BASE

/* Size of pages for the IO area */
#define	E2K_IO_PAGE_SIZE	E2K_SMALL_PAGE_SIZE
#define IO_AREA_PHYS_BASE	(machine.io_area_base)
#define IO_AREA_PHYS_SIZE	(machine.io_area_size)

/*
 * We add all the necessary barriers manually
 */
#define __io_br()
#define __io_ar(v) do { (void) (v); } while (0)
#define __io_bw()
#define __io_aw()

/*
 * _relaxed() accessors.
 */

static inline u8 native_readb_relaxed(const volatile void __iomem *addr)
{
	u8 res = *(const volatile u8 __force *) addr;
	return res;
}

static inline u16 native_readw_relaxed(const volatile void __iomem *addr)
{
	u16 res = *(const volatile u16 __force *) addr;
	return res;
}

static inline u32 native_readl_relaxed(const volatile void __iomem *addr)
{
	u32 res = *(const volatile u32 __force *) addr;
	return res;
}

static inline u64 native_readq_relaxed(const volatile void __iomem *addr)
{
	u64 res = *(const volatile u64 __force *) addr;
	return res;
}

static inline void native_writeb_relaxed(u8 value, volatile void __iomem *addr)
{
	*(volatile u8 __force *) addr = value;
}

static inline void native_writew_relaxed(u16 value, volatile void __iomem *addr)
{
	*(volatile u16 __force *) addr = value;
}

static inline void native_writel_relaxed(u32 value, volatile void __iomem *addr)
{
	*(volatile u32 __force *) addr = value;
}

static inline void native_writeq_relaxed(u64 value, volatile void __iomem *addr)
{
	*(volatile u64 __force *) addr = value;
}


/*
 * Strongly ordered accessors.
 */

static inline u8 native_readb(const volatile void __iomem *addr)
{
	u8 res;
	if (cpu_has(CPU_FEAT_ISET_V6)) {
		IO_LOAD_NV_MAS((volatile u8 __force *) addr, res,
				MAS_LOAD_ACQUIRE_V6(MAS_MT_0), b, "memory");
	} else {
		res = native_readb_relaxed(addr);
	}
	return res;
}

static inline u16 native_readw(const volatile void __iomem *addr)
{
	u16 res;
	if (cpu_has(CPU_FEAT_ISET_V6)) {
		IO_LOAD_NV_MAS((volatile u16 __force *) addr, res,
				MAS_LOAD_ACQUIRE_V6(MAS_MT_0), h, "memory");
	} else {
		res = native_readw_relaxed(addr);
	}
	return res;
}

static inline u32 native_readl(const volatile void __iomem *addr)
{
	u32 res;
	if (cpu_has(CPU_FEAT_ISET_V6)) {
		IO_LOAD_NV_MAS((volatile u32 __force *) addr, res,
				MAS_LOAD_ACQUIRE_V6(MAS_MT_0), w, "memory");
	} else {
		res = native_readl_relaxed(addr);
	}
	return res;
}

static inline u64 native_readq(const volatile void __iomem *addr)
{
	u64 res;
	if (cpu_has(CPU_FEAT_ISET_V6)) {
		IO_LOAD_NV_MAS((volatile u64 __force *) addr, res,
				MAS_LOAD_ACQUIRE_V6(MAS_MT_0), d, "memory");
	} else {
		res = native_readq_relaxed(addr);
	}
	return res;
}

static inline void native_writeb(u8 value, volatile void __iomem *addr)
{
	if (cpu_has(CPU_FEAT_ISET_V6)) {
		IO_STORE_NV_MAS((volatile u8 __force *) addr, value,
				MAS_STORE_RELEASE_V6(MAS_MT_0), b, "memory");
		/* wmb() after MMIO writes is not required by documentation, but
		 * this is how x86 works and how most of the drivers are tested. */
		wmb();
	} else {
		native_writeb_relaxed(value, addr);
	}
}

static inline void native_writew(u16 value, volatile void __iomem *addr)
{
	if (cpu_has(CPU_FEAT_ISET_V6)) {
		IO_STORE_NV_MAS((volatile u16 __force *) addr, value,
				MAS_STORE_RELEASE_V6(MAS_MT_0), h, "memory");
		wmb();
	} else {
		native_writew_relaxed(value, addr);
	}
}

static inline void native_writel(u32 value, volatile void __iomem *addr)
{
	if (cpu_has(CPU_FEAT_ISET_V6)) {
		IO_STORE_NV_MAS((volatile u32 __force *) addr, value,
				MAS_STORE_RELEASE_V6(MAS_MT_0), w, "memory");
		wmb();
	} else {
		native_writel_relaxed(value, addr);
	}
}

static inline void native_writeq(u64 value, volatile void __iomem *addr)
{
	if (cpu_has(CPU_FEAT_ISET_V6)) {
		IO_STORE_NV_MAS((volatile u64 __force *) addr, value,
				MAS_STORE_RELEASE_V6(MAS_MT_0), d, "memory");
		wmb();
	} else {
		native_writeq_relaxed(value, addr);
	}
}

/*
 * Port accessors, also strongly ordered
 *
 * All necessary memory barriers are applied in e2k_api.h
 */

static inline u8 native_inb(unsigned int port)
{
	return NATIVE_READ_MAS_B(IO_AREA_PHYS_BASE + port, MAS_IOADDR);
}
static inline u16 native_inw(unsigned int port)
{
	return NATIVE_READ_MAS_H(IO_AREA_PHYS_BASE + port, MAS_IOADDR);
}
static inline u32 native_inl(unsigned int port)
{
	return NATIVE_READ_MAS_W(IO_AREA_PHYS_BASE + port, MAS_IOADDR);
}
static inline void native_outb(u8 byte, unsigned int port)
{
	NATIVE_WRITE_MAS_B(IO_AREA_PHYS_BASE + port, byte, MAS_IOADDR);
}
static inline void native_outw(u16 halfword, unsigned int port)
{
	NATIVE_WRITE_MAS_H(IO_AREA_PHYS_BASE + port, halfword, MAS_IOADDR);
}
static inline void native_outl(u32 word, unsigned int port)
{
	NATIVE_WRITE_MAS_W(IO_AREA_PHYS_BASE + port, word, MAS_IOADDR);
}


/*
 * Variants of inX/outX that repeatedly access the same port
 */

static inline void native_insb(unsigned short port, void *dst, unsigned long count)
{
	u8 *b_p = dst;
	while (count--)
		*b_p++ = native_inb(port);
}
static inline void native_insw(unsigned short port, void *dst, unsigned long count)
{
	u16 *hw_p = dst;
	while (count--)
		*hw_p++ = native_inw(port);
}
static inline void native_insl(unsigned short port, void *dst, unsigned long count)
{
	u32 *l_p = dst;
	while (count--)
		*l_p++ = native_inl(port);
}

static inline void native_outsb(unsigned short port, const void *src, unsigned long count)
{
	const u8 *b_p = src;
	while (count--)
		native_outb(*b_p++, port);
}
static inline void native_outsw(unsigned short port, const void *src, unsigned long count)
{
	const u16 *hw_p = src;
	while (count--)
		native_outw(*hw_p++, port);
}
static inline void native_outsl(unsigned short port, const void *src, unsigned long count)
{
	const u32 *l_p = src;
	while (count--)
		native_outl(*l_p++, port);
}

/*
 * And some e2k-specific accessors
 */
static inline void native_debug_cons_outb(u8 byte, u16 port)
{
	native_outb(byte, port);
}
static inline u8 native_debug_cons_inb(u16 port)
{
	return native_inb(port);
}
static inline u32 native_debug_cons_inl(u16 port)
{
	return native_inl(port);
}

extern void native_conf_inb(unsigned int domain, unsigned int bus,
					unsigned long port, u8 *byte);
extern void native_conf_inw(unsigned int domain, unsigned int bus,
					unsigned long port, u16 *hword);
extern void native_conf_inl(unsigned int domain, unsigned int bus,
					unsigned long port, u32 *word);
extern void native_conf_outb(unsigned int domain, unsigned int bus,
					unsigned long port, u8 byte);
extern void native_conf_outw(unsigned int domain, unsigned int bus,
					unsigned long port, u16 hword);
extern void native_conf_outl(unsigned int domain, unsigned int bus,
					unsigned long port, u32 word);


#if defined CONFIG_KVM_GUEST_KERNEL
/* it is virtualized guest kernel */
# include <asm/kvm/guest/io.h>

# define __raw_readb kvm_readb_relaxed
# define __raw_readw kvm_readw_relaxed
# define __raw_readl kvm_readl_relaxed
# define __raw_readq kvm_readq_relaxed
# define __raw_writeb kvm_writeb_relaxed
# define __raw_writew kvm_writew_relaxed
# define __raw_writel kvm_writel_relaxed
# define __raw_writeq kvm_writeq_relaxed
# define readb kvm_hv_readb
# define readw kvm_hv_readw
# define readl kvm_hv_readl
# define readq kvm_hv_readq
# define writeb kvm_hv_writeb
# define writew kvm_hv_writew
# define writel kvm_hv_writel
# define writeq kvm_hv_writeq
# define inb kvm_hv_inb
# define inw kvm_hv_inw
# define inl kvm_hv_inl
# define outb kvm_hv_outb
# define outw kvm_hv_outw
# define outl kvm_hv_outl
# define insb kvm_hv_insb
# define insw kvm_hv_insw
# define insl kvm_hv_insl
# define outsb kvm_hv_outsb
# define outsw kvm_hv_outsw
# define outsl kvm_hv_outsl
#else
/* Native kernel - either host or without any virtualization at all */
# define __raw_readb native_readb_relaxed
# define __raw_readw native_readw_relaxed
# define __raw_readl native_readl_relaxed
# define __raw_readq native_readq_relaxed
# define __raw_writeb native_writeb_relaxed
# define __raw_writew native_writew_relaxed
# define __raw_writel native_writel_relaxed
# define __raw_writeq native_writeq_relaxed
# define readb native_readb
# define readw native_readw
# define readl native_readl
# define readq native_readq
# define writeb native_writeb
# define writew native_writew
# define writel native_writel
# define writeq native_writeq
# define inb native_inb
# define inw native_inw
# define inl native_inl
# define outb native_outb
# define outw native_outw
# define outl native_outl
# define insb native_insb
# define insw native_insw
# define insl native_insl
# define outsb native_outsb
# define outsw native_outsw
# define outsl native_outsl

static inline void boot_writeb(u8 b, void __iomem *addr)
{
	boot_native_writeb(b, addr);
}

static inline void boot_writew(u16 w, void __iomem *addr)
{
	boot_native_writew(w, addr);
}

static inline void boot_writel(u32 l, void __iomem *addr)
{
	boot_native_writel(l, addr);
}

static inline void boot_writeq(u64 q, void __iomem *addr)
{
	boot_native_writeq(q, addr);
}

static inline u8 boot_readb(void __iomem *addr)
{
	return boot_native_readb(addr);
}

static inline u16 boot_readw(void __iomem *addr)
{
	return boot_native_readw(addr);
}

static inline u32 boot_readl(void __iomem *addr)
{
	return boot_native_readl(addr);
}

static inline u64 boot_readq(void __iomem *addr)
{
	return boot_native_readq(addr);
}


static inline void
conf_inb(unsigned int domain, unsigned int bus, unsigned long port, u8 *byte)
{
	native_conf_inb(domain, bus, port, byte);
}
static inline void
conf_inw(unsigned int domain, unsigned int bus, unsigned long port, u16 *hword)
{
	native_conf_inw(domain, bus, port, hword);
}
static inline void
conf_inl(unsigned int domain, unsigned int bus, unsigned long port, u32 *word)
{
	native_conf_inl(domain, bus, port, word);
}
static inline void
conf_outb(unsigned int domain, unsigned int bus, unsigned long port, u8 byte)
{
	native_conf_outb(domain, bus, port, byte);
}
static inline void
conf_outw(unsigned int domain, unsigned int bus, unsigned long port, u16 hword)
{
	native_conf_outw(domain, bus, port, hword);
}
static inline void
conf_outl(unsigned int domain, unsigned int bus, unsigned long port, u32 word)
{
	native_conf_outl(domain, bus, port, word);
}

static inline void debug_cons_outb(u8 byte, u16 port)
{
	native_debug_cons_outb(byte, port);
}
static inline void debug_cons_outb_p(u8 byte, u16 port)
{
	native_debug_cons_outb(byte, port);
}
static inline u8 debug_cons_inb(u16 port)
{
	return native_debug_cons_inb(port);
}
static inline u32 debug_cons_inl(u16 port)
{
	return native_debug_cons_inl(port);
}
static inline void boot_debug_cons_outb(u8 byte, u16 port)
{
	boot_native_outb(byte, port);
}
static inline u8 boot_debug_cons_inb(u16 port)
{
	return boot_native_inb(port);
}
static inline u32 boot_debug_cons_inl(u16 port)
{
	return boot_native_inl(port);
}

static inline int __init arch_pci_init(void)
{
	return native_arch_pci_init();
}

#endif

/*
 * Map in an area of physical address space, for accessing
 * I/O devices etc.
 */
extern void __iomem *ioremap_wc(resource_size_t address, unsigned long size);
#define ioremap_wc ioremap_wc

extern void __iomem *ioremap_np(resource_size_t address, unsigned long size);
#define ioremap_np ioremap_np

extern void __iomem *ioremap(resource_size_t address, unsigned long size);
#define ioremap ioremap

extern void __iomem *ioremap_prot(resource_size_t address, unsigned long size,
		unsigned long prot_val);
#define ioremap_prot ioremap_prot

#define iounmap iounmap
extern void iounmap(volatile void __iomem *addr);

#define ARCH_HAS_IOREMAP_WC

void *arch_memremap_wb(phys_addr_t phys_addr, size_t size);
#define arch_memremap_wb arch_memremap_wb

extern void __memset_io(void *s, long c, size_t count);

#define memset_io(dst, c, n) _memset_io(dst, c, n, __alignof(*(dst)))
static inline void _memset_io(volatile void __iomem *dst, int c, size_t n,
		const unsigned long dst_align)
{
	long cc;

	cc = c & 0xff;
	cc = cc | (cc << 8);
	cc = cc | (cc << 16);
	cc = cc | (cc << 32);

	if (__builtin_constant_p(n) && dst_align >= 8 && n < 136) {
		/* Inline small aligned memset's */
		volatile u64 __iomem *l_dst = dst;

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
			*(u32 __iomem *) (dst + (n & ~0x7UL)) = cc;
		if (n & 2)
			*(u16 __iomem *) (dst + (n & ~0x3UL)) = cc;
		if (n & 1)
			*(u8 __iomem *) (dst + (n & ~0x1UL)) = cc;
	} else {
		__memset_io((void * __force) dst, cc, n);
	}
}

extern void __memcpy_fromio(void *dst, const void *src, size_t n);
extern void __memcpy_toio(void *dst, const void *src, size_t n);
#define memcpy_fromio(a, b, c)	__memcpy_fromio((a), (void * __force) (b), (c))
#define memcpy_toio(a, b, c)	__memcpy_toio((void * __force) (a), (b), (c))

#define ARCH_HAS_VALID_PHYS_ADDR_RANGE
extern int valid_phys_addr_range(phys_addr_t addr, size_t size);
extern int valid_mmap_phys_addr_range(unsigned long pfn, size_t size);

/**
 * virt_to_phys - map virtual addresses to physical
 * @address: address to remap
 *
 * The returned physical address is the physical (CPU) mapping for
 * the memory address given. It is only valid to use this function on
 * addresses directly mapped or allocated via kmalloc.
 *
 * This function does not give bus mappings for DMA transfers. In
 * almost all conceivable cases a device driver should not be using
 * this function.
 */
#define virt_to_phys virt_to_phys
static inline phys_addr_t __force virt_to_phys(volatile void *address)
{
	return __pa(address);
}

/**
 * phys_to_virt - map physical address to virtual
 * @address: address to remap
 *
 * The returned virtual address is a current CPU mapping for
 * the memory address given. It is only valid to use this function on
 * addresses that have a kernel mapping.
 *
 * This function does not handle bus mappings for DMA transfers. In
 * almost all conceivable cases a device driver should not be using
 * this function.
 */
#define phys_to_virt phys_to_virt
static inline void __force *phys_to_virt(phys_addr_t address)
{
	return __va(address);
}

#include <asm-generic/io.h>
#undef PCI_IOBASE


extern unsigned long get_domain_pci_conf_base(unsigned int domain);
extern unsigned long get_domain_pci_conf_size(unsigned int domain);

/*
 * ISA I/O bus memory addresses are 1:1 with the physical address.
 */
#define isa_virt_to_bus virt_to_phys

#endif  /* _E2K_IO_H_ */
