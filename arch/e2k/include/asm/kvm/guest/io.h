
#ifndef	_E2K_KVM_GUEST_IO_H_
#define	_E2K_KVM_GUEST_IO_H_

#include <linux/types.h>

#include <asm/head.h>

#define	GUEST_IO_PORTS_ADDRESS(port)	(GUEST_IO_PORTS_VIRT_BASE + (port))
static inline void
KVM_DEBUG_OUTB(u8 byte, u16 port)
{
	u8 __iomem *io_port = (u8 __iomem *)GUEST_IO_PORTS_ADDRESS(port);

	*io_port = byte;
	wmb();	/* wait for write completed */
}

static inline u8
KVM_DEBUG_INB(u16 port)
{
	u8 __iomem *io_port = (u8 __iomem *)GUEST_IO_PORTS_ADDRESS(port);
	u8 data;

	data = *io_port;
	rmb();	/* wait for read completed */
	return data;
}

static inline u32
KVM_DEBUG_INL(u16 port)
{
	u32 __iomem *io_port = (u32 __iomem *)GUEST_IO_PORTS_ADDRESS(port);
	u32 data;

	data = *io_port;
	rmb();	/* wait for read completed */
	return data;
}

extern void kvm_writeb(u8 b, volatile void __iomem *addr);
extern void kvm_writew(u16 w, volatile void __iomem *addr);
extern void kvm_writel(u32 l, volatile void __iomem *addr);
extern void kvm_writell(u64 q, volatile void __iomem *addr);

extern u8 kvm_readb(const volatile void __iomem *addr);
extern u16 kvm_readw(const volatile void __iomem *addr);
extern u32 kvm_readl(const volatile void __iomem *addr);
extern u64 kvm_readll(const volatile void __iomem *addr);

extern void boot_kvm_writeb(u8 b, void __iomem *addr);
extern void boot_kvm_writew(u16 w, void __iomem *addr);
extern void boot_kvm_writel(u32 l, void __iomem *addr);
extern void boot_kvm_writell(u64 q, void __iomem *addr);

extern u8 boot_kvm_readb(void __iomem *addr);
extern u16 boot_kvm_readw(void __iomem *addr);
extern u32 boot_kvm_readl(void __iomem *addr);
extern u64 boot_kvm_readll(void __iomem *addr);

extern u8 kvm_inb(unsigned short port);
extern u16 kvm_inw(unsigned short port);
extern u32 kvm_inl(unsigned short port);

extern void kvm_outb(unsigned char byte, unsigned short port);
extern void kvm_outw(unsigned short halfword, unsigned short port);
extern void kvm_outl(unsigned int word, unsigned short port);

extern void kvm_outsb(unsigned short port, const void *src, unsigned long count);
extern void kvm_outsw(unsigned short port, const void *src, unsigned long count);
extern void kvm_outsl(unsigned short port, const void *src, unsigned long count);
extern void kvm_insb(unsigned short port, void *src, unsigned long count);
extern void kvm_insw(unsigned short port, void *src, unsigned long count);
extern void kvm_insl(unsigned short port, void *src, unsigned long count);
extern void kvm_conf_inb(unsigned int domain, unsigned int bus,
				unsigned long port, u8 *byte);
extern void kvm_conf_inw(unsigned int domain, unsigned int bus,
				unsigned long port, u16 *hword);
extern void kvm_conf_inl(unsigned int domain, unsigned int bus,
				unsigned long port, u32 *word);
extern void kvm_conf_outb(unsigned int domain, unsigned int bus,
				unsigned long port, u8 byte);
extern void kvm_conf_outw(unsigned int domain, unsigned int bus,
				unsigned long port, u16 hword);
extern void kvm_conf_outl(unsigned int domain, unsigned int bus,
				unsigned long port, u32 word);

extern unsigned long kvm_notify_io(unsigned int notifier_io);

extern int __init kvm_arch_pci_init(void);

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is pure guest kernel (not paravirtualized based on pv_ops */

static inline void kvm_hv_writeb(u8 b, volatile void __iomem *addr)
{
	if (IS_HV_GM())
		return native_writeb(b, addr);

	kvm_writeb(b, addr);
}
static inline void kvm_hv_writew(u16 w, volatile void __iomem *addr)
{
	if (IS_HV_GM())
		return native_writew(w, addr);

	kvm_writew(w, addr);
}
static inline void kvm_hv_writel(u32 l, volatile void __iomem *addr)
{
	if (IS_HV_GM())
		return native_writel(l, addr);

	kvm_writel(l, addr);
}
static inline void kvm_hv_writeq(u64 q, volatile void __iomem *addr)
{
	if (IS_HV_GM())
		return native_writeq(q, addr);

	kvm_writell(q, addr);
}

static inline void boot_writeb(u8 b, void __iomem *addr)
{
	boot_kvm_writeb(b, addr);
}
static inline void boot_writew(u16 w, void __iomem *addr)
{
	boot_kvm_writew(w, addr);
}
static inline void boot_writel(u32 l, void __iomem *addr)
{
	boot_kvm_writel(l, addr);
}
static inline void boot_writeq(u64 l, void __iomem *addr)
{
	boot_kvm_writell(l, addr);
}

static inline u8 kvm_hv_readb(const volatile void __iomem *addr)
{
	if (IS_HV_GM())
		return native_readb(addr);

	return kvm_readb(addr);
}
static inline u16 kvm_hv_readw(const volatile void __iomem *addr)
{
	if (IS_HV_GM())
		return native_readw(addr);

	return kvm_readw(addr);
}
static inline u32 kvm_hv_readl(const volatile void __iomem *addr)
{
	if (IS_HV_GM())
		return native_readl(addr);

	return kvm_readl(addr);
}
static inline u64 kvm_hv_readq(const volatile void __iomem *addr)
{
	if (IS_HV_GM())
		return native_readq(addr);

	return kvm_readll(addr);
}

static inline u8 boot_readb(void __iomem *addr)
{
	return boot_kvm_readb(addr);
}
static inline u16 boot_readw(void __iomem *addr)
{
	return boot_kvm_readw(addr);
}
static inline u32 boot_readl(void __iomem *addr)
{
	return boot_kvm_readl(addr);
}
static inline u64 boot_readq(void __iomem *addr)
{
	return boot_kvm_readll(addr);
}

/*
 * _relaxed() accessors.
 */
static inline u8 kvm_readb_relaxed(const volatile void __iomem *addr)
{
	if (IS_HV_GM())
		return native_readb_relaxed(addr);

	return kvm_readb(addr);
}

static inline u16 kvm_readw_relaxed(const volatile void __iomem *addr)
{
	if (IS_HV_GM())
		return native_readw_relaxed(addr);

	return kvm_readw(addr);
}

static inline u32 kvm_readl_relaxed(const volatile void __iomem *addr)
{
	if (IS_HV_GM())
		return native_readl_relaxed(addr);

	return kvm_readl(addr);
}

static inline u64 kvm_readq_relaxed(const volatile void __iomem *addr)
{
	if (IS_HV_GM())
		return native_readq_relaxed(addr);

	return kvm_readll(addr);
}

static inline void kvm_writeb_relaxed(u8 value, volatile void __iomem *addr)
{
	if (IS_HV_GM())
		return native_writeb_relaxed(value, addr);

	kvm_writeb(value, addr);
}

static inline void kvm_writew_relaxed(u16 value, volatile void __iomem *addr)
{
	if (IS_HV_GM())
		return native_writew_relaxed(value, addr);

	kvm_writew(value, addr);
}

static inline void kvm_writel_relaxed(u32 value, volatile void __iomem *addr)
{
	if (IS_HV_GM())
		return native_writel_relaxed(value, addr);

	kvm_writel(value, addr);
}

static inline void kvm_writeq_relaxed(u64 value, volatile void __iomem *addr)
{
	if (IS_HV_GM())
		return native_writeq_relaxed(value, addr);

	kvm_writell(value, addr);
}


static inline u8 kvm_hv_inb(unsigned long port)
{
	if (IS_HV_GM())
		return native_inb(port);

	return kvm_inb(port);
}
static inline u16 kvm_hv_inw(unsigned long port)
{
	if (IS_HV_GM())
		return native_inw(port);

	return kvm_inw(port);
}
static inline u32 kvm_hv_inl(unsigned long port)
{
	if (IS_HV_GM())
		return native_inl(port);

	return kvm_inl(port);
}
static inline void kvm_hv_outb(unsigned char byte, unsigned long port)
{
	if (IS_HV_GM())
		return native_outb(byte, port);

	kvm_outb(byte, port);
}
static inline void kvm_hv_outw(unsigned short halfword, unsigned long port)
{
	if (IS_HV_GM())
		return native_outw(halfword, port);

	kvm_outw(halfword, port);
}
static inline void kvm_hv_outl(unsigned int word, unsigned long port)
{
	if (IS_HV_GM())
		return native_outl(word, port);

	kvm_outl(word, port);
}

static inline void kvm_hv_outsb(unsigned short port, const void *src, unsigned long count)
{
	if (IS_HV_GM())
		return native_outsb(port, src, count);

	kvm_outsb(port, src, count);
}
static inline void kvm_hv_outsw(unsigned short port, const void *src, unsigned long count)
{
	if (IS_HV_GM())
		return native_outsw(port, src, count);

	kvm_outsw(port, src, count);
}
static inline void kvm_hv_outsl(unsigned short port, const void *src, unsigned long count)
{
	if (IS_HV_GM())
		return native_outsl(port, src, count);

	kvm_outsl(port, src, count);
}

static inline void kvm_hv_insb(unsigned short port, void *dst, unsigned long count)
{
	if (IS_HV_GM())
		return native_insb(port, dst, count);

	kvm_insb(port, dst, count);
}
static inline void kvm_hv_insw(unsigned short port, void *dst, unsigned long count)
{
	if (IS_HV_GM())
		return native_insw(port, dst, count);

	kvm_insw(port, dst, count);
}
static inline void kvm_hv_insl(unsigned short port, void *dst, unsigned long count)
{
	if (IS_HV_GM())
		return native_insl(port, dst, count);

	kvm_insl(port, dst, count);
}

static inline void
conf_inb(unsigned int domain, unsigned int bus, unsigned long port, u8 *byte)
{
	if (IS_HV_GM())
		return native_conf_inb(domain, bus, port, byte);

	kvm_conf_inb(domain, bus, port, byte);
}
static inline void
conf_inw(unsigned int domain, unsigned int bus, unsigned long port, u16 *hword)
{
	if (IS_HV_GM())
		return native_conf_inw(domain, bus, port, hword);

	kvm_conf_inw(domain, bus, port, hword);
}
static inline void
conf_inl(unsigned int domain, unsigned int bus, unsigned long port, u32 *word)
{
	if (IS_HV_GM())
		return native_conf_inl(domain, bus, port, word);

	kvm_conf_inl(domain, bus, port, word);
}
static inline void
conf_outb(unsigned int domain, unsigned int bus, unsigned long port, u8 byte)
{
	if (IS_HV_GM())
		return native_conf_outb(domain, bus, port, byte);

	kvm_conf_outb(domain, bus, port, byte);
}
static inline void
conf_outw(unsigned int domain, unsigned int bus, unsigned long port, u16 hword)
{
	if (IS_HV_GM())
		return native_conf_outw(domain, bus, port, hword);

	kvm_conf_outw(domain, bus, port, hword);
}
static inline void
conf_outl(unsigned int domain, unsigned int bus, unsigned long port, u32 word)
{
	if (IS_HV_GM())
		return native_conf_outl(domain, bus, port, word);

	kvm_conf_outl(domain, bus, port, word);
}

static inline void boot_debug_cons_outb(u8 byte, u16 port)
{
	KVM_DEBUG_OUTB(byte, port);
}
static inline u8 boot_debug_cons_inb(u16 port)
{
	return KVM_DEBUG_INB(port);
}
static inline u32 boot_debug_cons_inl(u16 port)
{
	return KVM_DEBUG_INL(port);
}
static inline void debug_cons_outb(u8 byte, u16 port)
{
	KVM_DEBUG_OUTB(byte, port);
}
static inline void debug_cons_outb_p(u8 byte, u16 port)
{
	KVM_DEBUG_OUTB(byte, port);
}
static inline u8 debug_cons_inb(u16 port)
{
	return KVM_DEBUG_INB(port);
}
static inline u32 debug_cons_inl(u16 port)
{
	return KVM_DEBUG_INL(port);
}

static inline int __init arch_pci_init(void)
{
	return kvm_arch_pci_init();
}
#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif  /* _E2K_KVM_GUEST_IO_H_ */
