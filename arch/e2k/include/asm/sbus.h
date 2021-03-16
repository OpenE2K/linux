#ifndef E2K_SBUS_H
#define E2K_SBUS_H

#include <asm/io.h>
#include <asm/openprom.h>


/**
 * SBus accessors.
 */

#define _ALIGN_MASK     (~(uint64_t)0x3)

static __inline__ u8 _sbus_readb(unsigned long addr)
{
	/* PCI2SBUS doesn't receive 1-byte read good. It's hardware bug */

	return (*(volatile uint32_t *)(addr & _ALIGN_MASK) >> (addr & (0x3))*0x8) & 0xFF;
}

static __inline__ u16 _sbus_readw(unsigned long addr)
{
	return be16_to_cpu((readw(addr)));
}

static __inline__ u32 _sbus_readl(unsigned long addr)
{
	return be32_to_cpu((readl(addr)));
}

static __inline__ void _sbus_writeb(u8 b, unsigned long addr)
{
	writeb(b, addr);
}

static __inline__ void _sbus_writew(u16 w, unsigned long addr)
{
	writew(cpu_to_be16(w), addr);
}
 
static __inline__ void _sbus_writel(u32 l, unsigned long addr)
{
	writel(cpu_to_be32(l), addr);
}

#define sbus_readb(a)           _sbus_readb((unsigned long)(a))
#define sbus_readw(a)           _sbus_readw((unsigned long)(a))
#define sbus_readl(a)           _sbus_readl((unsigned long)(a))
#define sbus_writeb(v, a)       _sbus_writeb(v, (unsigned long)(a))
#define sbus_writew(v, a)       _sbus_writew(v, (unsigned long)(a))
#define sbus_writel(v, a)       _sbus_writel(v, (unsigned long)(a))

static inline int sbus_addr_is_valid(unsigned long ba)
{
	u8 value = sbus_readb(ba);
	return (value == 0xFD) || (value == 0xF1);
}

#endif
