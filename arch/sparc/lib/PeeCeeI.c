/*
 * PeeCeeI.c: The emerging standard...
 *
 * Copyright (C) 1997 David S. Miller (davem@caip.rutgers.edu)
 */

#include <linux/module.h>

#include <asm/io.h>
#include <asm/byteorder.h>

void outsb(unsigned long __addr, const void *src, unsigned long count)
{
	void __iomem *addr = (void __iomem *) __addr;
	const u8 *p = src;

	while (count--)
		outb(*p++, addr);
}
EXPORT_SYMBOL(outsb);

void outsw(unsigned long __addr, const void *src, unsigned long count)
{
	void __iomem *addr = (void __iomem *) __addr;

	while (count--) {
		__raw_writew(*(u16 *)src, addr);
		src += sizeof(u16);
	}
}
EXPORT_SYMBOL(outsw);

void outsl(unsigned long __addr, const void *src, unsigned long count)
{
	void __iomem *addr = (void __iomem *) __addr;
	u32 l, l2;

	if (!count)
		return;

	switch (((unsigned long)src) & 0x3) {
	case 0x0:
		/* src is naturally aligned */
		while (count--) {
			__raw_writel(*(u32 *)src, addr);
			src += sizeof(u32);
		}
		break;
	case 0x2:
		/* 2-byte alignment */
		while (count--) {
			l = (*(u16 *)src) << 16;
			l |= *(u16 *)(src + sizeof(u16));
			__raw_writel(l, addr);
			src += sizeof(u32);
		}
		break;
	case 0x1:
		/* Hold three bytes in l each time, grab a byte from l2 */
		l = (*(u8 *)src) << 24;
		l |= (*(u16 *)(src + sizeof(u8))) << 8;
		src += sizeof(u8) + sizeof(u16);
		while (count--) {
			l2 = *(u32 *)src;
			l |= (l2 >> 24);
			__raw_writel(l, addr);
			l = l2 << 8;
			src += sizeof(u32);
		}
		break;
	case 0x3:
		/* Hold a byte in l each time, grab 3 bytes from l2 */
		l = (*(u8 *)src) << 24;
		src += sizeof(u8);
		while (count--) {
			l2 = *(u32 *)src;
			l |= (l2 >> 8);
			__raw_writel(l, addr);
			l = l2 << 24;
			src += sizeof(u32);
		}
		break;
	}
}
EXPORT_SYMBOL(outsl);

void insb(unsigned long __addr, void *dst, unsigned long count)
{
	void __iomem *addr = (void __iomem *) __addr;

	if (count) {
		u32 *pi;
		u8 *pb = dst;

		while ((((unsigned long)pb) & 0x3) && count--)
			*pb++ = inb(addr);
		pi = (u32 *)pb;
		while (count >= 4) {
			u32 w;

			w  = (inb(addr) << 24);
			w |= (inb(addr) << 16);
			w |= (inb(addr) << 8);
			w |= (inb(addr) << 0);
			*pi++ = w;
			count -= 4;
		}
		pb = (u8 *)pi;
		while (count--)
			*pb++ = inb(addr);
	}
}
EXPORT_SYMBOL(insb);

void insw(unsigned long __addr, void *dst, unsigned long count)
{
	void __iomem *addr = (void __iomem *) __addr;

	if (count) {
		u16 *ps = dst;
		u32 *pi;

		if (((unsigned long)ps) & 0x2) {
			*ps++ = le16_to_cpu(inw(addr));
			count--;
		}
		pi = (u32 *)ps;
		while (count >= 2) {
			u32 w;

			w  = (le16_to_cpu(inw(addr)) << 16);
			w |= (le16_to_cpu(inw(addr)) << 0);
			*pi++ = w;
			count -= 2;
		}
		ps = (u16 *)pi;
		if (count)
			*ps = le16_to_cpu(inw(addr));
	}
}
EXPORT_SYMBOL(insw);

void insl(unsigned long __addr, void *dst, unsigned long count)
{
	void __iomem *addr = (void __iomem *) __addr;

	if (count) {
		if ((((unsigned long)dst) & 0x3) == 0) {
			u32 *pi = dst;
			while (count--)
				*pi++ = le32_to_cpu(inl(addr));
		} else {
			u32 l = 0, l2, *pi;
			u16 *ps;
			u8 *pb;

			switch (((unsigned long)dst) & 3) {
			case 0x2:
				ps = dst;
				count -= 1;
				l = le32_to_cpu(inl(addr));
				*ps++ = l;
				pi = (u32 *)ps;
				while (count--) {
					l2 = le32_to_cpu(inl(addr));
					*pi++ = (l << 16) | (l2 >> 16);
					l = l2;
				}
				ps = (u16 *)pi;
				*ps = l;
				break;

			case 0x1:
				pb = dst;
				count -= 1;
				l = le32_to_cpu(inl(addr));
				*pb++ = l >> 24;
				ps = (u16 *)pb;
				*ps++ = ((l >> 8) & 0xffff);
				pi = (u32 *)ps;
				while (count--) {
					l2 = le32_to_cpu(inl(addr));
					*pi++ = (l << 24) | (l2 >> 8);
					l = l2;
				}
				pb = (u8 *)pi;
				*pb = l;
				break;

			case 0x3:
				pb = (u8 *)dst;
				count -= 1;
				l = le32_to_cpu(inl(addr));
				*pb++ = l >> 24;
				pi = (u32 *)pb;
				while (count--) {
					l2 = le32_to_cpu(inl(addr));
					*pi++ = (l << 8) | (l2 >> 24);
					l = l2;
				}
				ps = (u16 *)pi;
				*ps++ = ((l >> 8) & 0xffff);
				pb = (u8 *)ps;
				*pb = l;
				break;
			}
		}
	}
}
EXPORT_SYMBOL(insl);



#ifdef	__arch64__
/*
 * Copy data from IO memory space to "real" memory space.
 * This needs to be optimized.
 */
void memcpy_fromio(void *to, const volatile void __iomem *from, long count)
{
	/* Optimize aligned transfers.  Everything else gets handled
	   a byte at a time. */

#ifdef	__arch64__
	if (count >= 8 && !(((long)to & 7) || ((long)from & 7))) {
		count -= 8;
		do {
			*(u64 *)to = __raw_readq(from);
			count -= 8;
			to += 8;
			from += 8;
		} while (count >= 0);
		count += 8;
	}
#endif
	if (count >= 4 && !(((long)to & 3) || ((long)from & 3))) {
		count -= 4;
		do {
			*(u32 *)to = __raw_readl(from);
			count -= 4;
			to += 4;
			from += 4;
		} while (count >= 0);
		count += 4;
	}

	if (count >= 2 && !(((long)to & 1) || ((long)from & 1))) {
		count -= 2;
		do {
			*(u16 *)to = __raw_readw(from);
			count -= 2;
			to += 2;
			from += 2;
		} while (count >= 0);
		count += 2;
	}

	while (count > 0) {
		*(u8 *) to = __raw_readb(from);
		count--;
		to++;
		from++;
	}
	mb();
}

EXPORT_SYMBOL(memcpy_fromio);


/*
 * Copy data from "real" memory space to IO memory space.
 * This needs to be optimized.
 */
void memcpy_toio(volatile void __iomem *to, const void *from, long count)
{
	/* Optimize aligned transfers.  Everything else gets handled
	   a byte at a time. */

#ifdef	__arch64__
	if (count >= 8 && !(((long)to & 7) || ((long)from & 7))) {
		count -= 8;
		do {
			__raw_writeq(*(const u64 *)from, to);
			count -= 8;
			to += 8;
			from += 8;
		} while (count >= 0);
		count += 8;
	}
#endif

	if (count >= 4 && !(((long)to & 3) || ((long)from & 3))) {
		count -= 4;
		do {
			__raw_writel(*(const u32 *)from, to);
			count -= 4;
			to += 4;
			from += 4;
		} while (count >= 0);
		count += 4;
	}

	if (count >= 2 && !(((long)to & 1) || ((long)from & 1))) {
		count -= 2;
		do {
			__raw_writew(*(const u16 *)from, to);
			count -= 2;
			to += 2;
			from += 2;
		} while (count >= 0);
		count += 2;
	}

	while (count > 0) {
		__raw_writeb(*(const u8 *) from, to);
		count--;
		to++;
		from++;
	}
	mb();
}

EXPORT_SYMBOL(memcpy_toio);


/*
 * "memset" on IO memory space.
 */
void _memset_c_io(volatile void __iomem *to, unsigned long c, long count)
{
	/* Handle any initial odd byte */
	if (count > 0 && ((long)to & 1)) {
		__raw_writeb(c, to);
		to++;
		count--;
	}

	/* Handle any initial odd halfword */
	if (count >= 2 && ((long)to & 2)) {
		__raw_writew(c, to);
		to += 2;
		count -= 2;
	}

#ifdef	__arch64__
	/* Handle any initial odd word */
	if (count >= 4 && ((long)to & 4)) {
		__raw_writel(c, to);
		to += 4;
		count -= 4;
	}

	/* Handle all full-sized quadwords: we're aligned
	   (or have a small count) */
	count -= 8;
	if (count >= 0) {
		do {
			__raw_writeq(c, to);
			to += 8;
			count -= 8;
		} while (count >= 0);
	}
	count += 8;

	/* The tail is word-aligned if we still have count >= 4 */
	if (count >= 4) {
		__raw_writel(c, to);
		to += 4;
		count -= 4;
	}
#else /*__arch64__*/
	count -= 4;
	if (count >= 0) {
		do {
			__raw_writel(c, to);
			to += 4;
			count -= 4;
		} while (count >= 0);
	}
	count += 4;
#endif /*__arch64__*/

	/* The tail is half-word aligned if we have count >= 2 */
	if (count >= 2) {
		__raw_writew(c, to);
		to += 2;
		count -= 2;
	}

	/* And finally, one last byte.. */
	if (count) {
		__raw_writeb(c, to);
	}
	mb();
}

EXPORT_SYMBOL(_memset_c_io);

#endif /*__arch64__*/
