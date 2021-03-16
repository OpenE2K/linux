#ifndef	_ASM_E90S_IO_EPIC_H
#define	_ASM_E90S_IO_EPIC_H

#define E90S_EPIC_EOI_BASE		0x02000000
#define E90S_EPIC_APIC_EOI_BASE		0x01000000

static inline void epic_ioapic_eoi(u8 vector)
{
	unsigned v = vector << 8;
	v |= 0x5;
	writel_asi(v, E90S_EPIC_APIC_EOI_BASE, ASI_EPIC);
}

static inline void get_io_epic_msi(int node, u32 *lo, u32 *hi)
{
	u64 v = nbsr_readl(NBSR_EPIC_UP_MSG_BASE, node);
	v = NBSR_EPIC_UP_MSG_BASE_TO_ADDR(v);
	*lo = v;
	*hi = v >> 32;
}

#include <asm-l/io_epic.h>

#endif	/* _ASM_E90S_IO_EPIC_H */
