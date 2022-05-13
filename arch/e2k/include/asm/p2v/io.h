#pragma once

#include <asm/e2k_api.h>
#include <asm/machdep.h>

#define	BOOT_E2K_X86_IO_PAGE_SIZE 	BOOT_E2K_LARGE_PAGE_SIZE
#define BOOT_X86_IO_AREA_PHYS_BASE	(boot_machine.x86_io_area_base)
#define BOOT_X86_IO_AREA_PHYS_SIZE	(boot_machine.x86_io_area_size)

static inline void boot_native_writeb(u8 b, void __iomem *addr)
{
	NATIVE_WRITE_MAS_B((e2k_addr_t)addr, b, MAS_IOADDR);
}

static inline void boot_native_writew(u16 w, void __iomem *addr)
{
	NATIVE_WRITE_MAS_H((e2k_addr_t)addr, w, MAS_IOADDR);
}

static inline void boot_native_writel(u32 l, void __iomem *addr)
{
	NATIVE_WRITE_MAS_W((e2k_addr_t)addr, l, MAS_IOADDR);
}

static inline void boot_native_writeq(u64 q, void __iomem *addr)
{
	NATIVE_WRITE_MAS_D((e2k_addr_t)addr, q, MAS_IOADDR);
}

static inline u8 boot_native_readb(void __iomem *addr)
{
	return NATIVE_READ_MAS_B((e2k_addr_t)addr, MAS_IOADDR);
}

static inline u16 boot_native_readw(void __iomem *addr)
{
	return NATIVE_READ_MAS_H((e2k_addr_t)addr, MAS_IOADDR);
}

static inline u32 boot_native_readl(void __iomem *addr)
{
	return NATIVE_READ_MAS_W((e2k_addr_t)addr, MAS_IOADDR);
}

static inline u64 boot_native_readq(void __iomem *addr)
{
	return NATIVE_READ_MAS_D((e2k_addr_t)addr, MAS_IOADDR);
}

//TODO seems like these are unused, probably should delete them

static inline void boot_native_outb(u8 byte, u16 port)
{
	NATIVE_WRITE_MAS_B(BOOT_X86_IO_AREA_PHYS_BASE + port, byte, MAS_IOADDR);
}
static inline u8 boot_native_inb(u16 port)
{
	return (u8) NATIVE_READ_MAS_B(BOOT_X86_IO_AREA_PHYS_BASE + port, MAS_IOADDR);
}
static inline u32 boot_native_inl(u16 port)
{
	return (u32) NATIVE_READ_MAS_W(BOOT_X86_IO_AREA_PHYS_BASE + port, MAS_IOADDR);
}
