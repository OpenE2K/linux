
#ifndef	_E2K_HB_REGS_H_
#define	_E2K_HB_REGS_H_

#ifdef __KERNEL__

#include <linux/types.h>
#ifndef	__ASSEMBLY__
#include <linux/pci.h>
#include <asm/e2k.h>
#include <asm/e2k_sic.h>
#endif	/* __ASSEMBLY__ */

#undef  DEBUG_ERALY_HB_MODE
#undef  DebugEHB
#define	DEBUG_ERALY_HB_MODE	0	/* early Host Bridge access */
#undef  DEBUG_BOOT_HB_MODE
#undef  DebugBEHB
#define	DEBUG_BOOT_HB_MODE	0	/* boot Host Bridge access */
#ifndef	CONFIG_BOOT_E2K
#define	DebugEHB(fmt, args...)		\
		({ if (DEBUG_ERALY_HB_MODE)	\
			printk(fmt, ##args); })
#define	DebugBEHB(fmt, args...)		\
		({ if (DEBUG_BOOT_HB_MODE)	\
			do_boot_printk(fmt, ##args); })
#else	/* CONFIG_BOOT_E2K */
#define	DebugEHB(fmt, args...)		\
		({ if (DEBUG_ERALY_HB_MODE)	\
			rom_printk(fmt, ##args); })
#define	DebugBEHB(fmt, args...)		\
		({ if (DEBUG_BOOT_HB_MODE)	\
			rom_printk(fmt, ##args); })
#endif	/* ! CONFIG_BOOT_E2K */

#undef	DEBUG_HB_MODE
#undef	DebugHB
#define	DEBUG_HB_MODE		0	/* Host Bridge access */
#define	DebugHB(fmt, args...)			\
		({ if (DEBUG_HB_MODE)		\
			printk(fmt, ##args); })

/*
 * Host Bridge is PCI device on root bus #0 and has common PCI configure
 * registers and some additional special registers
 */

/* Host bridge is device 0x1f on root bus #0 */
#define	HB_PCI_BUS_NUM		0x00
#define	HB_PCI_SLOT		0x1f
#define	HB_PCI_FUNC		0x00
/* Embeded Graphic is device 0x1e on root bus #0 */
#define	EG_PCI_BUS_NUM		0x00
#define	EG_PCI_SLOT		0x1e
#define	EG_PCI_FUNC		0x00

/* Base address of legacy NBSR registers */
#define HB_PCI_LEGACY_BAR	PCI_BASE_ADDRESS_0	/* 0x10 64 bits */
 #define HB_PCI_LEGACY_MEMORY_BAR	0x000000fffff00000	/* [39:20] */
 #define HB_PCI_LEGACY_ADDR_MASK	0x00000000000ffff0	/* [19: 4] 1M */
/* Base address of Power Management Controller registers */
#define HB_PCI_PMC_BAR		PCI_BASE_ADDRESS_2	/* 0x18 64 bits */
 #define HB_PCI_PMC_MEMORY_BAR		0x000000ffffff0000	/* [39:16] */
 #define HB_PCI_PMC_ADDR_MASK		0x000000000000fff0	/* [15: 4] */
								/* 64K */

/* Additional special registers */

/* Host Bridge configuration register */
#define	HB_PCI_CFG		0x40			/* 32 bits */
 #define HB_CFG_MaskIntSic		0x00000080	/* SIC interrupts */
							/* to embedeed IOAPIC */
 #define HB_CFG_MaskIntWlcc		0x00000040	/* WLCC interrupts */
							/* to embedeed IOAPIC */
 #define HB_CFG_MaskIntIommu		0x00000020	/* IOMMU interrupts */
							/* to embedeed IOAPIC */
 #define HB_CFG_ShareHostInterrupts	0x00000010	/* HB interrupts */
							/* are shared as IRQ2 */
							/* else IRQ2 & IRQ3 */
 #define HB_CFG_ShareGraphicsInterrupts	0x00000008	/* EG interrupts */
							/* are shared as IRQ0 */
							/* else IRQ0 & IRQ1 */
 #define HB_CFG_InternalIoApicEnable	0x00000004	/* embeded interrupts */
							/* to embedeed IOAPIC */
							/* else to LAPIC LVT */
 #define HB_CFG_IntegratedVgaEnable	0x00000002	/* Legacy VGA access */
							/* to EG */
							/* else to IOHUB */
 #define HB_CFG_IntegratedGraphicsEnable 0x00000001	/* EG is on */

/* Top Of low Memory register */
#define	HB_PCI_TOM		0x44			/* 32 bits */
 #define HB_PCI_TOM_LOW_MASK	0x00000000fff00000	/* [31:20] */

/* Top Of high Memory register */
#define	HB_PCI_TOM2		0x48			/* 64 bits */
 #define HB_PCI_TOM2_HI_MASK	0x000000fffff00000	/* [39:20] */
 #define HB_PCI_HI_ADDR_BASE	0x0000000100000000	/* 4Gb */

/* Base Address of high memory from which remapped low memore */
#define	HB_PCI_REMAPBASE	0x50			/* 64 bits */
 #define HB_PCI_REMAPBASE_MASK	0x000000fffff00000	/* [39:20] */

/* Base Address of embeded IO APIC */
#define	HB_PCI_IOAPICBASE	0x58			/* 64 bits */
 #define HB_PCI_IOAPICBASE_MASK	0x000000ffffffff00	/* [39: 8] */

/* PMC MSI configuration register */
#define	HB_PCI_PMC_MSGCTL	0x62			/* 16 bits */
/* PMC MSI address register */
#define	HB_PCI_PMC_MSGADDR	0x64			/* 32 bits */
 #define HB_PCI_MESSADGEADDRESS	0xfffffffc		/* [31: 2] */

/*
 * Embeded Graphic controller registers
 */

/* Base address of Video RAM */
#define EG_PCI_VRAM_BAR		PCI_BASE_ADDRESS_0	/* 0x10 64 bits */
 #define EG_PCI_VRAM_MEMORY_BAR	0x000000fff8000000	/* [39:30] */
 #define EG_PCI_VRAM_ADDRMASK1024 0x0000000020000000	/* [29] */
 #define EG_PCI_VRAM_ADDRMASK512  0x0000000010000000	/* [28] */
 #define EG_PCI_VRAM_ADDRMASK256  0x0000000008000000	/* [27] */
 #define EG_PCI_VRAM_ADDR_MASK	0x0000000007fffff0	/* [26: 4] 128M */
/* Base address of MGA-2 registers */
#define EG_PCI_MGA2_BAR		PCI_BASE_ADDRESS_2	/* 0x18 32 bits */
 #define EG_PCI_MGA2_MEMORY_BAR	0xfffc0000		/* [31:18] */
 #define EG_PCI_MGA2_ADDR_MASK	0x0003ffff		/* [17: 4] 256K */
/* Base address of GC2500 registers */
#define EG_PCI_GC2500_BAR	PCI_BASE_ADDRESS_3	/* 0x1c 32 bits */
 #define EG_PCI_GC2500_MEMORY_BAR 0xfffc0000		/* [31:18] */
 #define EG_PCI_GC2500_ADDR_MASK  0x0003ffff		/* [17: 4] 256K */
/* Embeded Graphic controller CFG register */
#define	EG_PCI_CFG		0x40			/* 32 bits */
 #define EG_CFG_VRAM_SIZE_MASK	0x00000003		/* [ 1: 0] */
  #define EG_CFG_VRAM_SIZE_128	0x0			/* 128 Mb */
  #define EG_CFG_VRAM_SIZE_256	0x1			/* 256 Mb */
  #define EG_CFG_VRAM_SIZE_512	0x2			/* 512 Mb */
  #define EG_CFG_VRAM_SIZE_1024	0x3			/* 1 Gb */
/* Embeded Graphic MSI configuration register */
#define	EG_PCI_MSGCTL		0x46			/* 16 bits */
/* Embeded Graphic MSI address register */
#define	EG_PCI_MSGADDR		0x48			/* 32 bits */
 #define EG_PCI_MESSADGEADDRESS	0xfffffffc		/* [31: 2] */

#ifndef __ASSEMBLY__

/*
 * Host bridge & embeded graphic see as PCI devices on bus #0
 */
#define	hb_eg_early_readb(addr)			\
		boot_readb((void *)(addr))
#define	hb_eg_early_readw(addr)			\
		boot_readw((void *)(addr))
#define	hb_eg_early_readl(addr)			\
		boot_readl((void *)(addr))
#define	hb_eg_early_writeb(value, addr)		\
		boot_writeb((value), (void *)(addr))
#define	hb_eg_early_writew(value, addr)		\
		boot_writew((value), (void *)(addr))
#define	hb_eg_early_writel(value, addr)		\
		boot_writel((value), (void *)(addr))

#define hb_eg_early_pci_conf_base()	sic_domain_pci_conf_base(0)

#define	boot_hb_eg_readl(addr)		boot_readl((void *)(addr))
#define	boot_hb_eg_pci_conf_base()	boot_sic_domain_pci_conf_base(0)

static inline unsigned char
early_readb_hb_eg_reg(unsigned int bus, unsigned int slot, unsigned int func,
			unsigned int reg_offset)
{
	unsigned long reg_addr = hb_eg_early_pci_conf_base();
	unsigned char reg_value;

	reg_addr += CONFIG_CMD(bus, PCI_DEVFN(slot, func), reg_offset);
	reg_value = hb_eg_early_readb(reg_addr);
	DebugEHB("early_readb_hb_eg_reg() reg 0x%x read 0x%02hhx from 0x%lx\n",
		reg_offset, reg_value, reg_addr);
	return reg_value;
}

static inline unsigned short
early_readw_hb_eg_reg(unsigned int bus, unsigned int slot, unsigned int func,
			unsigned int reg_offset)
{
	unsigned long reg_addr = hb_eg_early_pci_conf_base();
	unsigned short reg_value;

	reg_addr += CONFIG_CMD(bus, PCI_DEVFN(slot, func), reg_offset);
	reg_value = hb_eg_early_readw(reg_addr);
	DebugEHB("early_readw_hb_eg_reg() reg 0x%x read 0x%04hx from 0x%lx\n",
		reg_offset, reg_value, reg_addr);
	return reg_value;
}

static inline unsigned int
early_readl_hb_eg_reg(unsigned int bus, unsigned int slot, unsigned int func,
			unsigned int reg_offset)
{
	unsigned long reg_addr = hb_eg_early_pci_conf_base();
	unsigned int reg_value;

	reg_addr += CONFIG_CMD(bus, PCI_DEVFN(slot, func), reg_offset);
	reg_value = hb_eg_early_readl(reg_addr);
	DebugEHB("early_readl_hb_eg_reg() reg 0x%x read 0x%08x from 0x%lx\n",
		reg_offset, reg_value, reg_addr);
	return reg_value;
}

static inline unsigned long
early_readll_hb_eg_reg(unsigned int bus, unsigned int slot, unsigned int func,
			unsigned int reg_offset)
{
	unsigned long reg_addr = hb_eg_early_pci_conf_base();
	unsigned long reg_value_lo;
	unsigned long reg_value_hi;
	unsigned long reg_value;

	reg_addr += CONFIG_CMD(bus, PCI_DEVFN(slot, func), reg_offset);
	reg_value_lo = hb_eg_early_readl(reg_addr);
	reg_value_hi = hb_eg_early_readl(reg_addr + sizeof(unsigned int));
	reg_value = reg_value_lo | (reg_value_hi << sizeof(unsigned int) * 8);
	DebugEHB("early_readw_hb_eg_reg() reg 0x%x read 0x%016lx from 0x%lx\n",
		reg_offset, reg_value, reg_addr);
	return reg_value;
}

static inline unsigned long
boot_readll_hb_eg_reg(unsigned int bus, unsigned int slot, unsigned int func,
			unsigned int reg_offset)
{
	unsigned long reg_addr = boot_hb_eg_pci_conf_base();
	unsigned long reg_value_lo;
	unsigned long reg_value_hi;
	unsigned long reg_value;

	reg_addr += CONFIG_CMD(bus, PCI_DEVFN(slot, func), reg_offset);
	reg_value_lo = boot_hb_eg_readl(reg_addr);
	reg_value_hi = boot_hb_eg_readl(reg_addr + sizeof(unsigned int));
	reg_value = reg_value_lo | (reg_value_hi << sizeof(unsigned int) * 8);
	DebugBEHB("boot_readw_hb_eg_reg() reg 0x%x read 0x%016lx from 0x%lx\n",
		reg_offset, reg_value, reg_addr);
	return reg_value;
}

static inline void
early_writeb_hb_eg_reg(unsigned int bus, unsigned int slot, unsigned int func,
			unsigned char reg_value, unsigned int reg_offset)
{
	unsigned long reg_addr = hb_eg_early_pci_conf_base();

	reg_addr += CONFIG_CMD(bus, PCI_DEVFN(slot, func), reg_offset);
	hb_eg_early_writeb(reg_value, reg_addr);
	DebugEHB("early_writeb_hb_eg_reg() reg 0x%x write 0x%02hhx to 0x%lx\n",
		reg_offset, reg_value, reg_addr);
}

static inline void
early_writew_hb_eg_reg(unsigned int bus, unsigned int slot, unsigned int func,
			unsigned short reg_value, unsigned int reg_offset)
{
	unsigned long reg_addr = hb_eg_early_pci_conf_base();

	reg_addr += CONFIG_CMD(bus, PCI_DEVFN(slot, func), reg_offset);
	hb_eg_early_writew(reg_value, reg_addr);
	DebugEHB("early_writew_hb_eg_reg() reg 0x%x write 0x%04hx to 0x%lx\n",
		reg_offset, reg_value, reg_addr);
}

static inline void
early_writel_hb_eg_reg(unsigned int bus, unsigned int slot, unsigned int func,
			unsigned int reg_value, unsigned int reg_offset)
{
	unsigned long reg_addr = hb_eg_early_pci_conf_base();

	reg_addr += CONFIG_CMD(bus, PCI_DEVFN(slot, func), reg_offset);
	hb_eg_early_writel(reg_value, reg_addr);
	DebugEHB("early_writel_hb_eg_reg() reg 0x%x write 0x%08x to 0x%lx\n",
		reg_offset, reg_value, reg_addr);
}

static inline void
early_writell_hb_eg_reg(unsigned int bus, unsigned int slot, unsigned int func,
			unsigned long reg_value, unsigned int reg_offset)
{
	unsigned long reg_addr = hb_eg_early_pci_conf_base();
	unsigned int reg_value_lo;
	unsigned int reg_value_hi;

	reg_addr += CONFIG_CMD(bus, PCI_DEVFN(slot, func), reg_offset);
	reg_value_lo = reg_value & 0x00000000ffffffff;
	reg_value_hi = reg_value >> (sizeof(unsigned int) * 8);
	hb_eg_early_writel(reg_value_lo, reg_addr);
	hb_eg_early_writel(reg_value_hi, reg_addr + sizeof(unsigned int));
	DebugEHB("early_writell_hb_eg_reg() reg 0x%x write 0x%016lx to 0x%lx\n",
		reg_offset, reg_value, reg_addr);
}

static inline unsigned char
early_readb_hb_reg(unsigned int reg_offset)
{
	return early_readb_hb_eg_reg(HB_PCI_BUS_NUM, HB_PCI_SLOT, HB_PCI_FUNC,
					reg_offset);
}

static inline unsigned short
early_readw_hb_reg(unsigned int reg_offset)
{
	return early_readw_hb_eg_reg(HB_PCI_BUS_NUM, HB_PCI_SLOT, HB_PCI_FUNC,
					reg_offset);
}

static inline unsigned int
early_readl_hb_reg(unsigned int reg_offset)
{
	return early_readl_hb_eg_reg(HB_PCI_BUS_NUM, HB_PCI_SLOT, HB_PCI_FUNC,
					reg_offset);
}

static inline unsigned long
early_readll_hb_reg(unsigned int reg_offset)
{
	return early_readll_hb_eg_reg(HB_PCI_BUS_NUM, HB_PCI_SLOT, HB_PCI_FUNC,
					reg_offset);
}

static inline unsigned long
boot_readll_hb_reg(unsigned int reg_offset)
{
	return boot_readll_hb_eg_reg(HB_PCI_BUS_NUM, HB_PCI_SLOT, HB_PCI_FUNC,
					reg_offset);
}

static inline void
early_writeb_hb_reg(unsigned char reg_value, unsigned int reg_offset)
{
	early_writeb_hb_eg_reg(HB_PCI_BUS_NUM, HB_PCI_SLOT, HB_PCI_FUNC,
				reg_value, reg_offset);
}

static inline void
early_writew_hb_reg(unsigned short reg_value, unsigned int reg_offset)
{
	early_writew_hb_eg_reg(HB_PCI_BUS_NUM, HB_PCI_SLOT, HB_PCI_FUNC,
				reg_value, reg_offset);
}

static inline void
early_writel_hb_reg(unsigned int reg_value, unsigned int reg_offset)
{
	early_writel_hb_eg_reg(HB_PCI_BUS_NUM, HB_PCI_SLOT, HB_PCI_FUNC,
				reg_value, reg_offset);
}

static inline void
early_writell_hb_reg(unsigned long reg_value, unsigned int reg_offset)
{
	early_writell_hb_eg_reg(HB_PCI_BUS_NUM, HB_PCI_SLOT, HB_PCI_FUNC,
				reg_value, reg_offset);
}

static inline unsigned char
early_readb_eg_reg(unsigned int reg_offset)
{
	return early_readb_hb_eg_reg(EG_PCI_BUS_NUM, EG_PCI_SLOT, EG_PCI_FUNC,
					reg_offset);
}

static inline unsigned short
early_readw_eg_reg(unsigned int reg_offset)
{
	return early_readw_hb_eg_reg(EG_PCI_BUS_NUM, EG_PCI_SLOT, EG_PCI_FUNC,
					reg_offset);
}

static inline unsigned int
early_readl_eg_reg(unsigned int reg_offset)
{
	return early_readl_hb_eg_reg(EG_PCI_BUS_NUM, EG_PCI_SLOT, EG_PCI_FUNC,
					reg_offset);
}

static inline unsigned long
early_readll_eg_reg(unsigned int reg_offset)
{
	return early_readll_hb_eg_reg(EG_PCI_BUS_NUM, EG_PCI_SLOT, EG_PCI_FUNC,
					reg_offset);
}

static inline void
early_writeb_eg_reg(unsigned char reg_value, unsigned int reg_offset)
{
	early_writeb_hb_eg_reg(EG_PCI_BUS_NUM, EG_PCI_SLOT, EG_PCI_FUNC,
				reg_value, reg_offset);
}

static inline void
early_writew_eg_reg(unsigned short reg_value, unsigned int reg_offset)
{
	early_writew_hb_eg_reg(EG_PCI_BUS_NUM, EG_PCI_SLOT, EG_PCI_FUNC,
				reg_value, reg_offset);
}

static inline void
early_writel_eg_reg(unsigned int reg_value, unsigned int reg_offset)
{
	early_writel_hb_eg_reg(EG_PCI_BUS_NUM, EG_PCI_SLOT, EG_PCI_FUNC,
				reg_value, reg_offset);
}

static inline void
early_writell_eg_reg(unsigned long reg_value, unsigned int reg_offset)
{
	early_writell_hb_eg_reg(EG_PCI_BUS_NUM, EG_PCI_SLOT, EG_PCI_FUNC,
				reg_value, reg_offset);
}

static inline unsigned long
early_get_legacy_nbsr_base(void)
{
	return early_readll_hb_reg(HB_PCI_LEGACY_BAR) &
					HB_PCI_LEGACY_MEMORY_BAR;
}

static inline unsigned long
boot_get_legacy_nbsr_base(void)
{
	return boot_readll_hb_reg(HB_PCI_LEGACY_BAR) &
					HB_PCI_LEGACY_MEMORY_BAR;
}

#endif /* ! __ASSEMBLY__ */

#endif /* __KERNEL__ */

#endif  /* _E2K_HB_REGS_H_ */
