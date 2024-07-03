/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _BOOT_E2K_SIC_H_
#define _BOOT_E2K_SIC_H_

#include <linux/init.h>
#include <linux/nodemask.h>

#include <asm/e2k_api.h>
#include <asm/machines.h>
#include <asm/e2k_sic.h>
#include <asm/hb_regs.h>

#ifdef CONFIG_E2K_LEGACY_SIC

# if defined(CONFIG_E1CP)
#  define BOOT_PCICFG_AREA_PHYS_BASE	E1CP_PCICFG_AREA_PHYS_BASE
# endif

static inline unsigned long
__boot_readll_hb_reg(unsigned int reg_offset)
{
	return early_readll_hb_eg_reg(HB_PCI_BUS_NUM, HB_PCI_SLOT, HB_PCI_FUNC,
			reg_offset, BOOT_PCICFG_AREA_PHYS_BASE);
}

static inline unsigned int
__boot_readl_hb_reg(unsigned int reg_offset)
{
	return early_readl_hb_eg_reg(HB_PCI_BUS_NUM, HB_PCI_SLOT, HB_PCI_FUNC,
			reg_offset, BOOT_PCICFG_AREA_PHYS_BASE);
}

static inline unsigned int
__boot_readl_eg_reg(unsigned int reg_offset)
{
	return early_readl_hb_eg_reg(EG_PCI_BUS_NUM, EG_PCI_SLOT, EG_PCI_FUNC,
			reg_offset, BOOT_PCICFG_AREA_PHYS_BASE);
}

static inline unsigned short
__boot_readw_hb_reg(unsigned int reg_offset)
{
	return early_readw_hb_eg_reg(HB_PCI_BUS_NUM, HB_PCI_SLOT, HB_PCI_FUNC,
			reg_offset, BOOT_PCICFG_AREA_PHYS_BASE);
}

static inline unsigned short
__boot_readw_eg_reg(unsigned int reg_offset)
{
	return early_readw_hb_eg_reg(EG_PCI_BUS_NUM, EG_PCI_SLOT, EG_PCI_FUNC,
			reg_offset, BOOT_PCICFG_AREA_PHYS_BASE);
}

static inline unsigned long
__boot_get_legacy_nbsr_base(void)
{
	return __boot_readll_hb_reg(HB_PCI_LEGACY_BAR) &
			HB_PCI_LEGACY_MEMORY_BAR;
}

static inline void
__boot_writell_hb_reg(unsigned long reg_value, unsigned int reg_offset)
{
	early_writell_hb_eg_reg(HB_PCI_BUS_NUM, HB_PCI_SLOT, HB_PCI_FUNC,
		reg_value, reg_offset, BOOT_PCICFG_AREA_PHYS_BASE);
}

static inline void
__boot_writel_hb_reg(unsigned int reg_value, unsigned int reg_offset)
{
	early_writel_hb_eg_reg(HB_PCI_BUS_NUM, HB_PCI_SLOT, HB_PCI_FUNC,
		reg_value, reg_offset, BOOT_PCICFG_AREA_PHYS_BASE);
}

static inline void
__boot_writel_eg_reg(unsigned int reg_value, unsigned int reg_offset)
{
	early_writel_hb_eg_reg(EG_PCI_BUS_NUM, EG_PCI_SLOT, EG_PCI_FUNC,
		reg_value, reg_offset, BOOT_PCICFG_AREA_PHYS_BASE);
}

static inline void
__boot_writew_hb_reg(unsigned short reg_value, unsigned int reg_offset)
{
	early_writew_hb_eg_reg(HB_PCI_BUS_NUM, HB_PCI_SLOT, HB_PCI_FUNC,
		reg_value, reg_offset, BOOT_PCICFG_AREA_PHYS_BASE);
}

static inline void
__boot_writew_eg_reg(unsigned short reg_value, unsigned int reg_offset)
{
	early_writew_hb_eg_reg(EG_PCI_BUS_NUM, EG_PCI_SLOT, EG_PCI_FUNC,
		reg_value, reg_offset, BOOT_PCICFG_AREA_PHYS_BASE);
}
#endif /* CONFIG_E2K_LEGACY_SIC */

/*
 * NBR area configuration
 */

#undef	BOOT_NSR_AREA_PHYS_BASE

#if defined CONFIG_E2K_LEGACY_SIC
# if defined(CONFIG_E1CP)
#  define BOOT_NSR_AREA_PHYS_BASE	__boot_get_legacy_nbsr_base()
# endif
#else
# if defined(CONFIG_E2S)
#  define BOOT_NSR_AREA_PHYS_BASE	E2S_NSR_AREA_PHYS_BASE
# elif defined(CONFIG_E8C)
#  define BOOT_NSR_AREA_PHYS_BASE	E8C_NSR_AREA_PHYS_BASE
# elif defined(CONFIG_E8C2)
#  define BOOT_NSR_AREA_PHYS_BASE	E8C2_NSR_AREA_PHYS_BASE
# elif defined(CONFIG_E12C)
#  define BOOT_NSR_AREA_PHYS_BASE	E12C_NSR_AREA_PHYS_BASE
# elif defined(CONFIG_E16C)
#  define BOOT_NSR_AREA_PHYS_BASE	E16C_NSR_AREA_PHYS_BASE
# elif defined(CONFIG_E2C3)
#  define BOOT_NSR_AREA_PHYS_BASE	E2C3_NSR_AREA_PHYS_BASE
# elif	defined(CONFIG_E48C)
#  define BOOT_NSR_AREA_PHYS_BASE	E48C_NSR_AREA_PHYS_BASE
# elif	defined(CONFIG_E8V7)
#  define BOOT_NSR_AREA_PHYS_BASE	E8V7_NSR_AREA_PHYS_BASE
# endif
#endif

/*
 * Nodes system registers area - NSR = { NSR0 ... NSRj ... }
 * NSR is some part of common system communicator area SR
 */
#define	BOOT_NODE_NSR_SIZE		BOOT_NSR_AREA_SIZE
#undef	THE_NODE_NSR_PHYS_BASE
#define	THE_NODE_NSR_PHYS_BASE(node)	\
		(BOOT_NSR_AREA_PHYS_BASE + (node * BOOT_NODE_NSR_SIZE))

/*
 * Nodes processor system registers (north bridge)
 * NBSR = { NBSR0 ... NBSRj ... }
 * NBSR is some part of node system registers area NSR
 */
#define	BOOT_NODE_NBSR_OFFSET		BOOT_NBSR_OFFSET
#undef	THE_NODE_NBSR_PHYS_BASE
#define	THE_NODE_NBSR_PHYS_BASE(node)	\
		((unsigned char __iomem *)(THE_NODE_NSR_PHYS_BASE(node) + \
						BOOT_NODE_NBSR_OFFSET))

#endif /* _BOOT_E2K_SIC_H_ */
