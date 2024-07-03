/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _E2K_SIC_REGS_ACCESS_H_
#define _E2K_SIC_REGS_ACCESS_H_

#ifdef __KERNEL__

#include <asm/io.h>
#include <asm/e2k_sic.h>

#undef  DEBUG_BOOT_NBSR_MODE
#undef  DebugBNBSR
#define	DEBUG_BOOT_NBSR_MODE	0	/* early NBSR access */
#define	DebugBNBSR(fmt, args...)		\
		({ if (DEBUG_BOOT_NBSR_MODE)	\
			do_boot_printk(fmt, ##args); })

#define SIC_io_reg_offset(io_link, reg) ((reg) + 0x1000 * (io_link))

#ifndef	CONFIG_BOOT_E2K
#define nbsr_early_read(addr)		boot_readl((addr))
#define nbsr_early_write(value, addr)	boot_writel((value), (addr))
#else	/* CONFIG_BOOT_E2K */
#define nbsr_early_read(addr)		boot_native_readl((addr))
#define nbsr_early_write(value, addr)	boot_native_writel((value), (addr))
#endif	/* ! CONFIG_BOOT_E2K */

static inline unsigned int
boot_do_sic_read_node_nbsr_reg(unsigned char __iomem *node_nbsr, int reg_offset)
{
	unsigned char __iomem *addr;
	unsigned int reg_value;

	addr = node_nbsr + reg_offset;
	reg_value = nbsr_early_read(addr);
	DebugBNBSR("boot_sic_read_node_nbsr_reg() the node reg 0x%x read 0x%x "
		"from 0x%lx\n",
		reg_offset, reg_value, addr);
	return reg_value;
}

static inline void
boot_do_sic_write_node_nbsr_reg(unsigned char __iomem *node_nbsr, int reg_offset,
				unsigned int reg_val)
{
	unsigned char __iomem *addr;

	addr = node_nbsr + reg_offset;
	nbsr_early_write(reg_val, addr);
	DebugBNBSR("boot_sic_write_node_nbsr_reg() the node reg 0x%x write "
		"0x%x to 0x%lx\n",
		reg_offset, reg_val, addr);
}

#define nbsr_read(addr)			readl((addr))
#define nbsr_readll(addr)		readq((addr))
#define nbsr_readw(addr)		readw((addr))
#define nbsr_write(value, addr)		writel((value), (addr))
#define nbsr_writell(value, addr)	writeq((value), (addr))
#define nbsr_writew(value, addr)	writew((value), (addr))
#define nbsr_write_relaxed(value, addr)	writel_relaxed((value), (addr))

unsigned int sic_get_mc_ecc(int node, int num);
void sic_set_mc_ecc(int node, int num, unsigned int reg_value);

unsigned int sic_get_mc_opmb(int node, int num);
unsigned int sic_get_mc_cfg(int node, int num);

unsigned int sic_get_ipcc_csr(int node, int num);
void sic_set_ipcc_csr(int node, int num, unsigned int val);

unsigned int sic_get_ipcc_str(int node, int num);
void sic_set_ipcc_str(int node, int num, unsigned int val);

unsigned int sic_get_io_str(int node, int num);
void sic_set_io_str(int node, int num, unsigned int val);
#endif	/* __KERNEL__ */

#include <asm-l/sic_regs.h>

#endif  /* _E2K_SIC_REGS_ACCESS_H_ */
