#ifndef _E2K_SIC_REGS_ACCESS_H_
#define _E2K_SIC_REGS_ACCESS_H_

#ifdef __KERNEL__

#include <asm/io.h>

#define SIC_io_reg_offset(io_link, reg) ((reg) + 0x1000 * (io_link))

#define nbsr_early_read(addr)		boot_readl((addr))
#define nbsr_early_write(value, addr)	boot_writel((value), (addr))

#define nbsr_read(addr)			readl((addr))
#define nbsr_write(value, addr)		writel((value), (addr))

unsigned int sic_get_mc_ecc(int node, int num);
unsigned int sic_get_mc_opmb(int node, int num);
unsigned int sic_get_ipcc_csr(int node, int num);
void sic_set_ipcc_csr(int node, int num, unsigned int val);
unsigned int sic_get_ipcc_pmr(int node, int num);
unsigned int sic_get_ipcc_str(int node, int num);
void sic_set_ipcc_str(int node, int num, unsigned int val);
unsigned int sic_get_io_csr(int node, int num);
unsigned int sic_get_io_tmr(int node, int num);
unsigned int sic_get_io_str(int node, int num);
void sic_set_io_str(int node, int num, unsigned int val);
unsigned int sic_get_pl_csr(int node, int num);
#endif	/* __KERNEL__ */

#include <asm-l/sic_regs.h>

#endif  /* _E2K_SIC_REGS_ACCESS_H_ */
