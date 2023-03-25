#ifndef	_ASM_E2K_IO_EPIC_H
#define	_ASM_E2K_IO_EPIC_H

#include <asm/sic_regs.h>

static inline void epic_ioapic_eoi(u8 vector)
{
	unsigned int value = vector << 8;

	value |= 0x5;

	sic_write_nbsr_reg(SIC_hc_ioapic_eoi, value);
}

static inline void get_io_epic_msi(int node, u32 *lo, u32 *hi)
{
	if (node < 0)
		node = 0;
	/* FIXME SIC reads with mas 0x13 aren't supported by hypervisor */
	if (paravirt_enabled()) {
		*lo = early_sic_read_node_nbsr_reg(node, SIC_rt_msi);
		*hi = early_sic_read_node_nbsr_reg(node, SIC_rt_msi_h);
	} else {
		*lo = sic_read_node_nbsr_reg(node, SIC_rt_msi);
		*hi = sic_read_node_nbsr_reg(node, SIC_rt_msi_h);
	}
}
#include <asm-l/io_epic.h>
#endif	/* _ASM_E2K_IO_EPIC_H */
