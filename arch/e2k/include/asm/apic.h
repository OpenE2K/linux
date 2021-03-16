#ifndef __ASM_E2K_APIC_H
#define __ASM_E2K_APIC_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <asm/e2k_api.h>
#include <asm/irq.h>
#include <asm/io.h>

#ifndef __ASSEMBLY__

/*
 * Basic functions accessing APICs.
 */
static inline void arch_apic_write(unsigned int reg, unsigned int v)
{
	boot_writel(v, (void __iomem *) (APIC_DEFAULT_PHYS_BASE + reg));
}

static inline unsigned int arch_apic_read(unsigned int reg)
{
	return boot_readl((void __iomem *) (APIC_DEFAULT_PHYS_BASE + reg));
}

static inline void boot_arch_apic_write(unsigned int reg, unsigned int v)
{
	arch_apic_write(reg, v);
}

static inline unsigned int boot_arch_apic_read(unsigned int reg)
{
	return arch_apic_read(reg);
}

#if IS_ENABLED(CONFIG_RDMA) || IS_ENABLED(CONFIG_RDMA_SIC) || \
    IS_ENABLED(CONFIG_RDMA_NET)
extern int rdma_apic_init;
extern int rdma_node[];
#endif

#endif	/* !(__ASSEMBLY__) */

#include <asm-l/apic.h>

#endif /* __KERNEL__ */
#endif /* __ASM_E2K_APIC_H */
