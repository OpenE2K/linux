#ifndef __ASM_APIC_H
#define __ASM_APIC_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <asm/e2k_api.h>
#include <asm/irq.h>

#ifndef __ASSEMBLY__

/*
 * Basic functions accessing APICs.
 */

static inline void arch_apic_write(u32 reg, u32 v)
{
	E2K_WRITE_MAS_W(APIC_DEFAULT_PHYS_BASE + reg, v, MAS_IOADDR);
}

static inline u32 arch_apic_read(u32 reg)
{
	return E2K_READ_MAS_W(APIC_DEFAULT_PHYS_BASE + reg, MAS_IOADDR);
}
#endif	/* !(__ASSEMBLY__) */

#if IS_ENABLED(CONFIG_RDMA) || IS_ENABLED(CONFIG_RDMA_SIC) || \
    IS_ENABLED(CONFIG_RDMA_NET)
extern int rdma_apic_init;
extern int rdma_node[];
#endif

#include <asm-l/apic.h>

#endif /* __KERNEL__ */
#endif
