#ifndef __ASM_APIC_H
#define __ASM_APIC_H

#include <linux/types.h>
#include <asm/sections.h>
#include <asm/io.h>
#include <asm/apicdef.h>
#include <asm/irq.h>
#include <asm/e90s.h>

#ifndef __ASSEMBLY__

/*
 * Basic functions accessing APICs.
 */
static inline void arch_apic_write(unsigned long reg, unsigned long v)
{
	writel_asi(v, reg, ASI_LAPIC);
}
static inline unsigned long arch_apic_read(unsigned long reg)
{
	return readl_asi(reg, ASI_LAPIC);
}

static __inline int logical_smp_processor_id(void)
{
	return (GET_APIC_LOGICAL_ID(arch_apic_read(APIC_LDR)));
}

#endif	/* !(__ASSEMBLY__) */

#if (defined(CONFIG_E90S)) && \
	(defined(CONFIG_RDMA_SIC) || defined(CONFIG_RDMA_SIC_MODULE) || defined(CONFIG_RDMA_NET) || defined(CONFIG_RDMA_NET_MODULE))
extern int rdma_apic_init;
extern int rdma_node[];
#endif

#include <asm-l/apic.h>

#endif /*__ASM_APIC_H*/
