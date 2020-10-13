#ifndef __ASM_APIC_H
#define __ASM_APIC_H

#include <linux/types.h>
#include <asm/sections.h>
#include <asm/apicdef.h>
#include <asm/irq.h>
#include <asm/e90s.h>

/*
 * IDT vectors usable for external interrupt sources start
 * at 0x20:
 */
//#define FIRST_EXTERNAL_VECTOR	0x20

//#define SYSCALL_VECTOR		0x80


//#define THERMAL_APIC_VECTOR	0xf0

/*
 * Local APIC cluster (quad) congiguration
 */
#define	MAX_APIC_QUADS		E90S_MAX_APIC_QUADS
#define	apic_quad_to_cpumask(quad)			\
		e90s_apic_quad_to_cpumask(quad, cpu_online_map)
#define	cpu_to_apic_quad(cpu)	e90s_cpu_to_apic_quad(cpu)
#define	cpu_to_apic_cpu(cpu)	e90s_cpu_to_apic_cpu(cpu)

#ifndef __ASSEMBLY__

/*
 * Basic functions accessing APICs.
 */
static inline void arch_apic_write(unsigned long reg, unsigned long v)
{
	__asm__ __volatile__("membar #Sync\n\t"
			     "stwa %0, [%1] %2\n\t"
			     "membar #Sync"
			     : /* no outputs */
			     : "r" (v), "r" (reg), "i" (ASI_LAPIC)
			     : "memory");
}
static inline unsigned long arch_apic_read(unsigned long reg)
{
	u32 dword;
	__asm__ __volatile__("membar #Sync\n\t"
			     "lduwa [%1] %2, %0\n\t"
			     "membar #Sync"
			     : "=r" (dword)
			     : "r" (reg), "i" (ASI_LAPIC)
			     : "memory");	
	return dword;
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
