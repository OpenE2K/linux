#ifndef _ASM_E2S_H_
#define _ASM_E2S_H_

/*
 * Machine (based on E4C processor) topology:
 * E4C is NUMA system on distributed memory and can have several nodes.
 * Each node can have some memory (faster to access) and max 4 CPUs (cores)
 * Node number is the same as chip-processor number
 * Some nodes (CPUs) can be without memory
 * LAPIC cluster number is the same as node number
 */

#ifndef __ASSEMBLY__
struct pt_regs;

extern void boot_e2s_setup_arch(void);
extern void e2s_setup_machine(void);
extern void sic_error_interrupt(struct pt_regs *regs);
#endif

#define	E2S_NR_NODE_CPUS		4
#define	E2S_MAX_NR_NODE_CPUS		E2S_NR_NODE_CPUS

#define	E2S_NODE_IOLINKS		1

#define	E2S_PCICFG_AREA_PHYS_BASE	0x0000000200000000UL
#define	E2S_PCICFG_AREA_SIZE		0x0000000010000000UL

#define E2S_NSR_AREA_PHYS_BASE		0x0000000110000000UL

#define E2S_SIC_MC_SIZE			0xa4
#define E2S_SIC_MC_COUNT		3

#endif /* _ASM_E2S_H_ */
