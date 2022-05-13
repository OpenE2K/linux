#ifndef _ASM_E8C_H_
#define _ASM_E8C_H_

/*
 * Machine (based on E8C processor) topology:
 * E8C is NUMA system on distributed memory and can have several nodes.
 * Each node can have some memory (faster to access) and max 8 CPUs (cores)
 * Node number is the same as chip-processor number
 * Some nodes (CPUs) can be without memory
 * LAPIC cluster number is the same as node number
 */

#ifndef __ASSEMBLY__
struct pt_regs;

extern void boot_e8c_setup_arch(void);
extern void e8c_setup_machine(void);
extern void sic_error_interrupt(struct pt_regs *regs);
#endif

#define	E8C_NR_NODE_CPUS		8
#define	E8C_MAX_NR_NODE_CPUS		16

#define	E8C_NODE_IOLINKS		1

#define	E8C_PCICFG_AREA_PHYS_BASE	E2S_PCICFG_AREA_PHYS_BASE
#define	E8C_PCICFG_AREA_SIZE		E2S_PCICFG_AREA_SIZE

#define E8C_NSR_AREA_PHYS_BASE		E2S_NSR_AREA_PHYS_BASE

#define E8C_SIC_MC_SIZE			0xe4
#define E8C_SIC_MC_COUNT		4

#define E8C_L3_CACHE_SHIFT		6
#define E8C_L3_CACHE_BYTES		(1 << E8C_L3_CACHE_SHIFT)

#endif /* _ASM_E8C_H_ */
