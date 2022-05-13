#ifndef _ASM_E12C_H_
#define _ASM_E12C_H_

/*
 * Machine (based on E12C processor) topology:
 * E12C is NUMA system on distributed memory and can have several nodes.
 * Each node can have some memory (faster to access) and max 12 CPUs (cores)
 * Node number is the same as chip-processor number
 * Some nodes (CPUs) can be without memory
 * LAPIC cluster number is the same as node number
 */

#ifndef __ASSEMBLY__
struct pt_regs;

extern void boot_e12c_setup_arch(void);
extern void e12c_setup_machine(void);
#endif

#define	E12C_NR_NODE_CPUS		12
#define	E12C_MAX_NR_NODE_CPUS		16

#define	E12C_NODE_IOLINKS		1

#define	E12C_PCICFG_AREA_PHYS_BASE	E2S_PCICFG_AREA_PHYS_BASE
#define	E12C_PCICFG_AREA_SIZE		E2S_PCICFG_AREA_SIZE

#define E12C_NSR_AREA_PHYS_BASE		E2S_NSR_AREA_PHYS_BASE

#define E12C_SIC_MC_SIZE		E16C_SIC_MC_SIZE
#define E12C_SIC_MC_COUNT		2

#define E12C_L3_CACHE_SHIFT		E8C_L3_CACHE_SHIFT
#define E12C_L3_CACHE_BYTES		E8C_L3_CACHE_BYTES

#endif /* _ASM_E12C_H_ */
