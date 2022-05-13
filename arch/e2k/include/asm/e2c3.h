#ifndef _ASM_E2C3_H_
#define _ASM_E2C3_H_

/*
 * Machine (based on E2C3 processor) topology:
 * E2C3 is NUMA system on distributed memory and can have several nodes.
 * Each node can have some memory (faster to access) and max 2 CPUs (cores)
 * Node number is the same as chip-processor number
 * Some nodes (CPUs) can be without memory
 * LAPIC cluster number is the same as node number
 */

#ifndef __ASSEMBLY__
struct pt_regs;

extern void boot_e2c3_setup_arch(void);
extern void e2c3_setup_machine(void);
#endif

#define	E2C3_NR_NODE_CPUS		2
#define	E2C3_MAX_NR_NODE_CPUS		16

#define	E2C3_NODE_IOLINKS		1

#define	E2C3_PCICFG_AREA_PHYS_BASE	E2S_PCICFG_AREA_PHYS_BASE
#define	E2C3_PCICFG_AREA_SIZE		E2S_PCICFG_AREA_SIZE

#define E2C3_NSR_AREA_PHYS_BASE		E2S_NSR_AREA_PHYS_BASE

#define E2C3_SIC_MC_SIZE		E16C_SIC_MC_SIZE
#define E2C3_SIC_MC_COUNT		E12C_SIC_MC_COUNT

#endif /* _ASM_E2C3_H_ */
