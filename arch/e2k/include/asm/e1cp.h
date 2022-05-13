#ifndef _ASM_E1CP_H_
#define _ASM_E1CP_H_

/*
 * Machine (based on E1C+ processor) topology:
 * E1C+ is one core CPU + graphical processor to support 3D, so
 * - is not NUMA system
 * - is not SMP system
 */

#ifndef __ASSEMBLY__
extern void boot_e1cp_setup_arch(void);
extern void e1cp_setup_machine(void);
#endif

#define E1CP_NR_NODE_CPUS		1
#define E1CP_MAX_NR_NODE_CPUS		E1CP_NR_NODE_CPUS

#define	E1CP_NODE_IOLINKS		2

#define	E1CP_PCICFG_AREA_PHYS_BASE	0x000000ff10000000UL
#define	E1CP_PCICFG_AREA_SIZE		0x0000000010000000UL

#define E1CP_SIC_MC_COUNT		2

#endif /* _ASM_E1CP_H_ */
