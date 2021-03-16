#ifndef _ASM_ES2_H_
#define _ASM_ES2_H_

/*
 * Machine (based on E2C+ processor) topology:
 * E2C+ is NUMA system on distributed memory and can have several nodes.
 * Each node can have some memory (faster to access) and max 4 CPUs (cores),
 * but real processor chip has only two cores (2 other should be considered
 * as always disabled). So online CPU numbers will be 0, 1, 4, 5, 8, 9 ...
 * Node number is the same as chip-processor number
 * Some nodes (CPUs) can be without memory
 * LAPIC cluster number is the same as node number
 */

#ifndef __ASSEMBLY__
struct pt_regs;

extern void boot_es2_setup_arch(void);
extern void es2_setup_machine(void);
extern void setup_APIC_vector_handler(int vector,
		void (*handler)(struct pt_regs *), bool system, char *name);
extern void eldsp_interrupt(struct pt_regs *regs);
#endif

#define	ES2_CPU_VENDOR			"Elbrus-MCST"
#define	ES2_CPU_FAMILY			4

#define	ES2_NR_NODE_CPUS		2
#define	ES2_MAX_NR_NODE_CPUS		4

#define	ES2_NODE_IOLINKS		2

#define	ES2_PCICFG_AREA_PHYS_BASE	0x0000000200000000UL
#define	ES2_PCICFG_AREA_SIZE		0x0000000010000000UL

#define ES2_NSR_AREA_PHYS_BASE		0x0000000110000000UL

#define	ES2_NBSR_AREA_OFFSET		0x0000000000000000UL
#define	ES2_NBSR_AREA_SIZE		0x0000000000100000UL

#define ES2_COPSR_AREA_PHYS_BASE	0x00000001c0000000UL
#define	ES2_COPSR_AREA_SIZE		0x0000000001000000UL

#define ES2_MLT_SIZE			16

#define	ES2_TLB_LINES_BITS_NUM		8
#define ES2_TLB_ADDR_LINE_NUM		0x00000000000ff000
#define ES2_TLB_ADDR_LINE_NUM2		0x000000003fc00000
#define ES2_TLB_ADDR_LINE_NUM_SHIFT2	22
#define ES2_TLB_ADDR_SET_NUM		0x0000000000000018
#define ES2_TLB_ADDR_SET_NUM_SHIFT	3

#define ES2_SIC_MC_COUNT		2
#define ES2_SIC_MC1_ECC			0x500

#define ES2_CLOCK_TICK_RATE		10000000

#define ES2_L1_CACHE_SHIFT		5
#define ES2_L1_CACHE_BYTES		(1 << ES2_L1_CACHE_SHIFT)
#define ES2_L2_CACHE_SHIFT		6
#define ES2_L2_CACHE_BYTES		(1 << ES2_L2_CACHE_SHIFT)

#endif /* _ASM_ES2_H_ */
