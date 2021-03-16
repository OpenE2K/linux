#ifndef _ASM_E16C_H_
#define _ASM_E16C_H_

/*
 * Machine (based on E16C processor) topology:
 * E16C is NUMA system on distributed memory and can have several nodes.
 * Each node can have some memory (faster to access) and max 16 CPUs (cores)
 * Node number is the same as chip-processor number
 * Some nodes (CPUs) can be without memory
 * LAPIC cluster number is the same as node number
 */

#ifndef __ASSEMBLY__
struct pt_regs;

extern void boot_e16c_setup_arch(void);
extern void e16c_setup_machine(void);
extern void setup_APIC_vector_handler(int vector,
		void (*handler)(struct pt_regs *), bool system, char *name);
#endif

#define	E16C_CPU_VENDOR			ES2_CPU_VENDOR
#define	E16C_CPU_FAMILY			6

#define	E16C_NR_NODE_CPUS		16
#define	E16C_MAX_NR_NODE_CPUS		16

#define	E16C_NODE_IOLINKS		1

#define	E16C_PCICFG_AREA_PHYS_BASE	ES2_PCICFG_AREA_PHYS_BASE
#define	E16C_PCICFG_AREA_SIZE		ES2_PCICFG_AREA_SIZE

#define E16C_NSR_AREA_PHYS_BASE		ES2_NSR_AREA_PHYS_BASE

#define	E16C_NBSR_AREA_OFFSET		ES2_NBSR_AREA_OFFSET
#define	E16C_NBSR_AREA_SIZE		ES2_NBSR_AREA_SIZE

#define E16C_COPSR_AREA_PHYS_BASE	ES2_COPSR_AREA_PHYS_BASE
#define	E16C_COPSR_AREA_SIZE		ES2_COPSR_AREA_SIZE

#define E16C_MLT_SIZE			ES2_MLT_SIZE

#define	E16C_TLB_LINES_BITS_NUM		ES2_TLB_LINES_BITS_NUM
#define E16C_TLB_ADDR_LINE_NUM		E2S_TLB_ADDR_LINE_NUM
#define E16C_TLB_ADDR_LINE_NUM2		E2S_TLB_ADDR_LINE_NUM2
#define E16C_TLB_ADDR_LINE_NUM_SHIFT2	E2S_TLB_ADDR_LINE_NUM_SHIFT2
#define E16C_TLB_ADDR_SET_NUM		E2S_TLB_ADDR_SET_NUM
#define E16C_TLB_ADDR_SET_NUM_SHIFT	E2S_TLB_ADDR_SET_NUM_SHIFT

#define E16C_SIC_MC_COUNT		E8C_SIC_MC_COUNT
#define E16C_SIC_MC1_ECC		E2S_SIC_MC1_ECC

#define E16C_CLOCK_TICK_RATE		ES2_CLOCK_TICK_RATE

#define E16C_L1_CACHE_SHIFT		ES2_L1_CACHE_SHIFT
#define E16C_L1_CACHE_BYTES		ES2_L1_CACHE_BYTES
#define E16C_L2_CACHE_SHIFT		ES2_L2_CACHE_SHIFT
#define E16C_L2_CACHE_BYTES		ES2_L2_CACHE_BYTES
#define E16C_L3_CACHE_SHIFT		E8C_L3_CACHE_SHIFT
#define E16C_L3_CACHE_BYTES		E8C_L3_CACHE_BYTES

#endif /* _ASM_E16C_H_ */
