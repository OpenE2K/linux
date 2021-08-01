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
extern void setup_APIC_vector_handler(int vector,
		void (*handler)(struct pt_regs *), bool system, char *name);
#endif

#define	E2C3_CPU_VENDOR			ES2_CPU_VENDOR
#define	E2C3_CPU_FAMILY			E16C_CPU_FAMILY

#define	E2C3_NR_NODE_CPUS		2
#define	E2C3_MAX_NR_NODE_CPUS		16

#define	E2C3_NODE_IOLINKS		1

#define	E2C3_PCICFG_AREA_PHYS_BASE	ES2_PCICFG_AREA_PHYS_BASE
#define	E2C3_PCICFG_AREA_SIZE		ES2_PCICFG_AREA_SIZE

#define E2C3_NSR_AREA_PHYS_BASE		ES2_NSR_AREA_PHYS_BASE

#define	E2C3_NBSR_AREA_OFFSET		ES2_NBSR_AREA_OFFSET
#define	E2C3_NBSR_AREA_SIZE		ES2_NBSR_AREA_SIZE

#define E2C3_COPSR_AREA_PHYS_BASE	ES2_COPSR_AREA_PHYS_BASE
#define	E2C3_COPSR_AREA_SIZE		ES2_COPSR_AREA_SIZE

#define E2C3_MLT_SIZE			ES2_MLT_SIZE

#define	E2C3_TLB_LINES_BITS_NUM		ES2_TLB_LINES_BITS_NUM
#define E2C3_TLB_ADDR_LINE_NUM		E2S_TLB_ADDR_LINE_NUM
#define E2C3_TLB_ADDR_LINE_NUM2		E2S_TLB_ADDR_LINE_NUM2
#define E2C3_TLB_ADDR_LINE_NUM_SHIFT2	E2S_TLB_ADDR_LINE_NUM_SHIFT2
#define E2C3_TLB_ADDR_SET_NUM		E2S_TLB_ADDR_SET_NUM
#define E2C3_TLB_ADDR_SET_NUM_SHIFT	E2S_TLB_ADDR_SET_NUM_SHIFT

#define E2C3_SIC_MC_SIZE		E16C_SIC_MC_SIZE
#define E2C3_SIC_MC_COUNT		E12C_SIC_MC_COUNT

#define E2C3_CLOCK_TICK_RATE		ES2_CLOCK_TICK_RATE

#define E2C3_L1_CACHE_SHIFT		ES2_L1_CACHE_SHIFT
#define E2C3_L1_CACHE_BYTES		ES2_L1_CACHE_BYTES
#define E2C3_L2_CACHE_SHIFT		ES2_L2_CACHE_SHIFT
#define E2C3_L2_CACHE_BYTES		ES2_L2_CACHE_BYTES

#endif /* _ASM_E2C3_H_ */
