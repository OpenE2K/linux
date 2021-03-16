#ifndef _ASM_E8C2_H_
#define _ASM_E8C2_H_

/*
 * Machine (based on E8C2 processor) topology:
 * E8C2 is NUMA system on distributed memory and can have several nodes.
 * Each node can have some memory (faster to access) and max 8 CPUs (cores)
 * Node number is the same as chip-processor number
 * Some nodes (CPUs) can be without memory
 * LAPIC cluster number is the same as node number
 */

#ifndef __ASSEMBLY__
struct pt_regs;

extern void boot_e8c2_setup_arch(void);
extern void e8c2_setup_machine(void);
extern void setup_APIC_vector_handler(int vector,
		void (*handler)(struct pt_regs *), bool system, char *name);
extern void sic_error_interrupt(struct pt_regs *regs);
#endif

#define	E8C2_CPU_VENDOR			ES2_CPU_VENDOR
#define	E8C2_CPU_FAMILY			5

#define	E8C2_NR_NODE_CPUS		E8C_NR_NODE_CPUS
#define	E8C2_MAX_NR_NODE_CPUS		E8C_MAX_NR_NODE_CPUS

#define	E8C2_NODE_IOLINKS		E8C_NODE_IOLINKS

#define	E8C2_PCICFG_AREA_PHYS_BASE	ES2_PCICFG_AREA_PHYS_BASE
#define	E8C2_PCICFG_AREA_SIZE		ES2_PCICFG_AREA_SIZE

#define E8C2_NSR_AREA_PHYS_BASE		ES2_NSR_AREA_PHYS_BASE

#define	E8C2_NBSR_AREA_OFFSET		ES2_NBSR_AREA_OFFSET
#define	E8C2_NBSR_AREA_SIZE		ES2_NBSR_AREA_SIZE

#define E8C2_COPSR_AREA_PHYS_BASE	ES2_COPSR_AREA_PHYS_BASE
#define	E8C2_COPSR_AREA_SIZE		ES2_COPSR_AREA_SIZE

#define E8C2_MLT_SIZE			ES2_MLT_SIZE

#define	E8C2_TLB_LINES_BITS_NUM		ES2_TLB_LINES_BITS_NUM
#define E8C2_TLB_ADDR_LINE_NUM		E2S_TLB_ADDR_LINE_NUM
#define E8C2_TLB_ADDR_LINE_NUM2		E2S_TLB_ADDR_LINE_NUM2
#define E8C2_TLB_ADDR_LINE_NUM_SHIFT2	E2S_TLB_ADDR_LINE_NUM_SHIFT2
#define E8C2_TLB_ADDR_SET_NUM		E2S_TLB_ADDR_SET_NUM
#define E8C2_TLB_ADDR_SET_NUM_SHIFT	E2S_TLB_ADDR_SET_NUM_SHIFT

#define E8C2_SIC_MC_SIZE		0xf4
#define E8C2_SIC_MC_COUNT		E8C_SIC_MC_COUNT
#define E8C2_SIC_MC1_ECC		E2S_SIC_MC1_ECC

#define E8C2_CLOCK_TICK_RATE		ES2_CLOCK_TICK_RATE

#define E8C2_L1_CACHE_SHIFT		ES2_L1_CACHE_SHIFT
#define E8C2_L1_CACHE_BYTES		ES2_L1_CACHE_BYTES
#define E8C2_L2_CACHE_SHIFT		ES2_L2_CACHE_SHIFT
#define E8C2_L2_CACHE_BYTES		ES2_L2_CACHE_BYTES
#define E8C2_L3_CACHE_SHIFT		E8C_L3_CACHE_SHIFT
#define E8C2_L3_CACHE_BYTES		E8C_L3_CACHE_BYTES

#endif /* _ASM_E8C2_H_ */
