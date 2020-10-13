#ifndef _ASM_E3K_H_
#define _ASM_E3K_H_

#include <linux/init.h>
#include <asm/mas.h>

#define	E3M_CPU_VENDOR		"Elbrus-MCST"
#define	E3M_CPU_FAMILY		3
#define	E3M_CPU_MODEL		IDR_E3M_MDL
#define	E3M_CPU_REVISION	2

extern void __init boot_e3m_setup_arch(void);
extern void __init e3m_setup_arch(void);
extern int  e3m_get_cpuinfo(char *);

/*
 * Machine (based on e3m processor) topology:
 * e3m is classical SMP system on common memory, so can have only
 * one node and this node include all CPUs
 */

#define	e3m_cpu_to_node(cpu)		(0)
#define	e3m_node_to_cpumask(node, main_cpu_mask)	\
		(main_cpu_mask)
#define	e3m_node_to_first_cpu(node, main_cpu_mask)	\
		(0)	/* CPU #0 should be allways */

#define	boot_e3m_cpu_to_node(cpu)	e3m_cpu_to_node(cpu)
#define	boot_e3m_node_to_cpumask(node, boot_main_cpu_mask)		\
					(boot_main_cpu_mask)

/*
 * IO links and IO controllers topology
 * E3M machines use Intel's chipset PIIX4 connected through own north bridge
 * All other machines use IO links and own chipset and main IO buses controller
 * is IOHUB.
 * Without losing generality, IO controller of E3M can consider as connected
 * through simple IO link too, but it needs do not forget that IO controller
 * is PIIX4 while details are essential
 */
#define	E3M_MAX_NUMIOLINKS	1	/* e3m has only one IO controller */
					/* connected through North bridge */
#define	E3M_NODE_IOLINKS	E3M_MAX_NUMIOLINKS

#endif /* ASM_E3M_H_ */
