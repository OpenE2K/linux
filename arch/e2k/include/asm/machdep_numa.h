#ifndef _E2K_MACHDEP_NUMA_H_
#define _E2K_MACHDEP_NUMA_H_

#include <asm/machdep.h>
#include <asm/p2v/boot_v2p.h>

#ifdef	CONFIG_NUMA
#define	the_node_machine(nid)	\
		((machdep_t *)__va(vpa_to_pa( \
					node_kernel_va_to_pa(nid, &machine))))
#define	node_machine		the_node_machine(numa_node_id())
#define	the_node_pgtable_struct(nid)	\
		((pt_struct_t *)__va(vpa_to_pa(node_kernel_va_to_pa(nid, \
							&pgtable_struct))))
#define	node_pgtable_struct	the_node_pgtable_struct(numa_node_id())
#else	/* ! CONFIG_NUMA */
#define	the_node_machine(nid)	(&machine)
#define	node_machine		the_node_machine(0)
#define	the_node_pgtable_struct(nid)	(&pgtable_struct)
#define	node_pgtable_struct		the_node_pgtable_struct(0)
#endif	/* CONFIG_NUMA */

#endif
