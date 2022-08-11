#ifndef _E2K_NUMNODES_H
#define _E2K_NUMNODES_H

#include <linux/numa.h>
#include <linux/topology.h>

#if NODES_SHIFT > 0

#ifndef	DEBUG_NODES_MODE
#define	DEBUG_NODES_MODE	0	/* for each nodes from */
#endif	/* ! DEBUG_NODES_MODE */
#define DebugN(...)		DebugPrintCont(DEBUG_NODES_MODE ,##__VA_ARGS__)

/*
 * The define can be used only for preempt disable mode
 * or argument 'from' is not dinamicaly recalculated expression
 *	as numa_node_id()
 */
#define for_each_node_mask_from_not_preempt(node, from, mask)		\
	for ((node) = (from),						\
		({DebugN("for node %d = from %d, mask "			\
			"0x%lx\n", node, from, mask.bits[0]); }),	\
		((!node_isset((node), (mask))) ?			\
			({DebugN("    node is not set ");		\
			(node) = next_node((node), (mask))		\
			; DebugN("so node is next %d\n", node);})	\
			:						\
			({DebugN("    node is set\n"); 			\
			(node);}));					\
		( ({DebugN("while node %d >= from %d ", node, from);	\
		((node) >= (from));}) ? ({DebugN(" ? node %d < "	\
						"MAX_NUMNODES %d\n",	\
						node, MAX_NUMNODES);	\
					((node) < MAX_NUMNODES);})	\
					:				\
					({DebugN(" : node < from\n");	\
					((node) < (from));}));		\
		(({DebugN("next: node %d >= from %d", node, from);	\
		((node) >= (from));}) ?					\
			({DebugN(" ? ");				\
			((node) = next_node((node), (mask)));		\
				DebugN("node = next %d", node);		\
				DebugN(" node %d >= MAX_NUMNODES %d ",	\
					node, MAX_NUMNODES);		\
				(node) >= MAX_NUMNODES;}) ?		\
				({DebugN(" ? ");			\
				(({((node) = first_node((mask)));	\
					DebugN("node = first %d >= from %d", \
						node, from);		\
					(node) >= (from);}) ?		\
					({DebugN(" ? node = MAX_NUMNODES " \
						"%d\n", MAX_NUMNODES);	\
					(node) = MAX_NUMNODES;})	\
					:				\
					({ DebugN(" : node %d\n", node); \
					(node);}));})			\
				:					\
				({DebugN(" :  node %d\n", node);	\
				(node);})				\
			:						\
			({DebugN(" : ");				\
			({((node) = next_node((node), (mask)));		\
				DebugN("node = next %d", node);		\
				(node) >= (from);}) ?			\
				({DebugN(" ? node = MAX_NUMNODES %d\n",	\
					MAX_NUMNODES);			\
				(node) = MAX_NUMNODES;})		\
				:					\
				({DebugN(" : node %d\n", node);		\
				(node);});})))
/*
 * The define can be used at preempt enable mode, but you should pass
 * additional temporary variable to keep 'from' value
 */
#define for_each_node_mask_from_preempt(node, from, mask, tmp_from)	\
		tmp_from = (from);					\
		for_each_node_mask_from_not_preempt((node), tmp_from, (mask))
#else /* NODES_SHIFT == 0 */
#define for_each_node_mask_from_not_preempt(node, from, mask)		\
		for ((node) = (from); (node) < 1; (node)++)
#define for_each_node_mask_from_preempt(node, from, mask, tmp_from)	\
		for_each_node_mask_from_not_preempt((node), (from), (mask))
#endif /* NODES_SHIFT > 0 */

#define	for_each_cpu_of_node(node, cpu, cpu_mask)			\
		cpu_mask = node_to_present_cpumask(node);		\
		for_each_cpu(cpu, &cpu_mask)

#define for_each_node_from_not_preempt(node, from)			\
		for_each_node_mask_from_not_preempt((node), (from),	\
							node_possible_map)
#define for_each_node_from_preempt(node, from, tmp_from)		\
		for_each_node_mask_from_preempt((node), (from),	\
						node_possible_map, (tmp_from))
#define for_each_online_node_from_not_preempt(node, from)		\
		for_each_node_mask_from_not_preempt((node), (from),	\
							node_online_map)
#define for_each_online_node_from_preempt(node, from, tmp_from)		\
		for_each_node_mask_from_preempt((node), (from),		\
						node_online_map, (tmp_from))
#ifdef	CONFIG_NUMA
#define calculate_node_has_not_dup_kernel_map(node_mask)		 \
({									 \
	nodemask_t	node_present_map;				 \
	nodes_clear(node_present_map);					 \
	memcpy(node_present_map.bits, &phys_nodes_map,			 \
			sizeof(phys_nodes_map));			 \
	nodes_andnot((node_mask), node_present_map,			 \
			node_has_dup_kernel_map);			 \
})
#define	node_has_dup_kernel(nid)					\
		node_isset((nid), node_has_dup_kernel_map)
#define for_each_node_has_dup_kernel(node)				\
		for_each_node_mask((node), node_has_dup_kernel_map)
#define	for_each_node_has_not_dup_kernel(node, node_mask)		\
		calculate_node_has_not_dup_kernel_map((node_mask));	\
		for_each_node_mask((node), (node_mask))
#else	/* ! CONFIG_NUMA */
#define	node_has_dup_kernel(nid) ((nid) == 0)
#define for_each_node_has_dup_kernel(node)	\
		for ((node) = 0; (node) < 1; (node)++)
#endif	/* CONFIG_NUMA */

#endif /* _E2K_NUMNODES_H */
