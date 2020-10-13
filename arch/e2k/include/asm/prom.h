#ifndef __E2K_PROM_H
#define __E2K_PROM_H

#ifdef CONFIG_OF
#define OF_ROOT_NODE_ADDR_CELLS_DEFAULT 2
#define OF_ROOT_NODE_SIZE_CELLS_DEFAULT 1

#define of_compat_cmp(s1, s2, l)	strncmp((s1), (s2), (l))
#define of_prop_cmp(s1, s2)		strcasecmp((s1), (s2))
#define of_node_cmp(s1, s2)		strcmp((s1), (s2))

int of_getintprop_default(struct device_node *np, const char *name, int def);

#define of_node_to_nid(dp)      (NUMA_NO_NODE)
#endif

#endif /* __E2K_PROM_H */
