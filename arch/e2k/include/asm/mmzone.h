#ifndef _E2K_MMZONE_H_
#define _E2K_MMZONE_H_

#include <linux/nodemask.h>
#include <linux/topology.h>

#include <asm/smp.h>
#include <asm/numnodes.h>

#define __NODE_DATA(ndata, nid)	((ndata)[(nid)])

#ifdef CONFIG_NEED_MULTIPLE_NODES
extern pg_data_t *node_data[];
#define	NODE_DATA(nid)		__NODE_DATA(node_data, nid)
#endif

#define kvaddr_to_nid(kaddr)	pfn_to_nid(__pa(kaddr) >> PAGE_SHIFT)

#endif /* _E2K_MMZONE_H_ */
