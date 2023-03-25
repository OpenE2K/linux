#ifndef _BOOT_TOPOLOGY_H_
#define _BOOT_TOPOLOGY_H_

#include <linux/numa.h>
#ifdef	CONFIG_NUMA
#include <linux/cpumask.h>
#endif	/* CONFIG_NUMA */
#include <asm/e2s.h>
#include <asm/e8c.h>
#include <asm/e8c2.h>
#include <asm/e1cp.h>
#include <asm/e12c.h>
#include <asm/e16c.h>
#include <asm/e2c3.h>

/*
 * IO links/controllers/buses topology:
 * each node of e2k machines can have from 1 to MAX_NODE_IOLINKS IO links
 * which can be connected to IOHUB or RDMA
 * Real possible number of IO links on node is described by following
 * macroses for every type of machines
 */

#undef	E2K_NODE_IOLINKS

#if	defined(CONFIG_E2S)
#define	E2K_NODE_IOLINKS	E2S_NODE_IOLINKS
#elif	defined(CONFIG_E8C)
#define	E2K_NODE_IOLINKS	E8C_NODE_IOLINKS
#elif	defined(CONFIG_E8C2)
#define	E2K_NODE_IOLINKS	E8C2_NODE_IOLINKS
#elif	defined(CONFIG_E1CP)
#define	E2K_NODE_IOLINKS	E1CP_NODE_IOLINKS
#elif	defined(CONFIG_E12C)
#define	E2K_NODE_IOLINKS	E12C_NODE_IOLINKS
#elif	defined(CONFIG_E16C)
#define	E2K_NODE_IOLINKS	E16C_NODE_IOLINKS
#elif	defined(CONFIG_E2C3)
#define	E2K_NODE_IOLINKS	E2C3_NODE_IOLINKS
#endif

#endif /* _BOOT_TOPOLOGY_H_ */
