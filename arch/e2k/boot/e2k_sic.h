#ifndef _BOOT_E2K_SIC_H_
#define _BOOT_E2K_SIC_H_

#include <linux/init.h>
#include <linux/nodemask.h>

#include <asm/e2k_api.h>
#include <asm/e2s.h>
#include <asm/e1cp.h>
#include <asm/e8c.h>
#include <asm/e8c2.h>
#include <asm/e2k_sic.h>

/*
 * NBR area configuration
 */
#undef	BOOT_NSR_AREA_PHYS_BASE

#if	defined(CONFIG_E2S)
#define	BOOT_NSR_AREA_PHYS_BASE		E2S_NSR_AREA_PHYS_BASE
#elif	defined(CONFIG_E8C)
#define	BOOT_NSR_AREA_PHYS_BASE		E8C_NSR_AREA_PHYS_BASE
#elif	defined(CONFIG_E8C2)
#define	BOOT_NSR_AREA_PHYS_BASE		E8C2_NSR_AREA_PHYS_BASE
#elif	defined(CONFIG_E1CP)
#define	BOOT_NSR_AREA_PHYS_BASE		E1CP_NSR_AREA_PHYS_BASE
#elif	defined(CONFIG_E12C)
#define	BOOT_NSR_AREA_PHYS_BASE		E12C_NSR_AREA_PHYS_BASE
#elif	defined(CONFIG_E16C)
#define	BOOT_NSR_AREA_PHYS_BASE		E16C_NSR_AREA_PHYS_BASE
#elif	defined(CONFIG_E2C3)
#define	BOOT_NSR_AREA_PHYS_BASE		E2C3_NSR_AREA_PHYS_BASE
#endif

/*
 * Nodes system registers area - NSR = { NSR0 ... NSRj ... }
 * NSR is some part of common system communicator area SR
 */
#define	BOOT_NODE_NSR_SIZE		BOOT_NSR_AREA_SIZE
#undef	THE_NODE_NSR_PHYS_BASE
#define	THE_NODE_NSR_PHYS_BASE(node)	\
		(BOOT_NSR_AREA_PHYS_BASE + (node * BOOT_NODE_NSR_SIZE))

/*
 * Nodes processor system registers (north bridge)
 * NBSR = { NBSR0 ... NBSRj ... }
 * NBSR is some part of node system registers area NSR
 */
#define	BOOT_NODE_NBSR_OFFSET		BOOT_NBSR_OFFSET
#undef	THE_NODE_NBSR_PHYS_BASE
#define	THE_NODE_NBSR_PHYS_BASE(node)	\
		((unsigned char *)(THE_NODE_NSR_PHYS_BASE(node) + \
						BOOT_NODE_NBSR_OFFSET))

#endif /* _BOOT_E2K_SIC_H_ */
