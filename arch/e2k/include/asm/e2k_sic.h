#ifndef _ASM_E2K_SIC_H_
#define _ASM_E2K_SIC_H_

#include <linux/init.h>
#include <linux/numa.h>
#include <linux/nodemask.h>

#include <asm-l/mpspec.h>
#include <asm/e2k.h>
#include <asm/e2k_api.h>
#include <asm/mas.h>
#include <asm/e3s.h>
#include <asm/es2.h>
#include <asm/e2s.h>
#include <asm/e8c.h>
#include <asm/hb_regs.h>

#ifndef	CONFIG_E2K_MACHINE
extern int boot_get_e2k_machine_id(void);
#endif	/* CONFIG_E2K_MACHINE */

extern int e2k_sic_get_vector(void);

/*
 * NBR area configuration
 */

#define	E2K_NSR_AREA_PHYS_BASE			\
({						\
	u64 ret = -1;				\
						\
	if (IS_MACHINE_E3S)			\
		ret = E3S_NSR_AREA_PHYS_BASE;	\
	else if (IS_MACHINE_ES2)		\
		ret = ES2_NSR_AREA_PHYS_BASE;	\
	else if (IS_MACHINE_E2S)		\
		ret = E2S_NSR_AREA_PHYS_BASE;	\
	else if (IS_MACHINE_E8C)		\
		ret = E8C_NSR_AREA_PHYS_BASE;	\
	else if (IS_MACHINE_E1CP)		\
		ret = E1CP_NSR_AREA_PHYS_BASE;	\
	else if (IS_MACHINE_E8C2)		\
		ret = E8C2_NSR_AREA_PHYS_BASE;	\
	else					\
		BUG();				\
						\
	ret;					\
})

#define	E2K_NSR_AREA_SIZE			\
({						\
	u64 ret = -1;				\
						\
	if (IS_MACHINE_E3S)			\
		ret = E3S_NSR_AREA_SIZE;	\
	else if (IS_MACHINE_ES2)		\
		ret = ES2_NBSR_AREA_SIZE;	\
	else if (IS_MACHINE_E2S)		\
		ret = E2S_NBSR_AREA_SIZE;	\
	else if (IS_MACHINE_E8C)		\
		ret = E8C_NBSR_AREA_SIZE;	\
	else if (IS_MACHINE_E1CP)		\
		ret = E1CP_NBSR_AREA_SIZE;	\
	else if (IS_MACHINE_E8C2)		\
		ret = E8C2_NBSR_AREA_SIZE;	\
	else					\
		BUG();				\
						\
	ret;					\
})

#define	E2K_NBSR_OFFSET				\
({						\
	u64 ret = -1;				\
						\
	if (IS_MACHINE_E3S)			\
		ret = E3S_NBSR_AREA_OFFSET;	\
	else if (IS_MACHINE_ES2)		\
		ret = ES2_NBSR_AREA_OFFSET;	\
	else if (IS_MACHINE_E2S)		\
		ret = E2S_NBSR_AREA_OFFSET;	\
	else if (IS_MACHINE_E8C)		\
		ret = E8C_NBSR_AREA_OFFSET;	\
	else if (IS_MACHINE_E1CP)		\
		ret = E1CP_NBSR_AREA_OFFSET;	\
	else if (IS_MACHINE_E8C2)		\
		ret = E8C2_NBSR_AREA_OFFSET;	\
	else					\
		BUG();				\
						\
	ret;					\
})

#define	E2K_NBSR_SIZE				\
({						\
	u64 ret = -1;				\
						\
	if (IS_MACHINE_E3S)			\
		ret = E3S_NBSR_AREA_SIZE;	\
	else if (IS_MACHINE_ES2)		\
		ret = ES2_NBSR_AREA_SIZE;	\
	else if (IS_MACHINE_E2S)		\
		ret = E2S_NBSR_AREA_SIZE;	\
	else if (IS_MACHINE_E8C)		\
		ret = E8C_NBSR_AREA_SIZE;	\
	else if (IS_MACHINE_E1CP)		\
		ret = E1CP_NBSR_AREA_SIZE;	\
	else if (IS_MACHINE_E8C2)		\
		ret = E8C2_NBSR_AREA_SIZE;	\
	else					\
		BUG();				\
						\
	ret;					\
})

#define	E2K_COPSR_AREA_PHYS_BASE			\
({							\
	u64 ret = -1;					\
							\
	if (IS_MACHINE_ES2)				\
		ret = ES2_COPSR_AREA_PHYS_BASE		\
	else if (IS_MACHINE_E2S)			\
		ret = E2S_COPSR_AREA_PHYS_BASE;		\
	else if (IS_MACHINE_E8C)			\
		ret = E8C_COPSR_AREA_PHYS_BASE;		\
	else if (IS_MACHINE_E8C2)			\
		ret = E8C2_COPSR_AREA_PHYS_BASE;	\
	else						\
		BUG();					\
							\
	ret;						\
})

#define	E2K_COPSR_AREA_SIZE			\
({						\
	u64 ret = -1;				\
						\
	if (IS_MACHINE_ES2)			\
		ret = ES2_COPSR_AREA_SIZE;	\
	else if (IS_MACHINE_E2S)		\
		ret = E2S_COPSR_AREA_SIZE;	\
	else if (IS_MACHINE_E8C)		\
		ret = E8C_COPSR_AREA_SIZE;	\
	else if (IS_MACHINE_E8C2)		\
		ret = E8C2_COPSR_AREA_SIZE;	\
	else					\
		BUG();				\
						\
	ret;					\
})

/*
 * Nodes system registers area - NSR = { NSR0 ... NSRj ... }
 * NSR is some part of common system communicator area SR
 */
#define	NODE_NSR_SIZE			E2K_NSR_AREA_SIZE
#define	THE_NODE_NSR_PHYS_BASE(node)	\
		(E2K_NSR_AREA_PHYS_BASE + (node * NODE_NSR_SIZE))
#define	NODE_NSR_PHYS_BASE()		\
		THE_NODE_NSR_PHYS_BASE(node_numa_id())

/*
 * Nodes processor system registers (north bridge)
 * NBSR = { NBSR0 ... NBSRj ... }
 * NBSR is some part of node system registers area NSR
 */
#define	NODE_NBSR_SIZE			E2K_NBSR_SIZE
#define	NODE_NBSR_OFFSET		E2K_NBSR_OFFSET
#define	THE_NODE_NBSR_PHYS_BASE(node)	\
		((unsigned char *)(THE_NODE_NSR_PHYS_BASE(node) + \
						NODE_NBSR_OFFSET))
#define	NODE_NBSR_PHYS_BASE()		\
		THE_NODE_NBSR_PHYS_BASE(node_numa_id())

/*
 * Nodes system coprocessors registers area - COPSR = { COPSR0 ... COPSRj ... }
 */
#define	NODE_COPSR_SIZE			E2K_COPSR_AREA_SIZE
#define	THE_NODE_COPSR_PHYS_BASE(node)	\
		(E2K_COPSR_AREA_PHYS_BASE + (node * NODE_COPSR_SIZE))
#define	NODE_COPSR_PHYS_BASE()		\
	    THE_NODE_COPSR_PHYS_BASE(node_numa_id())

extern unsigned char *nodes_nbsr_base[/*MAX_NUMNODES*/];

extern void __init boot_e2k_sic_setup_arch(void);

extern int __init e2k_sic_init(void);
extern int __init e2k_early_iohub_online(int node, int link);

static inline unsigned char *
sic_get_node_nbsr_base(int node_id)
{
	return nodes_nbsr_base[node_id];
}

#define sic_domain_pci_conf_base(domain) \
({ \
	unsigned long __ret; \
 \
	if (IS_MACHINE_E3S) \
		__ret = e3s_domain_pci_conf_base(domain); \
	else if (IS_MACHINE_ES2) \
		__ret = es2_domain_pci_conf_base(domain); \
	else if (IS_MACHINE_E2S) \
		__ret = e2s_domain_pci_conf_base(domain); \
	else if (IS_MACHINE_E8C) \
		__ret = e8c_domain_pci_conf_base(domain); \
	else if (IS_MACHINE_E1CP) \
		__ret = e1cp_domain_pci_conf_base(domain); \
	else if (IS_MACHINE_E8C2) \
		__ret = e8c2_domain_pci_conf_base(domain); \
	else { \
		printk(KERN_ERR "sic_domain_pci_conf_base() " \
				"unknown or invalid machine type\n"); \
		__ret = 0; \
	} \
	__ret; \
})

extern unsigned long domain_to_pci_conf_base[];

static inline unsigned long
domain_pci_conf_base(unsigned int domain)
{
	return (domain_to_pci_conf_base[domain]);
}

#endif /* _ASM_E2K_SIC_H_ */
