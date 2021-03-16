#ifndef _ASM_E2K_SIC_H_
#define _ASM_E2K_SIC_H_

#include <linux/init.h>
#include <linux/mmdebug.h>
#include <linux/numa.h>
#include <linux/nodemask.h>

#include <asm-l/mpspec.h>
#include <asm/e2k.h>
#include <asm/e2k_api.h>
#include <asm/mas.h>
#include <asm/es2.h>
#include <asm/e2s.h>
#include <asm/e8c.h>
#include <asm/e16c.h>
#include <asm/e12c.h>
#include <asm/e2c3.h>

/*
 * NBR area configuration
 */
#define	E2K_NSR_AREA_PHYS_BASE		(machine.get_nsr_area_phys_base())
#define	E2K_NSR_AREA_SIZE		(machine.nbsr_area_size)
#define	E2K_NBSR_OFFSET			(machine.nbsr_area_offset)
#define	E2K_NBSR_SIZE			(machine.nbsr_area_size)
#define	E2K_COPSR_AREA_PHYS_BASE	(machine.copsr_area_phys_base)
#define	E2K_COPSR_AREA_SIZE		(machine.copsr_area_size)

#define	BOOT_NSR_AREA_PHYS_BASE		(boot_machine.nsr_area_phys_base)
#define	BOOT_NSR_AREA_SIZE		(boot_machine.nbsr_area_size)
#define	BOOT_NBSR_OFFSET		(boot_machine.nbsr_area_offset)
#define	BOOT_NBSR_SIZE			(boot_machine.nbsr_area_size)
#define	BOOT_COPSR_AREA_PHYS_BASE	(boot_machine.copsr_area_phys_base)
#define	BOOT_COPSR_AREA_SIZE		(boot_machine.copsr_area_size)

/*
 * Nodes system registers area - NSR = { NSR0 ... NSRj ... }
 * NSR is some part of common system communicator area SR
 */
#define	NODE_NSR_SIZE			E2K_NSR_AREA_SIZE
#define	THE_NODE_NSR_PHYS_BASE(node)	\
		(E2K_NSR_AREA_PHYS_BASE + (node * NODE_NSR_SIZE))

#define	BOOT_NODE_NSR_SIZE		BOOT_NSR_AREA_SIZE
#define	BOOT_THE_NODE_NSR_PHYS_BASE(node)	\
		(BOOT_NSR_AREA_PHYS_BASE + (node * BOOT_NODE_NSR_SIZE))

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

#define	BOOT_NODE_NBSR_SIZE		BOOT_NBSR_SIZE
#define	BOOT_NODE_NBSR_OFFSET		BOOT_NBSR_OFFSET
#define	BOOT_THE_NODE_NBSR_PHYS_BASE(node)	\
		((unsigned char *)(BOOT_THE_NODE_NSR_PHYS_BASE(node) + \
						BOOT_NODE_NBSR_OFFSET))

/*
 * Nodes system coprocessors registers area - COPSR = { COPSR0 ... COPSRj ... }
 */
#define	NODE_COPSR_SIZE			E2K_COPSR_AREA_SIZE
#define	THE_NODE_COPSR_PHYS_BASE(node)	\
		(E2K_COPSR_AREA_PHYS_BASE + (node * NODE_COPSR_SIZE))

extern unsigned char *nodes_nbsr_base[MAX_NUMNODES];
extern phys_addr_t nodes_nbsr_phys_base[MAX_NUMNODES];

extern void boot_e2k_sic_setup_arch(void);
#ifndef CONFIG_E2K_MACHINE
extern int boot_get_e2k_machine_id(void);
#endif

extern int __init e2k_sic_init(void);
extern int __init e2k_early_iohub_online(int node, int link);

static inline e2k_addr_t sic_get_io_area_base(void)
{
	return machine.x86_io_area_base;
}

static inline e2k_addr_t sic_get_io_area_size(void)
{
	return machine.x86_io_area_size;
}
extern e2k_addr_t sic_get_io_area_max_size(void);

static inline unsigned char *sic_get_node_nbsr_base(int node_id)
{
	return nodes_nbsr_base[node_id];
}

static inline phys_addr_t sic_get_node_nbsr_phys_base(int node_id)
{
	phys_addr_t base = nodes_nbsr_phys_base[node_id];
	VM_BUG_ON(!base);
	return base;
}

#define sic_domain_pci_conf_size()	(machine.pcicfg_area_size)
#define sic_domain_pci_conf_base(domain)				\
		(machine.pcicfg_area_phys_base +			\
		sic_domain_pci_conf_size() * ((unsigned long)domain))

#define boot_sic_domain_pci_conf_base(domain)				\
		(boot_machine.pcicfg_area_phys_base +			\
		boot_machine.pcicfg_area_size * ((unsigned long)domain))

extern unsigned long domain_to_pci_conf_base[];

static inline unsigned long
domain_pci_conf_base(unsigned int domain)
{
	return domain_to_pci_conf_base[domain];
}

static inline unsigned long
domain_pci_conf_size(unsigned int domain)
{
	return sic_domain_pci_conf_size();
}

#endif /* _ASM_E2K_SIC_H_ */
