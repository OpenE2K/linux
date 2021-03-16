#ifndef SBUS_PROC_TREE_H
#define SBUS_PROC_TREE_H

#include <asm/openprom.h>

extern int prom_root_node;

#define MAX_NODES	1024

enum {
	NO_TYPE,
#define	NO_TYPE		NO_TYPE
	BUS,
#define	BUS		BUS
	PCI,
#define	PCI		PCI
	SBUS,
#define	SBUS		SBUS
	CPU,
#define	CPU		CPU
	MEMORY,
#define	MEMORY		MEMORY
	SCSI,
#define	SCSI		SCSI
	IDE,
#define	IDE		IDE
	LAST_TYPE
#define	LAST_TYPE	LAST_TYPE
};

#define GET_DEV_TREE	(MCT_TREE_MAGIC | 0)

/* Linux device tables */
typedef struct knode_dev {
	struct knode_dev	*next;	/* next device on this Bus or null */
	struct knode_dev	*child;	/* List of childes if any */
	struct knode_dev	*parent; /* Parent device if not toplevel */
	int	prom_node;	/* PROM device tree node for this device */
	char	name[64];	/* PROM device name */
	int	slot;
	int	id;		/* seq. number of node*/
	int	depth;
	int	type;
	int	data;

	struct linux_prom_registers reg_addrs[PROMREG_MAX];
	int num_registers, ranges_applied;

	struct linux_prom_ranges device_ranges[PROMREG_MAX];
	int num_device_ranges;

	unsigned int irqs[4];       /* [31:8] - p2s_id, [7:0] - irq */
	int num_irqs;
} knode_t;

#endif
