
#ifndef _ASM_L_OF_DEVICE_H
#define _ASM_L_OF_DEVICE_H
#ifdef __KERNEL__

#include <linux/device.h>
#include <linux/mod_devicetable.h>
#include <asm/sbus.h>
#include <linux/of.h>

/*
 * The of_device is a kind of "base class" that is a superset of
 * struct device for use by devices attached to an OF node and
 * probed using OF properties.
 */
struct of_device;
struct of_device
{
	char				name[32];	
        struct of_device		*parent;
        struct device                   dev;
	struct device_node		*node;
        struct resource                 resource[PROMREG_MAX];
        unsigned int                    irqs[PROMINTR_MAX];
        int                             num_irqs;
        struct  proc_dir_entry *pde;    /* this node's proc directory */
	int				registered;
//        void                            *sysdata;

	int				p2s_id;
//        int                             slot;
//        int                             portid;
        int                             clock_freq;
};

extern void __iomem *of_ioremap(struct resource *res, unsigned long offset, unsigned long size, char *name);
extern void of_iounmap(struct resource *res, void __iomem *base, unsigned long size);

extern struct device_node **l_allnodes;

#if 0
extern int of_register_driver(struct of_platform_driver *drv, struct bus_type *bus);
extern void of_unregister_driver(struct of_platform_driver *drv);
#endif

#endif /* __KERNEL__ */
#endif /* _ASM_L_OF_DEVI */
