#ifndef _ASM_E2K_DEVICE_H
/*
 * Arch specific extensions to struct device
 *
 * This file is released under the GPLv2
 */
 
struct dev_archdata {
#ifdef CONFIG_ACPI
	void		*acpi_handle;
#endif
	unsigned	link;
};

struct pdev_archdata {
};

#define dev_to_link(__dev)		((__dev)->archdata.link)
#define set_dev_link(__dev, __link)	do {						\
						(__dev)->archdata.link = __link;	\
					} while(0)

#endif /* _ASM_E2K_DEVICE_H */
