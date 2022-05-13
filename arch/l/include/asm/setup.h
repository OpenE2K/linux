#ifndef _L_SETUP_H
#define _L_SETUP_H

#include <linux/pci.h>

int l_set_ethernet_macaddr(struct pci_dev *pdev, char *macaddr);
extern int (*l_set_boot_mode)(int);

int l_setup_arch(void);
void l_setup_vga(void);
unsigned long measure_cpu_freq(int cpu);
#endif /* _L_SETUP_H */
