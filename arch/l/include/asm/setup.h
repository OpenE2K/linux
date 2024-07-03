/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _L_SETUP_H
#define _L_SETUP_H

#include <linux/pci.h>

extern int l_set_ethernet_macaddr(struct pci_dev *pdev, char *macaddr);
extern int (*l_set_boot_mode)(int);
extern void l_recover_reset_state(void);
extern int l_setup_arch(void);
extern void l_setup_vga(void);
extern unsigned long measure_cpu_freq(int cpu);
extern bool check_reset_by_lwdt(void);
#endif /* _L_SETUP_H */
