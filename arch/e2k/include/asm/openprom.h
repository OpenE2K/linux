/* $Id: openprom.h,v 1.1 2005/12/22 16:14:19 alexmipt Exp $ 
 * openprom.h:  Prom structures and defines for access to the OPENBOOT
 *              prom routines and data areas.
 *
 * Copyright (C) 1995 David S. Miller (davem@caip.rutgers.edu)
 * Copyright (C) 2005 Alexander Shmelev (ashmelev@task.sun.mcst.ru)
 */
 
#ifndef __OPENPROM_H
#define __OPENPROM_H

/* Routines for traversing the prom device tree. */
struct linux_nodeops {
	int (*no_nextnode)(int node);
	int (*no_child)(int node);
	int (*no_proplen)(int node, char *name);
	int (*no_getprop)(int node, char *name, char *val);
	int (*no_setprop)(int node, char *name, char *val, int len);
	char * (*no_nextprop)(int node, char *name);
};

/* More fun PROM structures for device probing. */
#define PROMREG_MAX     16
#define PROMVADDR_MAX   16
#define PROMINTR_MAX    15

struct linux_prom_registers {
	u32 which_io;		/* Registers space */
	u32 phys_addr;		/* The physical address of this register */
	u32 reg_size;		/* How many bytes does this register take up? */
};

/* Element of the "ranges" vector */
struct linux_prom_ranges {
	u32 ot_child_space;
	u32 ot_child_base;		/* Bus feels this */
	u32 ot_parent_space;
	u32 ot_parent_base;		/* CPU looks from here */
	u32 or_size;
};

struct linux_prom_irqs {
	u32 pri;    /* IRQ priority */
	u32 vector; /* This is foobar, what does it do? */
};

#endif	/* !(__OPENPROM_H) */
