/*
 *  linux/include/asm-e2k/ide.h
 *
 *  Copyright (C) 1994-1996  Linus Torvalds & authors
 */

/*
 *  This file contains the E2K architecture specific IDE code.
 *  LMS simulates generic i386 ISA IDE hardware.
 */

#ifndef _E2K_IDE_H_
#define _E2K_IDE_H_

#ifdef __KERNEL__

#include <linux/config.h>
#include <asm/machdep.h>

#ifndef MAX_HWIFS
#define MAX_HWIFS	CONFIG_IDE_MAX_HWIFS
#endif

typedef unsigned short ide_ioreg_t;

#define IDE_ARCH_OBSOLETE_DEFAULTS

static __inline__ int ide_default_irq(ide_ioreg_t base)
{
	switch (base) {
		case 0x1f0: return 14;
		case 0x170: return 15;
		case 0x1e8: return 11;
		case 0x168: return 10;
		case 0x1e0: return 8;
		case 0x160: return 12;
		default:
			return 0;
	}
}

static __inline__ ide_ioreg_t ide_default_io_base(int index)
{
	switch (index) {
		case 0:	return 0x1f0;
		case 1:	return 0x170;
		case 2: return 0x1e8;
		case 3: return 0x168;
		case 4: return 0x1e0;
		case 5: return 0x160;
		default:
			return 0;
	}
}

#define IDE_ARCH_OBSOLETE_INIT
#define ide_default_io_ctl(base)	((base) + 0x206) /* obsolete */

#ifdef CONFIG_PCI
#define ide_init_default_irq(base)	(0)
#else
#define ide_init_default_irq(base)	ide_default_irq(base)
#endif

#include <asm-generic/ide_iops.h>

#endif /* __KERNEL__ */

#endif /* _E2K_IDE_H_ */
