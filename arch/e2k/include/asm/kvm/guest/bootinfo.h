/*
 * E2K boot-time initializtion virtualization for KVM guest
 *
 * Copyright 2016 Salavat S. Guiliazov (atic@mcst.ru)
 */

#ifndef	_E2K_KVM_GUEST_BOOTINFO_H_
#define	_E2K_KVM_GUEST_BOOTINFO_H_

#ifndef __ASSEMBLY__

#include <linux/types.h>

#include <asm/mas.h>

/*
 * bootblock manipulations (read/write/set/reset) in virtual kernel mode
 * on physical level:
 *	write through and uncachable access on virtual "physical" address
 *	bootblock virtual address can be only read
 */

#define	KVM_READ_BOOTBLOCK_FIELD(bootblock_p, blk_field)		\
		DO_READ_BOOTBLOCK_FIELD(bootblock_p, blk_field,		\
						MAS_BYPASS_ALL_CACHES)

#define	KVM_WRITE_BOOTBLOCK_FIELD(bootblock_p, blk_field, field_value)	\
		DO_WRITE_BOOTBLOCK_FIELD(bootblock_p, blk_field,	\
						field_value,		\
						MAS_BYPASS_ALL_CACHES)

#ifdef	CONFIG_KVM_GUEST_KERNEL

#define	READ_BOOTBLOCK_FIELD(bootblock_p, blk_field)	\
		KVM_READ_BOOTBLOCK_FIELD(bootblock_p, blk_field)
#define	WRITE_BOOTBLOCK_FIELD(bootblock_p, blk_field, field_value)	\
		KVM_WRITE_BOOTBLOCK_FIELD(bootblock_p, blk_field,	\
						field_value)

#endif	/* CONFIG_GUEST_KERNEL */

#endif /* ! __ASSEMBLY__ */

#endif	/* _E2K_KVM_GUEST_BOOTINFO_H_ */
