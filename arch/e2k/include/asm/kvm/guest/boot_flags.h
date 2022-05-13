/*
 * E2K boot info flags support on KVM guest
 *
 * Copyright 2016 Salavat S. Guiliazov (atic@mcst.ru)
 */

#ifndef	_E2K_KVM_GUEST_BOOT_FLAGS_H_
#define	_E2K_KVM_GUEST_BOOT_FLAGS_H_

#ifndef __ASSEMBLY__
#include <linux/types.h>

#include <asm/e2k_api.h>
#include <asm/mas.h>

/*
 * bootblock manipulations (read/write/set/reset) in virtual kernel mode
 * on physical level:
 *	write through and uncachable access on virtual "physical" address
 *	bootblock virtual address can be only read
 */

#define	GUEST_READ_BOOTBLOCK_FIELD(bootblock_p, blk_field)		\
		DO_READ_BOOTBLOCK_FIELD(bootblock_p, blk_field,		\
						MAS_BYPASS_ALL_CACHES)

#define	GUEST_WRITE_BOOTBLOCK_FIELD(bootblock_p, blk_field, field_value) \
		DO_WRITE_BOOTBLOCK_FIELD(bootblock_p, blk_field,	\
						field_value,		\
						MAS_BYPASS_ALL_CACHES)

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is native guest kernel */
#define	READ_BOOTBLOCK_FIELD(bootblock_p, blk_field)	\
		GUEST_READ_BOOTBLOCK_FIELD(bootblock_p, blk_field)
#define	WRITE_BOOTBLOCK_FIELD(bootblock_p, blk_field, field_value)	\
		GUEST_WRITE_BOOTBLOCK_FIELD(bootblock_p, blk_field,	\
						field_value)
#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif /* ! __ASSEMBLY__ */

#endif	/* _E2K_KVM_GUEST_BOOT_FLAGS_H_ */
