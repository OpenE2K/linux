/*
 * E2K boot info flags support on paravirtualized kernel
 *
 * Copyright 2016 Salavat S. Guiliazov (atic@mcst.ru)
 */

#ifndef	_E2K_ASM_PARAVIRT_BOOT_FLAGS_H_
#define	_E2K_ASM_PARAVIRT_BOOT_FLAGS_H_

#ifndef __ASSEMBLY__

#include <linux/types.h>
#include <asm/paravirt/pv_ops.h>

#ifdef	CONFIG_KVM_GUEST
#include <asm/kvm/guest/boot_flags.h>
#else	/* ! CONFIG_KVM_GUEST */
 #error "Unknown virtualization type"
#endif	/* CONFIG_KVM_GUEST */

/*
 * bootblock manipulations (read/write/set/reset) in virtual kernel mode
 * on physical level:
 *	write through and uncachable access on virtual "physical" address
 *	bootblock virtual address can be only read
 */

#define	PV_READ_BOOTBLOCK_FIELD(bootblock_p, blk_field)	\
		((!paravirt_enabled()) ? \
			NATIVE_READ_BOOTBLOCK_FIELD(bootblock_p, blk_field) \
			: \
			GUEST_READ_BOOTBLOCK_FIELD(bootblock_p, blk_field))
#define	PV_WRITE_BOOTBLOCK_FIELD(bootblock_p, blk_field, field_value)	\
		((!paravirt_enabled()) ? \
			NATIVE_WRITE_BOOTBLOCK_FIELD(bootblock_p, blk_field, \
							field_value) \
			: \
			GUEST_WRITE_BOOTBLOCK_FIELD(bootblock_p, blk_field, \
							field_value))

#ifdef	CONFIG_PARAVIRT_GUEST
/* it is paravirtualized host and guest kernel */
#define	READ_BOOTBLOCK_FIELD(bootblock_p, blk_field)	\
		PV_READ_BOOTBLOCK_FIELD(bootblock_p, blk_field)
#define	WRITE_BOOTBLOCK_FIELD(bootblock_p, blk_field, field_value)	\
		PV_WRITE_BOOTBLOCK_FIELD(bootblock_p, blk_field,	\
						field_value)
#endif	/* CONFIG_PARAVIRT_GUEST */

#endif /* ! __ASSEMBLY__ */

#endif	/* ! _E2K_ASM_PARAVIRT_BOOT_FLAGS_H_ */
