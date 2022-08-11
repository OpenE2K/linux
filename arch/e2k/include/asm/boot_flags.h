/*
 * E2K boot info flags support.
 */
#ifndef _E2K_BOOT_FLAGS_H
#define _E2K_BOOT_FLAGS_H

#include <linux/types.h>

#include <asm/e2k_api.h>
#include <asm/bootinfo.h>
#include <asm/mas.h>
#include <asm/e2k.h>

/*
 * bootblock manipulations (read/write/set/reset) in virtual kernel mode
 * on physical level:
 *	write through and uncachable access on physical address
 *	bootblock virtual address can be only read
 */

#define	DO_READ_BOOTBLOCK_FIELD(bootblock_p, blk_field, mas)		\
({									\
	u64 field_value;						\
	switch (sizeof((bootblock_p)->blk_field)) {			\
	case 1:								\
		field_value =						\
			NATIVE_READ_MAS_B(&((bootblock_p)->blk_field),	\
					mas);				\
		 break;							\
	case 2:								\
		field_value =						\
			NATIVE_READ_MAS_H(&((bootblock_p)->blk_field),	\
					mas);				\
		 break;							\
	case 4:								\
		field_value =						\
			NATIVE_READ_MAS_W(&((bootblock_p)->blk_field),	\
					mas);				\
		 break;							\
	case 8:								\
		field_value =						\
			NATIVE_READ_MAS_D(&((bootblock_p)->blk_field),	\
					mas);				\
		 break;							\
	default:							\
		BUG();							\
	}								\
	(field_value);							\
})

#define	DO_WRITE_BOOTBLOCK_FIELD(bootblock_p, blk_field, field_value, mas) \
({									\
	switch (sizeof((bootblock_p)->blk_field)) {			\
	case 1:								\
		NATIVE_WRITE_MAS_B(&((bootblock_p)->blk_field),		\
					(field_value), mas);		\
		break;							\
	case 2:								\
		NATIVE_WRITE_MAS_H(&((bootblock_p)->blk_field),		\
					(field_value), mas);		\
		break;							\
	case 4:								\
		NATIVE_WRITE_MAS_W(&((bootblock_p)->blk_field),		\
					(field_value), mas);		\
		break;							\
	case 8:								\
		NATIVE_WRITE_MAS_D(&((bootblock_p)->blk_field),		\
					(field_value), mas);		\
		break;							\
	default:							\
		BUG();							\
	}								\
})
#define	NATIVE_READ_BOOTBLOCK_FIELD(bootblock_p, blk_field)	\
		DO_READ_BOOTBLOCK_FIELD(bootblock_p, blk_field, MAS_IOADDR)
#define	NATIVE_WRITE_BOOTBLOCK_FIELD(bootblock_p, blk_field, field_value) \
		DO_WRITE_BOOTBLOCK_FIELD(bootblock_p, blk_field,	\
						field_value, MAS_IOADDR)

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is native guest kernel */
#include <asm/kvm/guest/boot_flags.h>
#elif	defined(CONFIG_PARAVIRT_GUEST)
/* it is paravirtualized host and guest kernel */
#include <asm/paravirt/boot_flags.h>
#else	/* ! CONFIG_KVM_GUEST_KERNEL && ! CONFIG_PARAVIRT_GUEST */
/* it is native kernel without virtualization support */
/* or host kernel with virtualization support */
#define	READ_BOOTBLOCK_FIELD(bootblock_p, blk_field)	\
		NATIVE_READ_BOOTBLOCK_FIELD(bootblock_p, blk_field)
#define	WRITE_BOOTBLOCK_FIELD(bootblock_p, blk_field, field_value)	\
		NATIVE_WRITE_BOOTBLOCK_FIELD(bootblock_p, blk_field,	\
						field_value)
#endif	/* ! CONFIG_KVM_GUEST_KERNEL */

static inline u64
read_bootblock_flags(bootblock_struct_t *bootblock)
{
	return READ_BOOTBLOCK_FIELD(bootblock, kernel_flags);
}

static inline void
write_bootblock_flags(bootblock_struct_t *bootblock, u64 new_flags)
{
	WRITE_BOOTBLOCK_FIELD(bootblock, boot_flags, new_flags);
	WRITE_BOOTBLOCK_FIELD(bootblock, kernel_flags, new_flags);
}

static inline void
set_bootblock_flags(bootblock_struct_t *bootblock, u64 new_flags)
{
	u64 cur_flags = read_bootblock_flags(bootblock);
	write_bootblock_flags(bootblock, cur_flags | new_flags);
}

static inline void
reset_bootblock_flags(bootblock_struct_t *bootblock, u64 new_flags)
{
	u64 cur_flags = read_bootblock_flags(bootblock);
	write_bootblock_flags(bootblock, cur_flags & ~new_flags);
}

#endif /* _E2K_BOOT_FLAGS_H */
