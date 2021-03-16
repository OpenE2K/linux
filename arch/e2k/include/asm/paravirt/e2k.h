#ifndef _ASM_PARAVIRT_E2K_H_
#define _ASM_PARAVIRT_E2K_H_

/* Do not include the header directly, only through asm/e2k.h */


#include <linux/types.h>
#include <asm/paravirt/pv_ops.h>
#include <asm/kvm/guest/e2k.h>
#include <asm/paravirt/boot.h>

#define	pv_get_machine_id()	\
		((paravirt_enabled()) ? guest_machine_id : native_machine_id)
#define	boot_pv_get_machine_id()	\
		((boot_paravirt_enabled()) ? \
			guest_machine_id : boot_native_machine_id)
#define	pv_set_machine_id(mach_id)					\
({									\
	if (paravirt_enabled())						\
		guest_machine_id = (mach_id);				\
	else								\
		native_machine_id = (mach_id);				\
})
#define	boot_pv_set_machine_id(mach_id)					\
({									\
	if (boot_paravirt_enabled())					\
		guest_machine_id = (mach_id);				\
	else								\
		boot_native_machine_id = (mach_id);			\
})

static inline void
pv_set_mach_type_id(void)
{
	pv_init_ops.set_mach_type_id();
}

#ifdef	CONFIG_PARAVIRT_GUEST
/* it is paravirtualized host and guest kernel */

#define	get_machine_id()		pv_get_machine_id()
#define	boot_get_machine_id()		boot_pv_get_machine_id()
#define	set_machine_id(mach_id)		pv_set_machine_id(mach_id)
#define	boot_set_machine_id(mach_id)	boot_pv_set_machine_id(mach_id)

static inline void set_mach_type_id(void)
{
	pv_set_mach_type_id();
}

#endif	/* CONFIG_PARAVIRT_GUEST */

#endif /* _ASM_PARAVIRT_E2K_H_ */
