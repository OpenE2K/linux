#ifndef _ASM_KVM_GUEST_E2K_H_
#define _ASM_KVM_GUEST_E2K_H_

/* Do not include the header directly, only through asm/e2k.h */


#include <linux/types.h>

#include <asm/kvm/guest/e2k_virt.h>

#ifdef	CONFIG_VIRTUALIZATION

#if	defined(CONFIG_PARAVIRT_GUEST)
extern unsigned int guest_machine_id;
#define	boot_guest_machine_id	boot_get_vo_value(guest_machine_id)
#endif /* CONFIG_E2K_MACHINE */

extern void kvm_set_mach_type_id(void);

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is native guest kernel */
#ifdef	CONFIG_E2K_MACHINE
 #if	defined(CONFIG_E2K_VIRT)
  #define guest_machine_id	MACHINE_ID_E2K_VIRT
  #define boot_guest_machine_id	guest_machine_id
 #else
  #error "E2K VIRTUAL MACHINE type does not defined"
 #endif
#else	/* ! CONFIG_E2K_MACHINE */
extern unsigned int guest_machine_id;
#define	boot_guest_machine_id	boot_get_vo_value(guest_machine_id)
#endif /* CONFIG_E2K_MACHINE */

#define	machine_id		guest_machine_id
#define	boot_machine_id		boot_guest_machine_id

#define	get_machine_id()		machine_id
#define	boot_get_machine_id()		boot_machine_id
#define	set_machine_id(mach_id)		(machine_id = (mach_id))
#define	boot_set_machine_id(mach_id)	(boot_machine_id = (mach_id))

static inline void set_mach_type_id(void)
{
	kvm_set_mach_type_id();
}

#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif	/* CONFIG_VIRTUALIZATION */

#endif /* _ASM_KVM_GUEST_E2K_H_ */
