/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _ASM_KVM_GUEST_E2K_H_
#define _ASM_KVM_GUEST_E2K_H_

/* Do not include the header directly, only through asm/e2k.h */


#include <linux/types.h>

#include <asm/kvm/guest/e2k_virt.h>

#ifdef	CONFIG_VIRTUALIZATION

#ifdef	CONFIG_KVM_GUEST_KERNEL
extern unsigned int guest_machine_id;
#define	boot_guest_machine_id	boot_get_vo_value(guest_machine_id)
#endif	/* CONFIG_KVM_GUEST_KERNEL */

#define	machine_id		guest_machine_id
#define	boot_machine_id		boot_guest_machine_id

#define	get_machine_id()		machine_id
#define	boot_get_machine_id()		boot_machine_id

extern void kvm_set_mach_type_id(void);
static inline void set_mach_type_id(void)
{
	kvm_set_mach_type_id();
}

#endif	/* CONFIG_VIRTUALIZATION */

#endif /* _ASM_KVM_GUEST_E2K_H_ */
