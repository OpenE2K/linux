/*
 * E2K boot-time initializtion virtualization for KVM host
 *
 * Copyright 2017 Salavat S. Guiliazov (atic@mcst.ru)
 */

#ifndef	_E2K_KVM_BOOT_H_
#define	_E2K_KVM_BOOT_H_

#ifndef __ASSEMBLY__

#include <linux/types.h>
#include <linux/kernel.h>

#include <asm/e2k_api.h>

#ifndef	CONFIG_VIRTUALIZATION
/* it is native kernel without any virtualization support */
#else	/* CONFIG_VIRTUALIZATION */

#if	defined(CONFIG_PARAVIRT_GUEST) || defined(CONFIG_KVM_GUEST_KERNEL)
/* it is paravirtualized host and guest kernel */
/* or pure guest kernel */
#include <asm/kvm/guest/boot.h>
#endif	/* CONFIG_PARAVIRT_GUEST || CONFIG_KVM_GUEST_KERNEL */

#ifdef	CONFIG_KVM
extern void kvm_host_machine_setup_regs_v3(host_machdep_t *);
extern void kvm_host_machine_setup_regs_v6(host_machdep_t *);

static inline void kvm_host_machine_setup(void)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		kvm_host_machine_setup_regs_v6(&host_machine);
	} else {
		kvm_host_machine_setup_regs_v3(&host_machine);
	}
}
#endif	/* CONFIG_KVM */

#endif	/* CONFIG_VIRTUALIZATION */

#endif /* ! __ASSEMBLY__ */

#endif	/* _E2K_KVM_BOOT_H_ */
