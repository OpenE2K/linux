/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _E2K_KVM_MACHDEP_H_
#define _E2K_KVM_MACHDEP_H_

#include <linux/types.h>

typedef struct e2k_gregs e2k_global_regs_t;
typedef struct kernel_gregs kernel_gregs_t;


#ifndef	CONFIG_VIRTUALIZATION
/* it is native kernel without any virtualization support */
typedef struct guest_machdep {
	/* none any guest */
} guest_machdep_t;
#else /* CONFIG_VIRTUALIZATION */
extern void kvm_guest_save_local_gregs_v3(struct local_gregs *gregs, bool is_signal);
extern void kvm_guest_save_local_gregs_v5(struct local_gregs *gregs, bool is_signal);
extern void kvm_guest_save_kernel_gregs_v3(kernel_gregs_t *gregs);
extern void kvm_guest_save_kernel_gregs_v5(kernel_gregs_t *gregs);
extern void kvm_guest_save_gregs_v3(struct e2k_gregs *gregs);
extern void kvm_guest_save_gregs_v5(struct e2k_gregs *gregs);
extern void kvm_guest_restore_gregs_v3(const e2k_global_regs_t *gregs);
extern void kvm_guest_restore_gregs_v5(const e2k_global_regs_t *gregs);
extern void kvm_guest_restore_kernel_gregs_v3(e2k_global_regs_t *gregs);
extern void kvm_guest_restore_kernel_gregs_v5(e2k_global_regs_t *gregs);
extern void kvm_guest_restore_local_gregs_v3(const struct local_gregs *gregs, bool is_signal);
extern void kvm_guest_restore_local_gregs_v5(const struct local_gregs *gregs, bool is_signal);

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is virtualized guest kernel */
#include <asm/kvm/guest/machdep.h>
#endif /* CONFIG_KVM_GUEST_KERNEL */

#ifdef	CONFIG_KVM_HOST_KERNEL
/* it is host kernel with virtualization support */
typedef struct guest_machdep {
	/* cannot run as guest */
} guest_machdep_t;
#endif /* CONFIG_KVM_HOST_KERNEL */

#endif /* ! CONFIG_VIRTUALIZATION */

#endif /* _E2K_KVM_MACHDEP_H_ */
