#ifndef _E2K_KVM_MACHDEP_H_
#define _E2K_KVM_MACHDEP_H_

#include <linux/types.h>

#ifdef __KERNEL__

typedef struct global_regs global_regs_t;
typedef struct kernel_gregs kernel_gregs_t;
typedef struct host_gregs host_gregs_t;

#ifndef	CONFIG_VIRTUALIZATION
/* it is native kernel without any virtualization support */
typedef struct host_machdep {
	/* nothing to support and do */
} host_machdep_t;
typedef struct guest_machdep {
	/* none any guest */
} guest_machdep_t;
#else	/* CONFIG_VIRTUALIZATION */
extern void kvm_save_host_gregs_v2(struct host_gregs *gregs);
extern void kvm_save_host_gregs_v5(struct host_gregs *gregs);
extern void kvm_restore_host_gregs_v5(const struct host_gregs *gregs);

extern void kvm_guest_save_local_gregs_v2(struct local_gregs *gregs,
					bool is_signal);
extern void kvm_guest_save_local_gregs_v5(struct local_gregs *gregs,
					bool is_signal);
extern void kvm_guest_save_kernel_gregs_v2(kernel_gregs_t *gregs);
extern void kvm_guest_save_kernel_gregs_v5(kernel_gregs_t *gregs);
extern void kvm_guest_save_gregs_v2(struct global_regs *gregs);
extern void kvm_guest_save_gregs_v5(struct global_regs *gregs);
extern void kvm_guest_save_gregs_dirty_bgr_v2(struct global_regs *gregs);
extern void kvm_guest_save_gregs_dirty_bgr_v5(struct global_regs *gregs);
extern void kvm_guest_restore_gregs_v2(const global_regs_t *gregs);
extern void kvm_guest_restore_gregs_v5(const global_regs_t *gregs);
extern void kvm_guest_restore_kernel_gregs_v2(global_regs_t *gregs);
extern void kvm_guest_restore_kernel_gregs_v5(global_regs_t *gregs);
extern void kvm_guest_restore_local_gregs_v2(const struct local_gregs *gregs,
					bool is_signal);
extern void kvm_guest_restore_local_gregs_v5(const struct local_gregs *gregs,
					bool is_signal);

#if	defined(CONFIG_PARAVIRT_GUEST) || defined(CONFIG_KVM_GUEST_KERNEL)
/* it is paravirtualized host and guest kernel */
/* or pure guest kernel */
#include <asm/kvm/guest/machdep.h>
#endif	/* CONFIG_PARAVIRT_GUEST || CONFIG_KVM_GUEST_KERNEL */

#ifndef	CONFIG_KVM_GUEST_KERNEL
/* it is native host kernel with virtualization support */
/* or paravirtualized host and guest kernel */

typedef struct host_machdep {
} host_machdep_t;
#endif	/* ! CONFIG_KVM_GUEST_KERNEL */

#if	!defined(CONFIG_PARAVIRT_GUEST) && !defined(CONFIG_KVM_GUEST_KERNEL)
/* it is native host kernel with virtualization support */
typedef struct guest_machdep {
	/* cannot run as guest */
} guest_machdep_t;
#endif	/* ! CONFIG_PARAVIRT_GUEST && ! CONFIG_KVM_GUEST_KERNEL */

#endif	/* ! CONFIG_VIRTUALIZATION */

#endif /* __KERNEL__ */

#endif /* _E2K_KVM_MACHDEP_H_ */
