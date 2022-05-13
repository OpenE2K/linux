#ifndef _E2K_KVM_MACHDEP_H_
#define _E2K_KVM_MACHDEP_H_

#include <linux/types.h>

#ifdef __KERNEL__

typedef struct global_regs global_regs_t;
typedef struct kernel_gregs kernel_gregs_t;

#ifndef	CONFIG_VIRTUALIZATION
/* it is native kernel without any virtualization support */
typedef struct host_machdep {
	/* nothing to support and do */
} host_machdep_t;
typedef struct guest_machdep {
	/* none any guest */
} guest_machdep_t;
#else	/* CONFIG_VIRTUALIZATION */
extern void kvm_guest_save_local_gregs_v3(struct local_gregs *gregs,
					bool is_signal);
extern void kvm_guest_save_local_gregs_v5(struct local_gregs *gregs,
					bool is_signal);
extern void kvm_guest_save_kernel_gregs_v3(kernel_gregs_t *gregs);
extern void kvm_guest_save_kernel_gregs_v5(kernel_gregs_t *gregs);
extern void kvm_guest_save_gregs_v3(struct global_regs *gregs);
extern void kvm_guest_save_gregs_v5(struct global_regs *gregs);
extern void kvm_guest_save_gregs_dirty_bgr_v3(struct global_regs *gregs);
extern void kvm_guest_save_gregs_dirty_bgr_v5(struct global_regs *gregs);
extern void kvm_guest_restore_gregs_v3(const global_regs_t *gregs);
extern void kvm_guest_restore_gregs_v5(const global_regs_t *gregs);
extern void kvm_guest_restore_kernel_gregs_v3(global_regs_t *gregs);
extern void kvm_guest_restore_kernel_gregs_v5(global_regs_t *gregs);
extern void kvm_guest_restore_local_gregs_v3(const struct local_gregs *gregs,
					bool is_signal);
extern void kvm_guest_restore_local_gregs_v5(const struct local_gregs *gregs,
					bool is_signal);

#if	defined(CONFIG_PARAVIRT_GUEST) || defined(CONFIG_KVM_GUEST_KERNEL)
/* it is paravirtualized host and guest kernel */
/* or pure guest kernel */
#include <asm/kvm/guest/machdep.h>
#endif	/* CONFIG_PARAVIRT_GUEST || CONFIG_KVM_GUEST_KERNEL */

typedef struct host_machdep {
	u32 (*read_SH_CORE_MODE)(void);
	void (*write_SH_CORE_MODE)(u32);
	u64 (*read_SH_PSHTP)(void);
	void (*write_SH_PSHTP)(u64);
	u32 (*read_SH_PCSHTP)(void);
	void (*write_SH_PCSHTP)(u32);
	u64 (*read_SH_WD)(void);
	void (*write_SH_WD)(u64);
	u64 (*read_SH_OSR0)(void);
	void (*write_SH_OSR0)(u64);
	u64 (*read_VIRT_CTRL_MU)(void);
	void (*write_VIRT_CTRL_MU)(u64);
	u64 (*read_GID)(void);
	void (*write_GID)(u64);
	u64 (*read_GP_VPTB)(void);
	void (*write_GP_VPTB)(u64);
	u64 (*read_GP_PPTB)(void);
	void (*write_GP_PPTB)(u64);
	u64 (*read_SH_OS_PPTB)(void);
	void (*write_SH_OS_PPTB)(u64);
	u64 (*read_SH_OS_VPTB)(void);
	void (*write_SH_OS_VPTB)(u64);
	u64 (*read_SH_OS_VAB)(void);
	void (*write_SH_OS_VAB)(u64);
	u64 (*read_G_W_IMASK_MMU_CR)(void);
	void (*write_G_W_IMASK_MMU_CR)(u64);
	u64 (*read_SH_PID)(void);
	void (*write_SH_PID)(u64);
	u64 (*read_SH_MMU_CR)(void);
	void (*write_SH_MMU_CR)(u64);
} host_machdep_t;

#if	!defined(CONFIG_PARAVIRT_GUEST) && !defined(CONFIG_KVM_GUEST_KERNEL)
/* it is native host kernel with virtualization support */
typedef struct guest_machdep {
	/* cannot run as guest */
} guest_machdep_t;
#endif	/* ! CONFIG_PARAVIRT_GUEST && ! CONFIG_KVM_GUEST_KERNEL */

#endif	/* ! CONFIG_VIRTUALIZATION */

#endif /* __KERNEL__ */

#endif /* _E2K_KVM_MACHDEP_H_ */
