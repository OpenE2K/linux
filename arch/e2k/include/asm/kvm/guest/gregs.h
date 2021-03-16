#ifndef __KVM_GUEST_E2K_GREGS_H
#define __KVM_GUEST_E2K_GREGS_H

/* Does not include this header directly, include <asm/trap_table.h> */

#include <asm/gregs.h>

#ifndef	CONFIG_E2K_ISET_VER
#define	KVM_SAVE_HOST_GREGS(__ti)					\
({									\
	if (IS_HV_GM()) {						\
		machine.guest.save_host_gregs(&__ti->h_gregs);		\
	}								\
})
#define	KVM_RESTORE_HOST_GREGS(__ti)					\
({									\
	if (IS_HV_GM()) {						\
		machine.guest.restore_host_gregs(&__ti->h_gregs);	\
	}								\
})
#elif	CONFIG_E2K_ISET_VER < 5
#define	KVM_SAVE_HOST_GREGS(__ti)					\
({									\
	if (IS_HV_GM()) {						\
		DO_SAVE_VCPU_STATE_GREGS_V2(__ti->h_gregs.g);		\
	}								\
})
#define	KVM_RESTORE_HOST_GREGS(__ti)					\
({									\
	if (IS_HV_GM()) {						\
		DO_RESTORE_VCPU_STATE_GREGS_V2(__ti->h_gregs.g);	\
	}								\
})
#else	/* CONFIG_E2K_ISET_VER >= 5 */
#define	KVM_SAVE_HOST_GREGS(__ti)					\
({									\
	if (IS_HV_GM()) {						\
		DO_SAVE_VCPU_STATE_GREGS_V5(__ti->h_gregs.g);		\
	}								\
})
#define	KVM_RESTORE_HOST_GREGS(__ti)					\
({									\
	if (IS_HV_GM()) {						\
		DO_RESTORE_VCPU_STATE_GREGS_V5(__ti->h_gregs.g);	\
	}								\
})
#endif	/* CONFIG_E2K_ISET_VER */

/* save/restore of globals is executed by host kernel, so guest do nothing */
#define	KVM_SAVE_KERNEL_GREGS_AND_SET(__ti)				\
({									\
	if (IS_HV_GM()) {						\
		NATIVE_SAVE_KERNEL_GREGS_AND_SET(__ti);			\
	}								\
})
#define	KVM_RESTORE_KERNEL_GREGS_AND_FREE(__ti)				\
({									\
	if (IS_HV_GM()) {						\
		NATIVE_RESTORE_KERNEL_GREGS(&(__ti)->k_gregs);		\
	}								\
})
#define	KVM_RESTORE_KERNEL_GREGS_IN_SYSCALL(__ti)			\
({									\
	if (IS_HV_GM()) {						\
		E2K_CMD_SEPARATOR; /* to do not have priv action */	\
		NATIVE_RESTORE_KERNEL_GREGS_IN_SYSCALL(__ti);		\
	} else {							\
		/* macros should be used only to return to guest */	\
		/* kernel from host, so restore kernel gregs state */	\
		ONLY_SET_KERNEL_GREGS(__ti);				\
	}								\
})

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is native KVM guest kernel (not paravirtualized) */

#define	HOST_SAVE_VCPU_STATE_GREGS(__ti)
#define	HOST_RESTORE_VCPU_STATE_GREGS(__ti)

/* save/restore of globals is executed by host kernel, so guest do nothing */
#define	SAVE_KERNEL_GREGS_AND_SET(thread_info)		\
		KVM_SAVE_KERNEL_GREGS_AND_SET(thread_info)
#define	RESTORE_KERNEL_GREGS_AND_FREE(thread_info)	\
		KVM_RESTORE_KERNEL_GREGS_AND_FREE(thread_info)
#define	RESTORE_KERNEL_GREGS_IN_SYSCALL(thread_info)	\
		KVM_RESTORE_KERNEL_GREGS_IN_SYSCALL(thread_info)

#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif	/* __KVM_GUEST_E2K_GREGS_H */
