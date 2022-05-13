#ifndef _E2K_ASM_KVM_GREGS_H
#define _E2K_ASM_KVM_GREGS_H

#include <linux/kernel.h>
#include <linux/string.h>
#include <asm/machdep.h>
#include <asm/glob_regs.h>
#include <asm/ptrace.h>
#include <asm/e2k_debug.h>

#ifdef	CONFIG_VIRTUALIZATION
/* It is native host guest kernel with virtualization support */
/* or paravirtualized host and guest kernel */
/* or pure guest kernel */

#define	HOST_ONLY_COPY_TO_VCPU_STATE_GREG(__k_gregs, __vs) \
({ \
	(__k_gregs)->g[GUEST_VCPU_STATE_GREGS_PAIRS_INDEX].base = (__vs); \
})

#define	HOST_ONLY_COPY_FROM_VCPU_STATE_GREG(__k_gregs, __vs) \
({ \
	(__vs) = (__k_gregs)->g[GUEST_VCPU_STATE_GREGS_PAIRS_INDEX].base; \
})

#define	HOST_GET_SAVED_VCPU_STATE_GREG(__ti)				\
({									\
	unsigned long greg_vs;						\
									\
	HOST_ONLY_COPY_FROM_VCPU_STATE_GREG(&(__ti)->k_gregs, greg_vs);	\
	greg_vs;							\
})

#define	HOST_GET_SAVED_VCPU_STATE_GREG_AS_LIGHT(__ti)			\
({									\
	unsigned long greg_vs;						\
									\
	HOST_ONLY_COPY_FROM_VCPU_STATE_GREG(&(__ti)->k_gregs_light,	\
						greg_vs);		\
	greg_vs;							\
})

#define	HOST_ONLY_SAVE_VCPU_STATE_GREG(vs__)				\
({									\
	(vs__) = NATIVE_GET_UNTEGGED_DGREG(GUEST_VCPU_STATE_GREG);	\
})
#define	HOST_ONLY_RESTORE_VCPU_STATE_GREG(vs__)				\
({									\
	NATIVE_SET_DGREG(GUEST_VCPU_STATE_GREG, vs__);			\
})

#define	HOST_INIT_VCPU_STATE_GREG(__ti)					\
({									\
	kernel_gregs_t *k_gregs = &(__ti)->k_gregs;			\
	unsigned long vs;						\
									\
	vs = k_gregs->g[GUEST_VCPU_STATE_GREGS_PAIRS_INDEX].base;	\
	HOST_ONLY_RESTORE_VCPU_STATE_GREG(vs);				\
})

#ifdef	CONFIG_KVM_HOST_MODE
#define	HOST_SAVE_HOST_GREGS_TO(__k_gregs, only_kernel)			\
({									\
	kernel_gregs_t *k_gregs = (__k_gregs);				\
	unsigned long task__;						\
	unsigned long cpu_id__;						\
	unsigned long cpu_off__;					\
									\
	if (likely(!(only_kernel))) {					\
		unsigned long vs__;					\
									\
		HOST_ONLY_SAVE_VCPU_STATE_GREG(vs__);			\
		HOST_ONLY_COPY_TO_VCPU_STATE_GREG(k_gregs, vs__);	\
	}								\
	ONLY_SAVE_KERNEL_GREGS(task__, cpu_id__, cpu_off__);		\
	k_gregs->g[CURRENT_TASK_GREGS_PAIRS_INDEX].base = task__;	\
	k_gregs->g[SMP_CPU_ID_GREGS_PAIRS_INDEX].base = cpu_id__;	\
	k_gregs->g[MY_CPU_OFFSET_GREGS_PAIRS_INDEX].base = cpu_off__;	\
})

#define	HOST_SAVE_KERNEL_GREGS_AS_LIGHT(__ti) \
		HOST_SAVE_HOST_GREGS_TO(&(__ti)->k_gregs_light, false)

#define	HOST_SAVE_KERNEL_GREGS(__ti) \
		HOST_SAVE_HOST_GREGS_TO(&(__ti)->k_gregs, true)

#define	HOST_SAVE_HOST_GREGS(__ti) \
		HOST_SAVE_HOST_GREGS_TO(&(__ti)->k_gregs, false)

#define	HOST_SAVE_GUEST_KERNEL_GREGS(__gti) \
		HOST_SAVE_HOST_GREGS_TO(&(__gti)->gk_gregs, false)

#define	HOST_RESTORE_HOST_GREGS_FROM(__k_gregs, only_kernel)		\
({									\
	kernel_gregs_t *k_gregs = (__k_gregs);				\
	unsigned long task__;						\
	unsigned long cpu_id__;						\
	unsigned long cpu_off__;					\
									\
	if (likely(!(only_kernel))) {					\
		unsigned long vs__;					\
									\
		HOST_ONLY_COPY_FROM_VCPU_STATE_GREG(k_gregs, vs__);	\
		HOST_ONLY_RESTORE_VCPU_STATE_GREG(vs__);		\
	}								\
	task__ = k_gregs->g[CURRENT_TASK_GREGS_PAIRS_INDEX].base;	\
	cpu_id__ = k_gregs->g[SMP_CPU_ID_GREGS_PAIRS_INDEX].base;	\
	cpu_off__ = k_gregs->g[MY_CPU_OFFSET_GREGS_PAIRS_INDEX].base;	\
	ONLY_RESTORE_KERNEL_GREGS(task__, cpu_id__, cpu_off__);		\
})

#define HOST_VCPU_STATE_REG_SWITCH_TO_GUEST(vcpu)			\
({									\
	machine.save_kernel_gregs(&vcpu->arch.host_ctxt.k_gregs);	\
									\
	u64 guest_vs = GET_GUEST_VCPU_STATE_POINTER(vcpu);		\
	HOST_ONLY_RESTORE_VCPU_STATE_GREG(guest_vs);			\
})

#define HOST_VCPU_STATE_REG_RESTORE(host_ti)				\
({									\
	struct kvm_vcpu *vcpu = host_ti->vcpu;				\
									\
	copy_k_gregs_to_k_gregs(&host_ti->k_gregs_light,		\
				&vcpu->arch.host_ctxt.k_gregs);		\
})

#define HOST_VCPU_STATE_COPY_SWITCH_TO_GUEST(vcpu, __ti)		\
({									\
	gthread_info_t *_gti = pv_vcpu_get_gti(vcpu);			\
	kernel_gregs_t *k_gregs = &(__ti)->k_gregs;			\
	kernel_gregs_t *gk_gregs = &(_gti)->gk_gregs;			\
	u64 guest_vs;							\
									\
	HOST_ONLY_COPY_FROM_VCPU_STATE_GREG(gk_gregs, guest_vs);	\
	HOST_ONLY_COPY_TO_VCPU_STATE_GREG(k_gregs, guest_vs);		\
})

#define	HOST_RESTORE_KERNEL_GREGS_AS_LIGHT(_ti) \
		HOST_RESTORE_HOST_GREGS_FROM(&(_ti)->k_gregs_light, false)

#define	HOST_RESTORE_KERNEL_GREGS(_ti) \
		HOST_RESTORE_HOST_GREGS_FROM(&(_ti)->k_gregs, true)

#define	HOST_RESTORE_HOST_GREGS(_ti) \
		HOST_RESTORE_HOST_GREGS_FROM(&(_ti)->k_gregs, false)

#define	HOST_RESTORE_GUEST_KERNEL_GREGS(_gti) \
		HOST_RESTORE_HOST_GREGS_FROM(&(_gti)->gk_gregs, false)
#else	/* !CONFIG_KVM_HOST_MODE */
#define	HOST_SAVE_HOST_GREGS(__ti)
#define	HOST_RESTORE_HOST_GREGS(_ti)
#define	HOST_SAVE_KERNEL_GREGS_AS_LIGHT(__ti)
#define	HOST_RESTORE_KERNEL_GREGS_AS_LIGHT(_ti)
#endif	/* CONFIG_KVM_HOST_MODE */

#else	/* ! CONFIG_VIRTUALIZATION */
/* It is native host kernel without any virtualization */
/* not used */
#endif	/* CONFIG_VIRTUALIZATION */

#endif	/* _E2K_ASM_KVM_GREGS_H */
