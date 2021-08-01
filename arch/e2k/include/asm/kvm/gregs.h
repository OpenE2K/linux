#ifndef _E2K_ASM_KVM_GREGS_H
#define _E2K_ASM_KVM_GREGS_H

#include <linux/kernel.h>
#include <linux/string.h>
#include <asm/machdep.h>
#include <asm/glob_regs.h>
#include <asm/ptrace.h>

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

static inline void
copy_h_gregs_to_gregs(global_regs_t *dst, const host_gregs_t *src)
{
	tagged_memcpy_8(&dst->g[HOST_GREGS_PAIRS_START], src->g,
			sizeof(src->g));
}

static inline void
copy_h_gregs_to_h_gregs(host_gregs_t *dst, const host_gregs_t *src)
{
	tagged_memcpy_8(dst->g, src->g, sizeof(src->g));
}

static inline void
get_h_gregs_from_gregs(host_gregs_t *dst, const global_regs_t *src)
{
	tagged_memcpy_8(dst->g, &src->g[HOST_GREGS_PAIRS_START],
			sizeof(dst->g));
}

static inline void
copy_h_gregs_to_l_gregs(local_gregs_t *dst, const host_gregs_t *src)
{
	BUG_ON(HOST_GREGS_PAIRS_START < LOCAL_GREGS_START);
	tagged_memcpy_8(&dst->g[HOST_GREGS_PAIRS_START - LOCAL_GREGS_START],
			src->g, sizeof(src->g));
}

static inline void
get_h_gregs_from_l_regs(host_gregs_t *dst, const local_gregs_t *src)
{
	BUG_ON(HOST_GREGS_PAIRS_START < LOCAL_GREGS_START);
	tagged_memcpy_8(dst->g,
			&src->g[HOST_GREGS_PAIRS_START - LOCAL_GREGS_START],
			sizeof(dst->g));
}

#endif	/* _E2K_ASM_KVM_GREGS_H */
