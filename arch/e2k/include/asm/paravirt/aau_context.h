/*
 * AAU registers description, macroses for load/store AAU context
 * paravirtualized case
 *
 * array access descriptors			(AAD0, ... , AAD31);
 * initial indices				(AIND0, ... , AAIND15);
 * indices increment values			(AAINCR0, ... , AAINCR7);
 * current values of "prefetch" indices		(AALDI0, ... , AALDI63);
 * array prefetch initialization mask		(AALDV);
 * prefetch attributes				(AALDA0, ... , AALDA63);
 * array prefetch advance mask			(AALDM);
 * array access status register			(AASR);
 * array access fault status register		(AAFSTR);
 * current values of "store" indices		(AASTI0, ... , AASTI15);
 * store attributes				(AASTA0, ... , AASTA15);
 */

#ifndef _E2K_ASM_PARAVIRT_AAU_CONTEXT_H_
#define _E2K_ASM_PARAVIRT_AAU_CONTEXT_H_

#include <linux/types.h>
#include <asm/paravirt/pv_ops.h>

#ifdef	CONFIG_KVM_GUEST
#include <asm/aau_regs_types.h>
#include <asm/kvm/guest/aau_context.h>

#define	PV_SAVE_AAU_MASK_REGS(aau_context, aasr)			\
({									\
	if (!paravirt_enabled()) {					\
		NATIVE_SAVE_AAU_MASK_REGS(aau_context, aasr);		\
	} else {							\
		KVM_SAVE_AAU_MASK_REGS(aau_context, aasr);		\
	}								\
})

#define	PV_RESTORE_AAU_MASK_REGS(aau_context)				\
({									\
	if (!paravirt_enabled()) {					\
		NATIVE_RESTORE_AAU_MASK_REGS(aau_context);		\
	} else {							\
		KVM_RESTORE_AAU_MASK_REGS(aau_context);		\
	}								\
})

#define PV_SAVE_AADS(aau_regs)						\
({									\
	if (!paravirt_enabled()) {					\
		NATIVE_SAVE_AADS(aau_regs);				\
	} else {							\
		KVM_SAVE_AADS(aau_regs);				\
	}								\
})

#define PV_RESTORE_AADS(aau_regs)					\
({									\
	if (!paravirt_enabled()) {					\
		NATIVE_RESTORE_AADS(aau_regs);				\
	} else {							\
		KVM_RESTORE_AADS(aau_regs);				\
	}								\
})

#define PV_SAVE_AALDIS_V2(regs)						\
({									\
	if (!paravirt_enabled()) {					\
		NATIVE_SAVE_AALDIS_V2(regs);				\
	} else {							\
		KVM_SAVE_AALDIS(regs);					\
	}								\
})
#define PV_SAVE_AALDIS_V5(regs)						\
({									\
	if (!paravirt_enabled()) {					\
		NATIVE_SAVE_AALDIS_V5(regs);				\
	} else {							\
		KVM_SAVE_AALDIS(regs);					\
	}								\
})

#define PV_SAVE_AALDAS(aaldas_p)					\
({									\
	if (!paravirt_enabled()) {					\
		NATIVE_SAVE_AALDAS(aaldas_p);				\
	} else {							\
		KVM_SAVE_AALDAS(aaldas_p);				\
	}								\
})

#define PV_SAVE_AAFSTR(aau_context)	\
({									\
	if (!paravirt_enabled()) {					\
		NATIVE_SAVE_AAFSTR(aau_context);			\
	} else {							\
		KVM_SAVE_AAFSTR(aau_context);				\
	}								\
})

#define PV_SAVE_AAU_REGS_FOR_PTRACE(regs, ti)				\
({									\
	if (!paravirt_enabled()) {					\
		NATIVE_SAVE_AAU_REGS_FOR_PTRACE(regs, ti);		\
	} else {							\
		KVM_SAVE_AAU_REGS_FOR_PTRACE(regs, ti);			\
	}								\
})

#define PV_GET_ARRAY_DESCRIPTORS_V2(aau_context)			\
({									\
	if (!paravirt_enabled()) {					\
		NATIVE_GET_ARRAY_DESCRIPTORS_V2(aau_context);		\
	} else {							\
		kvm_get_array_descriptors(aau_context);			\
	}								\
})
#define PV_GET_ARRAY_DESCRIPTORS_V5(aau_context)			\
({									\
	if (!paravirt_enabled()) {					\
		NATIVE_GET_ARRAY_DESCRIPTORS_V5(aau_context);		\
	} else {							\
		kvm_get_array_descriptors(aau_context);			\
	}								\
})

#define PV_SET_ARRAY_DESCRIPTORS(aau_context)				\
({									\
	if (!paravirt_enabled()) {					\
		NATIVE_SET_ARRAY_DESCRIPTORS(aau_context);		\
	} else {							\
		kvm_set_array_descriptors(aau_context);			\
	}								\
})

#define PV_GET_SYNCHRONOUS_PART_V2(aau_context)				\
({									\
	if (!paravirt_enabled()) {					\
		NATIVE_GET_SYNCHRONOUS_PART_V2(aau_context);		\
	} else {							\
		kvm_get_synchronous_part(aau_context);			\
	}								\
})
#define PV_GET_SYNCHRONOUS_PART_V5(aau_context)				\
({									\
	if (!paravirt_enabled()) {					\
		NATIVE_GET_SYNCHRONOUS_PART_V5(aau_context);		\
	} else {							\
		kvm_get_synchronous_part(aau_context);			\
	}								\
})

#define PV_GET_AAU_CONTEXT_V2(aau_context)				\
({									\
	if (!paravirt_enabled()) {					\
		NATIVE_GET_AAU_CONTEXT_V2(aau_context);			\
	} else {							\
		kvm_get_aau_context(aau_context);			\
	}								\
})
#define PV_GET_AAU_CONTEXT_V5(aau_context)				\
({									\
	if (!paravirt_enabled()) {					\
		NATIVE_GET_AAU_CONTEXT_V5(aau_context);			\
	} else {							\
		kvm_get_aau_context(aau_context);			\
	}								\
})

static inline void
pv_get_array_descriptors_v2(e2k_aau_t *context)
{
	PV_GET_ARRAY_DESCRIPTORS_V2(context);
}
static inline void
pv_get_array_descriptors_v5(e2k_aau_t *context)
{
	PV_GET_ARRAY_DESCRIPTORS_V5(context);
}

static inline void
pv_get_synchronous_part_v2(e2k_aau_t *context)
{
	PV_GET_SYNCHRONOUS_PART_V2(context);
}
static inline void
pv_get_synchronous_part_v5(e2k_aau_t *context)
{
	PV_GET_SYNCHRONOUS_PART_V5(context);
}

/*
 * It's taken that aasr was get earlier(from get_aau_context caller)
 * and comparison with aasr.iab was taken.
 */
static inline void
pv_get_aau_context_v2(e2k_aau_t *context)
{
	PV_GET_AAU_CONTEXT_V2(context);
}
static inline void
pv_get_aau_context_v5(e2k_aau_t *context)
{
	PV_GET_AAU_CONTEXT_V5(context);
}

#else	/* ! CONFIG_KVM_GUEST */
 #error "Unknown virtualization type"
#endif	/* CONFIG_KVM_GUEST */

#ifdef	CONFIG_PARAVIRT_GUEST
/* It is paravirtualized host and guest kernel */

#define	SAVE_AAU_MASK_REGS(aau_context, aasr)	\
		PV_SAVE_AAU_MASK_REGS(aau_context, aasr)

#define	RESTORE_AAU_MASK_REGS(aau_context)	\
		PV_RESTORE_AAU_MASK_REGS(aau_context)

#define SAVE_AADS(aau_regs)	\
		PV_SAVE_AADS(aau_regs)

#define RESTORE_AADS(aau_regs)	\
		PV_RESTORE_AADS(aau_regs)

#define SAVE_AALDIS_V2(regs)	\
		PV_SAVE_AALDIS_V2(regs)
#define SAVE_AALDIS_V5(regs)	\
		PV_SAVE_AALDIS_V5(regs)

#define SAVE_AALDA(aaldas)	\
		PV_SAVE_AALDAS(aaldas)

#define SAVE_AAFSTR(regs)	\
		PV_SAVE_AAFSTR_REG(regs)

#define SAVE_AAU_REGS_FOR_PTRACE(regs, ti)	\
		PV_SAVE_AAU_REGS_FOR_PTRACE(regs, ti)

#define GET_ARRAY_DESCRIPTORS_V2(aau_context)	\
		PV_GET_ARRAY_DESCRIPTORS_V2(aau_context)
#define GET_ARRAY_DESCRIPTORS_V5(aau_context)	\
		PV_GET_ARRAY_DESCRIPTORS_V5(aau_context)

#define	GET_SYNCHRONOUS_PART_V2(aau_context)	\
		PV_GET_SYNCHRONOUS_PART_V2(aau_context)
#define	GET_SYNCHRONOUS_PART_V5(aau_context)	\
		PV_GET_SYNCHRONOUS_PART_V5(aau_context)

#define	GET_AAU_CONTEXT_V2(context)	\
		PV_GET_AAU_CONTEXT_V2(context)
#define	GET_AAU_CONTEXT_V5(context)	\
		PV_GET_AAU_CONTEXT_V5(context)

#endif	/* CONFIG_PARAVIRT_GUEST */

#endif /* _E2K_ASM_PARAVIRT_AAU_CONTEXT_H_ */
