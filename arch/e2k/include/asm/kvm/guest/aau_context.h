/*
 * KVM AAU registers model access
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

#ifndef _ASM_E2K_KVM_GUEST_AAU_CONTEXT_H_
#define _ASM_E2K_KVM_GUEST_AAU_CONTEXT_H_

#include <linux/types.h>
#include <asm/aau_regs_types.h>

#define	KVM_SAVE_AAU_MASK_REGS(aau_context, aasr)	\
({ \
	if (IS_HV_GM()) { \
		NATIVE_SAVE_AAU_MASK_REGS(aau_context, aasr); \
	} else { \
		PREFIX_SAVE_AAU_MASK_REGS(KVM, kvm, aau_context, aasr); \
	} \
})

#define	KVM_RESTORE_AAU_MASK_REGS(aau_context)	\
({ \
	if (IS_HV_GM()) { \
		E2K_CMD_SEPARATOR; \
		NATIVE_RESTORE_AAU_MASK_REGS(aau_context); \
	} else { \
		PREFIX_RESTORE_AAU_MASK_REGS(KVM, kvm, aau_context); \
	} \
})

#define KVM_SAVE_AADS(aau_regs)	\
({ \
	if (IS_HV_GM()) { \
		NATIVE_SAVE_AADS(aau_regs); \
	} else { \
		PREFIX_SAVE_AADS(KVM, kvm, aau_regs); \
	} \
})

#define KVM_RESTORE_AADS(aau_regs)	\
({ \
	if (IS_HV_GM()) { \
		NATIVE_RESTORE_AADS(aau_regs); \
	} else { \
		PREFIX_RESTORE_AADS(KVM, kvm, aau_regs); \
	} \
})

#define KVM_SAVE_AALDIS(regs)	\
({ \
	if (IS_HV_GM()) { \
		NATIVE_SAVE_AALDIS(regs); \
	} else { \
		PREFIX_SAVE_AALDIS_V5(KVM, kvm, regs); \
	} \
})
#define KVM_SAVE_AALDIS_V2(regs)	\
({ \
	if (IS_HV_GM()) { \
		NATIVE_SAVE_AALDIS_V2(regs); \
	} else { \
		PREFIX_SAVE_AALDIS_V5(KVM, kvm, regs); \
	} \
})
#define KVM_SAVE_AALDIS_V5(regs)	\
({ \
	if (IS_HV_GM()) { \
		NATIVE_SAVE_AALDIS_V5(regs); \
	} else { \
		PREFIX_SAVE_AALDIS_V5(KVM, kvm, regs); \
	} \
})

#define KVM_SAVE_AALDAS(aaldas_p)	\
({ \
	if (IS_HV_GM()) { \
		NATIVE_SAVE_AALDAS(aaldas_p); \
	} else { \
		PREFIX_SAVE_AALDAS(KVM, kvm, aaldas_p); \
	} \
})

#define KVM_SAVE_AAFSTR(aau_context)	\
({ \
	if (IS_HV_GM()) { \
		NATIVE_SAVE_AAFSTR(aau_context); \
	} else { \
		PREFIX_SAVE_AAFSTR(KVM, kvm, aau_context); \
	} \
})

#define KVM_SAVE_AAU_REGS_FOR_PTRACE(regs, ti)	\
({ \
	if (IS_HV_GM()) { \
		NATIVE_SAVE_AAU_REGS_FOR_PTRACE(regs, ti); \
	} else { \
		PREFIX_SAVE_AAU_REGS_FOR_PTRACE(KVM, kvm, regs, ti); \
	} \
})

#define	KVM_GET_ARRAY_DESCRIPTORS(aau_context)	\
		PREFIX_GET_ARRAY_DESCRIPTORS_V5(KVM, kvm, aau_context)
#define	KVM_GET_ARRAY_DESCRIPTORS_V2(aau_context)	\
({ \
	if (IS_HV_GM()) { \
		NATIVE_GET_ARRAY_DESCRIPTORS_V2(aau_context); \
	} else { \
		KVM_GET_ARRAY_DESCRIPTORS(aau_context); \
	} \
})
#define	KVM_GET_ARRAY_DESCRIPTORS_V5(aau_context)	\
({ \
	if (IS_HV_GM()) { \
		NATIVE_GET_ARRAY_DESCRIPTORS_V5(aau_context); \
	} else { \
		KVM_GET_ARRAY_DESCRIPTORS(aau_context); \
	} \
})
#define	KVM_SET_ARRAY_DESCRIPTORS(context)	\
({ \
	if (IS_HV_GM()) { \
		NATIVE_SET_ARRAY_DESCRIPTORS(context); \
	} else { \
		PREFIX_SET_ARRAY_DESCRIPTORS(KVM, kvm, context); \
	} \
})

#define	KVM_GET_SYNCHRONOUS_PART(context)	\
		PREFIX_GET_SYNCHRONOUS_PART_V5(KVM, kvm, context)
#define	KVM_GET_SYNCHRONOUS_PART_V2(context)	\
({ \
	if (IS_HV_GM()) { \
		NATIVE_GET_SYNCHRONOUS_PART_V2(context); \
	} else { \
		KVM_GET_SYNCHRONOUS_PART(context); \
	} \
})
#define	KVM_GET_SYNCHRONOUS_PART_V5(context)	\
({ \
	if (IS_HV_GM()) { \
		NATIVE_GET_SYNCHRONOUS_PART_V5(context); \
	} else { \
		KVM_GET_SYNCHRONOUS_PART(context); \
	} \
})

#define	KVM_GET_AAU_CONTEXT(context)	\
({ \
	if (IS_HV_GM()) { \
		NATIVE_GET_AAU_CONTEXT(context); \
	} else { \
		PREFIX_GET_AAU_CONTEXT(KVM, kvm, V5, v5, context); \
	} \
})
#define	KVM_GET_AAU_CONTEXT_V2(context)	\
({ \
	if (IS_HV_GM()) { \
		NATIVE_GET_AAU_CONTEXT_V2(context); \
	} else { \
		PREFIX_GET_AAU_CONTEXT(KVM, kvm, V5, v5, context); \
	} \
})
#define	KVM_GET_AAU_CONTEXT_V5(context)	\
({ \
	if (IS_HV_GM()) { \
		NATIVE_GET_AAU_CONTEXT_V5(context); \
	} else { \
		PREFIX_GET_AAU_CONTEXT(KVM, kvm, V5, v5, context); \
	} \
})

static inline void
kvm_save_aaldi(u64 *aaldis)
{
	KVM_SAVE_AALDIS(aaldis);
}
static inline void
kvm_save_aaldi_v2(u64 *aaldis)
{
	KVM_SAVE_AALDIS_V2(aaldis);
}
static inline void
kvm_save_aaldi_v5(u64 *aaldis)
{
	KVM_SAVE_AALDIS_V5(aaldis);
}

static inline void
kvm_get_array_descriptors(e2k_aau_t *context)
{
	KVM_GET_ARRAY_DESCRIPTORS(context);
}
static inline void
kvm_get_array_descriptors_v2(e2k_aau_t *context)
{
	KVM_GET_ARRAY_DESCRIPTORS_V2(context);
}
static inline void
kvm_get_array_descriptors_v5(e2k_aau_t *context)
{
	KVM_GET_ARRAY_DESCRIPTORS_V5(context);
}

static inline void
kvm_set_array_descriptors(const e2k_aau_t *context)
{
	KVM_SET_ARRAY_DESCRIPTORS(context);
}

static inline void
kvm_get_synchronous_part(e2k_aau_t *context)
{
	KVM_GET_SYNCHRONOUS_PART(context);
}
static inline void
kvm_get_synchronous_part_v2(e2k_aau_t *context)
{
	KVM_GET_SYNCHRONOUS_PART_V2(context);
}
static inline void
kvm_get_synchronous_part_v5(e2k_aau_t *context)
{
	KVM_GET_SYNCHRONOUS_PART_V5(context);
}

/*
 * It's taken that aasr was get earlier(from get_aau_context caller)
 * and comparison with aasr.iab was taken.
 */
static inline void
kvm_get_aau_context(e2k_aau_t *context)
{
	KVM_GET_AAU_CONTEXT(context);
}
static inline void
kvm_get_aau_context_v2(e2k_aau_t *context)
{
	KVM_GET_AAU_CONTEXT_V2(context);
}
static inline void
kvm_get_aau_context_v5(e2k_aau_t *context)
{
	KVM_GET_AAU_CONTEXT_V5(context);
}

static __always_inline void
kvm_set_aau_context(e2k_aau_t *context)
{
	/* AAU contesxt should restore host */
}

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* It is pure kvm kernel without paravirtualization */

#define	SAVE_AAU_MASK_REGS(aau_context, aasr)	\
		KVM_SAVE_AAU_MASK_REGS(aau_context, aasr)

#define	RESTORE_AAU_MASK_REGS(aau_context)	\
		KVM_RESTORE_AAU_MASK_REGS(aau_context)

#define SAVE_AADS(aau_regs)	\
		KVM_SAVE_AADS(aau_regs)

#define RESTORE_AADS(aau_regs)	\
		KVM_RESTORE_AADS(aau_regs)

#define SAVE_AALDIS_V2(regs)	KVM_SAVE_AALDIS_V2(regs)
#define SAVE_AALDIS_V5(regs)	KVM_SAVE_AALDIS_V5(regs)

#define SAVE_AALDA(aaldas)	KVM_SAVE_AALDAS(aaldas)

#define SAVE_AAFSTR(regs)	KVM_SAVE_AAFSTR_REG(regs)

#define SAVE_AAU_REGS_FOR_PTRACE(regs, ti)	\
		KVM_SAVE_AAU_REGS_FOR_PTRACE(regs, ti)

#define	GET_ARRAY_DESCRIPTORS_V2(context)	\
		KVM_GET_ARRAY_DESCRIPTORS_V2(context)
#define	GET_ARRAY_DESCRIPTORS_V5(context)	\
		KVM_GET_ARRAY_DESCRIPTORS_V5(context)

#define	GET_SYNCHRONOUS_PART_V2(context)	\
		KVM_GET_SYNCHRONOUS_PART_V2(context)
#define	GET_SYNCHRONOUS_PART_V5(context)	\
		KVM_GET_SYNCHRONOUS_PART_V5(context)

#define	GET_AAU_CONTEXT_V2(context)	KVM_GET_AAU_CONTEXT_V2(context)
#define	GET_AAU_CONTEXT_V5(context)	KVM_GET_AAU_CONTEXT_V5(context)

static inline void
save_aaldi(u64 *aaldis)
{
	kvm_save_aaldi(aaldis);
}
static inline void
set_array_descriptors(e2k_aau_t *context)
{
	kvm_set_array_descriptors(context);
}
static inline void
get_aau_context(e2k_aau_t *context)
{
	kvm_get_aau_context(context);
}

static __always_inline void
set_aau_context(e2k_aau_t *context)
{
	kvm_set_aau_context(context);
}

#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif /* _ASM_E2K_KVM_GUEST_AAU_CONTEXT_H_ */
