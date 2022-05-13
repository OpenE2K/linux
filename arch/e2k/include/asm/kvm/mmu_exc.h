#ifndef MMU_GVA_TRANSLATION_H
#define MMU_GVA_TRANSLATION_H

#include <linux/types.h>

#undef E2K_INVALID_PAGE
#define E2K_INVALID_PAGE	(~(hpa_t)0)

#define UNMAPPED_GVA		(~(gpa_t)0)
#define	arch_is_error_gpa(gpa)	((gpa_t)(gpa) == UNMAPPED_GVA)


typedef struct kvm_arch_exception {
	bool error_code_valid;	/* PFERR_* flags is valid */
	u32 error_code;		/* PFERR_* flags */
	u64 address;		/* page fault gpa */
	u64 ip;			/* IP to inject trap */
} kvm_arch_exception_t;

#endif /* MMU_GVA_TRANSLATION_H */
