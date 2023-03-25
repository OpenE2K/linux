/*
 * KVM guest hardware stacks access support
 *
 * Copyright (C) 2016 MCST
 */

#ifndef _E2K_KVM_GUEST_HW_STACKS_H_
#define _E2K_KVM_GUEST_HW_STACKS_H_

#ifndef __ASSEMBLY__

#include <asm/types.h>

/* procedure chain stack items access */
extern unsigned long kvm_get_active_cr0_lo_value(e2k_addr_t base,
							e2k_addr_t cr_ind);
extern unsigned long kvm_get_active_cr0_hi_value(e2k_addr_t base,
							e2k_addr_t cr_ind);
extern unsigned long kvm_get_active_cr1_lo_value(e2k_addr_t base,
							e2k_addr_t cr_ind);
extern unsigned long kvm_get_active_cr1_hi_value(e2k_addr_t base,
							e2k_addr_t cr_ind);
extern void kvm_put_active_cr0_lo_value(unsigned long cr0_lo_value,
					e2k_addr_t base, e2k_addr_t cr_ind);
extern void kvm_put_active_cr0_hi_value(unsigned long cr0_hi_value,
					e2k_addr_t base, e2k_addr_t cr_ind);
extern void kvm_put_active_cr1_lo_value(unsigned long cr1_lo_value,
					e2k_addr_t base, e2k_addr_t cr_ind);
extern void kvm_put_active_cr1_hi_value(unsigned long cr1_hi_value,
					e2k_addr_t base, e2k_addr_t cr_ind);

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* pure guest kernel (not paravirtualized based on pv_ops) */

/*
 * Procedure chain stack items access
 */
static inline unsigned long
get_active_cr0_lo_value(e2k_addr_t base, e2k_addr_t cr_ind)
{
	return kvm_get_active_cr0_lo_value(base, cr_ind);
}
static inline unsigned long
get_active_cr0_hi_value(e2k_addr_t base, e2k_addr_t cr_ind)
{
	return kvm_get_active_cr0_hi_value(base, cr_ind);
}
static inline unsigned long
get_active_cr1_lo_value(e2k_addr_t base, e2k_addr_t cr_ind)
{
	return kvm_get_active_cr1_lo_value(base, cr_ind);
}
static inline unsigned long
get_active_cr1_hi_value(e2k_addr_t base, e2k_addr_t cr_ind)
{
	return kvm_get_active_cr1_hi_value(base, cr_ind);
}
static inline void
put_active_cr0_lo_value(unsigned long cr0_lo_value,
				e2k_addr_t base, e2k_addr_t cr_ind)
{
	kvm_put_active_cr0_lo_value(cr0_lo_value, base, cr_ind);
}
static inline void
put_active_cr0_hi_value(unsigned long cr0_hi_value,
				e2k_addr_t base, e2k_addr_t cr_ind)
{
	kvm_put_active_cr0_hi_value(cr0_hi_value, base, cr_ind);
}
static inline void
put_active_cr1_lo_value(unsigned long cr1_lo_value,
				e2k_addr_t base, e2k_addr_t cr_ind)
{
	kvm_put_active_cr1_lo_value(cr1_lo_value, base, cr_ind);
}
static inline void
put_active_cr1_hi_value(unsigned long cr1_hi_value,
				e2k_addr_t base, e2k_addr_t cr_ind)
{
	kvm_put_active_cr1_hi_value(cr1_hi_value, base, cr_ind);
}

#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif	/* ! __ASSEMBLY__ */
#endif /* _E2K_KVM_GUEST_HW_STACKS_H_ */


