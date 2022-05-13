/*
 * KVM guest hardware stacks access support
 *
 * Copyright (C) 2016 MCST
 */

#ifndef _E2K_PARAVIRT_HW_STACKS_H_
#define _E2K_PARAVIRT_HW_STACKS_H_

#ifndef __ASSEMBLY__

#include <asm/types.h>
#include <asm/paravirt/pv_ops.h>

/* procedure chain stack items access */

static inline unsigned long
pv_get_active_cr0_lo_value(e2k_addr_t base, e2k_addr_t cr_ind)
{
	if (!paravirt_enabled())
		return native_get_active_cr0_lo_value(base, cr_ind);
	else
		return pv_cpu_ops.get_active_cr0_lo_value(base, cr_ind);
}
static inline unsigned long
pv_get_active_cr0_hi_value(e2k_addr_t base, e2k_addr_t cr_ind)
{
	if (!paravirt_enabled())
		return native_get_active_cr0_hi_value(base, cr_ind);
	else
		return pv_cpu_ops.get_active_cr0_hi_value(base, cr_ind);
}
static inline unsigned long
pv_get_active_cr1_lo_value(e2k_addr_t base, e2k_addr_t cr_ind)
{
	if (!paravirt_enabled())
		return native_get_active_cr1_lo_value(base, cr_ind);
	else
		return pv_cpu_ops.get_active_cr1_lo_value(base, cr_ind);
}
static inline unsigned long
pv_get_active_cr1_hi_value(e2k_addr_t base, e2k_addr_t cr_ind)
{
	if (!paravirt_enabled())
		return native_get_active_cr1_hi_value(base, cr_ind);
	else
		return pv_cpu_ops.get_active_cr1_hi_value(base, cr_ind);
}
static inline void
pv_put_active_cr0_lo_value(unsigned long cr_value,
				e2k_addr_t base, e2k_addr_t cr_ind)
{
	if (!paravirt_enabled())
		native_put_active_cr0_lo_value(cr_value, base, cr_ind);
	else
		pv_cpu_ops.put_active_cr0_lo_value(cr_value, base, cr_ind);
}
static inline void
pv_put_active_cr0_hi_value(unsigned long cr_value,
				e2k_addr_t base, e2k_addr_t cr_ind)
{
	if (!paravirt_enabled())
		native_put_active_cr0_hi_value(cr_value, base, cr_ind);
	else
		pv_cpu_ops.put_active_cr0_hi_value(cr_value, base, cr_ind);
}
static inline void
pv_put_active_cr1_lo_value(unsigned long cr_value,
				e2k_addr_t base, e2k_addr_t cr_ind)
{
	if (!paravirt_enabled())
		native_put_active_cr1_lo_value(cr_value, base, cr_ind);
	else
		pv_cpu_ops.put_active_cr1_lo_value(cr_value, base, cr_ind);
}
static inline void
pv_put_active_cr1_hi_value(unsigned long cr_value,
				e2k_addr_t base, e2k_addr_t cr_ind)
{
	if (!paravirt_enabled())
		native_put_active_cr1_hi_value(cr_value, base, cr_ind);
	else
		pv_cpu_ops.put_active_cr1_hi_value(cr_value, base, cr_ind);
}

#ifdef	CONFIG_PARAVIRT_GUEST
/* pure guest kernel (not paravirtualized based on pv_ops) */

/*
 * Procedure chain stack items access
 */
static inline unsigned long
get_active_cr0_lo_value(e2k_addr_t base, e2k_addr_t cr_ind)
{
	return pv_get_active_cr0_lo_value(base, cr_ind);
}
static inline unsigned long
get_active_cr0_hi_value(e2k_addr_t base, e2k_addr_t cr_ind)
{
	return pv_get_active_cr0_hi_value(base, cr_ind);
}
static inline unsigned long
get_active_cr1_lo_value(e2k_addr_t base, e2k_addr_t cr_ind)
{
	return pv_get_active_cr1_lo_value(base, cr_ind);
}
static inline unsigned long
get_active_cr1_hi_value(e2k_addr_t base, e2k_addr_t cr_ind)
{
	return pv_get_active_cr1_hi_value(base, cr_ind);
}
static inline void
put_active_cr0_lo_value(unsigned long cr_value,
				e2k_addr_t base, e2k_addr_t cr_ind)
{
	pv_put_active_cr0_lo_value(cr_value, base, cr_ind);
}
static inline void
put_active_cr0_hi_value(unsigned long cr_value,
				e2k_addr_t base, e2k_addr_t cr_ind)
{
	pv_put_active_cr0_hi_value(cr_value, base, cr_ind);
}
static inline void
put_active_cr1_lo_value(unsigned long cr_value,
				e2k_addr_t base, e2k_addr_t cr_ind)
{
	pv_put_active_cr1_lo_value(cr_value, base, cr_ind);
}
static inline void
put_active_cr1_hi_value(unsigned long cr_value,
				e2k_addr_t base, e2k_addr_t cr_ind)
{
	pv_put_active_cr1_hi_value(cr_value, base, cr_ind);
}
#endif	/* CONFIG_PARAVIRT_GUEST */

#endif	/* ! __ASSEMBLY__ */
#endif /* _E2K_PARAVIRT_HW_STACKS_H_ */


