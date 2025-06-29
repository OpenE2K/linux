/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Hardware stacks support
 */

#ifndef _E2K_HW_STACKS_H
#define _E2K_HW_STACKS_H

#include <asm/types.h>
#include <asm/cpu_regs_types.h>
#include <asm/processor.h>
#include <linux/uaccess.h>

typedef enum hw_stack_type {
	HW_STACK_TYPE_PS,
	HW_STACK_TYPE_PCS
} hw_stack_type_t;

/*
 * Procedure chain stacks can be mapped to user (user processes)
 * or kernel space (kernel threads). But mapping is always to privileged area
 * and directly can be accessed only by host kernel.
 * SPECIAL CASE: access to current procedure chain stack:
 *	1. Current stack frame must be locked (resident), so access is
 * safety and can use common load/store operations
 *	2. Top of stack can be loaded to the special hardware register file and
 * must be spilled to memory before any access.
 *	3. If items of chain stack are not updated, then spilling is enough to
 * their access
 *	4. If items of chain stack are updated, then interrupts and
 * any calling of function should be disabled in addition to spilling,
 * because of return (done) will fill some part of stack from memory and can be
 * two copy of chain stack items: in memory and in registers file.
 * We can update only in memory and following spill recover not updated
 * value from registers file.
 */

static inline unsigned long
native_get_active_cr_mem_value(e2k_addr_t base,
			       e2k_addr_t cr_ind, e2k_addr_t cr_item)
{
	return *((unsigned long *)(base + cr_ind + cr_item));
}

static inline unsigned long
native_get_active_cr0_lo_value(e2k_addr_t base, e2k_addr_t cr_ind)
{
	return native_get_active_cr_mem_value(base, cr_ind, CR0_LO_I);
}

static inline unsigned long
native_get_active_cr0_hi_value(e2k_addr_t base, e2k_addr_t cr_ind)
{
	return native_get_active_cr_mem_value(base, cr_ind, CR0_HI_I);
}

static inline unsigned long
native_get_active_cr1_lo_value(e2k_addr_t base, e2k_addr_t cr_ind)
{
	return native_get_active_cr_mem_value(base, cr_ind, CR1_LO_I);
}

static inline unsigned long
native_get_active_cr1_hi_value(e2k_addr_t base, e2k_addr_t cr_ind)
{
	return native_get_active_cr_mem_value(base, cr_ind, CR1_HI_I);
}

static inline void
native_put_active_cr_mem_value(unsigned long cr_value, e2k_addr_t base,
			       e2k_addr_t cr_ind, e2k_addr_t cr_item)
{
	*((unsigned long *)(base + cr_ind + cr_item)) = cr_value;
}

static inline void
native_put_active_cr0_lo_value(unsigned long cr0_lo_value,
			       e2k_addr_t base, e2k_addr_t cr_ind)
{
	native_put_active_cr_mem_value(cr0_lo_value, base, cr_ind, CR0_LO_I);
}

static inline void
native_put_active_cr0_hi_value(unsigned long cr0_hi_value,
			       e2k_addr_t base, e2k_addr_t cr_ind)
{
	native_put_active_cr_mem_value(cr0_hi_value, base, cr_ind, CR0_HI_I);
}

static inline void
native_put_active_cr1_lo_value(unsigned long cr1_lo_value,
			       e2k_addr_t base, e2k_addr_t cr_ind)
{
	native_put_active_cr_mem_value(cr1_lo_value, base, cr_ind, CR1_LO_I);
}

static inline void
native_put_active_cr1_hi_value(unsigned long cr1_hi_value,
			       e2k_addr_t base, e2k_addr_t cr_ind)
{
	native_put_active_cr_mem_value(cr1_hi_value, base, cr_ind, CR1_HI_I);
}

#ifdef CONFIG_KVM_GUEST_KERNEL
/* virtualized guest kernel */
#include <asm/kvm/guest/hw_stacks.h>
#else /* ! CONFIG_KVM_GUEST_KERNEL */
/* it is native kernel with or without virtualization support */
static inline unsigned long
get_active_cr0_lo_value(e2k_addr_t base, e2k_addr_t cr_ind)
{
	return native_get_active_cr0_lo_value(base, cr_ind);
}

static inline unsigned long
get_active_cr0_hi_value(e2k_addr_t base, e2k_addr_t cr_ind)
{
	return native_get_active_cr0_hi_value(base, cr_ind);
}

static inline unsigned long
get_active_cr1_lo_value(e2k_addr_t base, e2k_addr_t cr_ind)
{
	return native_get_active_cr1_lo_value(base, cr_ind);
}

static inline unsigned long
get_active_cr1_hi_value(e2k_addr_t base, e2k_addr_t cr_ind)
{
	return native_get_active_cr1_hi_value(base, cr_ind);
}

static inline void
put_active_cr0_lo_value(unsigned long cr0_lo_value,
			e2k_addr_t base, e2k_addr_t cr_ind)
{
	native_put_active_cr0_lo_value(cr0_lo_value, base, cr_ind);
}

static inline void
put_active_cr0_hi_value(unsigned long cr0_hi_value,
			e2k_addr_t base, e2k_addr_t cr_ind)
{
	native_put_active_cr0_hi_value(cr0_hi_value, base, cr_ind);
}

static inline void
put_active_cr1_lo_value(unsigned long cr1_lo_value,
			e2k_addr_t base, e2k_addr_t cr_ind)
{
	native_put_active_cr1_lo_value(cr1_lo_value, base, cr_ind);
}

static inline void
put_active_cr1_hi_value(unsigned long cr1_hi_value,
			e2k_addr_t base, e2k_addr_t cr_ind)
{
	native_put_active_cr1_hi_value(cr1_hi_value, base, cr_ind);
}
#endif /* CONFIG_KVM_GUEST_KERNEL */

static __always_inline void
get_kernel_cr1(e2k_cr1_t *cr1, e2k_addr_t base, e2k_addr_t cr_ind)
{
	cr1->lo = *((u64 *)(base + cr_ind + CR1_LO_I));
	cr1->hi = *((u64 *)(base + cr_ind + CR1_HI_I));
}

static __always_inline e2k_cr0_t *get_kernel_cr0_p(e2k_addr_t base,
						   e2k_addr_t cr_ind)
{
	return (e2k_cr0_t *)(base + cr_ind + CR0_I);
}

static __always_inline int get_cr0(e2k_cr0_t *cr0, u64 base, u64 cr_ind)
{
	if (IS_USER_ADDR(base)) {
		const void __priv *src = (const void __priv *) (base + cr_ind);
		if (copy_from_priv(&cr0, src, 16))
			return -EFAULT;
	}

	cr0->lo = *((u64 *)(base + cr_ind + CR0_LO_I));
	cr0->hi = *((u64 *)(base + cr_ind + CR0_HI_I));
}

static __always_inline int get_cr1(e2k_cr1_t *cr1, u64 base, u64 cr_ind)
{
	if (IS_USER_ADDR(base)) {
		const void __priv *src = (const void __priv *) (base + cr_ind + 16);
		if (copy_from_priv(&cr1, src, 16))
			return -EFAULT;
	}

	cr1->lo = *((u64 *)(base + cr_ind + CR1_LO_I));
	cr1->hi = *((u64 *)(base + cr_ind + CR1_HI_I));
}

static __always_inline int get_crs(e2k_mem_crs_t *crs, u64 base, u64 ind)
{
	if (IS_USER_ADDR(base)) {
		const void __priv *src = (const void __priv *) (base + ind);
		if (copy_from_priv(crs, src, sizeof(*crs)))
			return -EFAULT;
	}

	crs->cr0.lo = *((u64 *)(base + ind + CR0_LO_I));
	crs->cr0.hi = *((u64 *)(base + ind + CR0_HI_I));
	crs->cr1.lo = *((u64 *)(base + ind + CR1_LO_I));
	crs->cr1.hi = *((u64 *)(base + ind + CR1_HI_I));
}

extern int chain_stack_frame_init(e2k_mem_crs_t *crs, unsigned long fn,
				  size_t dstack_free_size, size_t dstack_frame_size,
				  e2k_psr_t psr, int wbs, int wpsz, bool user);

extern void __update_psp_regs(unsigned long base, unsigned long size,
			      unsigned long new_fp, e2k_psp_t *psp);
extern void update_psp_regs(unsigned long new_fp, e2k_psp_t *psp);

extern void __update_pcsp_regs(unsigned long base, unsigned long size,
			       unsigned long new_fp, e2k_pcsp_t *pcsp);
extern void update_pcsp_regs(unsigned long new_fp, e2k_pcsp_t *pcsp);

#endif /* _E2K_HW_STACKS_H */
