/*
 * Hardware stacks support
 *
 * Copyright 2001-2015 Salavat S. Guilyazov (atic@mcst.ru)
 */

#ifndef _E2K_HW_STACKS_H
#define _E2K_HW_STACKS_H

#include <asm/types.h>
#include <asm/cpu_regs_types.h>
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
native_put_active_cr_mem_value(unsigned long cr_value,
			e2k_addr_t base, e2k_addr_t cr_ind, e2k_addr_t cr_item)
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

static inline e2k_cr0_lo_t
native_get_active_cr0_lo(e2k_addr_t base, e2k_addr_t cr_ind)
{
	e2k_cr0_lo_t cr0_lo;

	cr0_lo.CR0_lo_half = native_get_active_cr0_lo_value(base, cr_ind);
	return cr0_lo;
}
static inline e2k_cr0_hi_t
native_get_active_cr0_hi(e2k_addr_t base, e2k_addr_t cr_ind)
{
	e2k_cr0_hi_t cr0_hi;

	cr0_hi.CR0_hi_half = native_get_active_cr0_hi_value(base, cr_ind);
	return cr0_hi;
}
static inline e2k_cr1_lo_t
native_get_active_cr1_lo(e2k_addr_t base, e2k_addr_t cr_ind)
{
	e2k_cr1_lo_t cr1_lo;

	cr1_lo.CR1_lo_half = native_get_active_cr1_lo_value(base, cr_ind);
	return cr1_lo;
}
static inline e2k_cr1_hi_t
native_get_active_cr1_hi(e2k_addr_t base, e2k_addr_t cr_ind)
{
	e2k_cr1_hi_t cr1_hi;

	cr1_hi.CR1_hi_half = native_get_active_cr1_hi_value(base, cr_ind);
	return cr1_hi;
}
static inline void
native_put_active_cr0_lo(e2k_cr0_lo_t cr0_lo,
				e2k_addr_t base, e2k_addr_t cr_ind)
{
	native_put_active_cr0_lo_value(cr0_lo.CR0_lo_half, base, cr_ind);
}
static inline void
native_put_active_cr0_hi(e2k_cr0_hi_t cr0_hi,
				e2k_addr_t base, e2k_addr_t cr_ind)
{
	native_put_active_cr0_hi_value(cr0_hi.CR0_hi_half, base, cr_ind);
}
static inline void
native_put_active_cr1_lo(e2k_cr1_lo_t cr1_lo,
				e2k_addr_t base, e2k_addr_t cr_ind)
{
	native_put_active_cr1_lo_value(cr1_lo.CR1_lo_half, base, cr_ind);
}
static inline void
native_put_active_cr1_hi(e2k_cr1_hi_t cr1_hi,
				e2k_addr_t base, e2k_addr_t cr_ind)
{
	native_put_active_cr1_hi_value(cr1_hi.CR1_hi_half, base, cr_ind);
}

static inline int
native_get_user_cr0_lo(e2k_cr0_lo_t *cr0_lo, e2k_addr_t base, e2k_addr_t cr_ind)
{
	unsigned long ts_flag;
	int ret;

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	ret = __get_user(AS_WORD_P(cr0_lo),
				(u64 __user *)(base + cr_ind + CR0_LO_I));
	clear_ts_flag(ts_flag);

	return ret;
}
static inline int
native_get_user_cr0_hi(e2k_cr0_hi_t *cr0_hi, e2k_addr_t base, e2k_addr_t cr_ind)
{
	unsigned long ts_flag;
	int ret;

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	ret = __get_user(AS_WORD_P(cr0_hi),
				(u64 __user *)(base + cr_ind + CR0_HI_I));
	clear_ts_flag(ts_flag);

	return ret;
}
static inline int
native_get_user_cr1_lo(e2k_cr1_lo_t *cr1_lo, e2k_addr_t base, e2k_addr_t cr_ind)
{
	unsigned long ts_flag;
	int ret;

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	ret = __get_user(AS_WORD_P(cr1_lo),
				(u64 __user *)(base + cr_ind + CR1_LO_I));
	clear_ts_flag(ts_flag);

	return ret;
}
static inline int
native_get_user_cr1_hi(e2k_cr1_hi_t *cr1_hi, e2k_addr_t base, e2k_addr_t cr_ind)
{
	unsigned long ts_flag;
	int ret;

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	ret = __get_user(AS_WORD_P(cr1_hi),
				(u64 __user *)(base + cr_ind + CR1_HI_I));
	clear_ts_flag(ts_flag);

	return ret;
}
static inline int
native_put_user_cr0_lo(e2k_cr0_lo_t cr0_lo, e2k_addr_t base, e2k_addr_t cr_ind)
{
	unsigned long ts_flag;
	int ret;

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	ret = __put_user(AS_WORD(cr0_lo),
				(u64 __user *)(base + cr_ind + CR0_LO_I));
	clear_ts_flag(ts_flag);

	return ret;
}
static inline int
native_put_user_cr0_hi(e2k_cr0_hi_t cr0_hi, e2k_addr_t base, e2k_addr_t cr_ind)
{
	unsigned long ts_flag;
	int ret;

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	ret = __put_user(AS_WORD(cr0_hi),
				(u64 __user *)(base + cr_ind + CR0_HI_I));
	clear_ts_flag(ts_flag);

	return ret;
}
static inline int
native_put_user_cr1_lo(e2k_cr1_lo_t cr1_lo, e2k_addr_t base, e2k_addr_t cr_ind)
{
	unsigned long ts_flag;
	int ret;

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	ret = __put_user(AS_WORD(cr1_lo),
				(u64 __user *)(base + cr_ind + CR1_LO_I));
	clear_ts_flag(ts_flag);

	return ret;
}
static inline int
native_put_user_cr1_hi(e2k_cr1_hi_t cr1_hi, e2k_addr_t base, e2k_addr_t cr_ind)
{
	unsigned long ts_flag;
	int ret;

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	ret = __put_user(AS_WORD(cr1_hi),
				(u64 __user *)(base + cr_ind + CR1_HI_I));
	clear_ts_flag(ts_flag);

	return ret;
}

static inline void
native_get_kernel_cr0_lo(e2k_cr0_lo_t *cr0_lo,
				e2k_addr_t base, e2k_addr_t cr_ind)
{
	AS_WORD_P(cr0_lo) = *((u64 *)(base + cr_ind + CR0_LO_I));
}
static inline void
native_get_kernel_cr0_hi(e2k_cr0_hi_t *cr0_hi,
				e2k_addr_t base, e2k_addr_t cr_ind)
{
	AS_WORD_P(cr0_hi) = *((u64 *)(base + cr_ind + CR0_HI_I));
}
static inline void
native_get_kernel_cr1_lo(e2k_cr1_lo_t *cr1_lo,
				e2k_addr_t base, e2k_addr_t cr_ind)
{
	AS_WORD_P(cr1_lo) = *((u64 *)(base + cr_ind + CR1_LO_I));
}
static inline void
native_get_kernel_cr1_hi(e2k_cr1_hi_t *cr1_hi,
				e2k_addr_t base, e2k_addr_t cr_ind)
{
	AS_WORD_P(cr1_hi) = *((u64 *)(base + cr_ind + CR1_HI_I));
}
static inline void
native_put_kernel_cr0_lo(e2k_cr0_lo_t cr0_lo,
				e2k_addr_t base, e2k_addr_t cr_ind)
{
	*((u64 *)(base + cr_ind + CR0_LO_I)) = AS_WORD(cr0_lo);
}
static inline void
native_put_kernel_cr0_hi(e2k_cr0_hi_t cr0_hi,
				e2k_addr_t base, e2k_addr_t cr_ind)
{
	*((u64 *)(base + cr_ind + CR0_HI_I)) = AS_WORD(cr0_hi);
}
static inline void
native_put_kernel_cr1_lo(e2k_cr1_lo_t cr1_lo,
			e2k_addr_t base, e2k_addr_t cr_ind)
{
	*((u64 *)(base + cr_ind + CR1_LO_I)) = AS_WORD(cr1_lo);
}
static inline void
native_put_kernel_cr1_hi(e2k_cr1_hi_t cr1_hi,
			e2k_addr_t base, e2k_addr_t cr_ind)
{
	*((u64 *)(base + cr_ind + CR1_HI_I)) = AS_WORD(cr1_hi);
}

#ifdef CONFIG_PARAVIRT_GUEST
/* it is paravirtualized host and guest kernel */
#include <asm/paravirt/hw_stacks.h>
#elif	defined(CONFIG_KVM_GUEST_KERNEL)
/* pure guest kernel (not paravirtualized) */
#include <asm/kvm/guest/hw_stacks.h>
#else	/* ! CONFIG_PARAVIRT_GUEST && ! CONFIG_KVM_GUEST_KERNEL */
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
#endif	/* CONFIG_PARAVIRT */

static inline e2k_cr0_lo_t
get_active_cr0_lo(e2k_addr_t base, e2k_addr_t cr_ind)
{
	e2k_cr0_lo_t cr0_lo;

	cr0_lo.CR0_lo_half = get_active_cr0_lo_value(base, cr_ind);
	return cr0_lo;
}
static inline e2k_cr0_hi_t
get_active_cr0_hi(e2k_addr_t base, e2k_addr_t cr_ind)
{
	e2k_cr0_hi_t cr0_hi;

	cr0_hi.CR0_hi_half = get_active_cr0_hi_value(base, cr_ind);
	return cr0_hi;
}
static inline e2k_cr1_lo_t
get_active_cr1_lo(e2k_addr_t base, e2k_addr_t cr_ind)
{
	e2k_cr1_lo_t cr1_lo;

	cr1_lo.CR1_lo_half = get_active_cr1_lo_value(base, cr_ind);
	return cr1_lo;
}
static inline e2k_cr1_hi_t
get_active_cr1_hi(e2k_addr_t base, e2k_addr_t cr_ind)
{
	e2k_cr1_hi_t cr1_hi;

	cr1_hi.CR1_hi_half = get_active_cr1_hi_value(base, cr_ind);
	return cr1_hi;
}
static inline void
put_active_cr0_lo(e2k_cr0_lo_t cr0_lo, e2k_addr_t base, e2k_addr_t cr_ind)
{
	put_active_cr0_lo_value(cr0_lo.CR0_lo_half, base, cr_ind);
}
static inline void
put_active_cr0_hi(e2k_cr0_hi_t cr0_hi, e2k_addr_t base, e2k_addr_t cr_ind)
{
	put_active_cr0_hi_value(cr0_hi.CR0_hi_half, base, cr_ind);
}
static inline void
put_active_cr1_lo(e2k_cr1_lo_t cr1_lo, e2k_addr_t base, e2k_addr_t cr_ind)
{
	put_active_cr1_lo_value(cr1_lo.CR1_lo_half, base, cr_ind);
}
static inline void
put_active_cr1_hi(e2k_cr1_hi_t cr1_hi, e2k_addr_t base, e2k_addr_t cr_ind)
{
	put_active_cr1_hi_value(cr1_hi.CR1_hi_half, base, cr_ind);
}

static inline int
get_user_cr0_lo(e2k_cr0_lo_t *cr0_lo, e2k_addr_t base, e2k_addr_t cr_ind)
{
	return native_get_user_cr0_lo(cr0_lo, base, cr_ind);
}
static inline int
get_user_cr0_hi(e2k_cr0_hi_t *cr0_hi, e2k_addr_t base, e2k_addr_t cr_ind)
{
	return native_get_user_cr0_hi(cr0_hi, base, cr_ind);
}
static inline int
get_user_cr1_lo(e2k_cr1_lo_t *cr1_lo, e2k_addr_t base, e2k_addr_t cr_ind)
{
	return native_get_user_cr1_lo(cr1_lo, base, cr_ind);
}
static inline int
get_user_cr1_hi(e2k_cr1_hi_t *cr1_hi, e2k_addr_t base, e2k_addr_t cr_ind)
{
	return native_get_user_cr1_hi(cr1_hi, base, cr_ind);
}
static inline int
put_user_cr0_lo(e2k_cr0_lo_t cr0_lo, e2k_addr_t base, e2k_addr_t cr_ind)
{
	return native_put_user_cr0_lo(cr0_lo, base, cr_ind);
}
static inline int
put_user_cr0_hi(e2k_cr0_hi_t cr0_hi, e2k_addr_t base, e2k_addr_t cr_ind)
{
	return native_put_user_cr0_hi(cr0_hi, base, cr_ind);
}
static inline int
put_user_cr1_lo(e2k_cr1_lo_t cr1_lo, e2k_addr_t base, e2k_addr_t cr_ind)
{
	return native_put_user_cr1_lo(cr1_lo, base, cr_ind);
}
static inline int
put_user_cr1_hi(e2k_cr1_hi_t cr1_hi, e2k_addr_t base, e2k_addr_t cr_ind)
{
	return native_put_user_cr1_hi(cr1_hi, base, cr_ind);
}

static inline void
get_kernel_cr0_lo(e2k_cr0_lo_t *cr0_lo, e2k_addr_t base, e2k_addr_t cr_ind)
{
	native_get_kernel_cr0_lo(cr0_lo, base, cr_ind);
}
static inline void
get_kernel_cr0_hi(e2k_cr0_hi_t *cr0_hi, e2k_addr_t base, e2k_addr_t cr_ind)
{
	native_get_kernel_cr0_hi(cr0_hi, base, cr_ind);
}
static inline void
get_kernel_cr1_lo(e2k_cr1_lo_t *cr1_lo, e2k_addr_t base, e2k_addr_t cr_ind)
{
	native_get_kernel_cr1_lo(cr1_lo, base, cr_ind);
}
static inline void
get_kernel_cr1_hi(e2k_cr1_hi_t *cr1_hi, e2k_addr_t base, e2k_addr_t cr_ind)
{
	native_get_kernel_cr1_hi(cr1_hi, base, cr_ind);
}
static inline void
put_kernel_cr0_lo(e2k_cr0_lo_t cr0_lo, e2k_addr_t base, e2k_addr_t cr_ind)
{
	native_put_kernel_cr0_lo(cr0_lo, base, cr_ind);
}
static inline void
put_kernel_cr0_hi(e2k_cr0_hi_t cr0_hi, e2k_addr_t base, e2k_addr_t cr_ind)
{
	native_put_kernel_cr0_hi(cr0_hi, base, cr_ind);
}
static inline void
put_kernel_cr1_lo(e2k_cr1_lo_t cr1_lo, e2k_addr_t base, e2k_addr_t cr_ind)
{
	native_put_kernel_cr1_lo(cr1_lo, base, cr_ind);
}
static inline void
put_kernel_cr1_hi(e2k_cr1_hi_t cr1_hi, e2k_addr_t base, e2k_addr_t cr_ind)
{
	native_put_kernel_cr1_hi(cr1_hi, base, cr_ind);
}

static inline int
get_cr0_lo(e2k_cr0_lo_t *cr0_lo, e2k_addr_t base, u64 cr_ind)
{
	int ret = 0;

	if (base < TASK_SIZE)
		ret = get_user_cr0_lo(cr0_lo, base, cr_ind);
	else
		get_kernel_cr0_lo(cr0_lo, base, cr_ind);
	return ret;
}

static inline int
get_cr0_hi(e2k_cr0_hi_t *cr0_hi, e2k_addr_t base, u64 cr_ind)
{
	int ret = 0;

	if (base < TASK_SIZE)
		ret = get_user_cr0_hi(cr0_hi, base, cr_ind);
	else
		get_kernel_cr0_hi(cr0_hi, base, cr_ind);
	return ret;
}

static inline int
get_cr1_lo(e2k_cr1_lo_t *cr1_lo, e2k_addr_t base, u64 cr_ind)
{
	int ret = 0;

	if (base < TASK_SIZE)
		ret = get_user_cr1_lo(cr1_lo, base, cr_ind);
	else
		get_kernel_cr1_lo(cr1_lo, base, cr_ind);
	return ret;
}

static inline int
get_cr1_hi(e2k_cr1_hi_t *cr1_hi, e2k_addr_t base, u64 cr_ind)
{
	int ret = 0;

	if (base < TASK_SIZE)
		ret = get_user_cr1_hi(cr1_hi, base, cr_ind);
	else
		get_kernel_cr1_hi(cr1_hi, base, cr_ind);
	return ret;
}

static inline int
put_cr0_lo(e2k_cr0_lo_t cr0_lo, e2k_addr_t base, u64 cr_ind)
{
	int ret = 0;

	if (base < TASK_SIZE)
		ret = put_user_cr0_lo(cr0_lo, base, cr_ind);
	else
		put_kernel_cr0_lo(cr0_lo, base, cr_ind);
	return ret;
}
static inline int
put_cr0_hi(e2k_cr0_hi_t cr0_hi, e2k_addr_t base, u64 cr_ind)
{
	int ret = 0;

	if (base < TASK_SIZE)
		ret = put_user_cr0_hi(cr0_hi, base, cr_ind);
	else
		put_kernel_cr0_hi(cr0_hi, base, cr_ind);
	return ret;
}

static inline int
put_cr1_lo(e2k_cr1_lo_t cr1_lo, e2k_addr_t base, u64 cr_ind)
{
	int ret = 0;

	if (base < TASK_SIZE)
		ret = put_user_cr1_lo(cr1_lo, base, cr_ind);
	else
		put_kernel_cr1_lo(cr1_lo, base, cr_ind);
	return ret;
}

static inline int
put_cr1_hi(e2k_cr1_hi_t cr1_hi, e2k_addr_t base, u64 cr_ind)
{
	int ret = 0;

	if (base < TASK_SIZE)
		ret = put_user_cr1_hi(cr1_hi, base, cr_ind);
	else
		put_kernel_cr1_hi(cr1_hi, base, cr_ind);
	return ret;
}

static inline int
get_cr0(e2k_cr0_lo_t *cr0_lo, e2k_cr0_hi_t *cr0_hi,
		e2k_pcsp_lo_t pcsp_lo, u64 cr_ind)
{
	u64 base = pcsp_lo.PCSP_lo_base;
	int ret = 0;

	ret += get_cr0_lo(cr0_lo, base, cr_ind);
	ret += get_cr0_hi(cr0_hi, base, cr_ind);
	return ret;
}

static inline int
get_cr1(e2k_cr1_lo_t *cr1_lo, e2k_cr1_hi_t *cr1_hi,
		e2k_pcsp_lo_t pcsp_lo, u64 cr_ind)
{
	u64 base = pcsp_lo.PCSP_lo_base;
	int ret = 0;

	ret += get_cr1_lo(cr1_lo, base, cr_ind);
	ret += get_cr1_hi(cr1_hi, base, cr_ind);
	return ret;
}

static inline int
get_user_crs(e2k_mem_crs_t *crs, e2k_addr_t base, e2k_addr_t cr_ind)
{
	unsigned long ts_flag;
	int ret;

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	ret = __copy_from_user(crs, (const char __user *)(base + cr_ind),
			sizeof(*crs));
	clear_ts_flag(ts_flag);

	return ret;
}

static inline int
put_user_crs(e2k_mem_crs_t *crs, e2k_addr_t base, e2k_addr_t cr_ind)
{
	unsigned long ts_flag;
	int ret;

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	ret = __copy_to_user((char __user *)(base + cr_ind), crs,
			sizeof(*crs));
	clear_ts_flag(ts_flag);

	return ret;
}

static inline void
get_kernel_crs(e2k_mem_crs_t *crs, e2k_addr_t base, e2k_addr_t cr_ind)
{
	get_kernel_cr0_lo(&crs->cr0_lo, base, cr_ind);
	get_kernel_cr0_hi(&crs->cr0_hi, base, cr_ind);
	get_kernel_cr1_lo(&crs->cr1_lo, base, cr_ind);
	get_kernel_cr1_hi(&crs->cr1_hi, base, cr_ind);
}

static inline void
put_kernel_crs(e2k_mem_crs_t *crs, e2k_addr_t base, e2k_addr_t cr_ind)
{
	put_kernel_cr0_lo(crs->cr0_lo, base, cr_ind);
	put_kernel_cr0_hi(crs->cr0_hi, base, cr_ind);
	put_kernel_cr1_lo(crs->cr1_lo, base, cr_ind);
	put_kernel_cr1_hi(crs->cr1_hi, base, cr_ind);
}

static inline int
get_crs(e2k_mem_crs_t *crs, e2k_addr_t base, e2k_addr_t cr_ind)
{
	int ret = 0;

	if (base < TASK_SIZE)
		ret = get_user_crs(crs, base, cr_ind);
	else
		get_kernel_crs(crs, base, cr_ind);
	return ret;
}

static inline int
put_crs(e2k_mem_crs_t *crs, e2k_addr_t base, e2k_addr_t cr_ind)
{
	int ret = 0;

	if (base < TASK_SIZE)
		ret = put_user_crs(crs, base, cr_ind);
	else
		put_kernel_crs(crs, base, cr_ind);
	return ret;
}

extern int chain_stack_frame_init(e2k_mem_crs_t *crs, void *fn_ptr,
		size_t dstack_size, e2k_psr_t psr,
		int wbs, int wpsz, bool user);

extern void __update_psp_regs(unsigned long base, unsigned long size,
				unsigned long new_fp,
				e2k_psp_lo_t *psp_lo, e2k_psp_hi_t *psp_hi);
extern void update_psp_regs(unsigned long new_fp,
			    e2k_psp_lo_t *psp_lo, e2k_psp_hi_t *psp_hi);

extern void __update_pcsp_regs(unsigned long base, unsigned long size,
				unsigned long new_fp,
				e2k_pcsp_lo_t *pcsp_lo, e2k_pcsp_hi_t *pcsp_hi);
extern void update_pcsp_regs(unsigned long new_fp,
			     e2k_pcsp_lo_t *pcsp_lo, e2k_pcsp_hi_t *pcsp_hi);

#endif /* _E2K_HW_STACKS_H */
