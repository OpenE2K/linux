/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _ASM_FUTEX_H
#define _ASM_FUTEX_H

#include <linux/futex.h>
#include <linux/uaccess.h>

#include <asm/atomic.h>
#include <asm/e2k_api.h>
#include <asm/errno.h>
#include <asm/mmu_types.h>

static inline int arch_futex_atomic_op_inuser(int op, int oparg, int *oval,
					      u32 __user *uaddr)
{
	int oldval, ret = 0;
	unsigned long flags;
	bool use_descriptor = !cpu_has(CPU_FEAT_ATOMIC_LDRD) && TASK_IS_PROTECTED(current);

	if (!access_ok(uaddr, sizeof(u32)))
		return -EFAULT;

	uaccess_enable();

	if (use_descriptor) {
		raw_all_irq_save(flags);
		e2k_usd_t usd = read_USD_reg();
		usd.P = 1;
		write_USD_reg(usd);
	}

	switch (op) {
	case FUTEX_OP_SET:
		ret = __api_user_xchg(oparg, uaddr, 4, w, LDST_WORD_FMT,
				      use_descriptor, STRONG_MB, oldval);
		break;
	case FUTEX_OP_ADD:
		ret = __api_user_atomic32_op("adds", oparg, uaddr,
					     use_descriptor, STRONG_MB, oldval);
		break;
	case FUTEX_OP_OR:
		ret = __api_user_atomic32_op("ors", oparg, uaddr,
					     use_descriptor, STRONG_MB, oldval);
		break;
	case FUTEX_OP_ANDN:
		ret = __api_user_atomic32_op("andns", oparg, uaddr,
					     use_descriptor, STRONG_MB, oldval);
		break;
	case FUTEX_OP_XOR:
		ret = __api_user_atomic32_op("xors", oparg, uaddr,
					     use_descriptor, STRONG_MB, oldval);
		break;
	default:
		oldval = 0;
		ret = -ENOSYS;
		break;
	}

	if (use_descriptor) {
		e2k_usd_t usd = read_USD_reg();
		usd.P = 0;
		write_USD_reg(usd);
		raw_all_irq_restore(flags);
	}

	uaccess_disable();

	if (!ret)
		*oval = oldval;

	return ret;
}

static inline int futex_atomic_cmpxchg_inatomic(u32 *uval, u32 __user *uaddr,
						u32 oldval, u32 newval)
{
	unsigned long flags;
	bool use_descriptor = !cpu_has(CPU_FEAT_ATOMIC_LDRD) && TASK_IS_PROTECTED(current);
	int ret;

	if (!access_ok(uaddr, sizeof(u32)))
		return -EFAULT;

	uaccess_enable();

	if (use_descriptor) {
		raw_all_irq_save(flags);
		e2k_usd_t usd = read_USD_reg();
		usd.P = 1;
		write_USD_reg(usd);
	}

	ret = __api_user_cmpxchg_word(oldval, newval, uaddr, use_descriptor, STRONG_MB, *uval);

	if (use_descriptor) {
		e2k_usd_t usd = read_USD_reg();
		usd.P = 0;
		write_USD_reg(usd);
		raw_all_irq_restore(flags);
	}

	uaccess_disable();

	return ret;
}

#endif
