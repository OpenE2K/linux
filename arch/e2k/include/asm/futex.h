/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _ASM_FUTEX_H
#define _ASM_FUTEX_H

#ifdef __KERNEL__

#include <linux/futex.h>

#include <asm/atomic.h>
#include <asm/e2k_api.h>
#include <asm/errno.h>
#include <linux/uaccess.h>

static inline int arch_futex_atomic_op_inuser(int op, int oparg, int *oval,
					      u32 __user *uaddr)
{
	int oldval, ret = 0;

	if (!access_ok(uaddr, sizeof(u32)))
		return -EFAULT;

	uaccess_enable();
	switch (op) {
	case FUTEX_OP_SET:
		ret = __api_user_xchg(oparg, uaddr, w, STRONG_MB, oldval);
		break;
	case FUTEX_OP_ADD:
		ret = __api_user_atomic32_op("adds", oparg, uaddr, STRONG_MB, oldval);
		break;
	case FUTEX_OP_OR:
		ret = __api_user_atomic32_op("ors", oparg, uaddr, STRONG_MB, oldval);
		break;
	case FUTEX_OP_ANDN:
		ret = __api_user_atomic32_op("andns", oparg, uaddr, STRONG_MB, oldval);
		break;
	case FUTEX_OP_XOR:
		ret = __api_user_atomic32_op("xors", oparg, uaddr, STRONG_MB, oldval);
		break;
	default:
		oldval = 0;
		ret = -ENOSYS;
		break;
	}
	uaccess_disable();

	if (!ret)
		*oval = oldval;

	return ret;
}

static inline int futex_atomic_cmpxchg_inatomic(u32 *uval, u32 __user *uaddr,
						u32 oldval, u32 newval)
{
	int ret;

	if (!access_ok(uaddr, sizeof(u32)))
		return -EFAULT;

	uaccess_enable();
	ret = __api_user_cmpxchg_word(oldval, newval, uaddr, STRONG_MB, *uval);
	uaccess_disable();

	return ret;
}

#endif
#endif
