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

	pagefault_disable();

	TRY_USR_PFAULT {
		switch (op) {
		case FUTEX_OP_SET:
			oldval = __api_xchg_return(oparg, uaddr, w, STRONG_MB);
			break;
		case FUTEX_OP_ADD:
			oldval = __api_futex_atomic32_op("adds", oparg, uaddr);
			break;
		case FUTEX_OP_OR:
			oldval = __api_futex_atomic32_op("ors", oparg, uaddr);
			break;
		case FUTEX_OP_ANDN:
			oldval = __api_futex_atomic32_op("andns", oparg, uaddr);
			break;
		case FUTEX_OP_XOR:
			oldval = __api_futex_atomic32_op("xors", oparg, uaddr);
			break;
		default:
			oldval = 0;
			ret = -ENOSYS;
			break;
		}
	} CATCH_USR_PFAULT {
		pagefault_enable();
		DebugUAF("%s (%d) - %s : futex_atomic_op data fault "
				"%px(%ld)\n" , __FILE__, __LINE__,
				__FUNCTION__, (uaddr), (sizeof(*uaddr)));
		return -EFAULT;
	} END_USR_PFAULT

	pagefault_enable();

	if (!ret)
		*oval = oldval;

	return ret;
}

static int futex_atomic_cmpxchg_inatomic(u32 *uval, u32 __user *uaddr,
					 u32 oldval, u32 newval)
{
	if (!access_ok(uaddr, sizeof(int)))
		return -EFAULT;

	TRY_USR_PFAULT {
		*uval = cmpxchg(uaddr, oldval, newval);
	} CATCH_USR_PFAULT {
		DebugUAF("%s (%d) - %s : futex_atomic_cmpxchg data fault "
				"%px(%ld)\n", __FILE__, __LINE__,
				__FUNCTION__, (uaddr), (sizeof(*uaddr)));
		return -EFAULT;
	} END_USR_PFAULT

	return 0;
}

#endif
#endif
