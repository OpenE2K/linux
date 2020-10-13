#ifndef _ASM_FUTEX_H
#define _ASM_FUTEX_H

#ifdef __KERNEL__

#include <linux/futex.h>
#include <asm/atomic.h>
#include <asm/e2k_api.h>
#include <asm/errno.h>
#include <asm/uaccess.h>

static int noinline
futex_atomic_op_inuser (int encoded_op, int __user *uaddr)
{
	int op = (encoded_op >> 28) & 7;
	int cmp = (encoded_op >> 24) & 15;
	int oparg = (encoded_op << 8) >> 20;
	int cmparg = (encoded_op << 20) >> 20;
	int oldval, ret = 0;

	if (encoded_op & (FUTEX_OP_OPARG_SHIFT << 28))
		oparg = 1 << oparg;

	if (!access_ok(VERIFY_WRITE, uaddr, sizeof(int)))
		return -EFAULT;

	pagefault_disable();

	BEGIN_USR_PFAULT("lbl_futex_atomic_op", "9f") ;
	switch (op) {
	case FUTEX_OP_SET:
		oldval = __api_xchg32_return(oparg, uaddr);
		break;
	case FUTEX_OP_ADD:
		oldval = __futex_atomic32_op("adds", oparg, uaddr);
		break;
	case FUTEX_OP_OR:
		oldval = __futex_atomic32_op("ors", oparg, uaddr);
		break;
	case FUTEX_OP_ANDN:
		oldval = __futex_atomic32_op("andns", oparg, uaddr);
		break;
	case FUTEX_OP_XOR:
		oldval = __futex_atomic32_op("xors", oparg, uaddr);
		break;
	default:
		oldval = 0;
		ret = -ENOSYS;
		break;
	}
	LBL_USR_PFAULT("lbl_futex_atomic_op", "9:");
	if (END_USR_PFAULT) {
		pagefault_enable();
		DebugUAF("%s (%d) - %s : futex_atomic_op data fault "
				"%p(%ld)\n" , __FILE__, __LINE__,
				__FUNCTION__, (uaddr), (sizeof(*uaddr)));
		return -EFAULT;
	}

	pagefault_enable();

	if (!ret) {
		switch (cmp) {
		case FUTEX_OP_CMP_EQ:
			ret = (oldval == cmparg);
			break;
		case FUTEX_OP_CMP_NE:
			ret = (oldval != cmparg);
			break;
		case FUTEX_OP_CMP_LT:
			ret = (oldval < cmparg);
			break;
		case FUTEX_OP_CMP_GE:
			ret = (oldval >= cmparg);
			break;
		case FUTEX_OP_CMP_LE:
			ret = (oldval <= cmparg);
			break;
		case FUTEX_OP_CMP_GT:
			ret = (oldval > cmparg);
			break;
		default:
			ret = -ENOSYS;
			break;
		}
	}

	return ret;
}

static int noinline 
futex_atomic_cmpxchg_inatomic(u32 *uval, u32 __user *uaddr,
			      u32 oldval, u32 newval)
{
	int tmp;

	if (!access_ok(VERIFY_WRITE, uaddr, sizeof(int)))
		return -EFAULT;

	BEGIN_USR_PFAULT("lbl_futex_atomic_cmpxchg", "8f");
	tmp = cmpxchg(uaddr, oldval, newval);
	LBL_USR_PFAULT("lbl_futex_atomic_cmpxchg", "8:");
	if (END_USR_PFAULT) {
		DebugUAF("%s (%d) - %s : futex_atomic_cmpxchg data fault "
				"%p(%ld)\n", __FILE__, __LINE__,
				__FUNCTION__, (uaddr), (sizeof(*uaddr)));
		return -EFAULT;
	}

	*uval = tmp;

	return 0;
}

#endif
#endif
