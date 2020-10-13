#include <asm/fast_syscalls.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>

#if _NSIG != 64
# error We read u64 value here...
#endif
notrace __interrupt __section(.ttable_entry6_C)
int fast_sys_siggetmask(u64 __user *oset, size_t sigsetsize)
{
	struct thread_info *const ti =
			(struct thread_info *) E2K_GET_DSREG_NV(osr0);
	struct task_struct *task = ti->task;
	u64 set;

	set = task->blocked.sig[0];

	if (unlikely(sigsetsize != 8))
		return -EINVAL;

	oset = (typeof(oset)) ((u64) oset & E2K_VA_MASK);
	if (unlikely((u64) oset + sizeof(sigset_t) > ti->addr_limit.seg))
		return -EFAULT;

	*oset = set;

	return 0;
}

