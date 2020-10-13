#include <linux/compat.h>
#include <linux/time.h>

#include <asm/fast_syscalls.h>
#include <asm/process.h>
#include <asm/uaccess.h>
#include <asm/ucontext.h>
#include <asm/unistd.h>

#if _NSIG != 64
# error We read u64 value here...
#endif
notrace __interrupt __section(.entry_handlers)
int fast_sys_getcontext(struct ucontext __user *ucp, size_t sigsetsize)
{
	struct thread_info *const ti =
			(struct thread_info *) E2K_GET_DSREG_NV(osr0);
	struct task_struct *task = ti->task;
	register u64 pcsp_lo, pcsp_hi;
	register u32 fpcr, fpsr, pfpfr;
	u64 set;

	BUILD_BUG_ON(sizeof(task->blocked.sig[0]) != 8);
	set = task->blocked.sig[0];

	if (unlikely(sigsetsize != 8))
		return -EINVAL;

	ucp = (typeof(ucp)) ((u64) ucp & E2K_VA_MASK);
	if (unlikely((u64) ucp + sizeof(struct ucontext) > ti->addr_limit.seg))
		return -EFAULT;

	E2K_GETCONTEXT(fpcr, fpsr, pfpfr, pcsp_lo, pcsp_hi);

	/* We want stack to point to user frame that called us */
	pcsp_hi -= SZ_OF_CR;

	*((u64 *) &ucp->uc_sigmask) = set;
	ucp->uc_mcontext.sbr = context_ti_key(ti);
	ucp->uc_mcontext.pcsp_lo = pcsp_lo;
	ucp->uc_mcontext.pcsp_hi = pcsp_hi;
	ucp->uc_extra.fpcr = fpcr;
	ucp->uc_extra.fpsr = fpsr;
	ucp->uc_extra.pfpfr = pfpfr;

	return 0;
}

