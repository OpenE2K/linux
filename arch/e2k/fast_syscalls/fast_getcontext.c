#include <linux/compat.h>
#include <linux/time.h>

#include <asm/fast_syscalls.h>
#include <asm/process.h>
#include <linux/uaccess.h>
#include <asm/ucontext.h>
#include <asm/unistd.h>

#if _NSIG != 64
# error We read u64 value here...
#endif
notrace __interrupt __section(".entry.text")
int fast_sys_getcontext(struct ucontext __user *ucp, size_t sigsetsize)
{
	struct thread_info *const ti = READ_CURRENT_REG();
	struct task_struct *task = thread_info_task(ti);
	register u64 pcsp_lo, pcsp_hi;
	register u32 fpcr, fpsr, pfpfr;
	u64 set, key;

#ifdef	CONFIG_KVM_HOST_MODE
	/* TODO getcontext does not have a slow counterpart, not implemented for paravirt guest */
	KVM_BUG_ON(test_ti_status_flag(ti, TS_HOST_AT_VCPU_MODE));
#endif

	BUILD_BUG_ON(sizeof(task->blocked.sig[0]) != 8);
	set = task->blocked.sig[0];

	if (unlikely(sigsetsize != 8))
		return -EINVAL;

	ucp = (typeof(ucp)) ((u64) ucp & E2K_VA_MASK);
	if (unlikely((u64) ucp + sizeof(struct ucontext) > ti->addr_limit.seg))
		return -EFAULT;

	key = context_ti_key_fast_syscall(ti);

	E2K_GETCONTEXT(fpcr, fpsr, pfpfr, pcsp_lo, pcsp_hi);

	/* We want stack to point to user frame that called us */
	pcsp_hi -= SZ_OF_CR;

	*((u64 *) &ucp->uc_sigmask) = set;
	ucp->uc_mcontext.sbr = key;
	ucp->uc_mcontext.pcsp_lo = pcsp_lo;
	ucp->uc_mcontext.pcsp_hi = pcsp_hi;
	ucp->uc_extra.fpcr = fpcr;
	ucp->uc_extra.fpsr = fpsr;
	ucp->uc_extra.pfpfr = pfpfr;

	return 0;
}

