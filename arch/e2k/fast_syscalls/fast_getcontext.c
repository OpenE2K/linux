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
	return _fast_sys_getcontext(ucp, sigsetsize);
}
