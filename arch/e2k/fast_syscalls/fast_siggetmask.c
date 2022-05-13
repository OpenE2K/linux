#include <asm/fast_syscalls.h>
#include <linux/uaccess.h>
#include <asm/unistd.h>

#if _NSIG != 64
# error We read u64 value here...
#endif

notrace __interrupt __section(.entry_handlers)
int fast_sys_siggetmask(u64 __user *oset, size_t sigsetsize)
{
	return _fast_sys_siggetmask(oset, sigsetsize);
}
