#include <asm/fast_syscalls.h>
#include <linux/uaccess.h>
#include <asm/unistd.h>

#if _NSIG != 64
# error We read u64 value here...
#endif

notrace __interrupt __section(.ttable_entry6_C)
int native_fast_sys_siggetmask(u64 __user *oset, size_t sigsetsize)
{
	return FAST_SYS_SIGGETMASK(oset, sigsetsize);
}

