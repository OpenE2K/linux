#include <linux/compat.h>
#include <linux/time.h>

#include <asm/fast_syscalls.h>
#include <asm/process.h>
#include <linux/uaccess.h>
#include <asm/ucontext.h>

#define	ttable_entry1_args3(sys_num, arg1, arg2)	\
		((ttable_entry_args3)(ttable_entry1))(sys_num, arg1, arg2)
#define	ttable_entry1_args4(sys_num, arg1, arg2, arg3)	\
		((ttable_entry_args4)(ttable_entry1))(sys_num, arg1, arg2, arg3)

notrace __section(".entry.text")
int compat_fast_sys_clock_gettime(const clockid_t which_clock,
		struct compat_timespec __user *__restrict tp)
{
	return _compat_fast_sys_clock_gettime(which_clock, tp);
}

notrace __section(".entry.text")
int compat_fast_sys_gettimeofday(struct compat_timeval __user *__restrict tv,
		struct timezone __user *__restrict tz)
{
	return _compat_fast_sys_gettimeofday(tv, tz);
}

notrace __interrupt __section(".entry.text")
int compat_fast_sys_siggetmask(u32 __user *oset, size_t sigsetsize)
{
	return _compat_fast_sys_siggetmask(oset, sigsetsize);
}

notrace __interrupt __section(".entry.text")
int compat_fast_sys_getcontext(struct ucontext_32 __user *ucp,
		size_t sigsetsize)
{
	return _compat_fast_sys_getcontext(ucp, sigsetsize);
}
