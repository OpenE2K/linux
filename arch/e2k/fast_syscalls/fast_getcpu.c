#include <linux/seqlock.h>

#include <asm/fast_syscalls.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>

notrace __interrupt __section(.entry_handlers)
int fast_sys_getcpu(unsigned __user *cpup, unsigned __user *nodep,
		struct getcpu_cache __user *unused)
{
	struct thread_info *const ti =
			(struct thread_info *) E2K_GET_DSREG_NV(osr0);
	int cpu = ti->cpu;
	int node;

	cpup = (typeof(cpup)) ((u64) cpup & E2K_VA_MASK);
	nodep = (typeof(nodep)) ((u64) nodep & E2K_VA_MASK);
	if (unlikely((u64) cpup + sizeof(unsigned) > ti->addr_limit.seg
			|| (u64) nodep + sizeof(unsigned) > ti->addr_limit.seg))
		return -EFAULT;

	if (nodep)
		node = cpu_to_node(cpu);

	if (cpup)
		*cpup = cpu;
	if (nodep)
		*nodep = node;

	return 0;
}

