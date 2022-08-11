#include <linux/seqlock.h>

#include <asm/fast_syscalls.h>
#include <linux/uaccess.h>
#include <asm/unistd.h>

notrace __interrupt __section(".entry.text")
int fast_sys_getcpu(unsigned __user *cpup, unsigned __user *nodep,
		struct getcpu_cache __user *unused)
{
	struct thread_info *const ti = READ_CURRENT_REG();
	int cpu = task_cpu(thread_info_task(ti));
	int node;

#ifdef	CONFIG_KVM_HOST_MODE
	if (unlikely(test_ti_status_flag(ti, TS_HOST_AT_VCPU_MODE)))
		ttable_entry_getcpu((u64) cpup, (u64) nodep, (u64) unused);
#endif

	cpup = (typeof(cpup)) ((u64) cpup & E2K_VA_MASK);
	nodep = (typeof(nodep)) ((u64) nodep & E2K_VA_MASK);
	if (unlikely((u64) cpup + sizeof(unsigned) > ti->addr_limit.seg
			|| (u64) nodep + sizeof(unsigned) > ti->addr_limit.seg))
		return -EFAULT;

	if (nodep)
		node = cpu_to_node(cpu);

	if (nodep)
		*nodep = node;
	if (cpup)
		*cpup = cpu;

	return 0;
}

