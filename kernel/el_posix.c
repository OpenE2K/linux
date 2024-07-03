/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Here is implementation of Posix Support
 * Two variants are implemented:
 *
 * 1. There is pobjs pointer in thread_t structure which points
 * to el_pobjs.
 *
 * 2. There are two variants to work with mutex (see el_posix.h):
 *
 * #define WAKEUP_MUTEX_ONE  1  // to wakeup only one thread
 * #define WAKEUP_MUTEX_ONE  0  // to wakeup all
 *
 * Short description of work.
 *
 * el_pobjs has two head queues for posix threads which are waiting
 * mutexes or conditions. User's address of needed mutex or condition
 * are located in item of queue.
 * Internel function pthread_run() will wakeup needed pthreads only.
 *
 * Implementation in kernel.
 * 	Aditional system call el_posix() was implemented for el_pthread lib:
 *
 *	sys_el_posix() (see kernel/el_posix.c)
 *	sys_clone2()	(see arch/e2k/process.c)
 *
 * 	To define syscall el_posix() was done:
 *
 *	unistd.h:
 *		#define	__NR_el_posix		255
 *	e2k_syswork.h :
 *		static inline _syscall5(int, el_posix, int, req,
 *				void *, a1, void *, a2, void *, a3, void *, a4);
 *
 *	systable.c :
 *		SYSTEM_CALL_DEFINE(sys_el_posix);
 *		SYSTEM_CALL_TBL_ENTRY(sys_el_posix),
 *
 * Note that to port our posix for sparc and i386 only sys_el_posix()
 * 	is needed as syscall el_posix().
 * 	sys_el_posix() can be port without changing as additional system call
 * 	(as for E2K)
 * 	or can be done as psevdo driver.
 *	Instead sys_clone2() should  be used nativ clone() (system call
 *	(see el_pthread.c)
 *
 *
 * Implementation of posix lib.
 * 	See el_pthread.c where lib posix is inplemented using el_posix()
 *
 * Posix implementation includes
 * 1. new linux/el_posix.h
 * 2. new kernel/el_posix.c
 * additional element is needed in struct thread_t:
 *	void		*pobjs;
 *
 * == SVS ==
 */

#define	DEBUG_POSIX	0	/* DEBUG_POSIX */
#if DEBUG_POSIX
# define DEBUG
# define DbgPos(fmt, ...) \
		trace_printk("%d " fmt, current->pid ,##__VA_ARGS__)
#else
# define DbgPos(...)
#endif

#include <linux/el_posix.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/timer.h>
#include <linux/interrupt.h>
#include <linux/compat.h>
#include <linux/spinlock.h>
#include <linux/proc_fs.h>
#ifdef CONFIG_MCST
#include <linux/hrtimer.h>
#include <linux/anon_inodes.h>
#include <linux/file.h>
#include <uapi/linux/mcst_rt.h>
#include <uapi/linux/el_posix.h>
#endif

#include <linux/sched/rt.h>

#ifdef CONFIG_E90S
#include <asm/e90s.h>
#endif
#include <asm/delay.h>
#include <asm/processor.h>
#include <asm/uaccess.h>
#ifdef CONFIG_SCLKR_CLOCKSOURCE
#include <asm/sclkr.h>
#endif

#define PMUTEX_UNLOCKED 1
#define PMUTEX_LOCKED_ONCE 0
//#define PMUTEX_HAS_QUEUE 2

#define PTHREAD_WAIT (PMUTEX_WAIT | PCOND_WAIT | WAKEUP_PID_WAIT | SWITCH_WAIT)

/*
 * wakeup_mode
 */
#define WAKEUP_ALL	0x100
#define WAKEUP_ONE	0x101
#define MOVE_TO_MUTEX	0x102
#define WAKEUP_PID	0x103

int have_pps_mpv = 0;
EXPORT_SYMBOL(have_pps_mpv);

int (*send_pps_mpv)(u32, int) = NULL;
EXPORT_SYMBOL(send_pps_mpv);
int (*mpv_get_freq_ptr)(u32) = NULL;
EXPORT_SYMBOL(mpv_get_freq_ptr);


/* cpu_freq_hz is used to convert clocks into ns in user space */
u32 cpu_freq_hz = UNSET_CPU_FREQ; /* CPU freq (Hz) */
EXPORT_SYMBOL(cpu_freq_hz);
int __init cpufreq_setup(char *str)
{
	cpu_freq_hz = simple_strtoul(str, &str, 0);
	return 1;
}
__setup("cpufreq=", cpufreq_setup);

#if defined(CONFIG_E2K)
extern long irq_bind_to_cpu(int irq_msk, int cpu);
extern long el_set_apic_timer(void);
extern long el_unset_apic_timer(void);
#endif

/*
 * Set rts_mode. enable mlock, param priority, setaffinity, cpu_bind,
 * irq_bind & mlock for all users.
 */

#define BAD_USER_REGION(addr, type) \
	(unlikely(!access_ok(VERIFY_WRITE, addr, sizeof(type)) \
		|| (((unsigned long) addr) % __alignof__(type)) != 0 ))

/*
 * If user call any func with bad addres in user area then he get SIGSEGV
 * from kernel's do_page_fault()
 */


/* To simplify 32-bit support user-space library always uses
 * 64-bit values for tv_sec and tv_nsec in struct timespec. */
struct timespec_64 {
	long long tv_sec;
	long long tv_nsec;
};

static DEFINE_RAW_SPINLOCK(atomic_add_lock);
/*#define EL_TIMERFD_USING */

/*#define SHOW_WOKEN_TIME*/
#ifdef SHOW_WOKEN_TIME
int show_woken_time = 0;
EXPORT_SYMBOL(show_woken_time);

int __init woken_setup(char *str)
{
	show_woken_time = simple_strtoul(str, &str, 0);
	return 1;
}
__setup("wokent=", woken_setup);

static ssize_t woken_write(struct file *file, const char __user *ubuf,
				size_t count, loff_t *ppos)
{
	char str[64];

	if (count == 0)
		return 0;
	if (copy_from_user(str, ubuf, sizeof(str)))
		return -EFAULT;
	show_woken_time = simple_strtoul(str, NULL, 0);
	return count;
}

int show_woken(struct seq_file *p, void *v)
{
	seq_printf(p, "wokent= %d\n", show_woken_time);
	return 0;
}

static int woken_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, show_woken, PDE_DATA(inode));
}

static const struct proc_ops proc_woken_operations = {
	.proc_open	= woken_open,
	.proc_read	= seq_read,
	.proc_write	= woken_write,
	.proc_lseek	= seq_lseek,
	.proc_release	= seq_release,
};

static int __init proc_woken_init(void)
{
	proc_create("woken-time", 0, NULL, &proc_woken_operations);
	return 0;
}
module_init(proc_woken_init);
#endif

int  cpus_intcount[NR_CPUS];

#include <linux/cpuset.h>

#ifdef SHOW_WOKEN_TIME
static int pr_err_done = 0;
#endif

long do_el_posix(int req, void __user *a1, void __user *a2,
		 void __user *a3, int a4)
{
	long 		rval = 0;

	switch (req) {
	case EL_ATOMIC_ADD: {
		int *target = (int *)a1;
		int delta   = (long)a2;
		int *dst    = (int *)a3;
		int val;

		raw_spin_lock_irq(&atomic_add_lock);
		rval = get_user(val, target);
		rval |= put_user(val, dst);
		rval |= put_user((val + delta), target);
		raw_spin_unlock_irq(&atomic_add_lock);
		break;
	}
#ifdef CONFIG_SCLKR_CLOCKSOURCE
	case EL_SCLKR_READ:
		return clocksource_sclkr.read(NULL);
#endif
	case EL_MISC_TO_DEBUG:
		switch ((long) a1) {
#ifdef CONFIG_E90S
#include <asm/pcr.h>
		case 6: {
			int reg = (int)(long long)a2;
			int val = (int)(long long)a3;
			wr_pcr(E90S_PCR_SYS | (val << 11));
			pr_warn("write_pcr reg=%d val=0x%x [reg]=0x%lx\n",
				reg, val,  E90S_PCR_SYS | (val << 11));
			break;
		}
#endif
		case 11:
			current->utime += (long)a2;
			current->se.sum_exec_runtime += (long)a2 * 10000000;
			printk(KERN_INFO "DBG pid=%d times are u=%lld s=%lld r=%lld"
					" after adding %ld\n",
				current->pid, current->utime, current->stime,
				current->se.sum_exec_runtime, (long)a2);
			break;
		}
		DbgPos("sys_el_posix: EL_MISC_TO_DEBUG\n");
		break;
	default:
		rval = -EINVAL;
	}
	return rval;
}


SYSCALL_DEFINE5(el_posix, int, req, void __user *, a1, void __user *, a2,
		void __user *, a3, int, a4)
{
	return do_el_posix(req, a1, a2, a3, a4);
}
#if !defined(CONFIG_E2K) && !defined(CONFIG_E90S)
asmlinkage long sys_el_posix(int req, void __user *a1, void __user *a2,
				    void __user *a3, int a4)
{
	return do_el_posix(req, a1, a2, a3, a4);
}
#endif
#ifdef CONFIG_COMPAT
COMPAT_SYSCALL_DEFINE5(el_posix, int, req, void __user *, a1, void __user *, a2,
				    void __user *, a3, int, a4)
{
	long rval;

	switch (req) {
		/* TODO: all el_posix users must use this interface */
		default:
			rval = do_el_posix(req, a1, a2, a3, a4);
			break;
	}
	return rval;
}
#endif /* CONFIG_COMPAT */

#include "sched/sched.h"
/*
 * Ease the printing of nsec fields:
 */
static long long nsec_high(unsigned long long nsec)
{
	if ((long long)nsec < 0) {
		nsec = -nsec;
		do_div(nsec, 1000000);
		return -nsec;
	}
	do_div(nsec, 1000000);
	return nsec;
}

static unsigned long nsec_low(unsigned long long nsec)
{
	if ((long long)nsec < 0)
		nsec = -nsec;
	return do_div(nsec, 1000000);
}
#define SPLIT_NS(x) nsec_high((x)), nsec_low((x))

static long long prev_cpuque_time = 0;
static long long intrv_cpuque_time = 0;
static long long cpuque_time;
int cpu_queue_collect = 0;
static void
print_task_s(struct seq_file *m, struct task_struct *p, int new_result, long long cur_tm)
{
	unsigned long flags;
	struct rq *rq = &per_cpu(runqueues, task_cpu(p));

	raw_spin_lock_irqsave(&rq->lock, flags);
	if (new_result) {
		p->se.oncpu_tm_res = p->se.oncpu_tm;
		if (p->se.oncpu_tm < 0) {
			p->se.oncpu_tm_res += cur_tm;
			p->se.oncpu_tm = -cur_tm;
		} else {
			p->se.oncpu_tm = 0;
		}
		p->se.ctx_sw_tm_res = p->se.ctx_sw_tm;
		if (p->se.ctx_sw_tm < 0) {
			p->se.ctx_sw_tm_res += cur_tm;
			p->se.ctx_sw_tm = -cur_tm;
		} else {
			p->se.ctx_sw_tm = 0;
		}
		p->se.cpu_queue_res = p->se.cpu_queue_tm;
		if (p->se.cpu_queue_tm < 0) {
			p->se.cpu_queue_res += cur_tm;
			p->se.cpu_queue_tm = -cur_tm;
		} else {
			p->se.cpu_queue_tm = 0;
		}
		p->se.cpu_queue_res -= p->se.oncpu_tm_res;
	}
	raw_spin_unlock_irqrestore(&rq->lock, flags);

	if (rq->curr == p)
		seq_printf(m, ">R");
	else
		seq_printf(m, " %c", task_state_to_char(p));

	seq_printf(m, "%15s id %5d %3d %9lld.%06ld %3lld %9lld.%06ld %3lld %9lld.%06ld %4lld",
		p->comm, task_pid_nr(p), task_cpu(p),
		SPLIT_NS((p->se.oncpu_tm_res)),
		p->se.oncpu_tm_res * 1000 / intrv_cpuque_time,
		SPLIT_NS((p->se.ctx_sw_tm_res)),
		p->se.ctx_sw_tm_res * 1000 / intrv_cpuque_time,
		SPLIT_NS((p->se.cpu_queue_res)),
		p->se.cpu_queue_res * 1000 / intrv_cpuque_time
		);
	if (new_result) {
		p->se.delt_exec_runtime =
			p->se.sum_exec_runtime - p->se.prev_runtime;
		p->se.prev_runtime = p->se.sum_exec_runtime;
	}
	seq_printf(m, "%9lld.%06ld %2lld\n",
	    SPLIT_NS((p->se.delt_exec_runtime)),
	    p->se.delt_exec_runtime * 1000 / intrv_cpuque_time);
}

static int  cpu_queue_show(struct seq_file *m, void *v)
{
	struct task_struct *g, *p;
	long long cur_tm_us, intrv_us;
	int new_result = 0;

	/* cpu_queue_show() is called 4-11 times for severel consoles
	 * for each cat /proc/cpu_queue run but we got single prev_* result */
	cpuque_time = sched_clock();
	if (!prev_cpuque_time || (cpuque_time - prev_cpuque_time > 300000000)) {
		intrv_cpuque_time = cpuque_time - prev_cpuque_time;
		prev_cpuque_time = cpuque_time;
		new_result = 1;
	}
	cur_tm_us = cpuque_time / 1000; /* to covert ns -> sec by SPLIT_NS() */
	intrv_us = intrv_cpuque_time / 1000;
	seq_printf(m, "\n  Sched_clock= %lld.%06ld Interval= %lld.%06ld sec\n",
			SPLIT_NS((cur_tm_us)), SPLIT_NS((intrv_us)));
	seq_printf(m, "s   process-name      PID  cpu      cpu_time(ms) %%o");
	seq_printf(m, "      ctx_swch(ms) %%o      cpu_queue(ms) %%o");
	seq_printf(m, "   Dsum-exec(ms) %%o\n");
	rcu_read_lock();
	for_each_process_thread(g, p) {
		print_task_s(m, p, new_result, cpuque_time);
	}
	rcu_read_unlock();
	return 0;
}
static int __init init_cpu_queue_procfs(void)
{
	proc_create_single("cpu_queue", 0, NULL, cpu_queue_show);
	return 0;
}
device_initcall(init_cpu_queue_procfs);
int __init cpu_queue_setup(char *str)
{
	cpu_queue_collect = 1;
	return 1;
}
__setup("cpu_queue_stat", cpu_queue_setup);
