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
#include <linux/sched/clock.h>

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

#ifdef CONFIG_MCST_4RT
static DEFINE_RAW_SPINLOCK(rts_lock);
long rts_mode = 0;	// hard realtime mode 0-unactive, 1-active
EXPORT_SYMBOL(rts_mode);
// mcst realtime mode mask
long rts_act_mask = 0;
EXPORT_SYMBOL(rts_act_mask);
#endif	/* CONFIG_MCST_4RT */

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
#ifdef CONFIG_MCST_4RT
static long
change_rts_mode_mask(long mode, long mask)
{
	unsigned long flags;
	long ret = rts_mode;

	if (mode != -1 && mask != -1) {
		printk("change_rts_mode_mask wrong mode = %ld, mask = %ld\n", mode, mask);
		return -EINVAL;
	}
	raw_spin_lock_irqsave(&rts_lock, flags);

	if (mode != -1) {
		if (!capable(CAP_SYS_ADMIN)) {
			ret = -EPERM;
			goto unlock;
		}
	
		mode = !!mode;
		if (mode == rts_mode) {
			goto unlock;
		}
		rts_mode = mode;
		if (mode) {
			mask = RTS_SOFT__RT;
		} else {
			mask = 0;
		}
	}
	ret = rts_act_mask;
	rts_act_mask = mask;

unlock:
	raw_spin_unlock_irq(&rts_lock);
	return ret;
}

#include <linux/sysctl.h>

static DEFINE_MUTEX(sysctl_lock);
static int sysctl_rts_mode;
static int sysctl_rts_mask;


static int
rts_mode_sysctl(struct ctl_table *table, int write,
                     void __user *buffer, size_t *lenp,
                     loff_t *ppos)
{
        int ret;

        mutex_lock(&sysctl_lock); 
	sysctl_rts_mode = !!rts_mode; 
        ret  = proc_dointvec(table, write, buffer, lenp, ppos);

        if (ret || !write )
                goto out;
	       
	ret = (int)change_rts_mode_mask((long)sysctl_rts_mode, -1);

 out:
        mutex_unlock(&sysctl_lock);
        return ret;
}



static int
rts_mask_sysctl(struct ctl_table *table, int write,
                     void __user *buffer, size_t *lenp,
                     loff_t *ppos)
{
        int ret;

        mutex_lock(&sysctl_lock); 
	sysctl_rts_mask = (int)rts_act_mask; 
        ret  = proc_dointvec(table, write, buffer, lenp, ppos);

        if (ret || !write )
                goto out;
	       
	ret = (int)change_rts_mode_mask(-1, (long)sysctl_rts_mask);

 out:
        mutex_unlock(&sysctl_lock);
        return ret;
}

struct ctl_table rt_table[] = {
       {
                .procname       = "rts_mode",
                .data           = &sysctl_rts_mode,
                .maxlen         = sizeof(unsigned int),
                .mode           = 0644,
                .proc_handler   = rts_mode_sysctl,
       },
       {
                .procname       = "rts_act_mask",
                .data           = &sysctl_rts_mask,
                .maxlen         = sizeof(unsigned int),
                .mode           = 0644,
                .proc_handler   = rts_mask_sysctl,
        },
	{}
};

#endif

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
#ifdef CONFIG_MCST_RT
#ifdef EL_TIMERFD_USING
static int el_open_timerfd(void);
static int el_timerfd_settime(int ufd, struct __kernel_itimerspec __user *tmr);
#ifdef CONFIG_COMPAT
static int compat_el_timerfd_settime(int ufd, struct old_itimerspec32 __user *tmr);
#endif
#endif /*EL_TIMERFD_USING */
#endif

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
#ifdef CONFIG_MCST_4RT
	/* For mcst_rt lib: */
	case EL_GET_CPUS_NUM:
		{
			int		cpu = 0;
			rval = 0;
			for_each_online_cpu(cpu) rval++;
			return rval;
		}
	case EL_GET_CPUS_MASK:
		{
			int		cpu = 0;
			rval = 0;
			for_each_online_cpu(cpu) {
				if (cpu > 63)
					return 0;
				rval |= (1LL << cpu);
			}
			return rval;
		}
	case EL_MY_CPU_ID:
		rval = raw_smp_processor_id();
		return rval;
#ifdef CONFIG_SMP
	case EL_SET_IRQ_MASK:
		{
			unsigned long __maybe_unused cpu_mask = (long)a2;
#if defined(CONFIG_E2K) || defined(CONFIG_E90S) || \
		(defined(__i386__) && defined(CONFIG_GENERIC_PENDING_IRQ))
			unsigned long irq_mask = (long)a1;
			cpumask_var_t cpu_mask_bitmap;
			int i;
			if (!alloc_cpumask_var(&cpu_mask_bitmap, GFP_KERNEL))
				return -ENOMEM;
			cpumask_clear(cpu_mask_bitmap);
			for_each_online_cpu(i) {
				if (cpu_mask & (1 << i)) {
					if (cpu_online(i)) {
						cpumask_set_cpu(i, cpu_mask_bitmap);
					} else {
						return -EINVAL;
					}
				}
			}
			for (i = 0; i < NR_IRQS; i++) {
			    if ((irq_mask >= (1<<24)) || (irq_mask & 1 << i))
				if (irq_to_desc(i) && irq_can_set_affinity(i))
					irq_set_affinity(i, cpu_mask_bitmap);
			}
			free_cpumask_var(cpu_mask_bitmap);
#elif defined(CONFIG_E90)
			extern int smp4m_irq_set_mask(int cpu_mask, int on);
			extern int smp4m_irq_get_mask(void);
			unsigned long all_cpu_mask = 0;
			smp4m_irq_set_mask(cpu_mask, 1);
			for_each_online_cpu(cpu) {
				all_cpu_mask |= (1 << cpu);
	       		}
			rval = smp4m_irq_set_mask(all_cpu_mask & ~cpu_mask, 0);
			return smp4m_irq_get_mask();
#endif
		}
		break;
#endif	/* SMP */
#if defined(CONFIG_E90S)
	case SPARC_GET_USEC:
		rval = put_user(get_cycles() * 1000000 / cpu_freq_hz,
					(long long *)a1);
		return rval;
#endif
	case EL_RTS_MODE:
		rval = change_rts_mode_mask((long) a1, -1);
		return rval;
	case EL_SET_RTS_ACTIVE:
		rval = change_rts_mode_mask(-1, (long) a1);
		return rval;
	case EL_GET_RTS_ACTIVE:
		return rts_act_mask;
	case EL_GET_CPU_FREQ:
#ifdef CONFIG_E90S
			return cpu_data(raw_smp_processor_id()).clock_tick;
#elif defined(__e2k__)
			return cpu_data[raw_smp_processor_id()].proc_freq;
#endif
#if 0
	case EL_SET_NET_RT:
		local_irq_disable();
		raw_spin_lock(&current->pi_lock);
		current->rt_flags |= RT_TASK_IS_NET_RT;
		raw_spin_unlock(&current->pi_lock);
		local_irq_enable();
		break;
	case EL_UNSET_NET_RT:
		local_irq_disable();
		raw_spin_lock(&current->pi_lock);
		current->rt_flags &= ~RT_TASK_IS_NET_RT;
		raw_spin_unlock(&current->pi_lock);
		local_irq_enable();
		break;
#endif
        case EL_SET_MLOCK_CONTROL :
                current->extra_flags |= RT_MLOCK_CONTROL;
                break;
        case EL_UNSET_MLOCK_CONTROL :
		current->extra_flags &= ~RT_MLOCK_CONTROL;
                break;
#ifdef SHOW_WOKEN_TIME
	case EL_GET_TIMES:
	{
		size_t sz = ((size_t)a2) / sizeof(long long);
		unsigned long long ip;
		unsigned long long *m = (unsigned long long *)a1;
		if (show_woken_time < 2) {
			if (pr_err_done)
				return -EINVAL;
			pr_err_done = 1;
			return -EINVAL;
		}

		if (sz > EL_GET_TIMES_WAKEUP) {
			rval = put_user(current->wakeup_tm,
				(m + EL_GET_TIMES_WAKEUP));
		}
		if (rval) {
			break;
		}
		if (sz > EL_GET_TIMES_SCHED_ENTER) {
			rval = put_user(current->sched_enter_tm,
				(m + EL_GET_TIMES_SCHED_ENTER));
		}
		if (rval) {
			break;
		}
		if (sz > EL_GET_TIMES_SCHED_LOCK) {
			rval = put_user(current->sched_lock_tm,
				(m + EL_GET_TIMES_SCHED_LOCK));
		}
		if (rval) {
			break;
		}
		if (sz > EL_GET_TIMES_WOKEN) {
			rval = put_user(current->waken_tm,
			(m + EL_GET_TIMES_WOKEN));
		}
		if (rval) {
			break;
		}
		if (sz > EL_GET_TIMES_LAST_PRMT_ENAB) {
			ip = (unsigned long long)current->last_ipi_prmt_enable;
			rval = put_user(ip, (m + EL_GET_TIMES_LAST_PRMT_ENAB));
		}
		if (rval) {
			break;
		}
		if (sz > EL_GET_TIMES_CNTXB) {
			rval = put_user(current->cntx_swb_tm,
				(m + EL_GET_TIMES_CNTXB));
		}
		if (rval) {
			break;
		}
		if (sz > EL_GET_TIMES_CNTXE) {
			rval = put_user(current->cntx_swe_tm,
				(m + EL_GET_TIMES_CNTXE));
		}
		if (rval) {
			break;
		}
		if (sz > EL_GET_TIMES_INTR_SC) {
			rval = put_user(current->intr_sc,
				(m + EL_GET_TIMES_INTR_SC));
		}
		if (rval) {
			break;
		}
		break;
	}
#endif
	case EL_WAKEUP_LAT:
		rval = put_user(current->waken_tm - current->wakeup_tm,
			(long long *)a1);
		break;
	case EL_USER_TICK: {
			int interval_us = (int)(long long)a1;
			do_postpone_tick(interval_us * 1000);
			break;
		}
#ifdef CONFIG_MCST_RT
#ifdef EL_TIMERFD_USING
	case EL_OPEN_TIMERFD :
		rval = el_open_timerfd();
		break;
	case EL_TIMERFD_SETTIME :
		rval = el_timerfd_settime((int) (unsigned long) a1, a2);
		break;
#endif /*EL_TIMERFD_USING */
#endif
#ifdef CONFIG_E90S
	case EL_SYNC_CYCLS: {
		int	i, this_cpu;
		do_sync_cpu_clocks = (unsigned long) a1;
		preempt_disable();
		this_cpu = smp_processor_id();
		for_each_online_cpu(i) {
			if (i != this_cpu)
				smp_synchronize_one_tick(i);
			else
				delta_ticks[i] = 0;
		}
		preempt_enable();
		return copy_to_user((void *)a2, (void *)delta_ticks,
				num_possible_cpus() * sizeof(long));
	}
#endif
	case EL_RT_CPU: {
		int set = (int)(long long)a1;
		struct task_struct *p, *t;
		unsigned long cpu = raw_smp_processor_id();
		cpumask_var_t new_mask;
		int retval;
		int restore_flag = 0;

		if (num_possible_cpus() == 1)
			return 0;
		if (set) {
			if (cpumask_test_cpu(cpu, rt_cpu_mask))
				return 0;
			if (!zalloc_cpumask_var(&new_mask, GFP_NOWAIT)) {
				return -ENOMEM;
			}
			cpumask_set_cpu(cpu, rt_cpu_mask);
#if 0
			pr_warn("RT_CPUset %lu rm=%5lx\n",
				cpu, cpumask_bits(rt_cpu_mask)[0]);
			trace_printk("RCPs rm=%5lx\n",
				cpumask_bits(rt_cpu_mask)[0]);
#endif
			read_lock(&tasklist_lock);
			do_each_thread(t, p) {
#if 0
				pr_warn("RT_CPUseB %lu %20s/%6d m=0x%5lx"
					" tcpu=%d md=%x na=%d\n",
					cpu, p->comm, p->pid,
					cpumask_bits(&p->cpus_allowed)[0],
					task_cpu(p), p->migrate_disable,
					p->nr_cpus_allowed);
#endif
				if (cpumask_weight(&p->cpus_mask) == 1)
					continue;
				get_task_struct(p);
				if (p->__state > TASK_UNINTERRUPTIBLE) {
					put_task_struct(p);
					continue;
				}
				cpumask_copy(new_mask, p->cpus_ptr);
				cpumask_clear_cpu(cpu, new_mask);
				if (cpumask_empty(new_mask)) {
					put_task_struct(p);
					continue;
				}
				restore_flag = p->flags & PF_NO_SETAFFINITY;
				p->flags &= ~PF_NO_SETAFFINITY;
				retval = sched_setaffinity(p->pid, new_mask);
				p->flags |= restore_flag;
				if (retval)
					pr_err("EL_RT_CPU: Could not set affinity "
						"%20s/%6d cpu_mask=0x%5lx ER=%d\n",
						p->comm, p->pid,
						cpumask_bits(new_mask)[0],
						retval);
#if 0
				cpuset_cpus_allowed(p, new_mask);
				pr_warn("RT_CPUset %lu %20s/%6d m=0x%4lx "
					"sm=0x%4lx tcpu=%d md=%x na=%d ret=%d\n",
					cpu, p->comm, p->pid,
					cpumask_bits(&p->cpus_allowed)[0],
					cpumask_bits(new_mask)[0],
					task_cpu(p), p->migrate_disable,
					p->nr_cpus_allowed, retval);
#endif
				put_task_struct(p);
			} while_each_thread(t, p);
			read_unlock(&tasklist_lock);
#if 0
#if defined(CONFIG_E2K) || defined(CONFIG_E90S) || \
		(defined(__i386__) && defined(CONFIG_GENERIC_PENDING_IRQ))
			int i;
			for (i = 0; i < NR_IRQS; i++) {
				struct irq_desc *desc =
					irq_to_desc((long)m->private);
				const struct cpumask *mask =
					desc->irq_data.affinity;
				if (irq_to_desc(i) && irq_can_set_affinity(i))
					irq_set_affinity(i, new_mask);
			}
#endif
#endif
			free_cpumask_var(new_mask);
			/* let rcu works completition in this cpu */
			schedule_timeout_interruptible(3);
#if 0
			cpu_callback(NULL, CPU_DEAD, cpu);
#endif
			tick_cancel_sched_timer(cpu);
		} else {
			if (!cpumask_test_cpu(cpu, rt_cpu_mask))
				return 0;
			cpumask_clear_cpu(cpu, rt_cpu_mask);
			if (!zalloc_cpumask_var(&new_mask, GFP_NOWAIT)) {
				return -ENOMEM;
			}
			read_lock(&tasklist_lock);
			do_each_thread(t, p) {
				if (cpumask_weight(&p->cpus_mask) == 1)
					continue;
				get_task_struct(p);
				if (p->__state > TASK_UNINTERRUPTIBLE) {
					put_task_struct(p);
					continue;
				}
				cpumask_copy(new_mask, p->cpus_ptr);
				cpumask_set_cpu(cpu, new_mask);
				p->flags &= ~PF_NO_SETAFFINITY;
				retval = sched_setaffinity(p->pid, new_mask);
				p->flags |= restore_flag;
				if (retval)
					pr_err("Could not set affinity to cpu "
						"%20s/%6d m=0x%5lx ER=%d\n",
						p->comm, p->pid,
						cpumask_bits(new_mask)[0],
						retval);
#if 0
				pr_warn("RT_CPUunset %lu %20s/%6d m=0x%5lx"
					"curcpu=%d md=%d na=%d ret=%d\n",
					cpu, p->comm, p->pid,
					cpumask_bits(&p->cpus_allowed)[0],
					task_cpu(p), p->migrate_disable,
					p->nr_cpus_allowed, retval);
#endif
				put_task_struct(p);
			} while_each_thread(t, p);
			read_unlock(&tasklist_lock);
			free_cpumask_var(new_mask);
			tick_setup_sched_timer();
#if 0
			cpu_callback(NULL, CPU_UP_PREPARE, cpu);
			cpu_callback(NULL, CPU_ONLINE, cpu);
#endif
		}
		return 0;
	}
#endif
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
		       void __user *, a3, int, a4) {
	long rval;

	switch (req) {
#ifdef CONFIG_MCST_RT
#ifdef EL_TIMERFD_USING
		case EL_TIMERFD_SETTIME:
			rval = compat_el_timerfd_settime((int) (unsigned long) a1, a2);
			break;
#endif /*EL_TIMERFD_USING */
#endif
		/* TODO: all el_posix users must use this interface */
		default:
			rval = do_el_posix(req, a1, a2, a3, a4);
			break;
	}
	return rval;
}
#endif /* CONFIG_COMPAT */

#ifdef CONFIG_MCST_RT
#ifdef EL_TIMERFD_USING

static inline int el_ctx_lock_irq(struct el_timerfd_ctx *ctx)
{
again:
	raw_spin_lock_irq(&ctx->lock);
	if (ctx->locked) {
		raw_spin_unlock_irq(&ctx->lock);
		if (signal_pending(current))
			return -ERESTARTSYS;
		goto again;
	}
	return 0;
}

static inline void el_ctx_unlock_irq(struct el_timerfd_ctx *ctx)
{
	raw_spin_unlock_irq(&ctx->lock);
}

static int el_timerfd_release(struct inode *inode, struct file *file)
{
	struct el_timerfd_ctx *ctx = file->private_data;

	hrtimer_cancel(&ctx->tmr);
	kfree(ctx);
	return 0;
}

static inline int eltfd_populate_user_buf(char __user *buf, size_t count,
				u64 ticks, s64 wu_time, ktime_t cb_timeout,
				s64 intr_timeout, ktime_t expiried)
{
	int res = 0;
	s64 nsec;

	/* Number of missed ticks */
	if (copy_to_user(buf, &ticks, sizeof(s64)))
		return -EFAULT;
	res = sizeof(s64);

	/* Wake up time */
	if (count >=  2 * sizeof(s64)) {
		buf += sizeof(s64);
		if (copy_to_user(buf, &wu_time, sizeof(s64)))
			return -EFAULT;
		res += sizeof(s64);
	}
	
	/* Callback timeout */
	if (count >=  3 * sizeof(s64)) {
		buf += sizeof(s64);
		nsec = ktime_to_ns(cb_timeout);
		if (copy_to_user(buf, &nsec, sizeof(s64)))
			return -EFAULT;
		res += sizeof(s64);
	}

	/* Latency of hrtimer_interrupt start */
	if (count >=  4 * sizeof(s64)) {
		buf += sizeof(s64);
		nsec = intr_timeout;
		if (copy_to_user(buf, &nsec, sizeof(s64)))
			return -EFAULT;
		res += sizeof(s64);
	}

	/* Time of timer expiration */
	if (count >=  5 * sizeof(s64)) {
		buf += sizeof(s64);
		nsec = ktime_to_ns(expiried);
		if (copy_to_user(buf, &nsec, sizeof(s64)))
			return -EFAULT;
		res += sizeof(s64);
	}

	return res;
}

static ssize_t el_timerfd_read(struct file *file, char __user *buf, size_t count,
				loff_t *ppos)
{
	struct el_timerfd_ctx *ctx = file->private_data;
	struct el_wait_queue_head wait = { .task = current,
					   .wuc_time = KTIME_MAX };
	s64 wu_time, intr_timeout;
	u64 ticks;
	ktime_t remaining;
	ktime_t cb_timeout;
	ktime_t expiried;
	int res;

	if (count < sizeof(s64))
		return -EINVAL;

	if (el_ctx_lock_irq(ctx))
		return -ERESTARTSYS;

	ticks = ctx->ticks;

	/* Have we missed at least a tick? */
	if (ctx->handled_ticks != ticks) {
		ctx->handled_ticks = ticks;
		cb_timeout   = ctx->cb_timeout;
		intr_timeout = ctx->tmr.intr_timeout;
		expiried     = ctx->expiried;
		ctx->tmr.intr_timeout = 0;
		el_ctx_unlock_irq(ctx);

		wu_time = 0;
		goto copy_to_user;
	}

	/* We have to wait next tick */
	list_add(&wait.task_list, &ctx->wqh.task_list);
	set_current_state(TASK_INTERRUPTIBLE);

	el_ctx_unlock_irq(ctx);

	while (1) {
		ktime_t now;

		schedule();

		now = ktime_get();

		if (el_ctx_lock_irq(ctx)) {
			res = -ERESTARTSYS;
			goto out;
		}

		/* Got we a new tick? */
		if (ticks != ctx->ticks) {
			ticks     = ctx->ticks;
			remaining = ktime_sub(now, wait.wuc_time);
			wu_time   = ktime_to_ns(remaining);
			cb_timeout   = ctx->cb_timeout;
			intr_timeout = ctx->tmr.intr_timeout;
			expiried     = ctx->expiried;
			ctx->handled_ticks = ticks;
			ctx->tmr.intr_timeout = 0;

			WARN_ON_ONCE(wait.wuc_time == KTIME_MAX);

			res = 0;
			break;
		}
		set_current_state(TASK_INTERRUPTIBLE);
		el_ctx_unlock_irq(ctx);
	}
	list_del(&wait.task_list);
	__set_current_state(TASK_RUNNING);
	el_ctx_unlock_irq(ctx);

	if (wu_time < 0)
		return -EAGAIN; /* It's wrong, because the timer had to be expiried */
	else if (res < 0)
		return res;
copy_to_user:
	res = eltfd_populate_user_buf(buf, count, ticks, wu_time, cb_timeout,
				      intr_timeout, expiried);
out:
	return res;
}

static const struct file_operations el_timerfd_fops = {
	.release        = el_timerfd_release,
	.read           = el_timerfd_read,
};

static int el_open_timerfd(void)
{
	struct el_timerfd_ctx *ctx;
	int ufd;
	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	hrtimer_init(&ctx->tmr, CLOCK_REALTIME, HRTIMER_MODE_ABS_HARD);

	raw_spin_lock_init(&ctx->lock);
	INIT_LIST_HEAD(&ctx->wqh.task_list);

	ctx->locked = 0;
	ctx->ticks  = 0;
	ctx->handled_ticks = 0;

	ufd = anon_inode_getfd("[el_timerfd]", &el_timerfd_fops, ctx, 0);
	if (ufd < 0)
		kfree(ctx);
	
	return ufd;
}

static struct file *el_timerfd_fget(int fd)
{
	struct file *file;

	file = fget(fd);
	if (!file)
		return ERR_PTR(-EBADF);
	if (file->f_op != &el_timerfd_fops) {
		fput(file);
		return ERR_PTR(-EINVAL);
	}
	
	return file;
}

enum hrtimer_restart el_timerfd_tmrproc(struct hrtimer *htmr)
{
	struct el_timerfd_ctx *ctx = container_of(htmr, struct el_timerfd_ctx, tmr);
	struct el_wait_queue_head *wait;
	ktime_t now = ctx->run_time;

	BUG_ON(!irqs_disabled());

	raw_spin_lock(&ctx->lock);

	ctx->ticks++;

	ctx->expiried   = hrtimer_get_expires(htmr);
	ctx->cb_timeout = ktime_sub(now, ctx->expiried);

	list_for_each_entry(wait, &ctx->wqh.task_list, task_list) {
		if (wait->wuc_time == KTIME_MAX) {
			wait->wuc_time = ktime_get();
			wake_up_state(wait->task, TASK_NORMAL);
		}
	}

	raw_spin_unlock(&ctx->lock);

	hrtimer_forward_now(htmr, ctx->tintv);

	return HRTIMER_RESTART;
}


static int do_el_timerfd_settime(int ufd, struct itimerspec64 *ktmr)
{
	struct file *file;
	struct el_timerfd_ctx *ctx;

	if (!itimerspec64_valid(ktmr))
		return -EINVAL;

	file = el_timerfd_fget(ufd);
	if (IS_ERR(file))
		return PTR_ERR(file);
	ctx = file->private_data;

	BUG_ON(irqs_disabled());

	for (;;) {
		raw_spin_lock_irq(&ctx->lock);
		if (ctx->locked) {
			raw_spin_unlock_irq(&ctx->lock);
			continue;
		}

		/* Prevent from parallel settime and read */
		ctx->locked = 1;
		raw_spin_unlock_irq(&ctx->lock);

		if (hrtimer_try_to_cancel(&ctx->tmr) >= 0)
			break;

		raw_spin_lock_irq(&ctx->lock);
		ctx->locked = 0;
		raw_spin_unlock_irq(&ctx->lock);
		cpu_relax();
	}

	raw_spin_lock_irq(&ctx->lock);

	ctx->tmr.function = el_timerfd_tmrproc;

	ctx->tintv = timespec64_to_ktime(ktmr->it_interval);

	hrtimer_set_expires(&ctx->tmr, ctx->tintv);

	/* Return the first timer expiration time */
	ktmr->it_value = ktime_to_timespec64(ctx->tmr.node.expires);

	ctx->tmr.intr_timeout = 0;

	raw_spin_unlock_irq(&ctx->lock);

	if (ctx->tintv != 0)
		hrtimer_start(&ctx->tmr, ctx->tintv, HRTIMER_MODE_REL);
	
	raw_spin_lock_irq(&ctx->lock);
	ctx->locked = 0;
	raw_spin_unlock_irq(&ctx->lock);

	fput(file);

	return 0;
}

static int el_timerfd_settime(int ufd, struct __kernel_itimerspec __user *tmr)
{
	struct itimerspec64 ktmr;
	int ret;

	if (get_itimerspec64(&ktmr, tmr))
		return -EFAULT;
	
	ret = do_el_timerfd_settime(ufd, &ktmr);
	if (ret < 0)
		return ret;
	
	return put_itimerspec64(&ktmr, tmr);
}

#ifdef CONFIG_COMPAT
static int compat_el_timerfd_settime(int ufd, struct old_itimerspec32 __user *tmr)
{
	struct itimerspec64 ktmr;
	int ret;

	if (get_old_itimerspec32(&ktmr, tmr))
		return -EFAULT;
	
	ret =  do_el_timerfd_settime(ufd, &ktmr);
	if (ret < 0)
		return ret;

	return put_old_itimerspec32(&ktmr, tmr);
}
#endif /* CONFIG_COMPAT */

#endif /*EL_TIMERFD_USING */
#endif /* CONFIG_MCST_RT */
#include "sched/sched.h"

#define SPLIT_NS(x) nsec_high((x)), nsec_low((x))

int cpu_queue_collect = 0;

#ifdef CONFIG_PROC_FS
static long long prev_cpuque_time = 0;
static long long intrv_cpuque_time = 0;
static long long cpuque_time;

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

static void
print_task_s(struct seq_file *m, struct task_struct *p, int new_result, long long cur_tm)
{
	unsigned long flags;
	struct rq *rq = &per_cpu(runqueues, task_cpu(p));

	raw_spin_lock_irqsave(&rq->__lock, flags);
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
	raw_spin_unlock_irqrestore(&rq->__lock, flags);

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
#endif

int __init cpu_queue_setup(char *str)
{
	cpu_queue_collect = 1;
	return 1;
}
__setup("cpu_queue_stat", cpu_queue_setup);
