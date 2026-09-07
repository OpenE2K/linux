/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/proc_fs.h>
#include <linux/sched/clock.h>

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
