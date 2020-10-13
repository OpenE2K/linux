#ifdef CONFIG_MCST_RT
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/seqlock.h>
#include <linux/timex.h>
#include <asm/timer.h>
#include <asm/uaccess.h>


#define GHZ 1000000000

#ifndef DINTR_TIMER_UNITS
#define DINTR_TIMER_UNITS	"unknown"
#endif

/* Time of disabled interrupts */
DEFINE_PER_CPU(unsigned long, dintr_time_max);
DEFINE_PER_CPU(unsigned long, dintr_time_min);

/* The different cpu_times for printing */
cpu_times_t cpu_times[NR_CPUS] = {
	[0 ... NR_CPUS-1] = {
	.curr_time_switch_to = 0,
	.min_time_switch_to = LLONG_MAX,
	.max_time_switch_to = 0
	}
};

static DEFINE_MUTEX(dintr_mutex);
int dintr_timer_state = DINTR_TIMER_WASNT_USE;

static int cpu_times_show(struct seq_file *m, void *v)
{
	int my_cpu, cpu;
	my_cpu = raw_smp_processor_id();

	/* Print the time of disabled interrupt state */
	seq_printf(m, "\t The duration of disabled interrupt state (in "
			DINTR_TIMER_UNITS ")\n");

	for_each_online_cpu(cpu) {
		unsigned long min = per_cpu(dintr_time_min, cpu);
		unsigned long max = per_cpu(dintr_time_max, cpu);

		if (min > max)
			seq_printf(m, "cpu=%d: no data\t%c\n", cpu,
					cpu == my_cpu ? '*' : '\0');
		else
			seq_printf(m, "cpu=%d: min=%lu, max=%lu\t%c\n", cpu,
					per_cpu(dintr_time_min, cpu),
					per_cpu(dintr_time_max, cpu),
					cpu == my_cpu ? '*' : '\0');
	}

	/* print times of switch_to */
	seq_printf(m, "\t The cpu times of switch_to (in nsec)\t\n");
	for_each_online_cpu(cpu) {
		u64 min_part = cpu_times[cpu].min_time_switch_to*GHZ;
		u64 max_part = cpu_times[cpu].max_time_switch_to*GHZ;

		do_div(min_part, cpu_freq_hz);
		do_div(max_part, cpu_freq_hz);
		seq_printf(m, "cpu=%d: min=%lu, max=%lu\n", cpu,
				min_part, max_part);
	}

	return 0;
}

static ssize_t cpu_times_write(struct file *f, const char __user *b,
			       size_t c, loff_t *o)
{
	char s;
	int cpu;

	if (get_user(s, b) == 0) {
		switch (s) {
		case '1':
			mutex_lock(&dintr_mutex);
			if (dintr_timer_state != DINTR_TIMER_RUNNING
				&& mcst_rt_timer_start() == 0)
				dintr_timer_state = DINTR_TIMER_RUNNING;
			mutex_unlock(&dintr_mutex);
			break;
		case '0':
			mutex_lock(&dintr_mutex);
			if (dintr_timer_state == DINTR_TIMER_RUNNING
				&& mcst_rt_timer_stop() == 0)
				dintr_timer_state = DINTR_TIMER_STOPPED;
			mutex_unlock(&dintr_mutex);
			break;
		default:
			for_each_online_cpu(cpu) {
				per_cpu(dintr_time_min, cpu) = ULONG_MAX;
				per_cpu(dintr_time_max, cpu) = 0;
				cpu_times[cpu].min_time_switch_to = LLONG_MAX;
				cpu_times[cpu].max_time_switch_to = 0;
			}
		}
	}
	return c;
}

static int cpu_times_open(struct inode *inode, struct file *file)
{
	return single_open(file, cpu_times_show, NULL);
}

static const struct file_operations cpu_times_fops = {
	.open		= cpu_times_open,
	.read		= seq_read,
	.write		= cpu_times_write,
	.llseek		= seq_lseek,
	.release	= single_release,
};

#ifdef CONFIG_TREE_RCU
static int rcu_stat_show(struct seq_file *m, void *v)
{
	unsigned int i, cpu;

	seq_printf(m, "RCU call statistics\n");

	for (i = 0; i < RCU_MAX_ACCOUNTED_FUNCS; i++) {
		void *func = rcu_statistics[i].func;
		unsigned int total = 0;

		if (func == 0)
			break;
		seq_printf(m, "\n%ps:\n", func);
		for_each_online_cpu(cpu) {
			seq_printf(m, "%lu(%u)\t", rcu_statistics[i].count[cpu],
						   cpu);
			total += rcu_statistics[i].count[cpu];
		}
		seq_printf(m, "\ntotal(%ps)=%u\n", func, total);
	}

	return 0;
}

static int rcu_stat_open(struct inode *inode, struct file *file)
{
	return single_open(file, rcu_stat_show, NULL);
}

static ssize_t rcu_stat_write(struct file *f, const char __user *b,
			      size_t c, loff_t *o)
{
	int i, cpu;

	for (i = 0; i < RCU_MAX_ACCOUNTED_FUNCS; i++) {
		for_each_online_cpu(cpu) {
			/* No syncronization, so may fail */
			rcu_statistics[i].count[cpu] = 0;
		}
	}
	return c;
}

static const struct file_operations rcu_stat_fops = {
	.open		= rcu_stat_open,
	.read		= seq_read,
	.write		= rcu_stat_write,
	.llseek		= seq_lseek,
	.release	= single_release,
};
#endif

static int __init proc_cpu_times_init(void)
{
	proc_create("cpu_times", 0, NULL, &cpu_times_fops);
#ifdef CONFIG_TREE_RCU
	proc_create("rcu_stat", 0, NULL, &rcu_stat_fops);
#endif
	return 0;
}
module_init(proc_cpu_times_init);
#endif
