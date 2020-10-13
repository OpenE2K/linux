
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/irqnr.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/timex.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <asm/uaccess.h>

int do_watch_preempt_disable = 0;
EXPORT_SYMBOL(do_watch_preempt_disable);

DEFINE_PER_CPU(u64, max_prmtdsbled);
DEFINE_PER_CPU(u64, tm_prmtdsbled);
DEFINE_PER_CPU(u32, nowatch_set);

static u32 nowatch_mask = NOPWATCH_DEAD | NOPWATCH_LOCTIM | NEVER_PWATCH;
static u64 max_tm;
static int num_dumps;
#ifdef CONFIG_LATENCY_TRACE
static int do_stop_tracing;
static u64 tm_stop_tracing;
#endif

#define peempt_value() (preempt_count() & ~PREEMPT_ACTIVE)


#ifdef CONFIG_E90
extern u64 get_usec_from_start(void);
#endif


void save_tm_prmtdsbl(int val)
{
	if (val == peempt_value()) {
#ifdef CONFIG_E90
		 __get_cpu_var(tm_prmtdsbled) = get_usec_from_start() << 1;
#else
		__get_cpu_var(tm_prmtdsbled) = get_cycles();
#endif
	}
}
EXPORT_SYMBOL(save_tm_prmtdsbl);

void chck_tm_prmtdsbl(int val)
{
	u64 stm = __get_cpu_var(tm_prmtdsbled);
#ifdef CONFIG_MCST
	if (peempt_value() == val) {
		current->my_last_ipi_prmt_enable =
			(unsigned long)__builtin_return_address(0);
	}
#endif
	if (stm == 0) {
		return;
	}
	if (peempt_value() == val) {
		if (__get_cpu_var(nowatch_set) & nowatch_mask) {
			/* Not intersting case for us */
			__get_cpu_var(nowatch_set) = 0;
			__get_cpu_var(tm_prmtdsbled) = 0;
			return;
		}
#ifdef CONFIG_E90
		u64 delta = (get_usec_from_start() << 1) - stm;
		if (delta > 2000000) {
			/* we can get wrong value . skip */
			__get_cpu_var(tm_prmtdsbled) = 0;
			return;
		}
#else
		u64 delta = get_cycles() - stm;
#endif
		__get_cpu_var(tm_prmtdsbled) = 0;
		if (delta > __get_cpu_var(max_prmtdsbled)) {
			__get_cpu_var(max_prmtdsbled) = delta;
		}
#ifdef CONFIG_LATENCY_TRACE
		if (tm_stop_tracing && delta > tm_stop_tracing) {
			end_tracing();
			tm_stop_tracing = 0;
			pr_info("Tracing stopped. delta = 0x%lld\n", delta);
		}
#endif
#ifdef CONFIG_FTRACE
		if (delta > 40000)
			trace_printk("PREEMPT delta=%lld\n", delta);
#endif
		if (max_tm && delta > max_tm && num_dumps > 0) {
			num_dumps--;
			if (num_dumps <= 0) {
				max_tm = 0;
			}
			WARN(1, "Preempt disable time too long on CPU%d: %llu\n",
				smp_processor_id(), delta);
		}
	}
}
EXPORT_SYMBOL(chck_tm_prmtdsbl);

/*	show max prrempt disable time for each CPU         */

static void *wp_seq_start(struct seq_file *f, loff_t *pos)
{
	return (*pos <= num_possible_cpus()) ? pos : NULL;
}

static void *wp_seq_next(struct seq_file *f, void *v, loff_t *pos)
{
	(*pos)++;
	if (*pos >= NR_CPUS)
		return NULL;
	return pos;
}

static void wp_seq_stop(struct seq_file *f, void *v)
{
	/* Nothing to do */
}

static ssize_t wp_write(struct file *file, const char __user *buf,
				size_t count, loff_t *ppos)
{
	char c;
	int cpu;
	char mb[32];
	char *me;
	unsigned long l;
	if (count == 0) {
		return 0;
	}
	if (get_user(c, buf)) {
		return -EFAULT;
	}
	if (c == '0') {
		do_watch_preempt_disable = 0;
		return count;
	}
	if (c == '1') {
		if (do_watch_preempt_disable) {
			do_watch_preempt_disable = 0;
			udelay(100);
		}
		for_each_possible_cpu(cpu) {
			per_cpu(max_prmtdsbled, cpu) = 0;
			per_cpu(tm_prmtdsbled, cpu) = 0;
		}
		do_watch_preempt_disable = 1;
		return count;
	}
	if (c == 't') {
		l = (count > 32) ? 32 : (count - 1);
		if (copy_from_user(mb, buf + 1, l)) {
			return -EFAULT;
		}
		max_tm = usecs_2cycles(simple_strtoul(mb, &me, 10));
		if (*me == 'n') {
			num_dumps = simple_strtoul(me + 1, NULL, 10);
		}
		if (num_dumps == 0) {
			num_dumps = 1;
		}
		return count;
	}
	if (c == 'n') {
		l = (count > 32) ? 32 : (count - 1);
		if (copy_from_user(mb, buf + 1, l)) {
			return -EFAULT;
		}
		num_dumps = simple_strtoul(mb, NULL, 10);
		return count;
	}
	if (c == 'N') {
		l = (count > 32) ? 32 : (count - 1);
		if (copy_from_user(mb, buf + 1, l)) {
			return -EFAULT;
		}
		if (!strncmp(mb, "loctim", 6)) {
			nowatch_mask |= NOPWATCH_LOCTIM;
		} else if (!strncmp(mb, "tsbgrow", 7)) {
			nowatch_mask |= NOPWATCH_TSBGROW;
		} else if (!strncmp(mb, "sched", 5)) {
			nowatch_mask |= NOPWATCH_SCHED;
		} else if (!strncmp(mb, "exitmm", 6)) {
			nowatch_mask |= NOPWATCH_EXITMM;
		} else {
			return -EFAULT;
		}
		return count;
	}
	if (c == 'Y') {
		l = (count > 32) ? 32 : (count - 1);
		if (copy_from_user(mb, buf + 1, l)) {
			return -EFAULT;
		}
		if (!strncmp(mb, "loctim", 6)) {
			nowatch_mask &= ~NOPWATCH_LOCTIM;
		} else if (!strncmp(mb, "tsbgrow", 7)) {
			nowatch_mask &= ~NOPWATCH_TSBGROW;
		} else if (!strncmp(mb, "sched", 5)) {
			nowatch_mask &= ~NOPWATCH_SCHED;
		} else if (!strncmp(mb, "exitmm", 6)) {
			nowatch_mask &= ~NOPWATCH_EXITMM;
		} else {
			return -EFAULT;
		}
		return count;
	}

#ifdef CONFIG_LATENCY_TRACE
	if (c == 'T') {
		l = (count > 32) ? 32 : (count - 1);
		if (copy_from_user(mb, buf + 1, l)) {
			return -EFAULT;
		}
		if (tm_stop_tracing) {
			end_tracing();
		}
		tm_stop_tracing = usecs_2cycles(simple_strtoul(mb, NULL, 10));
		begin_tracing();
		return count;
	}

#endif
#if defined(CONFIG_E90S) || defined(__e2k__)
extern void print_IO_LOCAL_APICS(void);
       if (c == 'A') {
               print_IO_LOCAL_APICS();
               return count;
       }
#endif


	return -EINVAL;
}


int show_wp(struct seq_file *p, void *v)
{
	int i = *(loff_t *) v;

	if (!cpu_online(i)) {
		return 0;
	}
	seq_printf(p, "CPU%d\t%llu usecs\n", i,
		 cycles_2usec(per_cpu(max_prmtdsbled, i)));
	return 0;
}

static const struct seq_operations wp_seq_ops = {
	.start = wp_seq_start,
	.next  = wp_seq_next,
	.stop  = wp_seq_stop,
	.show  = show_wp,
};

static int wp_open(struct inode *inode, struct file *filp)
{
	return seq_open(filp, &wp_seq_ops);
}

static const struct file_operations proc_wp_operations = {
	.open           = wp_open,
	.read           = seq_read,
	.write		= wp_write,
	.llseek         = seq_lseek,
	.release        = seq_release,
};

static int __init proc_wp_init(void)
{
	proc_create("watch-preempt", 0, NULL, &proc_wp_operations);
	return 0;
}
module_init(proc_wp_init);
