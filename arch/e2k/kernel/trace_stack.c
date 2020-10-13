/*
 * Copyright (C) 2008 Steven Rostedt <srostedt@redhat.com>
 *
 */
#include <linux/stacktrace.h>
#include <linux/kallsyms.h>
#include <linux/seq_file.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/debugfs.h>
#include <linux/ftrace.h>
#include <linux/module.h>
#include <linux/sysctl.h>
#include <linux/init.h>
#include <linux/fs.h>
#include "../../../kernel/trace/trace.h"

#include <asm/e2k_debug.h>
#include <asm/process.h>
#include <asm/setup.h>

#define STACK_TRACE_ENTRIES 500

struct extended_stack_trace {
	unsigned int nr_entries, max_entries;
	unsigned long *entries;
	unsigned long *sizes;
	int skip;	/* input argument: How many entries to skip */
};


static unsigned long stack_dump_trace[STACK_TRACE_ENTRIES+1] = {
	[0 ... (STACK_TRACE_ENTRIES)] = ULONG_MAX
};
static unsigned long stack_dumps_sizes[STACK_TRACE_ENTRIES+1] = {
	[0 ... (STACK_TRACE_ENTRIES)] = ULONG_MAX
};

static struct extended_stack_trace max_stack_trace = {
	.max_entries		= STACK_TRACE_ENTRIES,
	.entries		= stack_dump_trace,
	.sizes			= stack_dumps_sizes
};


static unsigned long p_stack_dump_trace[STACK_TRACE_ENTRIES+1] = {
	[0 ... (STACK_TRACE_ENTRIES)] = ULONG_MAX
};
static unsigned long p_stack_dumps_sizes[STACK_TRACE_ENTRIES+1] = {
	[0 ... (STACK_TRACE_ENTRIES)] = ULONG_MAX
};

static struct extended_stack_trace max_p_stack_trace = {
	.max_entries		= STACK_TRACE_ENTRIES,
	.entries		= p_stack_dump_trace,
	.sizes			= p_stack_dumps_sizes
};


static unsigned long pc_stack_dump_trace[STACK_TRACE_ENTRIES+1] = {
	[0 ... (STACK_TRACE_ENTRIES)] = ULONG_MAX
};

static struct stack_trace max_pc_stack_trace = {
	.max_entries		= STACK_TRACE_ENTRIES,
	.entries		= pc_stack_dump_trace,
};


static unsigned long max_stack_size;
static unsigned long max_p_stack_size;
static unsigned long max_pc_stack_size;
static arch_spinlock_t max_stack_lock =
	(arch_spinlock_t)__ARCH_SPIN_LOCK_UNLOCKED;

static DEFINE_PER_CPU(int, trace_active);
static DEFINE_MUTEX(stack_sysctl_mutex);

int stack_tracer_enabled = 0;
static int last_stack_tracer_enabled;

int stack_tracer_kernel_only = 0;


static int save_stack_address(struct task_struct *task,
		e2k_mem_crs_t *frame, unsigned long frame_address,
		void *data1, void *data2, void *data3)
{
	struct extended_stack_trace *trace = data1;
	u64 *prev = data2;
	u64 *prev_kernel_frame = data3;
	u64 alloc_stack = current_thread_info()->k_stk_sz;
	u64 free_stack, prev_size;
	u64 ip;

	if (trace->skip > 0) {
		trace->skip--;
		return 0;
	}

	ip = AS(frame->cr0_hi).ip << 3;

	/*
	 * Skip user frames
	 */
	if (!AS(frame->cr1_lo).pm) {
		trace->entries[trace->nr_entries] = ip;
		trace->sizes[trace->nr_entries] = 0;
		++(trace->nr_entries);
		return 0;
	}

	if (*prev == ULONG_MAX) {
		/*
		 * The top frame - save the used data stack size
		 * to do the necessary calculation one step later.
		 */
		free_stack = AS(frame->cr1_hi).ussz * 16;
		*prev = alloc_stack - free_stack;
	} else {
		u64 used_stack;

		free_stack = AS(frame->cr1_hi).ussz * 16;
		used_stack = alloc_stack - free_stack;
		if (used_stack > *prev) {
			/*
			 * Looks like the end of the stack
			 * (last frame has leftover information from
			 * the previously used kernel data stack).
			 */
			used_stack = 0;
		}
		prev_size = *prev - used_stack;
		*prev = used_stack;
	}

	if (likely(trace->nr_entries < trace->max_entries)) {
		trace->entries[trace->nr_entries] = ip;
		if (trace->nr_entries > 0)
			trace->sizes[*prev_kernel_frame] = prev_size;
		*prev_kernel_frame = trace->nr_entries;
		++(trace->nr_entries);
	} else {
		return 1;
	}

	return 0;
}

noinline
static void save_extended_stack_trace(struct extended_stack_trace *trace)
{
	u64 prev_kernel_frame = trace->nr_entries;
	u64 prev_used = ULONG_MAX;

	parse_chain_stack(NULL, save_stack_address, trace, &prev_used,
			&prev_kernel_frame);

	trace->sizes[prev_kernel_frame] = prev_used;

	if (trace->nr_entries < trace->max_entries)
		trace->entries[trace->nr_entries++] = ULONG_MAX;
}


static int save_p_stack_address(struct task_struct *task,
		e2k_mem_crs_t *frame, unsigned long frame_address,
		void *data, void *unused1, void *unused2)
{
	struct extended_stack_trace *trace = data;
	u64 size, ip;

	if (trace->skip > 0) {
		trace->skip--;
		return 0;
	}

	ip = AS(frame->cr0_hi).ip << 3;

	size = AS(frame->cr1_lo).wbs * EXT_4_NR_SZ;

	if (likely(trace->nr_entries < trace->max_entries)) {
		trace->entries[trace->nr_entries] = ip;
		trace->sizes[trace->nr_entries] = size;
		++(trace->nr_entries);
	} else {
		return 1;
	}

	return 0;
}

noinline
static void save_extended_p_stack_trace(struct extended_stack_trace *trace)
{
	parse_chain_stack(NULL, save_p_stack_address, trace, NULL, NULL);

	if (trace->nr_entries < trace->max_entries)
		trace->entries[trace->nr_entries++] = ULONG_MAX;
}

static int read_kernel_stacks_size(struct task_struct *task,
		e2k_mem_crs_t *frame, unsigned long frame_address,
		void *data1, void *data2, void *data3)
{
	unsigned long *cs_size = data1;
	unsigned long *ps_size = data2;
	int *skip = data3;

	if (*skip > 0) {
		(*skip)--;
		return 0;
	}

	if (!AS(frame->cr1_lo).pm)
		return 1;

	*cs_size += SZ_OF_CR;
	*ps_size += AS(frame->cr1_lo).wbs * EXT_4_NR_SZ;

	return 0;
}

noinline
static void get_kernel_stacks_size(unsigned long *cs_size,
		unsigned long *ps_size)
{
	int skip = 3;

	*cs_size = 0;
	*ps_size = 0;

	parse_chain_stack(NULL, read_kernel_stacks_size,
			  cs_size, ps_size, &skip);

}

static inline void check_stack(void)
{
	unsigned long this_size, flags, ps_size, cs_size;
	e2k_psp_lo_t psp_lo;
	e2k_psp_hi_t psp_hi;
	e2k_pshtp_t pshtp;
	e2k_pcsp_lo_t pcsp_lo;
	e2k_pcsp_hi_t pcsp_hi;
	e2k_pcshtp_t pcshtp;
	e2k_cr1_lo_t cr1_lo;

	this_size = E2K_GET_DSREG_NV(sbr) - (unsigned long) &this_size;

	if (stack_tracer_kernel_only &&
			(current->mm || (current->flags & PF_EXITING))) {
		get_kernel_stacks_size(&cs_size, &ps_size);
	} else {
		raw_all_irq_save(flags);
		AW(cr1_lo) = E2K_GET_DSREG_NV(cr1.lo);
		psp_lo = READ_PSP_LO_REG();
		psp_hi = READ_PSP_HI_REG();
		pcsp_lo = READ_PCSP_LO_REG();
		pcsp_hi = READ_PCSP_HI_REG();
		pshtp = READ_PSHTP_REG();
		pcshtp = READ_PCSHTP_REG();
		raw_all_irq_restore(flags);

		ps_size = AS(psp_hi).ind + GET_PSHTP_INDEX(pshtp) -
			  AS(cr1_lo).wbs * EXT_4_NR_SZ;
		if (AS(psp_lo).base < TASK_SIZE)
			ps_size += AS(psp_lo).base -
				   (u64) GET_PS_BASE(current_thread_info());

		cs_size = AS(pcsp_hi).ind + PCSHTP_SIGN_EXTEND(pcshtp) -
			  SZ_OF_CR;
		if (AS(pcsp_lo).base < TASK_SIZE)
			cs_size += AS(pcsp_lo).base -
				   (u64) GET_PCS_BASE(current_thread_info());
	}

	if (this_size <= max_stack_size && ps_size <= max_p_stack_size
			&& cs_size <= max_pc_stack_size)
		return;

	local_irq_save(flags);
	arch_spin_lock(&max_stack_lock);

	/* a race could have already updated it */
	if (this_size > max_stack_size) {
		max_stack_size = this_size;

		max_stack_trace.nr_entries	= 0;
		max_stack_trace.skip		= 3;

		save_extended_stack_trace(&max_stack_trace);
	}

	if (ps_size > max_p_stack_size) {
		max_p_stack_size = ps_size;

		max_p_stack_trace.nr_entries	= 0;
		max_p_stack_trace.skip		= 3;

		save_extended_p_stack_trace(&max_p_stack_trace);
	}

	if (cs_size > max_pc_stack_size) {
		max_pc_stack_size = cs_size;

		max_pc_stack_trace.nr_entries	= 0;
		max_pc_stack_trace.skip		= 3;

		save_stack_trace(&max_pc_stack_trace);
	}

	arch_spin_unlock(&max_stack_lock);
	local_irq_restore(flags);
}

static void
stack_trace_call(unsigned long ip, unsigned long parent_ip,
		 struct ftrace_ops *op, struct pt_regs *pt_regs)
{
	int cpu;

	if (unlikely(raw_nmi_irqs_disabled()))
		return;

	preempt_disable_notrace();

	cpu = raw_smp_processor_id();
	/* no atomic needed, we only modify this variable by this cpu */
	if (per_cpu(trace_active, cpu)++ != 0)
		goto out;

	check_stack();

 out:
	per_cpu(trace_active, cpu)--;
	/* prevent recursion in schedule */
	preempt_enable_notrace();
}

static struct ftrace_ops trace_ops __read_mostly = {
	.func = stack_trace_call,
	.flags = FTRACE_OPS_FL_RECURSION_SAFE,
};

static ssize_t
stack_max_size_read(struct file *filp, char __user *ubuf,
		    size_t count, loff_t *ppos)
{
	unsigned long *ptr = filp->private_data;
	char buf[64];
	int r;

	r = snprintf(buf, sizeof(buf), "%ld\n", *ptr);
	if (r > sizeof(buf))
		r = sizeof(buf);
	return simple_read_from_buffer(ubuf, count, ppos, buf, r);
}

static ssize_t
stack_max_size_write(struct file *filp, const char __user *ubuf,
		     size_t count, loff_t *ppos)
{
	long *ptr = filp->private_data;
	unsigned long val, flags;
	int ret;
	int cpu;

	ret = kstrtoul_from_user(ubuf, count, 10, &val);
	if (ret)
		return ret;

	local_irq_save(flags);

	/*
	 * In case we trace inside arch_spin_lock() or after (NMI),
	 * we will cause circular lock, so we also need to increase
	 * the percpu trace_active here.
	 */
	cpu = smp_processor_id();
	per_cpu(trace_active, cpu)++;

	arch_spin_lock(&max_stack_lock);
	*ptr = val;
	arch_spin_unlock(&max_stack_lock);

	per_cpu(trace_active, cpu)--;
	local_irq_restore(flags);

	return count;
}

static const struct file_operations stack_max_size_fops = {
	.open		= tracing_open_generic,
	.read		= stack_max_size_read,
	.write		= stack_max_size_write,
	.llseek		= default_llseek,
};

static void *
__next(struct seq_file *m, loff_t *pos)
{
	long n = *pos - 1;

	if (n >= max_stack_trace.nr_entries || stack_dump_trace[n] == ULONG_MAX)
		return NULL;

	m->private = (void *)n;
	return &m->private;
}

static void *
t_next(struct seq_file *m, void *v, loff_t *pos)
{
	(*pos)++;
	return __next(m, pos);
}

static void *t_start(struct seq_file *m, loff_t *pos)
{
	int cpu;

	local_irq_disable();

	cpu = smp_processor_id();
	per_cpu(trace_active, cpu)++;

	arch_spin_lock(&max_stack_lock);

	if (*pos == 0)
		return SEQ_START_TOKEN;

	return __next(m, pos);
}

static void t_stop(struct seq_file *m, void *p)
{
	int cpu;

	arch_spin_unlock(&max_stack_lock);

	cpu = smp_processor_id();
	per_cpu(trace_active, cpu)--;

	local_irq_enable();
}

static void print_disabled(struct seq_file *m)
{
	seq_puts(m, "#\n"
		 "#  Stack tracer disabled\n"
		 "#\n"
		 "# To enable the stack tracer, either add 'stacktrace' to the\n"
		 "# kernel command line\n"
		 "# or 'echo 1 > /proc/sys/kernel/stack_tracer_enabled'\n"
		 "#\n");
}

static int t_show(struct seq_file *m, void *v)
{
	long i;
	u64 total;

	if (v != SEQ_START_TOKEN)
		return 0;

	if (!stack_tracer_enabled && !max_stack_size && !max_p_stack_size
			&& !max_pc_stack_size) {
		print_disabled(m);

		return 0;
	}

	seq_printf(m, "%d entries in data stack\n"
		   "        Depth    Size   Location\n"
		   "        -----    ----   --------\n",
		   max_stack_trace.nr_entries - 1);

	total = max_stack_size;
	for (i = 0; i < max_stack_trace.nr_entries &&
			max_stack_trace.entries[i] != ULONG_MAX; i++) {
		seq_printf(m, "%3ld) %8d   %5d   %pF\n", i, total,
				max_stack_trace.sizes[i],
				max_stack_trace.entries[i]);
		total -= max_stack_trace.sizes[i];
	}

	seq_printf(m, "\n%d entries in procedure stack\n"
		   "        Depth    Size   Location\n"
		   "        -----    ----   --------\n",
		   max_p_stack_trace.nr_entries - 1);

	total = max_p_stack_size;
	for (i = 0; i < max_p_stack_trace.nr_entries &&
			max_p_stack_trace.entries[i] != ULONG_MAX; i++) {
		seq_printf(m, "%3ld) %8d   %5d   %pF\n", i, total,
				max_p_stack_trace.sizes[i],
				max_p_stack_trace.entries[i]);
		total -= max_p_stack_trace.sizes[i];
	}

	seq_printf(m, "\n%d entries in chain stack\n"
		   "        Location\n"
		   "        --------\n",
		   max_pc_stack_trace.nr_entries - 1);

	for (i = 0; i < max_pc_stack_trace.nr_entries &&
			max_pc_stack_trace.entries[i] != ULONG_MAX; i++)
		seq_printf(m, "%3ld)    %pF\n", i,
				max_pc_stack_trace.entries[i]);

	return 0;
}

static const struct seq_operations stack_trace_seq_ops = {
	.start		= t_start,
	.next		= t_next,
	.stop		= t_stop,
	.show		= t_show,
};

static int stack_trace_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &stack_trace_seq_ops);
}

static const struct file_operations stack_trace_fops = {
	.open		= stack_trace_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static int
stack_trace_filter_open(struct inode *inode, struct file *file)
{
	return ftrace_regex_open(&trace_ops, FTRACE_ITER_FILTER,
				 inode, file);
}

static const struct file_operations stack_trace_filter_fops = {
	.open = stack_trace_filter_open,
	.read = seq_read,
	.write = ftrace_filter_write,
	.llseek = ftrace_filter_lseek,
	.release = ftrace_regex_release,
};

int
stack_trace_sysctl(struct ctl_table *table, int write,
		   void __user *buffer, size_t *lenp,
		   loff_t *ppos)
{
	int ret;

	mutex_lock(&stack_sysctl_mutex);

	ret = proc_dointvec(table, write, buffer, lenp, ppos);

	if (ret || !write ||
	    (last_stack_tracer_enabled == !!stack_tracer_enabled))
		goto out;

	last_stack_tracer_enabled = !!stack_tracer_enabled;

	if (stack_tracer_enabled)
		register_ftrace_function(&trace_ops);
	else
		unregister_ftrace_function(&trace_ops);

 out:
	mutex_unlock(&stack_sysctl_mutex);
	return ret;
}

static char stack_trace_filter_buf[COMMAND_LINE_SIZE+1] __initdata;

static __init int enable_stacktrace(char *str)
{
	if (strncmp(str, "_filter=", 8) == 0)
		strncpy(stack_trace_filter_buf, str+8, COMMAND_LINE_SIZE);

	stack_tracer_enabled = 1;
	last_stack_tracer_enabled = 1;

	stack_tracer_kernel_only = (strstr(str, "kernel") != NULL);

	return 1;
}
__setup("stacktrace", enable_stacktrace);

static __init int stack_trace_init(void)
{
	struct dentry *d_tracer;

	d_tracer = tracing_init_dentry();
	if (!d_tracer)
		return 0;

	trace_create_file("stack_max_size", 0644, d_tracer,
			&max_stack_size, &stack_max_size_fops);

	trace_create_file("stack_max_size_p", 0644, d_tracer,
			&max_p_stack_size, &stack_max_size_fops);

	trace_create_file("stack_max_size_pc", 0644, d_tracer,
			&max_pc_stack_size, &stack_max_size_fops);

	trace_create_file("stack_trace", 0444, d_tracer,
			NULL, &stack_trace_fops);

	trace_create_file("stack_trace_filter", 0444, d_tracer,
			NULL, &stack_trace_filter_fops);

	if (stack_trace_filter_buf[0])
		ftrace_set_early_filter(&trace_ops, stack_trace_filter_buf, 1);

	if (stack_tracer_enabled)
		register_ftrace_function(&trace_ops);

	return 0;
}

device_initcall(stack_trace_init);
