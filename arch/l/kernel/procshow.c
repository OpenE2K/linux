/*
 * arch/l/kernel/procshow.c
 *
 * This file contains implementation of functions to show different data
 * through proc fs.
 *
 * Copyright (C) 2010-2014 Pavel V. Panteleev (panteleev_p@mcst.ru)
 */

#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/module.h>

#include <asm/bootinfo.h>

#ifdef CONFIG_BOOT_TRACE
#include <asm/boot_profiling.h>
#endif	/* CONFIG_BOOT_TRACE */

#ifdef CONFIG_E2K
#include <asm/sic_regs.h>
#include <asm/sic_regs_access.h>
#endif	/* CONFIG_E2K */

#if defined(CONFIG_E2K) || defined(CONFIG_E90S)
#include <asm/iolinkmask.h>
#endif

#define	BOOTDATA_FILENAME	"bootdata"
static struct proc_dir_entry *bootdata_entry;

#define LOADTIME_FILENAME	"loadtime"
static struct proc_dir_entry *loadtime_entry;


#ifdef CONFIG_BOOT_TRACE

#define LOADTIMEKERN_FILENAME	"loadtime_kernel"
static struct proc_dir_entry *loadtime_kernel_entry;

typedef struct loadtime_tpnt {
	char *name;
	char *keyword;
} loadtime_tpnt_t;

#define LOADTIME_TPNT_NUM	4

static loadtime_tpnt_t 	loadtime_tpnt_arr[LOADTIME_TPNT_NUM] = {
	{"KernelBoottimeInit",	"boot-time"   },
	{"KernelMemInit",	"mm_init"     },
	{"KernelPagingInit",	"paging_init" },
	{"KernelInitcalls",	"do_initcalls"},
};
#endif	/* CONFIG_BOOT_TRACE */

#ifdef CONFIG_E2K
#define LDSP_FILENAME		"dspinfo"
struct proc_dir_entry *ldsp_entry = NULL;
EXPORT_SYMBOL(ldsp_entry);
const struct file_operations *ldsp_proc_fops_pointer = NULL;
EXPORT_SYMBOL(ldsp_proc_fops_pointer);
#endif

#if defined(CONFIG_E2K) || defined(CONFIG_E90S)
#define RDMA_FILENAME		"rdmainfo"
struct proc_dir_entry	*rdma_entry = NULL;
EXPORT_SYMBOL(rdma_entry);
const struct file_operations *rdma_proc_fops_pointer = NULL;
EXPORT_SYMBOL(rdma_proc_fops_pointer);
#endif

static int bootdata_proc_show(struct seq_file *m, void *data)
{
	seq_printf(m,
		"boot_ver='%s'\n"
		"mb_type='%s' (0x%x)\n"
		"chipset_type='%s'\n"
		"cpu_type='%s'\n"
		"cache_lines_damaged=%lu\n",
		bootblock_virt->info.bios.boot_ver,
		GET_MB_TYPE_NAME(bootblock_virt->info.bios.mb_type),
		bootblock_virt->info.bios.mb_type,
		GET_CHIPSET_TYPE_NAME(bootblock_virt->info.bios.chipset_type),
		GET_CPU_TYPE_NAME(bootblock_virt->info.bios.cpu_type),
		(unsigned long)bootblock_virt->info.bios.cache_lines_damaged);

	return 0;
}

#ifdef CONFIG_BOOT_TRACE
#ifdef CONFIG_E2K
static u64 boot_loadtime_show(struct seq_file *m)
{
	boot_times_t t = bootblock_virt->boot_times;
	u64 arch     = t.arch * MSEC_PER_SEC / cpu_freq_hz;
	u64 unpack   = (t.unpack - t.arch) * MSEC_PER_SEC / cpu_freq_hz;
	u64 pci      = (t.pci - t.unpack) * MSEC_PER_SEC / cpu_freq_hz;
	u64 drivers1 = (t.drivers1 - t.pci) * MSEC_PER_SEC / cpu_freq_hz;
	u64 drivers2 = (t.drivers2 - t.drivers1) * MSEC_PER_SEC / cpu_freq_hz;
	u64 menu     = (t.menu - t.drivers2) * MSEC_PER_SEC / cpu_freq_hz;
	u64 sm       = (t.sm - t.menu) * MSEC_PER_SEC / cpu_freq_hz;
	u64 kernel   = (t.kernel - t.sm) * MSEC_PER_SEC / cpu_freq_hz;
	u64 total = 0;

	if (arch + unpack + pci + drivers1 + drivers2 + menu + sm + kernel) {
		seq_printf(m,
			"BootArch: %llu ms\nBootUnpack: %llu ms\n"
			"BootPci: %llu ms\nBootDrivers1: %llu ms\n"
			"BootDrivers2: %llu ms\nBootMenu: %llu ms\n"
			"BootSm: %llu ms\nBootKernel: %llu ms\n",
			arch, unpack, pci, drivers1, drivers2, menu, sm,
			kernel);
		total = boot_cycles_to_ms(t.kernel);
	} else {
		seq_printf(m, "Boot: %llu ms\n",
			boot_cycles_to_ms(boot_trace_events[0].cycles));
		total = boot_cycles_to_ms(boot_trace_events[0].cycles);
	}

	return total;
}
#else	/* !CONFIG_E2K */
static u64 boot_loadtime_show(struct seq_file *m)
{
	seq_printf(m, "Boot: %llu ms\n",
		boot_cycles_to_ms(boot_trace_events[0].cycles));
	return boot_cycles_to_ms(boot_trace_events[0].cycles);
}
#endif	/*  CONFIG_E2K */

static u64 kernel_loadtime_show(struct seq_file *m)
{
	int i;
	u64 kernel_common_time = 0;
	u64 kernel_traced_time = 0;
	u64 events_count = atomic_read(&boot_trace_top_event) + 1;

	for (i = 0; i < events_count - 1; i++) {
		struct boot_tracepoint *curr = &boot_trace_events[i];
		int j;

		for (j = 0; j < LOADTIME_TPNT_NUM; j++) {
			loadtime_tpnt_t elem = loadtime_tpnt_arr[j];
			u64 time = 0;
			u64 k;

			if (!strstr(curr->name, elem.keyword))
				continue;

			for (k = i + 1; k < events_count; k++) {
				struct boot_tracepoint *next =
						&boot_trace_events[k];
				u64 delta;

				if (!strstr(next->name, elem.keyword))
					continue;

				delta = next->cycles - curr->cycles;
				time = boot_cycles_to_ms(delta);

				break;
			}

			kernel_traced_time += time;

			if (time)
				seq_printf(m, "%s: %llu ms\n",
						elem.name, time);
		}
	}

	if (atomic_read(&boot_trace_top_event) != -1) {
		int top_event = atomic_read(&boot_trace_top_event);
		u64 start, end;

		start = boot_trace_events[0].cycles;
		end   = boot_trace_events[top_event].cycles;

		kernel_common_time = boot_cycles_to_ms(end - start);
		seq_printf(m, "KernelOther: %llu ms\n",
				kernel_common_time - kernel_traced_time);
	}

	return kernel_common_time;
}
#endif	/* CONFIG_BOOT_TRACE */

static int loadtime_proc_show(struct seq_file *m, void *data)
{
	u64 total_time = 0;

#ifdef CONFIG_BOOT_TRACE
	total_time += boot_loadtime_show(m);
	total_time += kernel_loadtime_show(m);
#endif

	seq_printf(m, "Total: %llu ms\n", total_time);

	return 0;
}

#ifdef CONFIG_BOOT_TRACE
static void show_cpu_indentation(struct seq_file *s, int num)
{
	int i;

	for (i = 0; i < num; i++)
		seq_printf(s, "\t");
}

static int loadtimekern_seq_show(struct seq_file *s, void *v)
{
	long pos = (struct boot_tracepoint *)v - boot_trace_events;
	struct boot_tracepoint *event = &boot_trace_events[pos];
	unsigned int cpu = event->cpu;
	struct boot_tracepoint *next = boot_trace_next_event(cpu, event);
	struct boot_tracepoint *prev = boot_trace_prev_event(cpu, event);
	struct boot_tracepoint *next_next = next ?
			boot_trace_next_event(cpu, next) : NULL;
	struct boot_tracepoint *prev_prev = prev ?
			boot_trace_prev_event(cpu, prev) : NULL;
	u64 delta_next = (next ? next->cycles : event->cycles) - event->cycles;
	u64 delta_prev = event->cycles - (prev ? prev->cycles : 0);
	u64 delta_ms_next = boot_cycles_to_ms(delta_next);
	u64 delta_ms_prev = boot_cycles_to_ms(delta_prev);
	int i, printed;

	if (pos == 0) {
			int top = atomic_read(&boot_trace_top_event);
			u64 delta, sec, msec;

			delta = boot_trace_events[top].cycles
				- boot_trace_events[0].cycles;
			delta = boot_cycles_to_ms(delta);

			msec = do_div(delta, MSEC_PER_SEC);
			sec  = delta;

		seq_printf(s,
			"Boot trace finished, kernel booted in %llu.%.3llu s,\n"
			"%d events were collected.\n"
			"Output format is:\n\tabsolute time; time passed "
			"after the last event; the event name\n",
			sec, msec, top + 1);

		seq_printf(s, "----------------------------------------"
				"-------------------------------\nCPU0");

		printed = 1;
		for (i = 1; i < NR_CPUS; i++) {
			seq_printf(s, "\tCPU%d", i);
			++printed;
			if (printed == num_online_cpus())
				break;
		}

		seq_printf(s, "\n----------------------------------------"
				"-------------------------------\n");
	}

	/* Print only the first two and the last two events
	 * and events with big enough delta. */
	if (!prev || !next || !next_next || !prev_prev ||
		       delta_ms_next >= CONFIG_BOOT_TRACE_THRESHOLD ||
		       delta_ms_prev >= CONFIG_BOOT_TRACE_THRESHOLD) {
		/* Print this event */
		show_cpu_indentation(s, cpu);
		seq_printf(s, "%3llu ms (delta %3llu ms) %s\n",
				boot_cycles_to_ms(event->cycles),
				boot_cycles_to_ms(delta_prev),
				event->name);
	} else {
		/* Skip this event. If this is the first or the last
		 * skipped event in a row then output < ... >. */
		u64 delta_cycles_next_next = next_next->cycles - next->cycles;
		u64 delta_cycles_prev_prev = prev->cycles - prev_prev->cycles;
		u64 delta_ms_next_next = boot_cycles_to_ms(delta_cycles_next_next);
		u64 delta_ms_prev_prev = boot_cycles_to_ms(delta_cycles_prev_prev);

		if ((delta_ms_next_next >= CONFIG_BOOT_TRACE_THRESHOLD
					&& delta_ms_next <
					CONFIG_BOOT_TRACE_THRESHOLD)
				|| (delta_ms_prev_prev >=
					CONFIG_BOOT_TRACE_THRESHOLD
					&& delta_ms_prev <
					CONFIG_BOOT_TRACE_THRESHOLD)) {
			/* Skip this event and inform about it. */
			show_cpu_indentation(s, cpu);
			seq_printf(s, "< ... >\n");
		} else {
			/* Skip this event and do nothing */
		}
	}

	return 0;
}

static void *loadtimekern_seq_start(struct seq_file *s, loff_t *pos)
{
	long count = atomic_read(&boot_trace_top_event);
	if (*pos > count || count == -1)
		return 0;
	return (&boot_trace_events[*pos]);
}

static void *loadtimekern_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	(*pos)++;
	if (*pos > atomic_read(&boot_trace_top_event))
		return 0;
	return (&boot_trace_events[*pos]);
}

static void loadtimekern_seq_stop(struct seq_file *s, void *v)
{
}

static const struct seq_operations loadtimekern_seq_ops = {
	.start = loadtimekern_seq_start,
	.next  = loadtimekern_seq_next,
	.stop  = loadtimekern_seq_stop,
	.show  = loadtimekern_seq_show
};

static int loadtimekern_proc_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &loadtimekern_seq_ops);
}

static const struct file_operations loadtime_kernel_proc_fops = {
	.owner   = THIS_MODULE,
	.open    = loadtimekern_proc_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release
};
#endif	/* CONFIG_BOOT_TRACE */

#if defined(CONFIG_E2K) || defined(CONFIG_E90S)
static int rdma_seq_show(struct seq_file *s, void *v)
{
	int node = *((int *)v);
	int i = 0;

	seq_printf(s, "  node: %d\n", node);
	for (i = 0; i < NODE_NUMIOLINKS; i++) {
		if (node_rdma_possible(node, i)) {
			seq_printf(s, "    link: %d - %s\n",
				   i,
				   node_rdma_online(node, i) ? "on" : "off");
		} else {
			seq_printf(s, "    link: %d - none\n", i);
		}
	}

	return 0;
}

static void *rdma_seq_start(struct seq_file *s, loff_t *pos)
{
	if (!node_online(*pos))
		*pos = next_online_node(*pos);
	if (*pos == MAX_NUMNODES)
		return 0;
	seq_printf(s, "- RDMA device info - number: %d, online: %d.\n",
		   num_possible_rdmas(), num_online_rdmas());
	seq_printf(s, "  Module not loaded.\n");
	seq_printf(s, "  Status for each node:\n");
	return (void *)pos;
}

static void *rdma_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	*pos = next_online_node(*pos);
	if (*pos == MAX_NUMNODES)
		return 0;
	return (void *)pos;
}

static void rdma_seq_stop(struct seq_file *s, void *v)
{
}

static const struct seq_operations rdma_seq_ops = {
	.start = rdma_seq_start,
	.next  = rdma_seq_next,
	.stop  = rdma_seq_stop,
	.show  = rdma_seq_show
};

static int rdma_proc_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &rdma_seq_ops);
}

static const struct file_operations rdma_proc_fops = {
	.owner   = THIS_MODULE,
	.open    = rdma_proc_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release
};
#endif /* CONFIG_E2K || CONFIG_E90S */

#ifdef CONFIG_E2K
static int ldsp_seq_show(struct seq_file *s, void *v)
{
	int node = *((int *)v);
	e2k_pwr_mgr_struct_t pwr;

	seq_printf(s, "    node: %d\n", node);
	pwr.word = sic_read_node_nbsr_reg(node, SIC_pwr_mgr);
	seq_printf(s, "      state: %s\n",
		   (pwr.fields.ic_clk) ? "on" : "off");

	return 0;
}

static void *ldsp_seq_start(struct seq_file *s, loff_t *pos)
{
	int node = 0, dsp_on = 0;
	e2k_pwr_mgr_struct_t pwr;

	if (!node_online(*pos))
		*pos = next_online_node(*pos);

	for_each_online_node(node) {
		pwr.word = sic_read_node_nbsr_reg(node, SIC_pwr_mgr);
		if (pwr.fields.ic_clk)
			dsp_on++;
	}

	seq_printf(s, "- ELDSP device info - number: %d, online: %d.\n",
		   num_online_nodes() * 4,
		   dsp_on * 4);
	seq_printf(s, "  Module not loaded.\n");
	if (*pos == MAX_NUMNODES)
		return 0;
	seq_printf(s, "  Status for each node:\n");
	return (void *)pos;
}

static void *ldsp_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	*pos = next_online_node(*pos);
	if (*pos == MAX_NUMNODES)
		return 0;
	return (void *)pos;
}

static void ldsp_seq_stop(struct seq_file *s, void *v)
{
}

static const struct seq_operations ldsp_seq_ops = {
	.start = ldsp_seq_start,
	.next  = ldsp_seq_next,
	.stop  = ldsp_seq_stop,
	.show  = ldsp_seq_show
};

static int ldsp_proc_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &ldsp_seq_ops);
}

static const struct file_operations ldsp_proc_fops = {
	.owner   = THIS_MODULE,
	.open    = ldsp_proc_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release
};
#endif	/* __e2k__ */

static int loadtime_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, loadtime_proc_show, NULL);
}

static const struct file_operations loadtime_proc_fops = {
	.owner   = THIS_MODULE,
	.open	 = loadtime_proc_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = single_release,
};

static int bootdata_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, bootdata_proc_show, NULL);
}

static const struct file_operations bootdata_proc_fops = {
	.owner   = THIS_MODULE,
	.open	 = bootdata_proc_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = single_release,
};

static int __init init_procshow(void)
{
	const char *signature;

	if (bootblock_virt == NULL) {
		return -EINVAL;
	}
	signature = (char *) bootblock_virt->info.bios.signature;

	if (!strcmp(signature, BIOS_INFO_SIGNATURE)) {
		bootdata_entry = proc_create(BOOTDATA_FILENAME, S_IRUGO,
				NULL, &bootdata_proc_fops);
		if (!bootdata_entry)
			return -ENOMEM;
	}

	loadtime_entry = proc_create(LOADTIME_FILENAME, S_IRUGO,
			NULL, &loadtime_proc_fops);
	if (!loadtime_entry)
		return -ENOMEM;

#ifdef CONFIG_BOOT_TRACE
	loadtime_kernel_entry = proc_create(LOADTIMEKERN_FILENAME, S_IRUGO,
			NULL, &loadtime_kernel_proc_fops);
	if (!loadtime_kernel_entry)
		return -ENOMEM;
#endif	/* CONFIG_BOOT_TRACE */

#ifdef CONFIG_E2K
	if (HAS_MACHINE_E2K_DSP) {
		ldsp_proc_fops_pointer = &ldsp_proc_fops;
		ldsp_entry = proc_create(LDSP_FILENAME, S_IRUGO,
				NULL, ldsp_proc_fops_pointer);
		if (!ldsp_entry) {
			ldsp_proc_fops_pointer = NULL;
			return -ENOMEM;
		}
	}
#endif

#if defined(CONFIG_E2K) || defined(CONFIG_E90S)
	if (num_possible_rdmas()) {
		rdma_proc_fops_pointer = &rdma_proc_fops;
		rdma_entry = proc_create(RDMA_FILENAME, S_IRUGO,
					 NULL, rdma_proc_fops_pointer);
		if (!rdma_entry) {
			rdma_proc_fops_pointer = NULL;
			return -ENOMEM;
		}
	}
#endif

	return 0;
}

static void __exit exit_procshow(void)
{
	const char *signature = (char *) bootblock_virt->info.bios.signature;

	if (!strcmp(signature, BIOS_INFO_SIGNATURE))
		proc_remove(bootdata_entry);

	proc_remove(loadtime_entry);

#ifdef CONFIG_BOOT_TRACE
	proc_remove(loadtime_kernel_entry);
#endif	/* CONFIG_BOOT_TRACE */

#ifdef CONFIG_E2K
	if (HAS_MACHINE_E2K_DSP)
		proc_remove(ldsp_entry);
#endif

#if defined(CONFIG_E2K) || defined(CONFIG_E90S)
	if (num_possible_rdmas())
		proc_remove(rdma_entry);
#endif
}

module_init(init_procshow);
module_exit(exit_procshow);
