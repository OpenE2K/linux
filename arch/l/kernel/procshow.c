/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * This file contains implementation of functions to show different data
 * through proc fs.
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

#ifdef CONFIG_E90S
#include <asm/sic_regs.h>
#endif

#if defined(CONFIG_E2K) || defined(CONFIG_E90S)
#include <asm/iolinkmask.h>
#endif


#define	BOOTDATA_FILENAME	"bootdata"
#define LOADTIME_FILENAME	"loadtime"


#ifdef CONFIG_BOOT_TRACE

#define LOADTIMEKERN_FILENAME	"loadtime_kernel"

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


#if defined(CONFIG_E2K) || defined(CONFIG_E90S)
#define RDMA_FILENAME		"rdmainfo"
struct proc_dir_entry	*rdma_entry = NULL;
EXPORT_SYMBOL(rdma_entry);
const struct proc_ops *rdma_proc_ops_pointer = NULL;
EXPORT_SYMBOL(rdma_proc_ops_pointer);

#define NODES_FILENAME		"nodesinfo"
struct proc_dir_entry *nodes_entry = NULL;
EXPORT_SYMBOL(nodes_entry);
const struct proc_ops *nodes_proc_ops_pointer = NULL;
EXPORT_SYMBOL(nodes_proc_ops_pointer);
#endif


#define BOOTLOG_FILENAME	"bootlog"
#define BOOTLOG_BLOCK_SIZE	1024

#define BOOTLOG_BLOCKS_COUNT	\
	((bootblock_virt->info.bios.bootlog_len / BOOTLOG_BLOCK_SIZE) + \
	 ((bootblock_virt->info.bios.bootlog_len % BOOTLOG_BLOCK_SIZE) ? \
			1 : 0))

static void get_uuid(__u8 *uuid, char *uuidstr)
{
	int i;
	uuidstr[0] = 0;
	for (i = 0; i < 16; i++) {
		if (uuid[i] != 0) {
			snprintf(uuidstr, 64,
				"uuid='%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x'\n",
				uuid[0], uuid[1], uuid[2], uuid[3],
				uuid[4], uuid[5], uuid[6], uuid[7],
				uuid[8], uuid[9], uuid[10], uuid[11],
				uuid[12], uuid[13], uuid[14], uuid[15]);
			break;
		}
	}
}

static void get_macaddr(__u8 *mac_addr, char *macstr)
{
	macstr[0] = 0;
	if (mac_addr[3] != 0 && mac_addr[4] != 0 && mac_addr[5] != 0) {
		snprintf(macstr, 32,
			"mac='%02X:%02X:%02X:%02X:%02X:%02X'\n",
			mac_addr[0], mac_addr[1],
			mac_addr[2], mac_addr[3],
			mac_addr[4], mac_addr[5]);
	}
}

static void get_sernum(__u64 mach_serialn, char *serstr)
{
	serstr[0] = 0;
	if (mach_serialn != 0) {
		snprintf(serstr, 32, "serial='%llu'\n", mach_serialn);
	}
}

static int bootdata_proc_show(struct seq_file *m, void *data)
{
	char serstr[32];
	char macstr[32];
	char uuidstr[64];

	get_sernum(bootblock_virt->info.mach_serialn, serstr);
	get_macaddr(bootblock_virt->info.mac_addr, macstr);
	get_uuid(bootblock_virt->info.bios.uuid, uuidstr);

	seq_printf(m,
		"boot_ver='%s'\n"
		"mb_type='%s' (0x%x)\n"
		"chipset_type='%s'\n"
		"cpu_type='%s'\n"
		"cache_lines_damaged=%lu\n"
		"%s%s%s",
		bootblock_virt->info.bios.boot_ver,
		mcst_mb_name,
		bootblock_virt->info.bios.mb_type,
		GET_CHIPSET_TYPE_NAME(bootblock_virt->info.bios.chipset_type),
		GET_CPU_TYPE_NAME(bootblock_virt->info.bios.cpu_type),
		(unsigned long)bootblock_virt->info.bios.cache_lines_damaged,
		strlen(uuidstr) ? uuidstr : "",
		strlen(macstr) ? macstr : "",
		strlen(serstr) ? serstr : "");

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
	int top = atomic_read(&boot_trace_top_event);
	struct boot_tracepoint *event = &boot_trace_events[pos],
		*prev  = (pos > 0) ? &boot_trace_events[pos - 1] : NULL,
		*prev2 = (pos > 1) ? &boot_trace_events[pos - 2] : NULL,
		*next  = (pos + 1 < top) ? &boot_trace_events[pos + 1] : NULL,
		*next2 = (pos + 2 < top) ? &boot_trace_events[pos + 2] : NULL;
	unsigned int i, cpuid = event->cpuid;

	if (pos == 0) {
		u64 delta, sec, msec;

		delta = boot_trace_events[top].cycles - boot_trace_events[0].cycles;
		delta = boot_cycles_to_ms(delta);

		msec = do_div(delta, MSEC_PER_SEC);
		sec  = delta;

		seq_printf(s,
			"Boot trace finished, kernel booted in %llu.%.3llu s,\n"
			"%d events were collected. Output format is:\n"
			"\tabsolute time; time passed after the last event; the event name\n"
			"-----------------------------------------------------------------------\n"
			"CPU0",
			sec, msec, top + 1);

		for (i = 1; i < num_online_cpus(); i++) {
			seq_printf(s, "\tCPU%d", i);
		}

		seq_printf(s, "\n-----------------------------------------------------------------------\n");
	}

	u64 delta_next = (next) ? (next->cycles - event->cycles) : 0;
	u64 delta_prev = event->cycles - (prev ? prev->cycles : 0);
	u64 delta_ms_next = boot_cycles_to_ms(delta_next);
	u64 delta_ms_prev = boot_cycles_to_ms(delta_prev);

	/* Print only the first two and the last two events
	 * and events with big enough delta. */
	if (pos < 2 || pos >= top -2 ||
		       delta_ms_next >= CONFIG_BOOT_TRACE_THRESHOLD ||
		       delta_ms_prev >= CONFIG_BOOT_TRACE_THRESHOLD) {
		/* Print this event */
		show_cpu_indentation(s, cpuid_to_cpu(cpuid));
		seq_printf(s, "%3llu ms (delta %3llu ms) %s\n",
				boot_cycles_to_ms(event->cycles),
				boot_cycles_to_ms(delta_prev),
				event->name);
	} else {
		/* Skip this event. If this is the first or the last
		 * skipped event in a row then output < ... >. */
		u64 delta_cycles_next_next = next2->cycles - next->cycles;
		u64 delta_cycles_prev_prev = prev->cycles - prev2->cycles;
		u64 delta_ms_next_next = boot_cycles_to_ms(delta_cycles_next_next);
		u64 delta_ms_prev_prev = boot_cycles_to_ms(delta_cycles_prev_prev);

		if ((delta_ms_next_next >= CONFIG_BOOT_TRACE_THRESHOLD
					&& delta_ms_next < CONFIG_BOOT_TRACE_THRESHOLD)
				|| (delta_ms_prev_prev >= CONFIG_BOOT_TRACE_THRESHOLD
					&& delta_ms_prev < CONFIG_BOOT_TRACE_THRESHOLD)) {
			/* Skip this event and inform about it. */
			show_cpu_indentation(s, cpuid_to_cpu(cpuid));
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

static const struct proc_ops loadtime_kernel_proc_ops = {
	.proc_open    = loadtimekern_proc_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = seq_release
};
#endif	/* CONFIG_BOOT_TRACE */

#if defined(CONFIG_E2K) || defined(CONFIG_E90S)
static int rdma_seq_show(struct seq_file *s, void *v)
{
	int node = (int)(*((loff_t *)v));
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

static const struct proc_ops rdma_proc_ops = {
	.proc_open    = rdma_proc_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = seq_release
};

static int nodes_seq_show(struct seq_file *s, void *v)
{
	unsigned int node1;
	unsigned int node2;
	unsigned int node3;

#ifdef CONFIG_E2K
	/* Check vp and vio bits of RT_LCFG SIC register */
	node1 = sic_read_node_nbsr_reg(0, SIC_rt_lcfg1) & 9;
	node2 = sic_read_node_nbsr_reg(0, SIC_rt_lcfg2) & 9;
	node3 = sic_read_node_nbsr_reg(0, SIC_rt_lcfg3) & 9;
#endif

#ifdef CONFIG_E90S
	node1 = sic_read_node_iolink_nbsr_reg(0, 0, NBSR_LINK0_CSR);
	node2 = sic_read_node_iolink_nbsr_reg(0, 0, NBSR_LINK1_CSR);
	node3 = sic_read_node_iolink_nbsr_reg(0, 0, NBSR_LINK2_CSR);
#endif

	seq_printf(s, "node0: on\n");
	seq_printf(s, "node1: %s\n", node1 != 0 ? "on" : "off");
	seq_printf(s, "node2: %s\n", node2 != 0 ? "on" : "off");
	seq_printf(s, "node3: %s\n", node3 != 0 ? "on" : "off");

	return 0;
}

static void *nodes_seq_start(struct seq_file *s, loff_t *pos)
{
	if (*pos != 0)
		return 0;
	return (void *)pos;
}

static void *nodes_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	(*pos) = 1;
	return 0;
}

static void nodes_seq_stop(struct seq_file *s, void *v)
{
}

static const struct seq_operations nodes_seq_ops = {
	.start = nodes_seq_start,
	.next  = nodes_seq_next,
	.stop  = nodes_seq_stop,
	.show  = nodes_seq_show
};

static int nodes_proc_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &nodes_seq_ops);
}

static const struct proc_ops nodes_proc_ops = {
	.proc_open    = nodes_proc_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = seq_release
};

#endif /* CONFIG_E2K || CONFIG_E90S */

static int loadtime_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, loadtime_proc_show, NULL);
}

static const struct proc_ops loadtime_proc_ops = {
	.proc_open    = loadtime_proc_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

static int bootdata_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, bootdata_proc_show, NULL);
}

static const struct proc_ops bootdata_proc_ops = {
	.proc_open    = bootdata_proc_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

static int bootlog_seq_show(struct seq_file *s, void *v)
{
	int block_num = *((loff_t *)v);
	u64 start_addr, end_addr, current_addr, len;

	start_addr = (u64)__va(bootblock_virt->info.bios.bootlog_addr);
	end_addr = start_addr + bootblock_virt->info.bios.bootlog_len;
	current_addr = start_addr + block_num * BOOTLOG_BLOCK_SIZE;

	len = (end_addr - current_addr < BOOTLOG_BLOCK_SIZE) ?
			(end_addr - current_addr) : BOOTLOG_BLOCK_SIZE;

	seq_write(s, (void *)current_addr, len);

	return 0;
}

static void *bootlog_seq_start(struct seq_file *s, loff_t *pos)
{
	if (*pos >= BOOTLOG_BLOCKS_COUNT)
		return 0;
	return (void *)pos;
}

static void *bootlog_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	(*pos)++;
	if (*pos >= BOOTLOG_BLOCKS_COUNT)
		return 0;
	return (void *)pos;
}

static void bootlog_seq_stop(struct seq_file *s, void *v)
{
}

static const struct seq_operations bootlog_seq_ops = {
	.start = bootlog_seq_start,
	.next  = bootlog_seq_next,
	.stop  = bootlog_seq_stop,
	.show  = bootlog_seq_show
};

static int bootlog_proc_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &bootlog_seq_ops);
}

static const struct proc_ops bootlog_proc_ops = {
	.proc_open    = bootlog_proc_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = seq_release
};

static int __init init_procshow(void)
{
	const char *signature;

	if (bootblock_virt == NULL) {
		return -EINVAL;
	}

	signature = (char *) bootblock_virt->info.bios.signature;
	if (!strcmp(signature, BIOS_INFO_SIGNATURE)) {
		if (!proc_create(BOOTDATA_FILENAME, S_IRUGO, NULL,
				 &bootdata_proc_ops))
			return -ENOMEM;
	}

	if (!proc_create(LOADTIME_FILENAME, S_IRUGO, NULL, &loadtime_proc_ops))
		return -ENOMEM;

#ifdef CONFIG_BOOT_TRACE
	if (!proc_create(LOADTIMEKERN_FILENAME, S_IRUGO, NULL,
			 &loadtime_kernel_proc_ops))
		return -ENOMEM;
#endif	/* CONFIG_BOOT_TRACE */

#if defined(CONFIG_E2K) || defined(CONFIG_E90S)
	if (num_possible_rdmas()) {
		rdma_proc_ops_pointer = &rdma_proc_ops;
		rdma_entry = proc_create(RDMA_FILENAME, S_IRUGO,
					 NULL, rdma_proc_ops_pointer);
		if (!rdma_entry) {
			rdma_proc_ops_pointer = NULL;
			return -ENOMEM;
		}
	}

	nodes_proc_ops_pointer = &nodes_proc_ops;
	nodes_entry = proc_create(NODES_FILENAME, S_IRUGO,
				NULL, nodes_proc_ops_pointer);
	if (!nodes_entry) {
		nodes_proc_ops_pointer = NULL;
		return -ENOMEM;
	}
#endif

	if (bootblock_virt->info.bios.bootlog_len) {
		if (!proc_create(BOOTLOG_FILENAME, S_IRUGO, NULL,
				 &bootlog_proc_ops))
			return -ENOMEM;
	}

	return 0;
}

module_init(init_procshow);
