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
#include <linux/mtd/mtd.h>

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
#define BOOTDATA_SYS_FILENAME	"boot"

#define SER_STR_SIZE	32
#define MAC_STR_SIZE	32
#define UUID_STR_SIZE	64

#define BOOT_COMMIT_STR_SIZE	32
#define BOOT_DATE_STR_SIZE		32
#define BOOT_VER_SIZE_STR		64
#define BOOT_COMMIT_SIZE_STR	64
#define BOOT_TARGET_SIZE_STR	64
#define BOOT_TYPE_STR_SIZE		64

#define DATE_INDEX		0
#define VERSION_INDEX	1
#define COMPILER_INDEX	2
#define AUTHOR_INDEX	3
#define RAW_INDEX		4
#define MTD_PARTITION_NUMBER 0

#define MAX_ITEMS				256
#define MAX_PNS_CHECKSUM_SIZE	9
#define MAX_KEY_SIZE			64
#define MAX_VALUE_SIZE			256


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

struct key_value_pair {
	char key[MAX_KEY_SIZE];
	char value[MAX_VALUE_SIZE];
};

struct private_data {
	struct key_value_pair items[MAX_ITEMS];
	size_t last_item;
	char pns_checksum[MAX_PNS_CHECKSUM_SIZE];
	struct mutex mutex_mtd;
};

struct procshow_data {
	struct kobject kobj;
	struct private_data *priv;
};

#if defined(CONFIG_E2K) || defined(CONFIG_E90S)
#define RDMA_FILENAME		"rdmainfo"
static struct proc_dir_entry	*rdma_entry = NULL;
static const struct proc_ops *rdma_proc_ops_pointer = NULL;

#define NODES_FILENAME		"nodesinfo"
static struct proc_dir_entry *nodes_entry = NULL;
static const struct proc_ops *nodes_proc_ops_pointer = NULL;
#endif


#define BOOTLOG_FILENAME	"bootlog"
#define BOOTLOG_BLOCK_SIZE	1024

#define BOOTLOG_BLOCKS_COUNT	\
	((bootblock_virt->info.bootlog_len / BOOTLOG_BLOCK_SIZE) + \
	 ((bootblock_virt->info.bootlog_len % BOOTLOG_BLOCK_SIZE) ? \
			1 : 0))

static void get_uuid_clean(__u8 *uuid, char *uuidstr)
{
	int i;
	uuidstr[0] = 0;
	for (i = 0; i < 16; i++) {
		if (uuid[i] != 0) {
			snprintf(uuidstr, UUID_STR_SIZE,
				"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
				uuid[0], uuid[1], uuid[2], uuid[3],
				uuid[4], uuid[5], uuid[6], uuid[7],
				uuid[8], uuid[9], uuid[10], uuid[11],
				uuid[12], uuid[13], uuid[14], uuid[15]);
			break;
		}
	}
}

static void get_macaddr_clean(__u8 *mac_addr, char *macstr)
{
	macstr[0] = 0;
	if (mac_addr[3] != 0 && mac_addr[4] != 0 && mac_addr[5] != 0) {
		snprintf(macstr, MAC_STR_SIZE,
			"%02X:%02X:%02X:%02X:%02X:%02X",
			mac_addr[0], mac_addr[1],
			mac_addr[2], mac_addr[3],
			mac_addr[4], mac_addr[5]);
	}
}
static void get_uuid(__u8 *uuid, char *uuidstr)
{
	char clean_uuidstr[UUID_STR_SIZE];
	get_uuid_clean(bootblock_virt->info.uuid, clean_uuidstr);
	if (strlen(clean_uuidstr))
		snprintf(uuidstr, UUID_STR_SIZE, "uuid='%s'\n", clean_uuidstr);
	else
		snprintf(uuidstr, UUID_STR_SIZE, "");
}

static void get_macaddr(__u8 *mac_addr, char *macstr)
{
	char clean_macstr[MAC_STR_SIZE];
	get_macaddr_clean(bootblock_virt->info.mac_addr, clean_macstr);
	if (strlen(clean_macstr))
		snprintf(macstr, MAC_STR_SIZE, "mac='%s'\n", clean_macstr);
	else
		snprintf(macstr, MAC_STR_SIZE, "");
}

static void get_sernum(__u64 mach_serialn, char *serstr)
{
	serstr[0] = 0;
	if (mach_serialn != 0) {
		snprintf(serstr, SER_STR_SIZE, "serial='%llu'\n", mach_serialn);
	}
}

static int bootdata_proc_show(struct seq_file *m, void *data)
{
	char serstr[SER_STR_SIZE];
	char macstr[MAC_STR_SIZE];
	char uuidstr[UUID_STR_SIZE];

	get_sernum(bootblock_virt->info.mach_serialn, serstr);
	get_macaddr(bootblock_virt->info.mac_addr, macstr);
	get_uuid(bootblock_virt->info.uuid, uuidstr);

	seq_printf(m,
		"boot_ver='%s'\n"
		"mb_type='%s' (0x%x)\n"
		"chipset_type='IOHUB'\n"
		"cpu_type='%s'\n"
		"cache_lines_damaged=%lu\n"
		"reset_type=0x%x\n"
		"%s%s%s",
		bootblock_virt->info.boot_ver,
		mcst_mb_name,
		bootblock_virt->info.mb_type,
		GET_CPU_TYPE_NAME(bootblock_virt->info.cpu_type),
		(unsigned long)bootblock_virt->info.cache_lines_damaged,
		bootblock_virt->info.reset_type,
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

	start_addr = (u64)__va(bootblock_virt->info.bootlog_addr);
	end_addr = start_addr + bootblock_virt->info.bootlog_len;
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

static struct kobject *bootdata_sys_kobj;
static struct kobject *bootbin_sys_kobj;

static ssize_t boot_ver_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	char boot_ver_clean[BOOT_VER_SIZE_STR] = "unknown";
	const char *raw_ver = bootblock_virt->info.boot_ver;

	if (!raw_ver)
		return scnprintf(buf, PAGE_SIZE, "%s\n", boot_ver_clean);

	const char *p_colons = strstr(raw_ver, "::");

	if (p_colons) {
		const char *start = raw_ver;

		while ((start < p_colons) && (*start == ' ' || *start == '\t'
				|| *start == '\n' || *start == '\r'))
			start++;

		const char *end = p_colons;

		while (end > start && (*(end - 1) == ' ' || *(end - 1) == '\t' ||
				*(end - 1) == '\n' || *(end - 1) == '\r'))
			end--;

		const char *p_release_end = strstr(start, "-");

		if (p_release_end && (p_release_end - start == 3) &&
				strncmp(start, "pre", 3) == 0) {
			p_release_end = strstr(p_release_end + 1, "-");
		}

		if (p_release_end && p_release_end < end) {
			p_release_end++;
			size_t boot_ver_len = end - p_release_end;
			if (boot_ver_len > 0 && boot_ver_len < sizeof(boot_ver_clean)) {
				strncpy(boot_ver_clean, p_release_end, boot_ver_len);
				boot_ver_clean[boot_ver_len] = '\0';
			}
		}
	}
	return scnprintf(buf, PAGE_SIZE, "%s\n", boot_ver_clean);
}

static ssize_t boot_type_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	char boot_type[BOOT_TYPE_STR_SIZE] = "unknown";
	const char *raw_ver = bootblock_virt->info.boot_ver;

	if (!raw_ver)
		return scnprintf(buf, PAGE_SIZE, "%s\n", boot_type);

	const char *p_colons = strstr(raw_ver, "::");

	if (p_colons) {
		const char *start = raw_ver;

		while ((start < p_colons) && (*start == ' ' || *start == '\t'
				|| *start == '\n' || *start == '\r'))
			start++;

		const char *end = p_colons;

		while (end > start && (*(end - 1) == ' ' || *(end - 1) == '\t' ||
				*(end - 1) == '\n' || *(end - 1) == '\r'))
			end--;

		const char *p_release_end = strstr(start, "-");

		if (p_release_end && (p_release_end - start == 3) &&
				strncmp(start, "pre", 3) == 0) {
			p_release_end = strstr(p_release_end + 1, "-");
		}

		size_t len = end - start;

		if (p_release_end && p_release_end < end) {
			size_t len_release = p_release_end - start;
			if (len_release >= sizeof(boot_type))
				len_release = sizeof(boot_type) - 1;

			strncpy(boot_type, start, len_release);
			boot_type[len_release] = '\0';
		} else {
			if (len > 0 && len < sizeof(boot_type)) {
				strncpy(boot_type, start, len);
				boot_type[len] = '\0';
			}
		}
	}
	return scnprintf(buf, PAGE_SIZE, "%s\n", boot_type);
}

static ssize_t boot_target_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	char boot_target[BOOT_TARGET_SIZE_STR] = "unknown";
	const char *raw_ver = bootblock_virt->info.boot_ver;

	if (!raw_ver)
		return scnprintf(buf, PAGE_SIZE, "%s\n", boot_target);

	const char *p_commit = strstr(raw_ver, "commit ");

	if (p_commit) {
		const char *end = NULL;
		const char *start = strchr(p_commit, '(');

		if (start)
			end = strchr(start, ')');

		if (start && end && end > start) {
			start++;
			size_t boot_target_len = end - start;
			strncpy(boot_target, start, boot_target_len);
			boot_target[boot_target_len] = '\0';
		}
	}
	return scnprintf(buf, PAGE_SIZE, "%s\n", boot_target);
}

static ssize_t boot_commit_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	char boot_commit[BOOT_COMMIT_SIZE_STR] = "unknown";
	const char *raw_ver = bootblock_virt->info.boot_ver;

	if (!raw_ver)
		return scnprintf(buf, PAGE_SIZE, "%s\n", boot_commit);

	const char *p_commit = strstr(raw_ver, "commit ");

	if (p_commit) {
		p_commit += 7;
		strscpy(boot_commit, p_commit, sizeof(boot_commit));

		char *comma = strchr(boot_commit, ',');
		if (comma)
			*comma = '\0';
	}
	return scnprintf(buf, PAGE_SIZE, "%s\n", boot_commit);
}

static ssize_t boot_commit_date_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	char boot_date_iso[BOOT_DATE_STR_SIZE] = "unknown";
	const char *raw_ver = bootblock_virt->info.boot_ver;

	if (!raw_ver)
		return scnprintf(buf, PAGE_SIZE, "%s\n", boot_date_iso);

	char *p_commit = strstr(raw_ver, "commit ");

	if (p_commit) {
		p_commit += 7;

		char *comma = strchr(p_commit, ',');
		if (comma) {
			const char *date_src = comma + 1;

			while (*date_src == ' ' || *date_src == '\t')
				date_src++;

			bool date_exist = true;

			for (int i = 0; i < 12; i++)
				if (!isdigit((unsigned char)date_src[i])) {
					date_exist = false;
					break;
				}

			if (date_exist)
				snprintf(boot_date_iso, sizeof(boot_date_iso),
					"%c%c%c%c-%c%c-%c%cT%c%c:%c%c",
					date_src[0], date_src[1], date_src[2],
					date_src[3], date_src[4], date_src[5],
					date_src[6], date_src[7], date_src[8],
					date_src[9], date_src[10], date_src[11]);
		}
	}
	return scnprintf(buf, PAGE_SIZE, "%s\n", boot_date_iso);
}

static ssize_t mb_type_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%s\n", mcst_mb_name);
}

static ssize_t mb_type_raw_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "0x%x\n", bootblock_virt->info.mb_type);
}

static ssize_t cpu_type_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%s\n", GET_CPU_TYPE_NAME(bootblock_virt->info.cpu_type));
}

static ssize_t cache_lines_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%lu\n",
					(unsigned long)bootblock_virt->info.cache_lines_damaged);
}

static ssize_t reset_type_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "0x%x\n", bootblock_virt->info.reset_type);
}

static ssize_t uuid_boot_part_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	char clean_uuidstr[UUID_STR_SIZE];
	get_uuid_clean(bootblock_virt->info.uuid, clean_uuidstr);

	return scnprintf(buf, PAGE_SIZE, "%s\n", clean_uuidstr);
}

static ssize_t mac_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	char clean_macstr[MAC_STR_SIZE];
	get_macaddr_clean(bootblock_virt->info.mac_addr, clean_macstr);

	return scnprintf(buf, PAGE_SIZE, "%s\n", clean_macstr);
}

static struct kobj_attribute boot_type_attr = __ATTR_RO(boot_type);
static struct kobj_attribute boot_ver_attr = __ATTR_RO(boot_ver);
static struct kobj_attribute boot_commit_attr = __ATTR_RO(boot_commit);
static struct kobj_attribute boot_commit_date_attr = __ATTR_RO(boot_commit_date);
static struct kobj_attribute boot_target_attr = __ATTR_RO(boot_target);
static struct kobj_attribute mb_type_attr = __ATTR_RO(mb_type);
static struct kobj_attribute mb_type_raw_attr = __ATTR_RO(mb_type_raw);
static struct kobj_attribute cpu_type_attr = __ATTR_RO(cpu_type);
static struct kobj_attribute cache_lines_attr = __ATTR_RO(cache_lines);
static struct kobj_attribute reset_type_attr = __ATTR_RO(reset_type);
static struct kobj_attribute uuid_boot_part_attr = __ATTR_RO(uuid_boot_part);
static struct kobj_attribute mac_attr = __ATTR_RO(mac);

static struct attribute *boot_sys_attrs[] = {
	&boot_type_attr.attr,
	&boot_ver_attr.attr,
	&boot_commit_attr.attr,
	&boot_commit_date_attr.attr,
	&boot_target_attr.attr,
	&mb_type_attr.attr,
	&mb_type_raw_attr.attr,
	&cpu_type_attr.attr,
	&cache_lines_attr.attr,
	&reset_type_attr.attr,
	&mac_attr.attr,
	&uuid_boot_part_attr.attr,
	NULL,
};

static struct attribute_group bootdata_sys_attr_group = {
	.attrs = boot_sys_attrs,
};

#ifdef CONFIG_MTD
int read_keys(struct mtd_info *mtd, size_t *offset, struct private_data *priv)
{
	char *key_p;
	char *val_p;
	size_t bytes_read;
	size_t key_len;
	size_t val_len;

	size_t bytes_in_buf = 0;
	size_t cur_pos = 0;
	int was_border = 1;
	char *buf = kzalloc(0x2000, GFP_KERNEL);

	while (buf) {
		if (*offset >= mtd->size) {
			pr_warn("Second BOOTBOOT in Signature not found: reached end of MTD device!\n");
			kfree(buf);
			return -1;
		}
		if (priv->last_item >= MAX_ITEMS) {
			pr_warn("Signature contains too many key-value pairs (> %d)\n", MAX_ITEMS);
			kfree(buf);
			return -1;
		}
		if (was_border) {
			size_t bytes_over = bytes_in_buf - cur_pos;
			if (bytes_over > 0)
				memmove(buf, buf + cur_pos, bytes_over);
			cur_pos = 0;
			bytes_in_buf = bytes_over;

			int err = mtd_read(mtd, *offset, 0x1000, &bytes_read, buf + bytes_in_buf);
			if (err && err != -EUCLEAN) {
				kfree(buf);
				return -1;
			}
			if (!bytes_read) {
				kfree(buf);
				return -1;
			}
			*offset += bytes_read;
			bytes_in_buf += bytes_read;
			was_border = 0;
		}

		key_p = buf + cur_pos;
		key_len = strnlen(key_p, bytes_in_buf - cur_pos);

		if (cur_pos + key_len == bytes_in_buf) {
			was_border = 1;
			continue;
		}

		if (!strcmp(key_p, "BOOTBOOT")) {
			kfree(buf);
			return 0;
		}

		cur_pos += key_len + 1;
		while (cur_pos < bytes_in_buf && buf[cur_pos] == '\0')
			cur_pos++;

		val_p = buf + cur_pos;
		val_len = strnlen(val_p, bytes_in_buf - cur_pos);

		if (cur_pos + val_len == bytes_in_buf) {
			was_border = 1;
			cur_pos = key_p - buf;
			continue;
		}

		cur_pos += val_len + 1;
		while (cur_pos < bytes_in_buf && buf[cur_pos] == '\0')
			cur_pos++;

		if (!strncmp(key_p, "BFLAGS", strlen("BFLAGS")))
			continue;
		if (!strncmp(key_p, "DATE", strlen("DATE"))) {
			strlcpy(priv->items[DATE_INDEX].key, "DATE", MAX_KEY_SIZE);
			strlcpy(priv->items[DATE_INDEX].value, val_p, MAX_VALUE_SIZE);
			continue;
		}
		if (!strncmp(key_p, "VERSION", strlen("VERSION"))) {
			strlcpy(priv->items[VERSION_INDEX].key, "VERSION", MAX_KEY_SIZE);
			strlcpy(priv->items[VERSION_INDEX].value, val_p, MAX_VALUE_SIZE);
			continue;
		}
		if (!strncmp(key_p, "COMPILER", strlen("COMPILER"))) {
			strlcpy(priv->items[COMPILER_INDEX].key, "COMPILER", MAX_KEY_SIZE);
			strlcpy(priv->items[COMPILER_INDEX].value, val_p, MAX_VALUE_SIZE);
			continue;
		}
		if (!strncmp(key_p, "AUTHOR", strlen("AUTHOR"))) {
			strlcpy(priv->items[AUTHOR_INDEX].key, "AUTHOR", MAX_KEY_SIZE);
			strlcpy(priv->items[AUTHOR_INDEX].value, val_p, MAX_VALUE_SIZE);
			continue;
		}
		strlcpy(priv->items[priv->last_item].key, key_p, MAX_KEY_SIZE);
		strlcpy(priv->items[priv->last_item].value, val_p, MAX_VALUE_SIZE);
		priv->last_item++;
	}
	kfree(buf);
	return 0;
}

static int mtd_access(struct private_data *priv)
{
	size_t bytes_read;
	struct mtd_info *mtd;
	char *read_buf = NULL;
	size_t offset = 0;
	int err = 0;
	uint64_t pns_size = 0;
	int read_status = 0;

	mtd = get_mtd_device(NULL, MTD_PARTITION_NUMBER);
	if (IS_ERR(mtd))
		return PTR_ERR(mtd);

	read_buf = kzalloc(0x1000, GFP_KERNEL);
	if (!read_buf) {
		put_mtd_device(mtd);
		return -ENOMEM;
	}
	*read_buf = '\0';

	while (!err || err == -EUCLEAN) {
		if (offset >= mtd->size) {
			pr_warn("Signature not found: reached end of MTD device!\n");
			kfree(read_buf);
			if (mtd)
				put_mtd_device(mtd);
			return -1;
		}
		if (!strncmp(read_buf, "BOOTBOOT", strlen("BOOTBOOT"))) {
			pns_size =	(uint64_t)(read_buf[15]) << 56 |
						(uint64_t)(read_buf[14]) << 48 |
						(uint64_t)(read_buf[13]) << 40 |
						(uint64_t)(read_buf[12]) << 32 |
						(uint64_t)(read_buf[11]) << 24 |
						(uint64_t)(read_buf[10]) << 16 |
						(uint64_t)(read_buf[9]) << 8  |
						(uint64_t)(read_buf[8]);
			offset += 0x10;
			read_status = read_keys(mtd, &offset, priv);
			break;
		}
		offset += 0x10000;
		err = mtd_read(mtd, offset, 0x1000, &bytes_read, read_buf);
	}

	if (pns_size) {
		err = mtd_read(mtd, pns_size - 0x8, 0x8, &bytes_read, read_buf);
		if (!err || err == -EUCLEAN)
			strlcpy(priv->pns_checksum, read_buf, MAX_PNS_CHECKSUM_SIZE);
	}

	kfree(read_buf);

	if (mtd)
		put_mtd_device(mtd);

	return 0;
}
#endif /* CONFIG_MTD */

static ssize_t date_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct procshow_data *data = container_of(kobj, struct procshow_data, kobj);
	struct private_data *priv_data;

	if (!data || !data->priv)
		return -ENODATA;

	priv_data = data->priv;
#ifdef CONFIG_MTD
	int ret;

	mutex_lock(&priv_data->mutex_mtd);
	if (!strcmp(priv_data->items[DATE_INDEX].value, "unknown"))
		ret = mtd_access(priv_data);
	mutex_unlock(&priv_data->mutex_mtd);
#endif

	return scnprintf(buf, PAGE_SIZE, "%s\n", priv_data->items[DATE_INDEX].value);
}

static ssize_t version_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct procshow_data *data = container_of(kobj, struct procshow_data, kobj);
	struct private_data *priv_data;

	if (!data || !data->priv)
		return -ENODATA;

	priv_data = data->priv;
#ifdef CONFIG_MTD
	int ret;

	mutex_lock(&priv_data->mutex_mtd);
	if (!strcmp(priv_data->items[VERSION_INDEX].value, "unknown"))
		ret = mtd_access(priv_data);
	mutex_unlock(&priv_data->mutex_mtd);
#endif

	return scnprintf(buf, PAGE_SIZE, "%s\n", priv_data->items[VERSION_INDEX].value);
}

static ssize_t compiler_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct procshow_data *data = container_of(kobj, struct procshow_data, kobj);
	struct private_data *priv_data;

	if (!data || !data->priv)
		return -ENODATA;

	priv_data = data->priv;
#ifdef CONFIG_MTD
	int ret;

	mutex_lock(&priv_data->mutex_mtd);
	if (!strcmp(priv_data->items[COMPILER_INDEX].value, "unknown"))
		ret = mtd_access(priv_data);
	mutex_unlock(&priv_data->mutex_mtd);
#endif

	return scnprintf(buf, PAGE_SIZE, "%s\n", priv_data->items[COMPILER_INDEX].value);
}

static ssize_t author_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct procshow_data *data = container_of(kobj, struct procshow_data, kobj);
	struct private_data *priv_data;

	if (!data || !data->priv)
		return -ENODATA;

	priv_data = data->priv;
#ifdef CONFIG_MTD
	int ret;

	mutex_lock(&priv_data->mutex_mtd);
	if (!strcmp(priv_data->items[AUTHOR_INDEX].value, "unknown"))
		ret = mtd_access(priv_data);
	mutex_unlock(&priv_data->mutex_mtd);
#endif

	return scnprintf(buf, PAGE_SIZE, "%s\n", priv_data->items[AUTHOR_INDEX].value);
}

static ssize_t raw_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct procshow_data *data = container_of(kobj, struct procshow_data, kobj);
	struct private_data *priv_data;
	ssize_t offset = 0;

	if (!data || !data->priv)
		return -ENODATA;

	priv_data = data->priv;
#ifdef CONFIG_MTD
	int ret;

	mutex_lock(&priv_data->mutex_mtd);
	if (!strcmp(priv_data->items[RAW_INDEX].value, "unknown"))
		ret = mtd_access(priv_data);
	mutex_unlock(&priv_data->mutex_mtd);
#endif

	for (int i = 0; i < MAX_ITEMS; ++i) {
		if (i == priv_data->last_item)
			break;
		if (strcmp(priv_data->items[i].value, "unknown")) {
			offset += scnprintf(buf + offset, PAGE_SIZE - offset, "%s:%s\n",
				priv_data->items[i].key, priv_data->items[i].value);
		}
	}

	return offset;
}

static ssize_t cksum_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct procshow_data *data = container_of(kobj, struct procshow_data, kobj);
	struct private_data *priv_data;

	if (!data || !data->priv)
		return -ENODATA;

	priv_data = data->priv;
#ifdef CONFIG_MTD
	int ret;

	mutex_lock(&priv_data->mutex_mtd);
	if (!strcmp(priv_data->pns_checksum, "unknown"))
		ret = mtd_access(priv_data);
	mutex_unlock(&priv_data->mutex_mtd);
#endif

	return scnprintf(buf, PAGE_SIZE, "%s\n", priv_data->pns_checksum);
}

static struct kobj_attribute date_attr = __ATTR_RO(date);
static struct kobj_attribute version_attr = __ATTR_RO(version);
static struct kobj_attribute compiler_attr = __ATTR_RO(compiler);
static struct kobj_attribute author_attr = __ATTR_RO(author);
static struct kobj_attribute raw_attr = __ATTR_RO(raw);
static struct kobj_attribute cksum_attr = __ATTR_RO(cksum);

static struct attribute *bootbin_attrs[] = {
	&date_attr.attr,
	&version_attr.attr,
	&compiler_attr.attr,
	&author_attr.attr,
	&raw_attr.attr,
	&cksum_attr.attr,
	NULL,
};

static struct attribute_group bootbin_sys_attr_group = {
	.attrs = bootbin_attrs,
};

static void procshow_release(struct kobject *kobj)
{
	struct procshow_data *data = container_of(kobj, struct procshow_data, kobj);
	kfree(data->priv);
	kfree(data);
}

static struct kobj_type kobj_type_bootbin = {
	.sysfs_ops = &kobj_sysfs_ops,
	.release = &procshow_release,
};


static int __init init_procshow(void)
{
	if (bootblock_virt == NULL)
		return -EINVAL;

	if (!proc_create(BOOTDATA_FILENAME, S_IRUGO, NULL,
			 &bootdata_proc_ops))
		return -ENOMEM;

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

	if (bootblock_virt->info.bootlog_len) {
		if (!proc_create(BOOTLOG_FILENAME, S_IRUGO, NULL,
				 &bootlog_proc_ops))
			return -ENOMEM;
	}

	bootdata_sys_kobj = kobject_create_and_add(BOOTDATA_SYS_FILENAME, firmware_kobj);
	if (!bootdata_sys_kobj) {
		pr_err("Failed to create boot info\n");
		return -ENOMEM;
	}

	if (sysfs_create_group(bootdata_sys_kobj, &bootdata_sys_attr_group)) {
		pr_err("Failed to create sysfs group\n");
		kobject_put(bootdata_sys_kobj);
		return -ENOMEM;
	}

	struct procshow_data *data = kzalloc(sizeof(struct procshow_data), GFP_KERNEL);

	if (!data)
		return -ENOMEM;

	data->priv = kzalloc(sizeof(struct private_data), GFP_KERNEL);

	if (!data->priv) {
		kfree(data);
		return -ENOMEM;
	}

	data->priv->last_item = RAW_INDEX;
	for (int i = 0; i < MAX_ITEMS; i++)
		strlcpy(data->priv->items[i].value, "unknown", MAX_VALUE_SIZE);
	strlcpy(data->priv->pns_checksum, "unknown", MAX_VALUE_SIZE);

	int ret = kobject_init_and_add(&data->kobj, &kobj_type_bootbin,
						bootdata_sys_kobj, "bootbin");
	if (ret) {
		kfree(data->priv);
		kfree(data);
		pr_err("Failed to create boot bin\n");
		return ret;
	}
	bootbin_sys_kobj = &data->kobj;

	if (sysfs_create_group(bootbin_sys_kobj, &bootbin_sys_attr_group)) {
		kfree(data->priv);
		kfree(data);
		pr_err("Failed to create sysfs group\n");
		kobject_put(&data->kobj);
		return -ENOMEM;
	}
	mutex_init(&data->priv->mutex_mtd);
	return 0;
}

module_init(init_procshow);
