/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Architecture-specific setup.
 */

#include <linux/dma-direct.h>
#include <linux/init.h>
#include <linux/efi.h>
#include <linux/tty.h>
#include <linux/blkdev.h>
#include <linux/sched.h>
#include <linux/console.h>
#include <linux/ioport.h>
#include <linux/acpi.h>
#include <linux/seq_file.h>
#include <linux/syscalls.h>
#include <linux/initrd.h>
#include <linux/memblock.h>
#include <linux/root_dev.h>
#include <linux/sched/mm.h>
#include <linux/screen_info.h>
#include <linux/start_kernel.h>
#include <linux/utsname.h>
#include <linux/timex.h>
#include <linux/kthread.h>
#include <linux/of_fdt.h>
#include <linux/pgtable.h>
#include <linux/smp.h>
#include <linux/irqchip.h>
#include <linux/kasan.h>

#include <asm/alternative.h>
#include <asm/cpu.h>
#include <asm/system.h>
#include <asm/e2k.h>
#include <asm/e2k_sic.h>
#include <asm/sic_regs.h>
#include <asm/sic_regs_access.h>
#include <asm/mmu_context.h>
#include <asm/page.h>
#include <asm/pgalloc.h>
#include <asm/set_memory.h>
#include <asm/head.h>
#include <asm/p2v/boot_head.h>
#include <asm/p2v/boot_init.h>
#include <asm/processor.h>
#include <asm/process.h>
#include <asm/bootinfo.h>
#include <asm/mpspec.h>
#include <asm/setup.h>
#include <asm/timer.h>
#include <asm/time.h>
#include <asm/traps.h>
#include <asm/p2v/boot_param.h>
#include <asm/e2k_debug.h>
#include <asm/simul.h>
#include <asm/kvm/hvc-console.h>

#include <asm-l/l_timer.h>
#include <asm-l/i2c-spi.h>
#include <asm/smp.h>


#undef	DEBUG_PROCESS_MODE
#undef	DebugP
#define	DEBUG_PROCESS_MODE	0	/* processes */
#define DebugP(...)		DebugPrint(DEBUG_PROCESS_MODE ,##__VA_ARGS__)

#undef	DEBUG_PER_CPU_MODE
#undef	DebugPC
#define	DEBUG_PER_CPU_MODE	0	/* per CPU data */
#define DebugPC(...)		DebugPrint(DEBUG_PER_CPU_MODE ,##__VA_ARGS__)

/* cpu_data[boot_cpu_physical_apicid] is data for the bootstrap processor: */
cpuinfo_e2k_t cpu_data[NR_CPUS];
EXPORT_SYMBOL(cpu_data);

/*
 * Initialize this to place in .data segment, not bss
 */
char command_line[COMMAND_LINE_SIZE] = {'a'};

#define MACH_TYPE_NAME_UNKNOWN		0
#define MACH_TYPE_NAME_E2S		1
#define MACH_TYPE_NAME_E8C		2
#define MACH_TYPE_NAME_E1CP		3
#define MACH_TYPE_NAME_E8C2		4
#define MACH_TYPE_NAME_E12C		5
#define MACH_TYPE_NAME_E16C		6
#define MACH_TYPE_NAME_E2C3		7
#define MACH_TYPE_NAME_E8V7		9

/*
 * Machine type names.
 * Machine name can be retrieved from /proc/cpuinfo as model name.
 */
static const char *const native_cpu_type_name[] = {
	"unknown",
	"e2s",
	"e8c",
	"e1c+",
	"e8c2",
	"e12c",
	"e16c",
	"e2c3",
	"e8v7",
};

static const char *const native_mach_type_name[] = {
	"unknown",
	"Elbrus-e2k-e2s",
	"Elbrus-e2k-e8c",
	"Elbrus-e2k-e1c+",
	"Elbrus-e2k-e8c2",
	"Elbrus-e2k-e12c",
	"Elbrus-e2k-e16c",
	"Elbrus-e2k-e2c3",
	"Elbrus-e2k-e8v7",
};

const char *e2k_get_cpu_type_name(int mach_type_id)
{
	return native_cpu_type_name[mach_type_id];
}

const char *e2k_get_mach_type_name(int mach_type_id)
{
	return native_mach_type_name[mach_type_id];
}

int e2k_get_machine_type_name(int mach_id)
{
	int mach_type;

	switch (mach_id) {
#ifdef CONFIG_CPU_E2S
	case MACHINE_ID_E2S_LMS:
	case MACHINE_ID_E2S:
		mach_type = MACH_TYPE_NAME_E2S;
		break;
#endif
#ifdef CONFIG_CPU_E8C
	case MACHINE_ID_E8C_LMS:
	case MACHINE_ID_E8C:
		mach_type = MACH_TYPE_NAME_E8C;
		break;
#endif
#ifdef CONFIG_CPU_E1CP
	case MACHINE_ID_E1CP_LMS:
	case MACHINE_ID_E1CP:
		mach_type = MACH_TYPE_NAME_E1CP;
		break;
#endif
#ifdef CONFIG_CPU_E8C2
	case MACHINE_ID_E8C2_LMS:
	case MACHINE_ID_E8C2:
		mach_type = MACH_TYPE_NAME_E8C2;
		break;
#endif
#ifdef CONFIG_CPU_E12C
	case MACHINE_ID_E12C_LMS:
	case MACHINE_ID_E12C:
		mach_type = MACH_TYPE_NAME_E12C;
		break;
#endif
#ifdef CONFIG_CPU_E16C
	case MACHINE_ID_E16C_LMS:
	case MACHINE_ID_E16C:
		mach_type = MACH_TYPE_NAME_E16C;
		break;
#endif
#ifdef CONFIG_CPU_E2C3
	case MACHINE_ID_E2C3_LMS:
	case MACHINE_ID_E2C3:
		mach_type = MACH_TYPE_NAME_E2C3;
		break;
#endif
#ifdef CONFIG_CPU_E8V7
	case MACHINE_ID_E8V7_LMS:
	case MACHINE_ID_E8V7:
		mach_type = MACH_TYPE_NAME_E8V7;
		break;
#endif
	default:
		panic("setup_arch(): !!! UNKNOWN MACHINE TYPE !!!");
		mach_type = MACH_TYPE_NAME_UNKNOWN;
		break;
	}
	return mach_type;
}

/*
 * Native mach_type_id variable is set in setup_arch() function.
 */
static int native_mach_type_id = MACH_TYPE_NAME_UNKNOWN;

/*
 * Function to get name of machine type.
 * Must be used after setup_arch().
 */
static const char *native_get_cpu_type_name(void)
{
	return e2k_get_cpu_type_name(native_mach_type_id);
}

const char *native_get_mach_type_name(void)
{
	return e2k_get_mach_type_name(native_mach_type_id);
}

void native_set_mach_type_id(void)
{
	native_mach_type_id = e2k_get_machine_type_name(machine.native_id);
	if (native_mach_type_id == MACH_TYPE_NAME_UNKNOWN) {
		pr_err("%s(): unknown the machine type name\n", __func__);
		machine.setup_arch = NULL;
	}
}

void native_print_machine_type_info(void)
{
	const char *cpu_type = "?????????????";

	cpu_type = native_get_cpu_type_name();
	pr_cont("NATIVE MACHINE TYPE: %s %s, ID %04x, REVISION: %03x, ISET #%d",
		cpu_type, (NATIVE_IS_MACHINE_SIM) ? "LMS" : "",
		native_machine_id, machine.native_rev, machine.native_iset_ver);
}

machdep_t machine __ro_after_init = { 0 };
EXPORT_SYMBOL(machine);

unsigned long cpu_features[(NR_CPU_FEATURES + 63) / 64] __ro_after_init;
EXPORT_SYMBOL(cpu_features);

#ifdef	CONFIG_E2K_MACHINE
/* 'native_machine_id' is defined in asm/e2k.h */
#else /* ! CONFIG_E2K_MACHINE */
unsigned int native_machine_id __ro_after_init = -1;
EXPORT_SYMBOL(native_machine_id);
#endif /* ! CONFIG_E2K_MACHINE */

unsigned long machine_serial_num = -1UL;
EXPORT_SYMBOL(machine_serial_num);

int iohub_i2c_line_id = 0;
EXPORT_SYMBOL(iohub_i2c_line_id);

static int __init iohub_i2c_line_id_setup(char *str)
{
	get_option(&str, &iohub_i2c_line_id);
	if (iohub_i2c_line_id > 3)
		iohub_i2c_line_id = 3;
	else if (iohub_i2c_line_id <= 0)
		iohub_i2c_line_id = 0;
	return 1;
}
__setup("iohub_i2c_line_id=", iohub_i2c_line_id_setup);

static int __init max_iolinks_num_setup(char *str)
{
	get_option(&str, &max_iolinks);
	if (max_iolinks > MAX_NUMIOLINKS)
		max_iolinks = MAX_NUMIOLINKS;
	else if (max_iolinks <= 0)
		max_iolinks = 1;
	return 0;
}
early_param("iolinks", max_iolinks_num_setup);

static int __init max_node_iolinks_num_setup(char *str)
{
	get_option(&str, &max_node_iolinks);
	if (max_node_iolinks > NODE_NUMIOLINKS)
		max_iolinks = NODE_NUMIOLINKS;
	else if (max_node_iolinks <= 0)
		max_node_iolinks = 1;
	return 0;
}
early_param("nodeiolinks", max_node_iolinks_num_setup);

void thread_init(void)
{
	unsigned long flags;
	thread_info_t *ti = current_thread_info();
	struct pt_regs *regs = (void *) current->stack + KERNEL_C_STACK_OFFSET +
					KERNEL_C_STACK_SIZE - KERNEL_PT_REGS_SIZE;

	kernel_trap_mask_init();

	/* Arch-indep. part expects pt_regs to be always present.  Prepare
	 * them for kernel threads too and initialize with sane & stale values. */
	BUG_ON((unsigned long) regs <= (unsigned long) &ti);
	memset(regs, 0, sizeof(*regs));

	raw_all_irq_save(flags);
	SAVE_STACK_REGS(regs, false, false);
	regs->stacks.usd = read_USD_reg();
	regs->stacks.top = (unsigned long) regs;
	ti->pt_regs = regs;

	ti->k_usd = native_read_USD_reg();
	ti->k_psp = native_read_PSP_reg();
	ti->k_pcsp = native_read_PCSP_reg();
	raw_all_irq_restore(flags);

	DebugP("kernel stack: bottom %llx pt_regs %px\n"
	       "k_usd.base %llx\nk_psp.base %llx\nk_pcsp.base %llx\n",
	       (u64) current->stack, ti->pt_regs,
	       USD_PTR(ti->k_usd), PSP_BASE(ti->k_psp), PCSP_BASE(ti->k_pcsp));

	/* it needs only for guest booting threads */
	virt_cpu_thread_init(current);

	DebugP("thread_init exited.\n");
}

static int __init parse_bootinfo(void)
{
	boot_info_t	*bootblock = &bootblock_virt->info;

	if (bootblock->signature == BOOTBLOCK_BOOT_SIGNATURE ||
			bootblock->signature == BOOTBLOCK_ROMLOADER_SIGNATURE ||
			bootblock->signature == BOOTBLOCK_KVM_GUEST_SIGNATURE) {
		machine_serial_num = bootblock->mach_serialn;

#ifdef CONFIG_BLK_DEV_INITRD
		if (bootblock->ramdisk_size) {
			initrd_start = vpa_to_pa(init_initrd_phys_base);
			initrd_end = initrd_start + init_initrd_size;
		} else {
			initrd_start = initrd_end = 0;
		}
#endif /* CONFIG_BLK_DEV_INITRD */
	} else {
		return -1;
	}
	return 0;
}

struct cpu_update_feature {
	int feature;
	bool set;
};

static void cpu_update_feature_greg(void *arg)
{
	struct cpu_update_feature *args = arg;
	int feature = args->feature;
	bool set = args->set;

	if (feature < 64) {
		if (set) {
			cpuhas_greg0 |= _BITULL(feature);
		} else {
			cpuhas_greg0 &= ~_BITULL(feature);
		}
	} else if (feature >= 64 && feature < 128) {
		if (set) {
			cpuhas_greg1 |= _BITULL(feature - 64);
		} else {
			cpuhas_greg1 &= ~_BITULL(feature - 64);
		}
	} else {
		BUG();
	}
}


notrace void cpu_set_feature(unsigned long *features, int feature)
{
	struct cpu_update_feature args = {
		.feature = feature,
		.set = true,
	};

	on_each_cpu(cpu_update_feature_greg, &args, true);
	set_bit(feature, features);
}

notrace void cpu_clear_feature(unsigned long *features, int feature)
{
	struct cpu_update_feature args = {
		.feature = feature,
		.set = false,
	};

	on_each_cpu(cpu_update_feature_greg, &args, true);
	clear_bit(feature, features);
}

static int __init check_hwbug_iommu(void)
{
	int node;

	if (!cpu_has(CPU_HWBUG_IOMMU))
		return 0;

	if (num_online_nodes() <= 1)
		cpu_clear_feature(cpu_features, CPU_HWBUG_IOMMU);

	for_each_online_node(node) {
		e2k_sic_sccfg_t	sccfg;

		AW(sccfg) = sic_read_node_nbsr_reg(node, SIC_sccfg);
		if (!sccfg.diren) {
			return 0;
		}

	}

	cpu_clear_feature(cpu_features, CPU_HWBUG_IOMMU);

	return 0;
}
arch_initcall(check_hwbug_iommu);

void __init e2k_start_kernel_switched_stacks(void)
{
	/*
	 * Set pointer of current task structure to kernel initial task
	 */
	setup_bsp_idle_task(0);

#ifdef	CONFIG_SMP
	current_thread_info()->cpu = 0;
	E2K_SET_DGREG_NV(SMP_CPU_ID_GREG, 0);
#endif

	/*
	 * to save initial state of debugging registers to enable
	 * hardware breakpoints
	 */
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	/* FIXME: debug registers is privileged */
	if (!paravirt_enabled())
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
		native_save_user_only_regs(&current->thread.sw_regs);

	/*
	 * All kernel threads share the same mm context.
	 */
	mmgrab(&init_mm);
	current->active_mm = &init_mm;
	BUG_ON(current->mm);

	E2K_JUMP(start_kernel);
}

void __init e2k_start_kernel(void)
{
	bsp_switch_to_init_stack();

	E2K_JUMP(e2k_start_kernel_switched_stacks);
}

/* Protect kernel from writing by virtual address at PAGE_OFFSET alias.
 * This could be called as early as setup_arch() if not for ftrace
 * initialization which accesses these areas. */
static __init int mark_linear_kernel_alias_ro(void)
{
	set_memory_ro((unsigned long) lm_alias(_stext),
		      (unsigned long) (_etext - _stext) >> PAGE_SHIFT);
	set_memory_ro((unsigned long) lm_alias(__start_rodata_notes),
		      (unsigned long) (__end_rodata_notes -
				       __start_rodata_notes) >> PAGE_SHIFT);
	set_memory_ro((unsigned long) lm_alias(__special_data_begin),
		      (unsigned long) (__special_data_end -
				       __special_data_begin) >> PAGE_SHIFT);
	set_memory_ro((unsigned long) lm_alias(__node_data_start),
		      (unsigned long) (__node_data_end -
				       __node_data_start) >> PAGE_SHIFT);
	set_memory_ro((unsigned long) lm_alias(__common_data_begin),
		      (unsigned long) (__common_data_end -
				       __common_data_begin) >> PAGE_SHIFT);
	return 0;
}
arch_initcall(mark_linear_kernel_alias_ro);

static void __init setup_cmd_line(char **cmdline_p)
{
	char *src = command_line, *dst = boot_command_line;
	/* Expand devtree command line with boot command line */
	if (dst[0])
		strlcat(dst, " ", COMMAND_LINE_SIZE);
	strlcat(dst, src, COMMAND_LINE_SIZE);
	*cmdline_p = dst;

	jump_label_init();
	parse_early_param();
}

#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
#define	_BINCOMP_STK_LIM	(8*1024*1024)
#endif

static void __init rlim_init(void)
{
	init_task.signal->rlim[RLIMIT_P_STACK_EXT].rlim_cur = PS_RLIM_CUR;
	init_task.signal->rlim[RLIMIT_P_STACK_EXT].rlim_max =
			USER_P_STACKS_MAX_SIZE;
	init_task.signal->rlim[RLIMIT_PC_STACK_EXT].rlim_cur = PCS_RLIM_CUR;
	init_task.signal->rlim[RLIMIT_PC_STACK_EXT].rlim_max =
			USER_PC_STACKS_MAX_SIZE;
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	init_task.signal->bin_comp_rlim[BC_RLIMIT_X86_DATA].rlim_cur = RLIM_INFINITY;
	init_task.signal->bin_comp_rlim[BC_RLIMIT_X86_DATA].rlim_max = RLIM_INFINITY;
	init_task.signal->bin_comp_rlim[BC_RLIMIT_X86_STACK].rlim_cur = _BINCOMP_STK_LIM;
	init_task.signal->bin_comp_rlim[BC_RLIMIT_X86_STACK].rlim_max = RLIM_INFINITY;
	init_task.signal->bin_comp_rlim[BC_RLIMIT_X86_AS].rlim_cur = RLIM_INFINITY;
	init_task.signal->bin_comp_rlim[BC_RLIMIT_X86_AS].rlim_max = RLIM_INFINITY;
#endif
}

void __init setup_arch(char **cmdline_p)
{
	extern int panic_timeout;
	int cpu;

	BUILD_BUG_ON(ARCH_KMALLOC_MINALIGN != max(ARCH_SLAB_MINALIGN, ARCH_DMA_MINALIGN));

	/*
	 * get cmdline from devtree
	 */
	early_device_tree_init();

	/*
	 * Place it before arch_setup_machine()
	 */
	setup_cmd_line(cmdline_p);

	arch_setup_machine();

	/*
	 * This should be as early as possible to fill cpu_present_mask and
	 * cpu_possible_mask.
	 */

	 /*
	 * Find (but now set) boot-time smp configuration.
	 * Like in i386 arch. used MP Floating Pointer Structure.
	 */
	find_smp_config();

	/*
	 * Set entries of MP Configuration tables (but now one processor
	 * system)
	 */
	get_smp_config();

#ifdef CONFIG_SMP
	nmi_call_function_init();
#endif

	parse_bootinfo();

	/* reboot on panic */
	panic_timeout = 30;	/* 30 seconds of black screen of death */

	l_setup_arch();
	set_mach_type_id();

	pr_notice("ARCH: E2K ");

	/* Although utsname is protected by uts_sem, locking it here is
	 * not needed - this early in boot process there is no one to race
	 * with. Moreover, semaphore operations must be called from places
	 * where sleeping is allowed, but here interrupts are disabled. */
	/* down_write(&uts_sem); */

	print_machine_type_info();

	/* See comment above */
	/* up_write(&uts_sem); */

	if (machine_serial_num == -1UL || machine_serial_num == 0)
		pr_cont(" SERIAL # UNKNOWN\n");
	else
		pr_cont(" SERIAL # 0x%016lx\n", machine_serial_num);

	printk("Kernel image check sum: %u\n",
	       bootblock_virt->info.kernel_csum);

	pr_notice("cpu to cpuid map: ");
	for_each_possible_cpu(cpu)
		pr_cont("%d->%d ", cpu, cpu_to_cpuid(cpu));
	pr_cont("\n");
	pr_info("Kernel loaded at phys. address 0x%llx\n", bootblock_virt->info.kernel_base);

	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
#ifdef CONFIG_THREAD_INFO_IN_TASK
		e2k_usd_t usd = init_task.thread_info.k_usd;
		init_task.thread_info.k_usd = new_usd(usd.Ptr - usd.Ind, usd.Ind, usd.Ind);
#else
		e2k_usd_t usd = init_thread_info.k_usd;
		init_thread_info.k_usd = new_usd(usd.Ptr - usd.Ind, usd.Ind, usd.Ind);
#endif
	}
	if (machine.setup_arch)
		machine.setup_arch();

	paravirt_banner();

	BOOT_TRACEPOINT("Calling paging_init()");
	paging_init();
	BOOT_TRACEPOINT("paging_init() finished");

	apply_alternative_instructions();

	device_tree_init();

	/* ACPI Tables are to be placed to phys addr in machine.setup_arch().
	 * acpi_boot_table_init() will parse the ACPI tables (if they are) for
	 * possible boot-time SMP configuration. If machine does not support
	 * ACPI, acpi_boot_table_init will disable it.
	 */
	acpi_boot_table_init();

	/* Parses MADT when ACPI is on. */
	early_acpi_boot_init();

	thread_init();

#ifdef CONFIG_BLK_DEV_INITRD
	ROOT_DEV = MKDEV(RAMDISK_MAJOR, 0);
#endif

#ifdef CONFIG_KASAN
	kasan_init();
#endif

	if (machine.native_iset_ver < E2K_ISET_V6) {
		/* memory wait operation is not supported */
		idle_nomwait = true;
		pr_info("Memory wait type idle is not supported, turn OFF\n");
	} else {
		pr_info("Memory wait type idle is %s\n",
			(idle_nomwait) ? "OFF" : "ON");
	}

	/*
	 * Read APIC and some other early information from ACPI tables.
	 */
	acpi_boot_init();

	arch_clock_setup();

	rlim_init();
}

void __init init_IRQ(void)
{
	BUG_ON(irq_init_percpu_irqstack(smp_processor_id()));

	/* SIC access should be initialized before IOAPIC (for EPIC EOI) */
	if (HAS_MACHINE_L_SIC) {
		int ret = e2k_sic_init();
		if (ret != 0) {
			panic("e2k_sic_init() failed, error %d\n", ret);
		}
	}
	/* Now we know iohubs configuration */
	e2k_apply_device_tree_patches();
	irqchip_init();
}

/*
 * Called by both boot and secondary processors
 * to move global data into per-processor storage.
 */
void store_cpu_info(int cpu)
{
	cpuinfo_e2k_t *c = &cpu_data[cpu];

	machine.setup_cpu_info(c);

	c->proc_freq = measure_cpu_freq(cpu);

	if (cpu_freq_hz == UNSET_CPU_FREQ)
		cpu_freq_hz = c->proc_freq;
	if (!cpu_clock_psec)
		cpu_clock_psec = 1000000000000L / cpu_freq_hz;

#ifdef CONFIG_SMP
	c->cpu = cpu;
#endif
}

static int __init boot_store_cpu_info(void)
{
	/* Final full version of the data */
	store_cpu_info(0);

	pr_info("Processor frequency %llu\n", cpu_data[0].proc_freq);

	return 0;
}
early_initcall(boot_store_cpu_info);

/*
 * Print CPU information.
 */
static int show_cpuinfo(struct seq_file *m, void *v)
{
	int rval = 0;

	if (machine.show_cpuinfo)
		rval = machine.show_cpuinfo(m, v);

	return rval;
}

static void *c_update(loff_t *pos)
{
	if (*pos)
		*pos = cpumask_next(*pos - 1, cpu_online_mask);
	else
		*pos = cpumask_first(cpu_online_mask);

	return *pos < nr_cpu_ids ? &cpu_data[*pos] : NULL;
}

static void *c_start(struct seq_file *m, loff_t *pos)
{
	cpus_read_lock();
	return c_update(pos);
}

static void *c_next(struct seq_file *m, void *v, loff_t *pos)
{
	++*pos;
	return c_update(pos);
}

static void c_stop(struct seq_file *m, void *v)
{
	cpus_read_unlock();
}

const struct seq_operations cpuinfo_op = {
	.start	= c_start,
	.next	= c_next,
	.stop	= c_stop,
	.show	= show_cpuinfo,
};


/*
 * Handler of errors.
 * The error message is output on console and CPU goes to suspended state
 * (executes infinite unmeaning cicle).
 * In simulation mode CPU is halted with error sign.
 */

void init_bug(const char *fmt_v, ...)
{
	register va_list ap;

	va_start(ap, fmt_v);
	dump_vprintk(fmt_v, ap);
	va_end(ap);
	dump_vprintk("\n\n\n", NULL);

	E2K_HALT_ERROR(100);

	for (;;)
		cpu_relax();
}

/*
 * Handler of warnings.
 * The warning message is output on console and CPU continues execution of
 * kernel process.
 */

void init_warning(const char *fmt_v, ...)
{
	register va_list ap;

	va_start(ap, fmt_v);
	dump_vprintk(fmt_v, ap);
	va_end(ap);
	dump_vprintk("\n", NULL);
}

#ifdef CONFIG_SYSFS
/*
 * Allow IPD setting under /sys/devices/system/cpu/e2k/ipd
 */
static ssize_t ipd_show(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	e2k_mmu_cr_t mmu_cr = get_MMU_CR();
	return sprintf(buf, "%d\n", mmu_cr.ipd);
}

static ssize_t ipd_store(struct device *dev,
			 struct device_attribute *attr,
			 const char *buf, size_t count)
{
	int ipd;
	e2k_mmu_cr_t mmu_cr = get_MMU_CR();

	if (kstrtoint(buf, 0, &ipd) < 0)
		return -EINVAL;

	if (ipd != 0 && ipd != 1)
		return -EINVAL;

	mmu_cr.ipd = ipd;
	set_MMU_CR(mmu_cr);

	return count;
}

static DEVICE_ATTR_RW(ipd);

/*
 * Allow CU_HW0 setting under /sys/devices/system/cpu/e2k/cu_hw0
 */

static ssize_t cu_hw0_show(struct device *dev,
			   struct device_attribute *attr, char *buf)
{
	e2k_cu_hw0_t cu_hw0 = native_read_CU_HW0_reg();

	return sprintf(buf, "0x%llx\n", AW(cu_hw0));
}

static ssize_t cu_hw0_store(struct device *dev,
			    struct device_attribute *attr,
			    const char *buf, size_t count)
{
	unsigned long flags;
	e2k_cu_hw0_t cu_hw0;

	if (kstrtoull(buf, 0, &AW(cu_hw0)) < 0)
		return -EINVAL;

	raw_all_irq_save(flags);
	native_write_CU_HW0_reg(cu_hw0);
	raw_all_irq_restore(flags);

	return count;
}

static DEVICE_ATTR_RW(cu_hw0);

/*
 * Allow CU_HW1 setting under /sys/devices/system/cpu/e2k/cu_hw1
 */

static ssize_t cu_hw1_show(struct device *dev,
			   struct device_attribute *attr, char *buf)
{
	u64 cu_hw1 = native_read_CU_HW1_reg_value();

	return sprintf(buf, "0x%llx\n", cu_hw1);
}

static ssize_t cu_hw1_store(struct device *dev,
			    struct device_attribute *attr,
			    const char *buf, size_t count)
{
	unsigned long flags;
	u64 cu_hw1;

	if (kstrtoull(buf, 0, &cu_hw1) < 0)
		return -EINVAL;

	raw_all_irq_save(flags);
	native_write_CU_HW1_reg_value(cu_hw1);
	raw_all_irq_restore(flags);

	return count;
}

static DEVICE_ATTR_RW(cu_hw1);

/*
 * Allow L2_CTRL_EXT setting under /sys/devices/system/cpu/e2k/l2_ctrl_ext
 */
static ssize_t l2_ctrl_ext_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "0x%llx\n", AW(read_L2_CTRL_EXT(0)));
}

static ssize_t l2_ctrl_ext_store(struct device *dev,
				 struct device_attribute *attr,
				 const char *buf, size_t count)
{
	unsigned long flags;
	e2k_l2_ctrl_ext_t l2_ctrl_ext;

	if (kstrtoull(buf, 0, &AW(l2_ctrl_ext)) < 0)
		return -EINVAL;

	raw_all_irq_save(flags);
	write_L2_CTRL_EXT(l2_ctrl_ext, 0);
	raw_all_irq_restore(flags);

	return count;
}

static DEVICE_ATTR_RW(l2_ctrl_ext);

static struct attribute *e2k_default_attrs_v3[] = {
	&dev_attr_ipd.attr,
	&dev_attr_cu_hw0.attr,
	NULL
};

static struct attribute *e2k_default_attrs_v5[] = {
	&dev_attr_cu_hw1.attr,
	NULL
};

static struct attribute *e2k_default_attrs_v6[] = {
	&dev_attr_l2_ctrl_ext.attr,
	NULL
};

static struct attribute_group e2k_attr_group_v3 = {
	.attrs = e2k_default_attrs_v3,
	.name = "e2k"
};

static struct attribute_group e2k_attr_group_v5 = {
	.attrs = e2k_default_attrs_v5,
	.name = "e2k"
};

static struct attribute_group e2k_attr_group_v6 = {
	.attrs = e2k_default_attrs_v6,
	.name = "e2k"
};

static __init int e2k_add_sysfs(void)
{
	int ret;

	ret = sysfs_create_group(&cpu_subsys.dev_root->kobj,
				 &e2k_attr_group_v3);
	if (ret)
		return ret;

	if (machine.native_iset_ver >= E2K_ISET_V5)
		sysfs_merge_group(&cpu_subsys.dev_root->kobj,
				  &e2k_attr_group_v5);

	if (machine.native_iset_ver >= E2K_ISET_V6)
		sysfs_merge_group(&cpu_subsys.dev_root->kobj,
				  &e2k_attr_group_v6);

	return 0;
}
late_initcall(e2k_add_sysfs);
#endif
