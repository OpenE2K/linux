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

#include <asm/alternative.h>
#include <asm/cpu.h>
#include <asm/system.h>
#include <asm/e2k.h>
#include <asm/e2k_sic.h>
#include <asm/io_apic.h>
#include <asm/sic_regs.h>
#include <asm/sic_regs_access.h>
#include <asm/mmu_context.h>
#include <asm/page.h>
#include <asm/pic.h>
#include <asm/pgalloc.h>
#include <asm/set_memory.h>
#include <asm/head.h>
#include <asm/p2v/boot_head.h>
#include <asm/p2v/boot_init.h>
#include <asm/machdep.h>
#include <asm/processor.h>
#include <asm/process.h>
#include <asm/bootinfo.h>
#include <asm/mpspec.h>
#include <asm/setup.h>
#include <asm/timer.h>
#include <asm/time.h>
#include <asm/traps.h>
#include <asm/p2v/boot_param.h>
#ifdef CONFIG_SOFTWARE_SWAP_TAGS
#include <asm/tag_mem.h>
#endif
#include <asm/e2k_debug.h>
#include <asm/simul.h>
#include <asm/kvm/hvc-console.h>

#include <asm-l/l_timer.h>
#include <asm-l/i2c-spi.h>
#include <asm-l/smp.h>
#ifdef CONFIG_OF
#include <asm-l/devtree.h>
#endif

/* For PCI or other memory-mapped resources */
unsigned long pci_mem_start = 0x80000000;

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
 * This space gets a copy of optional info passed to us by the bootstrap
 * Used to pass parameters into the kernel like root=/dev/sda1, etc.
 */
static char command_line[COMMAND_LINE_SIZE];

struct resource standard_io_resources[] = {
	{ 0x00, 0x1f, "dma1", IORESOURCE_BUSY },
	{ 0x20, 0x3f, "pic1", IORESOURCE_BUSY },
	{ 0x40, 0x5f, "timer", IORESOURCE_BUSY },
	{ 0x60, 0x6f, "keyboard", IORESOURCE_BUSY },
	{ 0x80, 0x8f, "dma page reg", IORESOURCE_BUSY },
	{ 0xa0, 0xbf, "pic2", IORESOURCE_BUSY },
	{ 0xc0, 0xdf, "dma2", IORESOURCE_BUSY }
};

#define MACH_TYPE_NAME_UNKNOWN		0
#define MACH_TYPE_NAME_E2S		1
#define MACH_TYPE_NAME_E8C		2
#define MACH_TYPE_NAME_E1CP		3
#define MACH_TYPE_NAME_E8C2		4
#define MACH_TYPE_NAME_E12C		5
#define MACH_TYPE_NAME_E16C		6
#define MACH_TYPE_NAME_E2C3		7
#define MACH_TYPE_NAME_E48C		8
#define MACH_TYPE_NAME_E8V7		9

/*
 * Machine type names.
 * Machine name can be retrieved from /proc/cpuinfo as model name.
 */
static const char const *native_cpu_type_name[] = {
	"unknown",
	"e2s",
	"e8c",
	"e1c+",
	"e8c2",
	"e12c",
	"e16c",
	"e2c3",
	"e48c",
	"e8v7",
};
static const char const *native_mach_type_name[] = {
	"unknown",
	"Elbrus-e2k-e2s",
	"Elbrus-e2k-e8c",
	"Elbrus-e2k-e1c+",
	"Elbrus-e2k-e8c2",
	"Elbrus-e2k-e12c",
	"Elbrus-e2k-e16c",
	"Elbrus-e2k-e2c3",
	"Elbrus-e2k-e48c",
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
#ifdef CONFIG_CPU_E48C
	case MACHINE_ID_E48C_LMS:
	case MACHINE_ID_E48C:
		mach_type = MACH_TYPE_NAME_E48C;
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
		pr_err("%s(): unknown the machine type name\n",
			__func__);
		machine.setup_arch = NULL;
	}
}

void native_print_machine_type_info(void)
{
	const char *cpu_type = "?????????????";

	cpu_type = native_get_cpu_type_name();
	pr_cont("NATIVE MACHINE TYPE: %s %s, ID %04x, REVISION: %03x, "
		"ISET #%d",
		cpu_type,
		(NATIVE_IS_MACHINE_SIM) ? "LMS" : "",
		native_machine_id,
		machine.native_rev, machine.native_iset_ver);
}

#define STANDARD_IO_RESOURCES (sizeof(standard_io_resources)/sizeof(struct resource))

machdep_t machine __ro_after_init = { 0 };
EXPORT_SYMBOL(machine);

#ifdef	CONFIG_E2K_MACHINE
/* 'native_machine_id' is defined in asm/e2k.h */
#else	/* ! CONFIG_E2K_MACHINE */
unsigned int native_machine_id __ro_after_init = -1;
EXPORT_SYMBOL(native_machine_id);
#endif	/* ! CONFIG_E2K_MACHINE */

unsigned long	machine_serial_num = -1UL;
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

extern int __initdata max_iolinks;
extern int __initdata max_node_iolinks;

static int __init
max_iolinks_num_setup(char *str)
{
	get_option(&str, &max_iolinks);
	if (max_iolinks > MAX_NUMIOLINKS)
		max_iolinks = MAX_NUMIOLINKS;
	else if (max_iolinks <= 0)
		max_iolinks = 1;
	return 1;
}
__setup("iolinks=", max_iolinks_num_setup);

static int __init
max_node_iolinks_num_setup(char *str)
{
	get_option(&str, &max_node_iolinks);
	if (max_node_iolinks > NODE_NUMIOLINKS)
		max_iolinks = NODE_NUMIOLINKS;
	else if (max_node_iolinks <= 0)
		max_node_iolinks = 1;
	return 1;
}
__setup("nodeiolinks=", max_node_iolinks_num_setup);

#if defined (CONFIG_SMP) && defined (CONFIG_HAVE_SETUP_PER_CPU_AREA)
unsigned long __per_cpu_offset[NR_CPUS] __ro_after_init;
EXPORT_SYMBOL(__per_cpu_offset);

# ifdef CONFIG_NEED_PER_CPU_EMBED_FIRST_CHUNK
#  ifdef CONFIG_NUMA
static int __init pcpu_cpu_distance(unsigned int from, unsigned int to)
{
	return node_distance(early_cpu_to_node(from), early_cpu_to_node(to));
}
#  endif /* CONFIG_NUMA */

static void * __init pcpu_alloc_memblock(unsigned int cpu, unsigned long size,
					 unsigned long align)
{
	const phys_addr_t goal = __pa(MAX_DMA_ADDRESS);
#  ifdef CONFIG_NUMA
	int node = early_cpu_to_node(cpu);
	void *ptr;

	if (!node_online(node) || !NODE_DATA(node)) {
		ptr = memblock_alloc_from(size, align, goal);
		DebugPC("cpu %d has no node %d or node-local memory\n",
			cpu, node);
		DebugPC("per cpu data for cpu%d %lu bytes at 0x%llx\n",
			cpu, size, __pa(ptr));
	} else {
		ptr = memblock_alloc_try_nid(size, align, goal,
					     MEMBLOCK_ALLOC_ACCESSIBLE,
					     node);
		DebugPC("per cpu data for cpu%d %lu bytes on node%d at 0x%llx\n",
			 cpu, size, node, __pa(ptr));
	}
	return ptr;
#  else
	return memblock_alloc_from(size, align, goal);
#  endif
}

static void * __init pcpu_fc_alloc(unsigned int cpu, size_t size, size_t align)
{
	return pcpu_alloc_memblock(cpu, size, align);
}

static void __init pcpu_fc_free(void *ptr, size_t size)
{
	memblock_free(__pa(ptr), size);
}
# endif /* CONFIG_NEED_PER_CPU_EMBED_FIRST_CHUNK */

# ifdef CONFIG_NEED_PER_CPU_PAGE_FIRST_CHUNK
static void __init pcpu_populate_pte(unsigned long addr)
{
	pgd_t *pgd = pgd_offset_k(addr);
	pud_t *pud;
	pmd_t *pmd;

	pud = pud_offset(pgd, addr);
	if (pud_none(*pud)) {
		pmd_t *new = memblock_alloc_from(PAGE_SIZE,
				PAGE_SIZE, PAGE_SIZE);
		pud_populate(&init_mm, pud, new);
	}

	pmd = pmd_offset(pud, addr);
	if (!pmd_present(*pmd)) {
		pte_t *new = memblock_alloc_from(PAGE_SIZE,
				PAGE_SIZE, PAGE_SIZE);
		pmd_populate_kernel(&init_mm, pmd, new);
	}
}
# endif /* CONFIG_NEED_PER_CPU_PAGE_FIRST_CHUNK */

void __init setup_per_cpu_areas(void)
{
	e2k_addr_t delta;
	unsigned int cpu;
	int rc = -EINVAL;

# ifdef CONFIG_NEED_PER_CPU_EMBED_FIRST_CHUNK
	if (pcpu_chosen_fc != PCPU_FC_PAGE) {
		rc = pcpu_embed_first_chunk(PERCPU_MODULE_RESERVE,
				PERCPU_DYNAMIC_RESERVE, PAGE_SIZE,
#  ifdef CONFIG_NUMA
				pcpu_cpu_distance,
#  else   /* !CONFIG_NUMA */
				NULL,
#  endif  /* CONFIG_NUMA */
				pcpu_fc_alloc, pcpu_fc_free);
		if (rc)
			DebugPC("embed allocator failed "
				"(%d), falling back to page size.\n", rc);
	}
# endif /* CONFIG_NEED_PER_CPU_EMBED_FIRST_CHUNK */

# ifdef CONFIG_NEED_PER_CPU_PAGE_FIRST_CHUNK
        if (rc < 0) {
		rc = pcpu_page_first_chunk(PERCPU_MODULE_RESERVE,
				pcpu_fc_alloc, pcpu_fc_free, pcpu_populate_pte);
		if (rc)
			DebugPC("page allocator failed (%d).\n", rc);
	}
# endif /* CONFIG_NEED_PER_CPU_PAGE_FIRST_CHUNK */

	if (rc < 0)
		panic("Failed to initialized percpu areas (err=%d).\n", rc);

	delta = (e2k_addr_t)pcpu_base_addr - (e2k_addr_t)__per_cpu_start;
	for_each_possible_cpu(cpu)
		__per_cpu_offset[cpu] = delta + pcpu_unit_offsets[cpu];

# ifdef CONFIG_L_LOCAL_APIC
	/* alrighty, percpu areas up and running */
	for_each_possible_cpu(cpu)
		per_cpu(cpu_to_picid, cpu) = early_per_cpu_map(cpu_to_picid, cpu);

	/* indicate the early static arrays will soon be gone */
	early_per_cpu_ptr(cpu_to_picid) = NULL;
# endif
}
#endif	/* CONFIG_SMP && CONFIG_HAVE_SETUP_PER_CPU_AREA */

void thread_init(void)
{
	thread_info_t *ti = current_thread_info();
	struct pt_regs *regs = (void *) current->stack + KERNEL_C_STACK_OFFSET +
					KERNEL_C_STACK_SIZE - KERNEL_PT_REGS_SIZE;

	kernel_trap_mask_init();

	/* Arch-indep. part expects pt_regs to be always present.  Prepare
	 * them for kernel threads too and initialize with some sane values. */
	BUG_ON((unsigned long) regs <= (unsigned long) &ti);
	memset(regs, 0, sizeof(*regs));
	SAVE_STACK_REGS(regs, current_thread_info(), false, false);
	regs->stacks.usd_lo = READ_USD_LO_REG();
	regs->stacks.usd_hi = READ_USD_HI_REG();
	regs->stacks.top = (unsigned long) regs;
	ti->pt_regs = regs;
	DebugP("kernel stack: bottom %llx pt_regs %px\n",
		(u64)current->stack, ti->pt_regs);

	ti->k_usd_hi = NATIVE_NV_READ_USD_HI_REG();
	ti->k_usd_lo = NATIVE_NV_READ_USD_LO_REG();
	ti->k_psp_lo = NATIVE_NV_READ_PSP_LO_REG();
	ti->k_psp_hi = NATIVE_NV_READ_PSP_HI_REG();
	ti->k_pcsp_lo = NATIVE_NV_READ_PCSP_LO_REG();
	ti->k_pcsp_hi = NATIVE_NV_READ_PCSP_HI_REG();

	DebugP("k_usd_lo.base %llx\nk_psp_lo.base %llx\nk_pcsp_lo.base %llx\n",
			AS(ti->k_usd_lo).base, AS(ti->k_psp_lo).base,
			AS(ti->k_pcsp_lo).base);

	/* it needs only for guest booting threads */
	virt_cpu_thread_init(current);

	DebugP("thread_init exited.\n");
}

int __init
parse_bootinfo(void)
{
	boot_info_t	*bootblock = &bootblock_virt->info;

	if (bootblock->signature == BOOTBLOCK_BOOT_SIGNATURE ||
			bootblock->signature == BOOTBLOCK_ROMLOADER_SIGNATURE ||
			bootblock->signature == BOOTBLOCK_KVM_GUEST_SIGNATURE) {
		if (!strncmp(bootblock->kernel_args_string,
				KERNEL_ARGS_STRING_EX_SIGNATURE,
				KERNEL_ARGS_STRING_EX_SIGN_SIZE))
			/* Extended command line (512 bytes) */
			strncpy(boot_command_line,
				bootblock->bios.kernel_args_string_ex,
				KSTRMAX_SIZE_EX);
		else
			/* Standart command line (128 bytes) */
			strncpy(boot_command_line,
				bootblock->kernel_args_string,
				KSTRMAX_SIZE);

		machine_serial_num = bootblock->mach_serialn;

#ifdef CONFIG_BLK_DEV_INITRD
		if (bootblock->ramdisk_size) {
			initrd_start = vpa_to_pa(init_initrd_phys_base);
			initrd_end = initrd_start + init_initrd_size;
		} else {
			initrd_start = initrd_end = 0;
		}
#endif /* CONFIG_BLK_DEV_INITRD */

		/* Workaround against misfortunate 80x30 vmode BOOT leftover  */
		if (bootblock->vga_mode == 0xe2) {
			screen_info.orig_y = 30;
			screen_info.orig_video_lines = 30;
		};
		if (bootblock->mach_flags & MSI_MACH_FLAG) {
			pr_info("MSI supported\n");
		} else {
			pr_info("MSI disabled\n");
			e2k_msi_disabled = 1;
		}
	} else {
		return -1;
	} 
	return 0;
}


notrace void cpu_set_feature(struct machdep *machine, int feature)
{
	set_bit(feature, machine->cpu_features);
}

notrace void cpu_clear_feature(struct machdep *machine, int feature)
{
	clear_bit(feature, machine->cpu_features);
}

static int __init check_hwbug_iommu(void)
{
	int node;

	if (!cpu_has(CPU_HWBUG_IOMMU))
		return 0;

	if (num_online_nodes() <= 1)
		cpu_clear_feature(&machine, CPU_HWBUG_IOMMU);

	for_each_online_node(node) {
		e2k_sic_sccfg_struct_t	sccfg;

		sccfg.E2K_SIC_SCCFG_reg =
				sic_read_node_nbsr_reg(node, SIC_sccfg);
		if (!sccfg.E2K_SIC_SCCFG_diren) {
			return 0;
		}

	}

	cpu_clear_feature(&machine, CPU_HWBUG_IOMMU);

	return 0;
}
arch_initcall(check_hwbug_iommu);

extern void (*late_time_init)(void);

static void __init e2k_late_time_init(void)
{
#ifdef	CONFIG_SOFTWARE_SWAP_TAGS
	swap_info_cache_init();
#endif	/* CONFIG_SOFTWARE_SWAP_TAGS */

	/*
	 * Now that the external timer is enabled we can
	 * set up the local PIC timer on boot CPU.
	 *
	 * Since setup_boot_pic_clock() will enable interrupts
	 * it should not be called from time_init().
	 */
	setup_boot_pic_clock();
}

void __init e2k_start_kernel_switched_stacks(void)
{
	/*
	 * Set pointer of current task structure to kernel initial task
	 */
	setup_bsp_idle_task(0);

#ifdef	CONFIG_SMP
	current->cpu = 0;
	E2K_SET_DGREG_NV(SMP_CPU_ID_GREG, 0);
#endif

	/*
	 * to save initial state of debugging registers to enable
	 * hardware breakpoints
	 */
	/* FIXME: debug registers is privileged */
	if (!paravirt_enabled())
		native_save_user_only_regs(&current->thread.sw_regs);

	/*
	 * All kernel threads share the same mm context.
	 */
	mmgrab(&init_mm);
	current->active_mm = &init_mm;
	BUG_ON(current->mm);

	E2K_JUMP(start_kernel);
}

void __init e2k_start_kernel()
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

static void __init parse_cmd_line(char **cmdline_p)
{
	char c = ' ', *to = command_line, *from = boot_command_line;
	int len = 0;

	for (;;) {
		if (c != ' ')
			goto next_char;
		if (!memcmp(from, "iolinks=", 8)) {
			from += 8;
			max_iolinks = simple_strtol(from, &from, 0);
		}
		if (!memcmp(from, "nodeiolinks=", 12)) {
			from += 12;
			max_node_iolinks = simple_strtol(from, &from, 0);
		}
next_char:
		c = *(from++);
		if (!c)
			break;
		if (COMMAND_LINE_SIZE <= ++len)
			break;
		*(to++) = c;
	}
	*to = '\0';
	*cmdline_p = command_line;
	strlcpy(boot_command_line, command_line, COMMAND_LINE_SIZE);
	pr_notice("Full kernel command line: %s\n", saved_boot_cmdline);
}

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
	init_task.signal->bin_comp_rlim[BC_RLIMIT_X86_STACK].rlim_cur = _STK_LIM;
	init_task.signal->bin_comp_rlim[BC_RLIMIT_X86_STACK].rlim_max = RLIM_INFINITY;
	init_task.signal->bin_comp_rlim[BC_RLIMIT_X86_AS].rlim_cur = RLIM_INFINITY;
	init_task.signal->bin_comp_rlim[BC_RLIMIT_X86_AS].rlim_max = RLIM_INFINITY;
#endif
}

void __init setup_arch(char **cmdline_p)
{
	phys_addr_t kernel_phys_base;
	extern int panic_timeout;
	int cpu;

	arch_setup_machine();

	/*
	 * This should be as early as possible to fill cpu_present_mask and
	 * cpu_possible_mask.
	 */
#ifdef CONFIG_L_LOCAL_APIC
	/*
	 * Find (but now set) boot-time smp configuration.
	 * Like in i386 arch. used MP Floating Pointer Structure.
	 */
	find_smp_config(&bootblock_virt->info);

	/*
	 * Set entries of MP Configuration tables (but now one processor
	 * system)
	 */
	get_smp_config();
#endif

	kernel_phys_base = pgd_kernel_address_to_phys(
			&swapper_pg_dir[pgd_index(KERNEL_BASE)], KERNEL_BASE);
	kernel_voffset = KERNEL_BASE - kernel_phys_base;
	numa_init();

#ifdef CONFIG_SMP
	nmi_call_function_init();
#endif

	parse_bootinfo();
	parse_cmd_line(cmdline_p);


	/* reboot on panic */
	panic_timeout = 30;	/* 30 seconds of black screen of death */

	parse_early_param();
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
	pr_info("Kernel loaded at phys. address 0x%llx\n", kernel_phys_base);

	if (machine.setup_arch)
		machine.setup_arch();

	paravirt_banner();

	BOOT_TRACEPOINT("Calling paging_init()");
	paging_init();
	BOOT_TRACEPOINT("paging_init() finished");

	apply_alternative_instructions();

#ifdef CONFIG_OF
	device_tree_init();
#endif
	/* Must be called after paging_init() & device_tree_init() */
	l_setup_vga();

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

#ifdef CONFIG_L_LOCAL_APIC
	init_pic_mappings();

	if (num_possible_cpus() != mp_num_processors) {
		pr_alert(
			"********************************************************\n"
			"*                                                      *\n"
			"* WARNING: Only %d from %d cpus were described by BOOT *\n"
			"* in MP configuration table! OS is unreliable!         *\n"
			"*                                                      *\n"
			"********************************************************\n",
			mp_num_processors, num_possible_cpus());
	}

	/* need to wait for io_apic is mapped */
	probe_nr_irqs_gsi();
#endif

	arch_clock_setup();

#ifdef CONFIG_NET
	extern int e1000;
	e1000 = 1;
#endif

	late_time_init = e2k_late_time_init;

	rlim_init();
}

void __init init_IRQ(void)
{
	BUG_ON(irq_init_percpu_irqstack(smp_processor_id()));
	machine.init_IRQ();
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
	while (*pos < NR_CPUS && !cpumask_test_cpu(*pos, cpu_online_mask))
		++*pos;

	return *pos < NR_CPUS ? &cpu_data[*pos] : NULL;
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

struct seq_operations cpuinfo_op = {
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

void 
init_bug(const char *fmt_v, ...)
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

void
init_warning(const char *fmt_v, ...)
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
			    struct device_attribute *attr,
			    char *buf)
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
				struct device_attribute *attr,
				char *buf)
{
	u64 cu_hw0 = NATIVE_READ_CU_HW0_REG_VALUE();

	return sprintf(buf, "0x%llx\n", cu_hw0);
}

static ssize_t cu_hw0_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	unsigned long flags;
	u64 cu_hw0;

	if (kstrtoull(buf, 0, &cu_hw0) < 0)
		return -EINVAL;

	raw_all_irq_save(flags);
	NATIVE_WRITE_CU_HW0_REG_VALUE(cu_hw0);
	raw_all_irq_restore(flags);

	return count;
}

static DEVICE_ATTR_RW(cu_hw0);

/*
 * Allow CU_HW1 setting under /sys/devices/system/cpu/e2k/cu_hw1
 */

static ssize_t cu_hw1_show(struct device *dev,
				struct device_attribute *attr,
				char *buf)
{
	u64 cu_hw1 = machine.get_cu_hw1();

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
	machine.set_cu_hw1(cu_hw1);
	raw_all_irq_restore(flags);

	return count;
}

static DEVICE_ATTR_RW(cu_hw1);

/*
 * Allow L2_CTRL_EXT setting under /sys/devices/system/cpu/e2k/l2_ctrl_ext
 */
static ssize_t l2_ctrl_ext_show(struct device *dev,
			    struct device_attribute *attr,
			    char *buf)
{
	return sprintf(buf, "0x%lx\n",
			 read_DCACHE_L2_reg(_E2K_DCACHE_L2_CTRL_EXT_REG, 0));
}

static ssize_t l2_ctrl_ext_store(struct device *dev,
			     struct device_attribute *attr,
			     const char *buf, size_t count)
{
	unsigned long flags;
	u64 l2_ctrl_ext;

	if (kstrtoull(buf, 0, &l2_ctrl_ext) < 0)
		return -EINVAL;

	raw_all_irq_save(flags);
	write_DCACHE_L2_reg(l2_ctrl_ext, _E2K_DCACHE_L2_CTRL_EXT_REG, 0);
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
