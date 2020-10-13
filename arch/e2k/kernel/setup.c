/*  $Id: setup.c,v 1.79 2009/12/28 16:08:15 atic Exp $
 *
 * Architecture-specific setup.
 *
 * Copyright 2001 Salavat S. Guiliazov (atic@mcst.ru)
 */

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
#include <linux/bootmem.h>
#include <linux/root_dev.h>
#include <linux/screen_info.h>
#include <linux/utsname.h>
#include <linux/timex.h>
#include <linux/kthread.h>

#include <asm/console.h>
#include <asm/cpu.h>
#include <asm/machdep.h>
#include <asm/system.h>
#include <asm/e2k.h>
#include <asm/e3m.h>
#include <asm/lms.h>
#include <asm/e3m_iohub.h>
#include <asm/e3m_iohub_lms.h>
#include <asm/e3s.h>
#include <asm/e3s_lms.h>
#include <asm/e2k_sic.h>
#include <asm/mmu_context.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/head.h>
#include <asm/boot_head.h>
#include <asm/boot_init.h>
#include <asm/machdep.h>
#include <asm/process.h>
#include <asm/bootinfo.h>
#include <asm/mpspec.h>
#include <asm/setup.h>
#include <asm/timer.h>
#include <asm/time.h>
#include <asm/boot_param.h>
#include <asm/sic_regs.h>
#ifdef CONFIG_SOFTWARE_SWAP_TAGS
#include <asm/tag_mem.h>
#endif
#include <asm/e2k_debug.h>
#ifdef CONFIG_MCST_RT
#include <asm/i8253.h>
#endif

#include <asm-l/l_timer.h>
#include <asm-l/i2c-spi.h>
#include <asm-l/smp.h>

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

#undef	DEBUG_SPRs_MODE
#define	DEBUG_SPRs_MODE		0	/* stack pointers registers */

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

#define MACH_TYPE_NAME_E3M		0
#define MACH_TYPE_NAME_E3S		1
#define MACH_TYPE_NAME_ES2_DSP		2
#define MACH_TYPE_NAME_ES2_RU		3
#define MACH_TYPE_NAME_E2S		4
#define MACH_TYPE_NAME_E3M_IOHUB	5
#define MACH_TYPE_NAME_E8C		6
#define MACH_TYPE_NAME_E1CP		7
#define MACH_TYPE_NAME_E8C2		8
#define MACH_TYPE_NAME_UNKNOWN		9

/*
 * Machine type names.
 * Machine name can be retrieved from /proc/cpuinfo as model name.
 */
static char *cpu_type_name[] = {
	"e3m",
	"e3s",
	"e2c+",
	"e2c",
	"e2s",
	"e3m",
	"e8c",
	"e1c+",
	"e8c2",
	"unknown"
};
static char *mach_type_name[] = {
	"Elbrus-e2k-e3m",
	"Elbrus-e2k-e3s",
	"Elbrus-e2k-e2c+",
	"Elbrus-e2k-e2c",
	"Elbrus-e2k-e2s",
	"Elbrus-e2k-e3m-iohub",
	"Elbrus-e2k-e8c",
	"Elbrus-e2k-e1c+",
	"Elbrus-e2k-e8c2",
	"unknown"
};

/*
 * mach_type_id variable is set in setup_arch() function.
 */
static int mach_type_id = MACH_TYPE_NAME_UNKNOWN;

/*
 * Function to get name of machine type.
 * Must be used after setup_arch().
 */
char *get_cpu_type_name(void)
{
	return cpu_type_name[mach_type_id];
}
char *get_mach_type_name(void)
{
	return mach_type_name[mach_type_id];
}
static void set_mach_type_id(void)
{
	switch(machine.virt_id)
	{
		case MACHINE_ID_E3M_LMS:
		case MACHINE_ID_E3M:
		case MACHINE_ID_VIRT_E3M:
			if (HAS_MACHINE_E2K_IOHUB)
				mach_type_id = MACH_TYPE_NAME_E3M_IOHUB;
			else
				mach_type_id = MACH_TYPE_NAME_E3M;
			break;
		case MACHINE_ID_E3M_IOHUB_LMS:
		case MACHINE_ID_E3M_IOHUB:
			mach_type_id = MACH_TYPE_NAME_E3M_IOHUB;
			break;
		case MACHINE_ID_E3S_LMS:
		case MACHINE_ID_E3S:
		case MACHINE_ID_VIRT_E3S:
			mach_type_id = MACH_TYPE_NAME_E3S;
			break;
		case MACHINE_ID_ES2_DSP_LMS:
		case MACHINE_ID_ES2_DSP:
		case MACHINE_ID_VIRT_ES2_DSP:
			mach_type_id = MACH_TYPE_NAME_ES2_DSP;
			break;
		case MACHINE_ID_ES2_RU_LMS:
		case MACHINE_ID_ES2_RU:
		case MACHINE_ID_VIRT_ES2_RU:
			mach_type_id = MACH_TYPE_NAME_ES2_RU;
			break;
		case MACHINE_ID_E2S_LMS:
		case MACHINE_ID_E2S:
		case MACHINE_ID_VIRT_E2S:
			mach_type_id = MACH_TYPE_NAME_E2S;
			break;
		case MACHINE_ID_E8C_LMS:
		case MACHINE_ID_E8C:
		case MACHINE_ID_VIRT_E8C:
			mach_type_id = MACH_TYPE_NAME_E8C;
			break;
		case MACHINE_ID_E1CP_LMS:
		case MACHINE_ID_E1CP:
		case MACHINE_ID_VIRT_E1CP:
			mach_type_id = MACH_TYPE_NAME_E1CP;
			break;
		case MACHINE_ID_E8C2_LMS:
		case MACHINE_ID_E8C2:
		case MACHINE_ID_VIRT_E8C2:
			mach_type_id = MACH_TYPE_NAME_E8C2;
			break;

		default:
			panic("setup_arch(): !!! UNKNOWN MACHINE TYPE !!!");
			machine.setup_arch = NULL;
			break;
	}
}

/*
 * Warning: only emulation e3s CPUs on e2c+ based machines is now implemented
 */
int is_virt_cpu_enabled(int cpuid)
{
	int node;
	int first_node_cpu;

	if (!HAS_MACHINE_VIRT_CPU)
		return 1;
	node = cpu_to_node(cpuid);
	first_node_cpu = node_to_first_present_cpu(node);
	if (IS_MACHINE_ES2 && IS_MACHINE_VIRT_E3S &&
					(cpuid != first_node_cpu))
		return 0;
	return 1;
}

static void print_machine_type_info(void)
{
	char *cpu_type = "?????????????";

	cpu_type = get_cpu_type_name();
	printk("MACHINE TYPE: %s %s %s %s, ID %04x, REVISION: %03x",
		cpu_type,
		(HAS_MACHINE_E2K_DSP) ? "DSP" : "",
		(HAS_MACHINE_E2K_IOHUB) ? "IOHUB" : "",
		(IS_MACHINE_SIM) ? "LMS" : "",
		machine.id, machine.rev);
}

int cards = 0;
EXPORT_SYMBOL(cards);

#define STANDARD_IO_RESOURCES (sizeof(standard_io_resources)/sizeof(struct resource))

struct screen_info screen_info = {
	.orig_x = 0,
	.orig_y = 25,
	.orig_video_page = 0,
	.orig_video_mode = 0,
	.orig_video_cols = 80,
	.orig_video_lines = 25,
	.orig_video_isVGA = 1,
	.orig_video_points = 16
};
EXPORT_SYMBOL(screen_info);

machdep_t __nodedata	machine = { 0 };
EXPORT_SYMBOL(machine);
#ifdef	CONFIG_E2K_MACHINE
//	machine_id;		is define in asm/e2k.h
//	virt_machine_id;	is define in asm/e2k.h
#else	/* ! CONFIG_E2K_MACHINE */
int __nodedata	machine_id = -1;
EXPORT_SYMBOL(machine_id);
int virt_machine_id = -1;
#endif	/* ! CONFIG_E2K_MACHINE */

unsigned long	machine_serial_num = -1UL;
static int __init machine_serial_num_setup(char *str)
{
	if (get_option(&str, (int *) &machine_serial_num))
	{
		l_base_mac_addr[3] = (machine_serial_num >> 8) & 0xff;
		l_base_mac_addr[4] = machine_serial_num & 0xff;
		printk("machine_serial_num_setup: "
			"New serial number is %lx\n"
			"Base ip addr for sunlance: %pM\n",
			machine_serial_num, l_base_mac_addr);
	}
	return 1;
}
__setup("mach_serialn=", machine_serial_num_setup);
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

extern void paging_init(void);

#if defined (CONFIG_SMP) && defined (CONFIG_HAVE_SETUP_PER_CPU_AREA)
unsigned long __nodedata __per_cpu_offset[NR_CPUS];
EXPORT_SYMBOL(__per_cpu_offset);

# ifdef CONFIG_NEED_PER_CPU_EMBED_FIRST_CHUNK
#  ifdef CONFIG_NUMA
static int __init pcpu_cpu_distance(unsigned int from, unsigned int to)
{
	int distance = REMOTE_DISTANCE;
	if (cpu_to_node(from) == cpu_to_node(to))
		distance = LOCAL_DISTANCE;
	return distance;
}
#  endif /* CONFIG_NUMA */

static __init void *pcpu_alloc_bootmem(unsigned int cpu, size_t size,
					    size_t align)
{
	e2k_addr_t goal = __pa(MAX_DMA_ADDRESS);
#  ifdef CONFIG_NUMA
	int node = cpu_to_node(cpu);
	void *ptr;

	if (node_online(node) && NODE_DATA(node) && NODE_DATA(node)->bdata) {
		ptr = __alloc_bootmem_node(NODE_DATA(node), size, align, goal);
		DebugPC("per cpu data for cpu%d %lu "
			"bytes on node%d at 0x%lx.\n",
			cpu, size, node, __pa(ptr));
	}
	else {
		ptr = __alloc_bootmem(size, align, goal);
		DebugPC("cpu%d has no node%d or "
			"node-local memory.\n", cpu, node);
		DebugPC("per cpu data for cpu%d %lu "
			"bytes at 0x%lx.\n", cpu, size, __pa(ptr));
	}
	return ptr;
#  else /* !CONFIG_NUMA */
	return __alloc_bootmem(size, align, goal);
#  endif /* CONFIG_NUMA */
}

static void __init pcpu_free_bootmem(void *ptr, size_t size)
{
        free_bootmem(__pa(ptr), size);
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
		pmd_t *new;

		new = __alloc_bootmem(PAGE_SIZE, PAGE_SIZE, PAGE_SIZE);
		pud_populate(&init_mm, pud, new);
	}

	pmd = pmd_offset(pud, addr);
	if (!pmd_present(*pmd)) {
		pte_t *new;

		new = __alloc_bootmem(PAGE_SIZE, PAGE_SIZE, PAGE_SIZE);
		pmd_populate_kernel(&init_mm, pmd, new);
	}
}
# endif /* CONFIG_NEED_PER_CPU_PAGE_FIRST_CHUNK */

void __init setup_per_cpu_areas(void)
{
	e2k_addr_t delta;
	unsigned int cpu;
# ifdef CONFIG_NUMA
	int node;
# endif /* CONFIG_NUMA */
	int rc = -EINVAL;

# ifdef CONFIG_NEED_PER_CPU_EMBED_FIRST_CHUNK
	if (pcpu_chosen_fc != PCPU_FC_PAGE) {
		rc = pcpu_embed_first_chunk(PERCPU_MODULE_RESERVE,
					    PERCPU_DYNAMIC_RESERVE,
					    PAGE_SIZE,
				    #ifdef CONFIG_NUMA
					    pcpu_cpu_distance,
				    #else   /* !CONFIG_NUMA */
					    NULL,
				    #endif  /* CONFIG_NUMA */
					    pcpu_alloc_bootmem,
					    pcpu_free_bootmem);
		if (rc)
			DebugPC("embed allocator failed "
				"(%d), falling back to page size.\n", rc);
	}
# endif /* CONFIG_NEED_PER_CPU_EMBED_FIRST_CHUNK */

# ifdef CONFIG_NEED_PER_CPU_PAGE_FIRST_CHUNK
        if (rc < 0) {
		rc = pcpu_page_first_chunk(PERCPU_MODULE_RESERVE,
					pcpu_alloc_bootmem,
					pcpu_free_bootmem,
					pcpu_populate_pte);
		if (rc)
			DebugPC("page allocator failed "
				"(%d).\n", rc);
	}
# endif /* CONFIG_NEED_PER_CPU_PAGE_FIRST_CHUNK */

	if (rc < 0)
		panic("Failed to initialized percpu areas (err=%d).\n", rc);

	delta = (e2k_addr_t)pcpu_base_addr - (e2k_addr_t)__per_cpu_start;
	for_each_possible_cpu(cpu)
		__per_cpu_offset[cpu] = delta + pcpu_unit_offsets[cpu];

# ifdef CONFIG_NUMA
	for_each_node_has_dup_kernel(node) {
		void *per_cpu_offset = __va(node_kernel_va_to_pa(node,
				__per_cpu_offset));
		memcpy(per_cpu_offset, __per_cpu_offset, 
			sizeof(__per_cpu_offset));
	}
# endif /* CONFIG_NUMA */

	/* alrighty, percpu areas up and running */
	for_each_possible_cpu(cpu) {
# ifdef CONFIG_L_LOCAL_APIC
		per_cpu(x86_cpu_to_apicid, cpu) =
			early_per_cpu_map(x86_cpu_to_apicid, cpu);
		per_cpu(x86_bios_cpu_apicid, cpu) =
			early_per_cpu_map(x86_bios_cpu_apicid, cpu);
# endif
	}

	/* Set per_cpu area pointer */
	set_my_cpu_offset(__per_cpu_offset[smp_processor_id()]);

	/* indicate the early static arrays will soon be gone */
#ifdef CONFIG_L_LOCAL_APIC
	early_per_cpu_ptr(x86_cpu_to_apicid) = NULL;
	early_per_cpu_ptr(x86_bios_cpu_apicid) = NULL;
#endif
}
#endif	/* CONFIG_SMP && CONFIG_HAVE_SETUP_PER_CPU_AREA */

struct hw_stack_area	u_ps_init[NR_CPUS];
struct hw_stack_area	u_pcs_init[NR_CPUS];

void __init_recv
thread_init(void)
{
	register volatile struct thread_struct *p;
	register thread_info_t *ti;
	register struct hw_stack_area *u_ps;
	register struct hw_stack_area *u_pcs;

	DebugP("thread_init entered for task 0x%p\n", current);
	ti = current_thread_info();
	p = &(current->thread);
	p->context = E2K_KERNEL_CONTEXT;
	/*
	 * READ_SBR_REG(); doesnt work right because low 32 bits == 0
	 * But we work here on the first stack and can use sbr reg here
	 */

	ti->k_stk_base = kernel_init_stack_virt_base(smp_processor_id());
	ti->k_stk_sz = kernel_init_stack_size(smp_processor_id());

	/* 
	 * Dont worry about p->k_stk_base - sizeof(pt_regs_t).
	 * In the ttable_entry() we will do first:
	 * pt_regs + sizeof(pt_regs_t);
	 */
	ti->pt_regs = NULL;
	DebugP("k_stk_base %lx pt_regs %p\n",
			ti->k_stk_base, ti->pt_regs);
	
	ti->k_usd_hi = READ_USD_HI_REG();
	ti->k_usd_lo = READ_USD_LO_REG();

	if (UHWS_PSEUDO_MODE) {
		u_ps = &u_ps_init[smp_processor_id()];
		list_add_tail(&u_ps->list_entry, &ti->ps_list);
		ti->cur_ps = u_ps;

		u_pcs = &u_pcs_init[smp_processor_id()];
		list_add_tail(&u_pcs->list_entry, &ti->pcs_list);
		ti->cur_pcs = u_pcs;
	}

	SET_PS_BASE(ti, (void *)READ_PSP_LO_REG().PSP_lo_base);
	SET_PS_SIZE(ti, KERNEL_P_STACK_SIZE);
	SET_PS_OFFSET(ti, 0);
	SET_PS_TOP(ti, KERNEL_P_STACK_SIZE);

	SET_PCS_BASE(ti, (void *)READ_PCSP_LO_REG().PCSP_lo_base);
	SET_PCS_SIZE(ti, KERNEL_PC_STACK_SIZE);
	SET_PCS_OFFSET(ti, 0);
	SET_PCS_TOP(ti, KERNEL_PC_STACK_SIZE);

	DebugP("k_stk_base: %lx\n", ti->k_stk_base);
	DebugP("k_usd_lo.base %lx\n", AS_STRUCT(ti->k_usd_lo).base);
	DebugP("k_psp_lo.base %lx\n", READ_PSP_LO_REG().PSP_lo_base);
	DebugP("k_pcsp_lo.base %lx\n", READ_PCSP_LO_REG().PCSP_lo_base);
	DebugP("thread_init exited.\n");
}

int __init
parse_bootinfo(void)
{
	boot_info_t	*bootblock = &bootblock_virt->info;

	if (bootblock->signature == X86BOOT_SIGNATURE ||
		bootblock->signature == ROMLOADER_SIGNATURE) {
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
#ifdef	CONFIG_E2K_MACHINE
#if defined(CONFIG_E2K_E3M_SIM)
		e3m_lms_setup_arch();
#elif defined(CONFIG_E2K_E3M)
		e3m_setup_arch();
#elif defined(CONFIG_E2K_E3M_IOHUB_SIM)
		e3m_iohub_lms_setup_machine();
#elif defined(CONFIG_E2K_E3M_IOHUB)
		e3m_iohub_setup_machine();
#elif defined(CONFIG_E2K_E3S_SIM)
		e3s_lms_setup_machine();
#elif defined(CONFIG_E2K_E3S)
		e3s_setup_machine();
#elif defined(CONFIG_E2K_ES2_DSP_SIM) || defined(CONFIG_E2K_ES2_RU_SIM)
		es2_lms_setup_machine();
#elif defined(CONFIG_E2K_ES2_DSP) || defined(CONFIG_E2K_ES2_RU)
		es2_setup_machine();
#elif defined(CONFIG_E2K_E2S_SIM)
		e2s_lms_setup_machine();
#elif defined(CONFIG_E2K_E2S)
		e2s_setup_machine();
#elif defined(CONFIG_E2K_E8C_SIM)
		e8c_lms_setup_machine();
#elif defined(CONFIG_E2K_E8C)
		e8c_setup_machine();
#elif defined(CONFIG_E2K_E1CP_SIM)
		e1cp_lms_setup_machine();
#elif defined(CONFIG_E2K_E1CP)
		e1cp_setup_machine();
#elif defined(CONFIG_E2K_E8C2_SIM)
		e8c2_lms_setup_machine();
#elif defined(CONFIG_E2K_E8C2)
		e8c2_setup_machine();
#else
#    error "E2K MACHINE type does not defined"
#endif
#else	/* ! CONFIG_E2K_MACHINE */
		e2k_setup_machine();
#endif /* CONFIG_E2K_MACHINE */

		machine_serial_num = bootblock->mach_serialn;

#ifdef CONFIG_BLK_DEV_INITRD
		if (bootblock->ramdisk_size) {
			initrd_start =  bootblock->ramdisk_base;
			initrd_end   =	bootblock->ramdisk_base + 
					bootblock->ramdisk_size;
		} else {
			initrd_start = initrd_end = 0;
		}
#endif /* CONFIG_BLK_DEV_INITRD */

		/* Workaround against misfortunate 80x30 vmode BOOT leftover  */
		if (bootblock->vga_mode == 0xe2) {
			screen_info.orig_y = 30;
			screen_info.orig_video_lines= 30;	
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

notrace __init
void setup_cpu_features(struct machdep *machine)
{
	int cpu = machine->id & MACHINE_ID_CPU_TYPE_MASK,
			revision = machine->rev;

	if (cpu == IDR_E3M_MDL)
		cpu_set_feature(machine, CPU_FEAT_ASYNC_FLUSH);

	if (cpu != IDR_E3S_MDL && cpu != IDR_ES2_DSP_MDL &&
			cpu != IDR_ES2_RU_MDL ||
			revision != 0)
		cpu_set_feature(machine, CPU_FEAT_WC_PCI_PREFETCH);

	/* Most of these bugs are not emulated on simulator but
	 * set them anyway to make kernel running on a simulator
	 * behave in the same way as on real hardware. */

	if (cpu == IDR_E3M_MDL && revision < 3 ||
	    cpu == IDR_E3S_MDL && revision < 1)
		cpu_set_feature(machine, CPU_HWBUG_QUADRO_STRD);

	if (cpu == IDR_E3M_MDL || cpu == IDR_E3S_MDL ||
	    cpu == IDR_ES2_DSP_MDL && revision < 1)
		cpu_set_feature(machine, CPU_HWBUG_LARGE_PAGES);

	if (cpu == IDR_E3S_MDL || cpu == IDR_ES2_DSP_MDL ||
	    cpu == IDR_ES2_RU_MDL)
		cpu_set_feature(machine, CPU_HWBUG_MC_SOFTRESET);

	if (cpu == IDR_E3S_MDL || cpu == IDR_ES2_DSP_MDL && revision < 1)
		cpu_set_feature(machine, CPU_HWBUG_LAPIC_TIMER);

	/* This workaround increases the count of DCACHE flushes.
	 * Turmalin has hardware bug with flushes so don't use
	 * this workaround on it. */
	if (cpu == IDR_ES2_DSP_MDL)
		cpu_set_feature(machine, CPU_HWBUG_ATOMIC);

	if (cpu == IDR_E2S_MDL)
		cpu_set_feature(machine, CPU_HWBUG_DIRCACHE_DISABLE);

	if (cpu == IDR_E3M_MDL ||
	    cpu == IDR_ES2_DSP_MDL && (revision <= 1 || revision == 6) ||
	    cpu == IDR_ES2_RU_MDL && revision <= 1 ||
	    cpu == IDR_E2S_MDL && revision == 0)
		cpu_set_feature(machine, CPU_HWBUG_CLW);

	if (cpu == IDR_E3M_MDL ||
	    cpu == IDR_ES2_DSP_MDL && (revision <= 1 || revision == 6) ||
	    cpu == IDR_ES2_RU_MDL && revision <= 1)
		cpu_set_feature(machine, CPU_HWBUG_PAGE_A);
}

static int __init check_hwbug_atomic(void)
{
	int node, cpu, nodes_num, cpus_num, node_with_many_cpus;
	cpumask_t node_cpus;

	if (!cpu_has(CPU_HWBUG_ATOMIC))
		return 0;

	/*
	 * Now that SMP has been initialized check again
	 * that this hardware bug can really happen.
	 *
	 * Conditions:
	 * 1. There must be more than 1 node present.
	 * 2. There must be a node with more than 1 cpu.
	 */

	node_with_many_cpus = false;
	nodes_num = 0;
	for_each_online_node(node) {
		++nodes_num;

		cpus_num = 0;
		for_each_cpu_of_node(node, cpu, node_cpus)
			++cpus_num;

		if (cpus_num > 1)
			node_with_many_cpus = true;
	}

	if (nodes_num > 1 && node_with_many_cpus)
		pr_alert("NOTE: workaround for hardware bug in atomics is enabled\n");
	else
		cpu_clear_feature(&machine, CPU_HWBUG_ATOMIC);

	return 0;
}
arch_initcall(check_hwbug_atomic);

extern void (*late_time_init)(void);

void __init
e2k_late_time_init(void)
{
#ifdef	CONFIG_SOFTWARE_SWAP_TAGS
	swap_info_cache_init();
#endif	/* CONFIG_SOFTWARE_SWAP_TAGS */

	if (HAS_MACHINE_L_SIC) {
		int ret = e2k_sic_init();
		if (ret != 0) {
			panic("e2k_late_time_init() could not init access "
				"to SIC registers, error %d\n", ret);
		}
	}

	/*
	 * Now that the external timer is enabled we can
	 * set up the local APIC timer on boot CPU.
	 *
	 * Since setup_boot_APIC_clock() will enable interrupts
	 * it should not be called from time_init().
	 */
	setup_boot_APIC_clock();
}

static int mcmonitor_enabled;

static int __init mcmonitor_setup(char *str)
{
	if (HAS_MACHINE_L_SIC)
		mcmonitor_enabled = 1;
	return 1;
}
__setup("mcmonitor", mcmonitor_setup);

static int mcmonitord(void *unused)
{
	u16 last_MC_ECC[MAX_NUMNODES][SIC_MAX_MC_COUNT];

	memset(last_MC_ECC, 0, sizeof(u16) * MAX_NUMNODES * SIC_MAX_MC_COUNT);

	while (!kthread_should_stop()) {
		int node;

		for_each_online_node(node) {
			int i;

			for (i = 0; i < SIC_MC_COUNT; i++) {
				e2k_mc_ecc_struct_t ecc;

				ecc.E2K_MC_ECC_reg = sic_get_mc_ecc(node, i);

				if (ecc.E2K_MC_ECC_secnt -
						last_MC_ECC[node][i]) {
					last_MC_ECC[node][i] =
						ecc.E2K_MC_ECC_secnt;
					pr_warning("MC error DETECTED on "
						"node%d: MC%d_ECC=0x%x (ee=%d "
						"dmode=%d of=%d ue=%d "
						"secnt=%d)\n",
						node, i,
						ecc.E2K_MC_ECC_reg,
						ecc.E2K_MC_ECC_ee,
						ecc.E2K_MC_ECC_dmode,
						ecc.E2K_MC_ECC_of,
						ecc.E2K_MC_ECC_ue,
						ecc.E2K_MC_ECC_secnt);
				}
			}
		}

		msleep_interruptible(MSEC_PER_SEC);
	}

	return 0;
}

static int __init mcmonitor_init(void)
{
	if (mcmonitor_enabled) {
		if (IS_ERR(kthread_run(mcmonitord, NULL, "mcmonitord")))
			pr_err("Failed to start mcmonitord daemon\n");
		else
			pr_notice("mcmonitord daemon started\n");
	}
	return 0;
}
arch_initcall(mcmonitor_init);

void __init
setup_arch(char **cmdline_p)
{
	int i;
	extern int panic_timeout;
	char c = ' ', *to = command_line, *from = boot_command_line;
	int len = 0;

	DebugSPRs("setup_arch()");

	parse_bootinfo();
	l_setup_arch();
	register_early_dump_console();

	/*
	 * Now we have only one machine based on e2c+ (cubic) CPU chip
	 * It is prototype and this prototype contains two nodes whis
	 * two IO links on each/ so max_iolinks can be 4.
	 * But hardware IO link #1 does not work right now, so we limit
	 * max IO node links number by only one IO link on each node
	 */
	if (IS_MACHINE_ES2_HW && machine.rev < 1)
		max_node_iolinks = 1;

	for (;;) {
		if (c != ' ')
			goto next_char;
#ifdef CONFIG_SERIAL_PRINTK
		if (!memcmp(from, "boot_printk", 11)) {
			extern int use_boot_printk;
			use_boot_printk = 1;
		}
		if (!memcmp(from, "boot_printk_all", 15)) {
			extern int use_boot_printk_all;
			use_boot_printk_all = 1;
		}
		if (!memcmp(from, "print_kernel_threads", 20)) {
			extern int print_kernel_threads;
			print_kernel_threads = 1;
		}
#endif	/* CONFIG_SERIAL_PRINTK */
		if (!memcmp(from, "print_window_regs", 17)) {
			extern int print_window_regs;
			print_window_regs = 1;
		}
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

	/* reboot on panic */
	panic_timeout = 30;	/* 30 seconds of black screen of death */

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
	
	if (machine_serial_num == -1UL || machine_serial_num == 0) {
		pr_notice(" SERIAL # UNKNOWN\n");
	} else {
		pr_notice(" SERIAL # 0x%016lx\n", machine_serial_num);
	}

	printk("Kernel image check sum: %u\n",
		bootblock_virt->info.kernel_csum);

	if (machine.setup_arch != NULL) {
		machine.setup_arch();
	}

	BOOT_TRACEPOINT("Calling paging_init()");
	paging_init();

	/* ACPI Tables are to be placed to phys addr in machine.setup_arch().
	 * acpi_boot_table_init() will parse the ACPI tables (if they are) for
	 * possible boot-time SMP configuration. If machine does not support
	 * ACPI, acpi_boot_table_init will disable it.
	 */
	acpi_boot_table_init();

	/* Parses MADT when ACPI is on. */
	early_acpi_boot_init();

	BOOT_TRACEPOINT("paging_init() finished");
	thread_init();

	/* request I/O space for devices used on all i[345]86 PCs */
	if (!HAS_MACHINE_E2K_IOHUB) {
		for (i = 0; i < STANDARD_IO_RESOURCES; i++)
			request_resource(&ioport_resource,
						standard_io_resources+i);
	}

#ifdef CONFIG_VT
#if defined(CONFIG_VGA_CONSOLE)
	conswitchp = &vga_con;
#elif defined(CONFIG_DUMMY_CONSOLE)
	conswitchp = &dummy_con;
#endif
#endif

#ifdef CONFIG_BLK_DEV_INITRD
	ROOT_DEV = MKDEV(RAMDISK_MAJOR, 0);
#endif

	/*
	 * Read APIC and some other early information from ACPI tables.
	 */
	acpi_boot_init();

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

        init_apic_mappings();

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

	/* TODO 2.6.38: just call ioapic_and_gsi_init() here... */
#if 0
	ioapic_init_mappings();
#endif

	/* need to wait for io_apic is mapped */
	probe_nr_irqs_gsi();
#endif

	arch_clock_setup();

#ifdef CONFIG_NET
	if (HAS_MACHINE_E2K_IOHUB) {
		extern int e1000;
		e1000 = 1;
	}
#endif

	parse_early_param();

	late_time_init = e2k_late_time_init;
}

u64 lapic_calibration_result_ticks = 0;

/*
 * Called by both boot and secondary processors
 * to move global data into per-processor storage.
 */
__init_recv void store_cpu_info(int cpuid)
{
	cpuinfo_e2k_t *c = &cpu_data[cpuid];

#ifdef CONFIG_SMP
	c->cpu = cpuid;
#endif
	machine.setup_cpu_info(c);
	if (IS_BOOT_STRAP_CPU()) {
		/* For boot cpu first try to read
		 * the result of the LAPIC calibration */
		if (lapic_calibration_result_ticks)
			c->proc_freq = lapic_calibration_result_ticks;
		else
			c->proc_freq = measure_cpu_freq();

		cpu_freq_hz = c->proc_freq;
	} else {
		u64 freq = measure_cpu_freq();
		if (freq ==
			cpu_data[boot_cpu_physical_apicid].proc_freq
			||
			freq / abs(freq -
				cpu_data[boot_cpu_physical_apicid].proc_freq)
					> 100) {
			/* All processors work at the same frequency */
			c->proc_freq =
				cpu_data[boot_cpu_physical_apicid].proc_freq;
		} else {
			c->proc_freq = freq;
			pr_warning("Warning: CPU#%d frequency (%ld) "
				"differs from CPU0 frequency (%ld), "
				"sched_clock() may work with errors\n",
				cpuid, freq,
				cpu_data[boot_cpu_physical_apicid].proc_freq);
		}
	}
	c->pte_quick = NULL;
	c->pud_quick = NULL;
	c->pmd_quick = NULL;
	c->pgd_quick = NULL;
	c->pgtable_cache_sz = 0;

        /* It will works only under PROFILE flag */
        set_calibration_result(c->proc_freq/HZ);

#ifdef CONFIG_SMP
	c->loops_per_jiffy = loops_per_jiffy;
	c->mmu_last_context = CTX_FIRST_VERSION;
	c->prof_counter = 1;
	c->prof_multiplier = 1;
#endif

	printk("cpu_data[%d]:\n\tproc_freq %ld\n", cpuid, c->proc_freq);

#ifdef CONFIG_SMP
	printk("\tloops_per_jiffy == %lu\n", c->loops_per_jiffy);
#endif
}

/*
 * Print CPU information.
 */

void print_cpu_info(cpuinfo_e2k_t *cpu_data)
{
	print_machine_type_info();
	printk("\n");
}

static int __init boot_store_cpu_info()
{
	/* Final full version of the data */
	store_cpu_info(boot_cpu_physical_apicid);

	print_cpu_info(&cpu_data[boot_cpu_physical_apicid]);

	return 0;
}
early_initcall(boot_store_cpu_info);

static int
show_cpuinfo(struct seq_file *m, void *v)
{
	int rval = 0;

	if (machine.show_cpuinfo != NULL) {
		rval = machine.show_cpuinfo(m, v);
	}

	return rval;
}

/*
 * Late time architecture specific initialization.
 */


static void *
c_start (struct seq_file *m, loff_t *pos)
{
#ifdef CONFIG_SMP
	while (*pos < NR_CPUS && !cpu_isset(*pos, *cpu_online_mask))
		++*pos;
#endif
	return *pos < NR_CPUS ? &cpu_data[*pos] : NULL;
}

static void *
c_next (struct seq_file *m, void *v, loff_t *pos)
{
	++*pos;
	return c_start(m, pos);
}

static void
c_stop (struct seq_file *m, void *v)
{
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

