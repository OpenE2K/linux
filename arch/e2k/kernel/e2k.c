#include <linux/ptrace.h>
#include <linux/hardirq.h>
#include <linux/init.h>
#include <linux/irq.h>
#include <linux/delay.h>
#include <linux/seq_file.h>
#include <linux/smp.h>
#include <linux/utsname.h>
#include <linux/pci.h>
#include <asm/e2k_api.h>
#include <asm/e2k_debug.h>
#include <asm/boot_recovery.h>
#include <asm/e2k.h>
#include <asm/e2k_sic.h>
#include <asm/e3m_iohub.h>
#include <asm/e3m_iohub_lms.h>
#include <asm/e3s.h>
#include <asm/e3s_lms.h>
#include <asm/es2.h>
#include <asm/es2_lms.h>
#include <asm/e2s.h>
#include <asm/e2s_lms.h>
#include <asm/e8c.h>
#include <asm/e8c_lms.h>
#include <asm/e1cp.h>
#include <asm/e1cp_lms.h>
#include <asm/e8c2.h>
#include <asm/e8c2_lms.h>
#include <asm/byteorder.h>
#include <asm/machdep.h>
#include <asm/smp.h>
#include <asm/io.h>
#include <asm/apic.h>
#include <asm/iommu.h>

#include <asm-l/i2c-spi.h>

#ifdef CONFIG_PROTECTED_MODE
#include <asm/3p.h>
#endif /* CONFIG_PROTECTED_MODE */

#ifdef  CONFIG_RECOVERY
#include <asm/cnt_point.h>
#endif	/* CONFIG_RECOVERY */

#undef	DEBUG_IRQ_MODE
#undef	DebugIRQ
#define	DEBUG_IRQ_MODE		0	/* interrupts */
#define DebugIRQ(...)		DebugPrint(DEBUG_IRQ_MODE ,##__VA_ARGS__)

extern void e2k_safe_infinite_loop(void);
extern void e2k_do_safe_reset_machine(u64, u32);

extern	void	obsolete_i8259_init(void);
#ifdef	CONFIG_RECOVERY
extern	void	obsolete_i8259_recovery(void);
#endif	/* CONFIG_RECOVERY */

/*
 *	Get CPU information for use by the procfs.
 */

#define DBG_HANG 0
#if DBG_HANG
extern char *execute_command;
extern void coredump_in_future(void);
#endif

extern char *get_mach_type_name(void);

static int soft_reset_off = 0;

static int __init
disable_soft_reset(char *str)
{
	soft_reset_off = 1;
	return 1;
}
__setup("softresetoff", disable_soft_reset);

static int __init
enable_soft_reset(char *str)
{
	soft_reset_off = 0;
	return 1;
}
__setup("softreseton", enable_soft_reset);

static int __init
setup_soft_reset(char *str)
{
	if (strcmp(str, "on") == 0) {
		soft_reset_off = 0;
	} else if (strcmp(str, "off") == 0) {
		soft_reset_off = 1;
	} else {
		printk("SOFT RESET enable/disable is not changed and is %s\n",
			(soft_reset_off) ? "off" : "on");
	}
	return 1;
}
__setup("softreset=", setup_soft_reset);

int
e2k_show_cpuinfo(struct seq_file *m, void *v)
{
	struct cpuinfo_e2k *c = v;
	u8 cputype;

#ifdef CONFIG_SMP
#	define lpj	c->loops_per_jiffy
#	define cpunum	c->cpu
#else
#	define lpj	loops_per_jiffy
#	define cpunum	0
#endif

#ifdef CONFIG_SMP
	if (!cpu_online(cpunum))
		return 0;
#endif

	/*
	 * Boot is brain-dead and takes cpu_type from RAM, so one should use
	 * cpu_type from boot in borderline case only ("virtual" cpu).
	 */
	cputype = (HAS_MACHINE_VIRT_CPU) ?
			bootblock_virt->info.bios.cpu_type : c->model;

	seq_printf(m,
		"processor\t: %d\n"
		"vendor_id\t: %s\n"
		"cpu family\t: %d\n"
		"model\t\t: %d\n"
		"model name\t: %s\n"
		"revision\t: %u\n"
		"cpu MHz\t\t: %lu.%02lu\n"
		"L1 cache size\t: %d KB\n"
		"L1 cache line length\t: %d bytes\n"
		"L2 cache size\t: %d KB\n"
		"L2 cache line length\t: %d bytes\n",
		cpunum,
/*		c->vendor,	*/
		mcst_mb_name,
		c->family,
		c->model,
		GET_CPU_TYPE_NAME(cputype),
/*		get_mach_type_name(),	*/
		c->revision,
		c->proc_freq / 1000000, c->proc_freq % 1000000,
		c->L1_size,
		c->L1_bytes,
		c->L2_size,
		c->L2_bytes);
	if (c->L3_size) {
		seq_printf(m,
			"L3 cache size\t: %d KB\n"
			"L3 cache line length\t: %d bytes\n",
			c->L3_size,
			c->L3_bytes);
	}
	seq_printf(m,
		"bogomips\t: %lu.%02lu\n\n",
		lpj/(500000/HZ),
		(lpj/(5000/HZ)) % 100);

#if 0 /* Not implemented yet */
#ifdef CONFIG_SMP
	smp_bogo(m);
#endif
	mmu_info(m);
#ifdef CONFIG_SMP
	smp_info(m);
#endif
#endif

	return 0;
}

/* Add for rdma_sic module */
int	rdma_present = 0;
EXPORT_SYMBOL(rdma_present);

#if IS_ENABLED(CONFIG_ELDSP)
void (*eldsp_interrupt_p)(struct pt_regs *regs) = NULL;
EXPORT_SYMBOL(eldsp_interrupt_p);

static void eldsp_interrupt(struct pt_regs *regs)
{
	static int int_eldsp_error = 0;

	ack_APIC_irq();
	irq_enter();
	if (eldsp_interrupt_p) {
		eldsp_interrupt_p(regs);
	} else {
		if (!int_eldsp_error)
			printk("eldsp: attempt calling null handler\n");
		int_eldsp_error++;
	}
	inc_irq_stat(irq_eldsp_count);
	irq_exit();
}
#endif


#define	L_IOMMU_MLT_HIT			0x8
#define	L_IOMMU_PROT_VIOL_RD		0x4
#define	L_IOMMU_PROT_VIOL_WR		0x2
#define	L_IOMMU_MMU_ERR_ADDR		0x1

static void iommu_interrupt(struct pt_regs *regs)
{
	int node = numa_node_id(), link;
	int cpu = smp_processor_id();
	unsigned long fsr = 0, fsr2 = 0;
	char *err;
	ack_APIC_irq();
	irq_enter();
	for (link = 0; link < MACH_MAX_NUMIOLINKS; link++) {
		fsr = l_iommu_read(node, link, L_IOMMU_ERROR);
		fsr2 = l_iommu_read(node, link, L_IOMMU_ERROR1);
		if (fsr)
			break;
	}

	err = fsr & L_IOMMU_MLT_HIT 		? "Multihit"
		: fsr & L_IOMMU_PROT_VIOL_WR	? "Write protection error"
		: fsr & L_IOMMU_MMU_ERR_ADDR 	? "Page miss"
		: fsr & L_IOMMU_PROT_VIOL_RD 	? "Write protection error"
			: "Unknown error";

	panic("IOMMU:%d:%d: error on %d cpu:"
		"\t\t%s (error regs:%lx,%lx) at address 0x%lx.\n",
			node, link, cpu,
			err, fsr, fsr2, (fsr & (~0xf)) << (IO_PAGE_SHIFT - 4));

	irq_exit();
}

static void sic_error_interrupt(struct pt_regs *regs)
{
	int node;

	pr_err("SIC error interrupt received on CPU%d:\n",
		smp_processor_id());
	for_each_online_node(node) {
		pr_err("\tNODE%d SIC_INT=0x%x\n",
			node,
			sic_read_node_nbsr_reg(node, SIC_sic_int));
	}
	pr_err("Dazed and confused, but trying to continue\n");
}

void __init_recv
e2k_init_IRQ(int recovery_flag)
{
	init_bsp_APIC();

	/*
	 * Currently we don't have to initialize
	 * interrupt[] array on recovery path.
	 */
	if (!recovery_flag) {
		/* Initialize interrupt[] array of system interrupts' handlers. */
		l_init_system_handlers_table();

		if(l_iommu_supported())
			setup_APIC_vector_handler(LVT3_INTERRUPT_VECTOR,
					iommu_interrupt, 1,
					"iommu_interrupt");
#if defined(CONFIG_ELDSP) || defined(CONFIG_ELDSP_MODULE)
		else if(IS_MACHINE_ES2)
			setup_APIC_vector_handler(LVT3_INTERRUPT_VECTOR,
					eldsp_interrupt, 1,
					"eldsp_interrupt");
#endif
		if (IS_MACHINE_E2S || IS_MACHINE_E8C || IS_MACHINE_E8C2)
			setup_APIC_vector_handler(LVT4_INTERRUPT_VECTOR,
					sic_error_interrupt, 1,
					"sic_error_interrupt");
		else if (IS_MACHINE_E1CP) {
			pr_err("setup APIC LVT vectors is not yet implemented "
				"for e1c+\n");
		}
	}

	if (!recovery_flag) {
		default_setup_apic_routing();

		if (!verify_local_APIC())
			pr_emerg("LAPIC is broken, trying to continue...\n");
	}

	connect_bsp_APIC();

	setup_local_APIC();

	if (!recovery_flag)
		/* Enable IO APIC before setting up error vector. */
		enable_IO_APIC();

	bsp_end_local_APIC_setup();

	if (apic->setup_portio_remap)
		apic->setup_portio_remap();

#ifdef CONFIG_RECOVERY
	setup_IO_APIC(recovery_flag);
#else
	setup_IO_APIC();
#endif
}

void write_back_cache_ipi(void *unused)
{
	unsigned long mmu_cr;
	unsigned long flags;

	raw_local_irq_save(flags);

	mmu_cr = READ_MMU_CR();
	mmu_cr &= ~_MMU_CR_CD_MASK;
	mmu_cr |= _MMU_CD_DIS;

	write_back_CACHE_all();
	WRITE_MMU_CR(__mmu_reg(mmu_cr));

	raw_local_irq_restore(flags);
}

void e2k_safe_reset_machine(void *pci_dev)
{
	struct pci_dev *dev = (struct pci_dev *) pci_dev;
	static atomic_t cpus = ATOMIC_INIT(0); 
	u64 addr;
	
	raw_local_irq_disable();

	atomic_inc(&cpus);
	while (atomic_read(&cpus) != num_online_cpus());

	/*
	 * All cpus reach this point simultaneously. After that BSP processor
	 * performes softreset, other cpus wait in infinite loop. While doing
	 * softreset and waiting in infinite loop memory is not used. It is
	 * needed to workaround hardware bug #54222.
	 */

	if (IS_BOOT_STRAP_CPU()) {
		addr = CONFIG_CMD(
				dev->bus->number,
				dev->devfn,
				PCI_SOFT_RESET_CONTROL) +
		       domain_pci_conf_base(pci_domain_nr(dev->bus));
		e2k_do_safe_reset_machine(addr, L_SOFTWARE_RESET);
	} else
		e2k_safe_infinite_loop();
}

void
e2k_reset_machine(void)
{
	/* Reset dump analyze mode before reset */
#if defined (CONFIG_RECOVERY) && (CONFIG_CNT_POINTS_NUM < 2)
	if (read_bootblock_flags(bootblock_phys) & DUMP_ANALYZE_BB_FLAG)
		reset_bootblock_flags(bootblock_phys, RECOVERY_BB_FLAG |
			CNT_POINT_BB_FLAG | DUMP_ANALYZE_BB_FLAG);
#endif	/* CONFIG_RECOVERY && (CONFIG_CNT_POINTS_NUM < 2) */

	if (machine.arch_reset) {
		machine.arch_reset();
	}
}

/* static int ide_irqs = 0; */

void e2k_restart(char *cmd)
{
	while (soft_reset_off) {
		E2K_CMD_SEPARATOR;
	}
	e2k_reset_machine();

	/* Never reached */
	printk("System did not restart, so it can be done only by hands\n");
}

void e2k_power_off(void)
{
	printk("System power off...\n");

	while (soft_reset_off) {
		E2K_CMD_SEPARATOR;
	}
	if (machine.arch_halt) {
		machine.arch_halt();
	}

	E2K_HALT_OK();
}

void e2k_halt(void)
{
	printk("System halted.\n");

	while (soft_reset_off) {
		E2K_CMD_SEPARATOR;
	}
	if (machine.arch_halt) {
		machine.arch_halt();
	}

	E2K_HALT_OK();
}

/*
 * Power off function, if any
 */
void (*pm_power_off)(void) = e2k_power_off;
EXPORT_SYMBOL(pm_power_off);

#ifndef	CONFIG_E2K_MACHINE
void __init
e2k_setup_machine(void)
{
	switch (machine.id)
	{
		case MACHINE_ID_E3M_LMS:
			e3m_lms_setup_arch();
			break;
		case MACHINE_ID_E3M:
			e3m_setup_arch();
			break;
		case MACHINE_ID_E3M_IOHUB_LMS:
			e3m_iohub_lms_setup_machine();
			break;
		case MACHINE_ID_E3M_IOHUB:
			e3m_iohub_setup_machine();
			break;
		case MACHINE_ID_E3S_LMS:
			e3s_lms_setup_machine();
			break;
		case MACHINE_ID_E3S:
			e3s_setup_machine();
			break;
		case MACHINE_ID_ES2_DSP_LMS:
		case MACHINE_ID_ES2_RU_LMS:
			es2_lms_setup_machine();
			break;
		case MACHINE_ID_ES2_DSP:
		case MACHINE_ID_ES2_RU:
			es2_setup_machine();
			break;
		case MACHINE_ID_E2S_LMS:
			e2s_lms_setup_machine();
			break;
		case MACHINE_ID_E2S:
			e2s_setup_machine();
			break;
		case MACHINE_ID_E8C_LMS:
			e8c_lms_setup_machine();
			break;
		case MACHINE_ID_E8C:
			e8c_setup_machine();
			break;
		case MACHINE_ID_E1CP_LMS:
			e1cp_lms_setup_machine();
			break;
		case MACHINE_ID_E1CP:
			e1cp_setup_machine();
			break;
		case MACHINE_ID_E8C2_LMS:
			e8c2_lms_setup_machine();
			break;
		case MACHINE_ID_E8C2:
			e8c2_setup_machine();
			break;
		default:
			panic("setup_arch(): !!! UNKNOWN MACHINE TYPE !!!\n");
			machine.setup_arch = NULL;
			break;
	}
}
#endif	/* CONFIG_E2K_MACHINE */

#if defined CONFIG_E2K_E3M || defined CONFIG_E2K_E3M_SIM \
	|| defined CONFIG_E2K_E3M_IOHUB || defined CONFIG_E2K_E3M_IOHUB_SIM \
	|| !defined CONFIG_E2K_MACHINE
int e3m_get_vector(void)
{
	return APIC_VECT_VECTOR(arch_apic_read(APIC_VECT));
}
#endif

/*
 * machine structure is constant structure so can has own copy
 * on each node in the case of NUMA
 * Copy the structure to all nodes
 */
void __init
e2k_setup_arch(void)
{
	int nid;

	for_each_node_has_dup_kernel(nid) {
		the_node_machine(nid)->show_cpuinfo	= e2k_show_cpuinfo;
		the_node_machine(nid)->init_IRQ		= e2k_init_IRQ;
		the_node_machine(nid)->restart		= e2k_restart;
		the_node_machine(nid)->power_off	= e2k_power_off;
		the_node_machine(nid)->halt		= e2k_halt;
	}
}
