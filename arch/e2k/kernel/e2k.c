/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/ptrace.h>
#include <linux/hardirq.h>
#include <linux/init.h>
#include <linux/irq.h>
#include <linux/delay.h>
#include <linux/seq_file.h>
#include <linux/smp.h>
#include <linux/utsname.h>
#include <linux/pci.h>
#include <linux/dma-map-ops.h>

#include <asm/e2k_api.h>
#include <asm/e2k_debug.h>
#include <asm/boot_recovery.h>
#include <asm/e2k.h>
#include <asm/e2k_sic.h>
#include <asm/machines.h>
#include <asm/hw_irq.h>
#include <asm/byteorder.h>
#include <asm/traps.h>
#include <asm/smp.h>
#include <asm/io.h>
#include <asm/pic.h>
#include <asm/io_apic.h>
#include <asm/io_epic.h>
#include <asm/l-iommu.h>
#include <asm/setup.h>
#include <asm/simul.h>

#include <asm-l/i2c-spi.h>



#undef	DEBUG_IRQ_MODE
#undef	DebugIRQ
#define	DEBUG_IRQ_MODE		0	/* interrupts */
#define DebugIRQ(...)		DebugPrint(DEBUG_IRQ_MODE ,##__VA_ARGS__)


extern char *get_mach_type_name(void);


int native_show_cpuinfo(struct seq_file *m, void *v)
{
	struct cpuinfo_e2k *c = v;
	unsigned long last = cpumask_last(cpu_online_mask);
	u64 freq;
	int cpu;

#ifdef CONFIG_SMP
	cpu = c->cpu;
	if (!cpu_online(cpu))
		return 0;
#else
	cpu = 0;
#endif
	freq = (measure_cpu_freq(cpu) + 500000) / 1000000;

	seq_printf(m,
		"processor\t: %d\n"
		"vendor_id\t: %s\n"
		"cpu family\t: %d\n"
		"model\t\t: %d\n"
		"model name\t: %s\n"
		"revision\t: %u\n"
		"cpu MHz\t\t: %llu\n"
		"bogomips\t: %llu.%02u\n\n",
		cpu, c->family >= 5 ? ELBRUS_CPU_VENDOR : mcst_mb_name,
		c->family, c->model, GET_CPU_TYPE_NAME(c->model),
		c->revision, freq, 2 * freq, 0);


	if (last == cpu)
		show_cacheinfo(m);

	return 0;
}

/* Add for rdma_sic module */
int	rdma_present = 0;
EXPORT_SYMBOL(rdma_present);

int iommu_panic_off = 0;

static int __init
disable_iommu_panic(char *str)
{
	iommu_panic_off = 1;
	return 1;
}
__setup("iommupanicoff", disable_iommu_panic);


#define	L_IOMMU_MLT_HIT			0x8
#define	L_IOMMU_PROT_VIOL_RD		0x4
#define	L_IOMMU_PROT_VIOL_WR		0x2
#define	L_IOMMU_MMU_ERR_ADDR		0x1

static void iommu_interrupt(struct pt_regs *regs)
{
	int node = numa_node_id(), n;
	int cpu = smp_processor_id();
	unsigned long fsr = 0, fsr2 = 0, addr;
	char *err;
	char str[1024];

	ack_pic_irq();
	irq_enter();

	fsr = l_iommu_read(node, L_IOMMU_ERROR);
	fsr2 = l_iommu_read(node, L_IOMMU_ERROR1);

	addr = (fsr & (~0xf)) << (IO_PAGE_SHIFT - 4);

	err = fsr & L_IOMMU_MLT_HIT 		? "Multihit"
		: fsr & L_IOMMU_PROT_VIOL_WR	? "Write protection error"
		: fsr & L_IOMMU_MMU_ERR_ADDR	? "Page miss"
		: fsr & L_IOMMU_PROT_VIOL_RD	? "Read protection error"
			: "Unknown error";
	n = snprintf(str, sizeof(str),
		"IOMMU:%d: error on cpu %d:\n"
		       "\t%s at address 0x%lx "
			"(device: %lx:%lx:%lx, error regs:%lx,%lx).\n",
			node, cpu,
			err, addr,
			(fsr2 >> 8) & 0xff, (fsr2 >> 3) & 0x1f,
			(fsr2 >> 0) & 0x7,
			fsr, fsr2);

	debug_dma_dump_mappings(NULL);

	irq_exit();

	if (iommu_panic_off)
		pr_emerg("%s", str);
	else
		panic(str);
}

#ifdef	CONFIG_EPIC
void __init e2k_init_IRQ_epic(void)
{
	int ret;

	/*
	 * Initialize interrupt[] array of system interrupts' handlers.
	 */
	epic_init_system_handlers_table();

	/* guest IRQs additional handlers */
	init_guest_system_handlers_table();

	setup_bsp_epic();

	/* SIC access should be initialized before IOEPIC (for RT_MSI) */
	ret = e2k_sic_init();
	if (ret)
		panic("e2k_sic_init() failed, error %d\n", ret);

	/*
	 * Initialize both IO-APICs and IO-EPICs
	 */
	if (nr_ioapics)
		setup_IO_APIC();
	if (nr_ioepics)
		setup_io_epic();

}
#endif

void __init e2k_init_IRQ_apic(void)
{
	init_bsp_APIC();

	/*
	 * Initialize interrupt[] array of system interrupts' handlers.
	 */
	l_init_system_handlers_table();

	if (HAS_MACHINE_E2K_IOMMU)
		setup_PIC_vector_handler(LVT3_INTERRUPT_VECTOR,
			e2k_iommu_error_interrupt, 1, "iommu_interrupt");
	else if (l_iommu_supported())
		setup_PIC_vector_handler(LVT3_INTERRUPT_VECTOR,
			iommu_interrupt, 1, "iommu_interrupt");

	if (machine.setup_apic_vector_handlers)
		machine.setup_apic_vector_handlers();

	/* guest IRQs additional handlers */
	init_guest_system_handlers_table();

	default_setup_apic_routing();

	if (!verify_local_APIC())
		pr_emerg("LAPIC is broken, trying to continue...\n");

	setup_local_APIC();

	bsp_end_local_APIC_setup();

	/* SIC access should be initialized before IOAPIC (for EPIC EOI) */
	if (HAS_MACHINE_L_SIC) {
		int ret = e2k_sic_init();
		if (ret != 0) {
			panic("e2k_sic_init() failed, error %d\n", ret);
		}
	}

	setup_IO_APIC();
}

#ifdef	CONFIG_EPIC
void __init e2k_init_IRQ(void)
{
	if (cpu_has_epic())
		return e2k_init_IRQ_epic();
	else
		return e2k_init_IRQ_apic();
}
#else
void __init e2k_init_IRQ(void)
{
	return e2k_init_IRQ_apic();
}
#endif

void e2k_restart(char *cmd)
{
	if (machine.arch_reset)
		machine.arch_reset(cmd);

	/* Never reached */
	printk("System did not restart, so it can be done only by hands\n");
}

static void do_halt(void)
{
	if (machine.arch_halt)
		machine.arch_halt();

	E2K_HALT_OK();
}

void e2k_power_off(void)
{
	printk("System power off...\n");
	do_halt();
}

void e2k_halt(void)
{
	printk("System halted.\n");
	do_halt();
}

/*
 * Power off function, if any
 */
void (*pm_power_off)(void) = e2k_power_off;
EXPORT_SYMBOL(pm_power_off);

/*
 * machine structure is constant structure so can has own copy
 * on each node in the case of NUMA
 * Copy the structure to all nodes
 */
static void __init
native_e2k_setup_machine(void)
{
	machine.show_cpuinfo = native_show_cpuinfo;
	machine.init_IRQ = e2k_init_IRQ;
	machine.restart = e2k_restart;
	machine.power_off = e2k_power_off;
	machine.halt = e2k_halt;
}

void __init
native_setup_machine(void)
{
#ifdef	CONFIG_E2K_MACHINE
# if defined(CONFIG_E2K_E2S)
	e2s_setup_machine();
# elif defined(CONFIG_E2K_E8C)
	e8c_setup_machine();
# elif defined(CONFIG_E2K_E1CP)
	e1cp_setup_machine();
# elif defined(CONFIG_E2K_E8C2)
	e8c2_setup_machine();
# elif defined(CONFIG_E2K_E12C)
	e12c_setup_machine();
# elif defined(CONFIG_E2K_E16C)
	e16c_setup_machine();
# elif defined(CONFIG_E2K_E2C3)
	e2c3_setup_machine();
# elif defined(CONFIG_E2K_E48C)
	e48c_setup_machine();
# elif defined(CONFIG_E2K_E8V7)
	e8v7_setup_machine();
# else
#     error "E2K MACHINE type does not defined"
# endif
#else	/* ! CONFIG_E2K_MACHINE */
	switch (machine.native_id)
	{
		case MACHINE_ID_E2S_LMS:
		case MACHINE_ID_E2S:
			e2s_setup_machine();
			break;
		case MACHINE_ID_E8C_LMS:
		case MACHINE_ID_E8C:
			e8c_setup_machine();
			break;
		case MACHINE_ID_E1CP_LMS:
		case MACHINE_ID_E1CP:
			e1cp_setup_machine();
			break;
		case MACHINE_ID_E8C2_LMS:
		case MACHINE_ID_E8C2:
			e8c2_setup_machine();
			break;
		case MACHINE_ID_E12C_LMS:
		case MACHINE_ID_E12C:
			e12c_setup_machine();
			break;
		case MACHINE_ID_E16C_LMS:
		case MACHINE_ID_E16C:
			e16c_setup_machine();
			break;
		case MACHINE_ID_E2C3_LMS:
		case MACHINE_ID_E2C3:
			e2c3_setup_machine();
			break;
		case MACHINE_ID_E48C_LMS:
		case MACHINE_ID_E48C:
			e48c_setup_machine();
			break;
		case MACHINE_ID_E8V7_LMS:
		case MACHINE_ID_E8V7:
			e8v7_setup_machine();
			break;
		default:
			panic("setup_arch(): !!! UNKNOWN MACHINE TYPE !!!\n");
			machine.setup_arch = NULL;
			break;
	}
#endif	/* CONFIG_E2K_MACHINE */

	native_e2k_setup_machine();
}
