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
#include <asm/l-iommu.h>
#include <asm/setup.h>
#include <asm/simul.h>

#include <asm-l/i2c-spi.h>


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

static void e2k_power_off(void)
{
	printk("System power off...\n");
	do_halt();
}

static void e2k_halt(void)
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
