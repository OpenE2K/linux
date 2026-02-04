/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/cpuhotplug.h>
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
#include <asm/pic.h>
#include <asm/sclkr.h>
#include <asm/setup.h>
#include <asm/simul.h>

#include <asm-l/i2c-spi.h>


extern char *get_mach_type_name(void);


static int native_show_cpuinfo(struct seq_file *m, void *v)
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
		"cpu MHz\t\t: %llu\n",
		cpu, c->family >= 5 ? ELBRUS_CPU_VENDOR : mcst_mb_name,
		c->family, c->model, GET_CPU_TYPE_NAME(c->model),
		c->revision, freq);

	seq_puts(m, "features\t:");
	cpuinfo_clk(m);
	cpuinfo_pic(m);
	if (is_prototype())
		seq_puts(m, " prototype");
	if (IS_HV_GM())
		seq_puts(m, " guest");
	seq_puts(m, "\n");

	seq_printf(m, "bogomips\t: %llu.%02u\n\n", 2 * freq, 0);


	if (last == cpu)
		show_cacheinfo(m);

	return 0;
}

static void e2k_restart(char *cmd)
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

void native_write_SCLKM1_reg(e2k_sclkm1_t sclkm1)
{
	if (cpu_has(CPU_HWBUG_SCLKM1_WRITE) && read_SCLKM1_reg().mode &&
			!sclkm1.mode && sclkm1.mdiv) {
		unsigned long flags;
		e2k_sclkr_t orig_sclkr, sclkr;

		all_irq_save(flags);

		/* Write mode */
		e2k_sclkm1_t sclkm1_no_mdiv = sclkm1;
		sclkm1_no_mdiv.mdiv = 0;
		NATIVE_WRITE_SCLKM1_REG_VALUE(AW(sclkm1_no_mdiv));
		/* Wait for mode change */
		orig_sclkr = read_SCLKR_reg();
		do {
			sclkr = read_SCLKR_reg();
		} while (orig_sclkr.lo == sclkr.lo);
		/* Write (m)div */
		NATIVE_WRITE_SCLKM1_REG_VALUE(AW(sclkm1));

		all_irq_restore(flags);
	} else {
		NATIVE_WRITE_SCLKM1_REG_VALUE(AW(sclkm1));
	}
}

static int e2k_cpu_starting(unsigned int cpu)
{
	int node = cpu_to_node(cpu);

	if (cpu_has(CPU_HWBUG_DMA_WR_GLUE)) {
		e2k_sic_hw1_t sic_hw1 = {
			.word = sic_read_node_nbsr_reg(node, SIC_hw1)
		};
		sic_hw1.v4_v5.dma_wr_glue_en = 0;
		sic_write_node_nbsr_reg(node, SIC_hw1, AW(sic_hw1));
	}

	return 0;
}

static int __init fixup_cpu_quirks(void)
{
	int ret = cpuhp_setup_state(CPUHP_AP_E2K_CPU_STARTING, "e2k/cpu:starting",
				e2k_cpu_starting, NULL);

	if (WARN(ret < 0, "Failed to setup e2k cpu hotplug state: %d\n", ret))
		return ret;

	return 0;
}
early_initcall(fixup_cpu_quirks);

