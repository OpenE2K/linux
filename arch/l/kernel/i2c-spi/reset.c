/*
 * Elbrus reset control driver
 *
 * Copyright (C) 2012 MCST
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 *
 * 2012-05-29	Created
 */

#include <linux/pci.h>
#include <linux/pci_ids.h>
#include <linux/delay.h>

#include <asm/machdep.h>
#include <asm/iolinkmask.h>
#include <asm/sic_regs.h>

#include <asm-l/i2c-spi.h>
#include <asm-l/gpio.h>
#include <asm-l/nmi.h>

#if IS_ENABLED(CONFIG_INPUT_LTC2954)
#include <linux/gpio.h>
#endif /* CONFIG_INPUT_LTC2954 */

#undef	DEBUG_RESET_MODE
#undef	DebugRS
#define	DEBUG_RESET_MODE	0	/* Elbrus reset debug */
#define	DebugRS			if (DEBUG_RESET_MODE) printk

static struct pci_dev *l_reset_device = NULL;

static void l_reset_pcie(void)
{
	int domain;
	for_each_online_iohub(domain) {
		struct pci_bus *bus = pci_find_bus(domain, 0);
		u16 vid = 0, did = 0;
		pci_bus_read_config_word(bus, 0, PCI_VENDOR_ID, &vid);
		pci_bus_read_config_word(bus, 0, PCI_DEVICE_ID, &did);
		if (vid != PCI_VENDOR_ID_MCST_PCIE_BRIDGE ||
				did != PCI_DEVICE_ID_MCST_PCIE_BRIDGE)
			break;
		 pci_bus_write_config_word(bus, 0, PCI_BRIDGE_CONTROL,
			       PCI_BRIDGE_CTL_BUS_RESET);
	}
}

static void l_set_soft_reset_state(void)
{
	unsigned int reg;
	pci_write_config_dword(l_reset_device, PCI_RESET_CONTROL,
			L_SOFTWARE_RESET_TO_SOFT | L_WATCHDOG_RESET_TO_SOFT);
	if (DEBUG_RESET_MODE) {
		pci_read_config_dword(l_reset_device,
			PCI_RESET_CONTROL, &reg);
		DebugRS("l_set_soft_reset_state() set Reset Control "
			"to 0x%x\n", reg);
	}
}

static void l_set_hard_reset_state(void)
{
	unsigned int reg;
	pci_write_config_dword(l_reset_device, PCI_RESET_CONTROL,
		L_SOFTWARE_RESET_TO_HARD | L_WATCHDOG_RESET_TO_HARD);
	if (DEBUG_RESET_MODE) {
		pci_read_config_dword(l_reset_device,
			PCI_RESET_CONTROL, &reg);
		DebugRS("l_set_hard_reset_state() set Reset Control "
			"to 0x%x\n", reg);
	}
}
#ifdef CONFIG_E90S
static int l_hard_reset = 1;
#else
static int l_hard_reset;
#endif
static int l_reset_setup(char *str)
{
	l_hard_reset = 1;
	return 1;
}

__setup("hardreset", l_reset_setup);

#ifdef CONFIG_E2K
static void dircache_disable(void)
{
	int node;

	for_each_online_node(node) {
		e2k_sic_sccfg_struct_t	sccfg;
		node_phys_mem_t		node_mem;
		e2k_phys_bank_t		bank_mem;
		e2k_addr_t		addr;

		node_mem = nodes_phys_mem[node];
		if (!node_mem.pfns_num)
			continue;

		bank_mem = node_mem.banks[0];
		if (!bank_mem.pages_num)
			continue;

		addr = (e2k_addr_t)phys_to_virt(bank_mem.base_addr);

		sccfg.E2K_SIC_SCCFG_reg =
				sic_read_node_nbsr_reg(node, SIC_sccfg);
		sccfg.E2K_SIC_SCCFG_dircacheen = 0;
		sic_write_node_nbsr_reg(
				node, SIC_sccfg, sccfg.E2K_SIC_SCCFG_reg);

		do {
			sccfg.E2K_SIC_SCCFG_reg =
				sic_read_node_nbsr_reg(node, SIC_sccfg);
		} while (sccfg.E2K_SIC_SCCFG_dircacheen);

		E2K_WAIT_ALL_OP;
		E2K_WRITE_MAS_D(addr, 0UL, MAS_DCACHE_LINE_FLUSH);
		E2K_WAIT_FLUSH;

		(void)E2K_READ_MAS_W(addr, MAS_BYPASS_ALL_CACHES);
		E2K_WAIT_ALL_OP;
	}
}
#endif

static void l_reset_machine(void)
{
	if (iohub_generation(l_reset_device) == 0) {
		/* system reset doesn't reset pcie */
		l_reset_pcie();
	}

#ifdef __e2k__
	if (bootblock_virt->info.bios.mb_type == MB_TYPE_ES2_PLATO1) {
		l_set_hard_reset_state();
	} else if (!l_hard_reset) {
		nmi_on_each_cpu(write_back_cache_ipi, NULL, 1, 0);
		if (cpu_has(CPU_HWBUG_DIRCACHE_DISABLE))
			dircache_disable();
	}

	if (cpu_has(CPU_HWBUG_MC_SOFTRESET)) {
		DebugRS("l_reset_machine() calling e2k_safe_reset_machine()\n");
		nmi_on_each_cpu(e2k_safe_reset_machine, l_reset_device, 0, 0);
	} else {
#endif	/* __e2k__ */
		DebugRS("l_reset_machine() write to:0x%x val:0x%x\n",
			PCI_SOFT_RESET_CONTROL, L_SOFTWARE_RESET);
		pci_write_config_dword(l_reset_device, PCI_SOFT_RESET_CONTROL,
			L_SOFTWARE_RESET);
#ifdef __e2k__
	}
#endif	/* __e2k__ */
}

static void l_halt_machine(void)
{
#if IS_ENABLED(CONFIG_INPUT_LTC2954)
	char *desc = "ltc2954_kill";
	int err = gpio_request(LTC2954_KILL_GPIO_PIN, desc);
	if (err < 0)
		return;

	err = gpio_direction_output(LTC2954_KILL_GPIO_PIN, 1);
	if (err < 0)
		return;

	/* Never back from this guy: */
	gpio_set_value(LTC2954_KILL_GPIO_PIN, 0);
#endif /* CONFIG_INPUT_LTC2954 */

	/*
	 * Machine halting is motherboard - dependent, so can be done
	 * only through interface kernel <-> boot
	 */
	pr_info("Hardware power off is not until implemented by "
		"boot/kernel, so use manual mode\n");
}


static void l_reset_set_control_func(struct pci_dev *dev)
{
#ifdef CONFIG_E2K
	int nid;
	for_each_node_has_dup_kernel(nid) {
		the_node_machine(nid)->arch_reset = &l_reset_machine;
		the_node_machine(nid)->arch_halt = &l_halt_machine;
	}
#else
	machine.arch_reset = &l_reset_machine;
	machine.arch_halt = &l_halt_machine;
#endif
	l_reset_device = dev;
}


static int l_reset_init(void)
{
	struct pci_dev *dev = pci_get_device(PCI_VENDOR_ID_ELBRUS,
			PCI_DEVICE_ID_MCST_I2CSPI, NULL);
	u32 duration;
	if (!dev && !(dev = pci_get_device(PCI_VENDOR_ID_MCST_TMP,
				PCI_DEVICE_ID_MCST_I2C_SPI, NULL)))
		return 0;

	l_reset_set_control_func(dev);
	duration = iohub_generation(l_reset_device) == 1 ?
		L_IOHUB2_SOFT_RESET_DURATION : L_IOHUB_SOFT_RESET_DURATION;

	pci_write_config_dword(dev, PCI_SOFT_RESET_DURATION,
				duration);

	if (DEBUG_RESET_MODE) {
		unsigned int reg;
		pci_read_config_dword(l_reset_device,
			PCI_SOFT_RESET_DURATION, &reg);
		DebugRS("l_set_soft_reset_state() set Software Reset Duration "
			"to 0x%x\n", reg);
	}
	if (l_hard_reset)
		l_set_hard_reset_state();
	else
		l_set_soft_reset_state();

	dev_info(&dev->dev, "probed\n");

	return 0;
}
device_initcall(l_reset_init);
