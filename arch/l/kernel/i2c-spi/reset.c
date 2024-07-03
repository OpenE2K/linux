/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Elbrus reset control driver
 */

#include <linux/pci.h>
#include <linux/pci_ids.h>
#include <linux/delay.h>

#include <asm/machdep.h>
#include <asm/iolinkmask.h>
#include <asm/sic_regs.h>
#include <asm/epic.h>

#include <asm-l/i2c-spi.h>
#include <asm-l/gpio.h>

#if IS_ENABLED(CONFIG_INPUT_LTC2954)
#include <linux/gpio.h>
#endif /* CONFIG_INPUT_LTC2954 */

#include <asm/l_spmc.h>


#undef	DEBUG_RESET_MODE
#undef	DebugRS
#define	DEBUG_RESET_MODE	0	/* Elbrus reset debug */
#define	DebugRS			if (DEBUG_RESET_MODE) printk

#define BOOT_MODE_BOOTCMD	0xAAAA5500

static struct pci_dev *l_reset_device = NULL;

int (*l_set_boot_mode)(int);


bool check_reset_by_lwdt(void)
{
	unsigned int reg;

	pci_read_config_dword(l_reset_device, PCI_SOFT_RESET_CONTROL, &reg);

	return (reg & L_LAST_RESET_INFO_TYPE_LWDT) ? true : false;
}

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

static int l_hard_reset = 1;

static int l_reset_setup(char *str)
{
	l_hard_reset = 0;
	return 1;
}
__setup("softreset", l_reset_setup);

void l_recover_reset_state(void)
{
	if (!l_hard_reset)
		l_set_soft_reset_state();
}

static void l_reset_machine(char *cmd)
{
	if (iohub_generation(l_reset_device) == 0) {
		/* system reset doesn't reset pcie */
		l_reset_pcie();
	}

	if (cmd && !strcmp(cmd, "bootcmd") && l_set_boot_mode)
		l_set_boot_mode(BOOT_MODE_BOOTCMD);

	DebugRS("l_reset_machine() write to:0x%x val:0x%x\n",
		PCI_SOFT_RESET_CONTROL, L_SOFTWARE_RESET);
	pci_write_config_dword(l_reset_device, PCI_SOFT_RESET_CONTROL,
		L_SOFTWARE_RESET);
}

static void l_halt_machine(void)
{
#if IS_ENABLED(CONFIG_INPUT_LTC2954)
	char *desc = "ltc2954_kill";
	int err = gpio_request(LTC2954_KILL_GPIO_PIN, desc);
	if (err < 0)
		goto spmc_halt;

	err = gpio_direction_output(LTC2954_KILL_GPIO_PIN, 1);
	if (err < 0)
		goto spmc_halt;

	/* Never back from this guy: */
	gpio_set_value(LTC2954_KILL_GPIO_PIN, 0);
spmc_halt:
#endif /* CONFIG_INPUT_LTC2954 */
	/* If here - try to use SPMC for halting: */
	pr_info("l_halt_machine: trying to halt using spmc...\n");
	do_spmc_halt();

	/*
	 * Machine halting is motherboard - dependent, so can be done
	 * only through interface kernel <-> boot
	 */
	pr_info("Hardware power off is not until implemented by "
		"boot/kernel, so use manual mode\n");
	while (1);
}


static void l_reset_set_control_func(struct pci_dev *dev)
{
	machine.arch_reset = &l_reset_machine;
	machine.arch_halt = &l_halt_machine;
	l_reset_device = dev;
}

static struct pci_dev *get_i2c_spi_dev(void)
{
	struct pci_dev *dev = NULL;
	if (cpu_has_epic())
		dev = pci_get_device(PCI_VENDOR_ID_MCST_TMP,
				PCI_DEVICE_ID_MCST_IOEPIC_I2C_SPI, NULL);
	if (!dev)
		dev = pci_get_device(PCI_VENDOR_ID_MCST_TMP,
					PCI_DEVICE_ID_MCST_I2C_SPI, NULL);
	if (!dev)
		dev = pci_get_device(PCI_VENDOR_ID_ELBRUS,
				PCI_DEVICE_ID_MCST_I2CSPI, NULL);

	return dev;
}

static int l_reset_init(void)
{
	struct pci_dev *dev = get_i2c_spi_dev();
	u32 duration;

	if (!dev)
		return 0;

	l_reset_set_control_func(dev);

	switch (iohub_generation(dev)) {
	case 0:
		duration = L_IOHUB_SOFT_RESET_DURATION;
		break;
	case 1:
		duration = L_IOHUB2_SOFT_RESET_DURATION;
		break;
	case 2:
		duration = L_EIOHUB_SOFT_RESET_DURATION;
		break;
	default:
		WARN(1, "reset duration is not set\n");
		duration = 0;
	}

	if (duration) {
		pci_write_config_dword(dev, PCI_SOFT_RESET_DURATION,
						duration);
	}

	if (DEBUG_RESET_MODE) {
		unsigned int reg;
		pci_read_config_dword(dev, PCI_SOFT_RESET_DURATION, &reg);
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
