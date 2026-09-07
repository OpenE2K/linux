/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include "bios.h"
#include <linux/pci_ids.h>
#include "pci.h"
#include "console/Am85C30.h"

#if defined(CONFIG_LMS_CONSOLE)
extern void console_probe(void);
#endif

bios_hardware_t hardware = {0};

/*
 * First part of BIOS initialization
 *
 * No any memory available yet. Minimum initializations for the moment.
 */

void bios_first(void)
{
#if defined(CONFIG_LMS_CONSOLE)
	console_probe();
#endif
}

/*
 * Rest of BIOS initialization
 *
 * Most of the job can be completed here. PCI should be inited before.
 */

void bios_rest(void)
{
#ifdef CONFIG_ENABLE_IOAPIC
	configure_pic_system();
	configure_system_timer();
#ifdef CONFIG_SERIAL_AM85C30_BOOT_CONSOLE
	zilog_serial_init();
#endif
#endif

#ifdef	CONFIG_E2K_LEGACY_SIC
	enable_embeded_graphic();
#else	/* ! CONFIG_E2K_LEGACY_SIC */
#ifdef	CONFIG_ENABLE_MGA
	enable_mga();
#endif	/* CONFIG_ENABLE_MGA */
#endif	/* CONFIG_E2K_LEGACY_SIC */
}
