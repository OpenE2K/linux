/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/export.h>
#include <linux/syscalls.h>

#include <asm/mas.h>
#include <asm/io.h>
#include <asm/iolinkmask.h>
#include <asm/e2k_sic.h>
#include <asm/e2k_api.h>
#include <asm/e2k_debug.h>

#undef	DEBUG_CIO_MODE
#undef	DebugCIO
#define	DEBUG_CIO_MODE		0	/* configuration space  */
					/* input/output functions */
#define DebugCIO(...)		DebugPrint(DEBUG_CIO_MODE, ##__VA_ARGS__)

SYSCALL_DEFINE3(ioperm, unsigned long, from, unsigned long, num, int, turn_on)
{
	return 0;
}

/*
 * Configuration area access
 */

unsigned long get_domain_pci_conf_base(unsigned int domain)
{
	unsigned long conf_base;

	if (!HAS_MACHINE_L_SIC) {
		pr_err("%s(): machine has not NBSR to calculate PCI CFG base\n",
			__func__);
		return -1;
	}
	if (!iohub_online(domain)) {
		pr_err("%s(): IOHUB domain # %d (node %d, link %d) is not online\n",
			__func__, domain, iohub_domain_to_node(domain),
			iohub_domain_to_link(domain));
		return -1;
	}
	conf_base = domain_pci_conf_base(domain);
	if (conf_base == 0) {
		pr_err("%s(): IOHUB domain # %d (node %d, link %d) PCI CFG base did not set\n",
			__func__, domain, iohub_domain_to_node(domain),
			iohub_domain_to_link(domain));
		return -1;
	}
	return conf_base;
}

unsigned long get_domain_pci_conf_size(unsigned int domain)
{
	unsigned long conf_size;

	if (!HAS_MACHINE_L_SIC) {
		pr_err("%s(): machine has not NBSR to calculate PCI CFG base\n",
			__func__);
		return -1;
	}
	if (!iohub_online(domain)) {
		pr_err("%s(): IOHUB domain # %d (node %d, link %d) is not online\n",
			__func__, domain, iohub_domain_to_node(domain),
			iohub_domain_to_link(domain));
		return -1;
	}
	conf_size = domain_pci_conf_size(domain);
	if (conf_size == 0) {
		pr_err("%s(): IOHUB domain # %d (node %d, link %d) PCI CFG base did not set\n",
			__func__, domain, iohub_domain_to_node(domain),
			iohub_domain_to_link(domain));
		return -1;
	}
	return conf_size;
}

void
native_conf_inb(unsigned int domain, unsigned int bus, unsigned long port,
			u8 *byte)
{
	unsigned long conf_base;
	unsigned long conf_port;

	conf_base = get_domain_pci_conf_base(domain);
	conf_port = conf_base + port;
	*byte = NATIVE_READ_MAS_B(conf_port, MAS_IOADDR);
	DebugCIO("value %x read from port %lx, domain #%d "
		"(node %d, IO link %d)\n",
		(u32) *byte, conf_port, domain,
	iohub_domain_to_node(domain), iohub_domain_to_link(domain));
}

void
native_conf_inw(unsigned int domain, unsigned int bus, unsigned long port,
			u16 *hword)
{
	unsigned long conf_base;
	unsigned long conf_port;

	conf_base = get_domain_pci_conf_base(domain);
	conf_port = conf_base + port;
	*hword = NATIVE_READ_MAS_H(conf_port, MAS_IOADDR);
	DebugCIO("value %x read from port %lx, domain #%d "
		"(node %d, IO link %d)\n",
		(u32) *hword, conf_port, domain,
		iohub_domain_to_node(domain), iohub_domain_to_link(domain));
}

void
native_conf_inl(unsigned int domain, unsigned int bus, unsigned long port,
			u32 *word)
{
	unsigned long conf_base;
	unsigned long conf_port;

	conf_base = get_domain_pci_conf_base(domain);
	conf_port = conf_base + port;
	*word = NATIVE_READ_MAS_W(conf_port, MAS_IOADDR);
	DebugCIO("value %x read from port %lx, domain #%d "
		"(node %d, IO link %d)\n",
		(u32) *word, conf_port, domain,
		iohub_domain_to_node(domain), iohub_domain_to_link(domain));
}

void
native_conf_outb(unsigned int domain, unsigned int bus, unsigned long port,
			u8 byte)
{
	unsigned long conf_base;
	unsigned long conf_port;

	conf_base = get_domain_pci_conf_base(domain);
	conf_port = conf_base + port;
	DebugCIO("value %x write to port %lx, domain #%d "
		"(node %d, IO link %d)\n",
		(u32) byte, conf_port, domain,
		iohub_domain_to_node(domain), iohub_domain_to_link(domain));
	NATIVE_WRITE_MAS_B(conf_port, byte, MAS_IOADDR);
}

void
native_conf_outw(unsigned int domain, unsigned int bus, unsigned long port,
			u16 hword)
{
	unsigned long conf_base;
	unsigned long conf_port;

	conf_base = get_domain_pci_conf_base(domain);
	conf_port = conf_base + port;
	DebugCIO("value %x write to port %lx, domain #%d "
		"(node %d, IO link %d)\n",
		(u32) hword, conf_port, domain,
		iohub_domain_to_node(domain), iohub_domain_to_link(domain));
	NATIVE_WRITE_MAS_H(conf_port, hword, MAS_IOADDR);
}

void
native_conf_outl(unsigned int domain, unsigned int bus, unsigned long port,
			u32 word)
{
	unsigned long conf_base;
	unsigned long conf_port;

	conf_base = get_domain_pci_conf_base(domain);
	conf_port = conf_base + port;
	DebugCIO("value %x write to port %lx, domain #%d "
		"(node %d, IO link %d)\n",
		(u32) word, conf_port, domain,
		iohub_domain_to_node(domain), iohub_domain_to_link(domain));
	NATIVE_WRITE_MAS_W(conf_port, word, MAS_IOADDR);
}
