/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/fb.h>
#include <linux/pci.h>
#include <linux/console.h>
#include <linux/vgaarb.h>
#include <linux/pci_ids.h>
#include <linux/random.h>
#include <linux/memblock.h>
#include <linux/sort.h>
#include <video/vga.h>
#include <asm/bootinfo.h>
#include <asm/io.h>
#include <asm/console.h>
#include <asm/setup.h>
#include <asm/fb.h>

#include "../../../drivers/pci/pci.h"

int fb_is_primary_device(struct fb_info *info)
{
	struct device *device = info->device;
	struct pci_dev *pci_dev = NULL;
	struct pci_dev *default_device = vga_default_device();
	struct resource *res = NULL;

	if (device && dev_is_pci(device))
		pci_dev = to_pci_dev(device);

	if (!pci_dev) {
		struct apertures_struct *gen_aper = info->apertures;
		if (gen_aper && gen_aper->count &&
				gen_aper->ranges[0].base == VGA_FB_PHYS_BASE)
			return 1;
		return 0;
	}

	if (default_device) {
		if (pci_dev == default_device)
			return 1;
		else
			return 0;
	}

	res = &pci_dev->resource[PCI_ROM_RESOURCE];

	if (res && res->flags & IORESOURCE_ROM_SHADOW)
		return 1;
	return 0;
}
EXPORT_SYMBOL(fb_is_primary_device);

#define L_MAC_MAX 32
static unsigned char l_base_mac_addr[6] = {0};
static int l_mac_last_nr = 0;
static bool l_get_all_mac_addr_from_boot = 1;

static const struct pci_device_id l_iohub_eth_devices[] = {
	{ PCI_DEVICE(SUNLANCE_PCI_VENDOR_ID, SUNLANCE_PCI_DEVICE_ID) },
	{ PCI_DEVICE(PCI_VENDOR_ID_ELBRUS, PCI_DEVICE_ID_MCST_E1000) },
	{ PCI_DEVICE(PCI_VENDOR_ID_MCST_TMP, PCI_DEVICE_ID_MCST_ETH) },
	{ PCI_DEVICE(PCI_VENDOR_ID_MCST_TMP, PCI_DEVICE_ID_MCST_MGB) },
	{ PCI_DEVICE(PCI_VENDOR_ID_MCST_TMP, PCI_DEVICE_ID_MCST_XGBE) },
	{ }	/* terminate list */
};

static struct l_pdev_mac {
	unsigned char depth, domain, bus, slot, func;
} *l_pdev_mac;

static int l_cmp_pdev_mac(const void *_a, const void *_b)
{
	const struct l_pdev_mac *a = _a, *b = _b;
	if (a->depth != b->depth)
		return (int)a->depth - (int)b->depth;
	if (a->domain != b->domain)
		return (int)a->domain - (int)b->domain;
	if (a->bus != b->bus)
		return (int)a->bus - (int)b->bus;
	if (a->slot != b->slot)
		return (int)a->slot - (int)b->slot;
	if (a->func != b->func)
		return (int)a->func - (int)b->func;
	WARN_ON(1);
	return 0;
}

static int l_get_depth(struct pci_dev *pdev)
{
	int i = 0;
	while ((pdev = pci_upstream_bridge(pdev)))
		i++;
	return i;
}

static int __init l_ethernet_mac_addr_init(void)
{
	int i = 0;
	struct pci_dev *pdev = NULL;
	const struct pci_device_id *ent;
	struct l_pdev_mac *m;
	ioh_eth_mac_table_entry_t *head = (ioh_eth_mac_table_entry_t *)
				bootblock_virt->info.mac_table_ptr;
	if (l_get_all_mac_addr_from_boot && head) /* boot sets all addresses */
		return 0;
	m = kmalloc(sizeof(*m) * L_MAC_MAX, GFP_KERNEL);
	if (!m)
		return -ENOMEM;
	for_each_pci_dev(pdev) {
		ent = pci_match_id(l_iohub_eth_devices, pdev);
		if (!ent)
			continue;
		m[i].depth  = l_get_depth(pdev);
		m[i].domain = pci_domain_nr(pdev->bus);
		m[i].bus    = pdev->bus->number;
		m[i].slot   = PCI_SLOT(pdev->devfn);
		m[i].func   = PCI_FUNC(pdev->devfn);
		i++;
		if (WARN_ON(i == L_MAC_MAX))
			break;
	}
	sort(m, i, sizeof(struct l_pdev_mac), l_cmp_pdev_mac, NULL);
	l_mac_last_nr = i;
	l_pdev_mac = m;
	return 0;
}
/* Needs to be done after pci initialization which are subsys_initcall. */
subsys_initcall_sync(l_ethernet_mac_addr_init);

static int l_set_ethernet_macaddr_old(struct pci_dev *pdev, char *macaddr)
{
	static DEFINE_SPINLOCK(lock);
	struct l_pdev_mac *m = l_pdev_mac;
	int i, ret = 0;
	for (i = 0; i < 6/*ETH_ALEN*/; i++)
		macaddr[i] = l_base_mac_addr[i];

	spin_lock_irq(&lock);

	if (pdev) {
		/* Find reserved mac-address for device */
		for (i = 0; i < l_mac_last_nr; i++) {
			if (m[i].domain == pci_domain_nr(pdev->bus) &&
				m[i].bus == pdev->bus->number &&
				m[i].slot == PCI_SLOT(pdev->devfn) &&
				m[i].func == PCI_FUNC(pdev->devfn)) {
				macaddr[5] += i;
				goto out;
			}
		}
	}
	/*Try to assign mac-address */
	if (l_mac_last_nr >= L_MAC_MAX) {
		ret = -ENOSPC;
		goto out;
	}

	i = l_mac_last_nr;

	if (pdev) {
		m[i].depth  = l_get_depth(pdev);
		m[i].domain = pci_domain_nr(pdev->bus);
		m[i].bus    = pdev->bus->number;
		m[i].slot   = PCI_SLOT(pdev->devfn);
		m[i].func   = PCI_FUNC(pdev->devfn);
	}
	macaddr[5] += i;
	l_mac_last_nr++;
out:
	spin_unlock_irq(&lock);
	return ret;
}

static int l_set_ethernet_macaddr_new(ioh_eth_mac_table_entry_t *h,
				struct pci_dev *pdev, char *macaddr)
{
	int domain = pci_domain_nr(pdev->bus);
	int bus    = pdev->bus->number;
	int slot   = PCI_SLOT(pdev->devfn);
	int func   = PCI_FUNC(pdev->devfn);
	for (; h; h = h->next) {
		h = __va(h);
		if (domain == h->pci_domain && bus == h->bus &&
				slot == h->slot && func == h->func) {
			memcpy(macaddr, h->mac_addr, sizeof(h->mac_addr));
			dev_info(&pdev->dev, "ethernet MAC %pM\n", macaddr);
			return 0;
		}
	}
	memcpy(macaddr, l_base_mac_addr, sizeof(l_base_mac_addr));
	WARN(1, "%s: failed to find MAC address\n", pci_name(pdev));
	return -ENOENT;
}

int l_set_ethernet_macaddr(struct pci_dev *pdev, char *macaddr)
{
	ioh_eth_mac_table_entry_t *head = (ioh_eth_mac_table_entry_t *)
				bootblock_virt->info.mac_table_ptr;
	if (l_get_all_mac_addr_from_boot && head) {/* boot sets all addresses */
		if (!pdev) {
			memcpy(macaddr, l_base_mac_addr, sizeof(l_base_mac_addr));
			return -EINVAL;
		}
		return l_set_ethernet_macaddr_new(head, pdev, macaddr);
	}
	return l_set_ethernet_macaddr_old(pdev, macaddr);
}
EXPORT_SYMBOL(l_set_ethernet_macaddr);

static int get_long_option(char **str, u64 *pint)
{
	char *cur = *str;

	if (!cur || !(*cur))
		return 0;
	*pint = simple_strtoull(cur, str, 0);
	if (cur == *str)
		return 0;
	return 1;
}

static int __init machine_mac_addr_setup(char *str)
{
	__be64 machine_mac_addr;
	if (!strcmp(str, "new")) {
		l_get_all_mac_addr_from_boot = 1;
	} else if (!strcmp(str, "old")) {
		l_get_all_mac_addr_from_boot = 0;
	} else if (get_long_option(&str, (u64 *)&machine_mac_addr)) {
		u64 tmp = be64_to_cpu(machine_mac_addr);
		memcpy(l_base_mac_addr, ((u8 *)&tmp) + 2,
					sizeof(l_base_mac_addr));

		printk("machine_mac_addr_setup: "
			"New MAC address is %06llx\n"
			"Base MAC addr for ethernet: %pm\n",
			machine_mac_addr, l_base_mac_addr);
	}
	return 1;
}
__setup("mach_mac=", machine_mac_addr_setup);

#define MB_NAME_BODY_SZ	32
static char mb_name_body[MB_NAME_BODY_SZ];
char *mcst_mb_name;
EXPORT_SYMBOL(mcst_mb_name);

int __init l_setup_arch(void)
{
	unsigned char *ma;
	u64 tsc = get_cycles();
	if(!bootblock_virt)
		return -1;

	/* Random ticks after booting */
	add_device_randomness(&tsc, sizeof(tsc));
	/* Some info from boot */
	add_device_randomness(bootblock_virt->info.boot_ver,
			      strlen(bootblock_virt->info.boot_ver));
	add_device_randomness(&bootblock_virt->info.mach_serialn,
			      sizeof(bootblock_virt->info.mach_serialn));

	ma = bootblock_virt->info.mac_addr;

	if (!ma[0] && !ma[1] && !ma[2] && !ma[3] && !ma[4] && !ma[5]) {
		l_base_mac_addr[0] = 0x08;
		l_base_mac_addr[1] = 0x00;
#ifdef __e2k__
		l_base_mac_addr[2] = 0x30;
#else
		l_base_mac_addr[2] = 0x20;
#endif
		l_base_mac_addr[3] = (bootblock_virt->info.mach_serialn >> 8) & 0xff;
		l_base_mac_addr[4] = bootblock_virt->info.mach_serialn & 0xff;
	} else {
		memcpy(l_base_mac_addr, ma, 6);
	}
	pr_info("Base MAC address %02x:%02x:%02x:%02x:%02x:%02x\n",
		l_base_mac_addr[0], l_base_mac_addr[1], l_base_mac_addr[2],
		l_base_mac_addr[3], l_base_mac_addr[4], l_base_mac_addr[5]);
	/* Set mb_name. If boot provides it from FRUiD, set it.
	 * If no, try to guess it by mb_version
	 * Max name len = 14. bootblock_virt->info.mb_name[15]
	 * is a revision of board
	 */
	ma = bootblock_virt->info.mb_name;
	if (ma[0]) {
		/* FRUiD name is valid */
		if (ma[15]) {
			/* we have valid revision. compose name */
			ma[14] = 0; /* for safety */
			sprintf(mb_name_body, "%s v.%u", ma, ma[15]);
			mcst_mb_name = mb_name_body;
		} else {
			mcst_mb_name = ma;
		}
	} else {
		mcst_mb_name =
			GET_MB_TYPE_NAME(bootblock_virt->info.mb_type);
	}

	register_early_dump_console();
	return 0;
}

