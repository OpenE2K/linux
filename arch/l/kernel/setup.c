#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/fb.h>
#include <linux/pci.h>
#include <linux/console.h>
#include <linux/screen_info.h>
#include <linux/vgaarb.h>
#include <linux/pci_ids.h>
#include <linux/random.h>
#include <linux/of_fdt.h>
#include <linux/memblock.h>
#include <asm/bootinfo.h>
#include <asm/io.h>
#include <asm/console.h>

struct screen_info screen_info = {
	.orig_x = 0,
	.orig_y = 25,
	.orig_video_page = 0,
	.orig_video_mode = 7,
	.orig_video_cols = 80,
	.orig_video_lines = 25,
	.orig_video_isVGA = 1,
	.orig_video_points = 16
};
EXPORT_SYMBOL(screen_info);

#define VGA_FB_PHYS 0xA0000
#define VGA_FB_PHYS_LEN 65536

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
				gen_aper->ranges[0].base == VGA_FB_PHYS)
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
MODULE_LICENSE("GPL");

void __init l_setup_vga(void)
{
	boot_info_t *boot_info = &bootblock_virt->info;
#ifdef CONFIG_VT
#ifdef CONFIG_VGA_CONSOLE
	struct device_node *root;
	const char *model = "";
#endif
#ifdef CONFIG_DUMMY_CONSOLE
	conswitchp = &dummy_con;
#endif
#ifdef CONFIG_VGA_CONSOLE
	if (memblock_is_region_memory(VGA_FB_PHYS, VGA_FB_PHYS_LEN)) {
		pr_info("Legacy VGA MMIO range routes to system memory.");
		return;
	}

	root = of_find_node_by_path("/");
	of_property_read_string(root, "model", &model);
	/* tablet displays garbage */
	if (!strcmp(model, "e1c+,mcst,e1cmt,tablet")) {
		of_node_put(root);
		return;
	}
	of_node_put(root);
	conswitchp = &vga_con;
#endif	/*CONFIG_VGA_CONSOLE*/
#endif /*CONFIG_VT*/
	if (boot_info->vga_mode != 0xe2) /* new boot */
		screen_info.orig_video_mode = boot_info->vga_mode;
}

#define L_MAC_SAVENUM 1
#if (L_MAC_SAVENUM)
#define L_MAC_MAX 32
static int l_mac_last_n = 0;
static unsigned char l_mac_addr5[L_MAC_MAX] = {-1};
static char l_mac_bus_name[L_MAC_MAX][50] = { {0} };
#endif
static unsigned char l_base_mac_addr[6] = {0};
char *mcst_mb_name;
EXPORT_SYMBOL(mcst_mb_name);

int l_set_ethernet_macaddr(struct pci_dev *pdev, char *macaddr)
{
	static int l_cards_without_mac = 1;
	static int assigned_predefined_address = 0;
	static raw_spinlock_t	my_spinlock =
		__RAW_SPIN_LOCK_UNLOCKED(my_spinlock);
	int i;
	for (i = 0; i < 6; i++) {
		macaddr[i] = l_base_mac_addr[i];
	}
	if (pdev && (((pdev->vendor == PCI_VENDOR_ID_ELBRUS &&
                pdev->device == 0x4d45) ||
                (pdev->vendor == PCI_VENDOR_ID_MCST_TMP &&
                pdev->device == PCI_DEVICE_ID_MCST_ETH)) &&
                (dev_to_node(&pdev->dev) <= 0) &&
                !assigned_predefined_address)) {
                /* It is iohub card. If it's first assign predefined */
                /* address - l_base_mac_addr */
                assigned_predefined_address = 1;
		return 1;
	}
	raw_spin_lock_irq(&my_spinlock);
#if (L_MAC_SAVENUM)
	if (pdev) {
		/* find prev mac for busname */
		macaddr[5] = 0;
		for (i = 0; i < l_mac_last_n; i++) {
			if (0 == strcmp(dev_name(&pdev->dev),
			    l_mac_bus_name[i])) {
				macaddr[5] = l_mac_addr5[i];
				pr_info("Saved MAC[5]:%02X for device %s\n",
					l_mac_addr5[i],
					dev_name(&pdev->dev));
				break;
			}
		}
		if (0 == macaddr[5]) {
			macaddr[5] = (l_base_mac_addr[5] +
				      l_cards_without_mac) & 0xff;
			l_cards_without_mac++;

			/* save mac and busname */
			if (l_mac_last_n < L_MAC_MAX) {
				l_mac_addr5[l_mac_last_n] = macaddr[5];
				strcpy(l_mac_bus_name[l_mac_last_n],
				       dev_name(&pdev->dev));
				pr_info("Save MAC[5]:%02X for device %s\n",
					l_mac_addr5[l_mac_last_n],
					l_mac_bus_name[l_mac_last_n]);
				l_mac_last_n += 1;
			}
		}
	} else {
		macaddr[5] += l_cards_without_mac & 0xff;
		l_cards_without_mac++;
	}
#else
	macaddr[5] += l_cards_without_mac & 0xff;
	l_cards_without_mac++;
#endif
	raw_spin_unlock_irq(&my_spinlock);
	return 0;
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
	u64 machine_mac_addr;
	if (get_long_option(&str, &machine_mac_addr)) {
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

int __init l_setup_arch(void)
{
	unsigned char *ma;
	u64 tsc = get_cycles();
	if(!bootblock_virt)
		return -1;

	/* Random ticks after booting */
	add_device_randomness(&tsc, sizeof(tsc));
	/* Some info from boot */
	add_device_randomness(bootblock_virt->info.bios.boot_ver,
			      strlen(bootblock_virt->info.bios.boot_ver));
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
			GET_MB_TYPE_NAME(bootblock_virt->info.bios.mb_type);
	}

	register_early_dump_console();
	return 0;
}
