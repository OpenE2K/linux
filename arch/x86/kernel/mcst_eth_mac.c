#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/pci_ids.h>
#include <asm/setup.h>

static unsigned char l_base_mac_addr[6] = {0};


static int __init machine_mac_addr_setup(char *str)
{
	char *cur = str;
	int i;
	for (i = 0; i < 6; i++) {
		l_base_mac_addr[i] =
			(unsigned char)simple_strtoull(cur, &cur, 16);
		if (*cur != ':') {
			break;
		}
		cur++;
	}
	pr_info("MCST_base_mac_addr = %02x:%02x:%02x:%02x:%02x:%02x\n",
		l_base_mac_addr[0],
		l_base_mac_addr[1],
		l_base_mac_addr[2],
		l_base_mac_addr[3],
		l_base_mac_addr[4],
		l_base_mac_addr[5]);
	return 0;
}
__setup("mcst_mac=", machine_mac_addr_setup);

int l_set_ethernet_macaddr(struct pci_dev *pdev, char *macaddr)
{
	static raw_spinlock_t   my_spinlock =
		__RAW_SPIN_LOCK_UNLOCKED(my_spinlock);
	static int l_cards_without_mac = 1;
	int i;
	for (i = 0; i < 6; i++) {
		macaddr[i] = l_base_mac_addr[i];
	}
	raw_spin_lock_irq(&my_spinlock);
	macaddr[5] += l_cards_without_mac & 0xff;
	l_cards_without_mac ++;
	raw_spin_unlock_irq(&my_spinlock);
	return 0;
}
EXPORT_SYMBOL(l_set_ethernet_macaddr);


