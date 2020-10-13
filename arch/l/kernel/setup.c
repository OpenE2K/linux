#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <asm/bootinfo.h>
#include <asm/io.h>

unsigned char l_base_mac_addr[6] = {0};
int l_cards_without_mac = 0;
char *mcst_mb_name;
EXPORT_SYMBOL(mcst_mb_name);
EXPORT_SYMBOL(l_cards_without_mac);
EXPORT_SYMBOL(l_base_mac_addr);

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
int l_setup_arch(void)
{
	unsigned char *ma;
	if(!bootblock_virt)
		return -1;
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
	return 0;
}
