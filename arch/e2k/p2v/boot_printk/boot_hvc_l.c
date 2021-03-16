/*
 * l (Elbrus) console driver interface to hvc_console.c
 * based on xen console driver
 *
 * (c) 2007 Gerd Hoffmann <kraxel@suse.de>
 * (c) 2013 Salavat Gilyazov <atic@mcst.ru>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */

#include <linux/console.h>
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/virtio_console.h>

#include <asm/kvm/hypercall.h>
#include <asm/kvm/guest/hvc_l.h>
#include <asm/kvm/guest/irq.h>
#include <asm/kvm/hvc-console.h>
#include <asm/kvm/guest/io.h>

#undef	DEBUG_EARLY_CONSOLE_MODE
#undef	DebugBEC
#define	DEBUG_EARLY_CONSOLE_MODE	0	/* early console debugging */
#define	DebugBEC(fmt, args...)						\
({									\
	if (DEBUG_EARLY_CONSOLE_MODE)					\
		do_boot_printk("%s(): " fmt, __func__, ##args);		\
})

bool early_virtio_cons_enabled = false;

static unsigned char buffer[512];
static int buf_pos = 0;
#define	boot_buffer	boot_get_vo_value(buffer)
#define	boot_buf_pos	boot_get_vo_value(buf_pos)

static int boot_raw_console_write(const char *str, int len)
{
	int count = len;

	while (len > 0) {
		int rc = HYPERVISOR_console_io(CONSOLEIO_write, len,
								(char *)str);
		if (rc <= 0)
			break;

		str += rc;
		len -= rc;
	}
	return count - len;
}
void boot_hvc_l_raw_putc(unsigned char c)
{
	unsigned char *cur_buffer = boot_buffer;
	int cur_pos = boot_buf_pos;

	cur_buffer[cur_pos] = c;
	cur_pos++;
	if (cur_pos >= sizeof(buffer) || c == '\n') {
		boot_raw_console_write((const char *)cur_buffer, cur_pos);
		cur_pos = 0;
	}
	boot_buf_pos = cur_pos;
}

int __init boot_hvc_l_cons_init(e2k_addr_t console_base)
{
	if (!boot_paravirt_enabled())
		return -ENODEV;

#ifdef	CONFIG_EARLY_VIRTIO_CONSOLE
	boot_early_virtio_cons_enabled = true;
	DebugBEC("VIRTIO HVC Console interface will be used as "
		"boot console\n");
#endif	/* CONFIG_EARLY_VIRTIO_CONSOLE */
	return 0;
}
