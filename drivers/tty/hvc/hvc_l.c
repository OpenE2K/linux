/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * l (Elbrus) console driver interface to hvc_console.c based on xen console driver
 */

#include <linux/console.h>
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/virtio_console.h>

#include <asm/kvm/hypercall.h>
#include <asm/kvm/guest/irq.h>
#include <asm/kvm/hvc-console.h>
#include <asm/kvm/guest/io.h>

#include "hvc_console.h"

#undef	DEBUG_EARLY_CONSOLE_MODE
#undef	DebugEC
#define	DEBUG_EARLY_CONSOLE_MODE	0	/* early console debugging */
#define	DebugEC(fmt, args...)						\
({									\
	if (DEBUG_EARLY_CONSOLE_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

static int raw_console_write(const char *str, unsigned int len)
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
static int raw_put_chars(u32 vtermno, const char *str, int len)
{
	return raw_console_write(str, len);
}

#ifdef	CONFIG_EARLY_VIRTIO_CONSOLE
static void early_hvc_write(struct console *con, const char *s,
				unsigned int count)
{
	raw_console_write(s, count);
}
#endif

static int __init hvc_l_cons_init(void)
{
	int ret = ENODEV;

	if (!paravirt_enabled()) {
		DebugEC("early HVC console can be accessibly only "
			"at guest mode\n");
		return ret;
	}

	/* Register as early virtio console */
	ret = virtio_cons_early_init(raw_put_chars);
	if (ret) {
		DebugEC("Could not create early HVC console\n");
	} else {
		DebugEC("HVC Console interface will be used as "
			"early console\n");
	}

	return ret;
}

console_initcall(hvc_l_cons_init);

static unsigned char buffer[512];
static int buf_pos = 0;

void hvc_l_raw_putc(unsigned char c)
{
	buffer[buf_pos] = c;
	buf_pos++;
	if (buf_pos >= sizeof(buffer) || c == '\n') {
		raw_console_write((const char *)buffer, buf_pos);
		buf_pos = 0;
	}
}

#ifdef	CONFIG_EARLY_VIRTIO_CONSOLE
static struct console early_hvc_console = {
	.name = "early-hvc",
	.write = early_hvc_write,
	.flags = CON_BOOT | CON_PRINTBUFFER | CON_ANYTIME,
	.index = -1,
	.device = 0
};
#endif	/* CONFIG_EARLY_VIRTIO_CONSOLE */

__init struct console *hvc_l_early_cons_init(int idx)
{
#ifdef	CONFIG_EARLY_VIRTIO_CONSOLE
	if (!paravirt_enabled()) {
		DebugEC("early HVC console can be accessible only "
			"at guest mode\n");
		return NULL;
	}

	DebugEC("early HVC will be used as early console\n");
	return &early_hvc_console;
#else	/* !CONFIG_EARLY_VIRTIO_CONSOLE */
	return NULL;
#endif	/* CONFIG_EARLY_VIRTIO_CONSOLE */
}
