/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef	_E2K_CONSOLE_H_
#define	_E2K_CONSOLE_H_

#ifdef __KERNEL__

#ifndef __ASSEMBLY__
#include <linux/init.h>
#include <asm/types.h>
#include <stdarg.h>
#include <asm/cpu_regs.h>
#include <asm/machdep.h>
#include <asm-l/console.h>

#include <linux/types.h>
#include <asm/kvm/hvc-console.h>

static inline void
kvm_virt_console_dump_putc(char c)
{
#if	defined(CONFIG_HVC_L) && defined(CONFIG_EARLY_VIRTIO_CONSOLE)
	if (early_virtio_cons_enabled)
		hvc_l_raw_putc(c);
#endif	/* CONFIG_HVC_L && CONFIG_EARLY_VIRTIO_CONSOLE */
}

static inline void
native_virt_console_dump_putc(char c)
{
#ifdef	CONFIG_EARLY_VIRTIO_CONSOLE
	if (IS_HV_GM()) {
		/* virtio console is actual only for guest mode */
		kvm_virt_console_dump_putc(c);
	}
#endif	/* CONFIG_EARLY_VIRTIO_CONSOLE */
}

extern void	init_bug(const char *fmt_v, ...);
extern void	init_warning(const char *fmt_v, ...);

static inline void
virt_console_dump_putc(char c)
{
	native_virt_console_dump_putc(c);
}

#endif /* __ASSEMBLY__ */

#endif  /* __KERNEL__ */
#endif  /* _E2K_CONSOLE_H_ */
