#ifndef L_HVC_CONSOLE_H
#define L_HVC_CONSOLE_H

#include <asm/kvm/guest/hvc_l.h>

#ifdef	CONFIG_EARLY_VIRTIO_CONSOLE
extern int boot_hvc_l_cons_init(unsigned long console_base);
extern void boot_hvc_l_raw_putc(unsigned char c);
extern bool early_virtio_cons_enabled;
#define	boot_early_virtio_cons_enabled	\
		boot_get_vo_value(early_virtio_cons_enabled)
#else	/* !CONFIG_EARLY_VIRTIO_CONSOLE */
#define	early_virtio_cons_enabled	false
#define	boot_early_virtio_cons_enabled	false
#endif	/* CONFIG_EARLY_VIRTIO_CONSOLE */

#ifdef CONFIG_HVC_L
extern __init struct console *hvc_l_early_cons_init(int idx);
extern void hvc_l_raw_putc(unsigned char c);
#else	/* !CONFIG_HVC_L */
static inline struct console *hvc_l_early_cons_init(int idx)
{
	return NULL;
}
#endif	/* CONFIG_HVC_L */

#endif	/* L_HVC_CONSOLE_H */
