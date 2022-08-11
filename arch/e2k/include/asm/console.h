
#ifndef	_E2K_CONSOLE_H_
#define	_E2K_CONSOLE_H_

#ifdef __KERNEL__

#ifndef __ASSEMBLY__
#include <linux/init.h>
#include <asm/types.h>
#include <stdarg.h>
#include <asm/machdep.h>
#include <asm-l/console.h>
#include <asm/kvm/guest/console.h>

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

#if	defined(CONFIG_PARAVIRT_GUEST)
/* it is paravirtualized guest and host kernel */
#include <asm/paravirt/console.h>
#elif	defined(CONFIG_KVM_GUEST_KERNEL)
/* it is pure guest kernel (not paravirtualized based on pv_ops) */
#include <asm/kvm/guest/console.h>
#else	/* ! CONFIG_PARAVIRT_GUEST && ! CONFIG_KVM_GUEST_KERNEL */
/* native kernel or native kernel with virtualization support */
static inline void
virt_console_dump_putc(char c)
{
	native_virt_console_dump_putc(c);
}
#endif	/* CONFIG_PARAVIRT_GUEST */

#endif /* __ASSEMBLY__ */

#endif  /* __KERNEL__ */
#endif  /* _E2K_CONSOLE_H_ */
