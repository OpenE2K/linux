
#ifndef	_ASM_E2K_KVM_GUEST_CONSOLE_H_
#define	_ASM_E2K_KVM_GUEST_CONSOLE_H_

#ifdef __KERNEL__

#ifndef __ASSEMBLY__

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

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is pure guest kernel (not paravirtualized based on pv_ops) */
static inline void
virt_console_dump_putc(char c)
{
	kvm_virt_console_dump_putc(c);
}
#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif /* __ASSEMBLY__ */

#endif  /* __KERNEL__ */
#endif  /* _ASM_E2K_KVM_GUEST_CONSOLE_H_ */
