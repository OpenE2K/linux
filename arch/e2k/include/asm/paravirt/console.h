
#ifndef	_ASM_E2K_PARAVIRT_CONSOLE_H_
#define	_ASM_E2K_PARAVIRT_CONSOLE_H_

#ifdef __KERNEL__

#ifndef __ASSEMBLY__

#include <linux/types.h>

#ifdef	CONFIG_KVM_GUEST
#include <asm/kvm/guest/console.h>
#include <asm/pv_info.h>

static inline void
pv_virt_console_dump_putc(char c)
{
	if (!paravirt_enabled())
		native_virt_console_dump_putc(c);
	else
		kvm_virt_console_dump_putc(c);
}
#else	/* ! CONFIG_KVM_GUEST */
 #error "Unknown virtualization type"
#endif	/* CONFIG_KVM_GUEST */

#ifdef	CONFIG_PARAVIRT_GUEST
/* it is paravirtualized guest and host kernel */
static inline void
virt_console_dump_putc(char c)
{
	pv_virt_console_dump_putc(c);
}
#endif	/* CONFIG_PARAVIRT_GUEST */

#endif /* __ASSEMBLY__ */

#endif  /* __KERNEL__ */
#endif  /* _ASM_E2K_PARAVIRT_CONSOLE_H_ */
