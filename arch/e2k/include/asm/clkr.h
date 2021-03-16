#ifndef _ASM_E2K_CLKR_H
#define _ASM_E2K_CLKR_H

#include <asm/cpu.h>
#include <asm-l/clkr.h>

extern __interrupt u64 fast_syscall_read_clkr(void);

extern u64 last_clkr;
DECLARE_PER_CPU(u64, clkr_offset);

#if	defined(CONFIG_PARAVIRT_GUEST)
/* it is paravirtualized guest and host kernel */
#include <asm/paravirt/clkr.h>
#elif	defined(CONFIG_KVM_GUEST_KERNEL)
/* it is pure guest kernel (not paravirtualized based on pv_ops) */
#include <asm/kvm/guest/clkr.h>
#else	/* ! CONFIG_PARAVIRT_GUEST && ! CONFIG_KVM_GUEST_KERNEL */
/* native kernel with or without virtualization support */
#endif	/* CONFIG_PARAVIRT_GUEST */

#endif	/* _ASM_E2K_CLKR_H */
