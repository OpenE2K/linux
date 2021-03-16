/*
 * guest boot-time mmu_context.h support
 */

#ifndef _E2K_KVM_GUEST_BOOT_MMU_CONTEXT_H_
#define _E2K_KVM_GUEST_BOOT_MMU_CONTEXT_H_

#include <linux/types.h>

#include <asm/mmu_regs.h>
#include <asm/page.h>
#include <asm/mmu_regs_access.h>
#include <asm/mm_hooks.h>

/*
 * Set guest kernel MMU state
 */

extern void boot_kvm_set_kernel_MMU_state_before(void);
extern void boot_kvm_set_kernel_MMU_state_after(void);

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is pure guest kernel (not paravirtualized based on pv_ops) */

static inline void boot_set_kernel_MMU_state_before(void)
{
	boot_kvm_set_kernel_MMU_state_before();
}

static inline void boot_set_kernel_MMU_state_after(void)
{
	boot_kvm_set_kernel_MMU_state_after();
}
#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif	/* _E2K_KVM_GUEST_BOOT_MMU_CONTEXT_H_ */
