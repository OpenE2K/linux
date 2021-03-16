/*
 * boot-time mmu_context.h support
 */

#ifndef _E2K_P2V_BOOT_MMU_CONTEXT_H_
#define _E2K_P2V_BOOT_MMU_CONTEXT_H_

#include <linux/types.h>

#include <asm/mmu_regs.h>
#include <asm/page.h>
#include <asm/mmu_regs_access.h>
#include <asm/mm_hooks.h>

/*
 * Set kernel MMU state
 */

static inline void boot_native_set_kernel_MMU_state_before(void)
{
	e2k_addr_t root_base = MMU_KERNEL_PPTB;

	E2K_WAIT_ALL;

	BOOT_WRITE_OSCUIR_REG_VALUE(0);
	BOOT_WRITE_OSCUTD_REG_VALUE((unsigned long) boot_kernel_CUT);

	if (MMU_IS_SEPARATE_PT()) {
		e2k_core_mode_t core_mode;

#ifndef	CONFIG_PARAVIRT_GUEST
		BUILD_BUG_ON(MMU_SEPARATE_KERNEL_VAB != PAGE_OFFSET);
#endif	/* ! CONFIG_PARAVIRT_GUEST */
		BOOT_WRITE_MMU_OS_VPTB(MMU_SEPARATE_KERNEL_VPTB);
		BOOT_WRITE_MMU_OS_PPTB(root_base);
		BOOT_WRITE_MMU_CONT(MMU_KERNEL_CONTEXT);
		/* set user PT to kernel PT too/ as initial state */
		BOOT_WRITE_MMU_U_VPTB(MMU_SEPARATE_USER_VPTB);
		BOOT_WRITE_MMU_U_PPTB(root_base);

		/*
		 * How to enable separate virt spaces:
		 * 1) On phys. memory set OS_VAB = 0
		 * 2) Set CORE_MODE.sep_virt_space = 1
		 * 3) Enable virtual memory in MMU_CR
		 * 4) Jump out from short address by calling any function
		 * by its absolute virtual address
		 * 5) Set proper virtual OS_VAB
		 */
		BOOT_WRITE_MMU_OS_VAB(0UL);
		core_mode.CORE_MODE_reg = BOOT_READ_CORE_MODE_REG_VALUE();
		core_mode.CORE_MODE_sep_virt_space = 1;
		BOOT_WRITE_CORE_MODE_REG_VALUE(core_mode.CORE_MODE_reg);
	} else {
		BOOT_WRITE_MMU_U_VPTB(MMU_UNITED_KERNEL_VPTB);
		BOOT_WRITE_MMU_U_PPTB(root_base);
		BOOT_WRITE_MMU_CONT(MMU_KERNEL_CONTEXT);
	}
	E2K_WAIT_ALL;
}

static inline void boot_native_set_kernel_MMU_state_after(void)
{
	E2K_WAIT_ALL;
	BOOT_WRITE_OSCUTD_REG_VALUE((unsigned long) kernel_CUT);
	if (MMU_IS_SEPARATE_PT()) {
		BOOT_WRITE_MMU_OS_VAB(MMU_SEPARATE_KERNEL_VAB);
	}
	E2K_WAIT_ALL;
}

#if	!defined(CONFIG_PARAVIRT_GUEST) && !defined(CONFIG_KVM_GUEST_KERNEL)
/* it is native kernel without any virtualization */
/* it is native host kernel with virtualization support */

static inline void boot_set_kernel_MMU_state_before(void)
{
	boot_native_set_kernel_MMU_state_before();
}

static inline void boot_set_kernel_MMU_state_after(void)
{
	boot_native_set_kernel_MMU_state_after();
}

#elif	defined(CONFIG_KVM_GUEST_KERNEL)
/* it is pure guest kernel (not paravirtualized based on pv_ops) */
#include <asm/kvm/guest/boot_mmu_context.h>
#endif	/* ! CONFIG_PARAVIRT_GUEST && ! CONFIG_KVM_GUEST_KERNEL */

#endif	/* _E2K_P2V_BOOT_MMU_CONTEXT_H_ */
