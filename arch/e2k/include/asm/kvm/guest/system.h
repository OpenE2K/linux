/*
 * KVM guest processor and processes support
 *
 * Copyright (C) 2014 MCST
 */

#ifndef _E2K_KVM_GUEST_SYSTEM_H_
#define _E2K_KVM_GUEST_SYSTEM_H_

#ifndef __ASSEMBLY__

#include <linux/types.h>
#include <asm/kvm/cpu_regs_access.h>

/*
 * Guest kernel case assumption is that the host emulates hardware updates
 * of CPU registers state on trap or system call, in particular PSR state.
 * Hardware disables interrupt masks and switch interrupts control to PSR,
 * so host sets VCPU registers (copy into memory) in same state.
 *	Trap handler should switch interrupts control from PSR to UPSR
 * previously it should set UPSR to initial state for kernel with disabled
 * interrupts (so UPSR disable interrupts)
 *	If trap occurs on guest kernel, then interrupts should be enabled
 * and control should be under UPSR. So do not restore control under PSR and
 * restore only UPSR state.
 *	Guest kernel cannot use 'done' instruction and restore PSR state
 * saved into CR1.lo register, it should be done by host.
 */

#define	KVM_INIT_KERNEL_UPSR_REG(irq_en, nmirq_dis)			\
({									\
	e2k_upsr_t __upsr_val;						\
									\
	__upsr_val = nmirq_dis ? E2K_KERNEL_INITIAL_UPSR_WITH_DISABLED_NMI \
				:					\
				E2K_KERNEL_INITIAL_UPSR;		\
	KVM_WRITE_UPSR_REG_VALUE(__upsr_val.UPSR_reg);			\
})
#define	BOOT_KVM_INIT_KERNEL_UPSR_REG(irq_en, nmirq_dis)		\
({									\
	e2k_upsr_t __upsr_val;						\
									\
	__upsr_val = nmirq_dis ? E2K_KERNEL_INITIAL_UPSR_WITH_DISABLED_NMI \
				:					\
				E2K_KERNEL_INITIAL_UPSR;		\
	BOOT_KVM_WRITE_UPSR_REG_VALUE(__upsr_val.UPSR_reg);		\
})
#define	KVM_INIT_USER_UPSR_REG()	\
		KVM_WRITE_UPSR_REG_VALUE(E2K_USER_INITIAL_UPSR.UPSR_reg)
#define	KVM_INIT_USER_PSR()		\
		KVM_ATOMIC_WRITE_PSR_REG_VALUE(E2K_USER_INITIAL_PSR.PSR_reg, \
						false)	/* IRQs under UPSR */

#define	KVM_DO_SAVE_PSR_REG(psr_reg)					\
		(psr_reg.PSR_reg = KVM_READ_PSR_REG_VALUE())
#define	KVM_DO_SAVE_UPSR_REG(upsr_reg)					\
		(upsr_reg.UPSR_reg = KVM_READ_UPSR_REG_VALUE())
#define	KVM_DO_SAVE_PSR_UPSR_REGS(psr_reg, upsr_reg, under_upsr)	\
({									\
	KVM_DO_SAVE_PSR_REG((psr_reg));					\
	KVM_DO_SAVE_UPSR_REG((upsr_reg));				\
	under_upsr = kvm_get_vcpu_state()->irqs_under_upsr;		\
})
#define	KVM_DO_RESTORE_PSR_REG(psr_reg)					\
		(KVM_WRITE_PSR_REG_VALUE(psr_reg.PSR_reg))
#define	KVM_DO_RESTORE_UPSR_REG(upsr_reg)				\
		(KVM_WRITE_UPSR_REG_VALUE(upsr_reg.UPSR_reg))

#define	KVM_SWITCH_IRQ_TO_UPSR(disable_sge) \
	KVM_WRITE_PSR_REG_VALUE(AW(E2K_KERNEL_PSR_ENABLED))

#define	BOOT_KVM_SWITCH_IRQ_TO_UPSR() \
	BOOT_KVM_WRITE_PSR_REG_VALUE(AW(E2K_KERNEL_PSR_ENABLED))

#define	KVM_DO_RETURN_IRQ_TO_PSR(under_upsr, disable_sge) \
	KVM_ATOMIC_WRITE_PSR_REG_VALUE(AW(E2K_KERNEL_PSR_DISABLED), under_upsr)

#define	KVM_RETURN_IRQ_TO_PSR(under_upsr) \
	KVM_DO_RETURN_IRQ_TO_PSR(under_upsr, false)

#define	KVM_SET_USER_INITIAL_UPSR(upsr)					\
({									\
	KVM_RETURN_IRQ_TO_PSR(false);					\
	KVM_WRITE_UPSR_REG(upsr);					\
})

#define	KVM_CHECK_IRQ_UNDER_PSR(psr_reg, under_upsr)			\
({									\
	if (psr_reg.PSR_ie || psr_reg.PSR_uie || !psr_reg.PSR_pm) {	\
		pr_err("#U1 PSR 0x%x under upsr %d\n",			\
			psr_reg.PSR_reg, under_upsr);			\
		psr_reg.PSR_ie = 0;					\
		psr_reg.PSR_uie = 0;					\
		psr_reg.PSR_pm = 1;					\
		WARN_ON(true);						\
	}								\
	if (under_upsr) {						\
		pr_err("#U2 PSR 0x%x under upsr %d\n",			\
			psr_reg.PSR_reg, under_upsr);			\
		kvm_get_vcpu_state()->irqs_under_upsr = false;		\
		WARN_ON(true);						\
	}								\
})
#define	KVM_CHECK_IRQ_UNDER_UPSR(psr_reg, upsr_reg, under_upsr, has_irqs) \
({									\
	if (psr_reg.PSR_ie || !psr_reg.PSR_pm ||			\
			!psr_reg.PSR_uie && under_upsr) {		\
		pr_err("#K1 PSR 0x%x UPSR 0x%x under upsr %d\n",	\
			psr_reg.PSR_reg, upsr_reg.UPSR_reg,		\
			under_upsr);					\
		psr_reg.PSR_ie = 0;					\
		psr_reg.PSR_pm = 1;					\
		if (under_upsr)						\
			psr_reg.PSR_uie = 1;				\
		KVM_WRITE_PSR_REG_VALUE(psr_reg.PSR_reg);		\
		WARN_ON(true);						\
	}								\
	if (psr_reg.PSR_uie && !under_upsr) {				\
		E2K_LMS_HALT_OK;					\
		pr_err("#K2 PSR 0x%x UPSR 0x%x under upsr %d\n",	\
			psr_reg.PSR_reg, upsr_reg.UPSR_reg,		\
			under_upsr);					\
		kvm_get_vcpu_state()->irqs_under_upsr = true;		\
		WARN_ON(true);						\
	}								\
	if (!upsr_reg.UPSR_ie && under_upsr &&	has_irqs) {		\
		pr_err("#K3 PSR 0x%x UPSR 0x%x under upsr %d "		\
			"has IRQs %d\n",				\
			psr_reg.PSR_reg, upsr_reg.UPSR_reg,		\
			under_upsr, has_irqs);				\
		upsr_reg.UPSR_ie = 1;					\
		KVM_WRITE_UPSR_REG_VALUE(upsr_reg.UPSR_reg);		\
		WARN_ON(true);						\
	}								\
})
#define	KVM_CHECK_IRQ_STATE(psr_reg, upsr_reg, under_upsr,		\
				has_irqs, user_mode)			\
do {									\
	if (user_mode) {						\
		KVM_CHECK_IRQ_UNDER_PSR(psr_reg, under_upsr);		\
	} else {							\
		KVM_CHECK_IRQ_UNDER_UPSR(psr_reg, upsr_reg,		\
						under_upsr, has_irqs);	\
	}								\
} while (false)

#define	KVM_RETURN_TO_KERNEL_UPSR(upsr_reg) \
({ \
	if (IS_HV_GM()) { \
		e2k_cr1_lo_t cr1_lo; \
		unsigned psr; \
\
		cr1_lo = NATIVE_NV_READ_CR1_LO_REG(); \
		psr = cr1_lo.CR1_lo_psr; \
		KVM_WRITE_SW_PSR_REG_VALUE(psr); \
		NATIVE_RETURN_IRQ_TO_PSR(); \
	} else { \
		KVM_RETURN_IRQ_TO_PSR(true); \
	} \
	KVM_DO_RESTORE_UPSR_REG(upsr_reg); \
})
#define	KVM_RETURN_TO_INIT_USER_UPSR()					\
({									\
	KVM_INIT_USER_PSR();						\
	KVM_INIT_USER_UPSR_REG();					\
})
#define	KVM_SWITCH_TO_KERNEL_UPSR(psr_reg, upsr_reg, under_upsr,	\
					irq_en, nmirq_dis)		\
({									\
	KVM_DO_SAVE_PSR_UPSR_REGS(psr_reg, upsr_reg, under_upsr);	\
	KVM_DO_SWITCH_TO_KERNEL_UPSR(irq_en, nmirq_dis);		\
	kvm_get_vcpu_state()->irqs_under_upsr = true;			\
})

#define	KVM_DO_SWITCH_TO_KERNEL_UPSR(irq_en, nmirq_dis)	\
		PREFIX_DO_SWITCH_TO_KERNEL_UPSR(KVM, kvm,		\
						irq_en, nmirq_dis)
#define	KVM_RETURN_TO_USER_UPSR(upsr_reg, under_upsr)			\
({									\
	KVM_RETURN_IRQ_TO_PSR(under_upsr);				\
	KVM_DO_RESTORE_UPSR_REG(upsr_reg);				\
})
#define	KVM_SET_KERNEL_UPSR_WITH_DISABLED_NMI()		\
		PREFIX_SET_KERNEL_UPSR_WITH_DISABLED_NMI(KVM)
#define	KVM_SET_KERNEL_UPSR(disable_sge)	\
		PREFIX_SET_KERNEL_UPSR(KVM, disable_sge)
#define	BOOT_KVM_SET_KERNEL_UPSR()		\
		BOOT_PREFIX_SET_KERNEL_UPSR(KVM)

#define	kvm_psr_and_upsr_irqs_disabled()				\
({									\
	e2k_psr_t psr;							\
	e2k_upsr_t upsr;						\
	bool under_upsr;						\
									\
	KVM_DO_SAVE_PSR_UPSR_REGS(psr, upsr, under_upsr);		\
	psr_and_upsr_irqs_disabled_flags(psr.PSR_reg, upsr.UPSR_reg);	\
})

extern void *kvm_nested_kernel_return_address(int n);

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is pure guest kernel (not paravirtualized) */

#define	INIT_KERNEL_UPSR_REG(irq_en, nmirq_dis)	\
		KVM_INIT_KERNEL_UPSR_REG(irq_en, nmirq_dis)
#define	SET_KERNEL_UPSR(disable_sge)	\
		KVM_SET_KERNEL_UPSR(disable_sge)
#define	BOOT_SET_KERNEL_UPSR()	\
		BOOT_KVM_SET_KERNEL_UPSR()
#define	SET_KERNEL_UPSR_WITH_DISABLED_NMI()	\
		KVM_SET_KERNEL_UPSR_WITH_DISABLED_NMI()
#define	RETURN_TO_KERNEL_UPSR(upsr_reg) \
		KVM_RETURN_TO_KERNEL_UPSR(upsr_reg)

static inline void *
nested_kernel_return_address(int n)
{
	return kvm_nested_kernel_return_address(n);
}

#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif	/* ! __ASSEMBLY__ */
#endif /* _E2K_KVM_GUEST_SYSTEM_H_ */


