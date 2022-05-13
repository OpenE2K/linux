/*
 * Paravirtualized PV_OPs support
 *
 * Copyright (C) 2016 MCST
 */

#ifndef _E2K_PARAVIRT_SYSTEM_H_
#define _E2K_PARAVIRT_SYSTEM_H_

#ifndef __ASSEMBLY__

#include <linux/types.h>
#include <asm/paravirt/pv_ops.h>
#include <asm/kvm/guest/system.h>

#define	PV_SWITCH_IRQ_TO_UPSR(disable_sge)				\
({									\
	if (!paravirt_enabled()) {					\
		NATIVE_SWITCH_IRQ_TO_UPSR(disable_sge);			\
	} else {							\
		KVM_SWITCH_IRQ_TO_UPSR(disable_sge);			\
	}								\
})
#define	BOOT_PV_SWITCH_IRQ_TO_UPSR(disable_sge)				\
({									\
	if (!boot_paravirt_enabled()) {					\
		BOOT_NATIVE_WRITE_PSR_REG_VALUE(AW(E2K_KERNEL_PSR_ENABLED)); \
	} else {							\
		BOOT_KVM_WRITE_PSR_REG_VALUE(AW(E2K_KERNEL_PSR_ENABLED)); \
	}								\
})
#define	PV_INIT_KERNEL_UPSR_REG(irq_en, nmirq_dis) \
		PREFIX_INIT_KERNEL_UPSR_REG(PV, irq_en, nmirq_dis)
#define	BOOT_PV_INIT_KERNEL_UPSR_REG(irq_en, nmirq_dis) \
		BOOT_PREFIX_INIT_KERNEL_UPSR_REG(PV, irq_en, nmirq_dis)
#define	PV_SET_KERNEL_UPSR_WITH_DISABLED_NMI(disable_sge) \
		PREFIX_SET_KERNEL_UPSR_WITH_DISABLED_NMI(PV, disable_sge)
#define	BOOT_PV_SET_KERNEL_UPSR()	\
		BOOT_PREFIX_SET_KERNEL_UPSR(PV)

static inline void *
pv_nested_kernel_return_address(int n)
{
	return pv_cpu_ops.nested_kernel_return_address(n);
}

#ifdef	CONFIG_PARAVIRT_GUEST
/* it is paravirtualized host and guest kernel */

#define	INIT_KERNEL_UPSR_REG(irq_en, nmirq_dis) \
		PV_INIT_KERNEL_UPSR_REG(irq_en, nmirq_dis)
#define	BOOT_INIT_KERNEL_UPSR_REG(irq_en, nmirq_dis) \
		BOOT_PV_INIT_KERNEL_UPSR_REG(irq_en, nmirq_dis)
#define	SET_KERNEL_UPSR_WITH_DISABLED_NMI(disable_sge) \
		PV_SET_KERNEL_UPSR_WITH_DISABLED_NMI(disable_sge)
#define	BOOT_SET_KERNEL_UPSR()	BOOT_PV_SET_KERNEL_UPSR()

static inline void *
nested_kernel_return_address(int n)
{
	return pv_nested_kernel_return_address(n);
}

#endif	/* CONFIG_PARAVIRT_GUEST */

#endif	/* ! __ASSEMBLY__ */
#endif /* _E2K_PARAVIRT_SYSTEM_H_ */


