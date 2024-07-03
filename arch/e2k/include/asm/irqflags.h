/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _E2K_IRQFLAGS_H_
#define _E2K_IRQFLAGS_H_

#ifndef __ASSEMBLY__

#ifndef _LINUX_TRACE_IRQFLAGS_H
# error "Do not include <asm/irqflags.h> directly; use <linux/irqflags.h> instead."
#endif

#include <asm/system.h>

/*
 * There are two registers to control interrupts (enable/disable)
 *
 * The main register is privileged register PSR,
 *
 * the seconde is nonprivileged UPSR.
 *
 * PSR bits should enable interrupts and enable user interrupts to use UPSR
 * as control interrupts register.
 *
 * Principal difference between two registers is scope. UPSR is global
 * register: its scope is all execution, if some function enables/disables
 * interrupts in UPSR and returns to caller then caller will have enabled/
 * disabled interrupts as well. PSR is local register: its scope is current
 * function, and all invoked functions inherit its PSR state, but if invoked
 * function changes PSR and returns, then current function (caller) will see
 * own unchanged PSR state.
 *
 * (PSR is saved by call operation and is restored by return operation from
 * chine registers).
 *
 * So in PSR case, in particular, if interrupts are enabled/disabled
 * by some function call, then it is an error - interrupts enable/disable
 * state will be unchanged. But it is not error in UPSR case.
 *
 * Interrupts control using PSR requires structured kernel organization and
 * it can be permited only inheritance of interrupts enable/disable state
 * (from caller to invoked function) and it cannot be permited return of
 * interrupts enable/disable state (to caller)
 *
 * There is doubt that we should use interrupts control under UPSR
 *
 *
 * PSR and UPSR bits are used to enable and disable interrupts.
 *
 * PSR bits are used while:
 *	- A user process executes;
 *	- Trap or interrupt occures on user or kernel process, hardware
 * disables interrupts mask in PSR and PSR becomes main register to control
 * interrupts. Trap handler switches control from PSR register to UPSR
 * in the appropriate point and all following trap handling is done under
 * UPSR control;
 *	- Trap handler returns control from UPSR to PSR in the appropriate
 * point of trap handling end. Return from trap handler (DONE) restores
 * PSR from CR register and recovers interrupts control type in the trap point;
 *	- System call is same as trap (see above);
 *	- System call end is same as trap handler end (see above);
 *	- Switch from kernel process to user (exec() and signal handler)
 * is same as trap handler end. Before return to user function kernel sets
 * control under PSR and (only for signal handler) after return from user
 * recovers control under UPSR.
 *
 * Kernel cannot use standard macros, functions to enable / disable
 * interrupts same as local_irq_xxx() spin_lock_irq_xxx() ... while
 * interrupts are controled by PSR.
 *
 * UPSR bits are used by kernel while:
 *	Kernel jumpstart (system call #12) set UPSR register in the
 * initial state (where interrupts are disabled) and switches
 * control from PSR register to UPSR; From this point kernel runs
 * (except cases listed above for PSR) under UPSR interrupt bits
 */
#define	NATIVE_SWITCH_IRQ_TO_UPSR_MASK_REG() \
do { \
	BUG_ON(IS_IRQ_MASK_GLOBAL()); \
	NATIVE_WRITE_PSR_IRQ_BARRIER(AW(E2K_KERNEL_PSR_LOC_IRQ_ENABLED)); \
} while (false)

#define	NATIVE_RETURN_IRQ_TO_PSR_LOC_IRQ() \
do { \
	BUG_ON(IS_IRQ_MASK_GLOBAL()); \
	NATIVE_WRITE_PSR_IRQ_BARRIER(AW(E2K_KERNEL_PSR_LOC_IRQ_DISABLED_ALL)); \
} while (false)

#define	SWITCH_IRQ_TO_UPSR_MASK_REG() \
		WRITE_PSR_IRQ_BARRIER(AW(E2K_KERNEL_PSR_LOC_IRQ_ENABLED))

#define	SWITCH_IRQ_TO_MASK_REG(set_cr1_lo) \
do { \
	BUG_ON(IS_IRQ_MASK_GLOBAL()); \
	if (set_cr1_lo) { \
		e2k_cr1_lo_t cr1_lo = READ_CR1_LO_REG(); \
		AS(cr1_lo).ie = 1; \
		AS(cr1_lo).nmie = 1; \
		AS(cr1_lo).uie = 1; \
		AS(cr1_lo).unmie = 1; \
		WRITE_CR1_LO_REG(cr1_lo); \
	} \
 \
	SWITCH_IRQ_TO_UPSR_MASK_REG(); \
} while (false)

#define	BOOT_NATIVE_SWITCH_IRQ_TO_UPSR_MASK_REG() \
		BOOT_NATIVE_WRITE_PSR_REG_VALUE(AW(E2K_KERNEL_PSR_LOC_IRQ_ENABLED))

#define	BOOT_SWITCH_IRQ_TO_UPSR_MASK_REG() \
		BOOT_WRITE_PSR_REG_VALUE(AW(E2K_KERNEL_PSR_LOC_IRQ_ENABLED))

#define	NATIVE_SET_USER_INITIAL_UPSR_LOC_IRQ() \
({ \
	BUG_ON(IS_IRQ_MASK_GLOBAL()); \
	NATIVE_RETURN_IRQ_TO_PSR_LOC_IRQ(); \
	NATIVE_WRITE_UPSR_REG(E2K_USER_INITIAL_UPSR); \
})

#define	NATIVE_SET_USER_INITIAL_UPSR_GLOB_IRQ() \
({ \
	BUG_ON(!IS_IRQ_MASK_GLOBAL()); \
	NATIVE_WRITE_UPSR_REG(E2K_USER_INITIAL_UPSR); \
})

#define	NATIVE_SET_USER_INITIAL_UPSR() \
		((IS_IRQ_MASK_GLOBAL()) ? NATIVE_SET_USER_INITIAL_UPSR_GLOB_IRQ() : \
					  NATIVE_SET_USER_INITIAL_UPSR_LOC_IRQ())

#define	UPSR_LOC_IRQ_STI() \
({ \
	BUG_ON(IS_IRQ_MASK_GLOBAL()); \
	condition_collect_disable_interrupt_ticks( \
			READ_UPSR_REG_VALUE() & ~UPSR_IE); \
	WRITE_UPSR_IRQ_BARRIER(AW(E2K_KERNEL_UPSR_LOC_IRQ_ENABLED)); \
})

#define	UPSR_LOC_IRQ_CLI() \
({ \
	BUG_ON(IS_IRQ_MASK_GLOBAL()); \
	WRITE_UPSR_IRQ_BARRIER(AW(E2K_KERNEL_UPSR_LOC_IRQ_DISABLED)); \
	condition_mark_disable_interrupt_ticks(1); \
})

#define	UPSR_LOC_IRQ_SAVE_AND_CLI() \
({ \
	unsigned long __flags = READ_UPSR_REG_VALUE(); \
	BUG_ON(IS_IRQ_MASK_GLOBAL()); \
	WRITE_UPSR_IRQ_BARRIER(AW(E2K_KERNEL_UPSR_LOC_IRQ_DISABLED)); \
	condition_mark_disable_interrupt_ticks(1); \
	__flags; \
})

#define	UPSR_LOC_IRQ_SAVE()	READ_UPSR_REG_VALUE()

#define	PSR_LOC_IRQ_STI() \
({ \
	BUG_ON(IS_IRQ_MASK_GLOBAL()); \
	condition_collect_disable_interrupt_ticks( \
			READ_PSR_REG_VALUE() & ~PSR_IE); \
	WRITE_PSR_IRQ_BARRIER(AW(E2K_KERNEL_PSR_LOC_IRQ_ENABLED)); \
})

#define	PSR_LOC_IRQ_CLI() \
({ \
	BUG_ON(IS_IRQ_MASK_GLOBAL()); \
	WRITE_PSR_IRQ_BARRIER(AW(E2K_KERNEL_PSR_LOC_IRQ_DISABLED)); \
	condition_mark_disable_interrupt_ticks(1); \
})

#define	PSR_LOC_IRQ_SAVE_AND_CLI() \
({ \
	unsigned long __flags = READ_PSR_REG_VALUE(); \
	BUG_ON(IS_IRQ_MASK_GLOBAL()); \
	WRITE_PSR_IRQ_BARRIER(AW(E2K_KERNEL_PSR_LOC_IRQ_DISABLED)); \
	condition_mark_disable_interrupt_ticks(1); \
	__flags; \
})

#define	PSR_GLOB_IRQ_STI() \
({ \
	BUG_ON(!IS_IRQ_MASK_GLOBAL()); \
	condition_collect_disable_interrupt_ticks( \
			READ_PSR_REG_VALUE() & ~PSR_IE); \
	WRITE_PSR_IRQ_BARRIER(AW(E2K_KERNEL_PSR_GLOB_IRQ_ENABLED)); \
})

#define	PSR_GLOB_IRQ_CLI() \
({ \
	BUG_ON(!IS_IRQ_MASK_GLOBAL()); \
	WRITE_PSR_IRQ_BARRIER(AW(E2K_KERNEL_PSR_GLOB_IRQ_DISABLED)); \
	condition_mark_disable_interrupt_ticks(1); \
})

#define	PSR_GLOB_IRQ_SAVE_AND_CLI() \
({ \
	unsigned long __flags = READ_PSR_REG_VALUE(); \
	BUG_ON(!IS_IRQ_MASK_GLOBAL()); \
	WRITE_PSR_IRQ_BARRIER(AW(E2K_KERNEL_PSR_GLOB_IRQ_DISABLED)); \
	condition_mark_disable_interrupt_ticks(1); \
	__flags; \
})

#define	PSR_IRQ_STI() \
		((IS_IRQ_MASK_GLOBAL()) ? PSR_GLOB_IRQ_STI() : PSR_LOC_IRQ_STI())
#define	PSR_IRQ_CLI() \
		((IS_IRQ_MASK_GLOBAL()) ? PSR_GLOB_IRQ_CLI() : PSR_LOC_IRQ_CLI())
#define	PSR_IRQ_SAVE_AND_CLI() \
		((IS_IRQ_MASK_GLOBAL()) ? PSR_GLOB_IRQ_SAVE_AND_CLI() : \
					  PSR_LOC_IRQ_SAVE_AND_CLI())
#define	PSR_IRQ_SAVE() \
		READ_PSR_REG_VALUE()

#define	IRQ_STI() \
		((IS_IRQ_MASK_GLOBAL()) ? PSR_GLOB_IRQ_STI() : UPSR_LOC_IRQ_STI())
#define	IRQ_CLI() \
		((IS_IRQ_MASK_GLOBAL()) ? PSR_GLOB_IRQ_CLI() : UPSR_LOC_IRQ_CLI())
#define	IRQ_SAVE_AND_CLI() \
		((IS_IRQ_MASK_GLOBAL()) ? PSR_GLOB_IRQ_SAVE_AND_CLI() : \
					  UPSR_LOC_IRQ_SAVE_AND_CLI())
#define	IRQ_SAVE() \
		((IS_IRQ_MASK_GLOBAL()) ? PSR_IRQ_SAVE() : \
					  UPSR_LOC_IRQ_SAVE())

/*
 * nmi_* versions work only with non-maskbale ones interrupts.
 */

#define upsr_nmi_loc_irqs_disabled() \
		((READ_UPSR_REG_VALUE() & UPSR_NMIE) == 0)
#define upsr_nmi_loc_irqs_disabled_flags(flags) \
		((flags & UPSR_NMIE) == 0)

#define psr_nmi_glob_irqs_disabled() \
		((READ_PSR_REG_VALUE() & PSR_NMIE) == 0)
#define psr_nmi_glob_irqs_disabled_flags(flags) \
		((flags & PSR_NMIE) == 0)

#define nmi_irqs_disabled() \
		((IS_IRQ_MASK_GLOBAL()) ? psr_nmi_glob_irqs_disabled() : \
					  upsr_nmi_loc_irqs_disabled())
#define nmi_irqs_disabled_flags(flags) \
		((IS_IRQ_MASK_GLOBAL()) ? psr_nmi_glob_irqs_disabled_flags(flags) : \
					  upsr_nmi_loc_irqs_disabled_flags(flags))

#define	NATIVE_UPSR_LOC_IRQ_NMI_SAVE_AND_CLI(flags)		\
({								\
	flags = NATIVE_NV_READ_UPSR_REG_VALUE();		\
	NATIVE_WRITE_UPSR_IRQ_BARRIER(flags & ~UPSR_NMIE);	\
	condition_mark_disable_interrupt_ticks(1);		\
})
#define	NATIVE_UPSR_LOC_IRQ_NMI_STI(flags)			\
({								\
	NATIVE_WRITE_UPSR_IRQ_BARRIER((flags) | UPSR_NMIE);	\
	condition_mark_disable_interrupt_ticks(0);		\
})
#define	NATIVE_UPSR_LOC_IRQ_ALL_SAVE_AND_CLI(flags)		\
({								\
	flags = NATIVE_NV_READ_UPSR_REG_VALUE();		\
	NATIVE_WRITE_UPSR_IRQ_BARRIER(				\
			AW(E2K_KERNEL_UPSR_LOC_IRQ_DISABLED_ALL)); \
	condition_mark_disable_interrupt_ticks(1);              \
})

#define	NATIVE_PSR_GLOB_IRQ_NMI_SAVE_AND_CLI(flags)		\
({								\
	flags = NATIVE_NV_READ_PSR_REG_VALUE();			\
	NATIVE_WRITE_PSR_IRQ_BARRIER(flags & ~PSR_NMIE);	\
	condition_mark_disable_interrupt_ticks(1);		\
})
#define	NATIVE_PSR_GLOB_IRQ_NMI_STI(flags)			\
({								\
	NATIVE_WRITE_PSR_IRQ_BARRIER((flags) | PSR_NMIE);	\
	condition_mark_disable_interrupt_ticks(0);		\
})
#define	NATIVE_PSR_GLOB_IRQ_ALL_SAVE_AND_CLI(flags)		\
({								\
	flags = NATIVE_NV_READ_PSR_REG_VALUE();			\
	NATIVE_WRITE_PSR_IRQ_BARRIER(				\
			AW(E2K_KERNEL_PSR_GLOB_IRQ_DISABLED_ALL)); \
	condition_mark_disable_interrupt_ticks(1);              \
})

#define	NATIVE_IRQ_NMI_SAVE_AND_CLI(flags) \
		((IS_IRQ_MASK_GLOBAL()) ? \
			NATIVE_PSR_GLOB_IRQ_NMI_SAVE_AND_CLI(flags) : \
			NATIVE_UPSR_LOC_IRQ_NMI_SAVE_AND_CLI(flags))
#define	NATIVE_IRQ_NMI_STI(flags) \
		((IS_IRQ_MASK_GLOBAL()) ? \
			NATIVE_PSR_GLOB_IRQ_NMI_STI(flags) : \
			NATIVE_UPSR_LOC_IRQ_NMI_STI(flags))
#define	NATIVE_IRQ_ALL_SAVE_AND_CLI(flags) \
		((IS_IRQ_MASK_GLOBAL()) ? \
			NATIVE_PSR_GLOB_IRQ_ALL_SAVE_AND_CLI(flags) : \
			NATIVE_UPSR_LOC_IRQ_ALL_SAVE_AND_CLI(flags))

/*
 * all_* versions work on all interrupts including
 * both maskable and non-maskbale ones.
 */

#define	UPSR_LOC_IRQ_ALL_STI() \
({ \
	condition_collect_disable_interrupt_ticks( \
		READ_UPSR_REG_VALUE() & ~UPSR_IE & ~UPSR_NMIE); \
	WRITE_UPSR_IRQ_BARRIER(AW(E2K_KERNEL_UPSR_LOC_IRQ_ENABLED)); \
})

#define	UPSR_LOC_IRQ_ALL_CLI() \
({ \
	WRITE_UPSR_IRQ_BARRIER(AW(E2K_KERNEL_UPSR_LOC_IRQ_DISABLED_ALL)); \
	condition_mark_disable_interrupt_ticks(1); \
})

#define	SAVE_LOC_IRQ_AND_ALL_CLI(flags) \
({ \
	u64 __uasc_flags = READ_UPSR_REG_VALUE(); \
	WRITE_UPSR_IRQ_BARRIER(AW(E2K_KERNEL_UPSR_LOC_IRQ_DISABLED_ALL)); \
	condition_mark_disable_interrupt_ticks(1); \
	(flags) = __uasc_flags; \
})

#define	PSR_LOC_IRQ_ALL_STI() \
({ \
	condition_collect_disable_interrupt_ticks( \
			READ_PSR_REG_VALUE() & ~PSR_IE & ~PSR_NMIE); \
	WRITE_PSR_IRQ_BARRIER(AW(E2K_KERNEL_PSR_LOC_IRQ_ENABLED)); \
})

#define	PSR_LOC_IRQ_ALL_CLI() \
({ \
	WRITE_PSR_IRQ_BARRIER(AW(E2K_KERNEL_PSR_LOC_IRQ_DISABLED_ALL)); \
	condition_mark_disable_interrupt_ticks(1); \
})

#define	PSR_GLOB_IRQ_ALL_STI() \
({ \
	condition_collect_disable_interrupt_ticks( \
		READ_PSR_REG_VALUE() & ~PSR_IE & ~PSR_NMIE); \
	WRITE_PSR_IRQ_BARRIER(AW(E2K_KERNEL_PSR_GLOB_IRQ_ENABLED)); \
})

#define	PSR_GLOB_IRQ_ALL_CLI() \
({ \
	WRITE_PSR_IRQ_BARRIER(AW(E2K_KERNEL_PSR_GLOB_IRQ_DISABLED_ALL)); \
	condition_mark_disable_interrupt_ticks(1); \
})

#define	SAVE_GLOB_IRQ_AND_ALL_CLI(flags) \
({ \
	u64 __uasc_flags = READ_PSR_REG_VALUE(); \
	WRITE_PSR_IRQ_BARRIER(AW(E2K_KERNEL_PSR_GLOB_IRQ_DISABLED_ALL)); \
	condition_mark_disable_interrupt_ticks(1); \
	(flags) = __uasc_flags; \
})

#define	PSR_IRQ_ALL_STI() \
		((IS_IRQ_MASK_GLOBAL()) ? PSR_GLOB_IRQ_ALL_STI() : PSR_LOC_IRQ_ALL_STI())
#define	PSR_IRQ_ALL_CLI() \
		((IS_IRQ_MASK_GLOBAL()) ? PSR_GLOB_IRQ_ALL_CLI() : PSR_LOC_IRQ_ALL_CLI())

#define	IRQ_ALL_STI() \
		((IS_IRQ_MASK_GLOBAL()) ? PSR_GLOB_IRQ_ALL_STI() : \
					  UPSR_LOC_IRQ_ALL_STI())
#define	IRQ_ALL_CLI() \
		((IS_IRQ_MASK_GLOBAL()) ? PSR_GLOB_IRQ_ALL_CLI() : \
					  UPSR_LOC_IRQ_ALL_CLI())
#define	IRQ_SAVE_AND_ALL_CLI(irq_flags) \
		((IS_IRQ_MASK_GLOBAL()) ? \
			SAVE_GLOB_IRQ_AND_ALL_CLI(irq_flags) : \
			SAVE_LOC_IRQ_AND_ALL_CLI(irq_flags))
#define	SAVE_IRQ_AND_ALL_CLI(psr_flags, upsr_flags) \
		((IS_IRQ_MASK_GLOBAL()) ? \
			SAVE_GLOB_IRQ_AND_ALL_CLI(psr_flags) : \
			SAVE_LOC_IRQ_AND_ALL_CLI(upsr_flags))

#define psr_irqs_disabled_flags(flags)		(((flags) & PSR_IE) == 0)
#define upsr_loc_irqs_disabled_flags(flags)	(((flags) & UPSR_IE) == 0)
#define loc_irqs_under_upsr_flags(psr_flags)	(((psr_flags) & PSR_UIE) != 0)

#define irq_reg_disabled_flags(irq_flags) \
		((IS_IRQ_MASK_GLOBAL()) ? \
			psr_irqs_disabled_flags(irq_flags) : \
			upsr_loc_irqs_disabled_flags(irq_flags))

#define	psr_and_upsr_loc_irqs_disabled_flags(psr_flags, upsr_flags)	\
({									\
	bool ret;							\
	if (psr_irqs_disabled_flags(psr_flags)) {			\
		ret = true;						\
	} else if (loc_irqs_under_upsr_flags(psr_flags)) {		\
		ret = upsr_loc_irqs_disabled_flags(upsr_flags);		\
	} else {							\
		ret = false;						\
	}								\
	ret;								\
})
#define	psr_glob_irqs_disabled_flags(psr_flags)				\
({									\
	bool ret;							\
	BUG_ON(loc_irqs_under_upsr_flags(psr_flags));			\
	if (psr_irqs_disabled_flags(psr_flags)) {			\
		ret = true;						\
	} else {							\
		ret = false;						\
	}								\
	ret;								\
})
#define	psr_and_upsr_irqs_disabled_flags(psr_flags, upsr_flags)	\
		((IS_IRQ_MASK_GLOBAL()) ? \
			psr_glob_irqs_disabled_flags(psr_flags) : \
			psr_and_upsr_loc_irqs_disabled_flags(psr_flags, upsr_flags))

#define upsr_all_loc_irqs_disabled_flags(flags) \
		((flags & (UPSR_IE | UPSR_NMIE)) == 0)
#define upsr_all_loc_irqs_disabled() \
		upsr_all_loc_irqs_disabled_flags(READ_UPSR_REG_VALUE())

#define psr_all_irqs_disabled_flags(flags) \
		((flags & (PSR_IE | PSR_NMIE)) == 0)
#define psr_all_irqs_enabled_flags(flags) \
		((flags & (PSR_IE | PSR_NMIE)) == (PSR_IE | PSR_NMIE))
#define psr_all_irqs_disabled() \
		psr_all_irqs_disabled_flags(READ_PSR_REG_VALUE())
#define all_loc_irqs_under_upsr_flags(psr_flags)	\
		(((psr_flags) & (PSR_UIE | PSR_UNMIE)) != 0)
#define	psr_and_upsr_all_loc_irqs_disabled_flags(psr_flags, upsr_flags)	\
({									\
	bool ret;							\
	if (psr_all_irqs_disabled_flags(psr_flags)) {			\
		ret = true;						\
	} else if (all_loc_irqs_under_upsr_flags(psr_flags)) {		\
		ret = upsr_all_loc_irqs_disabled_flags(upsr_flags);	\
	} else {							\
		ret = false;						\
	}								\
	ret;								\
})
#define	psr_all_glob_irqs_disabled_flags(psr_flags)			\
({									\
	bool ret;							\
	BUG_ON(!IS_IRQ_MASK_GLOBAL());					\
	BUG_ON(all_loc_irqs_under_upsr_flags(psr_flags));		\
	if (psr_all_irqs_disabled_flags(psr_flags)) {			\
		ret = true;						\
	} else {							\
		ret = false;						\
	}								\
	ret;								\
})
#define	psr_and_upsr_all_irqs_disabled_flags(psr_flags, upsr_flags)	\
		((IS_IRQ_MASK_GLOBAL()) ? \
			psr_all_glob_irqs_disabled_flags(psr_flags) : \
			psr_and_upsr_all_loc_irqs_disabled_flags(psr_flags, \
								 upsr_flags))

#define all_irqs_disabled_flags(flags) \
		((IS_IRQ_MASK_GLOBAL()) ? psr_all_irqs_disabled_flags(flags) : \
					  upsr_all_loc_irqs_disabled_flags(flags))
#define all_irqs_disabled() \
		((IS_IRQ_MASK_GLOBAL()) ? psr_all_irqs_disabled() : \
					  upsr_all_loc_irqs_disabled())

#define psr_irqs_disabled()	\
		psr_irqs_disabled_flags(READ_PSR_REG_VALUE())
#define upsr_loc_irqs_disabled()	\
		upsr_loc_irqs_disabled_flags(READ_UPSR_REG_VALUE())

#define	psr_and_upsr_loc_irqs_disabled()			\
({								\
	unsigned long psr = READ_PSR_REG_VALUE();		\
	unsigned long upsr = READ_UPSR_REG_VALUE();		\
								\
	psr_and_upsr_loc_irqs_disabled_flags(psr, upsr);	\
})

#define	psr_and_upsr_all_loc_irqs_disabled()			\
({								\
	unsigned long psr = READ_PSR_REG_VALUE();		\
	unsigned long upsr = READ_UPSR_REG_VALUE();		\
								\
	psr_and_upsr_all_loc_irqs_disabled_flags(psr, upsr);	\
})

#define	psr_and_upsr_glob_irqs_disabled()	psr_irqs_disabled()

#define	psr_and_upsr_all_glob_irqs_disabled()	psr_all_irqs_disabled()

#define	psr_and_upsr_irqs_disabled() \
		((IS_IRQ_MASK_GLOBAL()) ? psr_and_upsr_glob_irqs_disabled() : \
					  psr_and_upsr_loc_irqs_disabled())
#define	psr_and_upsr_all_irqs_disabled() \
		((IS_IRQ_MASK_GLOBAL()) ? psr_and_upsr_all_glob_irqs_disabled() : \
					  psr_and_upsr_all_loc_irqs_disabled())

#define __raw_all_loc_irqs_disabled()	psr_and_upsr_all_loc_irqs_disabled()

#define native_psr_irqs_disabled()	\
		psr_irqs_disabled_flags(NATIVE_NV_READ_PSR_REG_VALUE())

#define	psr_and_upsr_nm_loc_irqs_disabled() \
({ \
	bool ret; \
	unsigned long psr = READ_PSR_REG_VALUE(); \
	if ((psr & PSR_NMIE) == 0) { \
		ret = true; \
	} else if (psr & PSR_UNMIE) { \
		ret = !(READ_UPSR_REG_VALUE() & UPSR_NMIE); \
	} else { \
		ret = false; \
	} \
	ret; \
})
#define	psr_nm_glob_irqs_disabled() \
({ \
	unsigned long psr_flags = READ_PSR_REG_VALUE(); \
	bool ret; \
	BUG_ON(!IS_IRQ_MASK_GLOBAL()); \
	BUG_ON(all_loc_irqs_under_upsr_flags(psr_flags)); \
	if ((psr_flags & PSR_NMIE) == 0) { \
		ret = true; \
	} else { \
		ret = false; \
	} \
	ret; \
})
#define	psr_and_upsr_nm_irqs_disabled()	\
		((IS_IRQ_MASK_GLOBAL()) ? \
			psr_nm_glob_irqs_disabled() : \
			psr_and_upsr_nm_loc_irqs_disabled())

#ifndef CONFIG_DEBUG_IRQ
#define __raw_loc_irqs_disabled()	upsr_loc_irqs_disabled()
#else
#define __raw_loc_irqs_disabled()	psr_and_upsr_loc_irqs_disabled()
#endif	/* ! CONFIG_DEBUG_IRQ */
#define __raw_glob_irqs_disabled()	psr_irqs_disabled()

#define __raw_loc_irqs_disabled_flags(flags)	upsr_loc_irqs_disabled_flags(flags)
#define __raw_glob_irqs_disabled_flags(flags)	psr_irqs_disabled_flags(flags)

#define __raw_irqs_disabled() \
		((IS_IRQ_MASK_GLOBAL()) ? __raw_glob_irqs_disabled() : \
					  __raw_loc_irqs_disabled())
#define __raw_irqs_disabled_flags(flags) \
		((IS_IRQ_MASK_GLOBAL()) ? __raw_glob_irqs_disabled_flags(flags) : \
					  __raw_loc_irqs_disabled_flags(flags))

#define SAVE_CURR_TIME_SWITCH_TO
#define CALCULATE_TIME_SWITCH_TO

#ifdef CONFIG_CLI_CHECK_TIME

typedef struct cli_info {
	long cli;
	long max_cli;
	long max_cli_cl;
	long max_cli_ip;

	long gcli;
	long max_gcli;
	long max_gcli_cl;
	long max_gcli_ip;
	
} cli_info_t;

typedef struct tt0_info {
	long max_tt0_prolog;
	long max_tt0_cl;
} tt0_info_t;

extern cli_info_t 	cli_info[];
extern tt0_info_t 	tt0_info[];
extern int 		cli_info_needed;
extern void 		tt0_prolog_ticks(long ticks);

#define Cli_cl	 	cli_info[raw_smp_processor_id()].cli
#define Max_cli  	cli_info[raw_smp_processor_id()].max_cli
#define Max_cli_cl  	cli_info[raw_smp_processor_id()].max_cli_cl
#define Max_cli_ip  	cli_info[raw_smp_processor_id()].max_cli_ip
#define Cli_irq	 	cli_info[raw_smp_processor_id()].irq

#define Gcli_cl 	cli_info[raw_smp_processor_id()].gcli
#define Max_gcli  	cli_info[raw_smp_processor_id()].max_gcli
#define Max_gcli_cl  	cli_info[raw_smp_processor_id()].max_gcli_cl
#define Max_gcli_ip  	cli_info[raw_smp_processor_id()].max_gcli_ip

#define Max_tt0_prolog 	tt0_info[raw_smp_processor_id()].max_tt0_prolog
#define Max_tt0_cl 	tt0_info[raw_smp_processor_id()].max_tt0_cl

#define	e2k_loc_irq_cli() \
{ \
	bool __save_time = cli_info_needed && !__raw_loc_irqs_disabled(); \
	UPSR_LOC_IRQ_CLI(); \
	if (__save_time) \
		Cli_cl = READ_CLKR_REG_VALUE(); \
}

#define	e2k_loc_irq_sti() \
{ \
	if (Cli_cl && __raw_loc_irqs_disabled() && \
		(Max_cli < READ_CLKR_REG_VALUE() - Cli_cl)) { \
		Max_cli = READ_CLKR_REG_VALUE() - Cli_cl; \
		Max_cli_cl = Cli_cl; \
		Max_cli_ip = READ_IP_REG_VALUE(); \
	} \
	UPSR_LOC_IRQ_STI(); \
}

#define	e2k_glob_irq_cli() \
{ \
	bool __save_time = cli_info_needed && !__raw_glob_irqs_disabled(); \
	PSR_GLOB_IRQ_CLI(); \
	if (__save_time) \
		Cli_cl = READ_CLKR_REG_VALUE(); \
}

#define	e2k_glob_irq_sti() \
{ \
	if (Cli_cl && __raw_glob_irqs_disabled() && \
		(Max_cli < READ_CLKR_REG_VALUE() - Cli_cl)) { \
		Max_cli = READ_CLKR_REG_VALUE() - Cli_cl; \
		Max_cli_cl = Cli_cl; \
		Max_cli_ip = READ_IP_REG_VALUE(); \
	} \
	PSR_GLOB_IRQ_STI(); \
}

/* check_cli() works under cli() but we want to check time of cli() */

#define	check_cli() \
{ \
	if (cli_info_needed) { \
		Cli_cl = READ_CLKR_REG_VALUE(); \
	} \
}

#define	sti_loc_irq_return() \
{ \
	if (cli_info_needed && __raw_loc_irqs_disabled() && \
		(Max_cli < READ_CLKR_REG_VALUE() - Cli_cl)) { \
		Max_cli = READ_CLKR_REG_VALUE() - Cli_cl; \
		Max_cli_cl = Cli_cl; \
		Max_cli_ip = READ_IP_REG_VALUE(); \
	} \
}
#else /* above CONFIG_CLI_CHECK_TIME */
#define	e2k_loc_irq_cli()	UPSR_LOC_IRQ_CLI()
#define	e2k_loc_irq_sti()	UPSR_LOC_IRQ_STI()
#define check_cli()
#define	sti_loc_irq_return()

#define	e2k_glob_irq_cli()	PSR_GLOB_IRQ_CLI()
#define	e2k_glob_irq_sti()	PSR_GLOB_IRQ_STI()
#define check_cli()
#define	sti_glob_irq_return()
#endif /* CONFIG_CLI_CHECK_TIME */

#define	e2k_sti()	((IS_IRQ_MASK_GLOBAL()) ? e2k_glob_irq_sti() : \
						  e2k_loc_irq_sti())
#define	e2k_cli()	((IS_IRQ_MASK_GLOBAL()) ? e2k_glob_irq_cli() : \
						  e2k_loc_irq_cli())
#define	sti_return()	\
do { \
	if (IS_IRQ_MASK_GLOBAL()) { \
		sti_glob_irq_return(); \
	} else { \
		sti_loc_irq_return(); \
	} \
} while (false)


/* Normal irq operations: disable maskable interrupts only,
 * but enable both maskable and non-maskable interrupts. */

#define arch_local_irq_enable()		e2k_sti()
#define arch_local_irq_disable()	e2k_cli()

#define arch_local_irq_save()		IRQ_SAVE_AND_CLI()
#define arch_local_irq_restore(x)	IRQ_RESTORE(x)

#define arch_local_save_flags()		IRQ_SAVE()

#define arch_irqs_disabled_flags(x)	__raw_irqs_disabled_flags(x)
#define arch_irqs_disabled()		__raw_irqs_disabled()

/* nmi_irq_*() - the same as above, but checks only non-maskable interrupts. */

#define raw_nmi_irqs_disabled_flags(x)	nmi_irqs_disabled_flags(x)
#define raw_nmi_irqs_disabled()		nmi_irqs_disabled()

/* all_irq_*() - the same as above, but enables, disables and checks
 * both non-maskable and maskable interrupts. */

#define raw_all_irq_enable()		IRQ_ALL_STI()
#define raw_all_irq_disable()		IRQ_ALL_CLI()

#define raw_all_irq_save(x)		IRQ_SAVE_AND_ALL_CLI(x)
#define raw_all_irq_restore(x)		IRQ_RESTORE(x)

#define raw_all_irqs_disabled_flags(x)	all_irqs_disabled_flags(x)
#define raw_all_irqs_disabled()		all_irqs_disabled()

#define all_irq_enable() \
	do { trace_hardirqs_on(); raw_all_irq_enable(); } while (0)

#define all_irq_disable() \
	do { raw_all_irq_disable(); trace_hardirqs_off(); } while (0)

#define all_irq_save(flags)				\
	do {						\
		typecheck(unsigned long, flags);	\
		raw_all_irq_save(flags);		\
		trace_hardirqs_off();			\
	} while (0)

#define all_irq_restore(flags)					\
	do {							\
		typecheck(unsigned long, flags);		\
		if (raw_all_irqs_disabled_flags(flags)) {	\
			raw_all_irq_restore(flags);		\
			trace_hardirqs_off();			\
		} else {					\
			trace_hardirqs_on();			\
			raw_all_irq_restore(flags);		\
		}						\
	} while (0)

/*
 * Used in the idle loop
 */
static inline void arch_safe_halt(void)
{
}

#endif /* __ASSEMBLY__ */
#endif /* _E2K_IRQFLAGS_H_ */
