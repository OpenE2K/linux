/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#pragma once

#include <asm/cpu_regs_access.h>
#include <linux/irqflags.h>

/* IRQs mask control under local PSR & global UPSR */
#define	BOOT_UPSR_ALL_STI()					\
({								\
	unsigned long last_upsr = BOOT_READ_UPSR_REG_VALUE();	\
	unsigned long cur_upsr;					\
	cur_upsr = last_upsr | (UPSR_IE | UPSR_NMIE);		\
	BOOT_WRITE_UPSR_REG_VALUE(cur_upsr);			\
})
#define	BOOT_UPSR_ALL_CLI()					\
({								\
	unsigned long last_upsr = BOOT_READ_UPSR_REG_VALUE();	\
	unsigned long cur_upsr;					\
	cur_upsr = last_upsr & ~(UPSR_IE | UPSR_NMIE);		\
	BOOT_WRITE_UPSR_REG_VALUE(cur_upsr);			\
})
#define	BOOT_UPSR_ALL_SAVE_AND_CLI(flags)			\
({								\
	flags = BOOT_READ_UPSR_REG_VALUE();			\
	BOOT_WRITE_UPSR_REG_VALUE(flags & ~(UPSR_IE | UPSR_NMIE)); \
})
#define	BOOT_UPSR_SAVE(src_upsr)				\
		(src_upsr = BOOT_READ_UPSR_REG_VALUE())
#define	BOOT_UPSR_RESTORE(src_upsr)				\
		BOOT_WRITE_UPSR_REG_VALUE(src_upsr)

/* IRQs mask control under global PSR (UPSR not used) */
#define	BOOT_PSR_ALL_STI()					\
({								\
	unsigned long last_psr = BOOT_READ_PSR_REG_VALUE();	\
	unsigned long cur_psr;					\
	cur_psr = last_psr | (PSR_IE | PSR_NMIE);		\
	BOOT_WRITE_PSR_REG_VALUE(cur_psr);			\
})
#define	BOOT_PSR_ALL_CLI()					\
({								\
	unsigned long last_psr = BOOT_READ_PSR_REG_VALUE();	\
	unsigned long cur_psr;					\
	cur_upsr = last_upsr & ~(PSR_IE | PSR_NMIE);		\
	BOOT_WRITE_PSR_REG_VALUE(cur_psr);			\
})
#define	BOOT_PSR_ALL_SAVE_AND_CLI(flags)			\
({								\
	flags = BOOT_READ_PSR_REG_VALUE();			\
	BOOT_WRITE_PSR_REG_VALUE(flags & ~(PSR_IE | PSR_NMIE));	\
})
#define	BOOT_PSR_SAVE(src_psr)					\
		(src_psr = BOOT_READ_PSR_REG_VALUE())
#define	BOOT_PSR_RESTORE(src_psr)				\
		BOOT_WRITE_PSR_REG_VALUE(src_psr)

/* IRQs mask control in dinamic case */
#define	BOOT_IRQ_ALL_STI() \
		((unlikely(IS_IRQ_MASK_GLOBAL())) ? \
			BOOT_PSR_ALL_STI() : BOOT_UPSR_ALL_STI())
#define	BOOT_IRQ_ALL_CLI() \
		((unlikely(IS_IRQ_MASK_GLOBAL())) ? \
			BOOT_PSR_ALL_CLI() : BOOT_UPSR_ALL_CLI())
#define	BOOT_IRQ_ALL_SAVE_AND_CLI(flags) \
		((unlikely(IS_IRQ_MASK_GLOBAL())) ? \
			BOOT_PSR_ALL_SAVE_AND_CLI(flags) : \
				BOOT_UPSR_ALL_SAVE_AND_CLI(flags))
#define	BOOT_IRQ_SAVE(src_irq) \
		((unlikely(IS_IRQ_MASK_GLOBAL())) ? \
			BOOT_PSR_SAVE(src_irq) : BOOT_UPSR_SAVE(src_irq))
#define	BOOT_IRQ_RESTORE(src_irq) \
		((unlikely(IS_IRQ_MASK_GLOBAL())) ? \
			BOOT_PSR_RESTORE(src_irq) : BOOT_UPSR_RESTORE(src_irq))

#define boot_raw_all_irq_enable()	BOOT_IRQ_ALL_STI()
#define boot_raw_all_irq_disable()	BOOT_IRQ_ALL_CLI()
#define boot_raw_all_irq_save(x)	BOOT_IRQ_ALL_SAVE_AND_CLI(x)
#define boot_raw_all_irq_restore(x)	BOOT_IRQ_RESTORE(x)

#define	BOOT_IRQ_BUG()	({BOOT_BUG("Do not use UPSR to control IRQs mask " \
				 "for global PSR interrupts mask mode\n"); \
			unreachable(); })

#define	BOOT_NATIVE_SWITCH_IRQ_TO_UPSR() \
		((unlikely(IS_IRQ_MASK_GLOBAL())) ? BOOT_IRQ_BUG() : \
			BOOT_NATIVE_WRITE_PSR_REG_VALUE(AW(E2K_KERNEL_PSR_ENABLED)))

#define	BOOT_SWITCH_IRQ_TO_UPSR() \
		((unlikely(IS_IRQ_MASK_GLOBAL())) ? BOOT_IRQ_BUG() : \
			BOOT_WRITE_PSR_REG_VALUE(AW(E2K_KERNEL_PSR_ENABLED))
