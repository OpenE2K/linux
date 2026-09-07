/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#pragma once

#include <asm/cpu_regs.h>
#include <linux/irqflags.h>

/* IRQs mask control under local PSR & global UPSR */
#define	BOOT_UPSR_ALL_STI()					\
	boot_write_UPSR_reg((e2k_upsr_t) { .word =		\
		AW(boot_read_UPSR_reg()) | UPSR_IE | UPSR_NMIE });

#define	BOOT_UPSR_ALL_CLI()					\
	boot_write_UPSR_reg((e2k_upsr_t) { .word =		\
		AW(boot_read_UPSR_reg()) & ~(UPSR_IE | UPSR_NMIE) });

#define	BOOT_UPSR_ALL_SAVE_AND_CLI(flags)			\
({								\
	flags = AW(boot_read_UPSR_reg());			\
	boot_write_UPSR_reg((e2k_upsr_t) { .word =		\
			 flags & ~(UPSR_IE | UPSR_NMIE) });	\
})
#define	BOOT_UPSR_SAVE(src_upsr)				\
		(src_upsr = AW(boot_read_UPSR_reg())
#define	BOOT_UPSR_RESTORE(src_upsr)				\
		boot_write_UPSR_reg((e2k_upsr_t) { .word = src_upsr })

/* IRQs mask control under global PSR (UPSR not used) */
#define	BOOT_PSR_ALL_STI()					\
({								\
	e2k_psr_t psr = boot_read_PSR_reg();			\
	psr.ie = 1;						\
	psr.nmie = 1;						\
	write_irq_barrier_PSR_reg(_psr);			\
})
#define	BOOT_PSR_ALL_CLI()					\
({								\
	e2k_psr_t psr = boot_read_PSR_reg();			\
	psr.ie = 1;						\
	psr.nmie = 1;						\
	write_irq_barrier_PSR_reg(_psr);			\
})
#define	BOOT_PSR_ALL_SAVE_AND_CLI(flags)			\
({								\
	e2k_psr_t psr = boot_read_PSR_reg();			\
	flags = AW(psr);					\
	psr.ie = 0;						\
	psr.nmie = 0;						\
	write_irq_barrier_PSR_reg(psr);				\
})
#define	BOOT_PSR_SAVE(src_psr)					\
		(src_psr = AW(boot_read_PSR_reg())
#define	BOOT_PSR_RESTORE(src_psr)				\
		write_irq_barrier_PSR_reg(TOS(e2k_psr_t, src_psr))

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
			boot_native_write_PSR_reg(E2K_KERNEL_PSR_ENABLED))

#define	BOOT_SWITCH_IRQ_TO_UPSR() \
		((unlikely(IS_IRQ_MASK_GLOBAL())) ? BOOT_IRQ_BUG() : \
			write_irq_barrier_PSR_reg(E2K_KERNEL_PSR_ENABLED))
