#pragma once

#include <asm/cpu_regs_access.h>
#include <linux/irqflags.h>

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

#define boot_raw_all_irq_enable()	BOOT_UPSR_ALL_STI()
#define boot_raw_all_irq_disable()	BOOT_UPSR_ALL_CLI()
#define boot_raw_all_irq_save(x)	BOOT_UPSR_ALL_SAVE_AND_CLI(x)
#define boot_raw_all_irq_restore(x)	BOOT_UPSR_RESTORE(x)

#define	BOOT_NATIVE_SWITCH_IRQ_TO_UPSR() \
	BOOT_NATIVE_WRITE_PSR_REG_VALUE(AW(E2K_KERNEL_PSR_ENABLED))
#define	BOOT_SWITCH_IRQ_TO_UPSR() \
	BOOT_WRITE_PSR_REG_VALUE(AW(E2K_KERNEL_PSR_ENABLED))
