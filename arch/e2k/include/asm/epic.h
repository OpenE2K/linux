#ifndef __ASM_E2K_EPIC_H
#define __ASM_E2K_EPIC_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/thread_info.h>
#include <asm/e2k_api.h>
#include <asm/irq.h>
#include <asm/io.h>
#include <asm/p2v/boot_v2p.h>

#ifndef __ASSEMBLY__

void do_sic_error_interrupt(void);

static inline bool cpu_has_epic(void)
{
	if (cpu_has(CPU_FEAT_EPIC))
		return true;
	else
		return false;
}

static inline unsigned get_current_epic_core_priority(void)
{
#ifdef	CONFIG_EPIC
	return current_thread_info()->pt_regs->epic_core_priority;
#else
	return 0;
#endif
}

static inline void set_current_epic_core_priority(unsigned p)
{
#ifdef	CONFIG_EPIC
	current_thread_info()->pt_regs->epic_core_priority = p;
#endif
}

/*
 * Basic functions accessing EPICs.
 */
static inline void epic_write_w(unsigned int reg, u32 v)
{
	boot_writel(v, (void __iomem *) (EPIC_DEFAULT_PHYS_BASE + reg));
}

static inline u32 epic_read_w(unsigned int reg)
{
	return boot_readl((void __iomem *) (EPIC_DEFAULT_PHYS_BASE + reg));
}

static inline void epic_write_d(unsigned int reg, u64 v)
{
	boot_writeq(v, (void __iomem *) (EPIC_DEFAULT_PHYS_BASE + reg));
}

static inline u64 epic_read_d(unsigned int reg)
{
	return boot_readq((void __iomem *) (EPIC_DEFAULT_PHYS_BASE + reg));
}

static inline void boot_epic_write_w(unsigned int reg, u32 v)
{
	epic_write_w(reg, v);
}

static inline u32 boot_epic_read_w(unsigned int reg)
{
	return epic_read_w(reg);
}

static inline void epic_write_guest_w(unsigned int reg, unsigned int v)
{
	epic_write_w(CEPIC_GUEST + reg, v);
}

static inline unsigned int epic_read_guest_w(unsigned int reg)
{
	return epic_read_w(CEPIC_GUEST + reg);
}

static inline void epic_write_guest_d(unsigned int reg, unsigned long v)
{
	epic_write_d(CEPIC_GUEST + reg, v);
}

static inline unsigned long epic_read_guest_d(unsigned int reg)
{
	return epic_read_d(CEPIC_GUEST + reg);
}

#include <asm-l/epic.h>

#endif	/* !(__ASSEMBLY__) */
#endif	/* __KERNEL__ */
#endif	/* __ASM_E2K_EPIC_H */
