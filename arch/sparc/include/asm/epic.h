#ifndef __ASM_E90S_EPIC_H
#define __ASM_E90S_EPIC_H

#ifdef __KERNEL__
#include <asm/io.h>


static inline unsigned get_current_epic_core_priority(void)
{
	return current_thread_info()->epic_core_priority;
}

static inline void set_current_epic_core_priority(unsigned p)
{
	current_thread_info()->epic_core_priority = p;
}

static inline void epic_write_w(unsigned int reg, unsigned int v)
{
	writel_asi(v, reg, ASI_EPIC);
}

static inline unsigned int epic_read_w(unsigned int reg)
{
	return readl_asi(reg, ASI_EPIC);
}

static inline void epic_write_d(unsigned int reg, unsigned long v)
{
	writeq_asi(v, reg, ASI_EPIC);
}

static inline unsigned long epic_read_d(unsigned int reg)
{
	return readq_asi(reg, ASI_EPIC);
}

#include <asm-l/epic.h>

#endif	/* __KERNEL__ */
#endif	/* __ASM_E90S_EPIC_H */
