#ifndef __ASM_PARAVIRT_EPIC_H
#define __ASM_PARAVIRT_EPIC_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <asm/paravirt/pv_ops.h>

/*
 * Basic functions accessing virtual CEPICs on guest.
 */

static inline unsigned int pv_epic_read_w(unsigned int reg)
{
	return pv_epic_ops.epic_read_w(reg);
}

static inline void pv_epic_write_w(unsigned int reg, unsigned int v)
{
	pv_epic_ops.epic_write_w(reg, v);
}

static inline unsigned long pv_epic_read_d(unsigned int reg)
{
	return pv_epic_ops.epic_read_d(reg);
}

static inline void pv_epic_write_d(unsigned int reg, unsigned long v)
{
	pv_epic_ops.epic_write_d(reg, v);
}

static inline unsigned int boot_pv_epic_read_w(unsigned int reg)
{
	return BOOT_PARAVIRT_EPIC_READ_W(reg);
}

static inline void boot_pv_epic_write_w(unsigned int reg, unsigned int v)
{
	BOOT_PARAVIRT_EPIC_WRITE_W(reg, v);
}

#ifdef	CONFIG_PARAVIRT_GUEST

static inline void epic_write_w(unsigned int reg, unsigned int v)
{
	pv_epic_write_w(reg, v);
}

static inline unsigned int epic_read_w(unsigned int reg)
{
	return pv_epic_read_w(reg);
}

static inline void epic_write_d(unsigned int reg, unsigned long v)
{
	pv_epic_write_d(reg, v);
}

static inline unsigned long epic_read_d(unsigned int reg)
{
	return pv_epic_read_w(reg);
}

static inline void boot_epic_write_w(unsigned int reg, unsigned int v)
{
	boot_pv_epic_write_w(reg, v);
}

static inline unsigned int boot_epic_read_w(unsigned int reg)
{
	return boot_pv_epic_read_w(reg);
}
#endif	/* CONFIG_PARAVIRT_GUEST */

#endif	/* __KERNEL__ */

#endif	/* __ASM_PARAVIRT_EPIC_H */
