#ifndef __ASM_PARAVIRT_APIC_H
#define __ASM_PARAVIRT_APIC_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <asm/paravirt/pv_ops.h>

/*
 * Basic functions accessing virtual Local APICs on guest.
 */

static inline unsigned int pv_arch_apic_read(unsigned int reg)
{
	return pv_apic_ops.apic_read(reg);
}

static inline void pv_arch_apic_write(unsigned int reg, unsigned int v)
{
	pv_apic_ops.apic_write(reg, v);
}

static inline unsigned int boot_pv_arch_apic_read(unsigned int reg)
{
	return BOOT_PARAVIRT_APIC_READ(reg);
}

static inline void boot_pv_arch_apic_write(unsigned int reg, unsigned int v)
{
	BOOT_PARAVIRT_APIC_WRITE(reg, v);
}

#ifdef	CONFIG_PARAVIRT_GUEST

static inline void arch_apic_write(unsigned int reg, unsigned int v)
{
	pv_arch_apic_write(reg, v);
}

static inline unsigned int arch_apic_read(unsigned int reg)
{
	return pv_arch_apic_read(reg);
}
static inline void boot_arch_apic_write(unsigned int reg, unsigned int v)
{
	boot_pv_arch_apic_write(reg, v);
}

static inline unsigned int boot_arch_apic_read(unsigned int reg)
{
	return boot_pv_arch_apic_read(reg);
}
#endif	/* CONFIG_PARAVIRT_GUEST */

#endif	/* __KERNEL__ */

#endif	/* __ASM_PARAVIRT_APIC_H */
