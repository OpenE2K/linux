/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_L_APIC_H
#define _ASM_L_APIC_H

#include <asm/io.h>
#include "apicdef.h"

struct irq_data;

/*
 * Debugging macros
 */
#define APIC_QUIET   0
#define APIC_VERBOSE 1
#define APIC_DEBUG   2

/* Macros for apic_extnmi which controls external NMI masking */
#define APIC_EXTNMI_BSP		0 /* Default */
#define APIC_EXTNMI_ALL		1
#define APIC_EXTNMI_NONE	2

/*
 * Define the default level of output to be very little
 * This can be turned up by using apic=verbose for more
 * information and apic=debug for _lots_ of information.
 * apic_verbosity is defined in apic.c
 */
#define apic_printk(v, s, a...) do {       \
		if ((v) <= apic_verbosity) \
			printk(s, ##a);    \
	} while (0)


extern int apic_verbosity;


/*
 * Copyright 2004 James Cleverdon, IBM.
 *
 * Generic APIC sub-arch data struct.
 *
 * Hacked for x86-64 by James Cleverdon from i386 architecture code by
 * Martin Bligh, Andi Kleen, James Bottomley, John Stultz, and
 * James Cleverdon.
 */

/*
 * Pointer to the local APIC driver in use on this system (there's
 * always just one such driver in use - the kernel decides via an
 * early probing process which one it picks - and then sticks to it):
 */

static inline void apic_write(unsigned int reg, unsigned int v)
{
	boot_writel(v, (void __iomem *) (APIC_DEFAULT_PHYS_BASE + reg));
}

static inline unsigned int apic_read(unsigned int reg)
{
	return boot_readl((void __iomem *) (APIC_DEFAULT_PHYS_BASE + reg));
}

static inline void apic_eoi(void)
{
	apic_write(APIC_EOI, APIC_EOI_ACK);
}

extern void native_apic_wait_icr_idle(void);
extern u32 native_safe_apic_wait_icr_idle(void);
extern void native_apic_icr_write(u32 low, u32 id);
extern u64 native_apic_icr_read(void);

static inline u64 apic_icr_read(void)
{
	return native_apic_icr_read();
}

static inline void apic_icr_write(u32 low, u32 high)
{
	native_apic_icr_write(low, high);
}

static inline void apic_wait_icr_idle(void)
{
	native_apic_wait_icr_idle();
}

static inline u32 safe_apic_wait_icr_idle(void)
{
	return native_safe_apic_wait_icr_idle();
}

static inline void ack_APIC_irq(void)
{
	/*
	 * ack_APIC_irq() actually gets compiled as a single instruction
	 * ... yummie.
	 */
	apic_eoi();
}

static inline unsigned default_get_apic_id(unsigned long x)
{
	unsigned int ver = GET_APIC_VERSION(apic_read(APIC_LVR));

	if (APIC_XAPIC(ver))
		return (x >> 24) & 0xFF;
	else
		return (x >> 24) & 0x0F;
}

static inline unsigned int read_apic_id(void)
{
	unsigned int reg;

	reg = apic_read(APIC_ID);

	return default_get_apic_id(reg);
}

extern int apic_get_vector(void);

struct msi_msg;
struct irq_cfg;

extern void __irq_msi_compose_msg(struct irq_cfg *cfg, struct msi_msg *msg,
				  bool dmar);


DECLARE_EARLY_PER_CPU_READ_MOSTLY(u16, cpu_to_picid);
/* P2V */

static inline void boot_arch_apic_write(unsigned int reg, unsigned int v)
{
	apic_write(reg, v);
}

static inline unsigned int boot_arch_apic_read(unsigned int reg)
{
	return apic_read(reg);
}

static inline unsigned int boot_apic_is_bsp(void)
{
	return BootStrap(boot_arch_apic_read(APIC_BSP));
}

static inline unsigned int boot_apic_read_id(void)
{
	return GET_APIC_ID(boot_arch_apic_read(APIC_ID));
}

#endif /* _ASM_L_APIC_H */
