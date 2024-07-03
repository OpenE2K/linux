/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef __BOOT_PIC_H
#define __BOOT_PIC_H

/*
 * Statically choose between APIC and EPIC basic functions, based on
 * CONFIG_BOOT_EPIC (defined in arch/e2k/boot/Makefile)
 */

#include <asm/apic.h>
#include <asm/epic.h>

#include "bios/printk.h"
#include <asm/e2k_sic.h>
#include "e2k_sic.h"
#include <asm/sic_regs.h>

/* Boot */
#ifdef	CONFIG_SMP
extern unsigned int all_pic_ids[];
#endif

static inline void native_epic_write_w(unsigned int reg, unsigned int v)
{
	NATIVE_WRITE_MAS_W(EPIC_DEFAULT_PHYS_BASE + reg, v, MAS_IOADDR);
}

static inline unsigned int native_epic_read_w(unsigned int reg)
{
	return NATIVE_READ_MAS_W(EPIC_DEFAULT_PHYS_BASE + reg, MAS_IOADDR);
}

static inline void native_epic_write_d(unsigned int reg, unsigned long v)
{
	NATIVE_WRITE_MAS_D(EPIC_DEFAULT_PHYS_BASE + reg, v, MAS_IOADDR);
}

static inline unsigned long native_epic_read_d(unsigned int reg)
{
	return NATIVE_READ_MAS_D(EPIC_DEFAULT_PHYS_BASE + reg, MAS_IOADDR);
}

static inline void native_apic_write(unsigned int reg, unsigned int v)
{
	NATIVE_WRITE_MAS_W(APIC_DEFAULT_PHYS_BASE + reg, v, MAS_IOADDR);
}

static inline unsigned int native_apic_read(unsigned int reg)
{
	return NATIVE_READ_MAS_W(APIC_DEFAULT_PHYS_BASE + reg, MAS_IOADDR);
}

#ifdef	CONFIG_BOOT_EPIC

#define	PIC_DEFAULT_PHYS_BASE	EPIC_DEFAULT_PHYS_BASE
#define	IO_PIC_DEFAULT_PHYS_BASE	IO_EPIC_DEFAULT_PHYS_BASE

extern void debug_epic_startup(int cpu, unsigned int value, unsigned long addr);
static inline void debug_pic_startup(int cpu, unsigned int value,
					unsigned long addr)
{
	debug_epic_startup(cpu, value, addr);
}

extern void boot_setup_cepic(int cpu);
static inline void setup_local_pic(int cpu)
{
	boot_setup_cepic(cpu);
}

extern void boot_print_cepic(void);
static inline void print_local_pic(void)
{
	boot_print_cepic();
}

#define NATIVE_READ_PIC_ID()	native_read_epic_id()
static inline unsigned int native_read_epic_id(void)
{
	return cepic_id_full_to_short(native_epic_read_w(CEPIC_ID));
}

/* No need for EOI at boot-time */
#define	native_pic_write_eoi()	do {} while (0)

static inline unsigned int native_pic_read_esr(void)
{
	return native_epic_read_w(CEPIC_ESR) & CEPIC_ESR_BIT_MASK;
}
static inline unsigned int native_pic_read_icr_busy(void)
{
	union cepic_icr reg;

	reg.raw = (unsigned long)native_epic_read_w(CEPIC_ICR);
	return reg.bits.stat;
}

static inline void native_pic_reset_esr(void)
{
	native_epic_write_w(CEPIC_ESR, 0);
}

static inline void native_pic_send_startup(int picid, unsigned long addr)
{
	union cepic_icr icr;

	/* Send startup IPI via ICR */
	icr.raw = 0;
	icr.bits.dst = cepic_id_short_to_full(picid);
	icr.bits.dlvm = CEPIC_ICR_DLVM_STARTUP;
	icr.bits.vect = addr >> 12;
	native_epic_write_d(CEPIC_ICR, icr.raw);
}

static inline unsigned int native_pic_read_nm(void)
{
	return native_epic_read_w(CEPIC_PNMIRR);
}

static inline void native_pic_reset_nm(void)
{
	native_epic_write_w(CEPIC_PNMIRR, CEPIC_PNMIRR_BIT_MASK);
}

static inline unsigned int native_pic_read_version(void)
{
	return NATIVE_GET_SICREG(prepic_version, 0, 0);
}

#else	/* CONFIG_BOOT_EPIC */

#define	PIC_DEFAULT_PHYS_BASE	APIC_DEFAULT_PHYS_BASE
#define	IO_PIC_DEFAULT_PHYS_BASE	IO_APIC_DEFAULT_PHYS_BASE

#define	NATIVE_READ_PIC_ID()	native_read_apic_id()
static inline unsigned int native_read_apic_id(void)
{
	return GET_APIC_ID(native_apic_read(APIC_ID));
}

extern void debug_apic_startup(int cpu, unsigned int value, unsigned long addr);
static inline void debug_pic_startup(int cpu, unsigned int value,
					unsigned long addr)
{
	debug_apic_startup(cpu, value, addr);
}

extern void setup_local_apic(int cpu);
static inline void setup_local_pic(int cpu)
{
	setup_local_apic(cpu);
}

extern void print_local_apic(void);
static inline void print_local_pic(void)
{
	print_local_apic();
}

static inline unsigned int native_pic_read_esr(void)
{
	return native_apic_read(APIC_ESR) & 0xEF;
}

static inline unsigned int native_pic_read_icr_busy(void)
{
	return native_apic_read(APIC_ICR) & APIC_ICR_BUSY;
}

static inline void native_pic_reset_esr(void)
{
	native_apic_write(APIC_ESR, 0);
}

static inline void native_pic_send_startup(int picid, unsigned long addr)
{
	/* Target chip */
	native_apic_write(APIC_ICR2, SET_APIC_DEST_FIELD(picid));

	/* Boot on the stack */
	/* Kick the second */
	native_apic_write(APIC_ICR, APIC_DM_STARTUP
				| (addr >> 12));
}

static inline unsigned int native_pic_read_nm(void)
{
	return native_apic_read(APIC_NM);
}

static inline void native_pic_reset_nm(void)
{
	native_apic_write(APIC_NM, APIC_NM_BIT_MASK);
}

static inline void native_pic_write_eoi(void)
{
	native_apic_write(APIC_EOI, 0x0);
}

static inline unsigned int native_pic_read_version(void)
{
	unsigned int apic_version;

	apic_version = GET_APIC_VERSION(native_apic_read(APIC_LVR));
	if (apic_version == 0)
		apic_version = APIC_VERSION;
	return apic_version;
}

#endif	/* CONFIG_BOOT_EPIC */
#endif	/* __BOOT_PIC_H */
