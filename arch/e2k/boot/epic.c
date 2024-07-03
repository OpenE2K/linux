/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 *	CEPIC handling
 */

#include <linux/init.h>

#include <linux/mm.h>
#include <linux/irq.h>
#include <linux/types.h>

#include <asm/atomic.h>
#include <asm/head.h>
#include <asm/epic.h>
#include <asm/bootinfo.h>
#include <asm/e2k_debug.h>

#include <asm/e2k_api.h>

#include "boot_io.h"
#include "pic.h"

/**************************** DEBUG DEFINES *****************************/
#undef	DEBUG_BOOT_MODE
#undef	Dprintk
#define	DEBUG_BOOT_MODE		1	/* SMP CPU boot */
#define	Dprintk(fmt, ...)			\
do {						\
	if (DEBUG_BOOT_MODE)			\
		rom_printk(fmt, ##__VA_ARGS__);	\
} while (0)
/************************************************************************/

/*
 * Print all CEPIC/PREPIC registers
 */
void boot_print_cepic(void)
{
	unsigned int value;

	value = native_epic_read_w(CEPIC_CTRL);
	rom_printk("0xfee00000 = CEPIC_CTRL: 0x%x\n", value);

	value = native_epic_read_w(CEPIC_ID);
	rom_printk("0xfee00010 = CEPIC_ID: 0x%x\n", value);

	value = native_epic_read_w(CEPIC_CPR);
	rom_printk("0xfee00070 = CEPIC_CPR: 0x%x\n", value);

	value = native_epic_read_w(CEPIC_ESR);
	rom_printk("0xfee00080 = CEPIC_ESR: 0x%x\n", value);

	value = native_epic_read_w(CEPIC_ESR2);
	rom_printk("0xfee00090 = CEPIC_ESR2: 0x%x\n", value);

	/* CEPIC_EOI is write-only */

	value = native_epic_read_w(CEPIC_CIR);
	rom_printk("0xfee000b0 = CEPIC_CIR: 0x%x\n", value);

	/* Reading CEPIC_PNMIRR starts NMI handling */

	value = native_epic_read_w(CEPIC_ICR);
	rom_printk("0xfee00200 = CEPIC_ICR: 0x%x\n", value);

	value = native_epic_read_w(CEPIC_ICR2);
	rom_printk("0xfee00204 = CEPIC_ICR2: 0x%x\n", value);

	value = native_epic_read_w(CEPIC_TIMER_LVTT);
	rom_printk("0xfee00220 = CEPIC_TIMER_LVTT: 0x%x\n", value);

	value = native_epic_read_w(CEPIC_TIMER_INIT);
	rom_printk("0xfee00230 = CEPIC_TIMER_INIT: 0x%x\n", value);

	value = native_epic_read_w(CEPIC_TIMER_CUR);
	rom_printk("0xfee00240 = CEPIC_TIMER_CUR: 0x%x\n", value);

	value = native_epic_read_w(CEPIC_TIMER_DIV);
	rom_printk("0xfee00250 = CEPIC_TIMER_DIV: 0x%x\n", value);

	value = native_epic_read_w(CEPIC_NM_TIMER_LVTT);
	rom_printk("0xfee00260 = CEPIC_NM_TIMER_LVTT: 0x%x\n", value);

	value = native_epic_read_w(CEPIC_NM_TIMER_INIT);
	rom_printk("0xfee00270 = CEPIC_NM_TIMER_INIT: 0x%x\n", value);

	value = native_epic_read_w(CEPIC_NM_TIMER_CUR);
	rom_printk("0xfee00280 = CEPIC_NM_TIMER_CUR: 0x%x\n", value);

	value = native_epic_read_w(CEPIC_NM_TIMER_DIV);
	rom_printk("0xfee00290 = CEPIC_NM_TIMER_DIV: 0x%x\n", value);

	value = native_epic_read_w(CEPIC_SVR);
	rom_printk("0xfee002a0 = CEPIC_SVR: 0x%x\n", value);

	value = native_epic_read_w(CEPIC_PNMIRR_MASK);
	rom_printk("0xfee002d0 = CEPIC_PNMIRR_MASK: 0x%x\n", value);

	/* Reading CEPIC_VECT_INTA starts MI handling */

	value = native_epic_read_w(CEPIC_CTRL2);
	rom_printk("0xfee01820 = CEPIC_CTRL2: 0x%x\n", value);

	value = native_epic_read_w(CEPIC_DAT);
	rom_printk("0xfee01830 = CEPIC_DAT: 0x%x\n", value);

	value = native_epic_read_w(CEPIC_DAT2);
	rom_printk("0xfee01834 = CEPIC_DAT2: 0x%x\n", value);

	value = native_epic_read_w(CEPIC_EPIC_INT);
	rom_printk("0xfee01850 = CEPIC_EPIC_INT: 0x%x\n", value);

	value = native_epic_read_w(CEPIC_EPIC_INT2);
	rom_printk("0xfee01860 = CEPIC_EPIC_INT2: 0x%x\n", value);

	value = native_epic_read_w(CEPIC_EPIC_INT3);
	rom_printk("0xfee01864 = CEPIC_EPIC_INT3: 0x%x\n", value);

	rom_printk("\n");
}

/*
 * Placeholder for boot-time CEPIC setup. Currently reset state is fine for
 * kernel, so do nothing
 */
void boot_setup_cepic(int cpu)
{
}

/*
 * Ensure that AP core received startup interrupt with matching address.
 * Print error messages, if that is not the case.
 */
void debug_epic_startup(int cpu, unsigned int value, unsigned long startup_addr)
{
	unsigned long addr;

	Dprintk("CPU #%d : CEPIC_PNMIRR value = 0x%x\n", cpu, value);

	if (!(value & CEPIC_PNMIRR_STARTUP))
		rom_printk("CPU #%d : ERROR: CEPIC startup bit is not set\n",
			cpu);

	addr = value & CEPIC_PNMIRR_STARTUP_ENTRY;

	Dprintk("CPU #%d : CEPIC received STARTUP with addr 0x%x\n", cpu, addr);

	if (addr != startup_addr >> 12)
		rom_printk("CPU #%d : ERROR : CEPIC incorrect startup addr\n",
			cpu);
}
