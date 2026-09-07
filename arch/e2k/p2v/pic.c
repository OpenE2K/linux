/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/kernel.h>
#include <linux/types.h>

#include "../../l/kernel/irq/apic/apic.h"
#include "../../l/kernel/irq/epic/epic.h"
#include <asm/pic.h>

#ifdef	CONFIG_EPIC
static inline unsigned int boot_epic_is_bsp(void)
{
	union cepic_ctrl reg;

	reg.raw = boot_epic_read_w(CEPIC_CTRL);
	return reg.bsp_core;
}

static inline unsigned int boot_epic_read_id(void)
{
	return boot_cepic_id_full_to_short(boot_epic_read_w(CEPIC_ID));
}

bool notrace boot_early_pic_is_bsp(void)
{
	e2k_idr_t idr;
	unsigned int reg;

	idr = boot_read_IDR_reg();
	if (idr.mdl >= IDR_E12C_MDL)
		reg = boot_epic_is_bsp();
	else
		reg = boot_apic_is_bsp();

	return !!reg;
}

unsigned int notrace boot_early_pic_read_id(void)
{
	e2k_idr_t idr;

	idr = boot_read_IDR_reg();
	if (idr.mdl >= IDR_E12C_MDL)
		return boot_epic_read_id();
	else
		return boot_apic_read_id();
}

#else
bool notrace boot_early_pic_is_bsp(void)
{
	return !!boot_apic_is_bsp();
}

unsigned int notrace boot_early_pic_read_id(void)
{
	return boot_apic_read_id();
}
#endif /*CONFIG_EPIC*/
