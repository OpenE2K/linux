/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef	_ASM_L_IO_EPIC_H
#define	_ASM_L_IO_EPIC_H

#include <linux/types.h>
#include <linux/msi.h>
#include <asm/mpspec.h>

#define	IOEPIC_ID			0x0
#define	IOEPIC_VERSION			0x4
#define	IOEPIC_INT_RID(pin)		(0x800 + 0x4 * pin)
#define	IOEPIC_TABLE_INT_CTRL(pin)	(0x20 + 0x1000 * pin)
#define	IOEPIC_TABLE_MSG_DATA(pin)	(0x24 + 0x1000 * pin)
#define	IOEPIC_TABLE_ADDR_HIGH(pin)	(0x28 + 0x1000 * pin)
#define	IOEPIC_TABLE_ADDR_LOW(pin)	(0x2c + 0x1000 * pin)

#define	MAX_IO_EPICS	(MAX_NUMIOLINKS + MAX_NUMNODES)

#define IOEPIC_AUTO     -1
#define IOEPIC_EDGE     0
#define IOEPIC_LEVEL    1

#define IOEPIC_VERSION_1	1
#define IOEPIC_VERSION_2	2	/* Fast level EOI (without reading int_ctrl) */

struct ioepic_vcpu_info {
	bool valid;
	bool msi_valid;

	struct list_head *ioepic_pt_pin;
	unsigned int vmid;
	phys_addr_t int_table;
	struct msi_msg msi;
};

#endif	/* _ASM_L_IO_EPIC_H */
