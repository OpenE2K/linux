/* SPDX-License-Identifier: GPL-2.0 */
/*
 *    Hantro axife controller hardware driver header file.
 *
 *    Copyright (c) 2017, VeriSilicon Inc.
 *
 *    This program is free software; you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License, version 2, as
 *    published by the Free Software Foundation.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License version 2 for more details.
 *
 *    You may obtain a copy of the GNU General Public License
 *    Version 2 at the following locations:
 *    https://opensource.org/licenses/gpl-2.0.php
 */

#ifndef _HANTRO_AXIFE_H_
#define _HANTRO_AXIFE_H_

#include "hantro_priv.h"
#include "hantro.h"

#define HANTRO_AXIFE_OFFSET 0
#define HANTRO_AXIFE_IOSIZE (64 * 4)
#define AXI_REG0_SW_HWCFG                  (0 * 4) //0x0
#define AXI_REG10_SW_FRONTEND_EN           (10 * 4) //0x28
#define AXI_REG11_SW_WORK_MODE             (11 * 4) //0x2c

long AxifeReadRegs(struct axife_t *dev, struct core_desc *core);
long AxifeWriteRegs(struct axife_t *dev, struct core_desc *core);
int hantro_axife_probe(dtbnode *pnode, int loop, struct axife_t *axifecore);
void hantro_axife_cleanup(void);
int hantroaxife_init(void);
int AXIFEFlush(volatile unsigned char *hwregs);
void AXIFEEnable(volatile unsigned char *hwregs);

#endif //_HANTRO_DEC400_H_
