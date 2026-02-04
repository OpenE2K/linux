/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

// primary linux startup module
// lintel_startup.s, written by <karbo@lab.sun.mcst.ru>
// linux_startup.s, written by <atic@soft.sun.mcst.ru> as modification
// of 'lintel_startup.s' to start up linux secondary module

#include <linux/linkage.h>

#define WSZ		0x20 			/* 20 quadwords	*/
#define RBS		0x10 			/* 10 quadwords	*/
#define RSZ		0x10 			/* 10 quadwords	*/

#define UPSR		0x1			/* fpu enabled */

#define BGR		0xff			/* %g24-%g31 enabled */

#define OSEM		0x0			/* no software traps enabled */

// We are starting first steps and call loader(). See romloader.S
// Static memory allocation is defined by romloader.lds

SYM_FUNC_START(start)
	{
		setwd	wsz=WSZ
		setbn	rbs = RBS, rsz = RSZ, rcur = 0x0
		setbp	psz = 0
	}
	rws UPSR,%upsr
	rws BGR,%bgr
	disp %ctpr1,loader
	rwd OSEM,%osem
	wait all_e=1
	ct %ctpr1
SYM_FUNC_END(start)

/*
 [probably] pending stuff:

 physprot: address=0x70, val=addr, lower 12 buts unused
 pcilb: address=0x80, val=addr, lower 12 bits unused

 not needed stuff:

 *NO* USD;
 *NO* CU table and CUTD;
 *NO* turn virtual addressing on;
*/

