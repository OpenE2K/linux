/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#pragma once

#include <uapi/asm/sigcontext.h>

struct sigcontext_prot {
	unsigned long long	cr0_lo;
	unsigned long long	cr0_hi;
	unsigned long long	cr1_lo;
	unsigned long long	cr1_hi;
	unsigned long long	sbr;	 /* 21 Stack base register: top of */
					 /*    local data (user) stack */
	unsigned long long	usd_lo;	 /* 22 Local data (user) stack */
	unsigned long long	usd_hi;	 /* 23 descriptor: base & size */
	unsigned long long	psp_lo;	 /* 24 Procedure stack pointer: */
	unsigned long long	psp_hi;	 /* 25 base & index & size */
	unsigned long long	pcsp_lo; /* 26 Procedure chain stack */
	unsigned long long	pcsp_hi; /* 27 pointer: base & index & size */
};
