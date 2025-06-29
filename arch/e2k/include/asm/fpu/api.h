/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#pragma once

#include <asm/ptrace.h>

/*
 * Set some special registers in accordance with
 * E2K API specifications.
 */
#define GET_FPU_DEFAULTS(fpsr, fpcr, pfpfr)	\
({						\
	AW(fpsr) = 0;				\
	AW(pfpfr) = 0;				\
	AW(fpcr) = 32;				\
						\
	/* masks */				\
	pfpfr.im = 1;				\
	pfpfr.dm = 1;				\
	pfpfr.zm = 1;				\
	pfpfr.om = 1;				\
	pfpfr.um = 1;				\
	pfpfr.pm = 1;				\
						\
	/* flags ! NEEDSWORK ! */		\
	pfpfr.pe = 1;				\
	pfpfr.ue = 1;				\
	pfpfr.oe = 1;				\
	pfpfr.ze = 1;				\
	pfpfr.de = 1;				\
	pfpfr.ie = 1;				\
	/* rounding */				\
	pfpfr.rc = 0;				\
						\
	pfpfr.fz  = 0;				\
	pfpfr.dpe = 0;				\
	pfpfr.due = 0;				\
	pfpfr.doe = 0;				\
	pfpfr.dze = 0;				\
	pfpfr.dde = 0;				\
	pfpfr.die = 0;				\
						\
	fpcr.im = 1;				\
	fpcr.dm = 1;				\
	fpcr.zm = 1;				\
	fpcr.om = 1;				\
	fpcr.um = 1;				\
	fpcr.pm = 1;				\
	/* rounding */				\
	fpcr.rc = 0;				\
	fpcr.pc = 3;				\
						\
	/* flags ! NEEDSWORK ! */		\
	fpsr.pe = 1;				\
	fpsr.ue = 1;				\
	fpsr.oe = 1;				\
	fpsr.ze = 1;				\
	fpsr.de = 1;				\
	fpsr.ie = 1;				\
						\
	fpsr.es = 0;				\
	fpsr.c1 = 0;				\
})

#define INIT_FPU_REGISTERS()			\
({						\
	e2k_fpsr_t fpsr;			\
	e2k_pfpfr_t pfpfr;			\
	e2k_fpcr_t fpcr;			\
						\
	GET_FPU_DEFAULTS(fpsr, fpcr, pfpfr);	\
						\
	native_write_PFPFR_reg(pfpfr);		\
	native_write_FPCR_reg(fpcr);		\
	native_write_FPSR_reg(fpsr);		\
})

extern void kernel_fpu_begin(void);
extern void kernel_fpu_end(void);

