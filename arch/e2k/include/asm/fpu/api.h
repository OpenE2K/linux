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
	AS_STRUCT(pfpfr).im = 1;		\
	AS_STRUCT(pfpfr).dm = 1;		\
	AS_STRUCT(pfpfr).zm = 1;		\
	AS_STRUCT(pfpfr).om = 1;		\
	AS_STRUCT(pfpfr).um = 1;		\
	AS_STRUCT(pfpfr).pm = 1;		\
						\
	/* flags ! NEEDSWORK ! */		\
	AS_STRUCT(pfpfr).pe = 1;		\
	AS_STRUCT(pfpfr).ue = 1;		\
	AS_STRUCT(pfpfr).oe = 1;		\
	AS_STRUCT(pfpfr).ze = 1;		\
	AS_STRUCT(pfpfr).de = 1;		\
	AS_STRUCT(pfpfr).ie = 1;		\
	/* rounding */				\
	AS_STRUCT(pfpfr).rc = 0;		\
						\
	AS_STRUCT(pfpfr).fz  = 0;		\
	AS_STRUCT(pfpfr).dpe = 0;		\
	AS_STRUCT(pfpfr).due = 0;		\
	AS_STRUCT(pfpfr).doe = 0;		\
	AS_STRUCT(pfpfr).dze = 0;		\
	AS_STRUCT(pfpfr).dde = 0;		\
	AS_STRUCT(pfpfr).die = 0;		\
						\
	AS_STRUCT(fpcr).im = 1;			\
	AS_STRUCT(fpcr).dm = 1;			\
	AS_STRUCT(fpcr).zm = 1;			\
	AS_STRUCT(fpcr).om = 1;			\
	AS_STRUCT(fpcr).um = 1;			\
	AS_STRUCT(fpcr).pm = 1;			\
	/* rounding */				\
	AS_STRUCT(fpcr).rc = 0;			\
	AS_STRUCT(fpcr).pc = 3;			\
						\
	/* flags ! NEEDSWORK ! */		\
	AS_STRUCT(fpsr).pe = 1;			\
	AS_STRUCT(fpsr).ue = 1;			\
	AS_STRUCT(fpsr).oe = 1;			\
	AS_STRUCT(fpsr).ze = 1;			\
	AS_STRUCT(fpsr).de = 1;			\
	AS_STRUCT(fpsr).ie = 1;			\
						\
	AS_STRUCT(fpsr).es = 0;			\
	AS_STRUCT(fpsr).c1 = 0;			\
})

#define INIT_FPU_REGISTERS()			\
({						\
	e2k_fpsr_t fpsr;			\
	e2k_pfpfr_t pfpfr;			\
	e2k_fpcr_t fpcr;			\
						\
	GET_FPU_DEFAULTS(fpsr, fpcr, pfpfr);	\
						\
	NATIVE_NV_WRITE_PFPFR_REG(pfpfr);	\
	NATIVE_NV_WRITE_FPCR_REG(fpcr);		\
	NATIVE_NV_WRITE_FPSR_REG(fpsr);		\
})

void kernel_fpu_begin(void);
void kernel_fpu_end(void);