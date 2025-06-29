/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */


#ifndef	_E2K_CPU_REGS_H_
#define	_E2K_CPU_REGS_H_

#ifdef __KERNEL__

#ifndef __ASSEMBLY__

/* Fix header dependency hell.  cpu_regs_access.h eventually includes
 * macros for paravirtualized guest which in turn rely on IS_HV_GM(),
 * and IS_HV_GM() relies in READ_CORE_MODE_REG() defined in this file. */

#define _INCLUDED_IN_CPU_REGS_H_
#include <asm/cpu_regs_access.h>
#undef _INCLUDED_IN_CPU_REGS_H_

#endif /* ! __ASSEMBLY__ */

#endif /* __KERNEL__ */

#endif /* _E2K_CPU_REGS_H_ */
