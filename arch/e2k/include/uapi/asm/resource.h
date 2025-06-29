/*
 * SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
 * Copyright (c) 2023 MCST
 */

#ifndef _E2K_RESOURCE_H_
#define _E2K_RESOURCE_H_

#include <asm-generic/resource.h>

/*
 * Redefine resource limits for e2k
 */
#undef	_STK_LIM
#define	_STK_LIM	(16*1024*1024)

#endif /* _E2K_RESOURCE_H_ */
