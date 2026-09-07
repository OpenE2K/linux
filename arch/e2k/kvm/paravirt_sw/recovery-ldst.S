/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <asm/e2k_api.h>

#include <linux/linkage.h>
#include <linux/errno.h>

SYM_FUNC_START(recovery_store_faulted)
.ignore ld_st_style
	{
		nop
		subd	0, EAGAIN, %dr0
		return	%ctpr3
	}
	{
		ct	%ctpr3
	}
SYM_FUNC_END(recovery_store_faulted)

SYM_FUNC_START(recovery_store_failed)
.ignore ld_st_style
	{
		nop
		subd	0, EFAULT, %dr0
		return	%ctpr3
	}
	{
		ct	%ctpr3
	}
SYM_FUNC_END(recovery_store_failed)

SYM_FUNC_START(recovery_load_faulted)
.ignore ld_st_style
	{
		nop
		subd	0, EAGAIN, %dr0
		return	%ctpr3
	}
	{
		ct	%ctpr3
	}
SYM_FUNC_END(recovery_load_faulted)

SYM_FUNC_START(recovery_load_failed)
.ignore ld_st_style
	{
		nop
		subd	0, EFAULT, %dr0
		return	%ctpr3
	}
	{
		ct	%ctpr3
	}
SYM_FUNC_END(recovery_load_failed)
