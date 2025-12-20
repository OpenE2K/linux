/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <asm/e2k_api.h>
#include <linux/errno.h>

.text

.global $recovery_store_faulted
.global $.recovery_store_faulted
$recovery_store_faulted:
$.recovery_store_faulted:
.ignore ld_st_style
	{
		nop
		subd	0, EAGAIN, %dr0
		return	%ctpr3
	}
	{
		ct	%ctpr3
	}
.size $recovery_store_faulted, . - $recovery_store_faulted

.global $recovery_store_failed
.global $.recovery_store_failed
$recovery_store_failed:
$.recovery_store_failed:
.ignore ld_st_style
	{
		nop
		subd	0, EFAULT, %dr0
		return	%ctpr3
	}
	{
		ct	%ctpr3
	}
.size $recovery_store_failed, . - $recovery_store_failed

.global $recovery_load_faulted
.global $.recovery_load_faulted
$recovery_load_faulted:
$.recovery_load_faulted:
.ignore ld_st_style
	{
		nop
		subd	0, EAGAIN, %dr0
		return	%ctpr3
	}
	{
		ct	%ctpr3
	}
.size $recovery_load_faulted, . - $recovery_load_faulted

.global $recovery_load_failed
.global $.recovery_load_failed
$recovery_load_failed:
$.recovery_load_failed:
.ignore ld_st_style
	{
		nop
		subd	0, EFAULT, %dr0
		return	%ctpr3
	}
	{
		ct	%ctpr3
	}
.size $recovery_load_failed, . - $recovery_load_failed
