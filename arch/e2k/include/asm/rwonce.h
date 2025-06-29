/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef __ASM_RWONCE_H
#define __ASM_RWONCE_H

#ifdef CONFIG_SMP

#include <asm/compiler.h>

#define __READ_ONCE(x)							\
({									\
	__unqual_scalar_typeof(x) __x =					\
		(*(volatile typeof(__x) *)(&(x)));			\
	/* Forbid lcc to move per-cpu global registers around */	\
	barrier_preemption();						\
	(typeof(x))__x;							\
})

#endif /* CONFIG_SMP */

#include <asm-generic/rwonce.h>

#endif /* __ASM_RWONCE_H */
