/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _E2K_CACHE_H_
#define _E2K_CACHE_H_

#include <asm/machines.h>

#define _max_(a, b)		((a) > (b) ? (a) : (b))
#define _max3_(a, b, c)		_max_((a), _max_((b), (c)))

#define L1_CACHE_SHIFT			5
#define L2_CACHE_SHIFT			6

#ifdef	CONFIG_E2K_MACHINE
# if defined(CONFIG_E2K_E8C)
#  define	L3_CACHE_SHIFT		E8C_L3_CACHE_SHIFT
# elif defined(CONFIG_E2K_E8C2)
#  define	L3_CACHE_SHIFT		E8C2_L3_CACHE_SHIFT
# elif defined(CONFIG_E2K_E12C)
#  define	L3_CACHE_SHIFT		E12C_L3_CACHE_SHIFT
# elif defined(CONFIG_E2K_E16C)
#  define	L3_CACHE_SHIFT		E16C_L3_CACHE_SHIFT
# elif defined(CONFIG_E2K_E48C)
#  define	L3_CACHE_SHIFT		E48C_L3_CACHE_SHIFT
# elif defined(CONFIG_E2K_E8V7)
#  define	L3_CACHE_SHIFT		E8V7_L3_CACHE_SHIFT
# endif
# ifndef L3_CACHE_SHIFT
#  define 	L3_CACHE_SHIFT		0
# endif
#else	/* ! CONFIG_E2K_MACHINE */
/* 
 * FIXME: Take it in mind while adding new cpu type
 */
# define L3_CACHE_SHIFT_MAX	E8C_L3_CACHE_SHIFT
# define L3_CACHE_SHIFT		L3_CACHE_SHIFT_MAX
#endif /* CONFIG_E2K_MACHINE */

#define	L1_CACHE_BYTES		(1 << L1_CACHE_SHIFT)
#define	L2_CACHE_BYTES		(1 << L2_CACHE_SHIFT)
#define	L3_CACHE_BYTES		(L3_CACHE_SHIFT ? (1 << L3_CACHE_SHIFT) : 0)

/* Stores pass through L1$, so we should use the biggest size. */
#define	SMP_CACHE_BYTES		_max3_(L1_CACHE_BYTES, L2_CACHE_BYTES, \
				       L3_CACHE_BYTES)
#define INTERNODE_CACHE_SHIFT	_max3_(L1_CACHE_SHIFT, L2_CACHE_SHIFT, \
				       L3_CACHE_SHIFT)

#define INTERNODE_CACHE_BYTES	(1 << INTERNODE_CACHE_SHIFT)

#define cache_line_size()	_max3_(L1_CACHE_BYTES, L2_CACHE_BYTES, \
				       L3_CACHE_BYTES)

#define __read_mostly __attribute__((__section__(".data..read_mostly")))

#endif /* _E2K_CACHE_H_ */
