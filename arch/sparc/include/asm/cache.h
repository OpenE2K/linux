/* SPDX-License-Identifier: GPL-2.0 */
/* cache.h:  Cache specific code for the Sparc.  These include flushing
 *           and direct tag/data line access.
 *
 * Copyright (C) 1995, 2007 David S. Miller (davem@davemloft.net)
 */

#ifndef _SPARC_CACHE_H
#define _SPARC_CACHE_H

#define ARCH_SLAB_MINALIGN	__alignof__(unsigned long long)

#ifdef	CONFIG_E90S
#define L1_CACHE_SHIFT 6
#else
#define L1_CACHE_SHIFT 5
#endif

#define L1_CACHE_BYTES (1 << L1_CACHE_SHIFT)

#ifdef CONFIG_SPARC32
#define SMP_CACHE_BYTES_SHIFT 5
#else
#define SMP_CACHE_BYTES_SHIFT 6
#endif

#define SMP_CACHE_BYTES (1 << SMP_CACHE_BYTES_SHIFT)

#define __read_mostly __attribute__((__section__(".data..read_mostly")))

#endif /* !(_SPARC_CACHE_H) */
