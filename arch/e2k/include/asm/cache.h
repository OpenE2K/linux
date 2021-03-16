#ifndef _E2K_CACHE_H_
#define _E2K_CACHE_H_

#include <asm/es2.h>
#include <asm/e2s.h>
#include <asm/e8c.h>
#include <asm/e8c2.h>
#include <asm/e1cp.h>
#include <asm/e16c.h>
#include <asm/e12c.h>
#include <asm/e2c3.h>

#define _max_(a, b)	((a) > (b) ? (a) : (b))
#define _max3_(a, b, c)		_max_((a), _max_((b), (c)))

#ifdef	CONFIG_E2K_MACHINE
# if defined(CONFIG_E2K_ES2_DSP) || defined(CONFIG_E2K_ES2_RU)
#  define	L1_CACHE_SHIFT		ES2_L1_CACHE_SHIFT
#  define	L2_CACHE_SHIFT		ES2_L2_CACHE_SHIFT
# elif defined(CONFIG_E2K_E2S)
#  define	L1_CACHE_SHIFT		E2S_L1_CACHE_SHIFT
#  define	L2_CACHE_SHIFT		E2S_L2_CACHE_SHIFT
# elif defined(CONFIG_E2K_E8C)
#  define	L1_CACHE_SHIFT		E8C_L1_CACHE_SHIFT
#  define	L2_CACHE_SHIFT		E8C_L2_CACHE_SHIFT
#  define	L3_CACHE_SHIFT		E8C_L3_CACHE_SHIFT
# elif defined(CONFIG_E2K_E1CP)
#  define	L1_CACHE_SHIFT		E1CP_L1_CACHE_SHIFT
#  define	L2_CACHE_SHIFT		E1CP_L2_CACHE_SHIFT
# elif defined(CONFIG_E2K_E8C2)
#  define	L1_CACHE_SHIFT		E8C2_L1_CACHE_SHIFT
#  define	L2_CACHE_SHIFT		E8C2_L2_CACHE_SHIFT
#  define	L3_CACHE_SHIFT		E8C2_L3_CACHE_SHIFT
# elif defined(CONFIG_E2K_E12C)
#  define	L1_CACHE_SHIFT		E12C_L1_CACHE_SHIFT
#  define	L2_CACHE_SHIFT		E12C_L2_CACHE_SHIFT
#  define	L3_CACHE_SHIFT		E12C_L3_CACHE_SHIFT
# elif defined(CONFIG_E2K_E16C)
#  define	L1_CACHE_SHIFT		E16C_L1_CACHE_SHIFT
#  define	L2_CACHE_SHIFT		E16C_L2_CACHE_SHIFT
#  define	L3_CACHE_SHIFT		E16C_L3_CACHE_SHIFT
# elif defined(CONFIG_E2K_E2C3)
#  define	L1_CACHE_SHIFT		E2C3_L1_CACHE_SHIFT
#  define	L2_CACHE_SHIFT		E2C3_L2_CACHE_SHIFT
# else
#    error "E2K MACHINE type does not defined"
# endif
# ifndef L3_CACHE_SHIFT
#  define L3_CACHE_SHIFT 0
# endif
#else	/* ! CONFIG_E2K_MACHINE */
/* 
 * FIXME: Take it in mind while adding new cpu type
 */
# define L1_CACHE_SHIFT_MAX	ES2_L1_CACHE_SHIFT
# define L2_CACHE_SHIFT_MAX	ES2_L2_CACHE_SHIFT
# define L3_CACHE_SHIFT_MAX	E8C_L3_CACHE_SHIFT

# define L1_CACHE_SHIFT		L1_CACHE_SHIFT_MAX
# define L2_CACHE_SHIFT		L2_CACHE_SHIFT_MAX
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
