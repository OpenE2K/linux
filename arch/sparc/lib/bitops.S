/* SPDX-License-Identifier: GPL-2.0 */
/* bitops.S: Sparc64 atomic bit operations.
 *
 * Copyright (C) 2000, 2007 David S. Miller (davem@davemloft.net)
 */

#include <linux/linkage.h>
#include <asm/asi.h>
#include <asm/backoff.h>
#include <asm/export.h>

	.text
#ifdef	CONFIG_RMO
	/* On SMP we need to use memory barriers to ensure
	 * correct memory operation ordering, nop these out
	 * for uniprocessor.
	 */

#ifdef CONFIG_SMP
#define BITOP_PRE_BARRIER	membar #StoreLoad | #LoadLoad
#define BITOP_POST_BARRIER	\
	membar #StoreLoad | #StoreStore
#else
#define BITOP_PRE_BARRIER
#define BITOP_POST_BARRIER
#endif

#endif	/* CONFIG_RMO */
ENTRY(test_and_set_bit)	/* %o0=nr, %o1=addr */
	BACKOFF_SETUP(%o3)
#ifdef	CONFIG_RMO
	BITOP_PRE_BARRIER
#endif	/* CONFIG_RMO */
	srlx	%o0, 6, %g1
	mov	1, %o2
	sllx	%g1, 3, %g3
	and	%o0, 63, %g2
	sllx	%o2, %g2, %o2
	add	%o1, %g3, %o1
1:	ldx	[%o1], %g7
	or	%g7, %o2, %g1
	casx	[%o1], %g7, %g1
	cmp	%g7, %g1
	bne,pn	%xcc, BACKOFF_LABEL(2f, 1b)
	 and	%g7, %o2, %g2
	clr	%o0
	movrne	%g2, 1, %o0
#ifdef	CONFIG_RMO
	BITOP_POST_BARRIER
#endif	/* CONFIG_RMO */
	retl
	 nop
2:	BACKOFF_SPIN(%o3, %o4, 1b)
ENDPROC(test_and_set_bit)
EXPORT_SYMBOL(test_and_set_bit)

ENTRY(test_and_clear_bit) /* %o0=nr, %o1=addr */
	BACKOFF_SETUP(%o3)
#ifdef	CONFIG_RMO
	BITOP_PRE_BARRIER
#endif	/* CONFIG_RMO */
	srlx	%o0, 6, %g1
	mov	1, %o2
	sllx	%g1, 3, %g3
	and	%o0, 63, %g2
	sllx	%o2, %g2, %o2
	add	%o1, %g3, %o1
1:	ldx	[%o1], %g7
	andn	%g7, %o2, %g1
	casx	[%o1], %g7, %g1
	cmp	%g7, %g1
	bne,pn	%xcc, BACKOFF_LABEL(2f, 1b)
	 and	%g7, %o2, %g2
	clr	%o0
	movrne	%g2, 1, %o0
#ifdef	CONFIG_RMO
	BITOP_POST_BARRIER
#endif	/* CONFIG_RMO */
	retl
	 nop
2:	BACKOFF_SPIN(%o3, %o4, 1b)
ENDPROC(test_and_clear_bit)
EXPORT_SYMBOL(test_and_clear_bit)

ENTRY(test_and_change_bit) /* %o0=nr, %o1=addr */
	BACKOFF_SETUP(%o3)
#ifdef	CONFIG_RMO
	BITOP_PRE_BARRIER
#endif	/* CONFIG_RMO */
	srlx	%o0, 6, %g1
	mov	1, %o2
	sllx	%g1, 3, %g3
	and	%o0, 63, %g2
	sllx	%o2, %g2, %o2
	add	%o1, %g3, %o1
1:	ldx	[%o1], %g7
	xor	%g7, %o2, %g1
	casx	[%o1], %g7, %g1
	cmp	%g7, %g1
	bne,pn	%xcc, BACKOFF_LABEL(2f, 1b)
	 and	%g7, %o2, %g2
	clr	%o0
	movrne	%g2, 1, %o0
#ifdef	CONFIG_RMO
	BITOP_POST_BARRIER
#endif	/* CONFIG_RMO */
	retl
	 nop
2:	BACKOFF_SPIN(%o3, %o4, 1b)
ENDPROC(test_and_change_bit)
EXPORT_SYMBOL(test_and_change_bit)

ENTRY(set_bit) /* %o0=nr, %o1=addr */
	BACKOFF_SETUP(%o3)
#if defined CONFIG_MCST && defined CONFIG_RMO
	BITOP_PRE_BARRIER
#endif	/* CONFIG_RMO */
	srlx	%o0, 6, %g1
	mov	1, %o2
	sllx	%g1, 3, %g3
	and	%o0, 63, %g2
	sllx	%o2, %g2, %o2
	add	%o1, %g3, %o1
1:	ldx	[%o1], %g7
	or	%g7, %o2, %g1
	casx	[%o1], %g7, %g1
	cmp	%g7, %g1
	bne,pn	%xcc, BACKOFF_LABEL(2f, 1b)
	 nop
	retl
	 nop
2:	BACKOFF_SPIN(%o3, %o4, 1b)
ENDPROC(set_bit)
EXPORT_SYMBOL(set_bit)

ENTRY(clear_bit) /* %o0=nr, %o1=addr */
	BACKOFF_SETUP(%o3)
#if defined CONFIG_MCST && defined CONFIG_RMO
	BITOP_PRE_BARRIER
#endif	/* CONFIG_RMO */
	srlx	%o0, 6, %g1
	mov	1, %o2
	sllx	%g1, 3, %g3
	and	%o0, 63, %g2
	sllx	%o2, %g2, %o2
	add	%o1, %g3, %o1
1:	ldx	[%o1], %g7
	andn	%g7, %o2, %g1
	casx	[%o1], %g7, %g1
	cmp	%g7, %g1
	bne,pn	%xcc, BACKOFF_LABEL(2f, 1b)
	 nop
	retl
	 nop
2:	BACKOFF_SPIN(%o3, %o4, 1b)
ENDPROC(clear_bit)
EXPORT_SYMBOL(clear_bit)

ENTRY(change_bit) /* %o0=nr, %o1=addr */
	BACKOFF_SETUP(%o3)
	srlx	%o0, 6, %g1
	mov	1, %o2
	sllx	%g1, 3, %g3
	and	%o0, 63, %g2
	sllx	%o2, %g2, %o2
	add	%o1, %g3, %o1
1:	ldx	[%o1], %g7
	xor	%g7, %o2, %g1
	casx	[%o1], %g7, %g1
	cmp	%g7, %g1
	bne,pn	%xcc, BACKOFF_LABEL(2f, 1b)
	 nop
	retl
	 nop
2:	BACKOFF_SPIN(%o3, %o4, 1b)
ENDPROC(change_bit)
EXPORT_SYMBOL(change_bit)
