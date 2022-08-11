
/*
 * Copyright (c) 1997, by MCST.
 */

#ifndef	_MVP_VAR_H
#define	_MVP_VAR_H

#include <linux/mcst/ddi.h>

#define	mcst_node_type	"mcst_node_type"

/*
 * Standard system includes
 */
#if 0
#include <linux/types.h>
#include <linux/param.h>
#include <linux/stat.h>
#include <linux/errno.h>
#endif

/*
 * Definition of relationship between dev_t and interrupt numbers
 * instance, #intr, in/out  <=> minor
 */
#define	MVP_IO_IN		1
#define	MVP_IO_OUT		2
#define	MVP_IO_OS		3

#define	MVPTYPE_OLD		1
#define	MVPTYPE_NEW		0

#define	MVP_MINOR(i, io, n)	((i) << 7 | (io) << 5 | (n))
#define	MVP_INTR(d)		(getminor(d) & 0x1f)
#define	MVP_INST(d)		(getminor(d) >> 7)
#define	MVP_INOUT(d)		(getminor(d) >> 5 & 3)
#define	MVP_IN(d)		(MVP_INOUT(d) == MVP_IO_IN)
#define	MVP_OUT(d)		(MVP_INOUT(d) == MVP_IO_OUT)
#define	MVP_OS(d)		(MVP_INOUT(d) == MVP_IO_OS)

#define	MVP_N2OUT(n)		(n < 8) ? 1 << (n + 8) : 1 << (n + 16)
#define	MVP_N2IN(n)		(n < 10) ? 1 << (n + 6) : 1 << (n + 12)
#define	MVP_NS2IN(m)		(((m << 6) & 0xffc0) | ((m << 12) & 0xffc00000))
#define	MVP_IN2NS(m)		(((m >> 6) & 0x3ff) | ((m >> 12) & 0xffc00))


/*
 * MVP chip definitions.
 */

#define	MVP_REG_SIZE	0x044	/* size to be mapped			*/

/*
 * MVP_PARITY
 */
#define	MVP_PARITY_ENABLE	0x400

/*
 * driver state per instance
 */

#if 0
typedef struct mvp_state {
	dev_info_t		*dip;		/* dip			*/
	kmutex_t		mux;		/* open/close mutex 	*/
	int			open_in;
	int			open_out;
	int			open_st;
	int			open_excl;
	caddr_t			regs_base;
	//ddi_acc_handle_t	acc_regs;	/* regs data acc handle	*/
	int			parity;
	int			base_polar;
	int			polar;
	int			current_st;
	off_t			mvp_regs_sz;
	//ddi_iblock_cookie_t	iblk_cookie;
	raw_spinlock_t		intr_lock;	/* interrupt mutex 	*/
	u_int			intr_mask;	/* pending mask		*/
	//struct pollhead	pollhead;
	wait_queue_head_t	pollhead;
						/* info & measurement	*/
	ulong_t			intr_claimed;
	ulong_t			intr_unclaimed;
	ulong_t			n_iter;		/* to send interrupt	*/
	ulong_t			first_lbolt;	/* interrupt send	*/
	ulong_t			last_lbolt;	/* interrupt recieved	*/
	u_int			mvp_type;	/* type of mvp */
} mvp_state_t;
#endif

/*
 * Macros for register access
 */
#define	MVP_REG_ADDR(s, reg)	((ulong_t *)(s->regs_base + reg))

#define	GET_MVP_REG(s, reg)	sbus_readl(MVP_REG_ADDR(s, reg))
#define	PUT_MVP_REG(s, reg, v)	sbus_writel(MVP_REG_ADDR(s, reg), (long)v)

#endif	/* _MVP_VAR_H */
