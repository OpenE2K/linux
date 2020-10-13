
/*
 * Copyright (c) 1997, by MCST.
 * 2004.7.5- pn-emv-MOP_REG_SIZE
 * 2004.8.17-pn-emv-   mop_state + MOP_PZU_SIZE, MOP_BOZU_SIZE
 * 2004.10.29
 * 2004.11.4
 * 2004.11.26
 * 2004.11.29
 */

#ifndef	_MOP_VAR_H
#define	_MOP_VAR_H


#ifdef	__cplusplus
extern "C" {
#endif

#define	mcst_node_type	"mcst_node_type"

/*
 * Definition of relationship between dev_t and interrupt numbers
 * instance, #intr, in/out  <=> minor
 */
  
#define	bozu_buso (0x664*4)			/* приказ МП  */
#define	bozu_dr   (0x680*4)			/* дескр рез  */

//#define NUM_INTR_DRV    7
#define	MOP_INTR_MAX	5

#define	MOP_IO_IN		1
#define	MOP_IO_OUT		2
#define	MOP_IO_RST		3
#define	MOP_IO_MPR		4
#define	MOP_IO_IMT		5
#define	MOP_IO_TST		6

#define	MOPTYPE_OLD		1
#define	MOPTYPE_NEW		0

#define	MOP_MINOR(i, io, n)	((i) << 7 | (io) << 5 | (n))
#define	MOP_INTR(d)		(getminor(d) & 0x1f)
#define	MOP_INST(d)		(getminor(d) >> 7)
#define	MOP_INOUT(d)	(getminor(d) >> 5 & 3)

#define	MOP_IN(d)		(MOP_INOUT(d) == MOP_IO_IN)
#define	MOP_OUT(d)		(MOP_INOUT(d) == MOP_IO_OUT)
#define	MOP_RST(d)		(MOP_INOUT(d) == MOP_IO_RST)
#define	MOP_MPR(d)		(MOP_INOUT(d) == MOP_IO_MPR)
#define	MOP_IMT(d)		(MOP_INOUT(d) == MOP_IO_IMT)
#define	MOP_TST(d)		(MOP_INOUT(d) == MOP_IO_TST)

#define	MOP_N2OUT(n)		(n < 8) ? 1 << (n + 8) : 1 << (n + 16)
#define	MOP_N2IN(n)		(n < 10) ? 1 << (n + 6) : 1 << (n + 12)
#define	MOP_NS2IN(m)		(((m << 6) & 0xffc0) | ((m << 12) & 0xffc00000))
#define	MOP_IN2NS(m)		(((m >> 6) & 0x3ff) | ((m >> 12) & 0xffc00))


/*
 * MOP chip definitions.
 */
#ifdef DDDD
#define	MOP_PZU_OFFSET	0x000	        /* offset to be mapped	*/
#define	MOP_PZU_SIZE	0x10000	        /* size   to be mapped	*/

#define	MOP_REG_OFFSET	0x10000	        /* offset to be mapped	*/
#define	MOP_REG_SIZE	0x100		/* size to be mapped	*/

#define	MOP_BOZU_OFFSET	0x40000	        /* offset to be mapped	*/
#define	MOP_BOZU_SIZE	0x10000		/* size to be mapped	*/

#define	MOP_BUF_OFFSET	0xc0000	        /* offset to be mapped	*/
#define	MOP_BUF_SIZE	0x100		/* size to be mapped	*/

#define	MOP_BOZU_MPCODE_OFFSET	(0x800*4) /* offset to be mapped*/
#define	MOP_BOZU_RST_SIZE	(0x1a0*4) /* size to be mapped	*/
#endif /* DDDD */
/*
 * MOP_PARITY
 */
#define	MOP_PARITY_ENABLE	0x400

typedef struct {
	kcondvar_t	cv;		/* событие для связи с пользователем	*/
/*	u_short		intr_val; */	/* значение       			*/
	u_short		cnt;		/* счетчик прер. 			*/
					/* в момент выхода на пользователя 	*/
	hrtime_t	time;		/* точное время прихода прер. 		*/
	hrtime_t	time_cnt1;	/* точное время прихода 1-го		*/
					/* прер. "потерянного" пользователем 	*/
	hrtime_t	delay;		/* интервал между 2-мя последними прер.	*/
					/* (в мксек) 				*/
} mop_intr_t;

/*
 * driver state per instance
 */
typedef struct mop_state {
	struct of_device	*op;
	dev_t		dev;
//	int			dev_type;
	int			inst;			/* номер экземпляра */
	int			major;			/* мажор экземпляра */
	int			irq;			/* номер прерывания */
	kmutex_t	mux;			/* open/close mutex 	*/
	int			open_in;
	int			open_out;
	int			open_rst;
	int			open_mpr;
	int			open_imt;	
	int			open_tst;

	int			open_exch;
	int			open_cntl;
	
	int			open_excl;
	int			mp_drv_loaded;
	
	caddr_t			pzu_base;
	caddr_t			regs_base;
	caddr_t			bozu_base;
	caddr_t			buf_base;
		
	//ddi_acc_handle_t	acc_regs;	/* regs data acc handle	*/
	//ddi_acc_handle_t	acc_bozu;       /* bozu data acc handle	*/
	//ddi_acc_handle_t	acc_pzu ;	/* pzu  data acc handle	*/
	//ddi_acc_handle_t	acc_buf ;	/* buf  data acc handle	*/	

	int			base_faza;
	int			faza;
	int			mask;
	int			current_st;
	
	off_t			mop_pzu_sz;
	off_t			mop_regs_sz;
	off_t			mop_bozu_sz;
	off_t			mop_buf_sz;	
	
	//ddi_iblock_cookie_t	iblk_cookie;
	raw_spinlock_t		intr_lock;	/* interrupt mutex 	*/
	u_int			intr_mask;	/* pending mask		*/
	//struct pollhead	pollhead;
	wait_queue_head_t	pollhead;	/* info & measurement	*/
	u_int			intr_claimed;
	u_int			intr_unclaimed;
	u_int			n_iter;		/* to send interrupt	*/
	u_int			first_lbolt;	/* interrupt send	*/
	u_int			last_lbolt;	/* interrupt recieved	*/
	u_int			mop_type;	/* type of mop          */
	u_int			intr_val;	/* значение             */
	mop_intr_t		intrs[NUM_INTR_DRV];/* arr of interr structure*/
	u_int			deb;		/* прзн отладочной печати*/
} mop_state_t;

/*
 * Macros for register access
  */
#define	MOP_REG_ADDR(s,reg)	((ulong_t *)(s->regs_base + reg))
#define	MOP_BOZU_ADDR(s,reg)	((ulong_t *)(s->bozu_base + reg))

#define	GET_MOP_REG(s,reg)	ddi_getl ( DDI_SBUS_SPARC, MOP_REG_ADDR(s,reg) )
#define	PUT_MOP_REG(s,reg,v)	ddi_putl ( DDI_SBUS_SPARC, MOP_REG_ADDR(s,reg) ,(long)v)

#define	GET_MOP_BOZU(s,reg)	ddi_getl ( DDI_SBUS_SPARC, MOP_BOZU_ADDR(s,reg) )
#define	PUT_MOP_BOZU(s,reg,v)	ddi_putl ( DDI_SBUS_SPARC, MOP_BOZU_ADDR(s,reg),(long)v)

#ifdef	__cplusplus
}
#endif


#endif	/* _MOP_VAR_H */
