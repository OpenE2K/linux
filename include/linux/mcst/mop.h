
/*
 * Copyright (c) 1997, by MCST.
 * 2004.7.5 pn izm nom reg          -----   MOP.H   LINUX  ------
 */
// 2004 11 29
#ifndef	_MOP_DEF_H
#define	_MOP_DEF_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Defines and structures useable by both the driver
 * and user application go here.
 */
#define name_mop "mop" 

/*
 * MOP chip definitions.
 */
 
#define	MOP_PZU_OFFSET	0x00000 /* offset to be mapped			*/
#define	MOP_PZU_SIZE	0x10000	/* size    to be mapped			*/

#define	MOP_REG_OFFSET	0x10000	/* offset to be mapped			*/
#define	MOP_REG_SIZE	0x100	/* size    to be mapped			*/

#define	MOP_BOZU_OFFSET	0x40000	/* offset to be mapped			*/
#define	MOP_BOZU_SIZE	0x10000	/* size    to be mapped			*/

#define	MOP_BUF_OFFSET	0xc0000	/* offset to be mapped			*/
#define	MOP_BUF_SIZE	0x100	/* size    to be mapped			*/

#define	MOP_BOZU_MPCODE_OFFSET	(0x800*4)	/* offset code MP	*/
#define	MOP_BOZU_RST_COUNTER	(0x1a0*4)	/* word addr 1a0	*/
 
/*
 * MOP Registers.
 */

#define	MOP_OIR		0x060	/* out	    interrupt	    reg 16 bits	 ROP	*/
#define	MOP_EIR		0x080	/* external interrupt	    reg 16 bits	 RIP	*/
#define	MOP_EIR0	0x084	/* external interrupt	    reg 16 bits	 	*/
#define	MOP_SIR		0x0a0	/* shadow   interrupt	    reg 16 bits	 RIPB read only	*/
#define MOP_FZMC        0x040   /* f-m ffmmffmm DF(0,1) ZF(1,1) PT(1,0)  RFM	*/

#ifdef __e2k__
typedef  u_int         mc_reg_t;      /* entire MC register like as long    */
#else 
typedef	 u_long        mc_reg_t;      /* entire MC register like as long    */
#endif

#ifdef MY_DRIVER_BIG_ENDIAN
typedef struct mc_rd_reg_bits          /* all register bits as to read */
{
   mc_reg_t  _unused_0       :  3;     /* [31:29] unused bits */
   mc_reg_t  _rnc            :  5;     /* [28:24] channel number of SBus */
   mc_reg_t  _unused_1       :  3;     /* [23:21] unused bits */
   mc_reg_t  _rerr           :  5;     /* [20:16] error register */
   mc_reg_t  _unused_2       :  3;     /* [15:13] unused bits */
   mc_reg_t  _rtm            :  5;     /* [12: 8] module type */
   mc_reg_t  _unused_3       :  1;     /*    [ 7] unused bits */
   mc_reg_t  _tpsb           :  1;     /*    [ 6] parity of SBus flag */
   mc_reg_t  _tsb            :  1;     /*    [ 5] request to SBus from MP */
   mc_reg_t  _tisb           :  1;     /*    [ 4] interrupt SBus from MP */
   mc_reg_t  _tlrm           :  1;     /*    [ 3] lock of reset module */
   mc_reg_t  _trm            :  1;     /*    [ 2] reset module */
   mc_reg_t  _tmi            :  1;     /*    [ 1] mask of interrupt to MP from
                                                  SPARC */
   mc_reg_t  _ti             :  1;     /*    [ 0] interrupt to MP from SPARC */
} mc_rd_reg_bits_t;
#else 
typedef struct mc_rd_reg_bits          /* all register bits as to read */
{
   mc_reg_t  _ti             :  1;     /*    [ 0] interrupt to MP from SPARC */
   mc_reg_t  _tmi            :  1;     /*    [ 1] mask of interrupt to MP from
                                                  SPARC */
   mc_reg_t  _trm            :  1;     /*    [ 2] reset module */
   mc_reg_t  _tlrm           :  1;     /*    [ 3] lock of reset module */
   mc_reg_t  _tisb           :  1;     /*    [ 4] interrupt SBus from MP */
   mc_reg_t  _tsb            :  1;     /*    [ 5] request to SBus from MP */
   mc_reg_t  _tpsb           :  1;     /*    [ 6] parity of SBus flag */
   mc_reg_t  _unused_3       :  1;     /*    [ 7] unused bits */
   mc_reg_t  _rtm            :  5;     /* [12: 8] module type */
   mc_reg_t  _unused_2       :  3;     /* [15:13] unused bits */
   mc_reg_t  _rerr           :  5;     /* [20:16] error register */
   mc_reg_t  _unused_1       :  3;     /* [23:21] unused bits */
   mc_reg_t  _rnc            :  5;     /* [28:24] channel number of SBus */
   mc_reg_t  _unused_0       :  3;     /* [31:29] unused bits */
} mc_rd_reg_bits_t;
#endif

#ifdef MY_DRIVER_BIG_ENDIAN
typedef union  mc_wr_reg_bits          /* all register bits as to write */
{
   mc_rd_reg_bits_t          tlrm_wr_reg_bits;   /* to write TLRM */
   struct trm_trcwd_wr_reg                       /* to write TRM + TRCWD */
   {
      mc_reg_t  _unused_0    :  3;     /* [31:29] unused bits */
      mc_reg_t  _rnc         :  5;     /* [28:24] channel number of SBus */
      mc_reg_t  _unused_1    :  3;     /* [23:21] unused bits */
      mc_reg_t  _rerr        :  5;     /* [20:16] error register */
      mc_reg_t  _unused_2    :  3;     /* [15:13] unused bits */
      mc_reg_t  _rtm         :  5;     /* [12: 8] module type */
      mc_reg_t  _unused_3    :  1;     /*    [ 7] unused bits */
      mc_reg_t  _tpsb        :  1;     /*    [ 6] parity of SBus flag */
      mc_reg_t  _tsb         :  1;     /*    [ 5] request to SBus from MP */
      mc_reg_t  _tisb        :  1;     /*    [ 4] interrupt SBus from MP */
      mc_reg_t  _trcwd       :  1;     /*    [ 3] reset of channel control word
                                                  register valid bit */
      mc_reg_t  _trm         :  1;     /*    [ 2] reset module */
      mc_reg_t  _tmi         :  1;     /*    [ 1] mask of interrupt to MP from
                                               SPARC */
      mc_reg_t  _ti          :  1;     /*    [ 0] interrupt to MP from SPARC */
   }                         trm_trcwd_wr_reg_bits;
} mc_wr_reg_bits_t;
#else
typedef union  mc_wr_reg_bits          /* all register bits as to write */
{
   mc_rd_reg_bits_t          tlrm_wr_reg_bits;   /* to write TLRM */
   struct trm_trcwd_wr_reg                       /* to write TRM + TRCWD */
   {
      mc_reg_t  _ti          :  1;     /*    [ 0] interrupt to MP from SPARC */
      mc_reg_t  _tmi         :  1;     /*    [ 1] mask of interrupt to MP from
                                               SPARC */
      mc_reg_t  _trm         :  1;     /*    [ 2] reset module */
      mc_reg_t  _trcwd       :  1;     /*    [ 3] reset of channel control word
                                                  register valid bit */
      mc_reg_t  _tisb        :  1;     /*    [ 4] interrupt SBus from MP */
      mc_reg_t  _tsb         :  1;     /*    [ 5] request to SBus from MP */
      mc_reg_t  _tpsb        :  1;     /*    [ 6] parity of SBus flag */
      mc_reg_t  _unused_3    :  1;     /*    [ 7] unused bits */
      mc_reg_t  _rtm         :  5;     /* [12: 8] module type */
      mc_reg_t  _unused_2    :  3;     /* [15:13] unused bits */
      mc_reg_t  _rerr        :  5;     /* [20:16] error register */
      mc_reg_t  _unused_1    :  3;     /* [23:21] unused bits */
      mc_reg_t  _rnc         :  5;     /* [28:24] channel number of SBus */
      mc_reg_t  _unused_0    :  3;     /* [31:29] unused bits */
   }                         trm_trcwd_wr_reg_bits;
} mc_wr_reg_bits_t;
#endif

typedef union mc_rd_reg                /* entire register as to read */
{
   mc_rd_reg_bits_t        as_bits;    /* as set of bits */
   mc_reg_t                whole;      /* as entire register */
} mc_rd_reg_t;

#define ti              0x00    /* TPM  */
#define tmi             0x04    /* TMPM */
#define trm             0x08    /* TSM  */
#define tlrm            0x0c    /* TBL  */
#define tisb            0x10    /* TPSH */
#define tsb             0x14    /* TBLPR ???????  */
#define tli             0x14    /*       ???????  */
#define       open_intr_bit   0x01  
#define       close_intr_bit  0x00  
#define tpsb            0x18    /* TP4SSH*/
#define rerr            0x1c    /* ROSH  */
#define chan_timer_char 0x1a0   /* Register to write timer value, new mode to looking for the
				   machine hanged up */

#define	MOP_N_IN_INTER	16
#define	MOP_N_OUT_INTER	16
#define	MOP_N_RST_INTER  4
#define	MOP_N_MPR_INTER	 4
#define	MOP_N_IMT_INTER	 4
#define	MOP_N_TST_INTER	 4

#define	MOP_IN_MASK	0xffc0ffc0u
#define	MOP_OUT_MASK	0xff00ff00u

 /* Constants for lighing interrupts  константы подсветки прерывания   */

#define	            c_mpr_0               0x00000001 /* прерывание от кан n      */
#define	            c_mpr_1               0x00000002
#define	            c_mpr_2               0x00000004
#define	            c_mpr_3               0x00000008

#define	            c_rst_on_0            0x00000110 /* связь восстановлена      */
#define	            c_rst_on_1            0x00000220
#define	            c_rst_on_2            0x00000440
#define	            c_rst_on_3            0x00000880

#define	            c_rst_off_0           0x00000010 /* связь прервана            */
#define	            c_rst_off_1           0x00000020
#define	            c_rst_off_2           0x00000040
#define	            c_rst_off_3           0x00000080

#define	            c_rst_upd_0           0x00001000 /* изменен код приема        */
#define	            c_rst_upd_1           0x00002000
#define	            c_rst_upd_2           0x00004000 /* код (3-n)-й тетраде слева */
#define	            c_rst_upd_3           0x00008000

#define	            c_rst_rst_0           0x000f1111 /* константа для rst SP WAIT */
#define	            c_rst_rst_1           0x00f02222
#define	            c_rst_rst_2           0x0f004444
#define	            c_rst_rst_3           0xf0008888

#define	            c_rst_cm_0            0xfff0eeef /* константа для rst SP INTR */
#define	            c_rst_cm_1            0xff0fdddf
#define	            c_rst_cm_2            0xf0ffbbbf
#define	            c_rst_cm_3            0x0fff777f

#define	MOP_IOC		('M' << 8)

/*
 * IOCTLs for send minor
 */

#define	MOPIO_SEND_INTR		(MOP_IOC | 1)

/*
 * IOCTLs for state minor
 */
#define	MOPIO_GET_STATE		(MOP_IOC | 0x2)
#define	MOPIO_SET_STATE		(MOP_IOC | 0x3)
#define	MOPIO_SET_POLAR		(MOP_IOC | 0x4)
#define	MOPIO_SET_MASK  	(MOP_IOC | 0x5)
#define	MOPIO_SET_FZMC  	(MOP_IOC | 0x6)

#define	MOPIO_LOAD_MP_DRV_CODE	(MOP_IOC | 0x10)
#define	MOPIO_RESET_MP		(MOP_IOC | 0x11)

/*
 * direct access to registers
 */
#ifdef JJJJ
#define	MOPIO_GET_REG		(MOP_IOC | 20
#define	MOPIO_SET_REG		(MOP_IOC | 21)
#define	MOPIO_AUTO_INTR		(MOP_IOC | 22)
#define	MOPIO_INFO		(MOP_IOC | 23)
#define	MOPIO_CLEAR_INFO	(MOP_IOC | 24)
#define	MOPIO_GET_INTR		(MOP_IOC | 25)
#define	MOPIO_GET_INTR_ALL	(MOP_IOC | 26)
#endif /*JJJJ*/
#define	MOPIO_GET_REG		(MOP_IOC | 0x20)
#define	MOPIO_SET_REG		(MOP_IOC | 0x21)
#define	MOPIO_AUTO_INTR		(MOP_IOC | 0x22)
#define	MOPIO_INFO		(MOP_IOC | 0x23)
#define	MOPIO_CLEAR_INFO	(MOP_IOC | 0x24)
#define	MOPIO_WRITE_COM		(MOP_IOC | 0x25)
#define	MOPIO_CLOSE_RST		(MOP_IOC | 0x26)
#define	MOPIO_RESET_INTR	(MOP_IOC | 0x27)
#define	MOPIO_WRITE_INTR	(MOP_IOC | 0x28)
#define	MOPIO_WRITE_SIG 	(MOP_IOC | 0x29)

#define	MOPIO_WAIT_INTR0	(MOP_IOC | 0x30)  /* Не менять кодировку команд */
#define	MOPIO_WAIT_INTR1	(MOP_IOC | 0x31)  /* Не менять кодировку команд */
#define	MOPIO_WAIT_INTR2	(MOP_IOC | 0x32)  /* Не менять кодировку команд */
#define	MOPIO_WAIT_INTR3	(MOP_IOC | 0x33)  /* Не менять кодировку команд */

#define	MOPIO_WAIT_RST0		(MOP_IOC | 0x34)  /* Не менять кодировку команд */
#define	MOPIO_WAIT_RST1		(MOP_IOC | 0x35)  /* Не менять кодировку команд */
#define	MOPIO_WAIT_RST2		(MOP_IOC | 0x36)  /* Не менять кодировку команд */
#define	MOPIO_WAIT_RST3		(MOP_IOC | 0x37)  /* Не менять кодировку команд */

#define	THAT_IS_WAIT_INTR(CMD)	(MOPIO_WAIT_INTR0 >> 2) == (CMD >> 2)

#define	MOPIO_START_MP		(MOP_IOC | 0x40)
#define	MOPIO_STOP_MP		(MOP_IOC | 0x41)
#define	MOPIO_DEBUG_ON		(MOP_IOC | 0x42)
#define	MOPIO_DEBUG_OFF		(MOP_IOC | 0x43)
#define MOPIO_SELF_TEST		(MOP_IOC | 0x99)

#define	MOPIO_WRITE_BOZU_0	(MOP_IOC | 0x50)
#define	MOPIO_WRITE_BOZU_1	(MOP_IOC | 0x51)
#define	MOPIO_WRITE_BOZU_2	(MOP_IOC | 0x52)
#define	MOPIO_WRITE_BOZU_3	(MOP_IOC | 0x53)

#define MOPIO_SET_TIME_OF_PANIC (MOP_IOC | 0x60)

#define	THAT_IS_WAIT_INTR(CMD)	(MOPIO_WAIT_INTR0 >> 2) == (CMD >> 2)

#define NUM_INTR_DRV	16

#define DONT_HAVE_IOCTL	'DONT'

typedef struct {
	u_int	intr_val;			/* значение       */
	int	intr_time;			/* время в мксек  */
	int	intr_delay;			/* время в мксек  */
	u_short intr_cnt;			/* счетчик        */
	int	intr_errno;			/* код ошибки 	  */
} mop_intrw_t;

typedef struct mop_op {
	int	reg;	/* register number		*/
	uint	val;	/* returned/passed value	*/
} mop_op_t;

typedef struct mop_info {
	u_int		intr_claimed;
	u_int		intr_unclaimed;
	u_long		first_lbolt;	/* interrupt send		*/
	u_long		last_lbolt;	/* interrupt recieved		*/
	clock_t		tick;		/* 1 tick in microseconds	*/
} mop_info_t;

typedef struct mop_buso {
	u_int		com;		/*  номер приказа		*/
	u_int		nom_kan;	/*  номер канала		*/
	u_int		time_interval;	/*  интервал времени		*/
	u_short		cod_out;	/*  код посылаемой константы	*/
	u_short		cod_in;		/*  код принимаемой константы	*/
	u_int		val_reg_faz_macki;/*значение регистра фазы-маски*/
} mop_buso_t;

typedef struct mop_buso_intr {
	u_int		com;		/*0 номер приказа		*/
	u_int		reg;	        /*1 режим выд сиг 0-пф 1-зф 2-пт*/
	u_int		time_interval;	/*2 интервал времени		*/
	u_short		time_int_0;	/*3 число инт выд сиг по 0-линии*/
	u_short		time_int_1;	/*  число инт выд сиг по 1-линии*/
	u_short		time_int_2;     /*4 число инт выд сиг по 2-линии*/
	u_short		time_int_3;	/*  число инт выд сиг по 3-линии*/
	u_short		time_int_4;	/*5 число инт выд сиг по 4-линии*/
	u_short		time_int_5;     /*  число инт выд сиг по 5-линии*/
	u_short		time_int_6;	/*6 число инт выд сиг по 6-линии*/
	u_short		time_int_7;	/*  число инт выд сиг по 7-линии*/
	u_short		time_int_8;     /*7 число инт выд сиг по 8-линии*/
	u_short		time_int_9;	/*  число инт выд сиг по 9-линии*/
	u_short		time_int_10;	/*8 число инт выд сиг по 10-лини*/
	u_short		time_int_11;    /*  число инт выд сиг по 11-лини*/
	u_short		time_int_12;	/*9 число инт выд сиг по 12-лини*/
	u_short		time_int_13;	/*  число инт выд сиг по 13-лини*/
	u_short		time_int_14;   /*10 число инт выд сиг по 14-лини*/
	u_short		time_int_15;	/*  число инт выд сиг по 15-лини*/
} mop_buso_intr_t;

typedef struct mop_buso_sig {
	u_int		com;		/*0 номер приказа		 */
	u_int		reg;	        /*1 режим выд сиг 0-пф 1-зф 2-пт */
	u_long		abuf;	        /*2 адрес   буфера               */
	u_int		rzmbuf;	        /*3 количество 16р слов в буфере */
	u_int		rzmpor;	        /*4 количество 16р слов в порции */
	u_int		kwopor;	        /*5 количество порций за 1 приказ*/
	u_int		time_interval;	/*6 интервал времени		 */
	u_int		nint;	        /*7 число интервалов меж порциями*/
} mop_buso_sig_t;


#ifdef	__cplusplus
}
#endif

#endif	/* _MOP_DEF_H */
