/*
 * SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
 * Copyright (c) 2023 MCST
 */

#ifndef MMRSE_IOCTL_H__
#define MMRSE_IOCTL_H__

#include <linux/types.h>
#include <linux/ioctl.h>


/**
 * Devices name:
 *   sprintf(name, "%s%d%s", "/dev/mmrse", num, DEVNAME_??);
 *   if((fd = open(name, O_RDWR)) < 0) {
 *     PERR("Error: %m\n");
 */
#define DEVNAME_BC	"c"	/* Bus Controller */
#define DEVNAME_RT	"t"	/* Remote Terminal */
#define DEVNAME_BM	"m"	/* Bus Monitor */


/*
 ******************************************************************************
 * IOCTL
 *   _IO            (TYPE, NR)
 *   _IOR/_IOW/_IOWR(type, NR, SIZE)
 *
 *   0xE0000000   DIR
 *   0x80000000     DIR = WRITE
 *   0x40000000     DIR = READ
 *   0x20000000     DIR = NONE
 *   0x3FFF0000   SIZE (sizeof)
 *   0x0000FF00   TYPE
 *   0x000000FF   NR (CMD)
 ******************************************************************************
 */

#define MMRSE_IOC_MAGIC 'm'


/*
 ******************************************************************************
 * COMMON
 ******************************************************************************
 */

/**
 * MMRSE_IOCTL_GET_STATS
 * Read statistic counters
 *
 * Returns:
 *   -EFAULT - copy_from/to_user failure
 *   0 if success
 *
 * Usage:
 *   mmrse_stats_t stats;
 *   if(ioctl(fd, MMRSE_IOCTL_GET_STATS, &stats)) printf("Error: %m\n");
 */

typedef struct {
	uint64_t bc_ok;		/* success */
	uint64_t bc_ecrc;	/* crc error */
	uint64_t bc_eto;	/* timeout */
	uint64_t bc_spec;	/* special fields in SW */
	uint64_t bc_ecmd;	/* wrong command */
	uint64_t bc_erp;	/* pause on receive */
	uint64_t bc_unk;	/* unknown */
	uint64_t rt_dma;	/* DMA */
	uint64_t rt_cmd;	/* CMD */
	uint64_t rt_rx;		/* RX */
	uint64_t rt_tx;		/* TX */
	uint64_t rt_msgerr;	/* message error */
	uint64_t rt_instr;	/* instrumentation */
	uint64_t rt_srq;	/* service request */
	uint64_t rt_bdcst;	/* broadcast rcvd */
	uint64_t rt_busy;	/* busy */
	uint64_t rt_subsys;	/* sub system flag */
	uint64_t rt_busacpt;	/* dynamic bus acceptance */
	uint64_t rt_term;	/* terminal flag */
} mmrse_stats_t;

#define MMRSE_IOCTL_GET_STATS		_IOR(MMRSE_IOC_MAGIC, 1, mmrse_stats_t)

/**
 * MMRSE_IOCTL_GET_DMA_LATENCY
 * Read last DMA latency in ns
 *
 * Returns:
 *   -EFAULT - copy_from/to_user failure
 *   0 if success
 *
 * Usage:
 *   uint64_t dma_lat;
 *   if(ioctl(fd, MMRSE_IOCTL_GET_DMA_LATENCY, &dma_lat)) printf("Error: %m\n");
 */
#define MMRSE_IOCTL_GET_DMA_LATENCY	_IOR(MMRSE_IOC_MAGIC, 2, uint64_t)


/*
 ******************************************************************************
 * BUS CONTROLLER
 ******************************************************************************
 */

/** Buffers for format 1, 2, 3, 7, 8 */
#define GET_SEND_BUFF_ADDR(BASE, N)	((BASE) + ((N) * 32))
#define GET_RECEIVE_BUFF_ADDR(BASE, N)	((BASE) + (32 * 32) + ((N) * 32))
#define GET_BC_BUFF_SIZE		((32 * 2) * 32 * 2)

/** Command Word */
#define MAKE_CW_CODE(rta, tr, mode, code) \
	(SET_CW_RTA(rta) | SET_CW_TR(tr) | SET_CW_MODE(mode) | SET_CW_MC(code))
#define MAKE_CW_DATA(rta, tr, sa, len) \
	(SET_CW_RTA(rta) | SET_CW_TR(tr) | SET_CW_SA(sa) |\
	SET_CW_DWC(DWC_LEN(len)))

#define SET_CW_RTA(d)	((0x1F & (d)) << 11) /* [15:11] Remote Terminal Addr. */
#define GET_CW_RTA(d)	(((d) >> 11) & 0x1F)
#define SET_CW_TR(d)	((0x01 & (d)) << 10) /* [10] Transmit/Receive */
#define GET_CW_TR(d)	(((d) >> 10) & 0x01)
#define SET_CW_SA(d)	((0x1F & (d)) << 5)  /* [9:5] Subaddress */
#define GET_CW_SA(d)	(((d) >> 5) & 0x1F)
#define SET_CW_MODE(d)	((0x1F & (d)) << 5)  /* [9:5] Mode */
#define GET_CW_MODE(d)	(((d) >> 5) & 0x1F)
#define SET_CW_DWC(d)	((0x1F & (d)) << 0)  /* [4:0] Data word count */
#define GET_CW_DWC(d)	(((d) >> 0) & 0x1F)
#define SET_CW_MC(d)	((0x1F & (d)) << 0)  /* [4:0] Mode code */
#define GET_CW_MC(d)	(((d) >> 0) & 0x1F)

/** RT Address - SET_CW_RTA(d) */
    #define	RT_ADDR_MIN	0
    #define	RT_ADDR_MAX	30
    #define	RT_ADDR_BRDCST	31
    #define	RT_ADDR_DISABLE	31

/** Transmit/Receive - SET_CW_TR(d) */
    #define	TR_BC2RT	0	/* Receive: BC -> RT */
    #define	TR_RT2BC	1	/* Transmit: RT -> BC */

/** Subaddress - SET_CW_SA(d) */
    #define	SUB_ADDR_MIN	1
    #define	SUB_ADDR_MAX	29
/** Mode - SET_CW_MODE(d) */
    #define	SA_CNTRL0	0x00	/* Mode (0) */
    #define	SA_CNTRL1	0x1F	/* Mode (31) */
    #define	SA_TEST		0x1E	/* Test (30) */

/** Data word count - SET_CW_DWC(d) */
    #define	DWC_LEN(len)	((len == 32) ? 0 : len)
/** Mode codes - SET_CW_MC(d)*/
    #define	MC_DBC		0x00	/* dynamic bus control */
    #define	MC_SYN		0x01	/* synchronize */
    #define	MC_TSW		0x02	/* transmit status word */
    #define	MC_IST		0x03	/* initiate self-test */
    #define	MC_TSD		0x04	/* transmitter shutdown */
    #define	MC_OTSD		0x05	/* override transmitter shutdown */
    #define	MC_ITFB		0x06	/* inhibit terminal flag bit */
    #define	MC_OITFB	0x07	/* override inhibit terminal flag bit */
    #define	MC_RRT		0x08	/* reset remote terminal */
    #define	MC_TVW		0x10	/* transmit vector word */
    #define	MC_SYNB		0x11	/* synchronize with data word */
    #define	MC_TLC		0x12	/* transmit last command */
    #define	MC_TBIT		0x13	/* transmit BIT word */
    /*#define	MC_STSD		0x14*/	/* selected transmitter shutdown */
    /*#define	MC_OSTSD	0x15*/	/* override sel'd txmitter shutdown */

/** Status Word */
#define GET_SW_RTA(d)	(0x1F & ((d) >> 11)) /* [15:11] Remote Terminal Addr. */
#define GET_SW_STAT(d)	(0x7FF & (d))	/* [10:00] */

/** status defines */
    #define	SW_RTA_MSK	0xf800	/* rt address */
    #define	SW_STAT_MSK	0x07ff	/* settable status bits */
    #define	SW_MSGERR	0x400	/* message error */
    #define	SW_INS		0x200	/* instrumentation */
    #define	SW_SRQ		0x100	/* service request */
    #define	SW_RSV2		0x80	/* reserved */
    #define	SW_RSV1		0x40	/* reserved */
    #define	SW_RSV0		0x20	/* reserved */
    #define	SW_BDCST	0x10	/* broadcast rcvd */
    #define	SW_SUBSYSBSY	0x8	/* busy */
    #define	SW_SUBSYSFL	0x4	/* sub system flag */
    #define	SW_BUS_ACPT	0x2	/* dynamic bus acceptance */
    #define	SW_TERM		0x1	/* terminal flag */


/**
 * MMRSE_IOCTL_BC_SEND_MESSAGE
 * Start sending Message
 * (for rormat 1 and 7 fill memory before call this)
 *
 * Returns:
 *   -EFAULT - copy_from/to_user failure
 *   -EBUSY - command buffer full
 *   -ETIMEDOUT - wait_event_interruptible_timeout
 *   >= 0 - BC_STATUS_RESULT_* status codes:
 *         MMRSE_BC_SEND_MESSAGE_RESULT_OK	- success
 *         MMRSE_BC_SEND_MESSAGE_RESULT_ECRC	- crc error
 *         MMRSE_BC_SEND_MESSAGE_RESULT_ETO	- timeout
 *         MMRSE_BC_SEND_MESSAGE_RESULT_ESPEC	- special fields in SW
 *         MMRSE_BC_SEND_MESSAGE_RESULT_ECMD	- wrong command
 *         MMRSE_BC_SEND_MESSAGE_RESULT_ERP	- pause on receive
 *         MMRSE_BC_SEND_MESSAGE_RESULT_NONE	- success, no SW
 *
 * Usage:
 *   mmr_cmd_t cmd;
 *   cmd.cw = MAKE_CW_CODE(rta, tr, mode, mcode); // Command Word
 *   cmd.dw = DW; // Data Word (format: 6, 10) or Command2 (format: 3, 8)
 *   int ret = ioctl(fd, MMRSE_IOCTL_BC_SEND_MESSAGE, &cmd);
 *   if(ret ...) ...
 *   uint16_t stat = cmd.cw; // Status Word (format: 1..6, 8)
 *   uint16_t dw = cmd.dw; // returned Data Word (format 5) or Status2 (format 3)
 */

typedef struct {
	uint16_t cw;	/* Command Word and second Command or Data Word */
	uint16_t dw;	/* Returns SW and DW */
} mmr_cmd_t;

#define MMRSE_IOCTL_BC_SEND_MESSAGE	_IOWR(MMRSE_IOC_MAGIC, 3, mmr_cmd_t)

/** status codes: */
#define MMRSE_BC_SEND_MESSAGE_RESULT_OK		0x0000
#define MMRSE_BC_SEND_MESSAGE_RESULT_ECRC	0x0001
#define MMRSE_BC_SEND_MESSAGE_RESULT_ETO	0x0002
#define MMRSE_BC_SEND_MESSAGE_RESULT_ESPEC	0x0003
#define MMRSE_BC_SEND_MESSAGE_RESULT_ECMD	0x0004
#define MMRSE_BC_SEND_MESSAGE_RESULT_ERP	0x0005
#define MMRSE_BC_SEND_MESSAGE_RESULT_NONE	0x0007


/**
 * MMRSE_IOCTL_BC_SET_CHANNEL
 * Set activ channel: 1 or 2 (poweron: 1)
 *
 * Returns:
 *   -EFAULT - copy_from/to_user failure
 *   -EBUSY - hardware error
 *   0 if success
 *
 * Usage:
 *   uint32_t ch = 1; // 2
 *   int ret = ioctl(fd, MMRSE_IOCTL_BC_SET_CHANNEL, &ch);
 *   (ch == real channel)
 */
#define MMRSE_IOCTL_BC_SET_CHANNEL	_IOW(MMRSE_IOC_MAGIC, 4, uint32_t)


/*
 ******************************************************************************
 * REMOTE TERMINAL
 ******************************************************************************
 */

#define GET_RT_BUF_SIZE		(32 * 2)		/* read or write */
#define GET_RT_BUFFS_SIZE	(64 * GET_RT_BUF_SIZE)	/* read or write */
#define GET_RT_BUF_NUM(off)	((off) >> 6)		/* / (2*32) */
#define GET_RT_BUF_BASE(num)	((num) << 6)		/* * (2*32) */


/**
 * MMRSE_IOCTL_RT_INIT
 * Initialize Remote Terminal
 *
 * Returns:
 *   -EFAULT - copy_from/to_user failure
 *   -EBUSY - Terminal not Active
 *   0 if success
 *
 * Usage:
 *   mmr_rt_init_t rt_i;
 *   rt_i.ta = 0;  // 0..30, 31 - disable
 *   rt_i.flags = RT_FLAG_BC_EN;
 *   rt_i.vw = VW;
 *   rt_i.imode = 0;
 *   rt_i.omode = 0;
 *   rt_i.set = RT_INIT_TFV | RT_INIT_IMODE | RT_INIT_OMODE;
 *   int ret = ioctl(fd, MMRSE_IOCTL_RT_INIT, &rt_i);
 */

/** mmr_rt_init_t flags: */
#define RT_FLAG_BC_EN	0x10	/* Enable Dynamic Bus Control Accept */
#define RT_FLAG_SRVREQ	0x08	/* Set Service Request Bit in Status Word */
#define RT_FLAG_BUSY	0x04	/* Set Busy Bit in Status Word */
#define RT_FLAG_TERM	0x02	/* Set Terminal Flag Bit in Status Word */
#define RT_FLAG_SUBSYS	0x01	/* Set Subsystem Flag Bit in Status Word */

/** mmr_rt_init_t set: */
#define RT_INIT_TFV	0x01	/* Set: ta, flags, vw */
#define RT_INIT_IMODE	0x02	/* Set: imode */
#define RT_INIT_OMODE	0x04	/* Set: omode */

typedef struct {
	uint8_t		ta;	/* Terminal Address: RT_ADDR_MIN..RT_ADDR_MAX */
	uint8_t		flags;	/* RT_FLAG_* ored */
	uint16_t	vw;	/* Vector Word */
	uint32_t	imode;	/* Enable buffers rewrite bitfield */
	uint32_t	omode;	/* Enable multi send bitfield */
	uint32_t	set;	/* RT_INIT_* ored */
} mmr_rt_init_t;

#define MMRSE_IOCTL_RT_INIT		_IOW(MMRSE_IOC_MAGIC, 5, mmr_rt_init_t)


/**
 * MMRSE_IOCTL_RT_GET_LAST_CMD
 * Get last command received
 *
 * Returns:
 *   -EFAULT - copy_from/to_user failure
 *   0 if success
 *
 * Usage:
 *   mmr_rt_last_cmd_t last_cmd;
 *   int ret = ioctl(fd, MMRSE_IOCTL_RT_GET_LAST_CMD, &last_cmd);
 *   if (last_cmd.cnt > 0) {
 *       if (last_cmd.cnt > 1)
 *           printf("some command is lost\n");
 *       uint16_t cw = last_cmd.cw;
 *       uint16_t dw = last_cmd.dw;
 *   } else {
 *       printf("no command received\n");
 *   }
 */

typedef struct {
	uint16_t	cw;	/* Command Word */
	uint16_t	dw;	/* Data Word */
	uint32_t	cnt;	/* 0 - empty, >1 - command received */
} mmr_rt_last_cmd_t;

#define MMRSE_IOCTL_RT_GET_LAST_CMD _IOR(MMRSE_IOC_MAGIC, 6, mmr_rt_last_cmd_t)


/*
 ******************************************************************************
 * BUS MONITOR
 ******************************************************************************
 */

/** Monitor Log DWORD format */
#define GET_MON_CHNUM(d)	((d) & 0x1)			/* [0] */
#define GET_MON_TIMECNT(d)	(((d) >> 1)  & 0x07FFUL)	/* [11:1] */
    #define MON_TIMECNT_FULL 0x800
#define GET_MON_ISPAUSE(d)	(((d) >> 12) & 0x0001UL)	/* [12] */
#define GET_MON_ISERCRC(d)	(((d) >> 13) & 0x0001UL)	/* [13] */
#define GET_MON_WRDTYPE(d)	(((d) >> 14) & 0x0003UL)	/* [15:14] */
    #define MON_WRDTYPE_DW 1
    #define MON_WRDTYPE_CW 2
#define GET_MON_WRDDATA(d)	(((d) >> 16) & 0xFFFFUL)	/* [31:16] */


/**
 * MMRSE_IOCTL_BM_STARTSTOP
 *
 * Returns:
 *   -EFAULT - copy_from/to_user failure
 *   0 if success
 *
 * Usage:
 *   uint64_t mode_size = BM_LOGMODE_VALID;
 *   int ret = ioctl(fd, MMRSE_IOCTL_BM_STARTSTOP, &mode_size);
 *   uint64_t log_size = mode_size;
 */

/** IN: Monitor Log mode */
#define BM_LOGMODE_OFF		0
#define BM_LOGMODE_FULL		1
#define BM_LOGMODE_VALID	2

/** OUT: log size: 32K..256K */

#define MMRSE_IOCTL_BM_STARTSTOP	_IOW(MMRSE_IOC_MAGIC, 7, uint64_t)


/**
 * MMRSE_IOCTL_BM_GET_PTRS
 * Read Rptr and Wptr
 *
 * Returns:
 *   -EFAULT - copy_from/to_user failure
 *   -ETIMEDOUT - log empty
 *   >= 0 - status codes:
 *         MMRSE_BM_GET_PTRS_RESULT_OK     - success
 *         MMRSE_BM_GET_PTRS_RESULT_LEMPTY - Log Full
 *
 * Usage:
 *   uint64_t w_r_ptr;
 *   int ret = ioctl(fd, MMRSE_IOCTL_BM_GET_PTRS, &w_r_ptr);
 *   uint32_t ptr_mask = (log_size >> 2) - 1;
 *   uint32_t rptr = (uint32_t)(w_r_ptr & ptr_mask);
 *   uint32_t wptr = (uint32_t)((w_r_ptr>>32) & ptr_mask);
 */
#define MMRSE_IOCTL_BM_GET_PTRS		_IOR(MMRSE_IOC_MAGIC, 8, uint64_t)

/** status codes: */
#define MMRSE_BM_GET_PTRS_RESULT_OK		0x0000
#define MMRSE_BM_GET_PTRS_RESULT_LEMPTY		0x0001


/**
 * MMRSE_IOCTL_BM_SET_RPTR
 * Set Rptr
 *
 * Returns:
 *   -EFAULT - copy_from/to_user failure
 *   0 if success
 *
 * Usage:
 *   uint32_t r_ptr = (uint32_t)(w_r_ptr & ptr_mask);
 *   int ret = ioctl(fd, MMRSE_IOCTL_BM_SET_RPTR, &r_ptr);
 */
#define MMRSE_IOCTL_BM_SET_RPTR		_IOW(MMRSE_IOC_MAGIC, 9, uint32_t)


#endif /* MMRSE_IOCTL_H__ */
