/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef MMRSE_REGS_H__
#define MMRSE_REGS_H__

/* mmrm_regs.doc - 2013.06.17 20:59 */

/**
 *  Bitfield tool
 */
#define GET_FIELD(r, p, m)  (((r) >> (p)) & (m))
#define GET_BIT(r, p)       GET_FIELD(r, p, 1)

#define SET_FIELD(d, p, m)  (((m) & (d)) << (p))
#define SET_BIT(p)          (1UL << (p))


/**
 * ENDIANES
 */
#ifdef __sparc__	/* ARCH: e90, e90s */
	#define MMRM_ENDIAN  (0x00000000)
	/*#define MMRM_ENDIAN  (0x00010100)*/
#else			/* ARCH: e2k, x86 */
	#define MMRM_ENDIAN  (0x00000000)
#endif /* __sparc__ */

#define buf32rd(x) readl(x)
#define buf32wr(d, x) writel(d, x)
#define reg32rd(x) readl(x)
#define reg32wr(d, x) writel(d, x)


/**
 *  Registers definitions
 *
 *  COMMON
 *
 * Common_Status Reg	+ 00h
 * DMA_Latency Reg	+ 04h
 *
 *  BUS CONTROLLER
 *
 * BC_Command Reg	+ 10h (FIFO x16)
 * BC_Result Reg	+ 14h (no FIFO)
 * BC_Control Reg	+ 18h
 * BC_Status Reg	+ 1Ch
 *
 *  REMOTE TERMINAL
 *
 * RT_Control Reg	+ 20h
 * RT_Status Reg	+ 24h
 * RT_Command Reg	+ 28h (FIFO x4)
 * RT_Task Reg		+ 2Ch
 *
 * RT_IValid Reg	+ 30h
 * RT_IFlag Reg		+ 34h
 * RT_IMode Reg		+ 38h
 * RT_IMask Reg		+ 3Ch
 *
 * RT_OValid Reg	+ 40h
 * RT_OFlag Reg		+ 44h
 * RT_OMode Reg		+ 48h
 * RT_OMask Reg		+ 4Ch
 *
 *  BUS MONITOR
 *
 * BM_Control Reg	+ 50h
 * BM_SAddr Reg		+ 54h
 * BM_WPtr Reg		+ 58h
 * BM_RPtr Reg		+ 5Ch
 */


/**
 ******************************************************************************
 * COMMON
 ******************************************************************************
 */

/* Common_Status Reg  | reset 0x0000:0000 */
#define COMMON_STATUS_REG		0x00
#define P_COMMON_STATUS_REG(x)		((void *)((x) + COMMON_STATUS_REG))
  #define COMMON_STATUS_GET_VERSION(r)	GET_FIELD(r, 24, 0xFF)	/* RO [31:24] */
  #define COMMON_STATUS_GET_INTSRC(r)	GET_FIELD(r, 0, 0x07)	/* RO [02:00] */
    #define COMMON_STATUS_INTSRC_BM	4
    #define COMMON_STATUS_INTSRC_RT	2
    #define COMMON_STATUS_INTSRC_BC	1
  #define COMMON_STATUS_SET_ACCESSMODE	MMRM_ENDIAN	/* RW [17:16][09:08] */

/* DMA_Latency Reg  | reset 0x0000:0000 | RO [31:00] */
#define DMA_LATENCY_REG			0x04
#define P_DMA_LATENCY_REG(x)		((void *)((x) + DMA_LATENCY_REG))


/**
 ******************************************************************************
 * Bus Controller
 ******************************************************************************
 */

/* BC_Command Reg     | reset 0x0000:0000 | FIFO x16 */
#define BC_COMMAND_REG			0x10
#define P_BC_COMMAND_REG(x)		((void *)((x) + BC_COMMAND_REG))
  /* Data Word (DW) in Mode Command with Data Word (Receive) */
  #define BC_COMMAND_SET_DW(d)		SET_FIELD(d, 16, 0xFFFF)/* RW [31:16] */
  /* Command Word (CW) next CW in format 3 and 8 */
  #define BC_COMMAND_SET_CW1(d)		SET_FIELD(d, 16, 0xFFFF)/* RW [31:16] */
  /* Command Word (CW) in Mode Command - mode codes */
  #define BC_COMMAND_SET_CW(d)		SET_FIELD(d, 0, 0xFFFF)	/* RW [15:00] */
  /* Command Word (CW) first CW in format 3 and 8 */
  #define BC_COMMAND_SET_CW0(d)		SET_FIELD(d, 0, 0xFFFF)	/* RW [15:00] */

/* BC_Result Reg      | reset 0x0000:0000 | no FIFO */
#define BC_RESULT_REG			0x14
#define P_BC_RESULT_REG(x)		((void *)((x) + BC_RESULT_REG))
  /* Data Word (DW) in Mode Command with Data Word  (Transmit) */
  #define BC_RESULT_GET_DW(r)		GET_FIELD(r, 16, 0xFFFF)/* RO [31:16] */
  /* Status Word (SW) next SW in format 3 and 8 */
  #define BC_RESULT_GET_SW1(r)		GET_FIELD(r, 16, 0xFFFF)/* RO [31:16] */
  /* Status Word (SW) in Mode Command - status defines */
  #define BC_RESULT_GET_SW(r)		GET_FIELD(r, 0, 0xFFFF)	/* RO [15:00] */
  /* Status Word (SW) first SW in format 3 and 8 */
  #define BC_RESULT_GET_SW0(r)		GET_FIELD(r, 0, 0xFFFF)	/* RO [15:00] */

/* BC_Control Reg     | reset 0x0000:0000 */
#define BC_CONTROL_REG			0x18
#define P_BC_CONTROL_REG(x)		((void *)((x) + BC_CONTROL_REG))
  /* buffer address in system memory */
  #define BC_CONTROL_SET_BUFADDR(d)	(0xFFFFF000UL & (d))	/* RW [31:12] */
  /* interrupt mode */
  #define BC_CONTROL_SET_INTMODE_ECBUF	SET_BIT(3)		/* RW [3] */
  #define BC_CONTROL_SET_INTMODE_DIS	(0 << 1)		/* RW [02:01] */
  #define BC_CONTROL_SET_INTMODE_SPEC	(1 << 1)		/* RW [02:01] */
  #define BC_CONTROL_SET_INTMODE_CMD	(2 << 1)		/* RW [02:01] */
  #define BC_CONTROL_SET_INTMODE_ALL	(3 << 1)		/* RW [02:01] */
  /* soft reset */
  #define BC_CONTROL_SET_SOFTRST	SET_BIT(0)		/* RW1S [0] */

/* BC_Status Reg      | reset 0x0000:0100 */
#define BC_STATUS_REG			0x1C
#define P_BC_STATUS_REG(x)		((void *)((x) + BC_STATUS_REG))
  /* Status Word (SW) in Mode Command - status defines */
  #define BC_STATUS_GET_SW(r)		GET_FIELD(r, 16, 0xFFFF)/* RO [31:16] */
  /* Status Word (SW) Valid */
  #define BC_STATUS_GET_SWVALID(r)	GET_BIT(r, 15)		/* RO [15] */
  /* last command result */
  #define BC_STATUS_GET_RESULT(r)	GET_FIELD(r, 12, 0x7)	/* RO [14:12] */
    #define BC_STATUS_RESULT_OK		0	/* success */
    #define BC_STATUS_RESULT_ECRC	1	/* crc error */
    #define BC_STATUS_RESULT_ETO	2	/* timeout */
    #define BC_STATUS_RESULT_ESPEC	3	/* special fields in SW */
    #define BC_STATUS_RESULT_ECMD	4	/* wrong command */
    #define BC_STATUS_RESULT_ERP	5	/* pause on receive */
    #define BC_STATUS_RESULT_NONE	7	/* for internal use - no SW */
  /* cmd fifo current length */
  #define BC_STATUS_GET_BUFCMDLEN(r)	GET_FIELD(r, 4, 0x1F)	/* RO [08:04] */
  /* Tx channel */
  #define BC_STATUS_SET_CHANNEL(d)	SET_FIELD(d, 2, 0x3)	/* RW [03:02] */
  #define BC_STATUS_GET_CHANNEL(r)	GET_FIELD(r, 2, 0x3)	/* RW [03:02] */
    #define BC_STATUS_CHANNEL0		1	/* default */
    #define BC_STATUS_CHANNEL1		2
  /* clean cmd fifo */
  #define BC_STATUS_SET_BUFCMDCLEAN	SET_BIT(1)		/* RW1S [1] */
  /* interrupt status */
  #define BC_STATUS_GET_INTSTAT(r)	GET_BIT(r, 0)		/* RW1C [0] */
  #define BC_STATUS_SET_INTACK		SET_BIT(0)		/* RW1C [0] */


/**
 ******************************************************************************
 * Remote Terminal
 ******************************************************************************
 */

/* RT_Control Reg     | reset 0x0000:0000 */
#define RT_CONTROL_REG			0x20
#define P_RT_CONTROL_REG(x)		((void *)((x) + RT_CONTROL_REG))
  /* Data Word (DW) in Mode Command: transmit vector word */
  #define RT_CONTROL_SET_VW(d)		SET_FIELD(d, 16, 0xFFFF)/* RW [31:16] */
  /* Set Dynamic Bus Control Bit in Status Word */
  #define RT_CONTROL_SET_BUSACPT	SET_BIT(15)		/* RW [15] */
  /* Remote Terminal Address */
  #define RT_CONTROL_SET_RTA(d)		SET_FIELD(d, 8, 0x1F)	/* RW [12:08] */
    #define RT_CONTROL_RTA_DIS		0x1F	/* group address - disable RT */
  /* Set All Force Flags */
  #define RT_CONTROL_SET_FF(d)		SET_FIELD(d, 4, 0x0F)	/* RW [07:04] */
  /* Set Service Request Bit in Status Word */
  #define RT_CONTROL_SET_SRVREQ		SET_BIT(7)		/* RW [7] */
  /* Set Busy Bit in Status Word */
  #define RT_CONTROL_SET_BUSY		SET_BIT(6)		/* RW [6] */
  /* Set Terminal Flag Bit in Status Word */
  #define RT_CONTROL_SET_TERM		SET_BIT(5)		/* RW [5] */
  /* Set Subsustem Flag Bit in Status Word */
  #define RT_CONTROL_SET_SUBSYS		SET_BIT(4)		/* RW [4] */
  /* Interrupt mode */
  #define RT_CONTROL_SET_INTMODE_DMA	SET_BIT(3)		/* RW [3] */
  #define RT_CONTROL_SET_INTMODE_DIS	(0 << 1)		/* RW [02:01] */
  #define RT_CONTROL_SET_INTMODE_CMD	(1 << 1)		/* RW [02:01] */
  #define RT_CONTROL_SET_INTMODE_SPEC	(2 << 1)		/* RW [02:01] */
  #define RT_CONTROL_SET_INTMODE_ALL	(3 << 1)		/* RW [02:01] */
  /* soft reset */
  #define RT_CONTROL_SET_SOFTRST	SET_BIT(0)		/* RW1S [0] */

/* RT_Status Reg      | reset 0x0000:0000 */
#define RT_STATUS_REG			0x24
#define P_RT_STATUS_REG(x)		((void *)((x) + RT_STATUS_REG))
  /* Data Word (DW) in Mode Command: transmit BIT word */
  #define RT_STATUS_GET_BITW(r)		GET_FIELD(r, 16, 0xFFFF)/* RO [31:16] */
  /* Disable RT (enable through RT_Control.SET_RTA) */
  #define RT_STATUS_SET_RTDIS		SET_BIT(15)		/* RW1C [15] */
  #define RT_STATUS_GET_RTACT(r)	GET_BIT(r, 15)		/* RW1C [15] */
  /* Channel Tx Status */
  #define RT_STATUS_GET_CHS(r)		GET_FIELD(r, 12, 0x03)	/* RO [13:12] */
  #define RT_STATUS_GET_CH1_DIS(r)	GET_BIT(r, 13)		/* RO [13] */
  #define RT_STATUS_GET_CH0_DIS(r)	GET_BIT(r, 12)		/* RO [12] */
  /* Current Status Word Status (see status defines) */
  #define RT_STATUS_GET_SW(r)		GET_FIELD(r, 4, 0xFF)	/* RO [11:04] */
    #define RT_STATUS_SW_MSGERR		0x80	/* message error */
    #define RT_STATUS_SW_INS		0x40	/* instrumentation */
    #define RT_STATUS_SW_SRQ		0x20	/* service request */
    #define RT_STATUS_SW_BDCST		0x10	/* broadcast rcvd */
    #define RT_STATUS_SW_SUBSYSBSY	0x08	/* busy */
    #define RT_STATUS_SW_SUBSYSFL	0x04	/* sub system flag */
    #define RT_STATUS_SW_BUS_ACPT	0x02	/* dynamic bus acceptance */
    #define RT_STATUS_SW_TERM		0x01	/* terminal flag */
  /* Interrupt status */
  #define RT_STATUS_GET_INTSTAT_ALL(r)	GET_FIELD(r, 0, 0xF)	/* R0 [03:00] */
    #define RT_STATUS_INTSTAT_DMA	0x08	/* end of DMA transaction */
    #define RT_STATUS_INTSTAT_CMD	0x04	/* command received */
    #define RT_STATUS_INTSTAT_RX	0x02	/* data received */
    #define RT_STATUS_INTSTAT_TX	0x01	/* data transmitted */
  #define RT_STATUS_SET_INTACK(d)	SET_FIELD(d, 0, 0x0F)	/* RW1S [3:0] */
    #define RT_STATUS_INTACK_ALL	(0x0000000FUL)		/* RW1S [3:0] */
  #define RT_STATUS_SET_INTACK_DMA	SET_BIT(3)		/* R0 [3] */
  #define RT_STATUS_SET_INTACK_CMD	SET_BIT(2)		/* RO [2] */
  #define RT_STATUS_SET_INTACK_RX	SET_BIT(1)		/* RO [1] */
  #define RT_STATUS_SET_INTACK_TX	SET_BIT(0)		/* RO [0] */

/* RT_Command Reg     | reset 0x0000:0000 | FIFO*4 - ! FIFO ! */
#define RT_COMMAND_REG			0x28
#define P_RT_COMMAND_REG(x)		((void *)((x) + RT_COMMAND_REG))
  /* Data Word (DW) in Mode Command with Data Word */
  #define RT_COMMAND_GET_DW(r)		GET_FIELD(r, 16, 0xFFFF)/* RO [31:16] */
  /* Command Word (SW) in Mode Command */
  #define RT_COMMAND_GET_CW(r)		GET_FIELD(r, 0, 0xFFFF)	/* RO [15:00] */

/* RT_Task Reg        | reset 0x0000:0000 */
#define RT_TASK_REG			0x2C
#define P_RT_TASK_REG(x)		((void *)((x) + RT_TASK_REG))
  #define RT_TASK_SET_DMAADDR(d)	(0xFFFFFFC0UL & (d))	/* RW [31:06] */
  #define RT_TASK_SET_BUFNUM(d)		SET_FIELD(d, 0, 0x3F)	/* RW [05:00] */

/* RT_IValid Reg      | reset 0x0000:0000 */
#define RT_IVALID_REG			0x30
#define P_RT_IVALID_REG(x)		((void *)((x) + RT_IVALID_REG))  /* RW1C */

/* RT_IFlag Reg       | reset 0x0000:0000 */
#define RT_IFLAG_REG			0x34
#define P_RT_IFLAG_REG(x)		((void *)((x) + RT_IFLAG_REG))	/* RO */

/* RT_IMode Reg       | reset 0x0000:0000 */
#define RT_IMODE_REG			0x38
#define P_RT_IMODE_REG(x)		((void *)((x) + RT_IMODE_REG))	/* RW */

/* RT_IMask Reg       | reset 0x0000:0000 */
#define RT_IMASK_REG			0x3C
#define P_RT_IMASK_REG(x)		((void *)((x) + RT_IMASK_REG))	/* RW */

/* RT_OValid Reg      | reset 0x0000:0000 */
#define RT_OVALID_REG			0x40
#define P_RT_OVALID_REG(x)		((void *)((x) + RT_OVALID_REG))  /* RW1S */

/* RT_OFlag Reg       | reset 0x0000:0000 */
#define RT_OFLAG_REG			0x44
#define P_RT_OFLAG_REG(x)		((void *)((x) + RT_OFLAG_REG))   /* RW1C */

/* RT_OMode Reg       | reset 0x0000:0000 */
#define RT_OMODE_REG			0x48
#define P_RT_OMODE_REG(x)		((void *)((x) + RT_OMODE_REG))	/* RW */

/* RT_OMask Reg       | reset 0x0000:0000 */
#define RT_OMASK_REG			0x4C
#define P_RT_OMASK_REG(x)		((void *)((x) + RT_OMASK_REG))	/* RW */


/**
 ******************************************************************************
 * Bus Monitor
 ******************************************************************************
 */

/* BM_Control Reg     | reset 0x0000:0000 */
#define BM_CONTROL_REG			0x50
#define P_BM_CONTROL_REG(x)		((void *)((x) + BM_CONTROL_REG))
  #define BM_CONTROL_LOG_MASK		((0x3 << 16) | (0x3 << 14))
  /* Log size */
  #define BM_CONTROL_SET_LOGSIZE(d)	SET_FIELD(d, 16, 0x3)	/* RW [17:16] */
    #define BM_CONTROL_LOGSIZE_32K	1
    #define BM_CONTROL_LOGSIZE_64K	2
    #define BM_CONTROL_LOGSIZE_128K	3
    #define BM_CONTROL_LOGSIZE_256K	0
  /* Log mode */
  #define BM_CONTROL_SET_LOGMODE(d)	SET_FIELD(d, 14, 0x3)	/* RW [15:14] */
    #define BM_CONTROL_LOGMODE_OFF	0
    #define BM_CONTROL_LOGMODE_FULL	1
    #define BM_CONTROL_LOGMODE_VALID	2
  /* Log Full */
  #define BM_CONTROL_GET_ISFULL(r)	GET_BIT(r, 4)		/* RO [4] */
  /* Interrupt mode */
  #define BM_CONTROL_INTMODE_MASK	(0x3 << 1)
  #define BM_CONTROL_SET_INTMODE_DATA	SET_BIT(2)		/* RW [2] */
  #define BM_CONTROL_SET_INTMODE_LPAGE	SET_BIT(1)		/* RW [1] */
  /* Soft Reset */
  #define BM_CONTROL_SET_SOFTRST	SET_BIT(0)		/* RW1S [0] */

/* BM_SAddr Reg       | reset 0x0000:0000 */
#define BM_SADDR_REG			0x54
#define P_BM_SADDR_REG(x)		((void *)((x) + BM_SADDR_REG))
  #define BM_SADDR_SET_LOGADDR(d)	(0xFFFFF000UL & (d))	/* RW [31:12] */

/* BM_WPtr Reg        | reset 0x0000:0000 */
#define BM_WPTR_REG			0x58
#define P_BM_WPTR_REG(x)		((void *)((x) + BM_WPTR_REG))
  /* Int Status */
  #define BM_WPTR_GET_INTSTAT(r)	GET_BIT(r, 31)		/* RW1S [31] */
  #define BM_WPTR_SET_INTACK		SET_BIT(31)		/* RW1S [31] */
  /* Log Wptr */
  #define BM_WPTR_GET_LOGWPTR(r)	GET_FIELD(r, 0, 0x3FFFF)/* RO [17:00] */

/* BM_RPtr Reg        | reset 0x0000:0000 */
#define BM_RPTR_REG			0x5C
#define P_BM_RPTR_REG(x)		((void *)((x) + BM_RPTR_REG))
  /* Log Rptr */
  #define BM_RPTR_GET_LOGRPTR(r)	GET_FIELD(r, 0, 0x3FFFF)/* RW [17:00] */
  #define BM_RPTR_SET_LOGRPTR(d)	SET_FIELD(d, 0, 0x3FFFF)/* RW [17:00] */


/**
 ******************************************************************************
 * size of a reg-memory & buffers
 ******************************************************************************
 */

/* Region 0: Memory (32-bit, non-prefetchable) [size=128] */
#define PCI_PORT_SIZE			0x60

/** size of a buf-memory */
/* Region 1: Memory (32-bit, non-prefetchable) [size=4K] */
#define PCI_BUFF_SIZE			0x1000

/** size of a memory for BC buffers [4k] */
#define BC_BUFF_SIZE			(32 * 2 * 32 * 2)

/** size of a memory BM log - 32K, 64K, 128K, 256K (base 32k) */
#define BM_LOG_PAGE_SIZE		0x1000  /* 4K */


#endif /* MMRSE_REGS_H__ */
