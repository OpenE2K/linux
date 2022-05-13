#ifndef	__MOKX_REGS_H__
#define	__MOKX_REGS_H__

/*
 * Structure message MOK_X
 *
 * 31:28 - rezerv   (��������������� - 0)
 * 27:24 - msg_type (��� ���������)
 * 23:16 - msg_addr (����� �������� ����������/������ ������)
 * 15:0  - msg_data (������)
 */
#define RDMA_MOK_X_TYPE_MSG_MASK	0x0f000000
#define RDMA_MOK_X_ADDR_MSG_MASK	0x00ff0000
#define RDMA_MOK_X_DATA_MSG_MASK	0x0000ffff
#define MOK_X_SHIFT_ADDR		16

/*
 * Type messages mask
 */
/* ������ �������� MOK_X */
#define RDMA_MOK_X_REG_WRITE			0x00000000
/* ������ �������� MOK_X */
#define RDMA_MOK_X_REG_READ			0x01000000
/* ������ �������� MOK_X �� ��������������� ������� */
#define RDMA_MOK_X_REMOTE_REG_WRITE		0x02000000
/* ������ �������� MOK_X �� ��������������� ������� */
#define RDMA_MOK_X_REMOTE_REG_READ		0x03000000
/* ����� �� ������ ������ �������� MOK_X �� ��������������� ������� */
#define RDMA_MOK_X_REMOTE_REG_RESPONSE		0x04000000
/* ������ �������� RDMA �� ��������������� ������� ������ */
#define RDMA_MOK_X_REMOTE_SYSTEM_REG_WRITE	0x05000000
/* ������ �������� RDMA �� ��������������� ������� ������ */
#define RDMA_MOK_X_REMOTE_SYSTEM_REG_READ	0x06000000
/* ����� �� ������ ������ �������� ������ �� ��������������� ������� ������ */
#define RDMA_MOK_X_REMOTE_SYSTEM_REG_RESPONSE	0x07000000
/* ����� ���� �������� */
#define RDMA_MOK_X_MSG_SHIFT			24

/* ������� 16 �������� �������� */
#define RDMA_MOK_X_LOW_REG			0x00000000
/* ������� 16 �������� �������� */
#define RDMA_MOK_X_HIGH_REG			0x01000000
/* ����� ��������� */
#define RDMA_MOK_X_MASK				0x00e00000

/*
 * Addrres registers MOK_X
 */
/* MDIO */
#define MOK_X_MGIO_CSR_H			0x0
#define MOK_X_MGIO_CSR_L			0x1
#define MOK_X_MGIO_DATA_H			0x2
#define MOK_X_MGIO_DATA_L			0x3
/* ������� ������������ � ������� */
#define MOK_X_CFG_STATUS			0x4
/* ������� ���������� ������� � ������ ����������� - tranciever_used_wd */
#define MOK_X_TRANCIEVER_USED_WD		0x5
/* ������� ���������� ������� � ������ ��������� - receiver_used_wd */
#define MOK_X_RECIEVER_USED_WD			0x6
/* ������� command */
#define MOK_X_COMMAND				0x7
/* ������� ������� ������� ����� ��� �������������� ������� �������� */
#define MOK_X_BURST_SIZE_H			0x8
/* ������� ������� ������� ����� ��� �������������� ������� �������� */
#define MOK_X_BURST_SIZE_L			0x9
/* ����� ��������� ������: 1 -����� �������� �������,    */
/*                         2 -����� �������� ������� 1G, */
/*                         0- �� ��������� ������� .     */
#define MOK_X_TEST_MODE_PACKETS			0xa
/* ������  XGMII 10:8 - ������ XGMII, 7:0 - ������ ���������� */
#define MOK_X_XGMII_CONTROL			0xf
/* ������� ���������� ������� (0x10 - 0x13) */
#define MOK_X_TRANSMITTED_PACKET_COUNTER0	0x10
#define MOK_X_TRANSMITTED_PACKET_COUNTER1	0x11
#define MOK_X_TRANSMITTED_PACKET_COUNTER2	0x12
#define MOK_X_TRANSMITTED_PACKET_COUNTER3	0x13
/* ������� �������� ������� (0x14 - 0x17) */
#define MOK_X_RECEIVED_PACKET_COUNTER0		0x14
#define MOK_X_RECEIVED_PACKET_COUNTER1		0x15
#define MOK_X_RECEIVED_PACKET_COUNTER2		0x16
#define MOK_X_RECEIVED_PACKET_COUNTER3		0x17
/* ������� �������� ������� � �������� (0x18 - 0x1b) */
#define MOK_X_RECEIVED_PACKET_ERR_COUNTER0	0x18
#define MOK_X_RECEIVED_PACKET_ERR_COUNTER1	0x19
#define MOK_X_RECEIVED_PACKET_ERR_COUNTER2	0x1a
#define MOK_X_RECEIVED_PACKET_ERR_COUNTER3	0x1b
/* ������� ���������� ������� (0x1c - 0x1f) */
#define MOK_X_RECEIVED_PACKET_NOT_COUNTER0	0x1c
#define MOK_X_RECEIVED_PACKET_NOT_COUNTER1	0x1d
#define MOK_X_RECEIVED_PACKET_NOT_COUNTER2	0x1e
#define MOK_X_RECEIVED_PACKET_NOT_COUNTER3	0x1f

/*
 * Register config/status MOK_X
 */
/* 15,r  link - �������� ����������. */
#define MOK_X_CFG_LINK_SHIFT			15
#define MOK_X_CFG_LINK			(1<<MOK_X_CFG_LINK_SHIFT)
/* 14,r  enable - �������������� ���. ��������� �� ��, ��� ����������
/ *      ����� ���� ������������� ��� ��ɣ��/�������� ������. */
#define MOK_X_CFG_ENABLE_SHIFT			14
#define MOK_X_CFG_ENABLE		(1<<MOK_X_CFG_ENABLE_SHIFT)
/* 13,rw master - ���, ����������� �� �� ��� ��� ������� �������. */
#define MOK_X_CFG_MASTER_SHIFT			13
#define MOK_X_CFG_MASTER		(1<<MOK_X_CFG_MASTER_SHIFT)
/* 12,rw slave - ���, ����������� �� �� ��� ��� ������� �������. */
#define MOK_X_CFG_SLAVE_SHIFT			12
#define MOK_X_CFG_SLAVE			(1<<MOK_X_CFG_SLAVE_SHIFT)
/* 11,rw enable_transmit - ���������� �������� ������. */
#define MOK_X_CFG_ENABLE_TRANSMIT_SHIFT		11
#define MOK_X_CFG_ENABLE_TRANSMIT	(1<<MOK_X_CFG_ENABLE_TRANSMIT_SHIFT)
/* 10,rw enable_receive - ���������� ��ɣ�� ������. ���� ���� ��� �� */
/*       ����������, �� ��� �������� ������ ������ ������������.     */
#define MOK_X_CFG_ENABLE_RECEIVE_SHIFT		10
#define MOK_X_CFG_ENABLE_RECEIVE	(1<<MOK_X_CFG_ENABLE_RECEIVE_SHIFT)
/* 9,rw  ready_to_receive - ���, ����������� ��������� ������. ���� ���� ��� */
/*       �� ����������, �� ��� �������� ������ ������ ����������� � ��ɣ���� */
/*       ������ � ������ ����������� �� ��������������� �������.	     */
#define MOK_X_CFG_READY_TO_RECEIVE_SHIFT	9
#define MOK_X_CFG_READY_TO_RECEIVE	(1<<MOK_X_CFG_READY_TO_RECEIVE_SHIFT)
/* 8,rw  granted_last_packet - ��������� ����� ���� ����������� �������� */
/*       ��������������� �������� ���������� ������ � ������.            */
#define MOK_X_CFG_GRANTED_LAST_PACKET_SHIFT	8
#define MOK_X_CFG_GRANTED_LAST_PACKET	(1<<MOK_X_CFG_GRANTED_LAST_PACKET_SHIFT)
/* 7,rw  granted_packet - ��������� ����� ���� ����������� �������� */
/*       ��������������� �������� ���� �������.			    */
#define MOK_X_CFG_GRANTED_PACKET_SHIFT		7
#define MOK_X_CFG_GRANTED_PACKET	(1<<MOK_X_CFG_GRANTED_PACKET_SHIFT)
/* 6,rw  in_ready_to_receive - ��������� ��� ��������������� ������� ������ */
/*       ��������� ������ */
#define MOK_X_CFG_IN_READY_TO_RECEIVE_SHIFT	6
#define MOK_X_CFG_IN_READY_TO_RECEIVE	(1<<MOK_X_CFG_IN_READY_TO_RECEIVE_SHIFT)
/* 5,rw  ����� ������ MODE1 */
#define MOK_X_CFG_MODE1_SHIFT			5
#define MOK_X_CFG_MODE1			(1<<MOK_X_CFG_MODE1_SHIFT)
/* 4,rw  ����� ������ MODE2 */
#define MOK_X_CFG_MODE2_SHIFT			4
#define MOK_X_CFG_MODE2			(1<<MOK_X_CFG_MODE2_SHIFT)
/* 3,rw  ����� ������ MODE3 */
#define MOK_X_CFG_MODE3_SHIFT			3
#define MOK_X_CFG_MODE3			(1<<MOK_X_CFG_MODE3_SHIFT)
/* 2,    ����� ������ MODE4 */
#define MOK_X_CFG_MODE4_SHIFT			2
#define MOK_X_CFG_MODE4			(1<<MOK_X_CFG_MODE4_SHIFT)
/* 1,    Timeout, ��������� �� �������� */
#define MOK_X_CFG_TIMEOUT_MSG_RECEIVE_SHIFT	1
#define MOK_X_CFG_TIMEOUT_MSG_RECEIVE	(1<<MOK_X_CFG_TIMEOUT_MSG_RECEIVE_SHIFT)
/* 0,    ������ 0 */
#define MOK_X_CFG_RESERV_0		0x00000000

/*
 * Register MGIO_CSR MOK_X
 */
/* 31-14 unused */
#define MOK_X_MGIO_CSR_UNUSED1_MASQ	0xffffd000
/* 13 RRDY (RESULT READY) rc */
#define MOK_X_MGIO_CSR_RESULT READY	0x00002000
/* 12-0 unused */
#define MOK_X_MGIO_CSR_UNUSED0_MASQ	0x00001fff

/*
 * Register MGIO_DATA MOK_X
 */
/* 31-30 - start of frame must be 01 */
#define MOK_X_MGIO_DATA_START_FRAME	0x00000000
/* 29-28 - operation code 01-write 10-read */
#define MOK_X_MGIO_DATA_OPER_CODE_ADDR	0x00000000
#define MOK_X_MGIO_DATA_OPER_CODE_WR	0x10000000
#define MOK_X_MGIO_DATA_OPER_CODE_RD	0x30000000
#define MOK_X_MGIO_DATA_OPER_CODE_RD_INC	0x20000000

/* 27-23 - phy address */
#define MOK_X_MGIO_DATA_PHY_ADDR_MASQ	0x0f800000
/* 22-18 - register address */
#define MOK_X_MGIO_DATA_REG_ADDR_MASQ	0x007c0000
/* 17-16 - must be 10 */
#define MOK_X_MGIO_DATA_TMP_CODE	0x00020000
/* 15-00 - on write command - data to be written */
#define MOK_X_MGIO_DATA_DATA_MASQ	0x0000ffff

/*
 * Register command MOK_X
 * �������, ��������
 */
/* 0x00, ����� ����������� */
#define MOK_X_COMMAND_RESET			0x00
/* 0x01, ����� transmitted packets counter */
#define MOK_X_TRANSMITTED_PACKET_COUNTER_RESET	0x01
/* 0x02, ����� Received packets counter, Received packets with error counter, */
/* Not received packets counter 					      */
#define MOK_X_TRANSMITTED_PACKET_COUNTER_OTHER	0x02
/* Reset PM8358*/
#define MOK_X_RESET_PM8358			0x03
/* Reset VSC8488*/
#define MOK_X_RESET_VSC8488			0x03

/*
 * Address RDMA register for MOK_X
 * Bug: 5 �������� �� ������� ���������� ��� RDMA reg - ���������� 16. ���������
 * ������ ���������.
 */
#define	RDMA_VID_H		0x00000000
#define	RDMA_VID_L		0x00010000
#define	RDMA_CS_H		0x00020000
#define	RDMA_CS_L		0x00030000
#define RDMA_ES_H		0x00040000	/* Event Status */
#define RDMA_ES_L		0x00050000	/* Event Status */
#define RDMA_IRQ_MC_H		0x00060000	/* Interrupt Mask Control */
#define RDMA_IRQ_MC_L		0x00070000	/* Interrupt Mask Control */
#define RDMA_DMA_TCS_H		0x00080000	/* DMA Tx Control/Status */
#define RDMA_DMA_TCS_L		0x00090000	/* DMA Tx Control/Status */
#define RDMA_DMA_TSA_H		0x000a0000	/* DMA Tx Start Address */
#define RDMA_DMA_TSA_L		0x000b0000	/* DMA Tx Start Address */
#define RDMA_DMA_TBC_H		0x000c0000	/* DMA Tx Byte Counter */
#define RDMA_DMA_TBC_L		0x000d0000	/* DMA Tx Byte Counter */
#define RDMA_DMA_RCS_H		0x000e0000	/* DMA Rx Control/Status */
#define RDMA_DMA_RCS_L		0x000f0000	/* DMA Rx Control/Status */
#define RDMA_DMA_RSA_H		0x00100000	/* DMA Rx Start Address */
#define RDMA_DMA_RSA_L		0x00110000	/* DMA Rx Start Address */
#define RDMA_DMA_RBC_H		0x00120000	/* DMA Rx Byte Counter */
#define RDMA_DMA_RBC_L		0x00130000	/* DMA Rx Byte Counter */
#define RDMA_MSG_CS_H		0x00140000	/* Messages Control/Status */
#define RDMA_MSG_CS_L		0x00150000	/* Messages Control/Status */
#define RDMA_TDMSG_H		0x00160000	/* Tx Data_Messages Buffer */
#define RDMA_TDMSG_L		0x00170000	/* Tx Data_Messages Buffer */
#define RDMA_RDMSG_H		0x00180000	/* Rx Data_Messages Buffer */
#define RDMA_RDMSG_L		0x00190000	/* Rx Data_Messages Buffer */
#define RDMA_DMA_HTSA_H		0x001a0000	/* DMA Tx Start Address */
#define RDMA_DMA_HTSA_L		0x001b0000	/* DMA Tx Start Address */
#define RDMA_DMA_HRSA_H		0x001c0000	/* DMA Tx Start Address */
#define	RDMA_DMA_HRSA_L		0x001d0000	/* DMA Tx Start Address */

#if 0
#define	RDMA_CH_IDT_H		0x00030000
#define	RDMA_CH_IDT_L		0x00040000
#define	RDMA_DD_ID_H		0x00070000
#define	RDMA_DD_ID_L		0x00080000
#define	RDMA_DMD_ID_H		0x00090000
#define	RDMA_DMD_ID_L		0x000a0000
#define	RDMA_N_IDT_H		0x000b0000
#define	RDMA_N_IDT_L		0x000c0000
#define	RDMA_CAM_H		0x000c0000 /* CAM - channel alive management */
#define	RDMA_CAM_L		0x000c0000 /* CAM - channel alive management */
#endif

#endif /* __MOKX_REGS_H__ */
