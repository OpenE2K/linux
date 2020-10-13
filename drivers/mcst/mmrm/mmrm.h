/* 
*
*/
#ifndef _MMRM_DRV_H
#define _MMRM_DRV_H

#define VENDOR_MCST			0x1FFF
#define MMRM_DEVICE_ID		0x8002
#define BRIDGE_DEVICE_ID	0x8001
#define MIN_REVISION		0x80
#define PR_READ_SIZE_REG	0x41
#define MMRM_READ_SIZE		0x04

#define MMRM_MAJOR_DEFAULT			0
#define MAX_MMRM					8
#define DEVICE_MEM_BYTE_SIZE		0x1C00
#define DEVICE_MEM_WORD_SIZE		DEVICE_MEM_BYTE_SIZE / 4
#define DEVICE_BUF_QUANTITY			64
#define DEVICE_BUF_BYTE_SIZE		64
#define BATCH_BUF_BYTE_SIZE			64
#define DEVICE_MEM_CLEAR			0xF4F4F4F4
#define MMRM_REGISTERS_ADR			0x800
#define BATCH_CMD_QUANTITY_REG_ADR	MMRM_REGISTERS_ADR + 0x00
#define BATCH_CMD_ADR_REG_ADR		MMRM_REGISTERS_ADR + 0x02
#define DEVICE_REGIM_REG_ADR		MMRM_REGISTERS_ADR + 0x09
#define U0KMKP_REG_ADR				MMRM_REGISTERS_ADR + 0x20
#define INTERRUPT_REG_ADR			MMRM_REGISTERS_ADR + 0x21
#define MAX_COMMAND_TIME			1000000
#define BLOCK_1_CHANNEL				0x0100
#define BLOCK_0_CHANNEL				0x0080
#define COMPLET_DESK_RES_SPOOL		0x00000004

typedef struct mmrm_dev {
	int			instance;
	int					opened;
	struct pci_dev		*pdev;
	int					irq;
	u32					*device_mem_start;
	u32					*batch_dma_adr;
	u32					*buf_dma_adr[DEVICE_BUF_QUANTITY];
	dma_addr_t			batch_bus_addr;
	dma_addr_t			bus_addr[DEVICE_BUF_QUANTITY];
	int					device_type;
	mmrm_term_dev_adr_t	term_dev_adress;
	mmrm_term_trans_t	term_trans_direction;
	mmrm_subadress_t	subadress;
	size_or_code_t		size_or_code;
	wait_queue_head_t	wait_trans_fin_queue;
	int					trans_completed;
	raw_spinlock_t		lock;
	kcondvar_t		intr_cv;
} mmrm_dev_t;

irqreturn_t pre_mmrm_handler(int irq, void *arg);
irqreturn_t mmrm_intr_handler(int irq, void *arg);

#endif  /* !(_MMRM_DRV_H) */
