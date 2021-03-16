/* 
*
*/

#ifndef _UAPI_MGPM_DRV_H
#define _UAPI_MGPM_DRV_H

#define VENDOR_MCST      0x1FFF
#define MGPM_DEVICE_ID   0x8003

#ifndef MGPM_MAJOR_DEFAULT
#define MGPM_MAJOR_DEFAULT 0
#endif

#define	mcst_node_type	"mcst_node_type"
#define	pci_dev_name	"pci1fff,8003"

#define	mgpm_module_name	"mgpm"

#define	NUM_OF_CHIP	1

#define MAX_MGPM                   8
#define DEVICE_BUF_QUANTITY        2
#define DEV_SWAPING_BYTE_ADR	   0x40
#define DEVICE_MEM_CLEAR           0xF4F4F4F4
#define MGPM_REGISTERS_ADR         0x800

#define DEVICE_REGIM_REG_ADR       (MGPM_REGISTERS_ADR + 0x09)*4
#define U0KMKP_REG_ADR             (MGPM_REGISTERS_ADR + 0x20)*4
#define INTERRUPT_REG_ADR          (MGPM_REGISTERS_ADR + 0x21)*4
#define BLOCK_1_CHANNEL            0x0100
#define BLOCK_0_CHANNEL            0x0080
#define MAX_COMMAND_TIME           5000000

#define BATCH_CMD_QUANTITY_REG_ADR 0x2000
#define BATCH_CMD_ADR_REG_ADR	   0x2004

#define MGPM_ADDR_WRITE		0x1400
#define MGPM_ADDR_READ		0x1404

#define MGPM_FR_NUM_TPR		0x2080 /*  */
#define MGPM_CT_T		0x2090 /* Timer */
#define MGPM_CT_MC_FPR		0x20a0 /* */

#define	MGPM_RESET		0x2010 /* Reset the device 		  */

#define MGPM_INTR_REG		0x2014 /* Interrupt triger (Read only) */
#define MGPM_INTR_FEQ_REG	0x2040 /* set interrupt frequency  R/W */
#define MGPM_CLR_INTR_MASK	0x2044 /* Interrupt Start. */
#define	MGPM_CLEAR_INTR_CNT	0x2048 /* Clear current CNT interrupt	  */
#define	MGPM_CLEAR_INTR_DMA	0x204C /* Clear current DMA interrupt	  */

/*
 * driver state per instance
 */
typedef struct mgpm_dev {
	int			opened;
	struct pci_dev		*pdev;
	struct cdev 		cdev;	/* Char device structure      */
	dev_t			dev;	/* Store device major & minor numbers */
	int			irq;
	u32			*device_mem_start;
	u32			*batch_dma_adr;
	u32			*buf_dma_adr[DEVICE_BUF_QUANTITY];
	dma_addr_t		batch_bus_addr;
	dma_addr_t		bus_addr[DEVICE_BUF_QUANTITY];
	int			device_type;
	mgpm_term_dev_adr_t	term_dev_adress;
	mgpm_term_trans_t	term_trans_direction;
	mgpm_subadress_t	subadress;
	size_or_code_t		size_or_code;
	wait_queue_head_t	wait_trans_fin_queue;
	wait_queue_head_t	wait_intr_fin_queue;	
	struct semaphore	sem;

	int			intr_claimed;

	int			trans_completed;/* meen DMA completed */
	int			intr_in_completed; /* meen timer intr in*/

	struct mgpm_op		*times;		/* time's. mmap to user */
	struct mgpm_op		*times_b;	/* for kmem_free 	*/
	u32			stat_size;	/* for kmem_free 	*/

} mgpm_dev_t;

/* create minor nodes */
#define	MGPM_MINOR(i, n)	((i) << 7 | (n))
/* get channel number from minor nodes */
#define	MGPM_INTR(d)		(getminor(d) & 0x3f)
/* get instance from minor node */
#define	MGPM_INST(d)		(getminor(d) >> 7)


#endif  /* !(_UAPI_MGPM_DRV_H) */

