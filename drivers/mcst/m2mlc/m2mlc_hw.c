/**
 * m2mlc_hw.c - M2MLC module device driver
 *
 * Hardware part
 */

#include <linux/io.h>

#include "m2mlc.h"


/**
 ******************************************************************************
 * COMMON
 ******************************************************************************
 **/

/**
 * Read register
 *
 * @base_addr:	registers base address
 * @port:	register offset
 *
 * Returns - readed value
 */
u32 m2mlc_read_reg32(void __iomem *base_addr, u32 port)
{
	return ioread32(base_addr + port);
} /* m2mlc_read_reg32 */

/**
 * Write register
 *
 * @base_addr:	registers base address
 * @port:	register offset
 * @val:	value
 */
void m2mlc_write_reg32(void __iomem *base_addr, u32 port, u32 val)
{
	iowrite32(val, base_addr + port);
} /* m2mlc_write_reg32 */

/**
 * Write register
 *
 * @base_addr:	registers base address
 * @port:	register offset
 * @val:	value
 */
void m2mlc_write_reg64(void __iomem *base_addr, u32 port, u64 val)
{
	/* TODO: iowrite64 */
	iowrite32((u32)(val>>32), base_addr + port + 4);	/* Hi */
	iowrite32((u32)val,       base_addr + port);		/* Lo */
} /* m2mlc_write_reg64 */


/**
 ******************************************************************************
 * Init
 ******************************************************************************
 */

/**
 * Get NIC Capability
 *
 * Returns RTL Version/Revision & Arbiter Config
 */
u16 m2mlc_hw_get_niccapability(struct pci_dev *pdev)
{
	u16 val = 0;

	pci_read_config_word(pdev, NICCPB_REG, &val);
	return val;
} /* m2mlc_hw_get_niccapability */

/**
 * Full Reset on probe and remove
 */
int m2mlc_hw_reset(m2mlc_priv_t *priv, int first)
{
	int i;
	u32 val;


	/* Request for full softreset */
	pci_read_config_dword(priv->pdev, NICCPB_REG, &val);
	if (NICCPB_GET_SOFTRES(val) != 0) {
		DEV_DBG(M2MLC_DBG_MSK_HW, &priv->pdev->dev,
			"SOFTRESET is not null: 0x%X\n", val);
		return 1; /* ERROR */
	}

	if (softreset_enable && !first) {
		val = val | NICCPB_SET_SOFTRES;
	}
	DEV_DBG(M2MLC_DBG_MSK_HW, &priv->pdev->dev,
		"SET NICCPB to: 0x%X\n", val);

	pci_write_config_dword(priv->pdev, NICCPB_REG, val);
	mdelay(10);
	pci_read_config_dword(priv->pdev, NICCPB_REG, &val);
	if (NICCPB_GET_SOFTRES(val) != 0) {
		DEV_DBG(M2MLC_DBG_MSK_HW, &priv->pdev->dev,
			"SOFTRESET is not null after 10ms: 0x%X\n", val);
		mdelay(10);
		pci_read_config_dword(priv->pdev, NICCPB_REG, &val);
		if (NICCPB_GET_SOFTRES(val) != 0) {
			DEV_DBG(M2MLC_DBG_MSK_HW, &priv->pdev->dev,
				"SOFTRESET is not null after 20ms: 0x%X\n",
				val);
			return 2; /* ERROR */
		}
	}
	DEV_DBG(M2MLC_DBG_MSK_HW, &priv->pdev->dev,
		"NICCPB is now: 0x%X (after 10ms)\n", val);

	/* enable access */
	for (i = 0; i < priv->niccpb_procval; i++) {
		m2mlc_write_reg32(priv->reg_base, RB_COM + CB_ADDR_ACC_CTRL(i),
				  CB_ADDR_ACC_CTRL_ADDR_MASK);
	}

	/* enable timeout */
	if ((timeout_retry > 0) || (timeout_counter > 0)) {
		val = (timeout_retry & CB_TO_CONTROL_RETRY_MASK) <<
				CB_TO_CONTROL_RETRY_SHIFT |
		      (timeout_counter & CB_TO_CONTROL_COUNTER_MASK) <<
				CB_TO_CONTROL_COUNTER_SHIFT;
		DEV_DBG(M2MLC_DBG_MSK_HW, &priv->pdev->dev,
			"Setting NIC_TO to %d %d: 0x%08X\n",
			timeout_retry, timeout_counter, val);
		m2mlc_write_reg32(priv->reg_base, RB_COM + CB_TO_CONTROL, val);
	}


	/* init base address registers */
	m2mlc_write_reg64(priv->reg_base, RB_COM + CB_PIO_DONE_QUE_ADDR_L, 0);
	m2mlc_write_reg64(priv->reg_base, RB_COM + CB_PIO_DATA_QUE_ADDR_L, 0);
	for (i = 0; i < priv->niccpb_procval; i++) {
		m2mlc_write_reg64(priv->reg_base,
				  RB_N(i) + M2MLC_RB_MB_STR_ADDR_L, 0);
		m2mlc_write_reg64(priv->reg_base,
				  RB_N(i) + M2MLC_RB_MB_RET_ADDR_L, 0);
		m2mlc_write_reg64(priv->reg_base,
				  RB_N(i) + M2MLC_RB_MB_DONE_QUE_ADDR_L, 0);
		m2mlc_write_reg64(priv->reg_base,
				  RB_N(i) + M2MLC_RB_DB_START_ADDR_L, 0);
		m2mlc_write_reg64(priv->reg_base,
				  RB_N(i) + M2MLC_RB_DB_RET_ADDR_L, 0);
		m2mlc_write_reg64(priv->reg_base,
				  RB_N(i) + M2MLC_RB_DMA_START_ADDR_L, 0);
		m2mlc_write_reg64(priv->reg_base,
				  RB_N(i) + M2MLC_RB_DMA_RET_ADDR_L, 0);
		m2mlc_write_reg64(priv->reg_base,
				  RB_N(i) + M2MLC_RB_DMA_DONE_QUE_ADDR_L, 0);
	}

	/* disable access */
	for (i = 0; i < priv->niccpb_procval; i++) {
		m2mlc_write_reg32(priv->reg_base, RB_COM + CB_ADDR_ACC_CTRL(i),
				  /* 0 */ 1); /* FIXME: chk in new RTL - ok? */
	}

	return 0;
} /* m2mlc_hw_reset */

/**
 * First Init at end of probe
 */
void m2mlc_hw_init(m2mlc_priv_t *priv)
{
	int i;
#if 0
	u32 irq_mask;
#endif

	/* enable access */
	for (i = 0; i < priv->niccpb_procval; i++) {
		m2mlc_write_reg32(priv->reg_base, RB_COM + CB_ADDR_ACC_CTRL(i),
				  CB_ADDR_ACC_CTRL_ADDR_MASK);
	}

	/* init base address registers */
	m2mlc_write_reg64(priv->reg_base,
			  RB_COM + CB_PIO_DONE_QUE_ADDR_L,
#ifdef USE_MUL2ALIGN
			  priv->pio_done_que_handle +
			  priv->pio_done_que_offset);
#else
			  priv->pio_done_que_handle);
#endif /* USE_MUL2ALIGN */
	m2mlc_write_reg64(priv->reg_base,
			  RB_COM + CB_PIO_DATA_QUE_ADDR_L,
#ifdef USE_MUL2ALIGN
			  priv->pio_data_que_handle +
			  priv->pio_data_que_offset);
#else
			  priv->pio_data_que_handle);
#endif /* USE_MUL2ALIGN */
	for (i = 0; i < priv->niccpb_procval; i++) {
		m2mlc_write_reg64(priv->reg_base,
				  RB_N(i) + M2MLC_RB_MB_STR_ADDR_L,
#ifdef USE_MUL2ALIGN
				  priv->mb_struct_handle[i] +
				  priv->mb_struct_offset);
#else
				  priv->mb_struct_handle[i]);
#endif /* USE_MUL2ALIGN */
		m2mlc_write_reg64(priv->reg_base,
				  RB_N(i) + M2MLC_RB_MB_RET_ADDR_L,
				  priv->mdd_ret_handle[i] + 0);
		m2mlc_write_reg64(priv->reg_base,
				  RB_N(i) + M2MLC_RB_MB_DONE_QUE_ADDR_L,
#ifdef USE_MUL2ALIGN
				  priv->mb_done_que_handle[i] +
				  priv->mb_done_offset);
#else
				  priv->mb_done_que_handle[i]);
#endif /* USE_MUL2ALIGN */
		m2mlc_write_reg64(priv->reg_base,
				  RB_N(i) + M2MLC_RB_DB_START_ADDR_L,
				  priv->db_start_handle[i]);
		m2mlc_write_reg64(priv->reg_base,
				  RB_N(i) + M2MLC_RB_DB_RET_ADDR_L,
				  priv->mdd_ret_handle[i] + sizeof(u32));
		m2mlc_write_reg64(priv->reg_base,
				  RB_N(i) + M2MLC_RB_DMA_START_ADDR_L,
#ifdef USE_MUL2ALIGN
				  priv->dma_start_handle[i] +
				  priv->dma_start_offset);
#else
				  priv->dma_start_handle[i]);
#endif /* USE_MUL2ALIGN */
		m2mlc_write_reg64(priv->reg_base,
				  RB_N(i) + M2MLC_RB_DMA_RET_ADDR_L,
				  priv->mdd_ret_handle[i] + (sizeof(u32)*2));
		m2mlc_write_reg64(priv->reg_base,
				  RB_N(i) + M2MLC_RB_DMA_DONE_QUE_ADDR_L,
#ifdef USE_MUL2ALIGN
				  priv->dma_done_que_handle[i] +
				  priv->dma_done_offset);
#else
				  priv->dma_done_que_handle[i]);
#endif /* USE_MUL2ALIGN */
	}

	/* disable access */
	for (i = 0; i < priv->niccpb_procval; i++) {
		m2mlc_write_reg32(priv->reg_base, RB_COM + CB_ADDR_ACC_CTRL(i),
				  0);
	}

	/* Enable Maintenance on PIO 0 */
	m2mlc_write_reg32(priv->reg_base, RB_COM + CB_ADDR_ACC_CTRL(0),
			  CB_ADDR_ACC_CTRL_MAINT_EN | 1);

#if 0
	/* DEBUG: */
	for (i = 0; i < priv->niccpb_procval; i++) {
		irq_mask = M2MLC_RB_INT_ENABLE_MSK;
		m2mlc_write_reg32(priv->reg_base,
				  RB_N(i) + M2MLC_RB_INT_ENABLE, irq_mask);
	}
#endif

} /* m2mlc_hw_init */

/**
 * Set ENDIANES
 */
void m2mlc_hw_set_endianes(m2mlc_priv_t *priv)
{
	/* FUTURE: for sparc */
} /* m2mlc_hw_set_endianes */


/**
 ******************************************************************************
 * PIO
 ******************************************************************************
 */

/*
 * Start PIO Transaction
 *
 */
void m2mlc_hw_pio_start(m2mlc_priv_t *priv, int ep, m2mlc_pio_cmd_t *pio_cmd)
{
	m2mlc_write_reg64(priv->reg_base, RB_N(ep) + M2MLC_RB_PIO_TRGT_PTR_L,
			  pio_cmd->Target_ptr);
	m2mlc_write_reg32(priv->reg_base, RB_N(ep) + M2MLC_RB_PIO_TRANS_PRM,
			  pio_cmd->Parameter.r);
	m2mlc_write_reg32(priv->reg_base, RB_N(ep) + M2MLC_RB_PIO_DRBL,
			  pio_cmd->Remote_Doorbell);
	m2mlc_write_reg32(priv->reg_base, RB_N(ep) + M2MLC_RB_PIO_TRANS_FS,
			  pio_cmd->Format.r);
} /* m2mlc_hw_pio_start */

/*
 * Get PIO Transaction status
 *
 */
void m2mlc_hw_pio_getstat(m2mlc_priv_t *priv, int ep, uint8_t *piostat/*,
			  int complete*/)
{
	u32 val = m2mlc_read_reg32(priv->reg_base,
				   RB_N(ep) + M2MLC_RB_PIO_TRANS_FS);
	*piostat = (u8)val;

	/* FIXME: ??? */
	/*if (complete) {
		m2mlc_write_reg32(priv->reg_base,
				  RB_N(ep) + M2MLC_RB_PIO_TRANS_FS,
				  M2MLC_PIO_STAT_COMPLETE);
	}*/
} /* m2mlc_hw_pio_getstat */


/**
 ******************************************************************************
 * Mailbox
 ******************************************************************************
 */

/*
 * Get Mailbox Structure Head & Tail Pointers
 *
 */
void m2mlc_hw_mb_getptrs_mail(m2mlc_priv_t *priv, int ep,
			      m2mlc_mb_ptrs_t *mbptrs)
{
	mbptrs->r = m2mlc_read_reg32(priv->reg_base,
				     RB_N(ep) + M2MLC_RB_MB_STR_PTRS);
} /* m2mlc_hw_mb_getptrs_mail */

/*
 * Set Mailbox Structure Tail Pointer
 *
 */
void m2mlc_hw_mb_settailptr_mail(m2mlc_priv_t *priv, int ep,
				 uint16_t tail_ptr)
{
	m2mlc_mb_ptrs_t mbptrs;

	mbptrs.p.TailPtr = tail_ptr;
	m2mlc_write_reg32(priv->reg_base,
			  RB_N(ep) + M2MLC_RB_MB_STR_PTRS, mbptrs.r);
} /* m2mlc_hw_mb_settailptr_mail */


/*
 * Get Mailbox Done Head & Tail Pointers
 *
 */
void m2mlc_hw_mb_getptrs_done(m2mlc_priv_t *priv, int ep,
			      m2mlc_mb_ptrs_t *mbptrs)
{
	mbptrs->r = m2mlc_read_reg32(priv->reg_base,
				     RB_N(ep) + M2MLC_RB_MB_DONE_PTRS);
} /* m2mlc_hw_mb_getptrs_done */

/*
 * Set Mailbox Done Tail Pointer
 *
 */
void m2mlc_hw_mb_settailptr_done(m2mlc_priv_t *priv, int ep,
				 uint16_t tail_ptr)
{
	m2mlc_mb_ptrs_t mbptrs;

	mbptrs.p.TailPtr = tail_ptr; /* + bit 31: Shadow Copy Enable */
	m2mlc_write_reg32(priv->reg_base,
			  RB_N(ep) + M2MLC_RB_MB_DONE_PTRS, mbptrs.r);
} /* m2mlc_hw_mb_settailptr_done */


/**
 ******************************************************************************
 * DoorBell
 ******************************************************************************
 */

/*
 * Get DoorBell Head & Tail Pointer
 *
 */
void m2mlc_hw_db_getptrs(m2mlc_priv_t *priv, int ep, m2mlc_db_ptrs_t *dbptrs)
{
	dbptrs->r = m2mlc_read_reg32(priv->reg_base,
				     RB_N(ep) + M2MLC_RB_DB_PTRS);
} /* m2mlc_hw_db_getptrs */

/*
 * Set DoorBell Head Pointer
 *
 */
void m2mlc_hw_db_settailptr(m2mlc_priv_t *priv, int ep, uint16_t tail_ptr)
{
	m2mlc_db_ptrs_t dbptrs;

	dbptrs.p.HeadPtr = tail_ptr; /* + bit 31: Shadow Copy Enable */
	m2mlc_write_reg32(priv->reg_base,
			  RB_N(ep) + M2MLC_RB_DB_PTRS, dbptrs.r);
} /* m2mlc_hw_db_settailptr */


/**
 ******************************************************************************
 * Interrupt
 ******************************************************************************
 */

/*
 * Interrupt Enable/Disable
 *
 */
void m2mlc_hw_int_setmask(m2mlc_priv_t *priv, int ep,
			  m2mlc_interrupt_t intmask)
{
	/* TODO: lock */
	m2mlc_write_reg32(priv->reg_base,
			  RB_N(ep) + M2MLC_RB_INT_ENABLE, intmask.r);
} /* m2mlc_hw_int_setmask */

#if 0
/*
 * Confirm Interrupt
 *
 */
void m2mlc_hw_int_clear(m2mlc_priv_t *priv, int ep,
			m2mlc_interrupt_t intclr)
{
	m2mlc_write_reg32(priv->reg_base,
			  RB_N(ep) + M2MLC_RB_INT_STATUS, intclr.r);
} /* m2mlc_hw_int_clear */
#endif /* 0 */

/*
 * Get Interrupt Status
 *
 */
void m2mlc_hw_int_getstat(m2mlc_priv_t *priv, int ep,
			  m2mlc_int_stat_t *intstat)
{
	intstat->fromreg.r = m2mlc_read_reg32(priv->reg_base,
					      RB_N(ep) + M2MLC_RB_INT_STATUS);
	intstat->intmask.r = m2mlc_read_reg32(priv->reg_base,
					      RB_N(ep) + M2MLC_RB_INT_ENABLE);
	/* TODO: lock & clean fromreg & ~intmask */
} /* m2mlc_hw_int_getstat */


/**
 ******************************************************************************
 * DMA
 ******************************************************************************
 */

/*
 * Get DMA Structure Head & Tail Pointers
 *
 */
void m2mlc_hw_dma_getptrs_str(m2mlc_priv_t *priv, int ep,
			      m2mlc_dma_str_ptrs_t *dmaptrs)
{
	dmaptrs->r = m2mlc_read_reg32(priv->reg_base,
				      RB_N(ep) + M2MLC_RB_DMA_STR_PTRS);
} /* m2mlc_hw_dma_getptrs_str */

/*
 * Set DMA Structure Head Pointer
 *
 */
void m2mlc_hw_dma_setheadptr_str(m2mlc_priv_t *priv, int ep,
				 uint16_t head_ptr)
{
	m2mlc_dma_str_ptrs_t dmaptrs;

	dmaptrs.p.HeadPtr = head_ptr;
	m2mlc_write_reg32(priv->reg_base, RB_N(ep) + M2MLC_RB_DMA_STR_PTRS,
			  dmaptrs.r);
} /* m2mlc_hw_dma_setheadptr_str */


/*
 * Get DMA Done Head & Tail Pointers
 *
 */
void m2mlc_hw_dma_getptrs_done(m2mlc_priv_t *priv, int ep,
			       m2mlc_dma_done_ptrs_t *dmaptrs)
{
	dmaptrs->r = m2mlc_read_reg32(priv->reg_base,
				      RB_N(ep) + M2MLC_RB_DMA_DONE_PTRS);
} /* m2mlc_hw_dma_getptrs_done */

/*
 * Set DMA Done Tail Pointer
 *
 */
void m2mlc_hw_dma_settailptr_done(m2mlc_priv_t *priv, int ep,
				  uint16_t tail_ptr)
{
	m2mlc_dma_done_ptrs_t dmaptrs;

	dmaptrs.p.TailPtr = tail_ptr;
	m2mlc_write_reg32(priv->reg_base, RB_N(ep) + M2MLC_RB_DMA_DONE_PTRS,
			  dmaptrs.r);
} /* m2mlc_hw_dma_settailptr_done */


/**
 ******************************************************************************
 * IRQ handler
 ******************************************************************************
 */

/**
 * Interrupt handler
 *
 * @irq:	not used / TODO: save base IRQ num in priv
 * @dev_id:	PCI device information struct
 */
irqreturn_t m2mlc_irq_handler(int irq, void *dev_id)
{
	struct pci_dev *pdev;
	m2mlc_priv_t *priv;
	u32 irq_stat;
	void __iomem *base_addr;
	int i;


	if (!dev_id)
		return IRQ_NONE;
	pdev = (struct pci_dev *)dev_id;

	priv = pci_get_drvdata(dev_id);
	if (!priv)
		return IRQ_NONE;

	base_addr = priv->reg_base;
	if (!base_addr)
		return IRQ_NONE;

	DEV_DBG(M2MLC_DBG_MSK_IRQ, &pdev->dev, "IRQ #%d\n", irq);

	/* Read IRQ status */
	/*irq_stat = COMMON_STATUS_GET_INTSRC(
		ioread32(P_COMMON_STATUS_REG(base_addr)));
	if (!irq_stat) return IRQ_NONE; */

	/*
	i = irq - pdev->irq;
	if ((i < 0) || (i >= priv->niccpb_procval)) {
		DEV_DBG(M2MLC_DBG_MSK_IRQ, &pdev->dev, "IRQ_NONE #%d\n", irq);
		return IRQ_NONE;
	}
	*/

	for (i = 0; i < priv->niccpb_procval; i++) {
		irq_stat = m2mlc_read_reg32(priv->reg_base,
					    RB_N(i) + M2MLC_RB_INT_STATUS);
		m2mlc_write_reg32(priv->reg_base,
				  RB_N(i) + M2MLC_RB_INT_STATUS, irq_stat);
		if (irq_stat)
			DEV_DBG(M2MLC_DBG_MSK_IRQ, &pdev->dev,
				"IRQ: stat = 0x%X\n", irq_stat);
	}

	/* TODO: lock & save fromirq */

	return IRQ_HANDLED;
} /* m2mlc_irq_handler */


/**
 ******************************************************************************
 * Debug
 ******************************************************************************
 */

#define PREG_N(R, C, N) LOG_MSG("\t0x%02X: 0x%08X - %s\n", R, \
				m2mlc_read_reg32(priv->reg_base, RB_N(N) + R), \
				C)
#define PREG_C(R, C)    LOG_MSG("\t0x%02X: 0x%08X - %s\n", R, \
				m2mlc_read_reg32(priv->reg_base, RB_COM + R), \
				C)

#define PREG_E(R, C)    LOG_MSG("\t0x%03X: 0x%08X - %s\n", R, \
				m2mlc_read_reg32(priv->ecs_base, R), \
				C)

/**
 * Regs Dump
 */
void m2mlc_hw_print_all_regs(m2mlc_priv_t *priv, uint32_t regmsk)
{
	int i;
	u_int32_t reg_id[] = {
		ECS_DEVID_CAR,
		ECS_DEVINF_CAR,
		ECS_ASMBLID_CAR,
		ECS_ASMBLINF_CAR,
		ECS_PEF_CAR,
		ECS_PELLCTRL_CSR,
		ECS_GPSTAT_CSR,
		ECS_BASEDEVID_CSR,
		ECS_HBASEDEVIDLOCK_CSR,
		ECS_ROUTE_RESP,
		ECS_PHYSTAT_CTRL
	};
	char *reg_name[] = {
		"Device_Identity_CAR           ",
		"Device_Information_CAR        ",
		"Assembly_Identity_CAR         ",
		"Assembly_Information_CAR      ",
		"Processing_Elem_Features_CAR  ",
		"Processing_Elem_LogLayCtrl_CSR",
		"General_Port_Status_CSR       ",
		"Base_Device_ID_CSR            ",
		"Host_Base_Device_ID_Lock_CSR  ",
		"Responce Route Field          ",
		"PHY_Port_Pn_Status_Control    ",
		"                              "
	};
	u_int32_t reg_id_rtacc[] = {
		ECS_RTACCSTAT_0,
		ECS_RTACCSTAT_1,
		ECS_RTACCSTAT_2,
		ECS_RTACCSTAT_3,
		ECS_RTACCSTAT_4,
		ECS_RTACCSTAT_5,
		ECS_RTACCSTAT_6,
		ECS_RTACCSTAT_7
	};
	char *reg_name_rtacc[] = {
		"Status_0 [1F..00]",
		"Status_1 [3F..20]",
		"Status_2 [5F..40]",
		"Status_3 [7F..60]",
		"Status_4 [9F..80]",
		"Status_5 [BF..A0]",
		"Status_6 [DF..C0]",
		"Status_7 [FF..E0]",
		"                 "
	};


	LOG_MSG("\n");
	LOG_MSG("  -= register dump (hex) =-\n");

	if (!(M2MLC_PRINTREG_BAR0 & regmsk))
		goto skip_1;
	LOG_MSG("BAR0: Element_Config_Space\n");
	for (i = 0; i < ARRAY_SIZE(reg_id); i++) {
		PREG_E(reg_id[i], reg_name[i]);
	}

skip_1:
	if (!(M2MLC_PRINTREG_RTACCESS & regmsk))
		goto skip_2;
	LOG_MSG("  RT Access Status:\n");
	for (i = 0; i < ARRAY_SIZE(reg_id_rtacc); i++) {
		PREG_E(reg_id_rtacc[i], reg_name_rtacc[i]);
	}

skip_2:
	if (!(M2MLC_PRINTREG_BAR1 & regmsk))
		goto skip_3;
	LOG_MSG("BAR1: Control Regs: PIO,Mailbox," \
				   "DoorBell,DMA,Interrupt,Status\n");
	for (i = 0; i < priv->niccpb_procval; i++) {
		if (!((1UL << i) & regmsk))
			continue;
		LOG_MSG("  Resource Block %d\n", i);
		/* = PIO box = */
		PREG_N(M2MLC_RB_PIO_TRGT_PTR_L, "PIO Target Pointer lower", i);
		PREG_N(M2MLC_RB_PIO_TRGT_PTR_H, "PIO Target Pointer upper", i);
		PREG_N(M2MLC_RB_PIO_TRANS_PRM,
		       "PIO Transaction parameters", i);
		PREG_N(M2MLC_RB_PIO_TRANS_FS,
		       "PIO Transaction Format & Status", i);
		PREG_N(M2MLC_RB_PIO_DRBL, "PIO Doorbell", i);
		/* = Mailbox Register Block = */
		PREG_N(M2MLC_RB_MB_STR_ADDR_L,
		       "Mailbox Structure Address Lower", i);
		PREG_N(M2MLC_RB_MB_STR_ADDR_H,
		       "Mailbox Structure Address Upper", i);
		PREG_N(M2MLC_RB_MB_STR_PTRS,
		       "Mailbox Struct Head & Tail Pointer", i);
		PREG_N(M2MLC_RB_MB_DONE_PTRS,
		       "Mailbox Done Head & Tail Pointer", i);
		PREG_N(M2MLC_RB_MB_RET_ADDR_L,
		       "Mailbox Return Address Lower", i);
		PREG_N(M2MLC_RB_MB_RET_ADDR_H,
		       "Mailbox Return Address Upper", i);
		PREG_N(M2MLC_RB_MB_DONE_QUE_ADDR_L,
		       "Mailbox Done Queue Address Lower", i);
		PREG_N(M2MLC_RB_MB_DONE_QUE_ADDR_H,
		       "Mailbox Done Queue Address Upper", i);
		/* = Doorbell's Register Block = */
		PREG_N(M2MLC_RB_DB_START_ADDR_L,
		       "Doorbell Start Address Lower", i);
		PREG_N(M2MLC_RB_DB_START_ADDR_H,
		       "Doorbell Start Address Upper", i);
		PREG_N(M2MLC_RB_DB_RET_ADDR_L,
		       "Doorbell Return Address Lower", i);
		PREG_N(M2MLC_RB_DB_RET_ADDR_H,
		       "Doorbell Return Address Upper", i);
		PREG_N(M2MLC_RB_DB_PTRS, "Doorbell Head & Tail Pointer", i);
		/* = DMA Mode Block = */
		PREG_N(M2MLC_RB_DMA_START_ADDR_L,
		       "DMA Start Address Lower", i);
		PREG_N(M2MLC_RB_DMA_START_ADDR_H,
		       "DMA Start Address Upper", i);
		PREG_N(M2MLC_RB_DMA_STR_PTRS,
		       "DMA Structure Head & Tail Pointer", i);
		PREG_N(M2MLC_RB_DMA_QUE_SIZE, "DMA Queue Size Register", i);
		PREG_N(M2MLC_RB_DMA_RET_ADDR_L, "DMA Return Address Lower", i);
		PREG_N(M2MLC_RB_DMA_RET_ADDR_H, "DMA Return Address Upper", i);
		PREG_N(M2MLC_RB_DMA_DONE_QUE_ADDR_L,
		       "DMA Done Queue Address Lower", i);
		PREG_N(M2MLC_RB_DMA_DONE_QUE_ADDR_H,
		       "DMA Done Queue Address Upper", i);
		PREG_N(M2MLC_RB_DMA_DONE_PTRS,
		       "DMA Done Head & Tail Pointer", i);
		/* = Interrupts = */
		PREG_N(M2MLC_RB_INT_STATUS, "Interrupt Status", i);
		PREG_N(M2MLC_RB_INT_ENABLE, "Interrupt Enable", i);
		/* = Error Reporting = */
		PREG_N(M2MLC_RB_ERR_STATUS, "Error Status", i);
	}

skip_3:
	if (!(M2MLC_PRINTREG_COMMON & regmsk))
		return;
	LOG_MSG("  Common Block\n");
#if 0
	LOG_MSG("    IOMMU Control Block\n");
	PREG_C(CB_IOMMU_CONTROL, "IOMMU Control Register");
#endif /* 0 */

	LOG_MSG("    Addresses Access Control Structure\n");
	for (i = 0; i < priv->niccpb_procval; i++) {
		PREG_C(CB_ADDR_ACC_CTRL(i), "Addresses Access Register N");
	}
	LOG_MSG("    PIO Common Block\n");
	PREG_C(CB_PIO_DONE_QUE_ADDR_L, "PIO Done Queue Table Address Lower");
	PREG_C(CB_PIO_DONE_QUE_ADDR_H, "PIO Done Queue Table Address Upper");
	PREG_C(CB_PIO_DATA_QUE_ADDR_L, "PIO Data Queue Table Address Lower");
	PREG_C(CB_PIO_DATA_QUE_ADDR_H, "PIO Data Queue Table Address Upper");
	PREG_C(CB_PIO_BOXES_AVAIL, "PIO boxes availability");
	LOG_MSG("    Timeout Control\n");
	PREG_C(CB_TO_CONTROL, "Timeout Control Register");
	LOG_MSG("    Common Interrupt Status & Mask\n");
	PREG_C(CB_COM_INT_STATUS, "Common Interrupt Status");
	PREG_C(CB_COM_INT_MASK, "Common Interrupt Mask");

} /* hw_print_all_regs */
