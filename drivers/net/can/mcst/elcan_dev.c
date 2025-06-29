/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * CAN bus driver for MCST ELCAN/CAN2 controller
 *
 */

#include "elcan.h"

/** Interface registers */

/* ELCAN_TIMINGS_REG */
#define PRESCALER_MASK		0x0000FFFF
#define PRESCALER_SHIFT		CAN2_REGS__PRESCALER
#define PROP_SEG_MASK		0x00FF0000
#define PROP_SEG_SHIFT		CAN2_REGS__PROP_SEG
#define PHASE_SEG_MASK		0xFF000000
#define PHASE_SEG_SHIFT		CAN2_REGS__PHASE_SEG

/* ELCAN_FILTER_REG */
#define FILT_MASK		0x0000FFFF
#define FILT_SHIFT		CAN2_REGS__FILT

/* ELCAN_CTLSTA_REG */
#define RESET_MASK		BIT(CAN2_REGS__RESET)
#define RESET_SHIFT		CAN2_REGS__RESET
#define ENABLE_MASK		BIT(CAN2_REGS__ENABLE)
#define ENABLE_SHIFT		CAN2_REGS__ENABLE
#define LOOPBACK_MASK		BIT(CAN2_REGS__LOOPBACK)
#define LOOPBACK_SHIFT		CAN2_REGS__LOOPBACK
#define SNIFF_MASK		BIT(CAN2_REGS__SNIFF)
#define SNIFF_SHIFT		CAN2_REGS__SNIFF
#define STATEIRQ_MASK		BIT(CAN2_REGS__STATEIRQ)
#define STATEIRQ_SHIFT		CAN2_REGS__STATEIRQ
#define STATE_MASK		0x00030000
#define STATE_SHIFT		CAN2_REGS__STATE
#define		STATE_BOFF		0
#define		STATE_EWARN		0x00030000
#define		STATE_EPASS		0x00010000
#define LEC_STUFF_ERR_MASK	BIT(CAN2_REGS__LEC_STUFF_ERR)
#define LEC_FORM_ERR_MASK	BIT(CAN2_REGS__LEC_FORM_ERR)
#define LEC_ACK_ERR_MASK	BIT(CAN2_REGS__LEC_ACK_ERR)
#define LEC_BIT1_ERR_MASK	BIT(CAN2_REGS__LEC_BIT1_ERR)
#define LEC_BIT0_ERR_MASK	BIT(CAN2_REGS__LEC_BIT0_ERR)
#define LEC_CRC_ERR_MASK	BIT(CAN2_REGS__LEC_CRC_ERR)
#define LEC_MASK		(LEC_STUFF_ERR_MASK | \
				 LEC_FORM_ERR_MASK | \
				 LEC_ACK_ERR_MASK | \
				 LEC_BIT1_ERR_MASK | \
				 LEC_BIT0_ERR_MASK | \
				 LEC_CRC_ERR_MASK)

/* ELCAN_ERROR_COUNTERS_REG */
#define TXERRORS_MASK		0x0000FFFF
#define TXERRORS_SHIFT		CAN2_REGS__TXERRORS
#define RXERRORS_MASK		0xFFFF0000
#define RXERRORS_SHIFT		CAN2_REGS__RXERRORS

/* ELCAN_TX_ID_REG */
/* ELCAN_RX_ID_PATTERN_[0..3]_REG */
/* ELCAN_RX_ID_MASK_[0..3]_REG */
/* ELCAN_RX_ID_REG */
#define ID_MASK			0x1FFFFFFF
#define ID_SHIFT		CAN2_REGS__TX_ID_FIELD
#define ID_BASE_MASK		0x1FFC0000
#define ID_BASE_SHIFT		18
#define ID_EXT_MASK		0x0003FFFF
#define ID_EXT_SHIFT		0

/* ELCAN_TX_CTRL_REG */
/* ELCAN_RX_CTRL_PATTERN_[0..3]_REG */
/* ELCAN_RX_CTRL_MASK_[0..3]_REG */
/* ELCAN_RX_CTRL_REG */
#define IDE_MASK		BIT(CAN2_REGS__TX_CTRL_IDE)
#define IDE_SHIFT		CAN2_REGS__TX_CTRL_IDE
#define RTR_MASK		BIT(CAN2_REGS__TX_CTRL_RTR)
#define RTR_SHIFT		CAN2_REGS__TX_CTRL_RTR
#define DLC_MASK		0x0000F000
#define DLC_SHIFT		CAN2_REGS__TX_CTRL_DLC
/* ELCAN_TX_CTRL_REG */
#define TX_RTYINF_MASK		BIT(CAN2_REGS__TX_CTRL_RTYINF)
#define TX_RTYINF_SHIFT		CAN2_REGS__TX_CTRL_RTYINF
#define TX_MBOX_MASK		0xF0000000
#define TX_MBOX_SHIFT		CAN2_REGS__TX_CTRL_MBOX

/* ELCAN_TX_STATUS_REG */
#define TX_PEND_MASK		0x0000FFFF
#define TX_PEND_SHIFT		CAN2_REGS__TX_STAT_PEND
#define TX_BUSY_MASK		0xFFFF0000
#define TX_BUSY_SHIFT		CAN2_REGS__TX_STAT_BUSY

/* ELCAN_TX_IRQ_REG */
#define TX_IRQ_EN_MASK		0x0000FFFF
#define TX_IRQ_EN_SHIFT		CAN2_REGS__TX_IRQ_EN

/* ELCAN_RX_CTRL_PATTERN_[0..3]_REG */
#define RX_MIN_DLC_MASK		0x00000F00
#define RX_MIN_DLC_SHIFT	CAN2_REGS__RX_MIN_DLC

/* ELCAN_RX_CTRL_REG */
#define RX_TIME_MASK		0xFFFF0000
#define RX_TIME_SHIFT		CAN2_REGS__RX_TIME

/* ELCAN_RX_COUNTERS_REG */
#define RX_PEND_MASK		0x0000FFFF
#define RX_PEND_SHIFT		CAN2_REGS__RX_PEND
#define RX_DROPS_MASK		0xFFFF0000
#define RX_DROPS_SHIFT		CAN2_REGS__RX_DROPS

/* ELCAN_RX_ENA_IRQ_REG */
#define RX_ENA_MASK		BIT(CAN2_REGS__RX_ENA)
#define RX_ENA_SHIFT		CAN2_REGS__RX_ENA
#define RX_RX_IRQ_TH_MASK	0xFFFF0000
#define RX_RX_IRQ_TH_SHIFT	CAN2_REGS__RX_IRQ_TH

/* ELCAN_IRQ_PEND_REG */
#define STATE_IRQ_PEND_MASK	BIT(CAN2_REGS__STATE_IRQ_PEND)
#define STATE_IRQ_PEND_SHIFT	CAN2_REGS__STATE_IRQ_PEND
#define TX_IRQ_PEND_MASK	BIT(CAN2_REGS__TX_IRQ_PEND)
#define TX_IRQ_PEND_SHIFT	CAN2_REGS__TX_IRQ_PEND
#define RX_IRQ_PEND_MASK	BIT(CAN2_REGS__RX_IRQ_PEND)
#define RX_IRQ_PEND_SHIFT	CAN2_REGS__RX_IRQ_PEND


/* napi related */
#define ELCAN_NAPI_WEIGHT	ELCAN_MSG_OBJ_RX_NUM


/*
 * elcan error types:
 * Bus errors (BUS_OFF, ERROR_WARNING, ERROR_PASSIVE) are supported
 */
enum elcan_bus_error_types {
	ELCAN_NO_ERROR = 0,
	ELCAN_BUS_OFF,
	ELCAN_ERROR_WARNING,
	ELCAN_ERROR_PASSIVE,
};


static inline void elcan_pm_runtime_enable(const struct elcan_priv *priv)
{
	if (priv->device)
		pm_runtime_enable(priv->device);
}

static inline void elcan_pm_runtime_disable(const struct elcan_priv *priv)
{
	if (priv->device)
		pm_runtime_disable(priv->device);
}

static inline void elcan_pm_runtime_get_sync(const struct elcan_priv *priv)
{
	if (priv->device)
		pm_runtime_get_sync(priv->device);
}

static inline void elcan_pm_runtime_put_sync(const struct elcan_priv *priv)
{
	if (priv->device)
		pm_runtime_put_sync(priv->device);
}

static inline void elcan_reset_ram(const struct elcan_priv *priv, bool enable)
{
	if (priv->caninit)
		priv->caninit(priv, enable);
}

/* enable/disable all irq */
static void elcan_irq_control(struct elcan_priv *priv, bool enable)
{
	u32 ctrl;

	ctrl = priv->read_reg(priv, ELCAN_CTLSTA_REG) & ~(STATEIRQ_MASK);

	if (enable) {
		priv->write_reg(priv, ELCAN_CTLSTA_REG, ctrl | STATEIRQ_MASK);
		priv->write_reg(priv, ELCAN_TX_IRQ_REG, TX_IRQ_EN_MASK);
		priv->write_reg(priv, ELCAN_RX_ENA_IRQ_REG, RX_ENA_MASK);
	} else {
		priv->write_reg(priv, ELCAN_RX_ENA_IRQ_REG,
				RX_ENA_MASK | RX_RX_IRQ_TH_MASK);
		priv->write_reg(priv, ELCAN_TX_IRQ_REG, 0);
		priv->write_reg(priv, ELCAN_CTLSTA_REG, ctrl | LEC_MASK);
	}
}

static int __elcan_get_berr_counter(const struct net_device *dev,
				    struct can_berr_counter *bec)
{
	u32 reg_err_counter;
	struct elcan_priv *priv = netdev_priv(dev);

	reg_err_counter = priv->read_reg(priv, ELCAN_ERROR_COUNTERS_REG);
	bec->rxerr = (reg_err_counter & RXERRORS_MASK) >> RXERRORS_SHIFT;
	bec->txerr = (reg_err_counter & TXERRORS_MASK) >> TXERRORS_SHIFT;

	return 0;
}


/*
 ******************************************************************************
 * Net device ops - Xmit
 ******************************************************************************
 */

/* called from Rx elcan_poll */
static void elcan_do_tx(struct net_device *dev)
{
	struct elcan_priv *priv = netdev_priv(dev);
	struct net_device_stats *stats = &dev->stats;
	u32 idx, pkts = 0, bytes = 0, pend, clr;

	pend = priv->read_reg(priv, ELCAN_TX_STATUS_REG) & 0xFFFF;
	clr = pend;

	if (!pend)
		return;

	/* find first bit set in a word */
	while ((idx = ffs(pend))) {
		idx--;
		pend &= ~(1 << idx);
		can_get_echo_skb(dev, idx);
		bytes += priv->dlc[idx];
		pkts++;
	}

	/* Clear the bits in the tx_active mask */
	priv->write_reg(priv, ELCAN_TX_STATUS_REG, clr);
	atomic_sub(clr, &priv->tx_active);

	if (clr & (1 << (ELCAN_MSG_OBJ_TX_NUM - 1)))
		netif_wake_queue(dev);

	if (pkts) {
		stats->tx_bytes += bytes;
		stats->tx_packets += pkts;
		can_led_event(dev, CAN_LED_EVENT_TX);
	}
} /* elcan_do_tx */

static u32 elcan_setup_tx_object(struct net_device *dev,
				  struct can_frame *frame, int idx)
{
	struct elcan_priv *priv = netdev_priv(dev);
	u32 dlc = frame->can_dlc;
	u32 id, ctrl = 0;

	if (frame->can_id & CAN_EFF_FLAG) {
		id = frame->can_id & CAN_EFF_MASK;
		ctrl |= IDE_MASK;
	} else {
		id = (frame->can_id & CAN_SFF_MASK) << 18;
	}

	if (frame->can_id & CAN_RTR_FLAG)
		ctrl |= RTR_MASK;

	ctrl |= (dlc << DLC_SHIFT) & DLC_MASK;

	/* default: disable oneshot */
	if (!(priv->can.ctrlmode & CAN_CTRLMODE_ONE_SHOT))
		ctrl |= TX_RTYINF_MASK;

	/* MBOX */
	ctrl |= (idx << TX_MBOX_SHIFT) & TX_MBOX_MASK;

	priv->write_reg(priv, ELCAN_TX_ID_REG, id);
	priv->write_reg(priv, ELCAN_TX_DATA0_REG, *(u32 *)frame->data);
	priv->write_reg(priv, ELCAN_TX_DATA1_REG, *(((u32 *)frame->data) + 1));

	return ctrl;
} /* elcan_setup_tx_object */

/* netdev callback */
static netdev_tx_t elcan_start_xmit(struct sk_buff *skb,
				    struct net_device *dev)
{
	struct can_frame *frame = (struct can_frame *)skb->data;
	struct elcan_priv *priv = netdev_priv(dev);
	u32 idx, ctrl;

	if (can_dropped_invalid_skb(dev, skb))
		return NETDEV_TX_OK;

	idx = ffz(atomic_read(&priv->tx_active));

	/* If this is the last buffer, stop the xmit queue */
	if (idx == ELCAN_MSG_OBJ_TX_NUM - 1)
		netif_stop_queue(dev);

	/*
	 * Store the message in the interface so we can call
	 * can_put_echo_skb(). We must do this before we enable
	 * transmit as we might race against do_tx().
	 */
	ctrl = elcan_setup_tx_object(dev, frame, idx);

	priv->dlc[idx] = frame->can_dlc;
	can_put_echo_skb(skb, dev, idx);

	/* Update the active bits */
	atomic_add((1 << idx), &priv->tx_active);
	/* Start transmission */
	priv->write_reg(priv, ELCAN_TX_CTRL_REG, ctrl);

	return NETDEV_TX_OK;
} /* elcan_start_xmit */


/*
 ******************************************************************************
 * Net device - Receive (irq/poll)
 ******************************************************************************
 */

static int elcan_handle_state_change(struct net_device *dev,
				     enum elcan_bus_error_types error_type)
{
	struct elcan_priv *priv = netdev_priv(dev);
	struct net_device_stats *stats = &dev->stats;
	struct can_frame *cf;
	struct sk_buff *skb;
	struct can_berr_counter bec;

	switch (error_type) {
	case ELCAN_NO_ERROR:
		priv->can.state = CAN_STATE_ERROR_ACTIVE;
		break;
	case ELCAN_ERROR_WARNING:
		/* error warning state */
		priv->can.can_stats.error_warning++;
		priv->can.state = CAN_STATE_ERROR_WARNING;
		break;
	case ELCAN_ERROR_PASSIVE:
		/* error passive state */
		priv->can.can_stats.error_passive++;
		priv->can.state = CAN_STATE_ERROR_PASSIVE;
		break;
	case ELCAN_BUS_OFF:
		/* bus-off state */
		priv->can.can_stats.bus_off++;
		priv->can.state = CAN_STATE_BUS_OFF;
		can_bus_off(dev);
		break;
	default:
		break;
	}

	/* propagate the error condition to the CAN stack */
	skb = alloc_can_err_skb(dev, &cf);
	if (unlikely(!skb))
		return 0;

	__elcan_get_berr_counter(dev, &bec);

	switch (error_type) {
	case ELCAN_NO_ERROR:
		/* error warning state */
		cf->can_id |= CAN_ERR_CRTL;
		cf->data[1] = CAN_ERR_CRTL_ACTIVE;
		cf->data[6] = bec.txerr;
		cf->data[7] = bec.rxerr;
		break;
	case ELCAN_ERROR_WARNING:
		/* error warning state */
		cf->can_id |= CAN_ERR_CRTL;
		cf->data[1] = (bec.txerr > bec.rxerr) ?
			CAN_ERR_CRTL_TX_WARNING :
			CAN_ERR_CRTL_RX_WARNING;
		cf->data[6] = bec.txerr;
		cf->data[7] = bec.rxerr;

		break;
	case ELCAN_ERROR_PASSIVE:
		/* error passive state */
		cf->can_id |= CAN_ERR_CRTL;
		if (bec.rxerr > 127)
			cf->data[1] |= CAN_ERR_CRTL_RX_PASSIVE;
		if (bec.txerr > 127)
			cf->data[1] |= CAN_ERR_CRTL_TX_PASSIVE;

		cf->data[6] = bec.txerr;
		cf->data[7] = bec.rxerr;
		break;
	case ELCAN_BUS_OFF:
		/* bus-off state */
		cf->can_id |= CAN_ERR_BUSOFF;
		break;
	default:
		break;
	}

	stats->rx_packets++;
	stats->rx_bytes += cf->can_dlc;
	netif_receive_skb(skb);

	return 1;
} /* elcan_handle_state_change */

static int elcan_handle_bus_err(struct net_device *dev, u32 lec_type)
{
	struct elcan_priv *priv = netdev_priv(dev);
	struct net_device_stats *stats = &dev->stats;
	struct can_frame *cf;
	struct sk_buff *skb;

	/*
	 * early exit if no lec update or no error
	 */
	if (!lec_type)
		return 0;

	if (!(priv->can.ctrlmode & CAN_CTRLMODE_BERR_REPORTING))
		return 0;

	/* common for all type of bus errors */
	priv->can.can_stats.bus_error++;
	stats->rx_errors++;

	/* propagate the error condition to the CAN stack */
	skb = alloc_can_err_skb(dev, &cf);
	if (unlikely(!skb))
		return 0;

	/*
	 * check for 'last error code' which tells us the
	 * type of the last error to occur on the CAN bus
	 */
	cf->can_id |= CAN_ERR_PROT | CAN_ERR_BUSERROR;

	if (lec_type & LEC_STUFF_ERR_MASK) {
		netdev_dbg(dev, "stuff error\n");
		cf->data[2] |= CAN_ERR_PROT_STUFF;
	} else if (lec_type & LEC_FORM_ERR_MASK) {
		netdev_dbg(dev, "form error\n");
		cf->data[2] |= CAN_ERR_PROT_FORM;
	} else if (lec_type & LEC_ACK_ERR_MASK) {
		netdev_dbg(dev, "ack error\n");
		cf->data[3] = CAN_ERR_PROT_LOC_ACK;
	} else if (lec_type & LEC_BIT1_ERR_MASK) {
		netdev_dbg(dev, "bit1 error\n");
		cf->data[2] |= CAN_ERR_PROT_BIT1;
	} else if (lec_type & LEC_BIT0_ERR_MASK) {
		netdev_dbg(dev, "bit0 error\n");
		cf->data[2] |= CAN_ERR_PROT_BIT0;
	} else if (lec_type & LEC_CRC_ERR_MASK) {
		netdev_dbg(dev, "CRC error\n");
		cf->data[3] = CAN_ERR_PROT_LOC_CRC_SEQ;
	}

	stats->rx_packets++;
	stats->rx_bytes += cf->can_dlc;
	netif_receive_skb(skb);
	return 1;
} /* elcan_handle_bus_err */

static int elcan_read_msg_object(struct net_device *dev)
{
	struct net_device_stats *stats = &dev->stats;
	struct elcan_priv *priv = netdev_priv(dev);
	struct can_frame *frame;
	struct sk_buff *skb;
	u32 id, data, ctrl;

	skb = alloc_can_skb(dev, &frame);
	if (!skb) {
		stats->rx_dropped++;
		return -ENOMEM;
	}

	ctrl = priv->read_reg(priv, ELCAN_RX_CTRL_REG);
	frame->can_dlc = get_can_dlc((ctrl & DLC_MASK) >> DLC_SHIFT);

	id = priv->read_reg(priv, ELCAN_RX_ID_REG) & ID_MASK;

	if ((ctrl & IDE_MASK) >> IDE_SHIFT)
		frame->can_id = (id & CAN_EFF_MASK) | CAN_EFF_FLAG;
	else
		frame->can_id = (id >> 18) & CAN_SFF_MASK;

	if ((ctrl & RTR_MASK) >> RTR_SHIFT) {
		frame->can_id |= CAN_RTR_FLAG;
	} else {
		data = priv->read_reg(priv, ELCAN_RX_DATA0_REG);
		memcpy(frame->data + 0, &data, 4);
		data = priv->read_reg(priv, ELCAN_RX_DATA1_REG);
		memcpy(frame->data + 4, &data, 4);
	}

	stats->rx_packets++;
	stats->rx_bytes += frame->can_dlc;

	netif_receive_skb(skb);
	return 0;
} /* elcan_read_msg_object */

static int elcan_handle_lost_msg_obj(struct net_device *dev)
{
	struct net_device_stats *stats = &dev->stats;
	struct can_frame *frame;
	struct sk_buff *skb;

	stats->rx_errors++;
	stats->rx_over_errors++;

	/* create an error msg */
	skb = alloc_can_err_skb(dev, &frame);
	if (unlikely(!skb))
		return 0;

	frame->can_id |= CAN_ERR_CRTL;
	frame->data[1] = CAN_ERR_CRTL_RX_OVERFLOW;

	netif_receive_skb(skb);
	return 1;
} /* elcan_handle_lost_msg_obj */

static int elcan_read_objects(struct net_device *dev, struct elcan_priv *priv,
			      u32 pend_drop, int quota)
{
	u32 pkts = 0;
	u32 pend = (pend_drop & RX_PEND_MASK) >> RX_PEND_SHIFT;
	u32 drop = (pend_drop & RX_DROPS_MASK) >> RX_DROPS_SHIFT;

	/*netdev_dbg(dev, "read_objects: pend = %d, drop = %d, quota = %d\n",
		   pend, drop, quota);*/

	while (pend && (quota > 0)) {
		pend -= 1;

		if (drop) {
			int n = elcan_handle_lost_msg_obj(dev);

			/* clean drops cnt */
			priv->write_reg(priv, ELCAN_RX_COUNTERS_REG,
					RX_DROPS_MASK);
			pkts++;
			quota--;
		}
		if (quota == 0)
			break;

		/* read the data from the message object */
		elcan_read_msg_object(dev);

		/* rx_finalize */
		priv->write_reg(priv, ELCAN_RX_COUNTERS_REG, 1);

		pkts++;
		quota--;
		/*netdev_dbg(dev,
			   "read_objects: pend = %d, pkts = %d, quota = %d\n",
			   pend, pkts, quota);*/
	}

	return pkts;
} /* elcan_read_objects */

static int elcan_do_rx_poll(struct net_device *dev, int quota)
{
	struct elcan_priv *priv = netdev_priv(dev);
	u32 pkts = 0, pend_drop, n;

	pend_drop = priv->read_reg(priv, ELCAN_RX_COUNTERS_REG);
	/* Read the objects */
	n = elcan_read_objects(dev, priv, pend_drop, quota);
	pkts += n;
	quota -= n;

	if (pkts)
		can_led_event(dev, CAN_LED_EVENT_RX);

	return pkts;
} /* elcan_do_rx_poll */

static int elcan_poll(struct napi_struct *napi, int quota)
{
	struct net_device *dev = napi->dev;
	struct elcan_priv *priv = netdev_priv(dev);
	u32 curr, last = priv->last_status;
	int work_done = 0;

	/* Only read the status register if a status interrupt was pending */
	if (atomic_xchg(&priv->sie_pending, 0)) {
		curr = priv->read_reg(priv, ELCAN_CTLSTA_REG);
		priv->last_status = curr;
		/* clean LEC bits (W1C) */
		priv->write_reg(priv, ELCAN_CTLSTA_REG, curr | LEC_MASK);
	} else {
		/* no change detected ... */
		curr = last;
	}

	/* handle state changes */
	if ((curr & STATE_MASK == STATE_EWARN) &&
	    (last & STATE_MASK != STATE_EWARN)) {
		netdev_dbg(dev, "entered error warning state\n");
		work_done += elcan_handle_state_change(dev, ELCAN_ERROR_WARNING);
	}

	if ((curr & STATE_MASK == STATE_EPASS) &&
	    (last & STATE_MASK != STATE_EPASS)) {
		netdev_dbg(dev, "entered error passive state\n");
		work_done += elcan_handle_state_change(dev, ELCAN_ERROR_PASSIVE);
	}

	if ((curr & STATE_MASK == STATE_BOFF) &&
	    (last & STATE_MASK != STATE_BOFF)) {
		netdev_dbg(dev, "entered bus off state\n");
		work_done += elcan_handle_state_change(dev, ELCAN_BUS_OFF);
		goto end;
	}

	/* handle bus recovery events */
	if ((curr & STATE_MASK != STATE_BOFF) &&
	    (last & STATE_MASK == STATE_BOFF)) {
		netdev_dbg(dev, "left bus off state\n");
		work_done += elcan_handle_state_change(dev, ELCAN_ERROR_PASSIVE);
	}

	if ((curr & STATE_MASK != STATE_EPASS) &&
	    (last & STATE_MASK == STATE_EPASS)) {
		netdev_dbg(dev, "left error passive state\n");
		work_done += elcan_handle_state_change(dev, ELCAN_ERROR_WARNING);
	}

	if ((curr & STATE_MASK != STATE_EWARN) &&
	    (last & STATE_MASK == STATE_EWARN)) {
		netdev_dbg(dev, "left error warning state\n");
		work_done += elcan_handle_state_change(dev, ELCAN_NO_ERROR);
	}

	/* handle lec errors on the bus */
	work_done += elcan_handle_bus_err(dev, curr & LEC_MASK);

	/* Handle Tx/Rx events. We do this unconditionally */
	work_done += elcan_do_rx_poll(dev, (quota - work_done));
	elcan_do_tx(dev);

end:
	if (work_done < quota) {
		napi_complete_done(napi, work_done);
		/* enable all IRQs if we are not in bus off state */
		if (priv->can.state != CAN_STATE_BUS_OFF)
			elcan_irq_control(priv, true);
	}

	return work_done;
} /* elcan_poll */

static irqreturn_t elcan_isr(int irq, void *dev_id)
{
	struct net_device *dev = (struct net_device *)dev_id;
	struct elcan_priv *priv = netdev_priv(dev);
	u32 reg_int;

	reg_int = priv->read_reg(priv, ELCAN_IRQ_PEND_REG);
	if (!reg_int)
		return IRQ_NONE;

	/* save for later use in poll */
	if (reg_int & STATE_IRQ_PEND_MASK) {
		atomic_set(&priv->sie_pending, 1);
		/* clear state irq */
		priv->write_reg(priv, ELCAN_IRQ_PEND_REG, STATE_IRQ_PEND_MASK);
	}

	/* disable all interrupts and schedule the NAPI */
	elcan_irq_control(priv, false);
	napi_schedule(&priv->napi);

	return IRQ_HANDLED;
} /* elcan_isr */


/*
 ******************************************************************************
 * Net device ops / Chip init
 ******************************************************************************
 */

/*
 *              ELCAN_PCH_FREQ[Hz]
 * BAUD[b/s] = ------------------------------------------------
 *             (PRESCALER + 2) * (1 + PROP_SEG + 2 * PHASE_SEG)
 */
static int elcan_set_bittiming(struct net_device *dev)
{
	struct elcan_priv *priv = netdev_priv(dev);
	const struct can_bittiming *bt = &priv->can.bittiming;
	u16 brp, sjw, prop, phase, tseg1;
	u32 reg;
	u64 baud;

#if 1
	netdev_dbg(dev,
		   "set_bittiming: bitrate = %u - "
		   "Bit-rate in bits/second\n",
		   bt->bitrate);
	netdev_dbg(dev,
		   "set_bittiming: sample_point = %u - "
		   "Sample point in one-tenth of a percent\n",
		   bt->sample_point);
	netdev_dbg(dev,
		   "set_bittiming: tq = %u - "
		   "Time quanta (TQ) in nanoseconds\n",
		   bt->tq);
	netdev_dbg(dev,
		   "set_bittiming: prop_seg = %u - "
		   "Propagation segment in TQs\n",
		   bt->prop_seg);
	netdev_dbg(dev,
		   "set_bittiming: phase_seg1 = %u - "
		   "Phase buffer segment 1 in TQs\n",
		   bt->phase_seg1);
	netdev_dbg(dev,
		   "set_bittiming: phase_seg2 = %u - "
		   "Phase buffer segment 2 in TQs\n",
		   bt->phase_seg2);
	netdev_dbg(dev,
		   "set_bittiming: sjw = %u - "
		   "Synchronisation jump width in TQs\n",
		   bt->sjw);
	netdev_dbg(dev,
		   "set_bittiming: brp = %u - "
		   "Bit-rate prescaler\n",
		   bt->brp);
#endif

	tseg1 = bt->prop_seg + bt->phase_seg1;
	phase = bt->phase_seg2;

	if (tseg1 > phase)
		prop = tseg1 - phase;
	else
		prop = 1;

	sjw = bt->sjw;
	if (sjw > 1)
		prop += sjw - 1;

	if (bt->brp > 1)
		brp = bt->brp - 2;
	else
		brp = 0;

	reg = ((brp << PRESCALER_SHIFT) & PRESCALER_MASK) |
	      ((prop << PROP_SEG_SHIFT) & PROP_SEG_MASK) |
	      ((phase << PHASE_SEG_SHIFT) & PHASE_SEG_MASK);

	baud = ELCAN_PCH_FREQ / (brp + 2) / (1 + prop + (2 * phase));

	netdev_info(dev,
		    "TIMINGS:=0x%08X (tseg1=%u, tseg2=%u, baud=%u)\n",
		    reg, tseg1, phase, (u32)baud);

	priv->write_reg(priv, ELCAN_TIMINGS_REG, reg);

	return 0;
} /* elcan_set_bittiming */

/*
 * Configure ELCAN chip:
 * - set operating mode
 * - configure message objects
 */
static int elcan_chip_config(struct net_device *dev)
{
	struct elcan_priv *priv = netdev_priv(dev);
	u32 ctrl;

	ctrl = priv->read_reg(priv, ELCAN_CTLSTA_REG) &
		~(LOOPBACK_MASK | SNIFF_MASK);

	if ((priv->can.ctrlmode & CAN_CTRLMODE_LISTENONLY) &&
	    (priv->can.ctrlmode & CAN_CTRLMODE_LOOPBACK)) {
		/* loopback + silent mode : useful for hot self-test */
		ctrl |= LOOPBACK_MASK | SNIFF_MASK;
		netdev_info(dev, "set operating mode: LOOPBACK + LISTENONLY\n");
	} else if (priv->can.ctrlmode & CAN_CTRLMODE_LOOPBACK) {
		/* loopback mode : useful for self-test function */
		ctrl |= LOOPBACK_MASK;
		netdev_info(dev, "set operating mode: LOOPBACK\n");
	} else if (priv->can.ctrlmode & CAN_CTRLMODE_LISTENONLY) {
		/* silent mode : bus-monitoring mode */
		ctrl |= SNIFF_MASK;
		netdev_info(dev, "set operating mode: LISTENONLY\n");
	}
	priv->write_reg(priv, ELCAN_CTLSTA_REG, ctrl | ENABLE_MASK);

	/* TODO:
	 * CAN_CTRLMODE_3_SAMPLES - Triple sampling mode
	 */

	/* configure message objects - drop all Rx frame */
	priv->write_reg(priv, ELCAN_RX_COUNTERS_REG, RX_PEND_MASK);

	/* Rx filters: */
	priv->write_reg(priv, ELCAN_RX_ID_MASK_0_REG, ID_MASK);
	priv->write_reg(priv, ELCAN_RX_CTRL_MASK_0_REG, IDE_MASK | RTR_MASK);
	priv->write_reg(priv, ELCAN_RX_CTRL_PATTERN_0_REG, DLC_MASK);

	/* Clear all internal status */
	atomic_set(&priv->tx_active, 0);

	/* set bittiming params */
	return elcan_set_bittiming(dev);
} /* elcan_chip_config */

static int elcan_start(struct net_device *dev)
{
	struct elcan_priv *priv = netdev_priv(dev);
	int err;

	/* basic elcan configuration */
	err = elcan_chip_config(dev);
	if (err)
		return err;

	priv->can.state = CAN_STATE_ERROR_ACTIVE;

	return 0;
} /* elcan_start */

static void elcan_stop(struct net_device *dev)
{
	struct elcan_priv *priv = netdev_priv(dev);

	elcan_irq_control(priv, false);
	priv->write_reg(priv, ELCAN_RX_ENA_IRQ_REG, 0);
	priv->write_reg(priv, ELCAN_CTLSTA_REG, LEC_MASK);
	priv->can.state = CAN_STATE_STOPPED;
} /* elcan_stop */


/* netdev callback */
static int elcan_open(struct net_device *dev)
{
	int err;
	struct elcan_priv *priv = netdev_priv(dev);

	elcan_pm_runtime_get_sync(priv);
	elcan_reset_ram(priv, true);

	/* open the can device */
	err = open_candev(dev);
	if (err) {
		netdev_err(dev, "failed to open can device\n");
		goto exit_open_fail;
	}

	/* register interrupt handler */
	err = request_irq(dev->irq, &elcan_isr, IRQF_SHARED, dev->name, dev);
	if (err < 0) {
		netdev_err(dev, "failed to request interrupt\n");
		goto exit_irq_fail;
	}

	/* start the elcan controller */
	err = elcan_start(dev);
	if (err)
		goto exit_start_fail;

	can_led_event(dev, CAN_LED_EVENT_OPEN);

	napi_enable(&priv->napi);
	/* enable status change, error and module interrupts */
	elcan_irq_control(priv, true);
	netif_start_queue(dev);

	return 0;

exit_start_fail:
	free_irq(dev->irq, dev);
exit_irq_fail:
	close_candev(dev);
exit_open_fail:
	elcan_reset_ram(priv, false);
	elcan_pm_runtime_put_sync(priv);
	return err;
} /* elcan_open */

/* netdev callback */
static int elcan_close(struct net_device *dev)
{
	struct elcan_priv *priv = netdev_priv(dev);

	netif_stop_queue(dev);
	napi_disable(&priv->napi);
	elcan_stop(dev);
	free_irq(dev->irq, dev);
	close_candev(dev);

	elcan_reset_ram(priv, false);
	elcan_pm_runtime_put_sync(priv);

	can_led_event(dev, CAN_LED_EVENT_STOP);

	return 0;
} /* elcan_close */


/*
 ******************************************************************************
 * Init part
 ******************************************************************************
 */

static const struct net_device_ops elcan_netdev_ops = {
	.ndo_open = elcan_open,
	.ndo_stop = elcan_close,
	.ndo_start_xmit = elcan_start_xmit,
	.ndo_change_mtu = can_change_mtu,
};

/* called form elcan_pci_probe() */
int elcan_register_dev(struct net_device *dev)
{
	struct elcan_priv *priv = netdev_priv(dev);
	int err;

	BUILD_BUG_ON_MSG(CAN2_REGS__TX_ID_FIELD != CAN2_REGS__RX_PTRN_ID,
			 "ID_FIELD different shift");
	BUILD_BUG_ON_MSG(CAN2_REGS__TX_ID_FIELD != CAN2_REGS__RX_MASK_ID,
			 "ID_FIELD different shift");
	BUILD_BUG_ON_MSG(CAN2_REGS__TX_ID_FIELD != CAN2_REGS__RX_ID_FIELD,
			 "ID_FIELD different shift");

	BUILD_BUG_ON_MSG(CAN2_REGS__TX_CTRL_IDE != CAN2_REGS__RX_PTRN_IDE,
			 "IDE different shift");
	BUILD_BUG_ON_MSG(CAN2_REGS__TX_CTRL_IDE != CAN2_REGS__RX_MASK_IDE,
			 "IDE different shift");
	BUILD_BUG_ON_MSG(CAN2_REGS__TX_CTRL_IDE != CAN2_REGS__RX_IDE,
			 "IDE different shift");

	BUILD_BUG_ON_MSG(CAN2_REGS__TX_CTRL_RTR != CAN2_REGS__RX_PTRN_RTR,
			 "RTR different shift");
	BUILD_BUG_ON_MSG(CAN2_REGS__TX_CTRL_RTR != CAN2_REGS__RX_MASK_RTR,
			 "RTR different shift");
	BUILD_BUG_ON_MSG(CAN2_REGS__TX_CTRL_RTR != CAN2_REGS__RX_RTR,
			 "RTR different shift");

	BUILD_BUG_ON_MSG(CAN2_REGS__TX_CTRL_DLC != CAN2_REGS__RX_MAX_DLC,
			 "DLC different shift");
	BUILD_BUG_ON_MSG(CAN2_REGS__TX_CTRL_DLC != CAN2_REGS__RX_DLC,
			 "DLC different shift");

	elcan_pm_runtime_enable(priv);

	dev->flags |= IFF_ECHO;	/* we support local echo */
	dev->netdev_ops = &elcan_netdev_ops;

	err = register_candev(dev);
	if (err)
		elcan_pm_runtime_disable(priv);
	else
		devm_can_led_init(dev);

	return err;
} /* elcan_register_dev */

/* called from elcan_pci_remove */
void elcan_unregister_dev(struct net_device *dev)
{
	struct elcan_priv *priv = netdev_priv(dev);

	unregister_candev(dev);

	elcan_pm_runtime_disable(priv);
} /* elcan_unregister_dev */


static int elcan_get_berr_counter(const struct net_device *dev,
				  struct can_berr_counter *bec)
{
	struct elcan_priv *priv = netdev_priv(dev);
	int err;

	elcan_pm_runtime_get_sync(priv);
	err = __elcan_get_berr_counter(dev, bec);
	elcan_pm_runtime_put_sync(priv);

	return err;
} /* elcan_get_berr_counter */

static int elcan_set_mode(struct net_device *dev, enum can_mode mode)
{
	struct elcan_priv *priv = netdev_priv(dev);
	int err;

	switch (mode) {
	case CAN_MODE_START:
		err = elcan_start(dev);
		if (err)
			return err;
		netif_wake_queue(dev);
		elcan_irq_control(priv, true);
		break;
	default:
		return -EOPNOTSUPP;
	}

	return 0;
} /* elcan_set_mode */

static const struct can_bittiming_const elcan_bittiming_const = {
	.name = KBUILD_MODNAME,
	.tseg1_min = 2,		/* Time segment 1 = prop_seg + phase_seg1 */
	.tseg1_max = 0xFFFF,
	.tseg2_min = 1,		/* Time segment 2 = phase_seg2 */
	.tseg2_max = 0xFF,
	.sjw_max = 1,		/* Synchronisation jump width */
	.brp_min = 2,		/* Bit-rate prescaler */
	.brp_max = 0xFFFF,
	.brp_inc = 1,
};

/* called form elcan_pci_probe() */
struct net_device *elcan_alloc_dev(void)
{
	struct net_device *dev;
	struct elcan_priv *priv;

	dev = alloc_candev(sizeof(struct elcan_priv), ELCAN_MSG_OBJ_TX_NUM);
	if (!dev)
		return NULL;

	priv = netdev_priv(dev);
	netif_napi_add(dev, &priv->napi, elcan_poll, ELCAN_NAPI_WEIGHT);

	priv->dev = dev;
	priv->can.bittiming_const = &elcan_bittiming_const;
	priv->can.do_set_mode = elcan_set_mode;
	priv->can.do_get_berr_counter = elcan_get_berr_counter;
	priv->can.ctrlmode_supported = CAN_CTRLMODE_LOOPBACK |
					CAN_CTRLMODE_LISTENONLY |
					CAN_CTRLMODE_ONE_SHOT |
					CAN_CTRLMODE_BERR_REPORTING;

	return dev;
} /* elcan_alloc_dev */

/* called from elcan_pci_remove */
void elcan_free_dev(struct net_device *dev)
{
	struct elcan_priv *priv = netdev_priv(dev);

	netif_napi_del(&priv->napi);
	free_candev(dev);
} /* elcan_free_dev */
