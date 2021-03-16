#ifndef MXGBE_PHY_H__
#define MXGBE_PHY_H__

#define MXGBE_PHY_DEV_PMD_PMA		0x01
#define MXGBE_PHY_DEV_WIS		0x02
#define MXGBE_PHY_DEV_PCS		0x03
#define MXGBE_PHY_DEV_PHY_XS		0x04
#define MXGBE_PHY_DEV_CHAN_AN		0x07
#define MXGBE_PHY_DEV_DCOFFSET		0x01
#define MXGBE_PHY_DEV_EDC		0x01
#define MXGBE_PHY_DEV_GLOBAL		0x1E
/*#define MXGBE_PHY_DEV_		0x1F*/

/* VSC8488 Temperature */
#define MXGBE_PHY_DEVGLB_TEMPMON	0x7FD6

/* PMA/PMD Status */
#define MXGBE_PHY_DEVPMA_STATUS1	0x0001
#define MXGBE_PHY_DEVPMA_STATUS2	0x0008


void mxgbe_mdio_reset(mxgbe_priv_t *priv);
int mxgbe_mdio_read(mxgbe_priv_t *priv, int phy_id, int dev, int reg_num);
int mxgbe_mdio_write(mxgbe_priv_t *priv, int phy_id, int dev, int reg_num,
		     int val_in);

int mxgbe_mdio_read_temp(mxgbe_priv_t *priv);
u32 mxgbe_mdio_get_pma_stat(mxgbe_priv_t *priv);


#endif /* MXGBE_PHY_H__ */
