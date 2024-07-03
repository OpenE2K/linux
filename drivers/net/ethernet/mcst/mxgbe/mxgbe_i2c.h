/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef MXGBE_I2C_H__
#define MXGBE_I2C_H__


/* I2C_0 - SFP+ */
#define I2C_SFP1_ADDR		0x50
#define I2C_SFP2_ADDR		0x51
/* I2C_1 - VSC8488 - 10G Phy */
/* I2C_2 - MAC EEPROM - 24AA025E48-I/OT - A[6:3] == 1010 | A[2:0] == 011*/
#define I2C_EEPROM_ADDR		0x53
#define I2C_EEPROM_MAC_BASE	0xFA


void mxgbe_i2c_reset(mxgbe_priv_t *priv);
struct i2c_adapter *mxgbe_i2c_create(struct device *parent,
				     void __iomem *regs, char *name);
void mxgbe_i2c_destroy(struct i2c_adapter *adapter);


u8 mxgbe_i2c_rd(struct i2c_adapter *adapter, u8 slave_addr, u8 addr);
void mxgbe_i2c_wr(struct i2c_adapter *adapter, u8 slave_addr, u8 addr, u8 val);

u64 mxgbe_i2c_read_mac(mxgbe_priv_t *priv);


#endif /* MXGBE_I2C_H__ */
