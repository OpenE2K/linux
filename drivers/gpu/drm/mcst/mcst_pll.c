/*
 * Copyright (c) 2005-2013 ZAO "MCST". All rights reserved.
 */

/*
 * Authors:
 *   Alexander Shmelev <ashmelev@task.sun.mcst.ru>
 *   Alexander Troosh <troosh@mcst.ru>
 */

#include "drmP.h"
//#include "drm.h"
#include "drm_crtc_helper.h"

#include "mcst_drv.h"


#if 0
#define PLL_INFO DRM_INFO
#else
#define PLL_INFO(...)
#endif

/*******************************************************************************
 * I2C Registers
 *******************************************************************************
 */
#define I2C_REG_PRER_LO (0x00 << 2)   /* Clock Prescale register lo-byte (RW) */
#define I2C_REG_PRER_HI (0x01 << 2)   /* Clock Prescale register hi-byte (RW) */
#define I2C_REG_CTR	(0x02 << 2)   /* Control Register (RW) */
#define I2C_REG_TXR	(0x03 << 2)   /* Transmit Register (W) */
#define I2C_REG_RXR	(0x03 << 2)   /* Receive Register (R)  */
#define I2C_REG_CR	(0x04 << 2)   /* Command Register (W)  */
#define I2C_REG_SR	(0x06 << 2)   /* Status Register (R)   */
#define I2C_REG_RESET	(0x07 << 2)   /* Reset Register        */

/* Prescaler divider evaluates as (PCICLK/(5*SCLK))-1 */
#define NORMAL_SCL 0x3F

/* Control Register bits */
#define I2C_CTR_EN	(1 << 7)      /* I2C core enable bit	       */
#define I2C_CTR_IEN	(1 << 6)      /* I2C core interrupt enable bit */

/* Command Register bits */
#define I2C_CR_STA	(1 << 7)      /* generate (repeated) start condition */
#define I2C_CR_STO	(1 << 6)      /* generate stop condition	     */
#define I2C_CR_RD	(1 << 5)      /* read from slave		     */
#define I2C_CR_WR	(1 << 4)      /* write to slave			     */
#define I2C_CR_NACK	(1 << 3)      /* when a receiver, sent I2C_CR_NACK   */
	       /* Interrupt acknowledge. When set, clears pending interrrupt */
#define I2C_CR_IACK	(1 << 0)

/* Status Register bits */
/* Receive acknowledge from slave. '1' - no acknowledge received */
#define I2C_SR_RxACK	(1 << 7)
/* I2C bus busy. '1' after START, '0' after STOP */
#define I2C_SR_BUSY	(1 << 6)
#define I2C_SR_AL	(1 << 5)      /* Arbitration lost */
/* Transfer in progress. '1' when transferring data */
#define I2C_SR_TIP	(1 << 1)
#define I2C_SR_IF	(1 << 0)      /* Interrupt flag */


/* Transmit Register operations */
#define I2C_READ_OP	0x01	/* Reading from slave (x << 1 | I2C_READ_OP) */
#define I2C_WRITE_OP	0xFE	/* Writing to slave (x << 1 & I2C_WRITE_OP) */

/*******************************************************************************
 * RAMDAC
 *******************************************************************************
 */
#define I2C_RAMDAC_ADDR 0x69

#define FS_REF		0x0	/* Reference clock [000] */
#define FS_PLL1_0	0x2	/* PLL1 0* Phase   */
#define FS_PLL1_180	0x3	/* PLL1 180* Phase */
#define FS_PLL2_0	0x4	/* PLL2 0* Phase   */
#define FS_PLL2_180	0x5	/* PLL2 180* Phase */
#define FS_PLL3_0	0x6	/* PLL3 0* Phase   */
#define FS_PLL3_180	0x7	/* PLL3 180* Phase */

/* The reciprocal of the reference oscillator (14.3181 Mhz) in picoseconds */
#define PIXCLOCK_EXT 69841


/*******************************************************************************
 * TMDS
 *******************************************************************************
 */
#define I2C_TMDS_ADDR	0x38

#define TMDS_0x00_RVAL	0x01	/* VND_IDL */
#define TMDS_0x01_RVAL	0x00	/* VND_IDH */
#define TMDS_0x02_RVAL	0x06	/* DEV_IDL */
#define TMDS_0x03_RVAL	0x00	/* DEV_IDH */
#define TMDS_0x04_RVAL	0x00	/* DEV_REV */
#define TMDS_0x08_WVAL	\
	((1<<5/*VEN*/) |\
	 (1<<4/*HEN*/) |\
	 (0<<3/*DSEL*/)|\
	 (1<<2/*BSEL*/)|\
	 (1<<1/*EDGE*/)|\
	 (0<<0/*nPD*/))
#define TMDS_0x09_WVAL	((0x2<<4/*MSEL[2:0]*/)|(0<<3/*TSEL*/)|(0<<0/*MDI*/))
#define TMDS_0x0A_WVAL	0x90	/* Default */
#define TMDS_0x0C_WVAL	0x89	/* Default */

typedef struct {
	int div;	/* [6:0] Linear output divider */

	int q;	/* [7:0] PPL*_Q */
	int p;	/* [9:0] PPL*_P */
	int po; /* [0:0] PPL_PO */

	int pixclock;
} clk_t;


static inline void
i2c_write(void __iomem *i2c_mmio, unsigned long reg, uint8_t val)
{
#ifdef MGA_TRACE
	uint32_t rdval;
#endif
	PLL_INFO(" i2c_write: I2C[0x%03lx] <= 0x%02x\n", reg, val);
	writel(val, (void *)((unsigned long)i2c_mmio + reg));
#ifdef MGA_TRACE
	rdval = readl((void *)((unsigned long)i2c_mmio + reg));
	PLL_INFO(" i2c_write: I2C[0x%03lx] => 0x%02x\n", reg, rdval);
#endif
}


#include <asm/pgtable.h>
static inline uint8_t
i2c_read(void __iomem *i2c_mmio, unsigned long reg)
{
	uint32_t result = 0;
	result = readl((void *)((unsigned long)i2c_mmio + reg));
#ifdef MGA_TRACE
	PLL_INFO(" i2c_read: I2C[0x%03lx] => 0x%02x\n", reg, result);
#endif
	return result;
}

static void
i2c_send(void __iomem *i2c_mmio, int cmd, int data)
{
#ifndef CONFIG_E2K_SIM
	unsigned char status;
#endif
	if (cmd & I2C_CR_WR) {
		i2c_write(i2c_mmio, I2C_REG_TXR, data);
	}
	i2c_write(i2c_mmio, I2C_REG_CR, cmd);

#ifndef CONFIG_E2K_SIM
	while ((status = i2c_read(i2c_mmio, I2C_REG_SR) & I2C_SR_TIP)) {
		mdelay(1);
		PLL_INFO("waiting 1 msec...\n");
	}
#endif
}

#if 0
static int tmds_write(void __iomem *i2c_mmio, unsigned long tmds_reg,
		uint8_t val)
{
	/* Sending TMDS device address */
	i2c_send(i2c_mmio, I2C_CR_STA | I2C_CR_WR,
			(I2C_TMDS_ADDR << 1) & I2C_WRITE_OP);
	if (i2c_read(i2c_mmio, I2C_REG_SR) & I2C_SR_RxACK) {
		PLL_INFO("TMDS[0x%02lx] <= 0x%02x\t[FAILED]", tmds_reg,
				val);
		return -1;
	}
	/* Sending TMDS register address */
	i2c_send(i2c_mmio, I2C_CR_WR, tmds_reg);
	if (i2c_read(i2c_mmio, I2C_REG_SR) & I2C_SR_RxACK) {
		PLL_INFO("TMDS[0x%02lx] <= 0x%02x\t[FAILED]", tmds_reg,
				val);
		return -1;
	}
	/* Sending TMDS register data */
	i2c_send(i2c_mmio, I2C_CR_STO | I2C_CR_WR, val);
	if (i2c_read(i2c_mmio, I2C_REG_SR) & I2C_SR_RxACK) {
		PLL_INFO("TMDS[0x%02lx] <= 0x%02x\t[FAILED]", tmds_reg,
				val);
		return -1;
	}
	return 0;
}


static uint8_t tmds_read(void __iomem *i2c_mmio, unsigned long tmds_reg)
{
	uint8_t val = 0;

	/* Sending TMDS device address */
	i2c_send(i2c_mmio, I2C_CR_STA | I2C_CR_WR,
			(I2C_TMDS_ADDR << 1) & I2C_WRITE_OP);
	if (i2c_read(i2c_mmio, I2C_REG_SR) & I2C_SR_RxACK) {
		PLL_INFO("TMDS[0x%02lx] => ????\t[FAILED]", tmds_reg);
		return -1;
	}
	/* Sending TMDS register address */
	i2c_send(i2c_mmio, I2C_CR_WR, tmds_reg);
	if (i2c_read(i2c_mmio, I2C_REG_SR) & I2C_SR_RxACK) {
		PLL_INFO("TMDS[0x%02lx] => ????\t[FAILED]", tmds_reg);
		return -1;
	}
	/* Sending TMDS device address */
	i2c_send(i2c_mmio, I2C_CR_STA | I2C_CR_WR,
			(I2C_TMDS_ADDR << 1) | I2C_READ_OP);
	if (i2c_read(i2c_mmio, I2C_REG_SR) & I2C_SR_RxACK) {
		PLL_INFO("TMDS[0x%02lx] => ????\t[FAILED]", tmds_reg);
		return -1;
	}
	/* Sending TMDS register data */
	i2c_send(i2c_mmio, I2C_CR_STO | I2C_CR_RD | I2C_CR_NACK, 0);

	val = i2c_read(i2c_mmio, I2C_REG_RXR);

	return val;
}
#endif

static int
ramdac_write(void __iomem *i2c_mmio, unsigned long ramdac_reg, uint8_t val)
{
	/* Sending RAMDAC device address */
	i2c_send(i2c_mmio, I2C_CR_STA | I2C_CR_WR,
			(I2C_RAMDAC_ADDR << 1) & I2C_WRITE_OP);
	if (i2c_read(i2c_mmio, I2C_REG_SR) & I2C_SR_RxACK) {
		PLL_INFO("RAMDAC[0x%02lx] <= 0x%02x\t[FAILED]",
				ramdac_reg, val);
		return -1;
	}

	/* Sending RAMDAC register address */
	i2c_send(i2c_mmio, I2C_CR_WR, ramdac_reg);
	if (i2c_read(i2c_mmio, I2C_REG_SR) & I2C_SR_RxACK) {
		PLL_INFO("RAMDAC[0x%02lx] <= 0x%02x\t[FAILED]",
				ramdac_reg, val);
		return -1;
	}

	/* Sending RAMDAC register data */
	i2c_send(i2c_mmio, I2C_CR_STO | I2C_CR_WR, val);
	if (i2c_read(i2c_mmio, I2C_REG_SR) & I2C_SR_RxACK) {
		PLL_INFO("RAMDAC[0x%02lx] <= 0x%02x\t[FAILED]",
				ramdac_reg, val);
		return -1;
	}

	return 0;
}

static uint8_t ramdac_read(void __iomem *i2c_mmio, unsigned long ramdac_reg)
{
	uint8_t val = 0;
	/* Sending RAMDAC device address */
	i2c_send(i2c_mmio, I2C_CR_STA | I2C_CR_WR,
			(I2C_RAMDAC_ADDR << 1) & I2C_WRITE_OP);
	if (i2c_read(i2c_mmio, I2C_REG_SR) & I2C_SR_RxACK) {
		PLL_INFO("RAMDAC[0x%02lx] => ????\t[FAILED]", ramdac_reg);
		return -1;
	}

	/* Sending RAMDAC register address */
	i2c_send(i2c_mmio, I2C_CR_WR, ramdac_reg);
	if (i2c_read(i2c_mmio, I2C_REG_SR) & I2C_SR_RxACK) {
		PLL_INFO("RAMDAC[0x%02lx] => ????\t[FAILED]", ramdac_reg);
		return -1;
	}

	/* Sending RAMDAC device address */
	i2c_send(i2c_mmio, I2C_CR_STA | I2C_CR_WR, (I2C_RAMDAC_ADDR << 1)
			| I2C_READ_OP);
	if (i2c_read(i2c_mmio, I2C_REG_SR) & I2C_SR_RxACK) {
		PLL_INFO("RAMDAC[0x%02lx] => ????\t[FAILED]", ramdac_reg);
		return -1;
	}

	/* Sending RAMDAC register data */
	i2c_send(i2c_mmio, I2C_CR_STO | I2C_CR_RD | I2C_CR_NACK, 0);

	val = i2c_read(i2c_mmio, I2C_REG_RXR);

	return val;
}


static void set_prescaler(void __iomem *i2c_mmio, int value)
{
	i2c_write(i2c_mmio, I2C_REG_PRER_LO, value & 0xFF);
	i2c_write(i2c_mmio, I2C_REG_PRER_HI, (value >> 8) & 0xFF);
}


/**
 * Assumes:
 *    DivSel = 0
 */
static void
__set_clk_fs(void __iomem *i2c_mmio, uint8_t a, uint8_t b, uint8_t c)
{
	uint8_t d = FS_REF;

	/* ClkA_FS[2:0] */
	ramdac_write(i2c_mmio, 0x08, (ramdac_read(i2c_mmio, 0x08) & 0x7F)
			| ((a & 0x01) << 7));
	ramdac_write(i2c_mmio, 0x0E, (ramdac_read(i2c_mmio, 0x0E) & 0xFC)
			| ((a & 0x06) >> 1));
	/* ClkB_FS[2:0] */
	ramdac_write(i2c_mmio, 0x0A, (ramdac_read(i2c_mmio, 0x0A) & 0x7F)
			| ((b & 0x01) << 7));
	ramdac_write(i2c_mmio, 0x0E, (ramdac_read(i2c_mmio, 0x0E) & 0xF3)
			| ((b & 0x06) << 1));
	/* ClkC_FS[2:0] */
	ramdac_write(i2c_mmio, 0x0C, (ramdac_read(i2c_mmio, 0x0C) & 0x7F)
			| ((c & 0x01) << 7));
	ramdac_write(i2c_mmio, 0x0E, (ramdac_read(i2c_mmio, 0x0E) & 0xCF)
			| ((c & 0x06) << 3));
	/* ClkD_FS[2:0] */
	ramdac_write(i2c_mmio, 0x0D, (ramdac_read(i2c_mmio, 0x0D) & 0x7F)
			| ((d & 0x01) << 7));
	ramdac_write(i2c_mmio, 0x0E, (ramdac_read(i2c_mmio, 0x0E) & 0x3F)
			| ((d & 0x06) << 5));
}


static void
__set_pll(void __iomem *i2c_mmio, int index, uint8_t Q, uint16_t P, uint8_t PO)
{
	unsigned long base;

	switch (index) {
	case 2:
		base = 0x11;
		break;
	case 3:
		base = 0x14;
		break;
	default:
		DRM_ERROR("Invalid PLL index %d\n", index);
		return;
	}

	/* PLL*_Q[7:0] */
	ramdac_write(i2c_mmio, base + 0, Q);

	/* PLL*_P[7:0] */
	ramdac_write(i2c_mmio, base + 1, P & 0xFF);
	{
		uint8_t val;
		uint8_t LF = 0x0;

		int P_T = (2 * ((P & 0x3FF) + 3)) + (PO & 0x01);

		if (P_T <= 231)
			LF = 0x0;
		else if (P_T <= 626)
			LF = 0x1;
		else if (P_T <= 834)
			LF = 0x2;
		else if (P_T <= 1043)
			LF = 0x3;
		else if (P_T <= 1600)
			LF = 0x4;


		/* PLL*_En, PLL*_LF, PLL*_PO, PLL*_P[9:8] */
		val  = (P & 0x300) >> 8;
		val |= (PO & 0x1) << 2;
		val |= LF << 3;
		/* val |= (enabled & 0x01) << 6; */

		ramdac_write(i2c_mmio, base + 2, val);
	}
}


static void __set_enabled(void __iomem *i2c_mmio, int index, uint8_t enabled)
{
	unsigned long base;
	uint8_t val;

	switch (index) {
	case 2:
		base = 0x11;
		break;
	case 3:
		base = 0x14;
		break;
	default:
		DRM_ERROR("Invalid PLL index %d\n", index);
		return;
	}

	val = ramdac_read(i2c_mmio, base + 2);
	val = val & (~(0x01 << 6));
	val |= (enabled & 0x01) << 6;
	ramdac_write(i2c_mmio, base + 2, val);
}


/**
 * Calculation of parameters PLL (here pixclock given in picoseconds,
 * so the argument 39,721 means the frequency of 10**12 / 39721 = 25175600 Hz
 */
static clk_t mcst_pll_calc(int pixclock)
{
	clk_t res;
	clk_t cur;
	int delta = INT_MAX;
	int tmp_pixclock, tmp_delta;

	res.pixclock = 39721;
	res.div      = 0x2;
	res.q	     = 0x95;
	res.p	     = 0x106;
	res.po	     = 0x1;
#ifdef __e2k__
	/* If run under simulator skip long loops */
	if (IS_MACHINE_SIM) {
		goto calculated;
	}
#endif
	for (cur.p = 0; cur.p < 0x400; cur.p++) {
		for (cur.po = 0; cur.po < 0x2; cur.po++) {
			for (cur.div = 2; cur.div < 0x80; cur.div += 2) {
				for (cur.q = 0; cur.q < 0x100; cur.q++) {

					tmp_pixclock = (PIXCLOCK_EXT * cur.div
							* (cur.q + 2))
						/ (2 * (cur.p + 3) + cur.po);

					tmp_delta = abs(pixclock-tmp_pixclock);
					if (tmp_delta < delta) {
						delta = tmp_delta;
						res = cur;
						res.pixclock = tmp_pixclock;
					}
					if (tmp_delta == 0) {
						goto calculated;
					}
				}
			}
		}
	}
	DRM_ERROR("Can't calculate constants for pixclock=%d\n, use default\n",
			pixclock);
	return res;

calculated:
	PLL_INFO("Calculated: pixclock %d (%d kHz) => %d (%d kHz) PLL setup: "
			"div=0x%02x q=0x%02x p=0x%02x po=0x%x\n",
			pixclock, 1000000000/pixclock,	res.pixclock,
			1000000000/res.pixclock, res.div, res.q, res.p, res.po);

	return res;
}


void mcst_pll_init_pixclock(void __iomem *i2c_mmio)
{
	int reg = 0;
	/*    clk_t memclk; */

	set_prescaler(i2c_mmio, NORMAL_SCL);

	/* Enable I2C core */
	i2c_write(i2c_mmio, I2C_REG_CTR, I2C_CTR_EN);

	/* Init all regs */
	for (reg = 0x08; reg <= 0x17; reg++)
		ramdac_write(i2c_mmio, reg, 0x0);

	for (reg = 0x40; reg <= 0x57; reg++)
		ramdac_write(i2c_mmio, reg, 0x0);

	ramdac_write(i2c_mmio, 0x17, 0x0);
	ramdac_write(i2c_mmio, 0x0F, (0x01 << 6) | (0x01 << 4) | 0x01);
	ramdac_write(i2c_mmio, 0x0D, 0x01);
	ramdac_write(i2c_mmio, 0x10, 0);

	/* Reset SDRAM controller */
	i2c_write(i2c_mmio, I2C_REG_RESET, 0x1);

	/* Disable I2C core */
	i2c_write(i2c_mmio, I2C_REG_CTR, 0x0);

	PLL_INFO("mcst_pll_init_pixclock(): DONE\n");
}

void
mcst_pll_set_pixclock(int output, void __iomem *i2c_mmio, uint32_t pixclock)
{
	clk_t vidclk = mcst_pll_calc(pixclock);

	set_prescaler(i2c_mmio, NORMAL_SCL);

	/* Enable I2C core */
	i2c_write(i2c_mmio, I2C_REG_CTR, I2C_CTR_EN);

	switch (output) {
	case 0:
		ramdac_write(i2c_mmio, 0x08, 0x0);
		__set_clk_fs(i2c_mmio, FS_REF,	 FS_REF, FS_PLL3_0);
		{
			/* Reset vidclk enabled bit */
			__set_enabled(i2c_mmio, 2, 0);
			__set_pll(i2c_mmio, 2, vidclk.q, vidclk.p, vidclk.po);
		}
		__set_clk_fs(i2c_mmio, FS_PLL2_0, FS_REF, FS_PLL3_0);
		ramdac_write(i2c_mmio, 0x08,
				((FS_PLL2_0 & 0x01) << 7)
				 | (vidclk.div & 0x7F));

		/* Set vidclk enabled bit */
		__set_enabled(i2c_mmio, 2, 1);
		break;

	case 1:
		ramdac_write(i2c_mmio, 0x0C, 0x0);
		__set_clk_fs(i2c_mmio, FS_PLL2_0, FS_REF, FS_REF);
		{
			/* Reset vidclk enabled bit */
			__set_enabled(i2c_mmio, 3, 0);
			__set_pll(i2c_mmio, 3, vidclk.q, vidclk.p, vidclk.po);
		}
		__set_clk_fs(i2c_mmio, FS_PLL2_0, FS_REF, FS_PLL3_0);
		ramdac_write(i2c_mmio, 0x0C,
				((FS_PLL3_0 & 0x01) << 7)
				| (vidclk.div & 0x7F));

		/* Set vidclk enabled bit */
		__set_enabled(i2c_mmio, 3, 1);
		break;
	}

	/* Disable I2C core */
	i2c_write(i2c_mmio, I2C_REG_CTR, 0x0);
}
