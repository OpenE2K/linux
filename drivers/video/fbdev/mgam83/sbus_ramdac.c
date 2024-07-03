/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/* 
 * RAMDAC routines
 */

#include <linux/kernel.h>
#include <linux/delay.h>
#include <asm/io.h>

#include "sbus_mgam83fb.h"
#if defined(CONFIG_SBUS)
#elif defined(CONFIG_PCI2SBUS_MODULE)
#include <linux/mcst/p2ssbus.h>
#endif

/*******************************************************************************
 * I2C Registers
 *******************************************************************************
 */
#define I2C_REG_PRER_LO		(0x00 << 2)	// Clock Prescale register lo-byte (RW)
#define I2C_REG_PRER_HI		(0x01 << 2)	// Clock Prescale register hi-byte (RW)
#define I2C_REG_CTR			(0x02 << 2)	// Control Register (RW)
#define I2C_REG_TXR			(0x03 << 2)	// Transmit Register (W)
#define I2C_REG_RXR			(0x03 << 2)	// Receive Register (R)
#define I2C_REG_CR			(0x04 << 2)	// Command Register (W)
#define I2C_REG_SR			(0x06 << 2)	// Status Register (R)
#define I2C_REG_RESET		(0x07 << 2)	// Reset Register 

// Prescaler divider evaluates as (PCICLK/(5*SCLK))-1
#define NORMAL_SCL 0x3F
#define I2C_PRER_VAL 0xFF

// Control Register bits
#define I2C_CTR_EN	(1 << 7)	// I2C core enable bit
#define I2C_CTR_IEN	(1 << 6)	// I2C core interrupt enable bit

// Command Register bits
#define I2C_CR_STA	(1 << 7)	// generate (repeated) start condition
#define I2C_CR_STO	(1 << 6)	// generate stop condition
#define I2C_CR_RD	(1 << 5)	// read from slave
#define I2C_CR_WR	(1 << 4)	// write to slave
#define I2C_CR_NACK	(1 << 3)	// when a receiver, sent I2C_CR_NACK
#define I2C_CR_IACK	(1 << 0) 	// Interrupt acknowledge. When set, clears pending interrrupt

// Status Register bits
#define I2C_SR_RxACK	(1 << 7)	// Receive acknowledge from slave. '1' - no acknowledge received 
#define I2C_SR_BUSY	(1 << 6)	// I2C bus busy. '1' after START, '0' after STOP
#define I2C_SR_AL	(1 << 5)	// Arbitration lost
#define I2C_SR_TIP	(1 << 1)	// Transfer in progress. '1' when transferring data
#define I2C_SR_IF	(1 << 0)	// Interrupt flag


// Transmit Register operations
#define I2C_READ_OP	0x01		// Reading from slave ( x << 1 | I2C_READ_OP )
#define I2C_WRITE_OP	0xFE		// Writing to slave ( x << 1 & I2C_WRITE_OP )

/*******************************************************************************
 * RAMDAC
 *******************************************************************************
 */
#define I2C_RAMDAC_ADDR 0x69

#define FS_REF		0x0	// Reference clock [000]
#define FS_PPL1_0	0x2	// PPL1 0* Phase
#define FS_PPL1_180	0x3	// PPL1 180* Phase
#define FS_PPL2_0	0x4	// PPL2 0* Phase
#define FS_PPL2_180	0x5	// PPL2 180* Phase
#define FS_PPL3_0	0x6	// PPL3 0* Phase
#define FS_PPL3_180	0x7	// PPL3 180* Phase

// External clock frequency 14.3181 Mhz
#define PIXCLOCK_EXT 69841

#undef MGAM_TRACE_FUNC
#ifdef MGAM_TRACE_FUNC
extern void mgam_trace_func(unsigned int i);
#define trace_func(x) mgam_trace_func(x)
#else
#define trace_func(x)
#endif
static inline void i2c_write(unsigned int bus_type, unsigned long i2c_vbase, unsigned long reg, uint8_t val )
{
#ifdef MGA_TRACE
	uint32_t rdval;
#endif
	TRACE_MSG( " i2c_write: I2C[0x%03lx] <= 0x%02x\n", reg, val );
	if (bus_type == BUS_TYPE_SBUS){
		writel( val, (void*)((unsigned long)i2c_vbase + reg) ); 
#ifdef MGA_TRACE
		rdval = readl((void*)((unsigned long)i2c_vbase + reg));
#endif
	}else{
		TRACE_MSG( " i2c_write: unknown bus type\n");
		return;
	}
	TRACE_MSG( " i2c_write: I2C[0x%03lx] => 0x%02x\n", reg, rdval );
}

static inline uint8_t i2c_read(unsigned int bus_type, unsigned long i2c_vbase, unsigned long reg )
{
	uint32_t result = 0;
	if (bus_type == BUS_TYPE_SBUS){
		result = readl( (void*)((unsigned long)i2c_vbase + reg) ); 
	}else{
		TRACE_MSG( " i2c_read: unknown bus type\n");
		return 0;
	}
	TRACE_MSG( " i2c_read: I2C[0x%03lx] => 0x%02x\n", reg, result );
	return result;
}

static void i2c_send(unsigned int bus_type, unsigned long i2c_vbase, int cmd, int data )
{
#ifndef CONFIG_E2K_SIM
	unsigned char status;
#endif
	
	if (cmd & I2C_CR_WR) 
		i2c_write(bus_type, i2c_vbase, I2C_REG_TXR, data );

	i2c_write(bus_type, i2c_vbase, I2C_REG_CR, cmd );

#ifndef CONFIG_E2K_SIM
	while ( ( status = i2c_read(bus_type, i2c_vbase, I2C_REG_SR ) & I2C_SR_TIP ) ) {
		mdelay(1);
		TRACE_MSG( "waiting 1 msec...\n" );
	}
#endif
}


static int ramdac_write(unsigned int bus_type, unsigned long i2c_vbase, unsigned long ramdac_reg, uint8_t val )
{
	// Sending RAMDAC device address
	i2c_send(bus_type, i2c_vbase, I2C_CR_STA | I2C_CR_WR, (I2C_RAMDAC_ADDR << 1) & I2C_WRITE_OP);
	if ( i2c_read(bus_type, i2c_vbase, I2C_REG_SR ) & I2C_SR_RxACK) {
		DEBUG_MSG( "RAMDAC[0x%02lx] <= 0x%02x\t[FAILED]", ramdac_reg, val );
		return -1;
	}

	// Sending RAMDAC register address
	i2c_send(bus_type, i2c_vbase, I2C_CR_WR, ramdac_reg );
	if ( i2c_read(bus_type, i2c_vbase, I2C_REG_SR ) & I2C_SR_RxACK) {
		DEBUG_MSG( "RAMDAC[0x%02lx] <= 0x%02x\t[FAILED]", ramdac_reg, val );
		return -1;
	}

	// Sending RAMDAC register data
	i2c_send(bus_type, i2c_vbase, I2C_CR_STO | I2C_CR_WR, val);
	if ( i2c_read(bus_type, i2c_vbase, I2C_REG_SR ) & I2C_SR_RxACK) {
		DEBUG_MSG( "RAMDAC[0x%02lx] <= 0x%02x\t[FAILED]", ramdac_reg, val );
		return -1;
	}

	return 0;
}


static uint8_t ramdac_read(unsigned int bus_type, unsigned long i2c_vbase, unsigned long ramdac_reg )
{
	uint8_t val = 0;

	// Sending RAMDAC device address
	i2c_send(bus_type, i2c_vbase, I2C_CR_STA | I2C_CR_WR, (I2C_RAMDAC_ADDR << 1) & I2C_WRITE_OP);
	if ( i2c_read(bus_type, i2c_vbase, I2C_REG_SR ) & I2C_SR_RxACK) {
		DEBUG_MSG( "RAMDAC[0x%02lx] => ????\t[FAILED]", ramdac_reg );
		return -1;
	}

	// Sending RAMDAC register address
	i2c_send(bus_type, i2c_vbase, I2C_CR_WR, ramdac_reg );
	if ( i2c_read(bus_type, i2c_vbase, I2C_REG_SR ) & I2C_SR_RxACK) {
		DEBUG_MSG( "RAMDAC[0x%02lx] => ????\t[FAILED]", ramdac_reg );
		return -1;
	}

	// Sending RAMDAC device address
	i2c_send(bus_type, i2c_vbase, I2C_CR_STA | I2C_CR_WR, (I2C_RAMDAC_ADDR << 1) | I2C_READ_OP);
	if ( i2c_read(bus_type, i2c_vbase, I2C_REG_SR ) & I2C_SR_RxACK) {
		DEBUG_MSG( "RAMDAC[0x%02lx] => ????\t[FAILED]", ramdac_reg );
		return -1;
	}

	// Sending RAMDAC register data
	i2c_send(bus_type, i2c_vbase, I2C_CR_STO | I2C_CR_RD | I2C_CR_NACK, 0);

	val = i2c_read(bus_type, i2c_vbase, I2C_REG_RXR );

	return val;
}


static void set_prescaler(unsigned int bus_type, unsigned long i2c_vbase, int value) 
{
	i2c_write(bus_type, i2c_vbase, I2C_REG_PRER_LO, value & 0xFF );
	i2c_write(bus_type, i2c_vbase, I2C_REG_PRER_HI, (value >> 8) & 0xFF );
}


/*
 * Assumes:
 *    DivSel = 0
 */
static void __set_clk_fs(unsigned int bus_type, unsigned long i2c_vbase, uint8_t a, uint8_t b, uint8_t c )
{
	uint8_t d = FS_REF;

	CHECKPOINT_ENTER;

	// ClkA_FS[2:0]	
	ramdac_write(bus_type, i2c_vbase, 0x08, ( ramdac_read(bus_type, i2c_vbase, 0x08 ) & 0x7F ) | ( ( a & 0x01 ) << 7 ) );
	ramdac_write(bus_type, i2c_vbase, 0x0E, ( ramdac_read(bus_type, i2c_vbase, 0x0E ) & 0xFC ) | ( ( a & 0x06 ) >> 1 ) );
	// ClkB_FS[2:0]
	ramdac_write(bus_type, i2c_vbase, 0x0A, ( ramdac_read(bus_type, i2c_vbase, 0x0A ) & 0x7F ) | ( ( b & 0x01 ) << 7 ) );
	ramdac_write(bus_type, i2c_vbase, 0x0E, ( ramdac_read(bus_type, i2c_vbase, 0x0E ) & 0xF3 ) | ( ( b & 0x06 ) << 1 ) );
	// ClkC_FS[2:0]
	ramdac_write(bus_type, i2c_vbase, 0x0C, ( ramdac_read(bus_type, i2c_vbase, 0x0C ) & 0x7F ) | ( ( c & 0x01 ) << 7 ) );
	ramdac_write(bus_type, i2c_vbase, 0x0E, ( ramdac_read(bus_type, i2c_vbase, 0x0E ) & 0xCF ) | ( ( c & 0x06 ) << 3 ) );
	// ClkD_FS[2:0]
	ramdac_write(bus_type, i2c_vbase, 0x0D, ( ramdac_read(bus_type, i2c_vbase, 0x0D ) & 0x7F ) | ( ( d & 0x01 ) << 7 ) );
	ramdac_write(bus_type, i2c_vbase, 0x0E, ( ramdac_read(bus_type, i2c_vbase, 0x0E ) & 0x3F ) | ( ( d & 0x06 ) << 5 ) );

	CHECKPOINT_LEAVE;
}

/*
static void __set_clk_div( unsigned long i2c_vbase, uint8_t a, uint8_t b, uint8_t c )
{
	CHECKPOINT_ENTER;
	
	// ClkA_Div[6:0]
	ramdac_write( i2c_vbase, 0x08, ( ramdac_read( i2c_vbase, 0x08 ) & 0x80 ) | (a & 0x7F) );
	// ClkB_Div[6:0]
	ramdac_write( i2c_vbase, 0x0A, ( ramdac_read( i2c_vbase, 0x0A ) & 0x80 ) | (b & 0x7F) );
	// ClkC_Div[6:0]
	ramdac_write( i2c_vbase, 0x0C, ( ramdac_read( i2c_vbase, 0x0C ) & 0x80 ) | (c & 0x7F) );
	// ClkD_Div[6:0]
	ramdac_write( i2c_vbase, 0x0D, ( ramdac_read( i2c_vbase, 0x0D ) & 0x80 ) | 0x01 );
	// ClkE_Div[1:0]
	ramdac_write( i2c_vbase, 0x0F, ( ramdac_read( i2c_vbase, 0x0F ) & 0xFC ) | 0x01 );


	CHECKPOINT_LEAVE;
}
*/

static void __set_ppl(unsigned int bus_type, unsigned long i2c_vbase, int index, uint8_t Q, uint16_t P, uint8_t PO )
{
	unsigned long base;

	CHECKPOINT_ENTER;
	switch( index ) {
	case 2 :
		base = 0x11;
		break;
	case 3 :
		base = 0x14;
		break;
	default :
		ERROR_MSG( "Invalid PPL index %d\n", index );	
		CHECKPOINT_LEAVE;
		return;
	}

	// PPL*_Q[7:0]
	ramdac_write( bus_type, i2c_vbase, base + 0, Q );

	// PPL*_P[7:0]
	ramdac_write( bus_type, i2c_vbase, base + 1, P & 0xFF );
	{
		uint8_t val;
		uint8_t LF = 0x0;
		
		int P_T = ( 2 * ( (P & 0x3FF) + 3 ) ) + (PO & 0x01);

		if ( P_T <= 231 ) 
			LF = 0x0;
		else if ( P_T <= 626 ) 
			LF = 0x1;
		else if ( P_T <= 834 ) 
			LF = 0x2;
		else if ( P_T <= 1043 ) 
			LF = 0x3;
		else if ( P_T <= 1600 ) 
			LF = 0x4;

	
		// PPL*_En, PPL*_LF, PPL*_PO, PPL*_P[9:8]
		val  = ( P & 0x300 ) >> 8;
		val |= ( PO & 0x1 ) << 2;
		val |= LF << 3;
		//val |= (enabled & 0x01) << 6;

		ramdac_write( bus_type, i2c_vbase, base + 2, val );
	}
	CHECKPOINT_LEAVE;
}


static void __set_enabled(unsigned int bus_type, unsigned long i2c_vbase, int index, uint8_t enabled )
{
	unsigned long base;
	uint8_t val;

	CHECKPOINT_ENTER;
	switch( index ) {
	case 2 :
		base = 0x11;
		break;
	case 3 :
		base = 0x14;
		break;
	default :
		ERROR_MSG( "Invalid PPL index %d\n", index );	
		CHECKPOINT_LEAVE;
		return;
	}

	val = ramdac_read( bus_type, i2c_vbase, base + 2 );
	val = val & (~(0x01 << 6));
	val |= (enabled & 0x01) << 6;
	ramdac_write( bus_type, i2c_vbase, base + 2, val );

	CHECKPOINT_LEAVE;
}



sbus_clk_t __sbus_calc( int pixclock )
{
	sbus_clk_t res;
	sbus_clk_t cur;
	int delta = INT_MAX;
	int tmp_pixclock, tmp_delta;
	CHECKPOINT_ENTER;
#ifdef __e2k__
	if (IS_MACHINE_SIM) {
		res.pixclock = 39721;
		res.div	= 0x2;
		res.q	= 0x95;
		res.p	= 0x106;
		res.po  = 0x1;
		goto calculated;
	}
#endif
	for( cur.p = 0; cur.p < 0x400; cur.p++ ) {
		for( cur.po = 0; cur.po < 0x2; cur.po++ ) {
			for( cur.div = 2; cur.div < 0x80; cur.div += 2 ) {
				for( cur.q = 0; cur.q < 0x100; cur.q++ ) {
					tmp_pixclock = (PIXCLOCK_EXT * cur.div * (cur.q + 2)) / (2 * (cur.p + 3) + cur.po);		
					tmp_delta = abs( pixclock - tmp_pixclock );
					if ( tmp_delta < delta ) {
						delta = tmp_delta;
						res = cur;
						res.pixclock = tmp_pixclock;
						if ( tmp_delta == 0 ) { 
							goto calculated;
						}
					}
				}
			}
		}
	}

calculated:
	DEBUG_MSG( "Calulated: pixclock %d div %x q %x p %x po %x\n", res.pixclock, res.div, res.q, res.p, res.po );

	CHECKPOINT_LEAVE;
	return res;
}


void __sbus_init_pixclock( int bus_type, unsigned long i2c_vbase ) 
{
	int reg = 0;

	CHECKPOINT_ENTER;

	if ( bus_type != BUS_TYPE_SBUS ) {
		printk( KERN_WARNING "Cannot init pixclock: unsupported MGA/M video card model!\n" );
		CHECKPOINT_LEAVE;
		return;	
	}

	set_prescaler(bus_type, i2c_vbase, I2C_PRER_VAL);
	

	// Enable I2C core
	i2c_write(bus_type, i2c_vbase, I2C_REG_CTR, I2C_CTR_EN );

	for ( reg = 0x08; reg <= 0x17; reg++ )
		ramdac_write(bus_type, i2c_vbase, reg, 0x0 );

	for ( reg = 0x40; reg <= 0x57; reg++ )
		ramdac_write(bus_type, i2c_vbase, reg, 0x0 );

	ramdac_write(bus_type, i2c_vbase, 0x17, 0x0 );
	ramdac_write(bus_type, i2c_vbase, 0x0F, ( 0x01 << 6 ) | ( 0x01 << 4 ) | 0x01 );
	ramdac_write(bus_type, i2c_vbase, 0x0D, 0x01 );
//	ramdac_write(bus_type, i2c_vbase, 0x10, ( 0x01 << 6 ) | ( 0x01 << 4 ) | ( 0x01 << 2 ) | 0x01 );
	ramdac_write(bus_type, i2c_vbase, 0x10, 0 );

	switch( bus_type ) {
#if defined(CONFIG_SBUS) || defined(CONFIG_PCI2SBUS_MODULE)
	case BUS_TYPE_SBUS :
		{
			sbus_clk_t memclk =__sbus_calc( SBUS_MEM_PIXCLOCK );
			DEBUG_MSG("memclk.q = 0x%x ,memclk.p = 0x%x, memclk.po = 0x%x, memclk.div=0x%x\n", 
				memclk.q, memclk.p, memclk.po, memclk.div);
			__set_ppl(bus_type, i2c_vbase, 3, memclk.q, memclk.p, memclk.po );
			__set_clk_fs(bus_type, i2c_vbase, FS_PPL2_0, FS_PPL2_0, FS_PPL3_0 );
			ramdac_write(bus_type, i2c_vbase, 0x0C, ( ramdac_read(bus_type, i2c_vbase, 0x0C ) & 0x80 ) | ( memclk.div & 0x7F) );
			__set_enabled(bus_type, i2c_vbase, 3, 1 );

			break;
		}
#endif
	}	

	// Reset SDRAM controller
	i2c_write(bus_type, i2c_vbase, I2C_REG_RESET, 0x1 );

	// Disable I2C core
	i2c_write(bus_type, i2c_vbase, I2C_REG_CTR, 0x0 );

	CHECKPOINT_LEAVE;
}


// \param model video card model (sbus)
void __sbus_set_pixclock( int bus_type, unsigned long i2c_vbase, uint32_t pixclock )
{
	sbus_clk_t vidclk = __sbus_calc( pixclock );

	CHECKPOINT_ENTER;

	if ( bus_type != BUS_TYPE_SBUS ) {
		printk( KERN_WARNING "Cannot set pixclock: unsupported MGA/M video card model!\n" );
		CHECKPOINT_LEAVE;
		return;	
	}
	trace_func(4);
	set_prescaler(bus_type, i2c_vbase, I2C_PRER_VAL);

	// Enable I2C core
	trace_func(5);
	i2c_write(bus_type, i2c_vbase, I2C_REG_CTR, I2C_CTR_EN );

	trace_func(6);
	ramdac_write(bus_type, i2c_vbase, 0x08, 0x0 );

	switch(bus_type ) {
#if defined(CONFIG_SBUS) || defined(CONFIG_PCI2SBUS_MODULE)
	case BUS_TYPE_SBUS :	
		trace_func(7);
		ramdac_write(bus_type, i2c_vbase, 0x0A, 0x0 ); break;
		trace_func(8);
		__set_clk_fs(bus_type, i2c_vbase, FS_REF, FS_REF, FS_PPL3_0 );
		break;
#endif
	}

	// Reset vidclk enabled bit
	trace_func(9);
	__set_enabled(bus_type, i2c_vbase, 2, 0 );
	trace_func(10);
	__set_ppl(bus_type, i2c_vbase, 2, vidclk.q, vidclk.p, vidclk.po );


	switch( bus_type ) {
#if defined(CONFIG_SBUS) || defined(CONFIG_PCI2SBUS_MODULE)
	case BUS_TYPE_SBUS :
		trace_func(11);
		__set_clk_fs(bus_type, i2c_vbase, FS_PPL2_0, FS_PPL2_0, FS_PPL3_0 );
		trace_func(12);
		ramdac_write(bus_type, i2c_vbase, 0x08, ( ( FS_PPL2_0 & 0x01 ) << 7 ) | (vidclk.div & 0x7F) );
		trace_func(13);
		ramdac_write(bus_type,  i2c_vbase, 0x0A, ( ( FS_PPL2_0 & 0x01 ) << 7 ) | (vidclk.div & 0x7F) );
		break;
#endif
	}

	// Set vidclk enabled bit
	trace_func(14);
	__set_enabled(bus_type, i2c_vbase, 2, 1 );


	// Disable I2C core
	trace_func(15);
	i2c_write(bus_type, i2c_vbase, I2C_REG_CTR, 0x0 );

	trace_func(16);
	CHECKPOINT_LEAVE;
}
