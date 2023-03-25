/*
 * include/asm-l/serial.h
 */
#ifndef _L_SERIAL_H
#define _L_SERIAL_H

/*
 * This assumes you have a 1.8432 MHz clock for your UART.
 *
 * It'd be nice if someone built a serial card with a 24.576 MHz
 * clock, since the 16550A is capable of handling a top speed of 1.5
 * megabits/second; but this requires the faster clock.
 */

#define BASE_BAUD ( 1843200 / 16 )

/* Standard COM flags (except for COM4, because of the 8514 problem) */
#ifdef CONFIG_SERIAL_DETECT_IRQ
#define STD_COM_FLAGS (UPF_BOOT_AUTOCONF | UPF_SKIP_TEST | UPF_AUTO_IRQ)
#define STD_COM4_FLAGS (UPF_BOOT_AUTOCONF | UPF_AUTO_IRQ)
#else
#define STD_COM_FLAGS (UPF_BOOT_AUTOCONF | UPF_SKIP_TEST)
#define STD_COM4_FLAGS UPF_BOOT_AUTOCONF
#endif

#define	AM85C30_RES_Tx_P	0x28
#define AM85C30_EXT_INT_ENAB	0x01
#define AM85C30_TxINT_ENAB	0x02
#define AM85C30_RxINT_MASK	0x18

/* AM85C30 WRITE Registers */

#define		AM85C30_WR0 		0x00
#define 	AM85C30_WR1		0x01
#define 	AM85C30_WR2		0x02
#define 	AM85C30_WR3		0x03
#define 	AM85C30_WR4		0x04
#define 	AM85C30_WR5		0x05
#define 	AM85C30_WR6		0x06
#define 	AM85C30_WR7		0x07
#define 	AM85C30_WR8		0x08
#define 	AM85C30_WR9		0x09
#define 	AM85C30_WR10		0x0a
#define 	AM85C30_WR11		0x0b
#define 	AM85C30_WR12		0x0c
#define 	AM85C30_WR13		0x0d
#define 	AM85C30_WR14		0x0e
#define 	AM85C30_WR15		0x0f

/* READ (Status) Registers */

#define		AM85C30_RR0		0x00
#define 	AM85C30_RR1		0x01
#define		AM85C30_RR2		0x02
#define		AM85C30_RR3		0x03
#define		AM85C30_RR8		0x08
#define		AM85C30_RR10		0x0a
#define		AM85C30_RR12		0x0c
#define		AM85C30_RR13		0x0d

#define		AM85C30_D0		(0x01 << 0)
#define		AM85C30_D1		(0x01 << 1)
#define		AM85C30_D2		(0x01 << 2)
#define		AM85C30_D3		(0x01 << 3)
#define		AM85C30_D4		(0x01 << 4)
#define		AM85C30_D5		(0x01 << 5)
#define		AM85C30_D6		(0x01 << 6)
#define		AM85C30_D7		(0x01 << 7)

#endif	/* ! _L_SERIAL_H */
