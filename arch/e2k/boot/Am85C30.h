
#ifdef CONFIG_E2K_SIC
extern unsigned short zilog_serial_init(void);
#endif

/* WRITE Registers */

#define		WR0 		0x00
#define 	WR1		0x01
#define 	WR2		0x02
#define 	WR3		0x03
#define 	WR4		0x04
#define 	WR5		0x05
#define 	WR6		0x06
#define 	WR7		0x07
#define 	WR8		0x08
#define 	WR9		0x09
#define 	WR10		0x0a
#define 	WR11		0x0b
#define 	WR12		0x0c
#define 	WR13		0x0d
#define 	WR14		0x0e
#define 	WR15		0x0f

/* READ (Status) Registers */

#define		RR0		0x00
#define 	RR1		0x01	
#define		RR2		0x02
#define		RR3		0x03
#define		RR8		0x08
#define		RR10		0x0a
#define		RR12		0x0c
#define		RR13		0x0d

#define		D0		(0x01 << 0)
#define		D1		(0x01 << 1)
#define		D2		(0x01 << 2)
#define		D3		(0x01 << 3)
#define		D4		(0x01 << 4)
#define		D5		(0x01 << 5)
#define		D6		(0x01 << 6)
#define		D7		(0x01 << 7)

/* WR0 */
/*  	D2,D1,D0
*	Register Access Pointer
*
*	000 - N0, [N8]*
*	001 - N1, [N9]*
*	010 - N2, [N10]*
*	011 - N3, [N11]*
*	100 - N4, [N12]*
*	101 - N5, [N13]*
*	110 - N6, [N14]*
*	111 - N7, [N15]*
*
*   if Point High Register Group = 1
*
*	D5,D4,D3
*
*	SCC Command
*
*	000 - Null Code 
*	001 - Point High Register Group 
*	010 - Reset Ext/Status Interrupts
*	011 - Send Abort
*	100 - Enable Int. on Next Rx Character
*	101 - Reset Tx Int. Pending
*	110 - Error Reset
*	111 - Reset Highest IUS
*
*	D7,D6
*	SCC Command
*
*	00 - Null Code
*	01 - Reset Rx CRC Checker 
*	10 - Reset Tx CRC Generator
*	11 - Reset Tx Underrun/EOM Latch
*/

/* WR1 */
/*	D0
*	Ext. Int. Enable
*	D1
*	Tx Int. Enable
*	D2
*	Parity is Special Condition
*	D4,D3
*	Rx Int Mode
*	
*	00 - Rx Int Disable
*	01 - Rx Int on First Char. or Special Condition
*	10 - Int on All Rx Char. or Special Condition 
*	11 - Rx Int. on Special Condition Only
*	D5
*	Wait/DMA Request on Receive/Transmit
*	D6
*	Wait/DMA Request Function
*	D7
*	Wait/DMA Request Enable
*/

/* WR2 */
/*	D7 - D0
*	Interrupt Vector
*/

/* WR3 */
/*	D0
*	Rx Enable
*	D1
*	Sync Character Load Inhibit
*	D2
*	Address Search Mode (SDLC)
*	D3
*	Rx CRC Enable
*	D4
*	Enter Hunt Mode
*	D5
*	Auto Enable
*	D7,D6
*
*	00 - Rx 5 Bits / Character
*	01 - Rx 6 Bits / Character
*	10 - Rx 7 Bits / Character 
*	11 - Rx 8 Bits / Character
*/

/* WR4 */
/*	D0
*	ParityEnable
*	D1
*	Parity Even(0) / Odd(1) 
*	D3,D2
*
*	00 - Sync Modes Enable
*	01 - 1 Stop Bit / Character
*	10 - 1.5 Stop Bits / Character
*	11 - 2 Stop Bits / Character
*	D5,D4
*
*	00 - 8-Bit Sync Character
*	01 - 16-Bit Sync Character
*	10 - SDLC Mode
*	11 - External Sync Mode
*	D7,D6
*
*	00 - X1 Clock Mode
*	01 - X16 Clock Mode
*	10 - X32 Clock Mode 
*	11 - X64 Clock Mode
*/

/* WR5 */
/*	D0
*	Tx CRC Enable
*	D1
*	RTS
*	D2
*	SDLC-/CRC-16
*	D3
*	Tx Enable
*	D4
*	Send Break
*	D6,D5
*
*	00 - Tx 5 Bits / Character
*	01 - Tx 6 Bits / Character
*	10 - Tx 7 Bits / Character 
*	11 - Tx 8 Bits / Character
*	D7
*	DTR
*/

/* WR6 */
/*	D5-D0
*	xN constant
*	D7,D6
*	Reserved (not used in asynchronous mode)
*/
	
/* WR7 */
/*	D6-D0
*	Reserved (not used in asynchronous mode)
*	D7
*	xN Mode Enable 
*/

/* WR8 */
/*	D7-D0
*	Transmit Buffer
*/

/* WR9 */
/*	D0
*	Vector Includes Status
*	D1
*	No Vector
*	D2
*	Disable Lower Chain
*	D3
*	Master Interrupt Enable
*	D4
*	Status High/Low_
*	D5
*	Interrupt Masking Without INTACK_
*	D7-D6
*	
*	00 - No Reset
*	01 - Channel B Reset
*	10 - Channel A Reset 
*	11 - Force Hardware Reset
*/

/* WR10 */
/*	D0
*	6 bit / 8 bit SYNC
*	D1
*	Loop Mode
*	D2
*	Abort/Flag on Underrun
*	D3
*	Mark/Flag Idle
*	D4
*	Go Active on Poll
*	D6-D5
*	
*	00 - NRZ
*	01 - NRZI
*	10 - FM1 (Transition = 1) 
*	11 - FM0 (Transition = 0)
*	D7
*	CRC Preset '1' or '0'
*/

/* WR11 */
/*	D1-D0
*
*	00 - TRxC Out = XTAL output
*	01 - TRxC Out = Transmit Clock
*	10 - TRxC Out = BRG output 
*	11 - TRxC Out = DPLL output
*	D2
*	TRxC O/I
*	D4-D3
*
*	00 - Transmit Clock = RTxC pin
*	01 - Transmit Clock = TRxC pin
*	10 - Transmit Clock = BRG output
*	11 - Transmit Clock = DPLL output
*	D6-D5
*
*	00 - Receive Clock = RTxC pin
*	01 - Receive Clock = TRxC pin
*	10 - Receive Clock = BRG output
*	11 - Receive Clock = DPLL output
*	D7
*	RTxC XTAL / NO XTAL
*/

/* WR12 */
/*	D7-D0
*	Lower Byte of Time Constant
*/

/* WR13 */
/*	D7-D0
*	Upper Byte of Time Constant
*/

/* WR14 */
/*	D0
*	BRG Enable
*	D1
*	BRG Source
*	D2
*	DTR / REQUESTt Function
*	D3
*	Auto Echo
*	D4
*	Local Loopback
*	D7-D5
*
*	000 - Null Command
*	001 - Enter Search Mode
*	010 - Reset Missing Clock 
*	011 - Disable DPLL
*	100 - Set Source = BR Generator
*	101 - Set Source = RTxC_
*	110 - Set FM Mode 
*	111 - Set NRZI Mode
*/

/* WR15 */
/*	D0
*	SDLC/HDLC Enhancement Enable
*	D1
*	Zero Count IE (Interrupt Enable)
*	D2
*	10 * 19-bit Frame Status FIFO Enable
*	D3
*	DCD IE
*	D4
*	Sync/Hunt IE
*	D5
*	CTS IE
*	D6
*	Tx Underrun / EOM IE
*	D7
*	Break/Abort IE
*/


/* RR0 */
/*	D0
*	Rx Character Availiable
*	D1
*	Zero Count
*	D2
*	Tx Buffer Empty
*	D3
*	DCD
*	D4
*	Sync/Hunt
*	D5
*	CTS
*	D6
*	Tx Underrun / EOM
*	D7
*	Break/Abort
*/

/* RR1 */
/*	D0
*	All Sent
*	D1
*	Residue Code 2
*	D2
*	Residue Code 1
*	D3
*	Residue Code 0
*	D4
*	Parity Error
*	D5
*	Rx Overrun Error
*	D6
*	CRC / Framing Error
*	D7
*	End of Frame (SDLC)
*/

/* RR2 */
/*	D7-D0
*	Interrupt Vector
*
*	Channel A RR2 = WR2
*	Channel B RR2 = Interrupt Vector Modified*
*	
*	*
*	D3	D2	D1	Status High/Low = 0
*	D4	D5	D6	Status High/Low = 1
*	
*	0	0	0	Ch B Transmit Buffer Empty
*	0	0	1	Ch B External/Status Change
*	0	1	0	Ch B Receive Char. Availiable
*	0	1	1	Ch B Special Receive Condition
*	1	0	0	Ch A Transmit Buffer Empty
*	1	0	1	Ch A External/Status Change
*	1	1	0	Ch A Receive Char. Availiable
*	1	1	1	Ch A Special Receive Condition
*/

/* RR3 */
/*	D0
*	Channel B Ext/Status IP (Interrupt Pending)
*	D1
*	Channel B Tx IP
*	D2
*	Channel B Rx IP
*	D3
*	Channel A Ext/Status IP
*	D4
*	Channel A Tx IP
*	D5
*	Channel A Rx IP
*	D7-D6
*	Always 00
*/

/* RR8 */
/*	D7-D0
* 	Receive Buffer
*/

/* RR10 */
/*	D7-D0
*	Reserved (not used in asynchronous mode)
*/

/* RR12 */
/*	D7-D0
*	Lower Byte of Time Constant
*/

/* RR13 */
/*	D7-D0
*	Upper Byte of Time Constant
*/







