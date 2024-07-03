#ifndef MGA_H
#define MGA_H

#	define PCI_VENDOR_ID_MGAM83	0x108e
#	define PCI_DEVICE_ID_MGAM83	0x8000

	// Indexes of pci_dev.resource[]
#	define PCI_MMIO_BAR		0
#	define PCI_MEM_BAR		1
#	define PCI_I2C_BAR		2

/*******************************************************************************
 * MMIO Registers
 *******************************************************************************
 */
#define REG_CTRL	0x000		// Control Register
#define REG_STAT	0x004		// Status Register
#define REG_HTIM	0x008		// Horizontal Timing Register
#define REG_VTIM	0x00c		// Vertical Timing Register
#define REG_HVLEN	0x010		// Horizontal and Vertical Length Register
#define REG_VBARa	0x014		// Video Memory Base Address Register A
#define REG_VBARb	0x018		// Video Memory Base Address Register B
#define REG_C0XY	0x030		// Cursor 0 X,Y Register
#define REG_C0BAR	0x034		// Cursor0 Base Address register
#define REG_C0CR	0x040		// Cursor0 Color Registers
#define REG_C1XY	0x070		// Cursor 0 X,Y Register
#define REG_C1BAR	0x074		// Cursor0 Base Address register
#define REG_C1CR	0x080		// Cursor0 Color Registers
#define REG_PCLT	0x800		// 8bpp Pseudo Color Lockup Table
#define REG_TST_D	0x01C		// Test Mode

// BitBlt module registers
#define BBR0		0x1000		// CTRL_REG if writing
					// STAT_REG if reading
#define BBR1		0x1004		// WINDOW_REG (size of the window to copy)
#define BBR2		0x1008		// SADDR_REG (Source address reg - byte offset
                                        // inside framebuffer) invisible framebuffer part
#define BBR3		0x100c		// DADDR_REG (Destination address reg - byte offset
                                        // inside framebuffer) visible framebuffer part
#define BBR4		0x1010		// PITCH_REG (value to increment both SADDR_REG and 
					// DADDR_REG to have them pointing to the next 
					// lines of WINDOWS (source and destination windows
					// respecteviely)). PITCH_REG has 2 parts. The highest 16
					// little-endian bits are for the destination and the lowest
					// ones are for the source. Determined in bytes
#define BBR5		0x1014		// BG_REG - Background color (color extenshion mode for
					// originally monochromed color only)
#define BBR6		0x1018		// FG_REG - Foreground color (color extenshion mode for
					// originally monochromed color only)
#define BBR7		0x101c		// RESERVED
	/* Bit feilds for CTRL_REG (little-endian mode) */
#define CE_EN		(1 << 0)	// Enable color extenshion (for
					// originally monochromed color only)
#define PAT_EN		(1 << 1)	// Enable 8x8 pattern multiplication
					// (Pattern Copy). Doesn't work if
					// continuous address generation for source 
					// is enabled. 
#define SFILL_EN	(1 << 2)	// Enable continuous color pouring mode
					// Works only in color extenshion mode
#define INV_EN		(1 << 3) 	// monochromed image invertion mode
					// Works only in color extenshion mode
#define TR_EN		(1 << 4)	// Transparency mode
					// Works only in color extenshion mode
#define HDIR		(1 << 5)	// Horizontal (when drawing a line of WINDOW)
					// incrementation sign (0 --->; 1 <---;)
#define VDIR		(1 << 6)	// Vertical incrementation sign (0 --->; 1 <---;)
					// The same as PITCH_REG parts sign 
#define SRC_MODE	(1 << 7)	// Enable address generation for source
					// If enabled makes module to increment source
					// address continuously inspite of lowest part of
					// PITCH_REG. (This mode has to be enabled if you
					// want to have your image object continuous in 
					// invisible part of framebuffer memory due to economy
					// reason i think)
/*#define TERM_MODE*///FIXME		// 32 bits word alignment when reached end of a line
					// Address generation for source mode only	
#define BPP_08		(0x00 << 10)
#define BPP_16		(0x01 << 10)
#define BPP_24		(0x02 << 10)
#define BPP_32		(0x03 << 10)

#define ROP_02		(0x02 << 12)	// DST = DST &~ SRC
#define ROP_03		(0x03 << 12)	// DST = DST
#define ROP_04		(0x04 << 12)	// DST = ~DST & SRC
#define ROP_05		(0x05 << 12)	// DST = SRC
#define ROP_06		(0x06 << 12)	// DST = DST != SRC
#define ROP_07		(0x07 << 12)	// DST = DST | SRC
#define ROP_08		(0x08 << 12)	// DST = ~DST &~ SRC
#define ROP_09		(0x09 << 12)	// DST = DST == SRC
#define ROP_0A		(0x0a << 12)    // DST = ~SRC
#define ROP_0B		(0x0b << 12)    // DST = DST | ~SRC
#define ROP_0C		(0x0c << 12)	// DST = ~DST
#define ROP_0D		(0x0d << 12)	// DST = ~DST | SRC
#define ROP_0E		(0x0e << 12)	// DST = ~DST | ~SRC
#define ROP_0F		(0x0f << 12)	// DST = {1}

/*#define SOFFS*///FIXME

#define SDMA_EN		(1 << 20)	// Enable DMA for Source
#define DDMA_EN		(1 << 21)	// Enable DMA for Destination

#define PAUSE		(1 << 27)	// BitBlt operation delay
					// Used for the executive control only
#define NFIE		(1 << 28)	// Enable interrupt in the case of unfilling 
					// task buffer
					// Used for the executive control only
#define NPIE		(1 << 29)	// Enable interrupt in the case of unexecuting 
					// of BitBlt operation 
					// Used for the executive control only
#define ABORT		(1 << 30)	// BitBlt operation abortion 
#define START		(1 << 31)	// BitBlt operation starting
	/* Bit feilds for STAT_REG (little-endian mode) */
#define FULL		(1 << 30)	// Double buffering state
					// 0 - Buffer isn't filled up, so another 
					// operation may be initiated 
					// 1 - Buffer is filled up
#define PROCESS		(1 << 31)	// BitBlt operation carring out state
					// 0 - The module isn't carring out BitBlt operation
					// 1 - BitBlt operation is running 	


// Control Register REG_CTRL
#define CTRL_IBBO	(0x1<<31)	// Inverse Bus Byte Order
#define CTRL_SAP
#define CTRL_HC1R_32	0		// Hardware Cursor1 Resolution 32x32
#define	CTRL_HC1R_64	(0x1<<25)	//                             64x64
#define CTRL_HC1E	(0x1<<24)	// Hardware Cursor1 Enabled
#define	CTRL_HC0R_32	0		// Hardware Cursor0 Resolution 32x32
#define	CTRL_HC0R_64	(0x1<<21)	//                             64x64
#define CTRL_HC0E	(0x1<<20)	// Hardware Cursor0 Enabled
#define CTRL_TST	(0x1<<17)	// TODO: ?????
#define CTRL_BL_POS	0 		// Blanking Polarization Level Positive
#define CTRL_BL_NEG	(0x1<<15)	//                             Negative
#define CTRL_CSYNC_HIGH	0		// Composite Synchronization Pulse Polarization Level Positive
#define CTRL_CSYNC_LOW	(0x1<<14)	//                                                    Negative
#define CTRL_VSYNC_HIGH	0		// Vertical Synchronization Pulse Polarization Level Positive
#define CTRL_VSYNC_LOW	(0x1<<13)	//                                                   Negative
#define CTRL_HSYNC_HIGH	0		// Horizontal Synchronization Pulse polarization Level Positive
#define CTRL_HSYNC_LOW	(0x1<<12)	//                                                     Negative

#define CTRL_PC_GRAY	0		// 8-bit Pseudo Color Grayscale
#define CTRL_PC_PSEUDO	(0x1<<11)	//                    Pseudo Color

#define CTRL_CD_8BPP	0		// Color Depth  8bpp
#define CTRL_CD_16BPP	(0x1<<9)	//             16bpp
#define CTRL_CD_24BPP	(0x2<<9)	//             24bpp
#define CTRL_CD_32BPP	(0x3<<9)	//             32bpp

#define CTRL_VBL_1	0		// Video Memory Burst Length 1 cycle
#define CTRL_VBL_2	(0x1<<7)	//                           2 cycles
#define CTRL_VBL_4	(0x2<<7)	//                           4 cycles
#define CTRL_VBL_8	(0x3<<7)	//                           8 cycles
#define CTRL_VBL1024	(0x203<<7)	//                          16 cycles (extension)

#define CTRL_CBSWE	(0x1<<6)	// CLUT Bank Switching Enable
#define CTRL_VBSWE	(0x1<<5)	// Video Bank Switching Enable
#define CTRL_CBSIE	(0x1<<4)	// CLUT Bank Switch Interrupt Enable
#define CTRL_VBSIE	(0x1<<3)	// VideoBank Switch Interrupt Enable
#define CTRL_HIE	(0x1<<2)	// HSync Interrupt Enable
#define CTRL_VIE	(0x1<<1)	// VSync Interrupt Enable
#define CTRL_VEN	(0x1<<0)		// Video Enable

// Status Register REG_STAT
#define STAT_HC1A	(0x1<<24)	// Hardware cursor1 available
#define STAT_HC0A	(0x1<<20)	// Hardware cursor0 available
#define STAT_ACMP	(0x1<<17)	// Active CLUT Memory Page
#define STAT_AVMP	(0x1<<16)	// Active Video Memory Page
#define STAT_CBSINT	(0x1<<7)	// CLUT Bank Switch Interrupt Pending
#define STAT_VBSINT	(0x1<<6)	// Bank Switch Interrupt Pending
#define STAT_HINT	(0x1<<5)	// Horizontal Interrupt Pending
#define STAT_VINT	(0x1<<4)	// Vertical Interrupt Pending
#define STAT_LUINT	(0x1<<1)	// Line FIFO Under-Run Interrupt Pending
#define STAT_SINT	(0x1<<0)	// System Error Interrupt Pending

#define FB_SYNC_HOR_HIGH_ACT	1	/* horizontal sync high active	*/
#define FB_SYNC_VERT_HIGH_ACT	2	/* vertical sync high active	*/
#define FB_SYNC_COMP_HIGH_ACT	8	/* composite sync high active   */

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


struct mgam83fb_par {
	int			bus_type;	// 0 - PCI, 1 - SBUS
	int			index;		// MGAM index

	struct {
		unsigned long 	base;		// phys address
		unsigned long	vbase;		// virtual address
		unsigned int	len;
	} mem;
	struct {
		unsigned long 	base;	// phys address
		unsigned long	vbase;	// virtual address
		unsigned int	len;
	} mmio;
	struct {
		unsigned long 	base;	// phys address
		unsigned long	vbase;	// virtual address
		unsigned int	len;
	} i2c;



	/* Current videomode **************************************************/
	__u32 xres;                     // visible resolution
	__u32 yres;
	__u32 xres_virtual;             // virtual resolution
	__u32 yres_virtual;
	__u32 xoffset;                  // offset from virtual to visible
	__u32 yoffset;                  // resolution

	__u32 bits_per_pixel;           // Bits per pixel

	__u32 pixclock;                 // pixel clock in ps (pico seconds)
	__u32 left_margin;              // time from sync to picture
	__u32 right_margin;             // time from picture to sync
	__u32 upper_margin;             // time from sync to picture
	__u32 lower_margin;
	__u32 hsync_len;                // length of horizontal sync
	__u32 vsync_len;                // length of vertical sync

	__u32 sync;

	u32     pseudo_palette[16];
			
};

#endif /* MGA_H */
