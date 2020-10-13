
#include <linux/pci.h>
#include <linux/pci_ids.h>

#include <asm/e2k_debug.h>
#include <asm/e2k.h>
#include "pci_isa_config.h"
#include "ide_config.h"

#include "southbridge.h"
#include "pci.h"
#include "mga.h"
#ifdef	CONFIG_E2K_LEGACY_SIC
#include <asm/hb_regs.h>
#endif	/* CONFIG_E2K_LEGACY_SIC */

#undef	DEBUG_MGA_MODE
#undef	DebugMGA
#define	DEBUG_MGA_MODE	0
#define DebugMGA 	if (DEBUG_MGA_MODE) rom_printk

#undef	TRACE_MSG
#define	DBG_MODE	0
#define DEBUG_MSG 	if (DBG_MODE)	rom_printk
#if 0
# define HZ		100	/* Internal kernel timer frequency */

void __delay(unsigned long loops)
{
	unsigned long i=loops;
	while (i--) {
	}
}

void __udelay(unsigned long usecs, unsigned long lps)
{
	__delay( (usecs * lps) * HZ / 1000000UL );
}

#define __udelay_val loops_per_jiffy

#define udelay(usecs) __udelay((usecs),__udelay_val)

#define mdelay(n) ({unsigned long __ms=(n); while (__ms--) udelay(1000);})

#endif
#if 0
static void error(char *x)
{
        rom_puts("\n\n");
        rom_puts(x);
        rom_puts("\n\n -- System halted");

        E2K_LMS_HALT_ERROR(0xdead); /* Halt */
}
#endif
#define INT_MAX		((int)(~0U>>1))

typedef struct {
	int div;	// [6:0] Linear output divider
	
	int q;	// [7:0] PPL*_Q
	int p;	// [9:0] PPL*_P
	int po;	// [0:0] PPL_PO

	int pixclock;
} clk_t;

clk_t __calc( int pixclock )
{
	clk_t res;
	DEBUG_MSG("__calc start\n");
	res.pixclock = 39721;
	res.div	= 0x2;
	res.q	= 0x95;
	res.p	= 0x106;
	res.po  = 0x1;
	DEBUG_MSG("__calc finish\n");
	DEBUG_MSG( "Calulated: pixclock %d div %x q %x p %x po %x\n", res.pixclock, res.div, res.q, res.p, res.po );

	return res;
}

static int SB_bus, SB_device;

static inline void mga_write(unsigned long v, unsigned long reg)
{
	E2K_WRITE_MAS_W(reg, v, MAS_IOADDR);
}

static inline unsigned long mga_read(unsigned long reg)
{
	return E2K_READ_MAS_W(reg, MAS_IOADDR);
}

static inline void i2c_write(unsigned long i2c_vbase, unsigned long reg, uint8_t val )
{
#ifdef MGA_TRACE
	uint32_t rdval;
#endif
	DEBUG_MSG( " i2c_write: I2C[0x%03lx] <= 0x%02x\n", reg, val );
	mga_write( val, ((unsigned long)i2c_vbase + reg));
#ifdef MGA_TRACE
	rdval = mga_read(((unsigned long)i2c_vbase + reg));
	TRACE_MSG( " i2c_write: I2C[0x%03lx] => 0x%02x\n", reg, rdval );
#endif
}

static inline uint8_t i2c_read(unsigned long i2c_vbase, unsigned long reg )
{
	uint32_t result = 0;
	result = mga_read(((unsigned long)i2c_vbase + reg) );
	DEBUG_MSG( " i2c_read: I2C[0x%03lx] => 0x%02x\n", reg, result );
	return result;
}

static void i2c_send(unsigned long i2c_vbase, int cmd, int data )
{
#if 0
	unsigned char status;
#endif	
	if (cmd & I2C_CR_WR) 
		i2c_write(i2c_vbase, I2C_REG_TXR, data );

	i2c_write(i2c_vbase, I2C_REG_CR, cmd );

#if 0
	while ( ( status = i2c_read(i2c_vbase, I2C_REG_SR ) & I2C_SR_TIP ) ) {
//		mdelay(1);
		DEBUG_MSG( "waiting 1 msec...\n" );
	}
#endif
}


static int ramdac_write(unsigned long i2c_vbase, unsigned long ramdac_reg, uint8_t val )
{
	// Sending RAMDAC device address
	i2c_send(i2c_vbase, I2C_CR_STA | I2C_CR_WR, (I2C_RAMDAC_ADDR << 1) & I2C_WRITE_OP);
	if ( i2c_read(i2c_vbase, I2C_REG_SR ) & I2C_SR_RxACK) {
		DEBUG_MSG( "RAMDAC[0x%02lx] <= 0x%02x\t[FAILED]", ramdac_reg, val );
		return -1;
	}

	// Sending RAMDAC register address
	i2c_send(i2c_vbase, I2C_CR_WR, ramdac_reg );
	if ( i2c_read(i2c_vbase, I2C_REG_SR ) & I2C_SR_RxACK) {
		DEBUG_MSG( "RAMDAC[0x%02lx] <= 0x%02x\t[FAILED]", ramdac_reg, val );
		return -1;
	}

	// Sending RAMDAC register data
	i2c_send(i2c_vbase, I2C_CR_STO | I2C_CR_WR, val);
	if ( i2c_read(i2c_vbase, I2C_REG_SR ) & I2C_SR_RxACK) {
		DEBUG_MSG( "RAMDAC[0x%02lx] <= 0x%02x\t[FAILED]", ramdac_reg, val );
		return -1;
	}

	return 0;
}


static uint8_t ramdac_read(unsigned long i2c_vbase, unsigned long ramdac_reg )
{
	uint8_t val = 0;

	// Sending RAMDAC device address
	i2c_send(i2c_vbase, I2C_CR_STA | I2C_CR_WR, (I2C_RAMDAC_ADDR << 1) & I2C_WRITE_OP);
	if ( i2c_read(i2c_vbase, I2C_REG_SR ) & I2C_SR_RxACK) {
		DEBUG_MSG( "RAMDAC[0x%02lx] => ????\t[FAILED]", ramdac_reg );
		return -1;
	}

	// Sending RAMDAC register address
	i2c_send(i2c_vbase, I2C_CR_WR, ramdac_reg );
	if ( i2c_read(i2c_vbase, I2C_REG_SR ) & I2C_SR_RxACK) {
		DEBUG_MSG( "RAMDAC[0x%02lx] => ????\t[FAILED]", ramdac_reg );
		return -1;
	}

	// Sending RAMDAC device address
	i2c_send(i2c_vbase, I2C_CR_STA | I2C_CR_WR, (I2C_RAMDAC_ADDR << 1) | I2C_READ_OP);
	if ( i2c_read(i2c_vbase, I2C_REG_SR ) & I2C_SR_RxACK) {
		DEBUG_MSG( "RAMDAC[0x%02lx] => ????\t[FAILED]", ramdac_reg );
		return -1;
	}

	// Sending RAMDAC register data
	i2c_send(i2c_vbase, I2C_CR_STO | I2C_CR_RD | I2C_CR_NACK, 0);

	val = i2c_read(i2c_vbase, I2C_REG_RXR );

	return val;
}

static void set_prescaler(unsigned long i2c_vbase, int value) 
{
	DEBUG_MSG("set_prescaler start\n");
	i2c_write(i2c_vbase, I2C_REG_PRER_LO, value & 0xFF );
	i2c_write(i2c_vbase, I2C_REG_PRER_HI, (value >> 8) & 0xFF );
	DEBUG_MSG("set_prescaler finish\n");
}

static void __set_clk_fs(unsigned long i2c_vbase, uint8_t a, uint8_t b, uint8_t c )
{
	uint8_t d = FS_REF;

	DEBUG_MSG("__set_clk_fs start\n");
	// ClkA_FS[2:0]	
	ramdac_write(i2c_vbase, 0x08, ( ramdac_read(i2c_vbase, 0x08 ) & 0x7F ) | ( ( a & 0x01 ) << 7 ) );
	ramdac_write(i2c_vbase, 0x0E, ( ramdac_read(i2c_vbase, 0x0E ) & 0xFC ) | ( ( a & 0x06 ) >> 1 ) );
	// ClkB_FS[2:0]
	ramdac_write(i2c_vbase, 0x0A, ( ramdac_read(i2c_vbase, 0x0A ) & 0x7F ) | ( ( b & 0x01 ) << 7 ) );
	ramdac_write(i2c_vbase, 0x0E, ( ramdac_read(i2c_vbase, 0x0E ) & 0xF3 ) | ( ( b & 0x06 ) << 1 ) );
	// ClkC_FS[2:0]
	ramdac_write(i2c_vbase, 0x0C, ( ramdac_read(i2c_vbase, 0x0C ) & 0x7F ) | ( ( c & 0x01 ) << 7 ) );
	ramdac_write(i2c_vbase, 0x0E, ( ramdac_read(i2c_vbase, 0x0E ) & 0xCF ) | ( ( c & 0x06 ) << 3 ) );
	// ClkD_FS[2:0]
	ramdac_write(i2c_vbase, 0x0D, ( ramdac_read(i2c_vbase, 0x0D ) & 0x7F ) | ( ( d & 0x01 ) << 7 ) );
	ramdac_write(i2c_vbase, 0x0E, ( ramdac_read(i2c_vbase, 0x0E ) & 0x3F ) | ( ( d & 0x06 ) << 5 ) );
	DEBUG_MSG("__set_clk_fs finish\n");
}

static void __set_ppl(unsigned long i2c_vbase, int index, uint8_t Q, uint16_t P, uint8_t PO )
{
	unsigned long base;

	switch( index ) {
	case 2 :
		base = 0x11;
		break;
	case 3 :
		base = 0x14;
		break;
	default :
		rom_printk( "Invalid PPL index %d\n", index );	
		return;
	}
	DEBUG_MSG("__set_ppl start\n");
	// PPL*_Q[7:0]
	ramdac_write(i2c_vbase, base + 0, Q );

	// PPL*_P[7:0]
	ramdac_write(i2c_vbase, base + 1, P & 0xFF );
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

		ramdac_write(i2c_vbase, base + 2, val );
	}
	DEBUG_MSG("__set_ppl finish\n");
}


static void __set_enabled(unsigned long i2c_vbase, int index, uint8_t enabled )
{
	unsigned long base;
	uint8_t val;

	switch( index ) {
	case 2 :
		base = 0x11;
		break;
	case 3 :
		base = 0x14;
		break;
	default :
		rom_printk( "Invalid PPL index %d\n", index );	
		return;
	}

	DEBUG_MSG("__set_enabled start\n");	
	val = ramdac_read(i2c_vbase, base + 2 );
	val = val & (~(0x01 << 6));
	val |= (enabled & 0x01) << 6;
	ramdac_write(i2c_vbase, base + 2, val );
	DEBUG_MSG("__set_enabled finish\n");
}

void __set_pixclock( unsigned long i2c_vbase, uint32_t pixclock )
{
	clk_t vidclk = __calc( pixclock );

	set_prescaler(i2c_vbase, NORMAL_SCL );

	// Enable I2C core
	i2c_write(i2c_vbase, I2C_REG_CTR, I2C_CTR_EN );

	ramdac_write(i2c_vbase, 0x08, 0x0 );

	ramdac_write(i2c_vbase, 0x0C, 0x0 );
	__set_clk_fs(i2c_vbase, FS_REF, FS_REF, FS_REF );

	// Reset vidclk enabled bit
	__set_enabled(i2c_vbase, 2, 0 );
	__set_ppl(i2c_vbase, 2, vidclk.q, vidclk.p, vidclk.po );

	__set_clk_fs(i2c_vbase, FS_PPL2_0, FS_REF, FS_PPL2_0 );
	ramdac_write(i2c_vbase, 0x08, ( ( FS_PPL2_0 & 0x01 ) << 7 ) | (vidclk.div & 0x7F) );
	ramdac_write(i2c_vbase, 0x0C, ( ( FS_PPL2_0 & 0x01 ) << 7 ) | (vidclk.div & 0x7F) );

	// Set vidclk enabled bit
	__set_enabled(i2c_vbase, 2, 1 );


	// Disable I2C core
	i2c_write(i2c_vbase, I2C_REG_CTR, 0x0 );
}

static void MMIO_WRITE( struct mgam83fb_par* p, unsigned long reg, uint32_t val )
{
	DEBUG_MSG( "MMIO[0x%03lx] <= 0x%08x\n", reg, val );
	mga_write( val, ((unsigned long)p->mmio.vbase + reg) );
	DEBUG_MSG( "Sleeping 10 msecs...\n" );
//	mdelay(10);
}

struct fb_bitfield {
	__u32 offset;			/* beginning of bitfield	*/
	__u32 length;			/* length of bitfield		*/
	__u32 msb_right;		/* != 0 : Most significant bit is */ 
					/* right */ 
};
#undef MGA_TEST
#ifdef MGA_TEST
static struct { struct fb_bitfield transp, red, green, blue; } colors = {
	{  0, 8, 0}, { 8, 8, 0}, { 16, 8, 0}, { 24, 8, 0}
};
#endif

int __set_mode( struct mgam83fb_par* p )
{
	int hsync = p->hsync_len;				// The Horizontal Syncronization Time (Sync Pulse )
	int hgdel = p->left_margin;				// The Horizontal Gate Delay Time (Back Porch)
	int hgate = p->xres;					// The Horizontal Gate Time (Active Time)
	int hlen = hsync + hgdel + hgate + p->right_margin;	// The Horizontal Length Time (Line Total)
	int vsync = p->vsync_len;				// The Vertical Syncronization Time (Sync Pulse )
	int vgdel = p->upper_margin;				// The Vertical Gate Delay Time (Back Porch)
	int vgate = p->yres;					// The Vertical Gate Time (Active Time)
	int vlen = vsync + vgdel + vgate + p->lower_margin;	// The Vertical Length Time (Frame total)
	int vbl = CTRL_VBL1024;					// Video Memory Burst Length
	int ctrl = CTRL_BL_NEG | vbl;


	DEBUG_MSG("__set_mode: start\n");
	switch( p->bits_per_pixel ) {
	case 8 :
		ctrl |= CTRL_CD_8BPP | CTRL_PC_PSEUDO;
		break;
	case 16 :
		ctrl |= CTRL_CD_16BPP;
#ifdef __LITTLE_ENDIAN
//		ctrl |= CTRL_IBBO;
#endif
		break;
	case 24 :
		ctrl |= CTRL_CD_24BPP;
#ifdef __LITTLE_ENDIAN
//		ctrl |= CTRL_IBBO;
#endif
		break;
	case 32 :
		ctrl |= CTRL_CD_32BPP;
#ifdef __LITTLE_ENDIAN
//		ctrl |= CTRL_IBBO;
#endif
		break;
	default:
		rom_printk( "Invalid color depth: %s %s %d\n", __FILE__, __FUNCTION__, __LINE__ );
		return -1;
	}

	ctrl |= ( p->sync & FB_SYNC_COMP_HIGH_ACT ) ? CTRL_CSYNC_HIGH : CTRL_CSYNC_LOW;
	ctrl |= ( p->sync & FB_SYNC_VERT_HIGH_ACT ) ? CTRL_VSYNC_HIGH : CTRL_VSYNC_LOW;
	ctrl |= ( p->sync & FB_SYNC_HOR_HIGH_ACT  ) ? CTRL_HSYNC_HIGH : CTRL_HSYNC_LOW;

	hsync--, hgdel--, hgate--, vsync--, vgdel--, vgate--, hlen--, vlen--;
	MMIO_WRITE( p, REG_CTRL, ctrl );
	MMIO_WRITE( p, REG_HTIM, hsync << 24 | hgdel << 16 | hgate );
	MMIO_WRITE( p, REG_VTIM, vsync << 24 | vgdel << 16 | vgate );
	MMIO_WRITE( p, REG_HVLEN, hlen << 16 | vlen );
	MMIO_WRITE( p, REG_VBARa, 0x0 );

	DEBUG_MSG( "hsync: %d hgdel: %d hgate %d\n", hsync, hgdel, hgate );
	DEBUG_MSG( "vsync: %d vgdel: %d vgate %d\n", vsync, vgdel, vgate );
	DEBUG_MSG( "hlen: %d vlen: %d\n", hlen, vlen );
	MMIO_WRITE( p, REG_CTRL, ctrl | CTRL_VEN );	
	DEBUG_MSG("__set_mode: finish\n");
	return 0;
}


#ifdef MGA_TEST
void drawStripe( unsigned long addr, 
				 int yB, int yE, 
				 int rB, int rE, int gB, int gE, int bB, int bE )
{
	int x, y;
	int xres = 640;
	int bpp = 32;
//	unsigned int once = 0;

	addr += yB * xres * (bpp >> 3);
/*	rom_printk("addr = 0x%x, yB = %d, yE = %d, rB = %d, rE = %d, gB = %d, gE = %d"
		   "		bB = %d, bE = %d\n", addr, yB, yE, rB, rE, gB, gE, bB, bE); */
	for ( y = yB; y < yE; y++ ) {
		for ( x = 0; x < xres; x++ ) {
/*			float factor = (float)x / (float)xres;
			unsigned int r = rB + factor * ( rE - rB );
			unsigned int g = gB + factor * ( gE - gB );
			unsigned int b = bB + factor * ( bE - bB );*/
			unsigned int r = rB + 1 * ( rE - rB );
			unsigned int g = gB + 1 * ( gE - gB );
			unsigned int b = bB + 1 * ( bE - bB );
#if 0
			if (once != 757){			
				rom_printk("r = %d, g = %d, b = %d\n", r, g, b);
				once++;
			}
#endif
			*(unsigned int*)addr = r << colors.red.offset | g << colors.green.offset | b << colors.blue.offset;

			addr += bpp >> 3;
		}
	}
}

#define CNVT_TOHW(val,width) ((((val)<<(width))+0x7FFF-(val))>>16)
void draw(struct bios_pci_dev *dev)
{
	u64 fb_phys_addr;
	int stripeHeight = 480 / 4;
	int rE = ( 1 << colors.red.length ) - 1;
	int gE = ( 1 << colors.red.length ) - 1;
	int bE = ( 1 << colors.red.length ) - 1;

	fb_phys_addr = dev->base_address[PCI_MEM_BAR];
	
	drawStripe( fb_phys_addr,                0, 1 * stripeHeight, 0, rE, 0, gE, 0, bE );
	drawStripe( fb_phys_addr, 1 * stripeHeight, 2 * stripeHeight, 0, 0, 0, 0, 0, bE );
	drawStripe( fb_phys_addr, 2 * stripeHeight, 3 * stripeHeight, 0, 0, 0, gE, 0, 0 );
	drawStripe( fb_phys_addr, 3 * stripeHeight, 4 * stripeHeight, 0, rE, 0, 0, 0, 0 );
};
#endif


void enable_mga(void)
{
	struct bios_pci_dev *dev;
	struct mgam83fb_par p;

	rom_printk("Scanning PCI bus for MGA video card ...");

	dev = bios_pci_find_device(PCI_VENDOR_ID_MGAM83, PCI_DEVICE_ID_MGAM83,
					NULL);
	
	if (dev) {
		SB_bus = dev->bus->number;
		SB_device = PCI_SLOT(dev->devfn);
		rom_printk("found on bus %d device %d\n", SB_bus, SB_device);
		DebugMGA("--------- VIDEO BIOS ------\n");
		DebugMGA("Class: %X\n", dev->class);
		DebugMGA("command: %x\n", dev->command);
		DebugMGA("base_address[0]: %04x\n", dev->base_address[0]);
		DebugMGA("size[0]: %04x\n", dev->size[0]);
		DebugMGA("base_address[1]: %04x\n", dev->base_address[1]);
		DebugMGA("size[1]: %04x\n", dev->size[1]);
		DebugMGA("base_address[2]: %04x\n", dev->base_address[2]);
		DebugMGA("size[2]: %04x\n", dev->size[2]);
		DebugMGA("base_address[3]: %04x\n", dev->base_address[3]);
		DebugMGA("size[0]: %04x\n", dev->size[3]);
		DebugMGA("base_address[4]: %04x\n", dev->base_address[4]);
		DebugMGA("size[4]: %04x\n", dev->size[4]);
		DebugMGA("base_address[5]: %04x\n", dev->base_address[5]);
		DebugMGA("size[5]: %04x\n", dev->size[5]);
		DebugMGA("rom_address: %04x\n", dev->rom_address);
		DebugMGA("rom_size %04x\n", dev->rom_size);
		p.mem.base 		= dev->base_address[PCI_MEM_BAR];
		p.mem.len 		= dev->size[PCI_MEM_BAR];
		p.mem.vbase		= dev->base_address[PCI_MEM_BAR];
		
		p.mmio.base		= dev->base_address[PCI_MMIO_BAR];
		p.mmio.len		= dev->size[PCI_MMIO_BAR];
		p.mmio.vbase 	 	= dev->base_address[PCI_MMIO_BAR];

		p.i2c.base		= dev->base_address[PCI_I2C_BAR];
		p.i2c.len		= dev->size[PCI_I2C_BAR];
		p.i2c.vbase 		= dev->base_address[PCI_I2C_BAR];	

		/* Update par */
		p.xres			= 0x280;
		p.yres			= 0x1e0;
		p.xres_virtual		= 0x280;
		p.yres_virtual		= 0x1e0;
		p.xoffset		= 0;
		p.yoffset		= 0;
		p.left_margin		= 0x28;
		p.right_margin		= 0x18;
		p.hsync_len		= 0x60;
		p.upper_margin		= 0x20;
		p.lower_margin		= 0xb;
		p.vsync_len		= 0x2;
		p.bits_per_pixel	= 0x20;
		p.pixclock		= 0x9b29;
		p.sync			= 0;
		
		DEBUG_MSG("!!! enable_mga: setting pixclock !!!\n");
		__set_pixclock( (unsigned long)p.i2c.vbase, p.pixclock );
		__set_mode( &p );
		rom_printk("MGA Initialization complete\n");
#ifdef MGA_TEST
		draw(dev);
#endif
	} else {
		rom_printk("!!! NOT FOUND !!!\n");
	}
}

#ifdef	CONFIG_E2K_LEGACY_SIC
void enable_embeded_graphic(void)
{
	struct bios_pci_dev *dev;
	unsigned int hb_cfg;
	unsigned short vpci_cmd;

	hb_cfg = early_readl_hb_reg(HB_PCI_CFG);
	if (!(hb_cfg & HB_CFG_IntegratedGraphicsEnable)) {
		rom_printk("Embeded graphic disabled, "
			"legacy VGA mode impossible\n");
		return;
	}

	rom_printk("Scanning PCI bus for Embeded MGA2 card ...");

	dev = bios_pci_find_device(PCI_VENDOR_ID_MCST_TMP,
					PCI_DEVICE_ID_MCST_MGA2, NULL);
	if (dev) {
		rom_printk("found on %d:%d:%d\n",
			dev->bus->number,
			PCI_SLOT(dev->devfn), PCI_FUNC(dev->devfn));
	} else {
		rom_printk("!!! NOT FOUND !!!\n");
		return;
	}
	hb_cfg |= HB_CFG_IntegratedVgaEnable;
	hb_cfg &= ~HB_CFG_ShareGraphicsInterrupts;
	early_writel_hb_reg(hb_cfg, HB_PCI_CFG);
	rom_printk("host bridge CFG: enable legacy VGA mode 0x%X\n",
		early_readl_hb_reg(HB_PCI_CFG));

	vpci_cmd = early_readw_eg_reg(PCI_COMMAND);
	vpci_cmd |= (PCI_COMMAND_IO | PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER);
	early_writew_eg_reg(vpci_cmd, PCI_COMMAND);
	rom_printk("Embeded Graphic CMD: enable IO/MMIO/DMA 0x%04x\n",
		vpci_cmd);
}
#endif	/* CONFIG_E2K_LEGACY_SIC */


