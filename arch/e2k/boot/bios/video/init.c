

#include <x86emu.h>
#include "init.h"
#include "printk.h"

#include <linux/pci_ids.h>

#include "pci-iface.h"
#include "bios.h"

#define die(x) { rom_printk(x); }
#define warn(x) { rom_printk(x);  }

#define DEBUG_VIDEO	0
#define DebugV(fmt, args...)				\
		({ if (DEBUG_VIDEO)			\
			rom_printk(fmt, ##args); })

void x86emu_dump_xregs(void);
int int15_handler(void);
int int16_handler(void);
int int1A_handler(void);
#ifndef _PC
int int42_handler(void);
#endif
int intE6_handler(void);
void setup_int_vect(void);
int run_bios_int(int num);
u32 getIntVect(int num);


void pushw(u16 val);

_ptr p;
ptr currentp = 0;
unsigned char biosmem[1024 * 1024];

int verbose = 1;


/* Interrupt multiplexer */

void do_int(int num)
{
	int ret = 0;

//	rom_printk("int%x vector at %x\n", num, getIntVect(num));

	/* This is a pInt leftover */
	currentp->num = num;

	switch (num) {
#ifndef _PC
	case 0x10:
	case 0x42:
	case 0x6D:

		if (getIntVect(num) == 0xFF065) {
			ret = int42_handler();
		}
		break;
#endif
	case 0x15:
		ret = int15_handler();
		break;
	case 0x16:
		ret = int16_handler();
		break;
	case 0x1A:
		ret = int1A_handler();
		break;
	case 0xe6:
		ret = intE6_handler();
		break;
	default:
		break;
	}

	if (!ret)
		ret = run_bios_int(num);

	if (!ret) {
		rom_printk("\nint%x: not implemented\n", num);
		//x86emu_dump_xregs();
	}
}


u8 x_inb(u16 port);
u16 x_inw(u16 port);
void x_outb(u16 port, u8 val);
void x_outw(u16 port, u16 val);
u32 x_inl(u16 port);
void x_outl(u16 port, u32 val);


X86EMU_pioFuncs myfuncs = {
	x_inb, x_inw, x_inl,
	x_outb, x_outw, x_outl
};


void X86EMU_setMemBase(void *base, unsigned int size);
void X86EMU_setabseg(void *abseg);
void x86emu_dump_xregs(void);
int X86EMU_set_debug(int debug);

X86EMU_intrFuncs intFuncs[256];

int pci_video_bios_init(struct bios_pci_dev *dev)
{
	void *abseg = 0;
	int i;
	unsigned char *cp;
	unsigned int size = 0;
	int base = 0;
	unsigned short initialip = 0, initialcs = 0, devfn = 0;
	char *date = "01/01/99";
#ifdef DEBUG
	int debugflag = 0;
	int trace = 0;
#endif

//	size = 64 * 1024;
	size = dev->rom_size;

	base = 0xc0000;
	initialcs = 0xc000;
	initialip = 0x0003;

//	rom_printk("Point 1 int%x vector at %x\n", 0x42, getIntVect(0x42));

	abseg = (void *) 0xa0000;

	currentp = &p;
	X86EMU_setMemBase(biosmem, sizeof(biosmem));
	X86EMU_setabseg(abseg);
	X86EMU_setupPioFuncs(&myfuncs);

	/* Setting up interrupt environment.
	 * basically this means initializing PCI and
	 * intXX handlers.
	 */
	pciInit();

	setup_int_vect();

	for (i = 0; i < 256; i++)
		intFuncs[i] = do_int;

	X86EMU_setupIntrFuncs(intFuncs);

	cp = (unsigned char *) dev->rom_address ;

	devfn = (PCI_SLOT(dev->devfn) << 3) | 
		 PCI_FUNC(dev->devfn);
	
	currentp->ax = devfn   ? devfn : 0xff;
	currentp->dx = 0x80;

	for (i = 0; i < size; i++) {
		wrb(base + i, cp[i]);
	}

	/* Put a date into ROM */
	for (i = 0; date[i]; i++)
		wrb(0xffff5 + i, date[i]);
	wrb(0xffff7, '/');
	wrb(0xffffa, '/');

	/* cpu setup */
	X86_AX = devfn ? devfn : 0xff;
	X86_DX = 0x80;
	X86_EIP = initialip;
	X86_CS = initialcs;

	/* Initialize stack and data segment */
	X86_SS = 0x0030;
	X86_DS = 0x0040;
	X86_SP = 0xfffe;
	/* We need a sane way to return from bios
	 * execution. A hlt instruction and a pointer
	 * to it, both kept on the stack, will do.
	 */
	pushw(0xf4f4);		/* hlt; hlt */
	pushw(X86_SS);
	pushw(X86_SP + 2);

	X86_ES = 0x0000;

#ifdef DEBUG
	if (trace) {
		rom_printk("Switching to single step mode.\n");
		X86EMU_trace_on();
	}
#endif

#if 0
	debugflag = DEBUG_MEM_TRACE_F |
		    DEBUG_DECODE_F | DEBUG_DISASSEMBLE_F |
		    DEBUG_TRACE_F | 
		    DEBUG_SYSINT_F;
#endif

#ifdef DEBUG
//	debugflag = 0x00ffffff;
	if (debugflag) {
		X86EMU_set_debug(debugflag);
	}
#endif

	X86EMU_exec();
	/* Cleaning up */
	pciExit();

	return 0;
}



/* VGA index register ports */
#define GRA_I   0x3CE           /* Graphics Controller Index */
#define SEQ_I   0x3C4           /* Sequencer Index */

/* VGA data register ports */
#define GRA_D   0x3CF           /* Graphics Controller Data Register */
#define SEQ_D   0x3C5           /* Sequencer Data Register */

#define CRT_IC  0x3D4           /* CRT Controller Index - color emulation */
#define CRT_DC  0x3D5           /* CRT Controller Data Register - color emulation */
#define IS1_RC  0x3DA           /* Input Status Register 1 - color emulation */
#define ATT_IW  0x3C0           /* Attribute Controller Index & Data Write Register */
#define ATT_R   0x3C1           /* Attribute Controller Data Read Register */

#define ATC_MODE                0x10
#define ATC_COLOR_PAGE          0x14


#define CRTC_H_TOTAL            0
#define CRTC_H_DISP             1
#define CRTC_H_BLANK_START      2
#define CRTC_H_BLANK_END        3
#define CRTC_H_SYNC_START       4
#define CRTC_H_SYNC_END         5
#define CRTC_V_TOTAL            6
#define CRTC_OVERFLOW           7
#define CRTC_PRESET_ROW         8
#define CRTC_MAX_SCAN           9
#define CRTC_CURSOR_START       0x0A
#define CRTC_CURSOR_END         0x0B
#define CRTC_START_HI           0x0C
#define CRTC_START_LO           0x0D
#define CRTC_CURSOR_HI          0x0E
#define CRTC_CURSOR_LO          0x0F
#define CRTC_V_SYNC_START       0x10
#define CRTC_V_SYNC_END         0x11
#define CRTC_V_DISP_END         0x12
#define CRTC_OFFSET             0x13
#define CRTC_UNDERLINE          0x14
#define CRTC_V_BLANK_START      0x15
#define CRTC_V_BLANK_END        0x16
#define CRTC_MODE               0x17
#define CRTC_LINE_COMPARE       0x18

// macros for writing to vga regs
#define write_seq(data,addr) outb(addr,SEQ_I); outb(data,SEQ_D)
#define write_gra(data,addr) outb(addr,GRA_I); outb(data,GRA_D)
#define write_crtc(data,addr) outb(addr,CRT_IC); outb(data,CRT_DC)
#define write_att(data,addr) inb(IS1_RC); inb(0x80); outb(addr,ATT_IW); inb(0x80); outb(data,ATT_IW); inb(0x80)


#define SEQ_CLOCK_MODE          0x01
#define SEQ_PLANE_WRITE         0x02
#define SEQ_CHARACTER_MAP       0x03
#define SEQ_MEMORY_MODE         0x04

#define GDC_PLANE_READ          0x04
#define GDC_MODE                0x05
#define GDC_MISC                0x06
#define GDC_BIT_MASK            0x08

#define VGA_FONT_BASE		0xa8000
#define CHAR_HEIGHT		16

unsigned char read_seq_b(unsigned short addr) {
	outb(addr,SEQ_I);
	return inb(SEQ_D);
}
unsigned char read_gra_b(unsigned short addr) {
	outb(addr,GRA_I);
	return inb(GRA_D);
}
unsigned char read_crtc_b(unsigned short addr) {
	outb(addr,CRT_IC);
	return inb(CRT_DC);
}
unsigned char read_att_b(unsigned short addr) {
	inb(IS1_RC);
	inb(0x80); 
	outb(addr,ATT_IW);
	return inb(ATT_R);
}


#if 0

void vga_set_amode (void) {
        unsigned char byte;

	rom_printk("Switching into alpha mode...");


        write_att(0x0c, ATC_MODE);

        //reset palette to normal in the case it was changed
        write_att(0x0, ATC_COLOR_PAGE);
//
// display is off at this point

        write_seq(0x3,SEQ_PLANE_WRITE); // planes 0 & 1
        byte = read_seq_b(SEQ_MEMORY_MODE) & ~0x04;
        write_seq(byte,SEQ_MEMORY_MODE);

        byte = read_gra_b(GDC_MODE) & ~0x60;
        write_gra(byte|0x10,GDC_MODE);

        write_gra(0x0e, GDC_MISC);

        write_crtc(0x00, CRTC_CURSOR_START);
        write_crtc(CHAR_HEIGHT-1, CRTC_CURSOR_END);

        byte = read_crtc_b(CRTC_MODE) & ~0xe0;
        write_crtc(byte|0xa0, CRTC_MODE);
        byte = read_crtc_b(CRTC_MAX_SCAN) & ~0x01f;
        write_crtc(byte | (CHAR_HEIGHT-1), CRTC_MAX_SCAN);


// turn on display, disable access to attr palette
        inb(IS1_RC);
        outb(0x20, ATT_IW);

	rom_printk("done.\n");
}

#endif

/*
 * by Steve M. Gehlbach, Ph.D. <steve@kesa.com>
 *
 * vga_font_load loads a font into font memory.  It
 * assumes alpha mode has been set.
 *
 * The font load code follows technique used
 * in the tiara project, which came from
 * the Universal Talkware Boot Loader,
 * http://www.talkware.net.
 */


void atyr128_font_enable(unsigned char *vidmem, int height, int num_chars) {

/* Note: the font table is 'height' long but the font storage area
 * is 32 bytes long.
 */

	int i;
	unsigned char byte;


//	rom_printk("Loading VGA font...");

	// set sequencer map 2, odd/even off
	byte = read_seq_b(SEQ_PLANE_WRITE) & ~0xf;

// rom_printk("SEQ_PLANE_WRITE %x\n", byte);

	write_seq(byte|4,SEQ_PLANE_WRITE);
	byte = read_seq_b(SEQ_MEMORY_MODE);

// rom_printk("SEQ_MEMORY_MODE %x\n", byte);

	write_seq(byte|4,SEQ_MEMORY_MODE);

	// select graphics map 2, odd/even off, map starts at 0xa0000
	write_gra(2,GDC_PLANE_READ);
	byte = read_gra_b(GDC_MODE) & ~0x10;

// rom_printk("GDC_MODE %x\n", byte);

	write_gra(byte,GDC_MODE);
	write_gra(0,GDC_MISC);

	/* Clear 256K */
	for (i = 0; i<(256 * 1024); i++) {
		vidmem[i] = 0;
	}


	// set sequencer back to maps 0,1, odd/even on
	byte = read_seq_b(SEQ_PLANE_WRITE) & ~0xf;
	write_seq(byte|3,SEQ_PLANE_WRITE);
	byte = read_seq_b(SEQ_MEMORY_MODE) & ~0x4;
	write_seq(byte,SEQ_MEMORY_MODE);

        byte = read_seq_b(SEQ_CHARACTER_MAP);

// rom_printk("SEQ_CHARACTER_MAP %x\n", byte);

        write_seq(0x0a, SEQ_CHARACTER_MAP);

	// select graphics back to map 0,1, odd/even on
	write_gra(0,GDC_PLANE_READ);
	byte = read_gra_b(GDC_MODE);
	write_gra(byte|0x10,GDC_MODE);
	write_gra(0xe,GDC_MISC);

//	rom_printk("done\n");

}


void video_bios(void)
{
	struct bios_pci_dev *dev;
	int adpt_cnt;
	unsigned char *code = 0;
	int pcirom = 0;
	int atyr128 = 0;
	int cl5446 = 0;
	int mga2 = 0;

	adpt_cnt = 0;

	DebugV("video_bios() started\n");
	dev = pci_find_class(PCI_CLASS_DISPLAY_VGA << 8, NULL);
	adpt_cnt++;

	if (dev) {
#if	DEBUG_VIDEO
		rom_printk("--------- VIDEO BIOS ------\n");
		rom_printk("Class: %X\n", dev->class);
		rom_printk("command: %x\n", dev->command);
		rom_printk("base_address[0]: %04x\n", dev->base_address[0]);
		rom_printk("size[0]: %04x\n", dev->size[0]);
		rom_printk("base_address[1]: %04x\n", dev->base_address[1]);
		rom_printk("size[1]: %04x\n", dev->size[1]);
		rom_printk("base_address[2]: %04x\n", dev->base_address[2]);
		rom_printk("size[2]: %04x\n", dev->size[2]);
		rom_printk("base_address[3]: %04x\n", dev->base_address[3]);
		rom_printk("size[0]: %04x\n", dev->size[3]);
		rom_printk("base_address[4]: %04x\n", dev->base_address[4]);
		rom_printk("size[4]: %04x\n", dev->size[4]);
		rom_printk("base_address[5]: %04x\n", dev->base_address[5]);
		rom_printk("size[5]: %04x\n", dev->size[5]);
		rom_printk("rom_address: %04x\n", dev->rom_address);
		rom_printk("rom_size %04x\n", dev->rom_size);
#endif
		code = (unsigned char *) dev->rom_address;

		if (code[0] == 0x55U &&
		    code[1] == 0xAAU ) {
			rom_printk("VIDEO BIOS found at %X\n", code);
			pcirom = 1;
		} else {
			rom_printk("No ROM signature found."
				   " Skipping BIOS init...\n");
			rom_printk("BYTES: %x %x\n", code[0],
					     code[1]);
		}

		switch (dev->vendor)
		{
		case PCI_VENDOR_ID_CIRRUS:
			if (dev->device == PCI_DEVICE_ID_CIRRUS_5446) {
				rom_printk("Cirrus Logic GD 5446 detected!\n");
				cl5446 = 1;
			};
			break;
		case PCI_VENDOR_ID_ATI:

			switch(dev->device)
			{
				case PCI_DEVICE_ID_ATI_RAGE128_PP:
					rom_printk("ATI Rage 128 PP detected!\n");
					atyr128 = 1;
					break;
				case PCI_DEVICE_ID_ATI_RAGE128_TR:
					rom_printk("ATI Rage 128 TR detected!\n");
					atyr128 = 1;
					break;
				default:
					rom_printk("Unknown ATI display adapter detected!\n");
					break;
			};

			break;
		case PCI_VENDOR_ID_MCST_TMP:
			if (dev->device == PCI_DEVICE_ID_MCST_MGA2) {
				rom_printk("Embeded Graphic MGA2/GC2500 "
					"detected!\n");
				mga2 = 1;
			};
			break;
		default:
			rom_printk("Unknown display adapter found!\n");
			break;
		}


	} else {
		rom_printk("No PCI display adaplers found!\n");

	}

	if (pcirom) {
		pci_video_bios_init(dev);
	} else if (mga2) {
#ifdef	CONFIG_VGA_CONSOLE
		vga_init();
#endif	/* CONFIG_VGA_CONSOLE */
	} else {
		return;
	}

	if (atyr128) {

		atyr128_font_enable( (unsigned char *) VGA_FONT_BASE, 
					CHAR_HEIGHT, 256);
#if 0

		unsigned char *vidmem = (unsigned char *) dev->base_address[0];
		int i;
		for (i=0; i < (1 * 1024 * 1024); i++) {
			vidmem[i] = 0;	
		};
#endif
	}

//	vga_set_amode();

	hardware.video = 1;

	if (atyr128)
	{
		long int i;
		/* delay to relax ATI hardware */
		for (i=0; i<77000000L; i++) {
			do {
				(void) (i);
			} while (0) ;
		}
	}

#if 0
	if (cl5446)
	{
		long int i;

//		rom_printk("qwertyuiopasdfghjklzxcvbnm\n");
//		rom_printk("qwertyuiopasdfghjklzxcvbnm\n");
//		rom_printk("qwertyuiopasdfghjklzxcvbnm\n");
		for (i=0; i<2000000L; i++) { do {i; } while (0) ; }
	}
#endif

}

