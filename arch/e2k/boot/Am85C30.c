
#include <linux/pci_ids.h>

#include <asm/e2k_api.h>
#include <asm/e2k_debug.h>
#include <asm/e2k.h>
#include <asm/bootinfo.h>

#include "bios/pci.h"
#include "bios/bios.h"
#include "bios/southbridge.h"
#include "Am85C30.h"

#undef	DEBUG_CONSOLE_MODE
#undef	DebugC
#define	DEBUG_CONSOLE_MODE	0	/* Console initialization */
#define	DebugC			if (DEBUG_CONSOLE_MODE) printk

#define PCI_DEVICE_ID_PAR_SER	0x8000 

unsigned long com_port;

unsigned long ch_a_control;
unsigned long ch_a_data;
unsigned long ch_b_control;
unsigned long ch_b_data;

#define NOT_BIOS 0

extern boot_info_t		*boot_info;

static void com_outb(u64 port, u8 byte)
{
       E2K_WRITE_MAS_B(port, byte, MAS_IOADDR);
}

static u8 com_inb(u64 port)
{
	return E2K_READ_MAS_B(port, MAS_IOADDR);
}

static u8 com_inb_command(u64 port, u8 reg_num)
{
	E2K_WRITE_MAS_B(port, reg_num, MAS_IOADDR);
	return E2K_READ_MAS_B(port, MAS_IOADDR);
}

static void com_outb_command(u64 port, u8 reg_num, u8 val)
{
	E2K_WRITE_MAS_B(port, reg_num, MAS_IOADDR);
	E2K_WRITE_MAS_B(port, val, MAS_IOADDR);
}

void
serial_putc(unsigned long com_port, unsigned char c)
{
	while ((com_inb_command(com_port, RR0) & D2) == 0){
	}
	com_outb((com_port + 0x01), c);
}

unsigned char
serial_getc(unsigned long com_port)
{
	while (((com_inb_command(com_port, RR0)) & D0) == 0){
	}
	return com_inb(com_port + 0x01);
}

unsigned short zilog_serial_init(void)
{
	struct bios_pci_dev *dev;
	unsigned char val = 0;

	rom_printk("Scanning PCI bus for ieee1284/rs232 device ...\n");
	dev = bios_pci_find_device(E3M_MULTIFUNC_VENDOR, PCI_DEVICE_ID_PAR_SER,
					NULL);
	if (dev == NULL) {
		dev = bios_pci_find_device(PCI_VENDOR_ID_MCST_TMP,
				PCI_DEVICE_ID_MCST_PARALLEL_SERIAL, dev);
	}
	if (dev){
		ch_a_control = (dev->base_address[1] &~ 0x01);
		ch_a_data    = (dev->base_address[1] &~ 0x01) + 0x01;
		ch_b_control = (dev->base_address[1] &~ 0x01) + 0x02;
		ch_b_data    = (dev->base_address[1] &~ 0x01) + 0x03;
		DebugC("zilog_serial_init: ch_a_control = 0x%x, ch_a_data = 0x%x\n"
			   "                   ch_b_control = 0x%x, ch_b_data = 0x%x\n",
			(unsigned int)ch_a_control, (unsigned int)ch_a_data, 
			(unsigned int)ch_b_control, (unsigned int)ch_b_data);
		com_port = ch_a_control;
	/* Hardware Reset */
		val = (val | D7 | D6); /* Force Hardware Reset */
		DebugC("zilog_serial_init: Hardware Reset: WR9 val = 0x%x\n", val);
		com_outb_command(ch_a_control, WR9, val); 
		/* It seems not neccesary due to WR9 sharing for both channels */
		com_outb_command(ch_b_control, WR9, val); 
#if NOT_BIOS
	/* Enabling interrupts */
		val = 0; val |= D3; 	/* Master Interrupt Enable */
		DebugC("zilog_serial_init: Hardware Reset: WR9 val = 0x%x\n", val);
		com_outb_command(ch_a_control, WR9, val); 
		/* It seems not neccesary due to WR9 sharing for both channels */
		com_outb_command(ch_b_control, WR9, val); 
#else
	/* Interrupts disabled */
#endif
#if NOT_BIOS
	/* Detailed interrupt installations */
		val = 0;
		val |= D1; /* Transmit interrupt enabling. An interrupt will be
			    * generated each time a packet is transmitted   */
		val |= D2; /* The parity error for recieved packet is Special
			    * Condition from now */  
		val |= D4; /* Enabling interrupt for each packet recieving and when
			    * Special Condition occurs */
		DebugC("zilog_serial_init: Hardware Reset: WR1 val = 0x%x\n", val);
		com_outb_command(ch_a_control, WR1, val); 
		com_outb_command(ch_b_control, WR1, val); 
#else
	/* poll mode */
		val = 0;
		DebugC("zilog_serial_init: Hardware Reset: WR1 val = 0x%x\n", val);
		com_outb_command(ch_a_control, WR1, val); 
		com_outb_command(ch_b_control, WR1, val); 
#endif
	/* Operation mode */
		val = 0;
#if NOT_BIOS
		val |= D0; /* Parity Enable */ 
			   /* Parity bit is present */
		val |= (D2 | D3); /* Setup stop bits, if any setuped the mode is asynchronus */
				  /* 2 stop bits */
#else
		val |= D2; /* stop bit = 1 */
#endif
		val |= D6; /* x16 mode */
		DebugC("zilog_serial_init: Hardware Reset: WR4 val = 0x%x\n", val);
		com_outb_command(ch_a_control, WR4, val); 
		com_outb_command(ch_b_control, WR4, val); 
	/* xN Mode Enable */
		val = 0;
		val |= D7; /* xN Mode Enable */ 
		DebugC("zilog_serial_init: Hardware Reset: WR7 val = 0x%x\n", val);
		com_outb_command(ch_a_control, WR7, val); 
		com_outb_command(ch_b_control, WR7, val); 
	/* setup xN constant */	  	
		val = 0;
		val |= (D0 | D2 | D4); /* 15_h = 21_d; xN = 0.5 * 21 = 10.5 */
		DebugC("zilog_serial_init: Hardware Reset: WR6 val = 0x%x\n", val);
		com_outb_command(ch_a_control, WR6, val); 
		com_outb_command(ch_b_control, WR6, val); 
	/* Bits per symbol to recieve */
		val = 0;
		val |= (D7 | D6); /* 8 bits per symbol */
		DebugC("zilog_serial_init: Hardware Reset: WR3 val = 0x%x\n", val);
		com_outb_command(ch_a_control, WR3, val); 
		com_outb_command(ch_b_control, WR3, val); 
	/* Bits per symbol to transmit */
		val = 0;
		val |= (D6 | D5); /* 8 bits per symbol */
		DebugC("zilog_serial_init: Hardware Reset: WR5 val = 0x%x\n", val);
		com_outb_command(ch_a_control, WR5, val); 
		com_outb_command(ch_b_control, WR5, val); 
	/* Encoding setup */
		val = 0;
#if NOT_BIOS
		val |= D5; /* NRZI encoding */
#else
			   /* NRZ encoding */
#endif
		DebugC("zilog_serial_init: Hardware Reset: WR10 val = 0x%x\n", val);
		com_outb_command(ch_a_control, WR10, val); 
		com_outb_command(ch_b_control, WR10, val); 
	/* Clock setup */
		val = 0;
		val |= (D4 | D6); /* Transmit Clock = BRG output; 
				   * Receive Clock = BRG output */
		DebugC("zilog_serial_init: Hardware Reset: WR11 val = 0x%x\n", val);
		com_outb_command(ch_a_control, WR11, val); 
		com_outb_command(ch_b_control, WR11, val); 
	/* Lower Byte of Time Constant */
		val = 0;
		val |= (D4 | D3 | D2 | D1); /* = 1e_h (4800) */
		DebugC("zilog_serial_init: Hardware Reset: WR12 val = 0x%x\n", val); 
		com_outb_command(ch_a_control, WR12, val); 
		com_outb_command(ch_b_control, WR12, val); 		
	/* Upper Byte of Time Constant */
		val = 0; /* determine 115200 baud rate when pclk = 4.9152 MHz */
		DebugC("zilog_serial_init: Hardware Reset: WR13 val = 0x%x\n", val);
		com_outb_command(ch_a_control, WR13, val); 
		com_outb_command(ch_b_control, WR13, val); 
	/* Determine synchronization source for BGR */
		val = 0; /* the source is RTxC pin */
		DebugC("zilog_serial_init: Hardware Reset: WR14 val = 0x%x\n", val);
		com_outb_command(ch_a_control, WR14, val); 
		com_outb_command(ch_b_control, WR14, val); 					
	/* switch on the reciver  */
		val = 0;
		val |= D0; /* turn on */
		val |= (D7 | D6); /* 8 bits per symbol */
		DebugC("zilog_serial_init: Hardware Reset: WR3 val = 0x%x\n", val);
		com_outb_command(ch_a_control, WR3, val); 
		com_outb_command(ch_b_control, WR3, val); 
	/* switch on the transmitter */
		val = 0;
		val |= D3; /* turn on */
		val |= (D6 | D5); /* 8 bits per symbol */
		DebugC("zilog_serial_init: Hardware Reset: WR5 val = 0x%x\n", val);
		com_outb_command(ch_a_control, WR5, val); 
		com_outb_command(ch_b_control, WR5, val); 
		com_port = ch_a_control;
		rom_printk("Initialization compleete ");
		if (boot_info) {
			boot_info->serial_base = com_port;
			rom_printk("AM85C30 Serial console enabled at "
				"0x%X base\n", com_port);
		} else {
			rom_printk("Unable to init boot_info BUG!!!\n");
		}
		hardware.serial = 1;
	} else {
		rom_printk("!!! NOT FOUND !!!\n");
	}
	
	return 0;	
}



