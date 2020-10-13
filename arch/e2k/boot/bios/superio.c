#include <asm/head.h>
#include <asm/mas.h>
#include <asm/console.h>

#include "bios.h"
#include "mc146818rtc.h"

/* Control */
#define UART_IER 0x01
#define UART_IIR 0x02
#define UART_FCR 0x02
#define UART_LCR 0x03
#define UART_MCR 0x04
#define UART_DLL 0x00
#define UART_DLM 0x01

/* Status */
#define UART_LSR 0x05
#define UART_MSR 0x06
#define UART_SCR 0x07

#define UART_LCS 0x3

#define	BASE_BAUD1 ( 1280000 / 16 )

#if defined(CONFIG_SERIAL_NS16550_BOOT_CONSOLE)
extern unsigned long serial_init(int chan, int boot);
extern unsigned long com_port;
#endif

static int set_irq = 0;

void set_irq_pin(void);

void write_sio(int index,int data)
{
	outb(index, 0x3f0);
	outb(data, 0x3f1);
}

unsigned char read_sio(int index)
{
	outb(index, 0x3f0);
	return inb(0x3f1);
}

inline void uart_init (unsigned base_port)
{
	int divisor = BASE_BAUD1;
        /* enable interrupts */
        outb(0x7, base_port + UART_IER); 

        /* enable fifo's */ 
        outb(0x01, base_port + UART_FCR);

        outb(0x80 | UART_LCS, base_port + UART_LCR);
        outb(divisor & 0xFF,   base_port + UART_DLL);
        outb((divisor >> 8) & 0xFF,    base_port + UART_DLM);
        outb(UART_LCS, base_port + UART_LCR);
}

#ifndef CONFIG_E2K_SIC
void enable_serial_ports(void)
{
	unsigned char byte;
	rom_printk("enable superio serial ports ...\n");

	outb(0x55, 0x3f0);
	
	byte = read_sio(0x22);
	byte |= (1 << 4);
	write_sio(0x22, byte); // com1 power on
	
	write_sio(0x7, 0x4);
	write_sio(0x30, 0);
	write_sio(0x60, 0x3);
	write_sio(0x61, 0xf8);
	write_sio(0x70, 0x4);
//	write_sio(0xf0, 0x2);
	write_sio(0x30, 0x1);

	uart_init(0x3f8);

	byte = read_sio(0x22);
	byte |= (1 << 5);
	write_sio(0x22, byte); // com2 power on
	
	write_sio(0x7, 0x4);
	write_sio(0x07, 0x05);
        write_sio(0x30, 0x00);
	write_sio(0x60, 0x2);
	write_sio(0x61, 0xf8);
	write_sio(0x70, 0x3);
	write_sio(0x74, 0x4); // no dma active
//	write_sio(0xf0, 0x2);
//	write_sio(0xf1, 0x6); // default 5
//	write_sio(0xf2, 0);
        write_sio(0x30, 0x01);
	
	uart_init(0x2f8);
	
	outb(0xAA, 0x3f0);

	if (!set_irq) set_irq_pin();
	set_irq = 1;

#if defined(CONFIG_SERIAL_NS16550_BOOT_CONSOLE)
	rom_printk("setup serial console ... ");
	com_port = serial_init(0, 0);
	rom_printk("on port 0x%x done\n", com_port);
#endif

	hardware.serial = 1;
}
#endif

void enable_parallel_port(void)
{
	unsigned char byte;
	rom_printk("enable superio parallel port ...\n");
	outb(0x55, 0x3f0);
	
	// [0]-FDC,[4]COM1,[5]COM2,[3]LPT
	byte = read_sio(0x22);
	byte |= (1 << 3);
	write_sio(0x22, byte); // lpt power on
	
	write_sio(0x7, 0x3);
	write_sio(0x30, 0);
	write_sio(0x60, 0x3);
	write_sio(0x61, 0x78);
	write_sio(0x70, 0x7);
	write_sio(0x74, 0x4); // no dma
	write_sio(0xf0, 0x3c); // default
	write_sio(0xf1, 0x00); // default
	write_sio(0x30, 0x1);
	
	outb(0xAA, 0x3f0);

	if (!set_irq) set_irq_pin();
	set_irq = 1;

	hardware.parallel = 1;
}

void enable_rtc(void)
{
	rom_printk("enable superio rtc ...\n");
	outb(0x55, 0x3f0);
	
	write_sio(0x7, 0x6);
	write_sio(0x30, 0);
//	write_sio(0x62, 0x70); //defaut
//	write_sio(0x63, 0x00); //default
	write_sio(0x70, 0x8);
//	write_sio(0xf0, 0x00); // default
	write_sio(0x30, 0x1);
	
	outb(0xAA, 0x3f0);

	if (!set_irq) set_irq_pin();
	set_irq = 1;

	hardware.rtc = 1;
}

void enable_keyboard(void)
{
	rom_printk("enable superio keyboard ...\n");
	outb(0x55, 0x3f0);
	
	write_sio(0x7, 0x7);
	write_sio(0x30, 0);
	write_sio(0x70, 0x1);
///	write_sio(0x72, 0xc);
	write_sio(0xf0, 0x3);
	write_sio(0x30, 0x1);
	
	outb(0xAA, 0x3f0);

	if (!set_irq) set_irq_pin();
	set_irq = 1;
	
	init_kbd();

	hardware.keyboard = 1;
}

void enable_mouse(void)
{
	rom_printk("enable superio mouse ...\n");
	outb(0x55, 0x3f0);
	
	write_sio(0x7, 0x7);
	write_sio(0x30, 0);
///	write_sio(0x70, 0x1);
	write_sio(0x72, 0xc);
	write_sio(0xf0, 0x3);
	write_sio(0x30, 0x1);
	
	outb(0xAA, 0x3f0);

	if (!set_irq) set_irq_pin();
	set_irq = 1;

	hardware.mouse = 1;
}

void enable_floppy(void)
{
	unsigned char byte;
	rom_printk("enable superio fdc ...\n");
	
	outb(0x55, 0x3f0);
	
	byte = read_sio(0x22);
	byte |= (1 << 0);
	write_sio(0x22, byte); // fdc power on	
	
	write_sio(0x7, 0x0);
	write_sio(0x30, 0);	// disable fdc
	write_sio(0x70, 0x06);	// irq
	write_sio(0x30, 0x1);	// enable fdc
	
	outb(0xAA, 0x3f0);

	if (!set_irq) set_irq_pin();
	set_irq = 1;
	
	/* 0x10	CMOS	fd drive type (2 nibbles: high=fd0, low=fd1)
	 * values:
	 * 1: 360K 5.25"
	 * 2: 1.2MB 5.25"
	 * 3: 720K 3.5"
	 * 4: 1.44MB 3.5"
	 * 5: 2.88MB 3.5"
	 */
	if (!CMOS_READ(0x10))
		CMOS_WRITE(0x40, 0x10);


	hardware.floppy = 1;
}

void set_irq_pin(void)
{
	outb(0x55, 0x3f0);

	write_sio(0x07, 0x08);
        write_sio(0x30, 0x00);
        write_sio(0xc0, 0x03);
//        write_sio(0xca, (1<<3)); // irq8
        write_sio(0xcc, (1<<3)); // irq12
        write_sio(0xd0, (1<<3)); // irq1
        write_sio(0xd1, (1<<3)); // irq3
        write_sio(0xd2, (1<<3)); // irq4
        write_sio(0xd3, (1<<3)); // irq5
        write_sio(0xd4, (1<<3)); // irq6
        write_sio(0xd5, (1<<3)); // irq7
        write_sio(0x30, 0x01);
	
	outb(0xAA, 0x3f0);
}
