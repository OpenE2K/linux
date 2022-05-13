#include <asm/mas.h>

#include "bios.h"
#include "mc146818rtc.h"

#include "../boot_io.h"

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

static int set_irq = 0;

void set_irq_pin(void);

void write_sio(int index,int data)
{
	bios_outb(index, 0x3f0);
	bios_outb(data, 0x3f1);
}

unsigned char read_sio(int index)
{
	bios_outb(index, 0x3f0);
	return bios_inb(0x3f1);
}

inline void uart_init (unsigned base_port)
{
	int divisor = BASE_BAUD1;
	/* enable interrupts */
	bios_outb(0x7, base_port + UART_IER);

	/* enable fifo's */
	bios_outb(0x01, base_port + UART_FCR);

	bios_outb(0x80 | UART_LCS, base_port + UART_LCR);
	bios_outb(divisor & 0xFF, base_port + UART_DLL);
	bios_outb((divisor >> 8) & 0xFF, base_port + UART_DLM);
	bios_outb(UART_LCS, base_port + UART_LCR);
}

void enable_parallel_port(void)
{
	unsigned char byte;
	rom_printk("enable superio parallel port ...\n");
	bios_outb(0x55, 0x3f0);
	
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
	
	bios_outb(0xAA, 0x3f0);

	if (!set_irq) set_irq_pin();
	set_irq = 1;

	hardware.parallel = 1;
}

void enable_rtc(void)
{
	rom_printk("enable superio rtc ...\n");
	bios_outb(0x55, 0x3f0);
	
	write_sio(0x7, 0x6);
	write_sio(0x30, 0);
	write_sio(0x70, 0x8);
	write_sio(0x30, 0x1);
	
	bios_outb(0xAA, 0x3f0);

	if (!set_irq) set_irq_pin();
	set_irq = 1;

	hardware.rtc = 1;
}

void enable_keyboard(void)
{
	rom_printk("enable superio keyboard ...\n");
	bios_outb(0x55, 0x3f0);
	
	write_sio(0x7, 0x7);
	write_sio(0x30, 0);
	write_sio(0x70, 0x1);
	write_sio(0xf0, 0x3);
	write_sio(0x30, 0x1);
	
	bios_outb(0xAA, 0x3f0);

	if (!set_irq) set_irq_pin();
	set_irq = 1;
	
	init_kbd();

	hardware.keyboard = 1;
}

void enable_mouse(void)
{
	rom_printk("enable superio mouse ...\n");
	bios_outb(0x55, 0x3f0);
	
	write_sio(0x7, 0x7);
	write_sio(0x30, 0);
	write_sio(0x72, 0xc);
	write_sio(0xf0, 0x3);
	write_sio(0x30, 0x1);
	
	bios_outb(0xAA, 0x3f0);

	if (!set_irq) set_irq_pin();
	set_irq = 1;

	hardware.mouse = 1;
}

void enable_floppy(void)
{
	unsigned char byte;
	rom_printk("enable superio fdc ...\n");
	
	bios_outb(0x55, 0x3f0);
	
	byte = read_sio(0x22);
	byte |= (1 << 0);
	write_sio(0x22, byte); // fdc power on	
	
	write_sio(0x7, 0x0);
	write_sio(0x30, 0);	// disable fdc
	write_sio(0x70, 0x06);	// irq
	write_sio(0x30, 0x1);	// enable fdc
	
	bios_outb(0xAA, 0x3f0);

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
	bios_outb(0x55, 0x3f0);

	write_sio(0x07, 0x08);
        write_sio(0x30, 0x00);
        write_sio(0xc0, 0x03);
        write_sio(0xcc, (1<<3)); // irq12
        write_sio(0xd0, (1<<3)); // irq1
        write_sio(0xd1, (1<<3)); // irq3
        write_sio(0xd2, (1<<3)); // irq4
        write_sio(0xd3, (1<<3)); // irq5
        write_sio(0xd4, (1<<3)); // irq6
        write_sio(0xd5, (1<<3)); // irq7
        write_sio(0x30, 0x01);
	
	bios_outb(0xAA, 0x3f0);
}
