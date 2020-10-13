/*
 * COM1 NS16550 support
 */

#include <linux/types.h>
#include <linux/serial.h>
#include <linux/serial_reg.h>

#include <asm/serial.h>
#include <asm/e2k_api.h>
#include <asm/e2k_debug.h>
#include <asm/boot_head.h>
#include <asm/atomic.h>
#include "boot_io.h"


#if defined (CONFIG_SERIAL_PRINTK) || defined(CONFIG_SERIAL_BOOT_PRINTK)
#define SERIAL_BAUD CONFIG_BOOT_SERIAL_BAUD
#else
#define SERIAL_BAUD	115200
#endif

#define BOTH_EMPTY (UART_LSR_TEMT | UART_LSR_THRE)

extern unsigned	char inb(unsigned long port);
extern void outb(unsigned char byte, unsigned long port);
unsigned short com_port;
static atomic_t swait = ATOMIC_INIT(0);

static void com_outb(u16 port, u8 byte)
{
       E2K_WRITE_MAS_B(PHYS_X86_IO_BASE + port, byte, MAS_IOADDR);
}

static u8 com_inb(u16 port)
{
	return E2K_READ_MAS_B(PHYS_X86_IO_BASE + port, MAS_IOADDR);
}

static struct serial_struct rs_table[RS_TABLE_SIZE] = {
	SERIAL_PORT_DFNS	/* Defined in <asm/serial.h> */
};

static int shift;

unsigned short serial_init(int chan, int boot)
{
	unsigned char lcr;
	unsigned int divisor, wait;
	struct serial_struct *rs;
	unsigned long *port;
	int lshift;
	/* We need to find out which type io we're expecting.  If it's
	 * 'SERIAL_IO_PORT', we get an offset from the isa_io_base.
	 * If it's 'SERIAL_IO_MEM', we can the exact location.  -- Tom */
	
	if (boot) {
		wait = atomic_read((atomic_t *)boot_vp_to_pp(&swait));
		rs = boot_vp_to_pp(rs_table);
		port = boot_vp_to_pp(&com_port);
	}
	else {
		wait = atomic_read(&swait);
		rs = rs_table;
		port = (unsigned long *)&com_port;
	}
	
	if (wait) return -1;

	switch (rs[chan].io_type) {
		case SERIAL_IO_PORT:
			*port = rs[chan].port;
			break;
		case SERIAL_IO_MEM:
			*port = (unsigned long)rs_table[chan].iomem_base;
			break;
		default:
			/* We can't deal with it. */
			return -1;
	}

	/* How far apart the registers are. */
	lshift = rs[chan].iomem_reg_shift;
	if (boot)
		atomic_set((atomic_t *)boot_vp_to_pp(&shift), lshift);
	else
		atomic_set((atomic_t *)(&shift), lshift);

	com_outb(*port + (UART_LCR << shift), 0x3);	/* 8n1 */
	com_outb(*port + (UART_IER << shift), 0);	/* no interrupt */
	com_outb(*port + (UART_FCR << shift), 0);	/* no fifo */
	com_outb(*port + (UART_MCR << shift), 0x3);	/* DTR + RTS */

	divisor = BASE_BAUD / SERIAL_BAUD;
	lcr = com_inb(*port + (UART_LCR << shift));
	com_outb(*port + (UART_LCR << shift), lcr | UART_LCR_DLAB);
	com_outb(*port + (UART_DLL << shift), divisor & 0xff);
	com_outb(*port + (UART_DLM << shift), (divisor >> 8) & 0xff);
	com_outb(*port + (UART_LCR << shift), lcr & ~UART_LCR_DLAB);
	
	/* Clear & enable FIFOs */
	com_outb(*port + (UART_FCR << shift), 0x07);
	
	if (boot) {
//		*(unsigned short *)(boot_vp_to_pp(&com_port)) = port;
		atomic_set((atomic_t *)boot_vp_to_pp(&swait), 1);
	}
	else {
//		com_port = port;
		atomic_set(&swait, 1);
	}
			
	return *port;
}

void
serial_init_wait(int boot)
{	
	if (boot)
		while(!atomic_read((atomic_t *)boot_vp_to_pp(&swait)));
	else
		while(atomic_read(&swait));
}
	
void
serial_putc(unsigned short com_port, unsigned char c)
{
//	unsigned int tmout = 10000;
	while ((com_inb(com_port + (UART_LSR << shift)) & BOTH_EMPTY) != BOTH_EMPTY) {
//		if (--tmout == 0) break;
	};
	com_outb(com_port, c);
}

unsigned char
serial_getc(unsigned short com_port)
{
	while ((com_inb(com_port + (UART_LSR << shift)) & UART_LSR_DR) == 0)
		;
	return com_inb(com_port);
}

int
serial_tstc(unsigned short com_port)
{
	return (com_inb(com_port + (UART_LSR << shift)) & UART_LSR_DR) != 0;
}
