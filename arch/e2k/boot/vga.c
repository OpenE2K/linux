
#include <linux/types.h>

#include <asm/e2k_debug.h>

#include "vga.h"
#include "boot_io.h"

char *vidmem = (char *) 0xB8000UL;
static int lines=25, cols=80;
static int orig_x=0, orig_y=0;

#define	VIDMEM_BUG	1

static void vidmem_cpy(void * __dest, __const void * __src,
			    int __n)
{
	int i;
	char *d = (char *)__dest, *s = (char *)__src;

	for (i=0;i<__n;i++) {

#ifndef VIDMEM_BUG
		d[i] = s[i];
#else
		char c;

		c = E2K_READ_MAS_B(& s[i] , MAS_IOADDR);
		E2K_WRITE_MAS_B(& d[i] , c , MAS_IOADDR);
#endif
	}
}

static void vga_outb(u16 port, u8 byte)
{
       E2K_WRITE_MAS_B(PHYS_X86_IO_BASE + port, byte, MAS_IOADDR);
}

static void clear_screen(void)
{
	int i, j;
	for (i = 0;  i < lines;  i++) {
	  for (j = 0;  j < cols;  j++) {
#ifndef VIDMEM_BUG
	    vidmem[((i*cols)+j)*2] = ' ';
	    vidmem[((i*cols)+j)*2+1] = 0x07;
#else
            E2K_WRITE_MAS_B(& vidmem[((i*cols)+j)*2] , ' ' , MAS_IOADDR);
            E2K_WRITE_MAS_B(& vidmem[((i*cols)+j)*2+1] , 0x07 , MAS_IOADDR);
#endif
	  }
	}
}

static void scroll(void)
{
	int i;

	vidmem_cpy ( vidmem, vidmem + cols * 2, ( lines - 1 ) * cols * 2 );
	for ( i = ( lines - 1 ) * cols * 2; i < lines * cols * 2; i += 2 ) {
#ifndef VIDMEM_BUG
		vidmem[i] = ' ';
#else
		E2K_WRITE_MAS_B(& vidmem[i], ' ' , MAS_IOADDR);
#endif
	}
}

/*
 * cursor() sets an offset (0-1999) into the 80x25 text area   
 */
static void cursor(int x, int y)
{
	int pos = (y*cols)+x;
	vga_outb(0x3D4, 14);
	vga_outb(0x3D5, pos >> 8);
	vga_outb(0x3D4, 15);
	vga_outb(0x3D5, pos);
}

void vga_putc(const char c)
{
	int x,y;

	x = orig_x;
	y = orig_y;

	if ( c == '\n' ) {
		x = 0;
		if ( ++y >= lines ) {
			scroll();
			y--;
		}
	} else if (c == '\r') {
		x = 0;
	} else if (c == '\b') {
		if (x > 0) {
			x--;
		} else {
			x = cols - 1; y = ( y == 0 ? y : y - 1);
		}
	} else {
#ifndef VIDMEM_BUG
		vidmem [ ( x + cols * y ) * 2 ] = c; 
#else
		E2K_WRITE_MAS_B(& vidmem [ ( x+cols*y )*2 ] , c , MAS_IOADDR); 
#endif
		if ( ++x >= cols ) {
			x = 0;
			if ( ++y >= lines ) {
				scroll();
				y--;
			}
		}
	}

	cursor(x, y);

	orig_x = x;
	orig_y = y;
}

void vga_puts(const char *s)
{
	int x,y;
	char c;

	x = orig_x;
	y = orig_y;

	while ( ( c = *s++ ) != '\0' ) {

		if ( c == '\n' ) {
			x = 0;
			if ( ++y >= lines ) {
				scroll();
				y--;
			}
		} else if (c == '\b') {
			if (x > 0) {
				x--;
			} else {
				x = cols - 1; y = ( y == 0 ? y : y - 1);
			}
		} else {
#ifndef VIDMEM_BUG
			vidmem [ ( x + cols * y ) * 2 ] = c; 
#else
			E2K_WRITE_MAS_B(& vidmem [(x+cols*y)*2], c ,MAS_IOADDR);
#endif
			if ( ++x >= cols ) {
				x = 0;
				if ( ++y >= lines ) {
					scroll();
					y--;
				}
			}
		}
	}

	cursor(x, y);

	orig_x = x;
	orig_y = y;
}


static void regs_init(void)
{
	int i;
	u16 port;
	u8  byte;

	i=0;

	while (vga_regs[i][0] != 0) {
//		rom_printk("regs_init: i = %d ," , i );

		port = (u16)  vga_regs[i][0];
		byte = (u8)   vga_regs[i][1];
//                rom_printk(" port = %x , byte = %x\n", port, byte);

		vga_outb(port, byte);
		i++;
	}

}

static void loadfont(void)
{
	int i;
	u8 *p;
	u8 byte;

	i=0;

	while (font[i][0] != 0) {
		p    = (u8 *) font[i][0];
		byte = (u8)   font[i][1];
#ifndef VIDMEM_BUG
		*p = byte;
#else
		E2K_WRITE_MAS_B(p , byte, MAS_IOADDR);
#endif
		i++;
	}
}


void vga_init(void)
{
	regs_init();
	loadfont();

	clear_screen();
	cursor(0,0);
	orig_x=0; orig_y=0;

	vga_puts("legacy VGA console. Text mode. 80x25. 16 colors.\n");

}
