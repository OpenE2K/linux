/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * This is a collection of several routines from gzip-1.0.3 
 * adopted for Linux.
 */

#include <linux/linkage.h>
#include <linux/vmalloc.h>
#include <linux/tty.h>
#include <asm/e2k_debug.h>
#include <asm/e2k.h>

#include "boot_io.h"

/*
 * gzip declarations
 */

#define OF(args)  args
#define STATIC static
#define	NOMEMCPY	1

//#undef memset
//#undef memcpy

/*
 * Why do we do this? Don't ask me..
 *
 * Incomprehensible are the ways of bootloaders.
 */
#define memzero(s, n)     memset ((s), 0, (n))

typedef unsigned char  uch;
typedef unsigned short ush;
typedef unsigned long  ulg;

#define WSIZE 0x8000		/* Window size must be at least 32k, */
				/* and a power of two */

static uch *inbuf;	     /* input buffer */
static uch window[WSIZE];    /* Sliding window buffer */

static unsigned insize = 0;  /* valid bytes in inbuf */
static unsigned inptr = 0;   /* index of next byte to be processed in inbuf */
static unsigned outcnt = 0;  /* bytes in output buffer */

/* gzip flag byte */
#define ASCII_FLAG   0x01 /* bit 0 set: file probably ASCII text */
#define CONTINUATION 0x02 /* bit 1 set: continuation of multi-part gzip file */
#define EXTRA_FIELD  0x04 /* bit 2 set: extra field present */
#define ORIG_NAME    0x08 /* bit 3 set: original file name present */
#define COMMENT      0x10 /* bit 4 set: file comment present */
#define ENCRYPTED    0x20 /* bit 5 set: file is encrypted */
#define RESERVED     0xC0 /* bit 6,7:   reserved */

#define get_byte()  (inptr < insize ? inbuf[inptr++] : fill_inbuf())
		
/* Diagnostic functions */
#ifdef DEBUG
#  define Assert(cond,msg) {if(!(cond)) error(msg);}
#  define Trace(x) fprintf x
#  define Tracev(x) {if (verbose) fprintf x ;}
#  define Tracevv(x) {if (verbose>1) fprintf x ;}
#  define Tracec(c,x) {if (verbose && (c)) fprintf x ;}
#  define Tracecv(c,x) {if (verbose>1 && (c)) fprintf x ;}
#else
#  define Assert(cond,msg)
#  define Trace(x)
#  define Tracev(x)
#  define Tracevv(x)
#  define Tracec(c,x)
#  define Tracecv(c,x)
#endif

static int  fill_inbuf(void);
static inline void flush_window(void);
static void error(char *m);

extern char input_data[];
extern char input_data_end[];

static long bytes_out = 0;
static uch *output_data;
static unsigned long output_ptr = 0;

extern long free_mem_ptr;
extern long free_mem_end_ptr;


#define ZLIB_INFLATE_NO_INFLATE_LOCK
#include "../../../lib/inflate.c"

#ifndef __HAVE_ARCH_MEMSET
void* memset(void* s, int c, size_t n)
{
	int i;
	char *ss = (char*)s;

	for (i=0;i<n;i++) ss[i] = c;
	return s;
}
#endif
#ifndef __HAVE_ARCH_MEMCPY
void* memcpy(void* __dest, __const void* __src,
			    size_t __n)
{
	int i;
	char *d = (char *)__dest, *s = (char *)__src;

	for (i=0;i<__n;i++) d[i] = s[i];
	return __dest;
}
#endif
/* ===========================================================================
 * Fill the input buffer. This is called only when the buffer is empty
 * and at least one byte is really needed.
 */
static int fill_inbuf(void)
{
	if (insize != 0) {
		error("ran out of input data");
	}

	inbuf = input_data;
	insize = input_data_end - input_data;
	inptr = 1;
	return inbuf[0];
}

/* ===========================================================================
 * Write the output window window[0..outcnt-1] and update crc and bytes_out.
 * (Used for the decompressed data only.)
 */
static void inline flush_window(void)
{
    ulg c = crc;         /* temporary variable */
    unsigned n;
    uch *in, *out, ch;
    
    in = window;
    out = &output_data[output_ptr]; 
    for (n = 0; n < outcnt; n++) {
	    ch = *out++ = *in++;
	    c = crc_32_tab[((int)c ^ ch) & 0xff] ^ (c >> 8);
    }
    crc = c;
    bytes_out += (ulg)outcnt;
    output_ptr += (ulg)outcnt;
    outcnt = 0;
  rom_printk("decompressed %d bytes\r", bytes_out);
}


static void error(char *x)
{
	rom_puts("\n\n");
	rom_puts(x);
	rom_puts("\n\n -- System halted");

	E2K_LMS_HALT_ERROR(0xdead);	/* Halt */
}


int decompress_kernel(ulong base)
{

	output_data = (uch *) base;

	makecrc();
	gunzip();

	return bytes_out;
}
