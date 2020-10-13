#include <linux/linkage.h>
#include <linux/vmalloc.h>
#include <linux/tty.h>
#include <asm/e2k_debug.h>
#include <asm/e2k.h>

#define STATIC static

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

/* Not needed, but used in some headers pulled in by decompressors */
extern char *strstr(const char *s1, const char *s2);

extern e2k_addr_t free_mem_ptr;
extern e2k_addr_t free_mem_end_ptr;

#include "../../../lib/decompress_inflate.c"

static void error_print(char *str)
{
	rom_printk(str);
}

int decompress_kernel(void *dst, void *src, ulong size)
{
	return decompress(src, size, NULL, NULL, dst, NULL, error_print);
}
