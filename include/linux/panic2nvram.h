
#ifndef __PANIC2NVRAM_H__
#define __PANIC2NVRAM_H__

extern unsigned int   start_nvram_panic_area;
extern unsigned int   size_nvram_panic_area;
extern int (*panic2nvram_read) (unsigned int off, unsigned char *addr, int sz);
extern void (*panic2nvram_write) (unsigned int off, unsigned char *addr, int sz);
extern int (*panic2nvram_raw_write) (unsigned int off, unsigned char *addr, int sz);

#endif
