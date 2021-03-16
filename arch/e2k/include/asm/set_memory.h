#ifndef _ASM_E2K_SET_MEMORY_H
#define _ASM_E2K_SET_MEMORY_H

#include <asm/page.h>
#include <asm-generic/set_memory.h>

extern int set_memory_ro(unsigned long addr, int numpages);
extern int set_memory_rw(unsigned long addr, int numpages);
extern int set_memory_x(unsigned long addr, int numpages);
extern int set_memory_nx(unsigned long addr, int numpages);

extern int set_memory_uc(unsigned long addr, int numpages);
extern int set_memory_wc(unsigned long addr, int numpages);
extern int set_memory_wb(unsigned long addr, int numpages);

extern int set_pages_array_uc(struct page **pages, int addrinarray);
extern int set_pages_array_wc(struct page **pages, int addrinarray);
extern int set_pages_array_wb(struct page **pages, int addrinarray);

int set_pages_uc(struct page *page, int numpages);
int set_pages_wc(struct page *page, int numpages);
int set_pages_wb(struct page *page, int numpages);

#endif
