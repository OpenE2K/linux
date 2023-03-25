#ifndef	_E2K_SWAP_INFO_H
#define	_E2K_SWAP_INFO_H

#include <linux/init.h>

typedef struct swap_page_info {
	struct swap_page_info *next;
	struct mm_struct* mm;
	e2k_addr_t addr;
} swap_page_info_t;

#define	PageSwapInfo(page)		(page)->swap_info
#define PageWithSwapInfo(page)		(PageSwapInfo(page) != NULL) 
#define ClearPageSwapInfo(page)		PageSwapInfo(page) = NULL

#endif
