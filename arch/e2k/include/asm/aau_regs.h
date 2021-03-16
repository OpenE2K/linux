/*
 * AAU registers description, macroses for load/store AAU context
 *
 * array access descriptors			(AAD0, ... , AAD31);
 * initial indices				(AIND0, ... , AAIND15);
 * indices increment values			(AAINCR0, ... , AAINCR7);
 * current values of "prefetch" indices		(AALDI0, ... , AALDI63);
 * array prefetch initialization mask		(AALDV);
 * prefetch attributes				(AALDA0, ... , AALDA63);
 * array prefetch advance mask			(AALDM);
 * array access status register			(AASR);
 * array access fault status register		(AAFSTR);
 * current values of "store" indices		(AASTI0, ... , AASTI15);
 * store attributes				(AASTA0, ... , AASTA15); 
 */

#ifndef _E2K_AAU_H_ 
#define _E2K_AAU_H_

#include <linux/types.h>
#include <asm/aau_regs_types.h>
#include <asm/aau_regs_access.h>

#endif /* _E2K_AAU_H_ */
