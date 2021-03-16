/* $Id: param.h,v 1.4 2008/12/19 12:44:14 atic Exp $ */
#ifndef _E2K_PARAM_H_
#define _E2K_PARAM_H_

#include <uapi/asm/param.h>


# define HZ		CONFIG_HZ	/* Internal kernel timer frequency */
# define USER_HZ	HZ		/* some user interfaces are in */
					/* "ticks" */
# define CLOCKS_PER_SEC (USER_HZ)
#endif /* _E2K_PARAM_H_ */
