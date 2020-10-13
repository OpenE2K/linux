/*
 * $Id: mlt.h,v 1.15 2009/11/05 12:30:21 kravtsunov_e Exp $
 */

#ifndef _UAPI_E2K_MLT_H_
#define _UAPI_E2K_MLT_H_

#include <asm/mas.h>
#include <asm/e2k_api.h>

#define	E2K_READ_MLT_REG(addr) \
		_E2K_READ_MAS(addr, MAS_MLT_REG, e2k_mlt_line_t, d, 2)

#endif /* _UAPI_E2K_MLT_H_ */
