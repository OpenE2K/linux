/* $Id: param.h,v 1.4 2008/12/19 12:44:14 atic Exp $ */

#ifndef _UAPI_E2K_PARAM_H_
#define _UAPI_E2K_PARAM_H_


#ifndef __KERNEL__
#define HZ 100
#endif

#define EXEC_PAGESIZE	4096	/* Intel size. */
				/* Check for 64K native pages if used. */

#ifndef NOGROUP
#define NOGROUP		(-1)
#endif

#define MAXHOSTNAMELEN	64	/* max length of hostname */

#endif /* _UAPI_E2K_PARAM_H_ */
