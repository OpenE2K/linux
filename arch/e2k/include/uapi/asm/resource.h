#ifndef _E2K_RESOURCE_H_
#define _E2K_RESOURCE_H_

#include <asm/stacks.h>
#include <asm-generic/resource.h>

/*
 * Redefine resource limits for e2k
 */
#undef	_STK_LIM
#define	_STK_LIM	RLIM_INFINITY

#endif /* _E2K_RESOURCE_H_ */
