#ifndef _E2K_RESOURCE_H_
#define _E2K_RESOURCE_H_

#include <asm/stacks.h>
#include <asm-generic/resource.h>

/*
 * Redefine resource limits for e2k
 */
#undef	_STK_LIM
#define	_STK_LIM	RLIM_INFINITY

/*
 * Hard stacks rlimits numbers
 */
#define RLIM_P_STACK_EXT	16
#define RLIM_PC_STACK_EXT	17

#endif /* _E2K_RESOURCE_H_ */
