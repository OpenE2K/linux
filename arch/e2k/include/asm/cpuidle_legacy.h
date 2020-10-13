#ifndef _E2K_CPUIDLE_LEGACY_H_
#define _E2K_CPUIDLE_LEGACY_H_

#include <asm/e2k_api.h>

/* Macros for jumping over wait trap */
#define SET_WTRAP_JUMP_ADDR(label, local_name)				\
	struct thread_info* _thread_info = current_thread_info();	\
	GET_LBL_ADDR(label, local_name, _thread_info->wtrap_jump_addr);	\
	E2K_CMD_SEPARATOR;

#define JUMP_OVER_WTRAP_LABEL(label, local_name)			\
	TRAP_RETURN_LABEL(label, local_name);				\

#endif /* _E2K_CPUIDLE_LEGACY_H_ */
