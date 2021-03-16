#ifndef _ASM_L_TIMER_H
#define _ASM_L_TIMER_H

#ifdef __KERNEL__

#include <asm/e2k.h>
#include <asm/l_timer_regs.h>

#define	L_TIMER_IS_ALLOWED()	(HAS_MACHINE_E2K_IOHUB || IS_HV_GM())

#include <asm-l/l_timer.h>

#endif  /* __KERNEL__ */
#endif	/* _ASM_L_TIMER_H */
