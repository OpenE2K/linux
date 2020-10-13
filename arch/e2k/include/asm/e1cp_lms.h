#ifndef _E2K_E1CP_LMS_H_
#define _E2K_E1CP_LMS_H_

#include <linux/init.h>
#include <asm/e3s_lms.h>
#include <asm/e1cp.h>


#define	E1CP_LMS_CPU_VENDOR	E3S_LMS_CPU_VENDOR
#define	E1CP_LMS_CPU_FAMILY	E3S_LMS_CPU_FAMILY

extern void __init boot_e1cp_lms_setup_arch(void);
extern void __init e1cp_lms_setup_arch(void);
extern void __init e1cp_lms_setup_machine(void);
extern int  e1cp_lms_get_cpuinfo(char *);

#endif /* _E2K_E1CP_LMS_H_ */
