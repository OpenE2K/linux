#ifndef _E2K_E8C_LMS_H_
#define _E2K_E8C_LMS_H_

#include <linux/init.h>
#include <asm/e3s_lms.h>
#include <asm/e8c.h>


#define	E8C_LMS_CPU_VENDOR	E3S_LMS_CPU_VENDOR
#define	E8C_LMS_CPU_FAMILY	E3S_LMS_CPU_FAMILY

extern void __init boot_e8c_lms_setup_arch(void);
extern void __init e8c_lms_setup_arch(void);
extern void __init e8c_lms_setup_machine(void);
extern int  e8c_lms_get_cpuinfo(char *);

#endif /* _E2K_E8C_LMS_H_ */
