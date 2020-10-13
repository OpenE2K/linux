#ifndef _E2K_ES2_LMS_H_
#define _E2K_ES2_LMS_H_

#include <linux/init.h>
#include <asm/e3s_lms.h>
#include <asm/es2.h>


#define	ES2_LMS_CPU_VENDOR	E3S_LMS_CPU_VENDOR
#define	ES2_LMS_CPU_FAMILY	E3S_LMS_CPU_FAMILY

extern void __init boot_es2_lms_setup_arch(void);
extern void __init es2_lms_setup_arch(void);
extern void __init es2_lms_setup_machine(void);
extern int  es2_lms_get_cpuinfo(char *);

#endif /* _E2K_ES2_LMS_H_ */
