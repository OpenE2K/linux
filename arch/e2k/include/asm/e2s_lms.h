#ifndef _E2K_E2S_LMS_H_
#define _E2K_E2S_LMS_H_

#include <linux/init.h>
#include <asm/e3s_lms.h>
#include <asm/e2s.h>


#define	E2S_LMS_CPU_VENDOR	E3S_LMS_CPU_VENDOR
#define	E2S_LMS_CPU_FAMILY	E3S_LMS_CPU_FAMILY

extern void __init boot_e2s_lms_setup_arch(void);
extern void __init e2s_lms_setup_arch(void);
extern void __init e2s_lms_setup_machine(void);
extern int  e2s_lms_get_cpuinfo(char *);

#endif /* _E2K_E2S_LMS_H_ */
