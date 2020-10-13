#ifndef _E2K_E3S_LMS_H_
#define _E2K_E3S_LMS_H_

#include <linux/init.h>
#include <asm/e3s.h>


#define	E3S_LMS_CPU_VENDOR	"Elbrus-MCST"
#define	E3S_LMS_CPU_FAMILY	4
#define	E3S_LMS_CPU_MODEL	IDR_E3S_MDL

extern void __init boot_e3s_lms_setup_arch(void);
extern void __init e3s_lms_setup_arch(void);
extern void __init e3s_lms_setup_machine(void);
extern int  e3s_lms_get_cpuinfo(char *);

#endif /* _E2K_E3S_LMS_H_ */
