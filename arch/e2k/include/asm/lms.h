#ifndef _E2K_LMS_H_
#define _E2K_LMS_H_

#include <linux/init.h>
#include <asm/e3s.h>

#define	E3M_LMS_CPU_VENDOR	"Elbrus-MCST"
#define	E3M_LMS_CPU_FAMILY	3
#define	E3M_LMS_CPU_MODEL	IDR_E3M_MDL
#define	E3M_LMS_CPU_REVISION	0

extern void __init boot_e3m_lms_setup_arch(void);
extern void __init e3m_lms_setup_arch(void);
extern int  e3m_lms_get_cpuinfo(char *);

#endif /* _E2K_LMS_H_ */
