#ifndef _E2K_AUXVEC_H
#define _E2K_AUXVEC_H

#define AT_FAST_SYSCALLS 32
/* Skip 33 as it is assumed to be AT_SYSINFO_EHDR in Linux */
#define AT_SYSTEM_INFO 34

#ifdef __KERNEL__
# define AT_VECTOR_SIZE_ARCH 2
#endif

#endif	/* _E2K_AUXVEC_H */
