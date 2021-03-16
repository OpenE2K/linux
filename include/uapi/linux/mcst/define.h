#ifndef  __LINUX_DEFINE_H__
#define __LINUX_DEFINE_H__

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef __KERNEL__
#include <sys/types.h>
#include <stdio.h>
#include <pthread.h>
#include <sys/time.h>
#include <asm/unistd.h>
#include <errno.h>

#ifndef __NR_sched_setaffinity
#define __NR_sched_setaffinity	160 /* e90 Specific                                */
static inline _syscall3(long, sched_setaffinity, int, pid, unsigned int, len, unsigned long*, user_mask_ptr);
#endif
#ifndef __NR_sched_getaffinity
#define __NR_sched_getaffinity	161 /* e90 Specific                                */
static inline _syscall3(long, sched_getaffinity, int, pid, unsigned int, len, unsigned long*, user_mask_ptr);
#endif

#if 0
#ifndef __NR_e90_ioctl
#define __NR_e90_ioctl          234 /* e90 Specific                                */
static inline _syscall2(int, e90_ioctl, unsigned int, cmd, void*, arg);
#endif
#endif

typedef unsigned char   	uchar_t;
typedef unsigned int    	uint_t;
typedef unsigned long   	ulong_t;

typedef pthread_mutex_t lwp_mutex_t;
typedef pthread_cond_t lwp_cond_t;
typedef pthread_mutex_t mutex_t;

#endif /* KERNEL */

typedef unsigned long long 	u_longlong_t;  
typedef long long       	longlong_t;

typedef struct timespec timestruc_t;

#define B_READ  2
#define B_WRITE 1
#define	MSG_LEN	4096
#define MAXSIG 32 

#ifdef	__cplusplus
}
#endif

#endif /*  __LINUX_DEFINE_H__ */
